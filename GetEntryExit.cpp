/*
* GetEntryPoint.cpp
*
*  Created on: 2014/06/03
*      Author: yoshimura
*/

#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/CheckerRegistry.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/ADT/SetVector.h"

using namespace clang;
using namespace ento;

namespace {

	typedef llvm::SmallString<64> FuncString;
	typedef FuncString FieldString;
	typedef FuncString StructString;
	typedef llvm::SmallSetVector<FuncString, 100> FuncSet;
	typedef llvm::SmallSetVector<std::tuple<FuncString, FuncString>, 100> FuncPairSet;
	typedef llvm::SmallSetVector<std::tuple<StructString, FieldString, FuncString>, 100> StructFuncSet;
	typedef llvm::StringMap<FuncSet> FuncExitMap;

	class SearchEntryCallInFunction : public StmtVisitor<SearchEntryCallInFunction> {
	private:
		FuncPairSet funcArgs;
		FuncSet rhsFuncs;
		StructFuncSet structFuncs;

	public:
		void VisitChildren(Stmt *stmt) {
			for (auto i = stmt->child_begin(), e = stmt->child_end(); i != e; ++i)
				if (Stmt *child = *i)
					Visit(child);
		}

		/* for cases like:
		* static int g(int arg) {
		*     ...
		* }
		* static void f() {
		*     int (*open)(int arg);
		*     ...
		*     open = g; // open may be passed to global functions
		*     ...
		* }
		*/
		void VisitBinaryOperator(BinaryOperator *op) {
			VisitChildren(op);
			if (!op->isAssignmentOp())
				return;

			StringRef funcName;
			// right of =
			if (const DeclRefExpr *declExpr = dyn_cast_or_null<DeclRefExpr>(op->getRHS()->IgnoreParenCasts())) {
				if (const FunctionDecl *funcDecl = dyn_cast_or_null<FunctionDecl>(declExpr->getDecl())) {
					funcName = funcDecl->getIdentifier()->getName();
				}
			}
			if (funcName.empty())
				return;

			// left of =
			if (const MemberExpr *declExpr = dyn_cast_or_null<MemberExpr>(op->getLHS()->IgnoreParenCasts())) {
				if (const FieldDecl *fieldDecl = dyn_cast_or_null<FieldDecl>(declExpr->getMemberDecl())) {
					StringRef fieldName = fieldDecl->getIdentifier()->getName();
					RecordDecl *recordDecl = const_cast<RecordDecl*>(fieldDecl->getParent());
					IdentifierInfo * structIdentifier = recordDecl->getIdentifier();
					while (!structIdentifier) {
						recordDecl = const_cast<RecordDecl*>(dyn_cast_or_null<RecordDecl>(recordDecl->getParent()));
						if (!recordDecl)
							break;
						structIdentifier = recordDecl->getIdentifier();
					}

					StringRef structName;
					if (structIdentifier)
						structName = structIdentifier->getName();
					else
						structName = "(no-name)";
					structFuncs.insert(std::make_tuple(structName, fieldName, funcName));
					return;
				}
			}

			rhsFuncs.insert(funcName);
		}

		/* for cases like:
		* static int h(int arg) {
		*     ...
		* }
		* static int g(int (*open)(int arg)) {
		*     ... // open may be passed to global functions
		* }
		* static void f() {
		*     ...
		*     g(h);
		*     ...
		* }
		*/
		void VisitCallExpr(CallExpr *call) {
			VisitChildren(call);
			const FunctionDecl * calleeDecl = call->getDirectCallee();
			if (!calleeDecl || !calleeDecl->isGlobal())
				return;

			StringRef calleeName = calleeDecl->getIdentifier()->getName();
			int i, e = call->getNumArgs();
			for (i = 0; i < e; i++) {
				if (DeclRefExpr *argExpr = dyn_cast<DeclRefExpr>(call->getArg(i)->IgnoreParenCasts()))
					if (const FunctionDecl *decl = dyn_cast_or_null<FunctionDecl>(argExpr->getDecl()))
						funcArgs.insert(std::make_tuple(calleeName, decl->getIdentifier()->getName()));
			}
		}

		void VisitStmt(Stmt *S) {
			VisitChildren(S);
		}

		void getFuncArgs(FuncPairSet &result) {
			result.insert(funcArgs.begin(), funcArgs.end());
		}

		void getRhsFuncs(FuncSet &result) {
			result.insert(rhsFuncs.begin(), rhsFuncs.end());
		}

		void getStructFuncs(StructFuncSet &result) {
			result.insert(structFuncs.begin(), structFuncs.end());
		}
	};

	//for getting exit points
	class WalkCall : public StmtVisitor<WalkCall> {
		FuncSet walked;
		FuncSet passed;

	public:
		void VisitChildren(Stmt *stmt) {
			for (auto i = stmt->child_begin(), e = stmt->child_end(); i != e; ++i)
				if (Stmt *child = *i)
					Visit(child);
		}

		void VisitCallExpr(CallExpr *call) {
			VisitChildren(call);
			if (const FunctionDecl * funcDecl = call->getDirectCallee()) {
				StringRef funcName = funcDecl->getIdentifier()->getName();
				if (!funcDecl->hasBody()) {
					walked.insert(funcName);
				}
				else if (passed.count(funcName) == 0) {
					passed.insert(funcName);
					Visit(funcDecl->getBody());
				}
			}
		}

		void VisitStmt(Stmt *S) {
			VisitChildren(S);
		}

		FuncSet & getWalkResult() {
			return walked;
		}
	};

	class GetEntryExit : public Checker<check::ASTDecl<FunctionDecl>,
		check::ASTDecl<VarDecl>, check::EndAnalysis> {
	public:
		GetEntryExit() : noCall("(no-calls)") {}
		void checkASTDecl(const FunctionDecl *fd, AnalysisManager &mgr, BugReporter &reporter) const;
		void checkASTDecl(const VarDecl *var, AnalysisManager &mgr, BugReporter &reporter) const;
		void checkEndAnalysis(ExplodedGraph &unused, BugReporter &unused2, ExprEngine &eng) const;
	private:
		void traverseListExpr(const Decl* left, Stmt * right) const;
		void printExitPoints(llvm::raw_fd_ostream &output, StringRef funcName) const;

		mutable StructFuncSet structFuncs;
		mutable FuncSet initFuncs;
		mutable FuncSet globalFuncs;
		mutable FuncPairSet funcArgs;
		mutable FuncSet rhsFuncs;

		mutable FuncExitMap exitPoints;

		const StringRef noCall;
	};
} // end of anonymous namespace

void GetEntryExit::traverseListExpr(const Decl* left, Stmt * right) const {
	const FieldDecl * fieldDecl = dyn_cast<FieldDecl>(left);
	if (!fieldDecl)
		return;

	if (const DeclRefExpr *refExpr = dyn_cast<DeclRefExpr>(right->IgnoreImplicit())) {
		if (const FunctionDecl *declFunc = dyn_cast<FunctionDecl>(refExpr->getDecl())) {
			StringRef fieldName = fieldDecl->getIdentifier()->getName();
			RecordDecl *recordDecl = const_cast<RecordDecl*>(fieldDecl->getParent());
			IdentifierInfo * structIdentifier = recordDecl->getIdentifier();
			while (!structIdentifier) {
				recordDecl = const_cast<RecordDecl*>(dyn_cast_or_null<RecordDecl>(recordDecl->getParent()));
				if (!recordDecl)
					break;
				structIdentifier = recordDecl->getIdentifier();
			}

			StringRef structName;
			if (structIdentifier)
				structName = structIdentifier->getName();
			else
				structName = "(no-name)";
			structFuncs.insert(std::make_tuple(structName, fieldName, declFunc->getIdentifier()->getName()));
		}
	}
	else if (const InitListExpr *listExpr = dyn_cast<InitListExpr>(right->IgnoreImplicit())) {
		/* for cases like:
		* const static struct x_ops op = { // op may be passed to global functions
		*     .open = f,
		*     .pm = { .suspend = g, .... }, // some nested structs are included
		*     .close = ...
		* };
		*/
		if (const RecordType * type = listExpr->getType()->getAsStructureType()) {
			const RecordDecl *nextStructDecl = type->getDecl();
			DeclContext::decl_iterator i = nextStructDecl->decls_begin(), e = nextStructDecl->decls_end();
			InitListExpr::const_iterator i2 = listExpr->begin(), e2 = listExpr->end();
			for (; i != e && i2 != e2; i2++) {
				bool increment = true;
				if (const RecordDecl *recordDecl = dyn_cast<RecordDecl>(*i)) {
					if (recordDecl->getIdentifier() == nullptr) {
						increment = false;
					}
				}
				traverseListExpr(*i, *i2);
				if (increment)
					i++;
			}
		}
	}
}

/* for cases like:
* static void f() {
*     ...
* }
* const static struct x_ops op = { // op may be passed to global functions
*     .open = f,
*     .close = ...
* };
* static void (*glob)(void) = f; // glob may be passed to global functions
*/
void GetEntryExit::checkASTDecl(const VarDecl *varDecl, AnalysisManager &mgr, BugReporter &reporter) const {
	if (!mgr.getSourceManager().isInMainFile(varDecl->getLocation()))
		return;
	const Expr *init = varDecl->getInit();
	if (!init)
		return;

	if (const RecordType * type = varDecl->getType()->getAsStructureType()) {
		const RecordDecl *structDecl = type->getDecl();
		if (structDecl->getTagKind() == RecordDecl::TagKind::TTK_Struct) {
			if (const InitListExpr *declExpr = dyn_cast<InitListExpr>(init->IgnoreParenCasts())) {
				DeclContext::decl_iterator i = structDecl->decls_begin(), e = structDecl->decls_end();
				InitListExpr::const_iterator i2 = declExpr->begin(), e2 = declExpr->end();
				for (; i != e && i2 != e2; i2++) {
					bool increment = true;
					if (const RecordDecl *recordDecl = dyn_cast<RecordDecl>(*i)) {
						if (recordDecl->getIdentifier() == nullptr) {
							increment = false;
						}
					}
					traverseListExpr(*i, *i2);
					if (increment)
						i++;
				}
			}
		}
	}
	else if (const DeclRefExpr *refExpr = dyn_cast<DeclRefExpr>(init->IgnoreParenCasts())) {
		if (const FunctionDecl * funcDecl = dyn_cast<FunctionDecl>(refExpr->getDecl()))
			initFuncs.insert(funcDecl->getIdentifier()->getName());
	}
}

/* for cases like:
* void f() { // any functions can call
*     ...
* }
*/
void GetEntryExit::checkASTDecl(const FunctionDecl *fd, AnalysisManager &mgr, BugReporter &reporter) const {
	if (!fd->hasBody())
		return;

	StringRef funcName = fd->getIdentifier()->getName();
	if (mgr.getSourceManager().isInMainFile(fd->getLocation())) {
		SearchEntryCallInFunction search;
		search.Visit(fd->getBody());
		search.getFuncArgs(funcArgs);
		search.getRhsFuncs(rhsFuncs);
		search.getStructFuncs(structFuncs);
		if (fd->getStorageClass() == StorageClass::SC_None) {
			globalFuncs.insert(funcName);
		}
	}

	//for getting exit points
	WalkCall walk;
	walk.Visit(fd->getBody());
	FuncSet exitFuncs = walk.getWalkResult();
	if (!exitFuncs.empty()) {
		exitPoints[funcName].insert(exitFuncs.begin(), exitFuncs.end());
	}
	else {
		exitPoints[funcName].insert(noCall);
	}
}

//for checkEndAnalysis
void GetEntryExit::printExitPoints(llvm::raw_fd_ostream &output, StringRef funcName) const {
	output << "\t";
	if (exitPoints.count(funcName) > 0) {
		FuncSet exitPointsForThisFunc = exitPoints[funcName];
		auto i2 = exitPointsForThisFunc.begin(), e2 = exitPointsForThisFunc.end();
		output << *(i2++);
		for (; i2 != e2; i2++)
			output << " " << *i2;
	}
	else {
		output << "(has-no-body)";
	}
}

//output results in .entry files
void GetEntryExit::checkEndAnalysis(ExplodedGraph &unused, BugReporter &unused2, ExprEngine &eng) const {
	SourceManager &mgr = eng.getAnalysisManager().getSourceManager();
	StringRef mainFileName = mgr.getFileEntryForID(mgr.getMainFileID())->getName();

	size_t cpos = mainFileName.rfind(".c");
	if (cpos == std::string::npos) {
		fprintf(stderr, "[GetEntryExit] Not .c file: %s\n", mainFileName.str().c_str());
	}
	SmallString<128> fileName = mainFileName.substr(0, cpos);
	fileName.append(".entry");
	SmallString<128> prefix = mainFileName.substr(0, cpos);
	prefix.append("/");
	std::string err;
	llvm::raw_fd_ostream output(fileName.c_str(), err, llvm::sys::fs::F_Text);
	if (!err.empty()) {
		fprintf(stderr, "[GetEntryExit] failed to open file: %s\n\t:%s\n", fileName.c_str(), err.c_str());
		return;
	}

	for (auto i = structFuncs.begin(), e = structFuncs.end(); i != e; i++) {
		output << std::get<0>(*i) << "::" << std::get<1>(*i)
			<< "\t" << prefix << std::get<2>(*i);
		printExitPoints(output, std::get<2>(*i));
		output << "\n";
	}
	for (auto i = funcArgs.begin(), e = funcArgs.end(); i != e; i++) {
		output << "argof(" << std::get<0>(*i) << ")\t" << prefix << std::get<1>(*i);
		printExitPoints(output, std::get<1>(*i));
		output << "\n";
	}
	for (auto i = initFuncs.begin(), e = initFuncs.end(); i != e; i++) {
		output << "init" << '\t' << *i;
		printExitPoints(output, *i);
		output << "\n";
	}
	for (auto i = globalFuncs.begin(), e = globalFuncs.end(); i != e; i++) {
		output << "global" << '\t' << *i;
		printExitPoints(output, *i);
		output << "\n";
	}
	for (auto i = rhsFuncs.begin(), e = rhsFuncs.end(); i != e; i++) {
		output << "rhs" << '\t' << *i;
		printExitPoints(output, *i);
		output << "\n";
	}
}

// register this checker
void registerGetEntryExit(CheckerRegistry &registry) {
	registry.addChecker<GetEntryExit>("linux.GetEntryExit",
		"Shows exit point functions for each entry point function in a translation unit");
}
