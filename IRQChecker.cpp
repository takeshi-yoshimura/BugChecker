#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/CheckerRegistry.h"

using namespace clang;
using namespace ento;

namespace {

	StringRef getTypeInfoString(const Expr *expr) {
		if (const DeclRefExpr *declExpr = dyn_cast_or_null<DeclRefExpr>(expr->IgnoreParenCasts())) {
			if (const VarDecl *decl = dyn_cast_or_null<VarDecl>(declExpr->getDecl()))
				return decl->getName();
			else if (const FunctionDecl *decl = dyn_cast_or_null<FunctionDecl>(declExpr->getDecl()))
				return decl->getName();
		}
		else if (const MemberExpr *declExpr = dyn_cast_or_null<MemberExpr>(expr)) {
			if (const MemberExpr *decl = dyn_cast_or_null<MemberExpr>(declExpr))
				return decl->getMemberNameInfo().getAsString();
		}
		return StringRef(expr->getStmtClassName());
	}

	SymbolRef getRootRegionSymbol(SymbolRef sym) {
		MemRegion * root = nullptr;
		if (const SymbolRegionValue * symRegion = dyn_cast_or_null<SymbolRegionValue>(sym)) {
			root = const_cast<MemRegion *>(symRegion->getRegion()->getBaseRegion());
		}
		else if (const SymbolMetadata *symRegion = dyn_cast_or_null<SymbolMetadata>(sym)) {
			root = const_cast<MemRegion *>(symRegion->getRegion()->getBaseRegion());
		}
		else if (const SymbolExtent *symRegion = dyn_cast_or_null<SymbolExtent>(sym)) {
			root = const_cast<MemRegion *>(symRegion->getRegion()->getBaseRegion());
		}
		else if (const SymbolDerived *symRegion = dyn_cast_or_null<SymbolDerived>(sym)) {
			root = const_cast<MemRegion *>(symRegion->getRegion()->getBaseRegion());
		}

		if (const SymbolicRegion *rootRegion = dyn_cast_or_null<SymbolicRegion>(root)) {
			return rootRegion->getSymbol(); //a root region is usually a symbol
		}
		return nullptr; // the root region is not a symbol, therefore we return a nullptr
	}

	const MemRegion * getRegion(SymbolRef sym) {
		if (const SymbolRegionValue * symRegion = dyn_cast_or_null<SymbolRegionValue>(sym)) {
			return symRegion->getRegion();
		}
		else if (const SymbolMetadata *symRegion = dyn_cast_or_null<SymbolMetadata>(sym)) {
			return symRegion->getRegion();
		}
		else if (const SymbolExtent *symRegion = dyn_cast_or_null<SymbolExtent>(sym)) {
			return symRegion->getRegion();
		}
		else if (const SymbolDerived *symRegion = dyn_cast_or_null<SymbolDerived>(sym)) {
			return symRegion->getRegion();
		}
		return nullptr; // the root region is not a symbol, therefore we return a nullptr
	}

#define IRQF_SHARED 0x00000080 // include/linux/interrupt.h

	//used only in IRQState::operator<() in order to use REGISTER_SET_WITH_PROGRAMSTATE
	class ComparableSVal : public SVal {
	public:
		bool operator<(const ComparableSVal &other) const {
			if (Kind != other.Kind)
				return Kind < other.Kind;
			return Data < other.Data;
		}
	};

	class IRQState {
		enum Kind {
			Unique, Shared
		} k;
		enum SubKind {
			Requested, RequestFailed, Freed, Escaped
		} k2;
		const Expr *irqExpr, *devIdExpr; //for memory leak diagnosis
		const SVal irqVal, devIdVal;

		IRQState(Kind k_, SubKind k2_, const Expr *irqExpr_, const Expr *devIdExpr_, const SVal &irqVal_, const SVal &devIdVal_)
			: k(k_), k2(k2_), irqExpr(irqExpr_), devIdExpr(devIdExpr_), irqVal(irqVal_), devIdVal(devIdVal_) {}

	public:
		bool isUnique() const { return k == Unique; }
		bool isShared() const { return k == Shared; }
		bool isRequested() const { return k2 == Requested; }
		bool isRequestFailed() const { return k2 == RequestFailed; }
		bool isFreed() const { return k2 == Freed; }
		bool isEscaped() const { return k2 == Escaped; }

		bool isSameIrq(const SVal &irqVal_) const {
			if (SymbolRef irqSym_ = irqVal_.getAsSymbol()) {
				return irqVal.getAsSymbol() == irqSym_;
			}
			return irqVal == irqVal_;
		}
		bool isSameIrq(SymbolRef irqSym_) const {
			return irqSym_ != nullptr && irqVal.getAsSymbol() == irqSym_;
		}
		bool isSameDevId(const SVal &devIdVal_) const {
			if (SymbolRef devIdSym_ = devIdVal_.getAsSymbol()) {
				return devIdVal.getAsSymbol() == devIdSym_;
			}
			return devIdVal == devIdVal_;
		}
		bool isSameDevId(SymbolRef devIdSym_) const {
			return devIdSym_ != nullptr && devIdVal.getAsSymbol() == devIdSym_;
		}
		bool isSameIrq(const IRQState &other) const {
			return isSameIrq(other.irqVal) && isSameDevId(other.devIdVal);
		}
		bool isIrqInEscapedRegion(SymbolRef escaped) const {
			SymbolRef rootSym = irqVal.getAsSymbol();
			while ((rootSym = getRootRegionSymbol(rootSym)) != nullptr) {
				if (rootSym == escaped)
					return true;
			}
			return false;
		}
		bool isIrqInRegionOf(const MemRegion * region) const {
			SymbolRef rootSym = irqVal.getAsSymbol();
			while (const MemRegion * mem = getRegion(rootSym)) {
				rootSym = getRootRegionSymbol(rootSym);
				if (mem->isSubRegionOf(region))
					return true;
			}
			return false;
		}
		bool isDevIdInEscapedRegion(SymbolRef escaped) const {
			SymbolRef rootSym = devIdVal.getAsSymbol();
			while ((rootSym = getRootRegionSymbol(rootSym)) != nullptr) {
				if (rootSym == escaped)
					return true;
			}
			return false;
		}
		bool isDevIdInRegionOf(const MemRegion * region) const {
			SymbolRef rootSym = devIdVal.getAsSymbol();
			while (const MemRegion * mem = getRegion(rootSym)) {
				rootSym = getRootRegionSymbol(rootSym);
				if (mem->isSubRegionOf(region))
					return true;
			}
			return false;
		}

		static IRQState getRequested(bool isUnique, const Expr * irqExpr_,
			const Expr *devIdExpr_, const SVal &irqVal_, const SVal &devIdVal_) {
			Kind k_ = (isUnique) ? Unique : Shared;
			return IRQState(k_, Requested, irqExpr_, devIdExpr_, irqVal_, devIdVal_);
		}
		static IRQState getRequested(const IRQState &other) {
			return getRequested(other.isUnique(), other.irqExpr, other.devIdExpr, other.irqVal, other.devIdVal);
		}

		static IRQState getRequestFailed(bool isUnique, const Expr * irqExpr_,
			const Expr *devIdExpr_, const SVal &irqVal_, const SVal &devIdVal_) {
			Kind k_ = (isUnique) ? Unique : Shared;
			return IRQState(k_, RequestFailed, irqExpr_, devIdExpr_, irqVal_, devIdVal_);
		}
		static IRQState getRequestFailed(const IRQState &other) {
			return getRequestFailed(other.isUnique(), other.irqExpr, other.devIdExpr, other.irqVal, other.devIdVal);
		}

		static IRQState getFreed(bool isUnique, const Expr * irqExpr_,
			const Expr *devIdExpr_, const SVal &irqVal_, const SVal &devIdVal_) {
			Kind k_ = (isUnique) ? Unique : Shared;
			return IRQState(k_, Freed, irqExpr_, devIdExpr_, irqVal_, devIdVal_);
		}
		static IRQState getFreed(const IRQState &other) {
			return getFreed(other.isUnique(), other.irqExpr, other.devIdExpr, other.irqVal, other.devIdVal);
		}

		static IRQState getEscaped(bool isUnique, const Expr * irqExpr_,
			const Expr *devIdExpr_, const SVal &irqVal_, const SVal &devIdVal_) {
			Kind k_ = (isUnique) ? Unique : Shared;
			return IRQState(k_, Escaped, irqExpr_, devIdExpr_, irqVal_, devIdVal_);
		}
		static IRQState getEscaped(const IRQState &other) {
			return getEscaped(other.isUnique(), other.irqExpr, other.devIdExpr, other.irqVal, other.devIdVal);
		}

		void markForBugReport(BugReport *reporter) const {
			reporter->addRange(irqExpr->getSourceRange());
			reporter->markInteresting(irqVal);
			reporter->markInteresting(devIdVal);
		}

		StringRef getIrqString() const {
			return getTypeInfoString(irqExpr);
		}
		StringRef getDevIdString() const {
			return getTypeInfoString(devIdExpr);
		}

		bool operator==(const IRQState &X) const {
			return k == X.k && k2 == X.k2 &&
				irqVal == X.irqVal && devIdVal == X.devIdVal &&
				irqExpr == X.irqExpr && devIdExpr == X.devIdExpr;
		}

		bool operator<(const IRQState &X) const {
			if (k != X.k)
				return k < X.k;
			if (k2 != X.k2)
				return k2 < X.k2;
			if (irqExpr != X.irqExpr)
				return irqExpr < X.irqExpr;
			if (devIdExpr != X.devIdExpr)
				return devIdExpr < X.devIdExpr;
			if (irqVal != X.irqVal) {
				const ComparableSVal &l(static_cast<const ComparableSVal &>(irqVal));
				const ComparableSVal &r(static_cast<const ComparableSVal &>(X.irqVal));
				return l < r;
			}
			const ComparableSVal &l(static_cast<const ComparableSVal &>(devIdVal));
			const ComparableSVal &r(static_cast<const ComparableSVal &>(X.devIdVal));
			return l < r;
		}

		void Profile(llvm::FoldingSetNodeID &ID) const {
			ID.AddInteger(k);
			ID.AddInteger(k2);
			ID.AddPointer(irqExpr);
			ID.AddPointer(devIdExpr);
			irqVal.Profile(ID);
			devIdVal.Profile(ID);
		}
	};


} //end of anonymous namespace

//main custom state
REGISTER_SET_WITH_PROGRAMSTATE(IrqStateSet, IRQState)

namespace {

	class IRQChecker : public Checker<eval::Call, check::EndFunction, check::PreCall> {
	public:
		IRQChecker() :
			IIrequest_irq(0), IIfree_irq(0), IIrequest_threaded_irq(0) {
		}
		bool evalCall(const CallExpr * call, CheckerContext &context) const;
		void checkPreCall(const CallEvent &call, CheckerContext &context) const;
		void checkEndFunction(CheckerContext &context) const;

	private:
		mutable IdentifierInfo *IIrequest_irq, *IIfree_irq, *IIrequest_threaded_irq;

		void initIdentifierInfo(ASTContext &astContext) const;
		const FunctionDecl* ancientCaller(const LocationContext *current) const;

		void RequestIRQ(const CallExpr * call, CheckerContext &context, bool isThreaded) const;
		void FreeIRQ(const CallExpr * call, CheckerContext &context) const;

		mutable std::unique_ptr<BugType> typeNullDevId;
		void reportNullDevId(const SVal * devId, const Expr *devIdExpr, CheckerContext &context) const;
		mutable std::unique_ptr<BugType> typeDoubleRequestUniqueIrq;
		void reportDoubleRequestUniqueIrq(const IRQState &state, CheckerContext &context) const;
		mutable std::unique_ptr<BugType> typeDoubleRequestSharedIrq;
		void reportDoubleRequestSharedIrq(const IRQState &state, CheckerContext &context) const;
		mutable std::unique_ptr<BugType> typeDoubleFree;
		void reportDoubleFree(const IRQState &state, CheckerContext &context) const;
		mutable std::unique_ptr<BugType> typeFreeRequestFailedIrq;
		void reportFreeRequestFailedIrq(const IRQState &state, CheckerContext &context) const;
		mutable std::unique_ptr<BugType> typeLeakIrq;
		void reportIrqLeak(const IRQState &state, CheckerContext &context) const;
		/*
		* wrong free should be checked as leaks because of pointer escapes
		mutable std::unique_ptr<BugType> typeWrongFree;
		void reportWrongFree(const SVal *irq, const SVal *devId,
		const Expr *irqExpr, const Expr *devIdExpr, CheckerContext &context) const;
		*/
	};
} // end of anonymous namespace


void IRQChecker::initIdentifierInfo(ASTContext &astContext) const {
	if (IIrequest_irq)
		return;
	IIrequest_irq = &astContext.Idents.get("request_irq");
	IIrequest_threaded_irq = &astContext.Idents.get("request_threaded_irq");
	IIfree_irq = &astContext.Idents.get("free_irq");
}

const FunctionDecl * IRQChecker::ancientCaller(const LocationContext *current) const {
	LocationContext *context = const_cast<LocationContext *>(current);
	while (!context->inTopFrame()) {
		context = const_cast<LocationContext *>(context->getParent());
	}
	return dyn_cast_or_null<FunctionDecl>(context->getDecl());
}


bool IRQChecker::evalCall(const CallExpr *call, CheckerContext &context) const {
	const FunctionDecl *funcDecl = context.getCalleeDecl(call);
	if (!funcDecl || funcDecl->getKind() != Decl::Function)
		return false;

	initIdentifierInfo(context.getASTContext());
	const FunctionDecl *ancient = ancientCaller(context.getLocationContext());
	if (ancient && ancient->getIdentifier()->getName().startswith("Test")) {
		if (funcDecl->getIdentifier() == IIrequest_irq) {
			RequestIRQ(call, context, false);
			return true;
		}
		else if (funcDecl->getIdentifier() == IIfree_irq) {
			FreeIRQ(call, context);
			return true;
		}
		else if (funcDecl->getIdentifier() == IIrequest_threaded_irq) {
			RequestIRQ(call, context, true);
			return true;
		}
	}
	return false;
}

/* pre-/post-specific function call (request_irq and free_irq) checker */

void IRQChecker::RequestIRQ(const CallExpr * call, CheckerContext &context, bool isThreaded) const {
	if (!isThreaded && call->getNumArgs() != 5)
		return;
	else if (isThreaded && call->getNumArgs() != 6)
		return;

	int devIdArg = 4, flagArg = 2;
	if (isThreaded) {
		flagArg = 3;
		devIdArg = 5;
	}

	ProgramStateRef state = context.getState();
	const LocationContext * loc = context.getLocationContext();
	SVal irqVal = state->getSVal(call->getArg(0), loc);
	SVal devIdVal = state->getSVal(call->getArg(devIdArg), loc);

	//check bad request_irq() here

	Optional<nonloc::ConcreteInt> flagNum = state->getSVal(call->getArg(flagArg), loc).getAs<nonloc::ConcreteInt>();
	bool isShared = flagNum.hasValue() && (flagNum->getValue().getLimitedValue() & IRQF_SHARED);
	if (isShared && devIdVal.isZeroConstant()) {
		reportNullDevId(&devIdVal, call->getArg(devIdArg)->IgnoreParenCasts(), context);
		return;
	}

	for (const IRQState &prevIrqState : state->get<IrqStateSet>()) {
		if (prevIrqState.isSameIrq(irqVal) && prevIrqState.isRequested()) {
			if (!isShared || prevIrqState.isUnique()) {
				reportDoubleRequestUniqueIrq(prevIrqState, context);
				return;
			}
			if (isShared && prevIrqState.isShared() && prevIrqState.isSameDevId(devIdVal)) {
				reportDoubleRequestSharedIrq(prevIrqState, context);
				return;
			}
		}
	}

	//transit the program state

	SValBuilder &svalBuilder = context.getSValBuilder();
	DefinedSVal retVal = svalBuilder.conjureSymbolVal(0, call, loc,
		context.blockCount()).castAs<DefinedSVal>();
	state = state->BindExpr(call, loc, retVal);

	DefinedSVal zero = svalBuilder.makeIntVal(0, context.getASTContext().IntTy);
	SVal retValIsZero = svalBuilder.evalEQ(state, retVal, zero);
	SVal retValIslowerThanZero =
		svalBuilder.evalBinOp(state, BinaryOperatorKind::BO_LT, retVal, zero, context.getASTContext().IntTy);
	DefinedSVal successCond = retValIsZero.castAs<DefinedSVal>();
	DefinedSVal failureCond = retValIslowerThanZero.castAs<DefinedSVal>();

	ConstraintManager &constMgr = context.getConstraintManager();
	ProgramStateRef stateNotFail, stateFail;
	stateNotFail = constMgr.assume(state, successCond, true);
	stateFail = constMgr.assume(state, failureCond, true);

	const Expr * irqExpr = call->getArg(0)->IgnoreParenCasts();
	const Expr * devIdExpr = call->getArg(devIdArg)->IgnoreParenCasts();
	stateNotFail = stateNotFail->add<IrqStateSet>(IRQState::getRequested(!isShared, irqExpr, devIdExpr, irqVal, devIdVal));
	stateFail = stateFail->add<IrqStateSet>(IRQState::getRequestFailed(!isShared, irqExpr, devIdExpr, irqVal, devIdVal));

	context.addTransition(stateNotFail);
	context.addTransition(stateFail);

	llvm::errs() << "[IRQChecker] ADD: " << irqVal;
	irqVal.dumpToStream(llvm::errs());
	irqVal.dump();
	fprintf(stderr, "| ");
	devIdVal.dump();
	fprintf(stderr, " (");
	call->getSourceRange().getBegin().dump(context.getSourceManager());
	fprintf(stderr, ")\n");
}

void IRQChecker::FreeIRQ(const CallExpr * call, CheckerContext &context) const {
	if (call->getNumArgs() != 2)
		return;

	ProgramStateRef state = context.getState();
	const LocationContext * loc = context.getLocationContext();
	SVal irqVal = state->getSVal(call->getArg(0), loc);
	SVal devIdVal = state->getSVal(call->getArg(1), loc);

	fprintf(stderr, "[IRQChecker] DEL: ");
	irqVal.dump();
	fprintf(stderr, "| ");
	devIdVal.dump();
	fprintf(stderr, " (");
	call->getSourceRange().getBegin().dump(context.getSourceManager());
	fprintf(stderr, ")\n");

	for (const IRQState &prevIrqState : state->get<IrqStateSet>()) {
		if (prevIrqState.isSameIrq(irqVal) && prevIrqState.isSameDevId(devIdVal)) {
			if (prevIrqState.isRequested()) {
				// Generate the next transition, in which the irq is freed.
				state = state->remove<IrqStateSet>(prevIrqState);
				state = state->add<IrqStateSet>(IRQState::getFreed(prevIrqState));
				context.addTransition(state);
			}
			else if (prevIrqState.isFreed()) {
				reportDoubleFree(prevIrqState, context);
			}
			else if (prevIrqState.isRequestFailed()) {
				reportFreeRequestFailedIrq(prevIrqState, context);
			}
			return;
		}
	}
	//here, we couldn't find any irqs which are already requested due to pointer escapes or something
	//but we may be able to detect double free later, so mark the freed irq.
	const Expr * irqExpr = call->getArg(0)->IgnoreParenCasts();
	const Expr * devIdExpr = call->getArg(1)->IgnoreParenCasts();
	state = state->add<IrqStateSet>(IRQState::getFreed(true, irqExpr, devIdExpr, irqVal, devIdVal));
	context.addTransition(state);

	// wrong free should be checked as leaks in the case of pointer escapes
	//reportWrongFree(&irqVal, &devIdVal, irqExpr, devIdExpr, context);
}

void IRQChecker::checkPreCall(const CallEvent &call, CheckerContext &context) const {
	initIdentifierInfo(context.getASTContext());

	if (call.getCalleeIdentifier() == IIrequest_irq ||
		call.getCalleeIdentifier() == IIrequest_threaded_irq ||
		call.getCalleeIdentifier() == IIfree_irq)
		return;

	const FunctionDecl *ancient = ancientCaller(context.getLocationContext());
	if (!ancient || !ancient->getIdentifier()->getName().startswith("Test"))
		return;

	if (const FunctionDecl *calleeDecl = dyn_cast_or_null<FunctionDecl>(call.getDecl())) {
		if (calleeDecl->hasBody())
			return; // if the analyzer can traverse the function, we let the analyzer handle pointer escapes.
	}

	//handle pointer escape

	ProgramStateRef state = context.getState();
	std::set<IRQState> remove;
	std::set<IRQState> add;

	for (unsigned int i = 0; i < call.getNumArgs(); i++) {
		SVal arg = call.getArgSVal(i);
		const MemRegion * mem = arg.getAsRegion();
		SymbolRef sym = arg.getAsSymbol();
		if (!mem)
			continue; // not a pointer

		for (const IRQState &irqState : state->get<IrqStateSet>()) {
			if ((irqState.isRequested()) &&
				(irqState.isIrqInRegionOf(mem) || irqState.isDevIdInRegionOf(mem) ||
				(irqState.isSameIrq(sym) || irqState.isSameDevId(sym)))) {
				fprintf(stderr, "[IRQChecker] ESCAPE: ");
				sym->dump();
				fprintf(stderr, " (");
				call.getOriginExpr()->getSourceRange().getBegin().dump(context.getSourceManager());
				fprintf(stderr, ")\n");
				remove.insert(irqState);
				add.insert(IRQState::getEscaped(irqState));
			}
		}
	}
	for (IRQState dead : remove) {
		state = state->remove<IrqStateSet>(dead);
	}
	for (IRQState dead : add) {
		state = state->add<IrqStateSet>(dead);
	}
	if (!remove.empty())
		context.addTransition(state);
}

void IRQChecker::checkEndFunction(CheckerContext &context) const {
	//check if we are in a test function
	const LocationContext *currCtxt = context.getLocationContext();
	if (!currCtxt->inTopFrame())
		return;
	const FunctionDecl *currFunc = dyn_cast_or_null<FunctionDecl>(currCtxt->getDecl());
	if (!currFunc || !currFunc->getIdentifier()->getName().startswith("Test"))
		return;

	ProgramStateRef state = context.getState();
	for (const IRQState &irqState : state->get<IrqStateSet>()) {
		if (irqState.isRequested()) {
			reportIrqLeak(irqState, context);
			return;
		}
	}
}


/* reporter methods...*/

void IRQChecker::reportNullDevId(const SVal * devId, const Expr *devIdExpr, CheckerContext &context) const {
	if (ExplodedNode *node = context.generateSink()) {
		if (!typeNullDevId)
			typeNullDevId.reset(new BugType(this, "Request Null dev ID", "IRQ Error"));

		SmallString<50> buf;
		llvm::raw_svector_ostream os(buf);
		os << getTypeInfoString(devIdExpr) << " is null despite shared irq request";
		BugReport *reporter = new BugReport(*typeNullDevId, os.str(), node);
		reporter->addRange(devIdExpr->getSourceRange());
		reporter->markInteresting(*devId);
		context.emitReport(reporter);
	}
}

void IRQChecker::reportDoubleRequestUniqueIrq(const IRQState &state, CheckerContext &context) const {
	if (ExplodedNode *node = context.generateSink()) {
		if (!typeDoubleRequestUniqueIrq)
			typeDoubleRequestUniqueIrq.reset(new BugType(this, "Double Request Unique IRQ", "IRQ Error"));

		SmallString<50> buf;
		llvm::raw_svector_ostream os(buf);
		os << state.getIrqString() << " is already requested";
		BugReport *reporter = new BugReport(*typeDoubleRequestUniqueIrq, os.str(), node);
		state.markForBugReport(reporter);
		context.emitReport(reporter);
	}
}

void IRQChecker::reportDoubleRequestSharedIrq(const IRQState &state, CheckerContext &context) const {
	if (ExplodedNode *node = context.generateSink()) {
		if (!typeDoubleRequestSharedIrq)
			typeDoubleRequestSharedIrq.reset(new BugType(this, "Double Request Shared IRQ", "IRQ Error"));

		SmallString<50> buf;
		llvm::raw_svector_ostream os(buf);
		os << state.getIrqString() << " is already requested with the same dev id";
		BugReport *reporter = new BugReport(*typeDoubleRequestSharedIrq, os.str(), node);
		state.markForBugReport(reporter);
		context.emitReport(reporter);
	}
}

void IRQChecker::reportDoubleFree(const IRQState &state, CheckerContext &context) const {
	if (ExplodedNode *node = context.generateSink()) {
		if (!typeDoubleFree)
			typeDoubleFree.reset(new BugType(this, "Double Free IRQ", "IRQ Error"));

		SmallString<50> buf;
		llvm::raw_svector_ostream os(buf);
		os << state.getIrqString() << " with " << state.getDevIdString() << " is already freed";
		BugReport *reporter = new BugReport(*typeDoubleFree, os.str(), node);
		state.markForBugReport(reporter);
		context.emitReport(reporter);
	}
}

void IRQChecker::reportFreeRequestFailedIrq(const IRQState &state, CheckerContext &context) const {
	if (ExplodedNode *node = context.generateSink()) {
		if (!typeFreeRequestFailedIrq)
			typeFreeRequestFailedIrq.reset(new BugType(this, "Free request-failed IRQ", "IRQ Error"));

		SmallString<50> buf;
		llvm::raw_svector_ostream os(buf);
		os << state.getIrqString() << " is freed on request_irq failure path";
		BugReport *reporter = new BugReport(*typeFreeRequestFailedIrq, os.str(), node);
		state.markForBugReport(reporter);
		context.emitReport(reporter);
	}
}

void IRQChecker::reportIrqLeak(const IRQState &state, CheckerContext &context) const {
	if (ExplodedNode *node = context.generateSink()) {
		if (!typeLeakIrq)
			typeLeakIrq.reset(new BugType(this, "IRQ Leak", "IRQ Error"));

		SmallString<100> buf;
		llvm::raw_svector_ostream os(buf);
		os << state.getIrqString() << " with " << state.getDevIdString() << " is never freed";
		BugReport *reporter = new BugReport(*typeLeakIrq, os.str(), node);
		state.markForBugReport(reporter);
		context.emitReport(reporter);
	}
}


// register this checker
void registerIRQChecker(CheckerRegistry &registry) {
	registry.addChecker<IRQChecker>("linux.IRQChecker", "Checks the consistency between request_irq and free_irq");
}
