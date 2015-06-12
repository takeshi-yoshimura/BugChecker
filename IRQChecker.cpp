#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/CheckerRegistry.h"
#include "MyBugReporter.h"

using namespace clang;
using namespace ento;

namespace {
	class UniqueIRQ {
	private:
		class ComparableSVal : public SVal {
		public:
			bool operator<(const ComparableSVal &other) const {
				return Data < other.Data; // It seems like Data is always unique unless the same or copied SVal
			}
		};

		const SVal irqVal, devIdVal;

		// always find the region that stores the value (e.g., return &sym even if typeof(sym) == int *)
		const MemRegion * getRegionStoring(SymbolRef sym) const {
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
			return nullptr; // the root region is not a symbol, so we return a nullptr
		}

		bool isInRegionOf(const MemRegion * region, const SVal &val) const {
			SymbolRef rootSym = val.getAsSymbol();
			while (const MemRegion * mem = getRegionStoring(rootSym)) {
				MemRegion * root = nullptr;
				if (const SymbolRegionValue * symRegion = dyn_cast_or_null<SymbolRegionValue>(rootSym)) {
					root = const_cast<MemRegion *>(symRegion->getRegion()->getBaseRegion());
				}
				else if (const SymbolMetadata *symRegion = dyn_cast_or_null<SymbolMetadata>(rootSym)) {
					root = const_cast<MemRegion *>(symRegion->getRegion()->getBaseRegion());
				}
				else if (const SymbolExtent *symRegion = dyn_cast_or_null<SymbolExtent>(rootSym)) {
					root = const_cast<MemRegion *>(symRegion->getRegion()->getBaseRegion());
				}
				else if (const SymbolDerived *symRegion = dyn_cast_or_null<SymbolDerived>(rootSym)) {
					root = const_cast<MemRegion *>(symRegion->getRegion()->getBaseRegion());
				}

				if (const SymbolicRegion *rootRegion = dyn_cast_or_null<SymbolicRegion>(root)) {
					rootSym =  rootRegion->getSymbol(); //a root region is usually a symbol
				}
				else {
					rootSym = nullptr;
				}
				if (mem->isSubRegionOf(region))
					return true;
			}
			return false;
		}

	public:
		UniqueIRQ(const SVal &irqVal_, const SVal &devIdVal_) : irqVal(irqVal_), devIdVal(devIdVal_) {}
		UniqueIRQ(const UniqueIRQ &other) : irqVal(other.irqVal), devIdVal(other.devIdVal) {}

		bool contains(const SymbolRef sym) const {
			return sym != nullptr && (irqVal.getAsSymbol() == sym || devIdVal.getAsSymbol() == sym);
		}

		bool isSameIrqValAs(const UniqueIRQ &irq) const {
			return irqVal == irq.irqVal;
		}

		int generateNewID() const {
			static int ID = 0;
			return ID++;
		}

		const SVal &getIrqVal() const {
			return irqVal;
		}
		const SVal &getDevIdVal() const {
			return devIdVal;
		}

		bool isSameRegionAs(const UniqueIRQ &other) const {
			const MemRegion * othIrqRegion = getRegionStoring(other.irqVal.getAsSymbol());
			const MemRegion * othDevIdRegion = getRegionStoring(other.devIdVal.getAsSymbol());
			const MemRegion * irqRegion = getRegionStoring(irqVal.getAsSymbol());
			const MemRegion * devIdRegion = getRegionStoring(devIdVal.getAsSymbol());
			return irqRegion == othIrqRegion && devIdRegion == othDevIdRegion;
		}

		bool overlap(const MemRegion *mem) const {
			return isInRegionOf(mem, irqVal) || isInRegionOf(mem, devIdVal);
		}

		bool overlap(SymbolRef sym) const {
			return isInRegionOf(getRegionStoring(sym), irqVal) || isInRegionOf(getRegionStoring(sym), devIdVal);
		}

		bool operator==(const UniqueIRQ &other) const {
			return irqVal == other.irqVal && devIdVal == other.devIdVal;
		}
		bool operator<(const UniqueIRQ &other) const {
			if (irqVal != other.irqVal) {
				return static_cast<const ComparableSVal &>(irqVal) < static_cast<const ComparableSVal &>(other.irqVal);
			}
			return static_cast<const ComparableSVal &>(devIdVal) < static_cast<const ComparableSVal &>(other.devIdVal);
		}
		void Profile(llvm::FoldingSetNodeID &ID) const {
			irqVal.Profile(ID);
			devIdVal.Profile(ID);
		}
		void dump() const {
			llvm::errs() << "irq: ";
			irqVal.dump();
			llvm::errs() << " | ";
			devIdVal.dump();
			llvm::errs() << "\n";
		}
	};

#define IRQF_SHARED 0x00000080 // include/linux/interrupt.h

	class IRQState {
	public:
		enum Kind {
			Requested, RequestFailed, Freed, Escaped, FreeAfterEscape, DoubleEscaped, //running states
			DoubleRequested, ZeroDevId, CannotShare, FreeFailed, WrongFree, DoubleFree, Leak, // buggy states (WrongFree is unused)
			End, EscapedEnd, Corrupt // non-buggy states
		};
		static const std::map<IRQState::Kind, const std::string> displayNameMap; // constant value. see the init code after this class

	private:
		const Kind k;
		const UniqueIRQ irq;
		const bool sharable;

		IRQState(Kind k_, const UniqueIRQ &irq_, bool sharable_) : k(k_), irq(irq_), sharable(sharable_) {}

	public:

		static IRQState getNewState(Kind k_, const UniqueIRQ &irq_, bool sharable_) {
			if (k_ < Requested || k_ > Corrupt) {
				assert(false && "Try to get nonexisting IRQState kind");
				return IRQState(Corrupt, irq_, sharable_);
			}
			return IRQState(k_, irq_, sharable_);
		}

		static IRQState getNewState(Kind k_, const IRQState &other) {
			return IRQState(k_, other.irq, other.sharable);
		}

		const Kind getKind() const {
			return k;
		}

		bool isSharable() const {
			return sharable;
		}

		const UniqueIRQ & getTrackingIRQ() const {
			return irq;
		}

		bool operator==(const IRQState &X) const {
			return k == X.k && irq == X.irq && sharable == X.sharable;
		}

		void Profile(llvm::FoldingSetNodeID &ID) const {
			ID.AddInteger(k);
			ID.AddBoolean(sharable);
		}
	};

	const std::map<IRQState::Kind, const std::string> IRQState::displayNameMap = {
		{ Requested, "Request irq" },
		{ RequestFailed, "Failed to request irq" },
		{ Freed, "Free irq" },
		{ Escaped, "Escape irq" },
		{ FreeAfterEscape, "Free irq" },
		{ DoubleEscaped, "Escape irq" },
		{ DoubleRequested, "Double requested" },
		{ ZeroDevId, "Zero dev_id for shared IRQ" },
		{ CannotShare, "Share unsharable IRQ" },
		{ WrongFree, "Free non-existent IRQ" }, // not used
		{ FreeFailed, "Free request-failed IRQ" },
		{ DoubleFree, "Double Free IRQ" },
		{ Leak, "Leak IRQ" },
		{ End, "End of analysis (Passed)" },
		{ EscapedEnd, "End of analysis (Escaped)" },
		{ Corrupt, "Checker bug" },
	};

	class IRQChecker : public Checker < eval::Call, check::PreCall, check::EndFunction, check::PreStmt<BinaryOperator>, check::EndAnalysis, check::PointerEscape, check::ConstPointerEscape > {
	public:
		bool evalCall(const CallExpr * call, CheckerContext &context) const;
		void checkPreCall(const CallEvent &call, CheckerContext &context) const;
		void checkEndFunction(CheckerContext &context) const;
		ProgramStateRef checkPointerEscape(ProgramStateRef state, const InvalidatedSymbols &escaped, const CallEvent *call, PointerEscapeKind kind) const;
		ProgramStateRef checkConstPointerEscape(ProgramStateRef state, const InvalidatedSymbols &escaped, const CallEvent *call, PointerEscapeKind kind) const;
		void checkPreStmt(const BinaryOperator *binOp, CheckerContext &context) const;
		void checkEndAnalysis(ExplodedGraph &graph, BugReporter &reporter, ExprEngine &eng) const;

		struct ExecutionSummary {
			std::map<int, std::pair<ExplodedNode *, std::string>> bugNodes;

			SourceLocation endLoc; // the end of Test* function
			ExplodedNode * endNode = nullptr; // representative node for passed (no-bugs-found) end
			bool escaped = false;
			std::map<SourceLocation, ExplodedNode *> hintNodes; // hints for diagnosing
			std::map<SourceLocation, std::string> hintMsgs; // hints for diagnosing
			std::set<const Stmt *> passedStmts;
		};

	private:
		const FunctionDecl* ancientCaller(const LocationContext *current) const;
		const ProgramStateRef trackState(ProgramStateRef state, const IRQState &irqState) const;
		void RequestIRQ(const CallExpr * call, CheckerContext &context, bool isThreaded) const;
		void FreeIRQ(const CallExpr * call, CheckerContext &context) const;
		ProgramStateRef checkPointerEscapeAux(ProgramStateRef state, const InvalidatedSymbols &escaped) const;
		std::set<int> handlePointerEscape(ProgramStateRef state, const SVal &val) const;
		const Stmt * getStmtFromProgramPoint(const ProgramPoint &p) const;

		class IRQBugVisitor : public BugReporterVisitorImpl<IRQBugVisitor> {
		protected:
			int id;
			bool IsLeak;

		public:
			IRQBugVisitor(int id_, bool isLeak = false): id(id_), IsLeak(isLeak) {}
			~IRQBugVisitor() override {}

			void Profile(llvm::FoldingSetNodeID &ID) const override {
				static int X = 0;
				ID.AddPointer(&X);
				ID.AddInteger(id);
			}

			PathDiagnosticPiece *VisitNode(const ExplodedNode *N, const ExplodedNode *PrevN, BugReporterContext &BRC, BugReport &BR) override;

			std::unique_ptr<PathDiagnosticPiece> getEndPath(BugReporterContext &BRC, const ExplodedNode *EndPathNode, BugReport &BR) override {
				if (!IsLeak)
					return nullptr;

				PathDiagnosticLocation L = PathDiagnosticLocation::createEndOfPath(EndPathNode, BRC.getSourceManager());
				// Do not add the statement itself as a range in case of leak.
				return llvm::make_unique<PathDiagnosticEventPiece>(L, BR.getDescription(), false);
			}
		};
	};
} //end of anonymous namespace

// main custom state: <irq ID, irq_state>, irq ID = first tracked irq name
REGISTER_MAP_WITH_PROGRAMSTATE(IRQStateMap, int, IRQState)
REGISTER_MAP_WITH_PROGRAMSTATE(RevIRQID, UniqueIRQ, int)

namespace {
	const FunctionDecl * IRQChecker::ancientCaller(const LocationContext *current) const {
		LocationContext *context = const_cast<LocationContext *>(current);
		while (!context->inTopFrame()) {
			context = const_cast<LocationContext *>(context->getParent());
		}
		return dyn_cast_or_null<FunctionDecl>(context->getDecl());
	}

	const ProgramStateRef IRQChecker::trackState(ProgramStateRef state, const IRQState &irqState) const {
		const UniqueIRQ &irq = irqState.getTrackingIRQ();
		// check if irq we try to track is known one
		if (const int * id = state->get<RevIRQID>(irq)) {
			const IRQState *irqState = state->get<IRQStateMap>(*id);
			if (irqState->getTrackingIRQ() == irq) {
				// we know this irq. just update the current state
				state = state->set<IRQStateMap>(*id, *irqState);
				return state;
			}
		}
		// we do not handle re-request of escaped IRQs. they should be considered as different IRQs

		// create new state space
		int newID = irq.generateNewID();
		state = state->set<IRQStateMap>(newID, irqState);
		state = state->set<RevIRQID>(irq, newID);
		return state;
	}

	bool IRQChecker::evalCall(const CallExpr *call, CheckerContext &context) const {
		const FunctionDecl *ancient = ancientCaller(context.getLocationContext());
		if (ancient && ancient->getIdentifier()->getName().startswith("Test")) {
			const FunctionDecl *funcDecl = context.getCalleeDecl(call);
			if (!funcDecl) {
				return false; // function pointer?
			}
			if (funcDecl->getIdentifier()->getName() == "request_irq" && call->getNumArgs() == 5) {
				RequestIRQ(call, context, false);
				return true;
			}
			else if (funcDecl->getIdentifier()->getName() == "request_threaded_irq" && call->getNumArgs() == 6) {
				RequestIRQ(call, context, true);
				return true;
			}
			else if (funcDecl->getIdentifier()->getName() == "free_irq" && call->getNumArgs() == 2) {
				FreeIRQ(call, context);
				return true;
			}
		}
		else {
			context.generateSink(); // we do not need to execute more
		}
		return false;
	}

	/* pre-/post-specific function call (request_irq and free_irq) checker */

	void IRQChecker::RequestIRQ(const CallExpr * call, CheckerContext &context, bool isThreaded) const {
		int devIdArg = 4, flagArg = 2;
		if (isThreaded) {
			flagArg = 3;
			devIdArg = 5;
		}

		ProgramStateRef state = context.getState();
		const LocationContext * loc = context.getLocationContext();
		SVal irqVal = state->getSVal(call->getArg(0), loc);
		SVal devIdVal = state->getSVal(call->getArg(devIdArg), loc);
		UniqueIRQ irq(irqVal, devIdVal);

		// check double request
		if (const int * id = state->get<RevIRQID>(irq)) {
			const IRQState * prevIrqState = state->get<IRQStateMap>(*id);
			if (prevIrqState->getKind() == IRQState::Requested) {
				state = state->set<IRQStateMap>(*id, IRQState::getNewState(IRQState::DoubleRequested, *prevIrqState));
				context.generateSink(state); // summarize buggy actions at the end of analysis
				return;
			}
		}

		Optional<nonloc::ConcreteInt> flagNum = state->getSVal(call->getArg(flagArg), loc).getAs<nonloc::ConcreteInt>();
		bool isShared = flagNum.hasValue() && (flagNum->getValue().getLimitedValue() & IRQF_SHARED);
		if (isShared && devIdVal.isZeroConstant()) {
			state = state->set<IRQStateMap>(irq.generateNewID(), IRQState::getNewState(IRQState::ZeroDevId, irq, true));
			context.generateSink(state); // summarize buggy actions at the end of analysis
			return;
		}

		// check sharability
		if (isShared) {
			IRQStateMapTy irqMap = state->get<IRQStateMap>();
			for (auto i = irqMap.begin(), e = irqMap.end(); i != e; ++i) {
				if (i->second.getTrackingIRQ().isSameIrqValAs(irq) && !i->second.isSharable()) {
					state = state->set<IRQStateMap>(i->first, IRQState::getNewState(IRQState::CannotShare, i->second));
					context.generateSink(state); // summarize buggy actions at the end of analysis
					return;
				}
			}
		}

		// transit the program state

		SValBuilder &svalBuilder = context.getSValBuilder();
		DefinedSVal retVal = svalBuilder.conjureSymbolVal(0, call, loc, context.blockCount()).castAs<DefinedSVal>();
		state = state->BindExpr(call, loc, retVal);

		DefinedSVal zero = svalBuilder.makeIntVal(0, context.getASTContext().IntTy);
		SVal retValIsZero = svalBuilder.evalEQ(state, retVal, zero);
		SVal retValIslowerThanZero = svalBuilder.evalBinOp(state, BinaryOperatorKind::BO_LT, retVal, zero, context.getASTContext().IntTy);
		DefinedSVal successCond = retValIsZero.castAs<DefinedSVal>();
		DefinedSVal failureCond = retValIslowerThanZero.castAs<DefinedSVal>();

		ConstraintManager &constMgr = context.getConstraintManager();
		ProgramStateRef stateNotFail = constMgr.assume(state, successCond, true);
		ProgramStateRef stateFail = constMgr.assume(state, failureCond, true);

		stateNotFail = trackState(stateNotFail, IRQState::getNewState(IRQState::Requested, irq, isShared));
		stateFail = trackState(stateFail, IRQState::getNewState(IRQState::RequestFailed, irq, isShared));
		context.addTransition(stateNotFail);
		context.addTransition(stateFail);
	}

	void IRQChecker::FreeIRQ(const CallExpr * call, CheckerContext &context) const {
		ProgramStateRef state = context.getState();
		SVal irqVal = state->getSVal(call->getArg(0), context.getLocationContext());
		SVal devIdVal = state->getSVal(call->getArg(1), context.getLocationContext());
		UniqueIRQ irq(irqVal, devIdVal);

		if (const int *id = state->get<RevIRQID>(irq)) {
			const IRQState *irqState = state->get<IRQStateMap>(*id);

			switch (irqState->getKind()) {
			case IRQState::Requested:
				state = state->set<IRQStateMap>(*id, IRQState::getNewState(IRQState::Freed, *irqState));
				context.addTransition(state);
				break;
			case IRQState::Escaped:
			case IRQState::DoubleEscaped:
				// unreachable here, probably. see the next loop
				state = state->set<IRQStateMap>(*id, IRQState::getNewState(IRQState::FreeAfterEscape, *irqState));
				context.addTransition(state);
				break;
			case IRQState::Freed:
			case IRQState::FreeAfterEscape:
				state = state->set<IRQStateMap>(*id, IRQState::getNewState(IRQState::DoubleFree, *irqState));
				context.generateSink(state); // summarize buggy actions at the end of analysis
				break;
			case IRQState::RequestFailed:
				state = state->set<IRQStateMap>(*id, IRQState::getNewState(IRQState::FreeFailed, *irqState));
				context.generateSink(state); // summarize buggy actions at the end of analysis
				break;
			default:
				llvm::errs() << "Unrecognized state at free_irq(): " << irqState->getKind() << "\n";
				assert(false && "Unrecognized state at free_irq()");
			}
			return;
		}

		// no id does not mean we didn't request irq. check escaped ones
		IRQStateMapTy irqMap = state->get<IRQStateMap>();
		std::set<int> escapedIds;
		for (auto i = irqMap.begin(), e = irqMap.end(); i != e; ++i) {
			if (i->second.getTrackingIRQ().isSameRegionAs(irq)) {
				// irq is an escaped irq, which was tracked but conjured somewhere.
				escapedIds.insert(i->first);
			}
		}
		// move states
		for (int id : escapedIds) {
			const IRQState *irqState = state->get<IRQStateMap>(id);
			state = state->set<RevIRQID>(irq, id);
			state = state->set<IRQStateMap>(id, IRQState::getNewState(IRQState::FreeAfterEscape, *irqState));
		}
		if (escapedIds.size() > 0) {
			context.addTransition(state);
			return;
		}

		// WrongFree should be reported as Leak.
		//state = state->set<IRQStateMap>(irq.generateNewID(), IRQState::getNewState(IRQState::WrongFree, irq, false));
		//context.generateSink(state);

		state = state->set<IRQStateMap>(irq.generateNewID(), IRQState::getNewState(IRQState::FreeAfterEscape, irq, false));
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
		IRQStateMapTy irqMap = state->get<IRQStateMap>();
		for (auto i = irqMap.begin(), e = irqMap.end(); i != e; ++i) {
			int id = i->first;
			const IRQState &irqState = i->second;
			switch (irqState.getKind()) {
			case IRQState::Requested:
				state = state->set<IRQStateMap>(id, IRQState::getNewState(IRQState::Leak, irqState));
				break;
			case IRQState::Escaped:
			case IRQState::DoubleEscaped:
			case IRQState::FreeAfterEscape:
				state = state->set<IRQStateMap>(id, IRQState::getNewState(IRQState::EscapedEnd, irqState));
				break;
			default:
				state = state->set<IRQStateMap>(id, IRQState::getNewState(IRQState::End, irqState));
			}
		}
		context.generateSink(state);
	}

	ProgramStateRef IRQChecker::checkPointerEscape(ProgramStateRef state, const InvalidatedSymbols &escaped, const CallEvent *call, PointerEscapeKind kind) const {
		return checkPointerEscapeAux(state, escaped);
	}
	ProgramStateRef IRQChecker::checkConstPointerEscape(ProgramStateRef state, const InvalidatedSymbols &escaped, const CallEvent *call, PointerEscapeKind kind) const {
		return checkPointerEscapeAux(state, escaped);
	}

	ProgramStateRef IRQChecker::checkPointerEscapeAux(ProgramStateRef state, const InvalidatedSymbols &escaped) const {
		std::set<int> escapedIds;
		for (auto i = escaped.begin(), e = escaped.end(); i != e; ++i) {
			SymbolRef sym = *i;
			RevIRQIDTy idMap = state->get<RevIRQID>();
			for (auto i2 = idMap.begin(), e2 = idMap.end(); i2 != e2; ++i2) {
				UniqueIRQ irq = i2->first;
				int id = i2->second;
				const IRQState * irqState = state->get<IRQStateMap>(id);
				if ((irqState->getKind() == IRQState::Requested ||
					irqState->getKind() == IRQState::Escaped || irqState->getKind() == IRQState::DoubleEscaped) && (irq.overlap(sym) || irq.contains(sym))) {
					escapedIds.insert(id);
				}
			}
		}

		// move states
		for (int id : escapedIds) {
			const IRQState *irqState = state->get<IRQStateMap>(id);
			if (irqState->getKind() != IRQState::Escaped)
				state = state->set<IRQStateMap>(id, IRQState::getNewState(IRQState::Escaped, *irqState));
			else
				state = state->set<IRQStateMap>(id, IRQState::getNewState(IRQState::DoubleEscaped, *irqState));
		}
		return state;
	}

	/**
	 * we do not use pointer escape handlers provided by the framework
	 * because it does not report the following cases:
	 * struct A a; request_irq(a->irq,..); f(&a); // because a is not in symbolic region?
	 * struct A *a, *b;request_irq(a->irq,..); a = b;
	 */
	std::set<int> IRQChecker::handlePointerEscape(ProgramStateRef state, const SVal &val) const {
		std::set<int> escapedIds;

		SymbolRef sym = val.getAsSymbol();
		const MemRegion *mem = val.getAsRegion();
		if (!mem && !sym)
			return escapedIds;

		RevIRQIDTy idMap = state->get<RevIRQID>();
		for (auto i2 = idMap.begin(), e2 = idMap.end(); i2 != e2; ++i2) {
			UniqueIRQ irq = i2->first;
			int id = i2->second;
			const IRQState * irqState = state->get<IRQStateMap>(id);
			if ((irqState->getKind() == IRQState::Requested ||
				irqState->getKind() == IRQState::Escaped || irqState->getKind() == IRQState::DoubleEscaped) && (irq.overlap(mem) || irq.contains(sym))) {
				escapedIds.insert(id);
			}
		}
		return escapedIds;
	}

	// handle pointer escape by external calls
	void IRQChecker::checkPreCall(const CallEvent &call, CheckerContext &context) const {
		if (!call.getCalleeIdentifier())
			return;
		StringRef funcName = call.getCalleeIdentifier()->getName();
		if (funcName == "request_irq" || funcName == "request_threaded_irq" || funcName == "free_irq")
			return;

		const FunctionDecl *ancient = ancientCaller(context.getLocationContext());
		if (!ancient || !ancient->getIdentifier()->getName().startswith("Test"))
			return;

		if (const FunctionDecl *calleeDecl = dyn_cast_or_null<FunctionDecl>(call.getDecl())) {
			if (calleeDecl->hasBody())
				return; // the analyzer traverses the function
		}

		ProgramStateRef state = context.getState();

		std::set<int> escapedIds; // for avoiding escape <-> double escape transition inside this loop
		for (unsigned int i = 0; i < call.getNumArgs(); i++) {
			SVal arg = call.getArgSVal(i);
			// check escaped memory region where the analysis engine stores symbolic values for irqs
			std::set<int> newEscapedIds = handlePointerEscape(state, arg);
			escapedIds.insert(newEscapedIds.begin(), newEscapedIds.end());
		}

		// move states
		for (int id : escapedIds) {
			const IRQState *irqState = state->get<IRQStateMap>(id);
			if (irqState->getKind() != IRQState::Escaped)
				state = state->set<IRQStateMap>(id, IRQState::getNewState(IRQState::Escaped, *irqState));
			else
				state = state->set<IRQStateMap>(id, IRQState::getNewState(IRQState::DoubleEscaped, *irqState));
		}
		if (escapedIds.size() > 0)
			context.addTransition(state);
	}

	// handle pointer escapes by assign operations
	void IRQChecker::checkPreStmt(const BinaryOperator *binOp, CheckerContext &context) const {
		if (!binOp->isAssignmentOp())
			return;

		ProgramStateRef state = context.getState();
		SVal leftV = state->getSVal(binOp->getLHS()->IgnoreParenCasts(), context.getLocationContext());

		// check overwriting memory region where the analysis engine stores symbolic values for irqs
		// we ignore memcpy functions, though...
		std::set<int> escapedIds = handlePointerEscape(state, leftV);

		// move states
		for (int id : escapedIds) {
			const IRQState *irqState = state->get<IRQStateMap>(id);
			if (irqState->getKind() != IRQState::Escaped)
				state = state->set<IRQStateMap>(id, IRQState::getNewState(IRQState::Escaped, *irqState));
			else
				state = state->set<IRQStateMap>(id, IRQState::getNewState(IRQState::DoubleEscaped, *irqState));
		}
		if (escapedIds.size() > 0)
			context.addTransition(state);
	}

	const Stmt * IRQChecker::getStmtFromProgramPoint(const ProgramPoint &p) const {
		if (Optional<StmtPoint> sp = p.getAs<StmtPoint>()) {
			return sp->getStmt();
		} else if (Optional<CallExitEnd> callExit = p.getAs<CallExitEnd>()) {
			return callExit->getCalleeContext()->getCallSite();
		} else if (Optional<BlockEdge> edge = p.getAs<BlockEdge>()) {
			return edge->getSrc()->getTerminator();
		}
		return nullptr;
	}

	// summarize the results
	void IRQChecker::checkEndAnalysis(ExplodedGraph &graph, BugReporter &reporter, ExprEngine &eng) const {
		std::map<const FunctionDecl *, ExecutionSummary> execs;
		ExplodedGraph::node_iterator i = graph.nodes_begin(), e = graph.nodes_end();
		ExplodedNode *latestNodeInMain = &(*i);
		for (; i != e; ++i) {
			ProgramStateRef state = i->getState();

			// for ease of dianogsing (current framework does not provide results in header files)
			if (reporter.getSourceManager().isInMainFile(i->getCodeDecl().getSourceRange().getBegin())) {
				latestNodeInMain = &(*i);
			}
			const FunctionDecl *ancient = ancientCaller(latestNodeInMain->getLocationContext());
			ExplodedNode::succ_iterator next = i->succ_begin(), e2 = i->succ_end();
			for (; next != e2; ++next) {
				ProgramStateRef nextState = (*next)->getState();

				// find out exit points of analysis
				IRQStateMapTy irqMap = nextState->get<IRQStateMap>();
				for (auto i = irqMap.begin(), e = irqMap.end(); i != e; ++i) {
					int id = i->first;
					const IRQState &nextIrqState = i->second;
					const IRQState * irqState = state->get<IRQStateMap>(id);

					Optional<PostStmt> passed = latestNodeInMain->getLocation().getAs<PostStmt>();
					if (passed && reporter.getSourceManager().isInMainFile(passed->getStmt()->getLocStart()))
						execs[ancient].passedStmts.insert(passed->getStmt());

					if (irqState && irqState->getKind() == nextIrqState.getKind()) {
						continue;
					}

					// state is changed at the next node

					const Stmt *s = getStmtFromProgramPoint(latestNodeInMain->getLocation());
					SourceLocation loc = (s) ? s->getLocStart() : SourceLocation();
					IRQState::Kind k = nextIrqState.getKind();
					if (IRQState::Requested <= k && k <= IRQState::DoubleEscaped) {
						if (k == IRQState::RequestFailed) continue;
						if (execs[ancient].hintNodes.count(loc) == 0) {
							execs[ancient].hintNodes[loc] = latestNodeInMain;
							execs[ancient].hintMsgs[loc] = IRQState::displayNameMap.at(k) + " "; // e.g., "request irq "
						}
						std::string &orig = execs[ancient].hintMsgs[loc];
						std::string a = "#" + std::to_string(id) + " ";
						if (orig.find(" " + a) == std::string::npos)
							orig += a; // e.g., "request irq #1 #2
					} else if (k == IRQState::End || k == IRQState::EscapedEnd) {
						// we don't care whatever the report uses as the end node
						execs[ancient].endLoc = loc;
						execs[ancient].endNode = latestNodeInMain;
					} else {
						//Here, we look at a buggy node
						execs[ancient].bugNodes[id] = std::make_pair(latestNodeInMain, IRQState::displayNameMap.at(k)); //+ "@irq #" + std::to_string(id));
					}
					if (k == IRQState::EscapedEnd)
						execs[ancient].escaped = true;
				}
			}
		}

		// generate one report set (at most 3 report types) for each function in a .c file
		for (std::pair<const FunctionDecl *, ExecutionSummary> exe : execs) {
			ExecutionSummary &e = exe.second;

			// report correct paths
			if (e.endNode) {
				// create hint messages about request, free, escape points
				MyBugReporter myReporter(reporter);
				for (std::pair<SourceLocation, ExplodedNode *> hint : e.hintNodes) {
					const Stmt *s = getStmtFromProgramPoint(hint.second->getLocation());
					if (!s)
						continue;
					PathDiagnosticLocation hintPos(s, reporter.getSourceManager(), hint.second->getLocationContext());
					PathDiagnosticEventPiece *p = new PathDiagnosticEventPiece(hintPos, e.hintMsgs[hint.first], true);
					myReporter.addPiece(p);
				}
				const std::string &desc = e.escaped ? IRQState::displayNameMap.at(IRQState::Escaped) : IRQState::displayNameMap.at(IRQState::End);
				BugType bug(this, desc, e.escaped ? "IRQ:Escape" : "IRQ:NoBugs");
				PathDiagnosticLocation end = PathDiagnosticLocation::createEndOfPath(e.endNode, reporter.getSourceManager());
				BugReport * r = new BugReport(bug, desc, e.endNode, end, exe.first);
				for (const Stmt *passed : exe.second.passedStmts) {
					r->addRange(passed->getSourceRange());
				}
				myReporter.diagnoseSimple(r);
				myReporter.flush();
			}

			// report buggy paths (all the reports are independent)
			// use default BugReporter in this case
			for (std::pair<int, std::pair<ExplodedNode *, std::string>> node : e.bugNodes) {
				const std::string &desc = node.second.second;
				const Stmt *s = getStmtFromProgramPoint(node.second.first->getLocation());
				BugType * bug = new BugType(this, desc.substr(0, desc.find('@')), "IRQ:Bug");
				PathDiagnosticLocation pos(s, reporter.getSourceManager(), node.second.first->getLocationContext());

				BugReport *r = new BugReport(*bug, desc, node.second.first, pos, exe.first);
				r->addVisitor(llvm::make_unique<IRQBugVisitor>(node.first));
				reporter.emitReport(r);
			}
		}
	}

	// mostly copied from MallocChecker
	// TODO: remove this
	PathDiagnosticPiece * IRQChecker::IRQBugVisitor::VisitNode(const ExplodedNode *N, const ExplodedNode *PrevN, BugReporterContext &BRC, BugReport &BR) {
		if (Optional<PostStmt> SP = N->getLocation().getAs<PostStmt>()) {
			if (SP->getStmt() && BRC.getSourceManager().isInMainFile(SP->getStmt()->getLocStart()))
				BR.addRange(SP->getStmt()->getSourceRange());
		}
		const Stmt *S = nullptr;
		if (Optional<PostStmt> SP = PrevN->getLocation().getAs<PostStmt>()) {
			S = SP->getStmt();
			if (BRC.getSourceManager().isInMainFile(S->getLocStart()))
				BR.addRange(S->getSourceRange());
		}
		if (!S)
			return nullptr; // S is used for creating PathDiagnosticLocation

		const IRQState *RS = N->getState()->get<IRQStateMap>(id);
		const IRQState *RSPrev = PrevN->getState()->get<IRQStateMap>(id);
		if (!RS || !RSPrev || RS->getKind() == RSPrev->getKind()) {
			return nullptr;
		}

		IRQState::Kind k = RS->getKind();
		if (IRQState::Requested <= k && k <= IRQState::DoubleEscaped) {
			std::string Msg = IRQState::displayNameMap.at(k) + " #" + std::to_string(id); // e.g., "request irq #1
			StackHintGeneratorForSymbol *StackHint = nullptr;
			if (SymbolRef Sym = RS->getTrackingIRQ().getIrqVal().getAsSymbol())
				StackHint = new StackHintGeneratorForSymbol(Sym, Msg);
			PathDiagnosticLocation Pos(S, BRC.getSourceManager(), N->getLocationContext());
			return new PathDiagnosticEventPiece(Pos, Msg, true, StackHint);
		}
		return nullptr;
	}
} //end of anonymous namespace

// register this checker
void registerIRQChecker(CheckerRegistry &registry) {
	registry.addChecker<IRQChecker>("linux.irq", "Checks the consistency between request_irq and free_irq");
}
