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

		const ComparableSVal &irqVal, &devIdVal;

		// always find the region that stores the value (e.g., return &sym even if typeof(sym) == int *)
		const MemRegion * getRegionStoring(SymbolRef sym) const {
			if (const SymbolRegionValue * symRegion = dyn_cast_or_null<SymbolRegionValue>(sym)) {
				return symRegion->getRegion();
			}
			return nullptr; //constant, etc.
		}

	public:
		UniqueIRQ(const SVal &irqVal_, const SVal &devIdVal_)
			: irqVal(static_cast<const ComparableSVal &>(irqVal_)), devIdVal(static_cast<const ComparableSVal &>(devIdVal_)) {}
		UniqueIRQ(const UniqueIRQ &other) : irqVal(other.irqVal), devIdVal(other.devIdVal) {}

		bool contains(const SymbolRef sym) const {
			return irqVal.getAsSymbol() == sym || devIdVal.getAsSymbol() == sym;
		}

		bool isSameIrqValAs(const UniqueIRQ &irq) const {
			return irqVal == irq.irqVal;
		}

		int generateNewID() const {
			static int ID = 0;
			return ID++;
		}

		bool isSameRegionAs(const UniqueIRQ &other) const {
			const MemRegion * othIrqRegion = getRegionStoring(other.irqVal.getAsSymbol());
			const MemRegion * othDevIdRegion = getRegionStoring(other.devIdVal.getAsSymbol());
			const MemRegion * irqRegion = getRegionStoring(irqVal.getAsSymbol());
			const MemRegion * devIdRegion = getRegionStoring(devIdVal.getAsSymbol());
			return irqRegion == othIrqRegion && devIdRegion == othDevIdRegion;
		}

		bool operator==(const UniqueIRQ &other) const {
			return irqVal == other.irqVal && devIdVal == other.devIdVal;
		}
		bool operator<(const UniqueIRQ &other) const {
			if (irqVal != other.irqVal) {
				return irqVal < other.irqVal;
			}
			return devIdVal < other.devIdVal;
		}
		void Profile(llvm::FoldingSetNodeID &ID) const {
			irqVal.Profile(ID);
			devIdVal.Profile(ID);
		}
	};

#define IRQF_SHARED 0x00000080 // include/linux/interrupt.h

	class IRQState {
	public:
		enum Kind {
			Requested, RequestFailed, Freed, Escaped, FreeAfterEscape, DoubleEscaped,
			DoubleRequested, ZeroDevId, CannotShare, WrongFree, DoubleFree, Leak,
			End, Corrupt
		};

	private:
		const Kind k;
		const UniqueIRQ &irq;
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

	class IRQBugVisitor : public BugReporterVisitorImpl < IRQBugVisitor > {
	public:
		~IRQBugVisitor() override {}

		void Profile(llvm::FoldingSetNodeID &ID) const override {
			static int X = 0;
			ID.AddPointer(&X);
		}

		PathDiagnosticPiece *VisitNode(const ExplodedNode *N, const ExplodedNode *PrevN, BugReporterContext &BRC, BugReport &BR) override;

		std::unique_ptr<PathDiagnosticPiece> getEndPath(BugReporterContext &BRC, const ExplodedNode *EndPathNode, BugReport &BR) override {
			PathDiagnosticLocation L = PathDiagnosticLocation::createEndOfPath(EndPathNode, BRC.getSourceManager());
			// Do not add the statement itself as a range in case of leak.
			return llvm::make_unique<PathDiagnosticEventPiece>(L, BR.getDescription(), false);
		}
	};

	class IRQChecker : public Checker < eval::Call, check::EndFunction, check::PointerEscape, check::PreStmt<BinaryOperator>, check::EndAnalysis > {
	public:
		bool evalCall(const CallExpr * call, CheckerContext &context) const;
		void checkEndFunction(CheckerContext &context) const;
		ProgramStateRef checkPointerEscape(ProgramStateRef state, const InvalidatedSymbols &escaped, const CallEvent *call, PointerEscapeKind kind) const;
		ProgramStateRef checkConstPointerEscape(ProgramStateRef state, const InvalidatedSymbols &escaped, const CallEvent *call, PointerEscapeKind kind) const;
		void checkPreStmt(const BinaryOperator *binOp, CheckerContext &context) const;
		void checkEndAnalysis(ExplodedGraph &graph, BugReporter &unused, ExprEngine &eng) const;

	private:
		mutable std::map<const FunctionDecl *, BugType *> bugTypes; // must be global to generate reports correctly

		const ProgramStateRef trackState(ProgramStateRef state, const IRQState &irqState) const;
		void RequestIRQ(const CallExpr * call, CheckerContext &context, bool isThreaded) const;
		void FreeIRQ(const CallExpr * call, CheckerContext &context) const;
		ProgramStateRef checkPointerEscapeAux(ProgramStateRef state, const InvalidatedSymbols &escaped) const;

		// copied from lib/StaticChecker/Core/ExprEngine.cpp:2003
		class CollectReachableSymbolsCallback : public SymbolVisitor {
			InvalidatedSymbols Symbols;
		public:
			CollectReachableSymbolsCallback(ProgramStateRef State) {}
			const InvalidatedSymbols &getSymbols() const { return Symbols; }

			bool VisitSymbol(SymbolRef Sym) override {
				Symbols.insert(Sym);
				return true;
			}
		};
	};
} //end of anonymous namespace

// main custom state: <irq ID, irq_state>, irq ID = first tracked irq name
REGISTER_MAP_WITH_PROGRAMSTATE(IRQStateMap, int, IRQState)
REGISTER_MAP_WITH_PROGRAMSTATE(RevIRQID, UniqueIRQ, int)

namespace {
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

		// check if irq is escaped one
		for (std::pair<int, IRQState> irqPair : state->get<IRQStateMap>()) {
			if (irqPair.second.getTrackingIRQ().isSameRegionAs(irq)) {
				//irq is an escaped irq, which was tracked but conjured somewhere.
				state = state->set<RevIRQID>(irq, irqPair.first);

				switch (irqPair.second.getKind()) {
				case IRQState::Escaped:
				case IRQState::DoubleEscaped:
					state = state->set<IRQStateMap>(irqPair.first, irqState);
					break;
				default:
					//debugging purpose
					assert(false && "Unrecognized state at request_irq() or request_threaded_irq()");
				}
				return state;
			}
		}

		// create new state space
		int newID = irq.generateNewID();
		state = state->set<IRQStateMap>(newID, irqState);
		state = state->set<RevIRQID>(irq, newID);
		return state;
	}

	bool IRQChecker::evalCall(const CallExpr *call, CheckerContext &context) const {
		LocationContext *lc = const_cast<LocationContext *>(context.getLocationContext());
		while (!lc->inTopFrame()) {
			lc = const_cast<LocationContext *>(lc->getParent());
		}
		const FunctionDecl *ancient = dyn_cast_or_null<FunctionDecl>(lc->getDecl());

		if (ancient && ancient->getIdentifier()->getName().startswith("Test")) {
			const FunctionDecl *funcDecl = context.getCalleeDecl(call);
			if (funcDecl)
				return false; // function pointer?

			if (funcDecl->getIdentifier()->getName() == "request_irq" && call->getNumArgs() != 5) {
				RequestIRQ(call, context, false);
				return true;
			}
			else if (funcDecl->getIdentifier()->getName() == "request_threaded_irq" && call->getNumArgs() != 6) {
				RequestIRQ(call, context, true);
				return true;
			}
			else if (funcDecl->getIdentifier()->getName() == "free_irq" && call->getNumArgs() != 2) {
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
				context.addTransition(state);
				context.generateSink(); // summarize buggy actions at the end of analysis
				return;
			}
		}

		Optional<nonloc::ConcreteInt> flagNum = state->getSVal(call->getArg(flagArg), loc).getAs<nonloc::ConcreteInt>();
		bool isShared = flagNum.hasValue() && (flagNum->getValue().getLimitedValue() & IRQF_SHARED);
		if (isShared && devIdVal.isZeroConstant()) {
			state = state->set<IRQStateMap>(irq.generateNewID(), IRQState::getNewState(IRQState::ZeroDevId, irq, true));
			context.addTransition(state);
			context.generateSink(); // summarize buggy actions at the end of analysis
			return;
		}

		// check sharability
		if (isShared) {
			for (std::pair<int, IRQState> irqPair : state->get<IRQStateMap>()) {
				if (irqPair.second.getTrackingIRQ().isSameIrqValAs(irq) && !irqPair.second.isSharable()) {
					state = state->set<IRQStateMap>(irqPair.first, IRQState::getNewState(IRQState::CannotShare, irqPair.second));
					context.addTransition(state);
					context.generateSink(); // summarize buggy actions at the end of analysis
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

		trackState(stateNotFail, IRQState::getNewState(IRQState::Requested, irq, isShared));
		trackState(stateFail, IRQState::getNewState(IRQState::RequestFailed, irq, isShared));
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
				context.addTransition(state);
				context.generateSink(); // summarize buggy actions at the end of analysis
				break;
			case IRQState::RequestFailed:
				state = state->set<IRQStateMap>(*id, IRQState::getNewState(IRQState::WrongFree, *irqState));
				context.addTransition(state);
				context.generateSink(); // summarize buggy actions at the end of analysis
			default:
				assert(false && "Unrecognized state at free_irq()");
			}
			return;
		}

		// no id does not mean we didn't request irq. check escaped ones
		for (std::pair<int, IRQState> irqPair : state->get<IRQStateMap>()) {
			if (irqPair.second.getTrackingIRQ().isSameRegionAs(irq)) {
				// irq is an escaped irq, which was tracked but conjured somewhere.
				state = state->set<RevIRQID>(irq, irqPair.first);

				switch (irqPair.second.getKind()) {
				case IRQState::Escaped:
				case IRQState::DoubleEscaped:
					state = state->set<IRQStateMap>(irqPair.first, IRQState::getNewState(IRQState::FreeAfterEscape, irqPair.second));
					break;
				default:
					//debugging purpose
					assert(false && "Unrecognized state at free_irq()");
				}
				return;
			}
		}

		// we couldn't find out irq so generate a sink to summarize afterwards. probably inconsistent arguments.
		state = state->set<IRQStateMap>(irq.generateNewID(), IRQState::getNewState(IRQState::WrongFree, irq, false));
		context.addTransition(state);
		context.generateSink();
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
		for (std::pair<int, IRQState> irqPair : state->get<IRQStateMap>()) {
			int id = irqPair.first;
			IRQState &irqState = irqPair.second;
			if (irqState.getKind() == IRQState::Requested)
				state = state->set<IRQStateMap>(id, IRQState::getNewState(IRQState::Leak, irqState));
			else
				state = state->set<IRQStateMap>(id, IRQState::getNewState(IRQState::End, irqState));
			context.addTransition(state);
		}
		context.generateSink();
	}

	ProgramStateRef IRQChecker::checkPointerEscape(ProgramStateRef state, const InvalidatedSymbols &escaped, const CallEvent *call, PointerEscapeKind kind) const {
		return checkPointerEscapeAux(state, escaped);
	}

	ProgramStateRef IRQChecker::checkConstPointerEscape(ProgramStateRef state, const InvalidatedSymbols &escaped, const CallEvent *call, PointerEscapeKind kind) const {
		return checkPointerEscapeAux(state, escaped);
	}

	ProgramStateRef IRQChecker::checkPointerEscapeAux(ProgramStateRef state, const InvalidatedSymbols &escaped) const {
		for (InvalidatedSymbols::const_iterator I = escaped.begin(), E = escaped.end(); I != E; ++I) {
			SymbolRef sym = *I;
			for (std::pair<UniqueIRQ, int> irqPair : state->get<RevIRQID>()) {
				UniqueIRQ irq = irqPair.first;
				int id = irqPair.second;
				if (!irq.contains(sym))
					continue;
				const IRQState *irqState = state->get<IRQStateMap>(id);
				if (irqState->getKind() != IRQState::Escaped)
					state = state->set<IRQStateMap>(id, IRQState::getNewState(IRQState::Escaped, *irqState));
				else
					state = state->set<IRQStateMap>(id, IRQState::getNewState(IRQState::DoubleEscaped, *irqState));
			}
		}
		return state;
	}

	void IRQChecker::checkPreStmt(const BinaryOperator *binOp, CheckerContext &context) const {
		if (!binOp->isAssignmentOp())
			return;

		ProgramStateRef state = context.getState();
		SVal leftV = state->getSVal(binOp->getLHS()->IgnoreParenCasts(), context.getLocationContext());
		SymbolRef lhs = leftV.getAsSymbol();
		if (!lhs)
			return; //can be reachable??

		// check overwriting memory region where the analysis engine stores symbolic values for irqs
		// we ignore memcpy functions, though...
		CollectReachableSymbolsCallback scan = state->scanReachableSymbols<CollectReachableSymbolsCallback>(leftV);
		const InvalidatedSymbols &escaped = scan.getSymbols();

		std::set<int> escapedIds, doubleEscapedIds; // for avoiding escape <-> double escape transition inside this loop
		for (InvalidatedSymbols::const_iterator i = escaped.begin(), e = escaped.end(); i != e; ++i) {
			SymbolRef sym = *i;
			for (std::pair<UniqueIRQ, int> irqPair : state->get<RevIRQID>()) {
				UniqueIRQ irq = irqPair.first;
				int id = irqPair.second;
				if (!irq.contains(sym))
					continue;
				const IRQState *irqState = state->get<IRQStateMap>(id);
				if (irqState->getKind() != IRQState::Escaped)
					escapedIds.insert(id);
				else
					doubleEscapedIds.insert(id);
			}
		}

		// move states
		for (int id : escapedIds) {
			const IRQState *irqState = state->get<IRQStateMap>(id);
			state = state->set<IRQStateMap>(id, IRQState::getNewState(IRQState::Escaped, *irqState));
		}
		for (int id : doubleEscapedIds) {
			const IRQState *irqState = state->get<IRQStateMap>(id);
			state = state->set<IRQStateMap>(id, IRQState::getNewState(IRQState::DoubleEscaped, *irqState));
		}
	}

	void IRQChecker::checkEndAnalysis(ExplodedGraph &graph, BugReporter &unused, ExprEngine &eng) const {
		MyBugReporter reporter(eng.getAnalysisManager(), eng);

		// summarize the results
		std::map<const FunctionDecl *, const Stmt *> exitPoints;
		std::map<const FunctionDecl *, std::set<StringRef>> descriptions;
		std::set<const FunctionDecl *> bugFound;
		std::set<const FunctionDecl *> escaped;
		ExplodedGraph::node_iterator i = graph.nodes_begin(), next = ++graph.nodes_begin(), e = graph.nodes_end();
		for (; next != e; ++next, ++i) {
			ProgramStateRef state = i->getState();
			ProgramStateRef nextState = next->getState();

			// find out exit points of analysis
			for (std::pair<int, IRQState> irqPair : nextState->get<IRQStateMap>()) {
				int id = irqPair.first;
				IRQState &nextIrqState = irqPair.second;
				const IRQState * irqState = state->get<IRQStateMap>(id);

				if (irqState && irqState->getKind() == nextIrqState.getKind()) {
					continue;
				}
				// state is changed at next node
				ProgramPoint p = i->getLocation();
				const FunctionDecl *funcDecl = dyn_cast_or_null<FunctionDecl>(p.getLocationContext()->getDecl());
				if (!funcDecl)
					continue;

				switch (nextIrqState.getKind()) {
				case IRQState::Requested:
				case IRQState::RequestFailed:
				case IRQState::Freed:
				case IRQState::End:
					// ignore normal transitions
					continue;
				case IRQState::Escaped:
				case IRQState::FreeAfterEscape:
				case IRQState::DoubleEscaped:
					descriptions[funcDecl].insert(StringRef("Escaped"));
					escaped.insert(funcDecl);
					break;
				case IRQState::DoubleRequested:
					descriptions[funcDecl].insert(StringRef("Double Requested"));
					bugFound.insert(funcDecl);
					break;
				case IRQState::ZeroDevId:
					descriptions[funcDecl].insert(StringRef("Zero dev_id for shared IRQ"));
					bugFound.insert(funcDecl);
					break;
				case IRQState::CannotShare:
					descriptions[funcDecl].insert(StringRef("Share unsharable IRQ"));
					bugFound.insert(funcDecl);
					break;
				case IRQState::WrongFree:
					descriptions[funcDecl].insert(StringRef("Free non-existing or request-failed IRQ"));
					bugFound.insert(funcDecl);
					break;
				case IRQState::DoubleFree:
					descriptions[funcDecl].insert(StringRef("Double Free"));
					bugFound.insert(funcDecl);
					break;
				case IRQState::Leak:
					descriptions[funcDecl].insert(StringRef("Leak"));
					bugFound.insert(funcDecl);
					break;
				case IRQState::Corrupt:
					descriptions[funcDecl].insert(StringRef("Checker inconsistency"));
					bugFound.insert(funcDecl);
					break;
				}

				// next node has escaped or buggy state here
				const Stmt *stmt = nullptr;
				if (Optional<StmtPoint> sp = p.getAs<StmtPoint>()) {
					stmt = sp->getStmt();
				}
				else if (Optional<CallExitEnd> exit = p.getAs<CallExitEnd>()) {
					stmt = exit->getCalleeContext()->getCallSite();
				}
				else if (Optional<BlockEdge> edge = p.getAs<BlockEdge>()) {
					stmt = edge->getSrc()->getTerminator();
				}
				else {
					llvm::errs() << "Unhandled Program kind: " << p.getKind() << "\n";
					assert(false && "Unhandled ProgramPoint kind");
				}
				if (stmt && funcDecl)
					exitPoints[funcDecl] = stmt;
			}
		}
		for (std::pair<const FunctionDecl *, const Stmt *> exitPoint : exitPoints) {
			StringRef funcName = exitPoint.first->getName();
			llvm::StringRef group = bugFound.count(exitPoint.first) > 0 ? "IRQ bug" : escaped.count(exitPoint.first) > 0 ? "IRQ escaped" : "IRQ bug not found";
			llvm::SmallString<64> bugType;
			for (llvm::StringRef str : descriptions[exitPoint.first]) {
				bugType.append(str);
				bugType.append(", ");
			}
			bugType.erase(bugType.end() - 2, bugType.end());
			llvm::Twine bugGroup = group + "@" + exitPoint.first->getName();
			if (bugTypes.count(exitPoint.first) == 0)
				bugTypes[exitPoint.first] = new BugType(this, bugType, bugGroup.str());

			PathDiagnosticLocation pos(exitPoint.second, reporter.getSourceManager(), next->getLocationContext());
			BugReport *report = new BugReport(*bugTypes[exitPoint.first], StringRef("The exit point of analysis"), &(*next), pos, exitPoint.first);
			report->addVisitor(llvm::make_unique<IRQBugVisitor>());
			reporter.emitReport(report);
		}
	}

	PathDiagnosticPiece * IRQBugVisitor::VisitNode(const ExplodedNode *node, const ExplodedNode *prevNode, BugReporterContext &reporterContext, BugReport &reporter) {
		return nullptr;
		/*ProgramStateRef state = node->getState();
		ProgramStateRef prevState = prevNode->getState();
		llvm::SmallVector<StringRef, 32> requested, freed, escaped, freeAfterEscape, bug;

		if (!prevNode->isSink && node->isSink()) {

		}

		IRQState *irqState = nullptr, *prevIrqState = nullptr;
		for (std::pair<UniqueIRQ, StringRef> irqPair : prevState->get<RevIRQID>()) {
		UniqueIRQ irq = irqPair.first;
		StringRef id = irqPair.second;
		const IRQState * irqState = prevState->get<IRQStateMap>(id);

		if (const IRQState * nextIrqState = state->get<IRQStateMap>(id)) {
		}
		}

		std::multimap<enum Kind, ExplodedNode> irqEvents;
		for (; i != e; prev = i, ++i) {
		ProgramStateRef prevState = prev->getState();
		ProgramStateRef state = i->getState();
		for (std::pair<StringRef, const IRQState *> irqPair : state->get<IRQStateMap>) {
		StringRef id = irqPair.first;
		const IRQState *irqState = irqPair.second;
		const IRQState *prevIrqState = prevState->get<IRQStateMap>(id);
		if (!prevIrqState || prevIrqState->getKind() != irqState->getKind()) {
		// a new state appeared here
		irqEvents.insert(std::pair<enum Kind, ExplodedNode>(irqState->getKind(), *i));
		}
		}
		}

		const Stmt *stmt = nullptr;
		const char *msg = nullptr;

		StackHintGeneratorForSymbol *StackHint = nullptr;
		// Retrieve the associated statement.
		ProgramPoint ProgLoc = N->getLocation();
		if (Optional<StmtPoint> SP = ProgLoc.getAs<StmtPoint>()) {
		stmt = SP->getStmt();
		} else if (Optional<CallExitEnd> Exit = ProgLoc.getAs<CallExitEnd>()) {
		stmt = Exit->getCalleeContext()->getCallSite();
		} else if (Optional<BlockEdge> Edge = ProgLoc.getAs<BlockEdge>()) {
		// If an assumption was made on a branch, it should be caught
		// here by looking at the state transition.
		stmt = Edge->getSrc()->getTerminator();
		}

		if (!stmt)
		return nullptr;

		// Find out if this is an interesting point and what is the kind.
		if (isa<CallExpr>(stmt) && (irqState && irqState->isRequested()) && (!prevIrqState || !prevIrqState->isRequested())) {
		msg = "IRQ is requested";
		StackHint = new StackHintGeneratorForSymbol(val.getAsSymbol(), "Requested IRQ");
		} else if (isa<CallExpr>(stmt) && (irqState && irqState->isFreed()) && (!prevIrqState || !prevIrqState->isFreed())) {
		msg = "IRQ is freed";
		StackHint = new StackHintGeneratorForSymbol(val.getAsSymbol(), "Returning; IRQ was released");
		} else if (isa<CallExpr>(stmt) && (irqState && irqState->isEscaped()) && (!prevIrqState || !prevIrqState->isEscaped())) {
		msg = "IRQ is escaped";
		StackHint = new StackHintGeneratorForSymbol(val.getAsSymbol(), "Escaped IRQ");
		}

		if (!msg)
		return nullptr;

		// Generate the extra diagnostic.
		PathDiagnosticLocation Pos(stmt, BRC.getSourceManager(), N->getLocationContext());
		return new PathDiagnosticEventPiece(Pos, msg, true, StackHint);*/
	}
} //end of anonymous namespace

// register this checker
void registerIRQChecker(CheckerRegistry &registry) {
	registry.addChecker<IRQChecker>("linux.irq", "Checks the consistency between request_irq and free_irq");
}
