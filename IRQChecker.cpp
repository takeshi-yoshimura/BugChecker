#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/CheckerRegistry.h"


// main custom state: <irq ID, irq_state>, irq ID = first tracked irq name
REGISTER_MAP_WITH_PROGRAMSTATE(IRQStateMap, StringRef, IRQState)
REGISTER_MAP_WITH_PROGRAMSTATE(RevIRQID, UniqueIRQ, StringRef)

using namespace clang;
using namespace ento;

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

// always find the region that stores the value (e.g., return &sym even if typeof(sym) == int *)
const MemRegion * getRegionStoring(SymbolRef sym) {
	if (const SymbolRegionValue * symRegion = dyn_cast_or_null<SymbolRegionValue>(sym)) {
		return symRegion->getRegion();
	}
	return nullptr; //constant, etc.
}

class ComparableSVal : public SVal {
public:
	bool operator<(const ComparableSVal &other) const {
		return Data < other.Data; // It seems like Data is always unique unless the same or copied SVal
	}
};

class UniqueIRQ {
private:
	const ComparableSVal &irqVal, &devIdVal;
	friend class SharedIRQ;

public:
	UniqueIRQ(const SVal &irqVal_, const SVal &devIdVal_)
		: irqVal(static_cast<const ComparableSVal &>(irqVal_)), devIdVal(static_cast<const ComparableSVal &>(devIdVal_)) {}
	UniqueIRQ(const UniqueIRQ &other) : irqVal(other.irqVal), devIdVal(other.devIdVal) {}

	bool contains(const SymbolRef sym) const {
		return irqVal.getAsSymbol() == sym || devIdVal.getAsSymbol() == sym;
	}

	bool isConjured(ConstraintManager &cmgr) const {
		bool result = false;
		if (isa<const GlobalsSpaceRegion>(irqVal)) {
			result |= irqVal.hasConjuredSymbol();
		}
		if (isa<const GlobalSystemSpaceRegion>(devIdVal)) {
			result |= devIdVal.hasConjuredSymbol();
		}
		return result;
	}

	const SVal & getIrqVal() const { return irqVal; }
	const SVal & getDevIdVal() const { return devIdVal; }

	bool isSameIrqValAs(const UniqueIRQ &irq) const {
		return irqVal == irq.irqVal;
	}

	StringRef getID() const {
		SmallString<50> buf;
		llvm::raw_svector_ostream os(buf);
		os << static_cast<const SVal>(irqVal) << "::" << static_cast<const SVal>(devIdVal);
		return os.str();
	}

	bool isRegionOverlapped(SymbolRef sym) const {
		const MemRegion * symRegion = getRegionStoring(sym);
		const MemRegion * irqRegion = getRegionStoring(irqVal.getAsSymbol());
		const MemRegion * devIdRegion = getRegionStoring(devIdVal.getAsSymbol());
		return irqRegion == symRegion || devIdRegion == symRegion;
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
/*
class SharedIRQ {
private:
	const ComparableSVal &irqVal;
	llvm::ImmutableSet<ComparableSVal> devIdVals;
	llvm::ImmutableSet<ComparableSVal>::Factory f;
	SharedIRQ(const UniqueIRQ &head) : irqVal(head.irqVal), devIdVals(f.add(f.getEmptySet(), static_cast<const ComparableSVal &>(head.devIdVal))) {}

public:
	SharedIRQ(const SharedIRQ &other) : irqVal(other.irqVal), devIdVals(other.devIdVals) {}
	SharedIRQ(const SharedIRQ &other, const SVal & devIdVal_)
		: irqVal(other.irqVal), devIdVals(f.add(other.devIdVals, static_cast<const ComparableSVal &>(devIdVal_))) {}

	static SharedIRQ create(const UniqueIRQ &head_) {
		return SharedIRQ(head_);
	}

	SharedIRQ add(const SVal &devIdVal) const {
		return SharedIRQ(*this, devIdVal);
	}

	bool has(const SVal &devIdVal) const {
		return devIdVals.contains(static_cast<const ComparableSVal &>(devIdVal));
	}

	const UniqueIRQ &getHead() const {
		return head;
	}

	bool operator==(const SharedIRQ &other) const {
		return head == other.head && devIdVals == other.devIdVals;
	}
	void Profile(llvm::FoldingSetNodeID &ID) const {
		head.Profile(ID);
		for (ComparableSVal devIdVal: devIdVals)
			devIdVal.Profile(ID);
	}
};*/

class IRQBugVisitor : public BugReporterVisitorImpl <IRQBugVisitor> {
protected:
	UniqueIRQ irq;
	bool isLeak;

public:
	IRQBugVisitor(const UniqueIRQ irq_, bool isLeak_) : irq(irq_), isLeak(isLeak_) {}
	~IRQBugVisitor() override {}

	void Profile(llvm::FoldingSetNodeID &ID) const override {
		static int X = 0;
		ID.AddPointer(&X);
		irq.Profile(ID);
	}

	PathDiagnosticPiece *VisitNode(const ExplodedNode *N, const ExplodedNode *PrevN, BugReporterContext &BRC, BugReport &BR) override;

	std::unique_ptr<PathDiagnosticPiece> getEndPath(BugReporterContext &BRC, const ExplodedNode *EndPathNode, BugReport &BR) override {
		if (!isLeak)
			return nullptr;

		PathDiagnosticLocation L = PathDiagnosticLocation::createEndOfPath(EndPathNode, BRC.getSourceManager());
		// Do not add the statement itself as a range in case of leak.
		return llvm::make_unique<PathDiagnosticEventPiece>(L, BR.getDescription(), false);
	}
};

#define IRQF_SHARED 0x00000080 // include/linux/interrupt.h

class IRQState {
	const UniqueIRQ &irq;
	const bool sharable;

	enum Kind {
		Requested, RequestFailed, Freed, Escaped, FreeAfterEscape, DoubleEscaped, Corrupt
	} k;

	IRQState(Kind k_, const UniqueIRQ &irq_, bool sharable_) : k(k_), irq(irq_), sharable(sharable_) {}

public:
	bool isRequested() const { return k == Requested; }
	bool isRequestFailed() const { return k == RequestFailed; }
	bool isFreed() const { return k == Freed; }
	bool isEscaped() const { return k == Escaped; }
	bool isFreeAfterEscape() const { return k == FreeAfterEscape; }
	bool isCorrupt() const { return k == Corrupt; }
	bool isDoubleEscaped() const { return k == DoubleEscaped; }
	bool isSharable() const { return sharable; }

	static IRQState getRequested(const UniqueIRQ &irq_, bool sharable_) { return IRQState(Requested, irq_, sharable_); }
	static IRQState getRequestFailed(const UniqueIRQ &irq_, bool sharable_) { return IRQState(RequestFailed, irq_, sharable_); }
	static IRQState getFreed(const UniqueIRQ &irq_, bool sharable_) { return IRQState(Freed, irq_, sharable_); }
	static IRQState getEscaped(const UniqueIRQ &irq_, bool sharable_) { return IRQState(Escaped, irq_, sharable_); }
	static IRQState getFreeAfterEscape(const UniqueIRQ &irq_, bool sharable_) { return IRQState(FreeAfterEscape, irq_, sharable_); }
	static IRQState getDoubleEscaped(const UniqueIRQ &irq_, bool sharable_) { return IRQState(DoubleEscaped, irq_, sharable_); }
	static IRQState getCorrupt(const UniqueIRQ &irq_, bool sharable_) { return IRQState(Corrupt, irq_, sharable_); }

	static IRQState getRequested(const IRQState &other) { return IRQState(Requested, other.irq, other.sharable); }
	static IRQState getRequestFailed(const IRQState &other) { return IRQState(RequestFailed, other.irq, other.sharable); }
	static IRQState getFreed(const IRQState &other) { return IRQState(Freed, other.irq, other.sharable); }
	static IRQState getEscaped(const IRQState &other) { return IRQState(Escaped, other.irq, other.sharable); }
	static IRQState getFreeAfterEscape(const IRQState &other) { return IRQState(FreeAfterEscape, other.irq, other.sharable); }
	static IRQState getDoubleEscaped(const IRQState &other) { return IRQState(DoubleEscaped, other.irq, other.sharable); }
	static IRQState getCorrupt(const IRQState &other) { return IRQState(Corrupt, other.irq, other.sharable); }

	const UniqueIRQ & getTrackingIRQ() const { return irq; }
	bool operator==(const IRQState &X) const { return k == X.k && irq == X.irq && sharable == X.sharable; }

	void Profile(llvm::FoldingSetNodeID &ID) const { ID.AddInteger(k); ID.AddBoolean(sharable); }
};

class IRQChecker : public Checker<eval::Call, check::EndFunction, check::PreCall, check::PointerEscape, check::PreStmt<BinaryOperator>, check::EndAnalysis> {
public:
	IRQChecker() :
		IIrequest_irq(0), IIfree_irq(0), IIrequest_threaded_irq(0) {
	}
	bool evalCall(const CallExpr * call, CheckerContext &context) const;
	void checkPreCall(const CallEvent &call, CheckerContext &context) const;
	void checkEndFunction(CheckerContext &context) const;
	ProgramStateRef checkPointerEscape(ProgramStateRef state, const InvalidatedSymbols &escaped, const CallEvent *call, PointerEscapeKind kind) const;
	ProgramStateRef checkConstPointerEscape(ProgramStateRef state, const InvalidatedSymbols &escaped, const CallEvent *call, PointerEscapeKind kind) const;
	void checkPreStmt(const BinaryOperator *binOp, CheckerContext &context) const;
	void checkEndAnalysis(ExplodedGraph &graph, BugReporter &reporter, ExprEngine &eng) const;

	typedef llvm::SmallVector < std::pair<UniqueIRQ, const IRQState *>, 32 > LeakBuffer;

private:
	mutable IdentifierInfo *IIrequest_irq, *IIfree_irq, *IIrequest_threaded_irq;

	void initIdentifierInfo(ASTContext &astContext) const;
	const FunctionDecl* ancientCaller(const LocationContext *current) const;
	const ProgramStateRef trackState(ProgramStateRef state, const IRQState &irqState) const;

	void RequestIRQ(const CallExpr * call, CheckerContext &context, bool isThreaded) const;
	void FreeIRQ(const CallExpr * call, CheckerContext &context) const;
	ProgramStateRef checkPointerEscapeAux(ProgramStateRef state, const InvalidatedSymbols &escaped, const CallEvent *call, PointerEscapeKind kind) const;

	// When request_irq(Untracked IRQ, IRQF_SHARED, 0)
	mutable std::unique_ptr<BugType> typeNullDevId;
	void reportNullDevId(const SVal * devId, const Expr *devIdExpr, CheckerContext &context) const;

	// When request_irq(Requested IRQ)
	mutable std::unique_ptr<BugType> typeDoubleRequestUniqueIrq;
	void reportDoubleRequestUniqueIrq(const IRQState &state, CheckerContext &context) const;

	// When request_irq(Requested IRQ, IRQF_SHARED) but the flag for the requested irq is not sharable
	mutable std::unique_ptr<BugType> typeCannotShareIrq;
	void reportCannotShareIrq(const IRQState &state, CheckerContext &context) const;

	// When free_irq(Freed IRQ)
	mutable std::unique_ptr<BugType> typeDoubleFree;
	void reportDoubleFree(const IRQState &state, CheckerContext &context) const;

	// When free_irq(RequestFailed IRQ)
	mutable std::unique_ptr<BugType> typeFreeRequestFailedIrq;
	void reportFreeRequestFailedIrq(const IRQState &state, CheckerContext &context) const;

	// When no free_irq(Requested IRQ) at the end of Test*()
	mutable std::unique_ptr<BugType> typeLeakIrq;
	void reportLeak(const IRQState &state, CheckerContext &context) const;

	// When free_irq(Untracked IRQ, due to misplaced arguments, etc.)
	mutable std::unique_ptr<BugType> typeWrongFree;
	void reportWrongFree(const IRQState &state, CheckerContext &context) const;

	// The below two do not always report bugs but are useful for checking false positives/negatives

	// When no free_irq(Escaped IRQ) at the end of Test*()
	mutable std::unique_ptr<BugType> typeEscaped;
	void reportEscaped(const IRQState &state, CheckerContext &context) const;

	// When free_irq(Escaped IRQ, including more-than-twice escaped IRQ)
	mutable std::unique_ptr<BugType> typeFreeAfterEscape;
	void reportFreeAfterEscape(const IRQState &state, CheckerContext &context) const;

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

const ProgramStateRef IRQChecker::trackState(ProgramStateRef state, const IRQState &irqState) const {
	const UniqueIRQ &irq = irqState.getTrackingIRQ();
	// check if irq we try to track is known one
	if (const StringRef * id = state->get<RevIRQID>(irq)) {
		const IRQState *irqState = state->get<IRQStateMap>(*id);
		if (irqState->getTrackingIRQ() == irq) {
			// we know this irq. just update the current state
			state = state->set<IRQStateMap>(*id, irqState);
			return state;
		}
	}

	// check if irq is escaped one
	for (std::pair<StringRef, const IRQState *> irqPair : state->get<IRQStateMap>()) {
		if (irqPair.second->getTrackingIRQ().isSameRegionAs(irq)) {
			//irq is an escaped irq, which was tracked but conjured somewhere.
			state = state->set<RevIRQID>(irq, irqPair.first);
			if (irqPair.second->isEscaped() || irqPair.second->isDoubleEscaped())
				state = state->set<IRQStateMap>(irqPair.first, irqState);
			else
				state = state->set<IRQStateMap>(irqPair.first, IRQState::getCorrupt(*irqPair.second)); //debugging purpose
			return state;
		}
	}

	// create new state space
	state = state->set<IRQStateMap>(irq.getID(), irqState);
	state = state->set<RevIRQID>(irq, irq.getID());
	return state;
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
	UniqueIRQ irq(irqVal, devIdVal);

	// check double request
	if (const StringRef * id = state->get<RevIRQID>(irq)) {
		const IRQState * prevIrqState = state->get<IRQStateMap>(*id);
		if (prevIrqState->isRequested()) {
			reportDoubleRequestUniqueIrq(*prevIrqState, context);
			return;
		}
	}

	Optional<nonloc::ConcreteInt> flagNum = state->getSVal(call->getArg(flagArg), loc).getAs<nonloc::ConcreteInt>();
	bool isShared = flagNum.hasValue() && (flagNum->getValue().getLimitedValue() & IRQF_SHARED);
	if (isShared && devIdVal.isZeroConstant()) {
		reportNullDevId(&devIdVal, call->getArg(devIdArg)->IgnoreParenCasts(), context);
		return;
	}

	// check sharability
	if (isShared) {
		for (std::pair<StringRef, const IRQState *> irqPair : state->get<IRQStateMap>()) {
			if (!irqPair.second->getTrackingIRQ().isSameIrqValAs(irq) || irqPair.second->isSharable())
				continue;
			reportCannotShareIrq(*irqPair.second, context);
			return;
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

	trackState(stateNotFail, IRQState::getRequested(irq, isShared));
	trackState(stateFail, IRQState::getRequestFailed(irq, isShared));
	context.addTransition(stateNotFail);
	context.addTransition(stateFail);
}

void IRQChecker::FreeIRQ(const CallExpr * call, CheckerContext &context) const {
	if (call->getNumArgs() != 2)
		return;

	ProgramStateRef state = context.getState();
	const LocationContext * loc = context.getLocationContext();
	SVal irqVal = state->getSVal(call->getArg(0), loc);
	SVal devIdVal = state->getSVal(call->getArg(1), loc);
	UniqueIRQ irq(irqVal, devIdVal);

	if (const StringRef *id = state->get<RevIRQID>(irq)) {
		const IRQState *irqState = state->get<IRQStateMap>(*id);
		if (irqState->isRequested()) {
			trackState(state, IRQState::getFreed(*irqState));
			context.addTransition(state);
		} else if (irqState->isFreed() || irqState->isFreeAfterEscape()) {
			reportDoubleFree(*irqState, context);
		} else if (irqState->isRequestFailed()) {
			reportFreeRequestFailedIrq(*irqState, context);
		}
		else if (irqState->isEscaped() || irqState->isDoubleEscaped()) {
			trackState(state, IRQState::getFreeAfterEscape(*irqState)); // unreachable here, probably.
			context.addTransition(state);
		}
		return;
	}

	// no id does not mean we didn't request irq. check escaped ones
	for (std::pair<StringRef, const IRQState *> irqPair : state->get<IRQStateMap>()) {
		if (irqPair.second->getTrackingIRQ().isSameRegionAs(irq)) {
			// irq is an escaped irq, which was tracked but conjured somewhere.
			state = state->set<RevIRQID>(irq, irqPair.first);
			if (irqPair.second->isEscaped() || irqPair.second->isDoubleEscaped())
				state = state->set<IRQStateMap>(irqPair.first, IRQState::getFreeAfterEscape(*irqPair.second));
			else
				state = state->set<IRQStateMap>(irqPair.first, IRQState::getCorrupt(*irqPair.second)); //debugging purpose
			return;
		}
	}

	// we couldn't find out irq. probably inconsistent arguments.
	reportWrongFree(irq, context);
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

	if (const FunctionDecl *calleeDecl = dyn_cast_or_null<FunctionDecl>(call.getDecl()))
		if (calleeDecl->hasBody())
			return;
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
	for (std::pair<StringRef, const IRQState *> irqPair: state->get<IRQStateMap>()) {
		const IRQState *irqState = irqPair.second;
		if (irqState->isRequested()) {
			reportLeak(*irqState, context);
		} else if (irqState->isEscaped() || irqState->isDoubleEscaped()) {
			reportEscaped(*irqState, context);
		} else if (irqState->isFreeAfterEscape()) {
			reportFreeAfterEscape(*irqState, context);
		}
	}
}

ProgramStateRef IRQChecker::checkPointerEscape(ProgramStateRef state, const InvalidatedSymbols &escaped, const CallEvent *call, PointerEscapeKind kind) const {
	if (call)
		return checkPointerEscapeAux(state, escaped, call, kind);
	return state;
}

ProgramStateRef IRQChecker::checkConstPointerEscape(ProgramStateRef state, const InvalidatedSymbols &escaped, const CallEvent *call, PointerEscapeKind kind) const {
	if (call)
		return checkPointerEscapeAux(state, escaped, call, kind);
	return state;
}

ProgramStateRef IRQChecker::checkPointerEscapeAux(ProgramStateRef state, const InvalidatedSymbols &escaped, const CallEvent *call, PointerEscapeKind kind) const {
	for (InvalidatedSymbols::const_iterator I = escaped.begin(), E = escaped.end(); I != E; ++I) {
		SymbolRef sym = *I;
		for (std::pair<UniqueIRQ, StringRef> irqPair : state->get<RevIRQID>()) {
			UniqueIRQ irq = irqPair.first;
			StringRef id = irqPair.second;
			if (!irq.contains(sym))
				continue;
			const IRQState *irqState = state->get<IRQStateMap>(id);
			state = state->set<IRQStateMap>(id, !irqState->isEscaped() ? IRQState::getEscaped(*irqState) : IRQState::getDoubleEscaped(*irqState));
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

	// check overwriting memory region where symbolic values for irqs are stored
	// we ignore memcpy functions, though...
	CollectReachableSymbolsCallback scan = state->scanReachableSymbols<CollectReachableSymbolsCallback>(leftV);
	const InvalidatedSymbols &escaped = scan.getSymbols();

	std::set<StringRef> escapedIds, doubleEscapedIds; // for avoiding escape <-> double escape transition inside this loop
	for (InvalidatedSymbols::const_iterator i = escaped.begin(), e = escaped.end(); i != e; ++i) {
		SymbolRef sym = *i;
		for (std::pair<UniqueIRQ, StringRef> irqPair : state->get<RevIRQID>()) {
			UniqueIRQ irq = irqPair.first;
			StringRef id = irqPair.second;
			if (!irq.contains(sym))
				continue;
			const IRQState *irqState = state->get<IRQStateMap>(id);
			if (!irqState->isEscaped())
				escapedIds.insert(id);
			else
				doubleEscapedIds.insert(id);
		}
	}
	for (StringRef id : escapedIds) {
		const IRQState *irqState = state->get<IRQStateMap>(id);
		state = state->set<IRQStateMap>(id, IRQState::getEscaped(*irqState));
	}
	for (StringRef id : doubleEscapedIds) {
		const IRQState *irqState = state->get<IRQStateMap>(id);
		state = state->set<IRQStateMap>(id, IRQState::getDoubleEscaped(*irqState));
	}
}

void IRQChecker::checkEndAnalysis(ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng) const {
	//traverse all the graph and summarize up the result especially about escaped states and leaks
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
		state.markForBugReport(reporter, false);
		context.emitReport(reporter);
	}
}

void IRQChecker::reportCannotShareIrq(const IRQState &state, CheckerContext &context) const {
	if (ExplodedNode *node = context.generateSink()) {
		if (!typeCannotShareIrq)
			typeCannotShareIrq.reset(new BugType(this, "Cannot Share IRQ", "IRQ Error"));

		SmallString<50> buf;
		llvm::raw_svector_ostream os(buf);
		os << state.getIrqString() << " is already requested with the same dev id";
		BugReport *reporter = new BugReport(*typeCannotShareIrq, os.str(), node);
		state.markForBugReport(reporter, false);
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
		state.markForBugReport(reporter, false);
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
		state.markForBugReport(reporter, false);
		context.emitReport(reporter);
	}
}

void IRQChecker::reportLeak(const IRQState &state, CheckerContext &context) const {
	if (ExplodedNode *node = context.generateSink()) {
		if (!typeLeakIrq)
			typeLeakIrq.reset(new BugType(this, "IRQ Leak", "IRQ Error"));

		SmallString<100> buf;
		llvm::raw_svector_ostream os(buf);
		os << state.getIrqString() << " with " << state.getDevIdString() << " is never freed";
		BugReport *reporter = new BugReport(*typeLeakIrq, os.str(), node);
		state.markForBugReport(reporter, true);
		context.emitReport(reporter);
	}
}

PathDiagnosticPiece * IRQBugVisitor::VisitNode(const ExplodedNode *N, const ExplodedNode *PrevN, BugReporterContext &BRC, BugReport &BR) {
	ProgramStateRef state = N->getState();
	ProgramStateRef prevState = PrevN->getState();

	IRQState *irqState = nullptr, *prevIrqState = nullptr;

	for (IRQState i : state->get<IrqStateSet>()) {
		if (i.isSameIrq(val) || i.isSameDevId(val)) {
			irqState = &i;
		}
	}
	for (IRQState i : prevState->get<IrqStateSet>()) {
		if (i.isSameIrq(val) || i.isSameDevId(val)) {
			prevIrqState = &i;
		}
	}

	const Stmt *stmt = nullptr;
	const char *msg = nullptr;

	StackHintGeneratorForSymbol *StackHint = nullptr;
	// Retrieve the associated statement.
	ProgramPoint ProgLoc = N->getLocation();
	if (Optional<StmtPoint> SP = ProgLoc.getAs<StmtPoint>()) {
		stmt = SP->getStmt();
	}
	else if (Optional<CallExitEnd> Exit = ProgLoc.getAs<CallExitEnd>()) {
		stmt = Exit->getCalleeContext()->getCallSite();
	}
	else if (Optional<BlockEdge> Edge = ProgLoc.getAs<BlockEdge>()) {
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
	return new PathDiagnosticEventPiece(Pos, msg, true, StackHint);
}

// register this checker
void registerIRQChecker(CheckerRegistry &registry) {
	registry.addChecker<IRQChecker>("linux.irq", "Checks the consistency between request_irq and free_irq");
}
