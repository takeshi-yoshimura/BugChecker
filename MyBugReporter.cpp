#include "MyBugReporter.h"
#include "clang/AST/DeclObjC.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/ParentMap.h"
#include "clang/AST/StmtCXX.h"
#include "clang/AST/StmtObjC.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/BugReporter/PathDiagnostic.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ExprEngine.h"
#include "llvm/ADT/Statistic.h"
#include <memory>
#include <queue>

using namespace clang;
using namespace ento;


#define DEBUG_TYPE "MyBugReporter"

STATISTIC(MaxBugClassSize,
	"The maximum number of bug reports in the same equivalence class");
STATISTIC(MaxValidBugClassSize,
	"The maximum number of bug reports in the same equivalence class "
	"where at least one report is valid (not suppressed)");

ExplodedGraph &MyBugReporter::getGraph() { return Eng.getGraph(); }

MyBugReporter::~MyBugReporter() {
	//FlushReports();

	// Free the bug reports we are tracking.
	typedef std::vector<MyBugReportEquivClass *> ContTy;
	for (ContTy::iterator I = EQClassesVector.begin(), E = EQClassesVector.end();
		I != E; ++I) {
		delete *I;
	}
}

void MyBugReporter::FlushReports() {
	if (BugTypes.isEmpty())
		return;

	// We need to flush reports in deterministic order to ensure the order
	// of the reports is consistent between runs.
	typedef std::vector<MyBugReportEquivClass *> ContVecTy;
	for (ContVecTy::iterator EI = EQClassesVector.begin(), EE = EQClassesVector.end();
		EI != EE; ++EI){
		MyBugReportEquivClass& EQ = **EI;
		FlushReport(EQ);
	}

	// Remove all references to the BugType objects.
	BugTypes = F.getEmptySet();
}

void MyBugReporter::Register(BugType *BT) {
	BugTypes = F.add(BugTypes, BT);
}

void MyBugReporter::emitReport(BugReport* R) {
	// To guarantee memory release.
	std::unique_ptr<BugReport> UniqueR(R);

	if (const ExplodedNode *E = R->getErrorNode()) {
		const AnalysisDeclContext *DeclCtx = 
			E->getLocationContext()->getAnalysisDeclContext();
		// The source of autosynthesized body can be handcrafted AST or a model
		// file. The locations from handcrafted ASTs have no valid source locations
		// and have to be discarded. Locations from model files should be preserved
		// for processing and reporting.
		if (DeclCtx->isBodyAutosynthesized() &&
			!DeclCtx->isBodyAutosynthesizedFromModelFile())
			return;
	}

	bool ValidSourceLoc = R->getLocation(getSourceManager()).isValid();
	assert(ValidSourceLoc);
	// If we mess up in a release build, we'd still prefer to just drop the bug
	// instead of trying to go on.
	if (!ValidSourceLoc)
		return;

	// Compute the bug report's hash to determine its equivalence class.
	llvm::FoldingSetNodeID ID;
	R->Profile(ID);

	// Lookup the equivance class.  If there isn't one, create it.
	BugType& BT = R->getBugType();
	Register(&BT);
	void *InsertPos;
	MyBugReportEquivClass* EQ = EQClasses.FindNodeOrInsertPos(ID, InsertPos);

	if (!EQ) {
		EQ = new MyBugReportEquivClass(std::move(UniqueR));
		EQClasses.InsertNode(EQ, InsertPos);
		EQClassesVector.push_back(EQ);
	}
	else
		EQ->AddReport(std::move(UniqueR));
}

//===----------------------------------------------------------------------===//
// Emitting reports in equivalence classes.
//===----------------------------------------------------------------------===//

namespace {
	struct FRIEC_WLItem {
		const ExplodedNode *N;
		ExplodedNode::const_succ_iterator I, E;

		FRIEC_WLItem(const ExplodedNode *n)
			: N(n), I(N->succ_begin()), E(N->succ_end()) {}
	};
}

static BugReport *
FindReportInEquivalenceClass(MyBugReportEquivClass& EQ,
SmallVectorImpl<BugReport*> &bugReports) {

	MyBugReportEquivClass::iterator I = EQ.begin(), E = EQ.end();
	assert(I != E);
	BugType& BT = I->getBugType();

	// If we don't need to suppress any of the nodes because they are
	// post-dominated by a sink, simply add all the nodes in the equivalence class
	// to 'Nodes'.  Any of the reports will serve as a "representative" report.
	if (!BT.isSuppressOnSink()) {
		BugReport *R = I;
		for (MyBugReportEquivClass::iterator I = EQ.begin(), E = EQ.end(); I != E; ++I) {
			const ExplodedNode *N = I->getErrorNode();
			if (N) {
				R = I;
				bugReports.push_back(R);
			}
		}
		return R;
	}

	// For bug reports that should be suppressed when all paths are post-dominated
	// by a sink node, iterate through the reports in the equivalence class
	// until we find one that isn't post-dominated (if one exists).  We use a
	// DFS traversal of the ExplodedGraph to find a non-sink node.  We could write
	// this as a recursive function, but we don't want to risk blowing out the
	// stack for very long paths.
	BugReport *exampleReport = nullptr;

	for (; I != E; ++I) {
		const ExplodedNode *errorNode = I->getErrorNode();

		if (!errorNode)
			continue;
		if (errorNode->isSink()) {
			llvm_unreachable(
				"BugType::isSuppressSink() should not be 'true' for sink end nodes");
		}
		// No successors?  By definition this nodes isn't post-dominated by a sink.
		if (errorNode->succ_empty()) {
			bugReports.push_back(I);
			if (!exampleReport)
				exampleReport = I;
			continue;
		}

		// At this point we know that 'N' is not a sink and it has at least one
		// successor.  Use a DFS worklist to find a non-sink end-of-path node.    
		typedef FRIEC_WLItem WLItem;
		typedef SmallVector<WLItem, 10> DFSWorkList;
		llvm::DenseMap<const ExplodedNode *, unsigned> Visited;

		DFSWorkList WL;
		WL.push_back(errorNode);
		Visited[errorNode] = 1;

		while (!WL.empty()) {
			WLItem &WI = WL.back();
			assert(!WI.N->succ_empty());

			for (; WI.I != WI.E; ++WI.I) {
				const ExplodedNode *Succ = *WI.I;
				// End-of-path node?
				if (Succ->succ_empty()) {
					// If we found an end-of-path node that is not a sink.
					if (!Succ->isSink()) {
						bugReports.push_back(I);
						if (!exampleReport)
							exampleReport = I;
						WL.clear();
						break;
					}
					// Found a sink?  Continue on to the next successor.
					continue;
				}
				// Mark the successor as visited.  If it hasn't been explored,
				// enqueue it to the DFS worklist.
				unsigned &mark = Visited[Succ];
				if (!mark) {
					mark = 1;
					WL.push_back(Succ);
					break;
				}
			}

			// The worklist may have been cleared at this point.  First
			// check if it is empty before checking the last item.
			if (!WL.empty() && &WL.back() == &WI)
				WL.pop_back();
		}
	}

	// ExampleReport will be NULL if all the nodes in the equivalence class
	// were post-dominated by sinks.
	return exampleReport;
}

void MyBugReporter::FlushReport(MyBugReportEquivClass& EQ) {
	SmallVector<BugReport*, 10> bugReports;
	BugReport *exampleReport = FindReportInEquivalenceClass(EQ, bugReports);
	if (exampleReport) {
		for (PathDiagnosticConsumer *PDC : getPathDiagnosticConsumers()) {
			FlushReport(exampleReport, *PDC, bugReports);
		}
	}
}

void MyBugReporter::FlushReport(BugReport *exampleReport,
	PathDiagnosticConsumer &PD,
	ArrayRef<BugReport*> bugReports) {

	// FIXME: Make sure we use the 'R' for the path that was actually used.
	// Probably doesn't make a difference in practice.
	BugType& BT = exampleReport->getBugType();

	std::unique_ptr<PathDiagnostic> D(new PathDiagnostic(
		exampleReport->getBugType().getCheckName(),
		exampleReport->getDeclWithIssue(), exampleReport->getBugType().getName(),
		exampleReport->getDescription(),
		exampleReport->getShortDescription(/*Fallback=*/false), BT.getCategory(),
		exampleReport->getUniqueingLocation(),
		exampleReport->getUniqueingDecl()));

	MaxBugClassSize = std::max(bugReports.size(),
		static_cast<size_t>(MaxBugClassSize));

	// Generate the full path diagnostic, using the generation scheme
	// specified by the PathDiagnosticConsumer. Note that we have to generate
	// path diagnostics even for consumers which do not support paths, because
	// the BugReporterVisitors may mark this bug as a false positive.
	if (!bugReports.empty())
		if (!generatePathDiagnostic(*D.get(), PD, bugReports))
			return;

	MaxValidBugClassSize = std::max(bugReports.size(),
		static_cast<size_t>(MaxValidBugClassSize));

	// Examine the report and see if the last piece is in a header. Reset the
	// report location to the last piece in the main source file.
	AnalyzerOptions& Opts = getAnalyzerOptions();
	if (Opts.shouldReportIssuesInMainSourceFile() && !Opts.AnalyzeAll)
		D->resetDiagnosticLocationToMainFile();

	// If the path is empty, generate a single step path with the location
	// of the issue.
	if (D->path.empty()) {
		PathDiagnosticLocation L = exampleReport->getLocation(getSourceManager());
		auto piece = llvm::make_unique<PathDiagnosticEventPiece>(
			L, exampleReport->getDescription());
		for (const SourceRange &Range : exampleReport->getRanges())
			piece->addRange(Range);
		D->setEndOfPath(std::move(piece));
	}

	// Get the meta data.
	const BugReport::ExtraTextList &Meta = exampleReport->getExtraText();
	for (BugReport::ExtraTextList::const_iterator i = Meta.begin(),
		e = Meta.end(); i != e; ++i) {
		D->addMeta(*i);
	}

	PD.HandlePathDiagnostic(std::move(D));
}









































//===----------------------------------------------------------------------===//
// Diagnostic cleanup.
//===----------------------------------------------------------------------===//

static PathDiagnosticEventPiece *
eventsDescribeSameCondition(PathDiagnosticEventPiece *X,
PathDiagnosticEventPiece *Y) {
	// Prefer diagnostics that come from ConditionBRVisitor over
	// those that came from TrackConstraintBRVisitor.
	const void *tagPreferred = ConditionBRVisitor::getTag();
	const void *tagLesser = TrackConstraintBRVisitor::getTag();

	if (X->getLocation() != Y->getLocation())
		return nullptr;

	if (X->getTag() == tagPreferred && Y->getTag() == tagLesser)
		return X;

	if (Y->getTag() == tagPreferred && X->getTag() == tagLesser)
		return Y;

	return nullptr;
}

/// An optimization pass over PathPieces that removes redundant diagnostics
/// generated by both ConditionBRVisitor and TrackConstraintBRVisitor.  Both
/// BugReporterVisitors use different methods to generate diagnostics, with
/// one capable of emitting diagnostics in some cases but not in others.  This
/// can lead to redundant diagnostic pieces at the same point in a path.
static void removeRedundantMsgs(PathPieces &path) {
	unsigned N = path.size();
	if (N < 2)
		return;
	// NOTE: this loop intentionally is not using an iterator.  Instead, we
	// are streaming the path and modifying it in place.  This is done by
	// grabbing the front, processing it, and if we decide to keep it append
	// it to the end of the path.  The entire path is processed in this way.
	for (unsigned i = 0; i < N; ++i) {
		IntrusiveRefCntPtr<PathDiagnosticPiece> piece(path.front());
		path.pop_front();

		switch (piece->getKind()) {
		case clang::ento::PathDiagnosticPiece::Call:
			removeRedundantMsgs(cast<PathDiagnosticCallPiece>(piece)->path);
			break;
		case clang::ento::PathDiagnosticPiece::Macro:
			removeRedundantMsgs(cast<PathDiagnosticMacroPiece>(piece)->subPieces);
			break;
		case clang::ento::PathDiagnosticPiece::ControlFlow:
			break;
		case clang::ento::PathDiagnosticPiece::Event: {
			if (i == N - 1)
				break;

			if (PathDiagnosticEventPiece *nextEvent =
				dyn_cast<PathDiagnosticEventPiece>(path.front().get())) {
				PathDiagnosticEventPiece *event =
					cast<PathDiagnosticEventPiece>(piece);
				// Check to see if we should keep one of the two pieces.  If we
				// come up with a preference, record which piece to keep, and consume
				// another piece from the path.
				if (PathDiagnosticEventPiece *pieceToKeep =
					eventsDescribeSameCondition(event, nextEvent)) {
					piece = pieceToKeep;
					path.pop_front();
					++i;
				}
			}
			break;
		}
		}
		path.push_back(piece);
	}
}

/// A map from PathDiagnosticPiece to the LocationContext of the inlined
/// function call it represents.
typedef llvm::DenseMap<const PathPieces *, const LocationContext *>
LocationContextMap;

/// Recursively scan through a path and prune out calls and macros pieces
/// that aren't needed.  Return true if afterwards the path contains
/// "interesting stuff" which means it shouldn't be pruned from the parent path.
static bool removeUnneededCalls(PathPieces &pieces, BugReport *R,
	LocationContextMap &LCM) {
	bool containsSomethingInteresting = false;
	const unsigned N = pieces.size();

	for (unsigned i = 0; i < N; ++i) {
		// Remove the front piece from the path.  If it is still something we
		// want to keep once we are done, we will push it back on the end.
		IntrusiveRefCntPtr<PathDiagnosticPiece> piece(pieces.front());
		pieces.pop_front();

		switch (piece->getKind()) {
		case PathDiagnosticPiece::Call: {
			PathDiagnosticCallPiece *call = cast<PathDiagnosticCallPiece>(piece);
			// Check if the location context is interesting.
			assert(LCM.count(&call->path));
			if (R->isInteresting(LCM[&call->path])) {
				containsSomethingInteresting = true;
				break;
			}

			if (!removeUnneededCalls(call->path, R, LCM))
				continue;

			containsSomethingInteresting = true;
			break;
		}
		case PathDiagnosticPiece::Macro: {
			PathDiagnosticMacroPiece *macro = cast<PathDiagnosticMacroPiece>(piece);
			if (!removeUnneededCalls(macro->subPieces, R, LCM))
				continue;
			containsSomethingInteresting = true;
			break;
		}
		case PathDiagnosticPiece::Event: {
			PathDiagnosticEventPiece *event = cast<PathDiagnosticEventPiece>(piece);

			// We never throw away an event, but we do throw it away wholesale
			// as part of a path if we throw the entire path away.
			containsSomethingInteresting |= !event->isPrunable();
			break;
		}
		case PathDiagnosticPiece::ControlFlow:
			break;
		}

		pieces.push_back(piece);
	}

	return containsSomethingInteresting;
}

namespace {
	/// A wrapper around a report graph, which contains only a single path, and its
	/// node maps.
	class ReportGraph {
	public:
		InterExplodedGraphMap BackMap;
		std::unique_ptr<ExplodedGraph> Graph;
		const ExplodedNode *ErrorNode;
		size_t Index;
	};

	/// A wrapper around a trimmed graph and its node maps.
	class TrimmedGraph {
		InterExplodedGraphMap InverseMap;

		typedef llvm::DenseMap<const ExplodedNode *, unsigned> PriorityMapTy;
		PriorityMapTy PriorityMap;

		typedef std::pair<const ExplodedNode *, size_t> NodeIndexPair;
		SmallVector<NodeIndexPair, 32> ReportNodes;

		std::unique_ptr<ExplodedGraph> G;

		/// A helper class for sorting ExplodedNodes by priority.
		template <bool Descending>
		class PriorityCompare {
			const PriorityMapTy &PriorityMap;

		public:
			PriorityCompare(const PriorityMapTy &M) : PriorityMap(M) {}

			bool operator()(const ExplodedNode *LHS, const ExplodedNode *RHS) const {
				PriorityMapTy::const_iterator LI = PriorityMap.find(LHS);
				PriorityMapTy::const_iterator RI = PriorityMap.find(RHS);
				PriorityMapTy::const_iterator E = PriorityMap.end();

				if (LI == E)
					return Descending;
				if (RI == E)
					return !Descending;

				return Descending ? LI->second > RI->second
					: LI->second < RI->second;
			}

			bool operator()(const NodeIndexPair &LHS, const NodeIndexPair &RHS) const {
				return (*this)(LHS.first, RHS.first);
			}
		};

	public:
		TrimmedGraph(const ExplodedGraph *OriginalGraph,
			ArrayRef<const ExplodedNode *> Nodes);

		bool popNextReportGraph(ReportGraph &GraphWrapper);
	};
}

TrimmedGraph::TrimmedGraph(const ExplodedGraph *OriginalGraph,
	ArrayRef<const ExplodedNode *> Nodes) {
	// The trimmed graph is created in the body of the constructor to ensure
	// that the DenseMaps have been initialized already.
	InterExplodedGraphMap ForwardMap;
	G = OriginalGraph->trim(Nodes, &ForwardMap, &InverseMap);

	// Find the (first) error node in the trimmed graph.  We just need to consult
	// the node map which maps from nodes in the original graph to nodes
	// in the new graph.
	llvm::SmallPtrSet<const ExplodedNode *, 32> RemainingNodes;

	for (unsigned i = 0, count = Nodes.size(); i < count; ++i) {
		if (const ExplodedNode *NewNode = ForwardMap.lookup(Nodes[i])) {
			ReportNodes.push_back(std::make_pair(NewNode, i));
			RemainingNodes.insert(NewNode);
		}
	}

	assert(!RemainingNodes.empty() && "No error node found in the trimmed graph");

	// Perform a forward BFS to find all the shortest paths.
	std::queue<const ExplodedNode *> WS;

	assert(G->num_roots() == 1);
	WS.push(*G->roots_begin());
	unsigned Priority = 0;

	while (!WS.empty()) {
		const ExplodedNode *Node = WS.front();
		WS.pop();

		PriorityMapTy::iterator PriorityEntry;
		bool IsNew;
		std::tie(PriorityEntry, IsNew) =
			PriorityMap.insert(std::make_pair(Node, Priority));
		++Priority;

		if (!IsNew) {
			assert(PriorityEntry->second <= Priority);
			continue;
		}

		if (RemainingNodes.erase(Node))
			if (RemainingNodes.empty())
				break;

		for (ExplodedNode::const_pred_iterator I = Node->succ_begin(),
			E = Node->succ_end();
			I != E; ++I)
			WS.push(*I);
	}

	// Sort the error paths from longest to shortest.
	std::sort(ReportNodes.begin(), ReportNodes.end(),
		PriorityCompare<true>(PriorityMap));
}

bool TrimmedGraph::popNextReportGraph(ReportGraph &GraphWrapper) {
	if (ReportNodes.empty())
		return false;

	const ExplodedNode *OrigN;
	std::tie(OrigN, GraphWrapper.Index) = ReportNodes.pop_back_val();
	assert(PriorityMap.find(OrigN) != PriorityMap.end() &&
		"error node not accessible from root");

	// Create a new graph with a single path.  This is the graph
	// that will be returned to the caller.
	auto GNew = llvm::make_unique<ExplodedGraph>();
	GraphWrapper.BackMap.clear();

	// Now walk from the error node up the BFS path, always taking the
	// predeccessor with the lowest number.
	ExplodedNode *Succ = nullptr;
	while (true) {
		// Create the equivalent node in the new graph with the same state
		// and location.
		ExplodedNode *NewN = GNew->getNode(OrigN->getLocation(), OrigN->getState(),
			OrigN->isSink());

		// Store the mapping to the original node.
		InterExplodedGraphMap::const_iterator IMitr = InverseMap.find(OrigN);
		assert(IMitr != InverseMap.end() && "No mapping to original node.");
		GraphWrapper.BackMap[NewN] = IMitr->second;

		// Link up the new node with the previous node.
		if (Succ)
			Succ->addPredecessor(NewN, *GNew);
		else
			GraphWrapper.ErrorNode = NewN;

		Succ = NewN;

		// Are we at the final node?
		if (OrigN->pred_empty()) {
			GNew->addRoot(NewN);
			break;
		}

		// Find the next predeccessor node.  We choose the node that is marked
		// with the lowest BFS number.
		OrigN = *std::min_element(OrigN->pred_begin(), OrigN->pred_end(),
			PriorityCompare<false>(PriorityMap));
	}

	GraphWrapper.Graph = std::move(GNew);

	return true;
}

/// Returns true if the given decl has been implicitly given a body, either by
/// the analyzer or by the compiler proper.
static bool hasImplicitBody(const Decl *D) {
	assert(D);
	return D->isImplicit() || !D->hasBody();
}

/// Recursively scan through a path and make sure that all call pieces have
/// valid locations. 
static void
adjustCallLocations(PathPieces &Pieces,
PathDiagnosticLocation *LastCallLocation = nullptr) {
	for (PathPieces::iterator I = Pieces.begin(), E = Pieces.end(); I != E; ++I) {
		PathDiagnosticCallPiece *Call = dyn_cast<PathDiagnosticCallPiece>(*I);

		if (!Call) {
			assert((*I)->getLocation().asLocation().isValid());
			continue;
		}

		if (LastCallLocation) {
			bool CallerIsImplicit = hasImplicitBody(Call->getCaller());
			if (CallerIsImplicit || !Call->callEnter.asLocation().isValid())
				Call->callEnter = *LastCallLocation;
			if (CallerIsImplicit || !Call->callReturn.asLocation().isValid())
				Call->callReturn = *LastCallLocation;
		}

		// Recursively clean out the subclass.  Keep this call around if
		// it contains any informative diagnostics.
		PathDiagnosticLocation *ThisCallLocation;
		if (Call->callEnterWithin.asLocation().isValid() &&
			!hasImplicitBody(Call->getCallee()))
			ThisCallLocation = &Call->callEnterWithin;
		else
			ThisCallLocation = &Call->callEnter;

		assert(ThisCallLocation && "Outermost call has an invalid location");
		adjustCallLocations(Call->path, ThisCallLocation);
	}
}

/// Remove edges in and out of C++ default initializer expressions. These are
/// for fields that have in-class initializers, as opposed to being initialized
/// explicitly in a constructor or braced list.
static void removeEdgesToDefaultInitializers(PathPieces &Pieces) {
	for (PathPieces::iterator I = Pieces.begin(), E = Pieces.end(); I != E;) {
		if (PathDiagnosticCallPiece *C = dyn_cast<PathDiagnosticCallPiece>(*I))
			removeEdgesToDefaultInitializers(C->path);

		if (PathDiagnosticMacroPiece *M = dyn_cast<PathDiagnosticMacroPiece>(*I))
			removeEdgesToDefaultInitializers(M->subPieces);

		if (PathDiagnosticControlFlowPiece *CF =
			dyn_cast<PathDiagnosticControlFlowPiece>(*I)) {
			const Stmt *Start = CF->getStartLocation().asStmt();
			const Stmt *End = CF->getEndLocation().asStmt();
			if (Start && isa<CXXDefaultInitExpr>(Start)) {
				I = Pieces.erase(I);
				continue;
			}
			else if (End && isa<CXXDefaultInitExpr>(End)) {
				PathPieces::iterator Next = std::next(I);
				if (Next != E) {
					if (PathDiagnosticControlFlowPiece *NextCF =
						dyn_cast<PathDiagnosticControlFlowPiece>(*Next)) {
						NextCF->setStartLocation(CF->getStartLocation());
					}
				}
				I = Pieces.erase(I);
				continue;
			}
		}

		I++;
	}
}

/// Remove all pieces with invalid locations as these cannot be serialized.
/// We might have pieces with invalid locations as a result of inlining Body
/// Farm generated functions.
static void removePiecesWithInvalidLocations(PathPieces &Pieces) {
	for (PathPieces::iterator I = Pieces.begin(), E = Pieces.end(); I != E;) {
		if (PathDiagnosticCallPiece *C = dyn_cast<PathDiagnosticCallPiece>(*I))
			removePiecesWithInvalidLocations(C->path);

		if (PathDiagnosticMacroPiece *M = dyn_cast<PathDiagnosticMacroPiece>(*I))
			removePiecesWithInvalidLocations(M->subPieces);

		if (!(*I)->getLocation().isValid() ||
			!(*I)->getLocation().asLocation().isValid()) {
			I = Pieces.erase(I);
			continue;
		}
		I++;
	}
}


//===----------------------------------------------------------------------===//
// PathDiagnosticBuilder and its associated routines and helper objects.
//===----------------------------------------------------------------------===//

namespace {
	class NodeMapClosure : public BugReport::NodeResolver {
		InterExplodedGraphMap &M;
	public:
		NodeMapClosure(InterExplodedGraphMap &m) : M(m) {}

		const ExplodedNode *getOriginalNode(const ExplodedNode *N) override {
			return M.lookup(N);
		}
	};

	class PathDiagnosticBuilder : public BugReporterContext {
		BugReport *R;
		PathDiagnosticConsumer *PDC;
		NodeMapClosure NMC;
	public:
		const LocationContext *LC;

		PathDiagnosticBuilder(MyBugReporter &br,
			BugReport *r, InterExplodedGraphMap &Backmap,
			PathDiagnosticConsumer *pdc)
			: BugReporterContext(br.toGRBugReporter()),
			R(r), PDC(pdc), NMC(Backmap), LC(r->getErrorNode()->getLocationContext())
		{}

		PathDiagnosticLocation ExecutionContinues(const ExplodedNode *N);

		PathDiagnosticLocation ExecutionContinues(llvm::raw_string_ostream &os,
			const ExplodedNode *N);

		BugReport *getBugReport() { return R; }

		Decl const &getCodeDecl() { return R->getErrorNode()->getCodeDecl(); }

		ParentMap& getParentMap() { return LC->getParentMap(); }

		const Stmt *getParent(const Stmt *S) {
			return getParentMap().getParent(S);
		}

		NodeMapClosure& getNodeResolver() override { return NMC; }

		PathDiagnosticLocation getEnclosingStmtLocation(const Stmt *S);

		PathDiagnosticConsumer::PathGenerationScheme getGenerationScheme() const {
			return PDC ? PDC->getGenerationScheme() : PathDiagnosticConsumer::Extensive;
		}

		bool supportsLogicalOpControlFlow() const {
			return PDC ? PDC->supportsLogicalOpControlFlow() : true;
		}
	};
} // end anonymous namespace

PathDiagnosticLocation
PathDiagnosticBuilder::ExecutionContinues(const ExplodedNode *N) {
	if (const Stmt *S = PathDiagnosticLocation::getNextStmt(N))
		return PathDiagnosticLocation(S, getSourceManager(), LC);

	return PathDiagnosticLocation::createDeclEnd(N->getLocationContext(),
		getSourceManager());
}

PathDiagnosticLocation
PathDiagnosticBuilder::ExecutionContinues(llvm::raw_string_ostream &os,
const ExplodedNode *N) {

	// Slow, but probably doesn't matter.
	if (os.str().empty())
		os << ' ';

	const PathDiagnosticLocation &Loc = ExecutionContinues(N);

	if (Loc.asStmt())
		os << "Execution continues on line "
		<< getSourceManager().getExpansionLineNumber(Loc.asLocation())
		<< '.';
	else {
		os << "Execution jumps to the end of the ";
		const Decl *D = N->getLocationContext()->getDecl();
		if (isa<ObjCMethodDecl>(D))
			os << "method";
		else if (isa<FunctionDecl>(D))
			os << "function";
		else {
			assert(isa<BlockDecl>(D));
			os << "anonymous block";
		}
		os << '.';
	}

	return Loc;
}

static const Stmt *getEnclosingParent(const Stmt *S, const ParentMap &PM) {
	if (isa<Expr>(S) && PM.isConsumedExpr(cast<Expr>(S)))
		return PM.getParentIgnoreParens(S);

	const Stmt *Parent = PM.getParentIgnoreParens(S);
	if (!Parent)
		return nullptr;

	switch (Parent->getStmtClass()) {
	case Stmt::ForStmtClass:
	case Stmt::DoStmtClass:
	case Stmt::WhileStmtClass:
	case Stmt::ObjCForCollectionStmtClass:
	case Stmt::CXXForRangeStmtClass:
		return Parent;
	default:
		break;
	}

	return nullptr;
}

static PathDiagnosticLocation
getEnclosingStmtLocation(const Stmt *S, SourceManager &SMgr, const ParentMap &P,
const LocationContext *LC, bool allowNestedContexts) {
	if (!S)
		return PathDiagnosticLocation();

	while (const Stmt *Parent = getEnclosingParent(S, P)) {
		switch (Parent->getStmtClass()) {
		case Stmt::BinaryOperatorClass: {
			const BinaryOperator *B = cast<BinaryOperator>(Parent);
			if (B->isLogicalOp())
				return PathDiagnosticLocation(allowNestedContexts ? B : S, SMgr, LC);
			break;
		}
		case Stmt::CompoundStmtClass:
		case Stmt::StmtExprClass:
			return PathDiagnosticLocation(S, SMgr, LC);
		case Stmt::ChooseExprClass:
			// Similar to '?' if we are referring to condition, just have the edge
			// point to the entire choose expression.
			if (allowNestedContexts || cast<ChooseExpr>(Parent)->getCond() == S)
				return PathDiagnosticLocation(Parent, SMgr, LC);
			else
				return PathDiagnosticLocation(S, SMgr, LC);
		case Stmt::BinaryConditionalOperatorClass:
		case Stmt::ConditionalOperatorClass:
			// For '?', if we are referring to condition, just have the edge point
			// to the entire '?' expression.
			if (allowNestedContexts ||
				cast<AbstractConditionalOperator>(Parent)->getCond() == S)
				return PathDiagnosticLocation(Parent, SMgr, LC);
			else
				return PathDiagnosticLocation(S, SMgr, LC);
		case Stmt::CXXForRangeStmtClass:
			if (cast<CXXForRangeStmt>(Parent)->getBody() == S)
				return PathDiagnosticLocation(S, SMgr, LC);
			break;
		case Stmt::DoStmtClass:
			return PathDiagnosticLocation(S, SMgr, LC);
		case Stmt::ForStmtClass:
			if (cast<ForStmt>(Parent)->getBody() == S)
				return PathDiagnosticLocation(S, SMgr, LC);
			break;
		case Stmt::IfStmtClass:
			if (cast<IfStmt>(Parent)->getCond() != S)
				return PathDiagnosticLocation(S, SMgr, LC);
			break;
		case Stmt::ObjCForCollectionStmtClass:
			if (cast<ObjCForCollectionStmt>(Parent)->getBody() == S)
				return PathDiagnosticLocation(S, SMgr, LC);
			break;
		case Stmt::WhileStmtClass:
			if (cast<WhileStmt>(Parent)->getCond() != S)
				return PathDiagnosticLocation(S, SMgr, LC);
			break;
		default:
			break;
		}

		S = Parent;
	}

	assert(S && "Cannot have null Stmt for PathDiagnosticLocation");

	return PathDiagnosticLocation(S, SMgr, LC);
}

PathDiagnosticLocation
PathDiagnosticBuilder::getEnclosingStmtLocation(const Stmt *S) {
	assert(S && "Null Stmt passed to getEnclosingStmtLocation");
	return ::getEnclosingStmtLocation(S, getSourceManager(), getParentMap(), LC,
		/*allowNestedContexts=*/false);
}

//===----------------------------------------------------------------------===//
// "Visitors only" path diagnostic generation algorithm.
//===----------------------------------------------------------------------===//
static bool GenerateVisitorsOnlyPathDiagnostic(
	PathDiagnostic &PD, PathDiagnosticBuilder &PDB, const ExplodedNode *N,
	ArrayRef<std::unique_ptr<BugReporterVisitor>> visitors) {
	// All path generation skips the very first node (the error node).
	// This is because there is special handling for the end-of-path note.
	N = N->getFirstPred();
	if (!N)
		return true;

	BugReport *R = PDB.getBugReport();
	while (const ExplodedNode *Pred = N->getFirstPred()) {
		for (auto &V : visitors) {
			// Visit all the node pairs, but throw the path pieces away.
			PathDiagnosticPiece *Piece = V->VisitNode(N, Pred, PDB, *R);
			delete Piece;
		}

		N = Pred;
	}

	return R->isValid();
}

//===----------------------------------------------------------------------===//
// "Minimal" path diagnostic generation algorithm.
//===----------------------------------------------------------------------===//
typedef std::pair<PathDiagnosticCallPiece*, const ExplodedNode*> StackDiagPair;
typedef SmallVector<StackDiagPair, 6> StackDiagVector;

static void updateStackPiecesWithMessage(PathDiagnosticPiece *P,
	StackDiagVector &CallStack) {
	// If the piece contains a special message, add it to all the call
	// pieces on the active stack.
	if (PathDiagnosticEventPiece *ep =
		dyn_cast<PathDiagnosticEventPiece>(P)) {

		if (ep->hasCallStackHint())
			for (StackDiagVector::iterator I = CallStack.begin(),
				E = CallStack.end(); I != E; ++I) {
				PathDiagnosticCallPiece *CP = I->first;
				const ExplodedNode *N = I->second;
				std::string stackMsg = ep->getCallStackMessage(N);

				// The last message on the path to final bug is the most important
				// one. Since we traverse the path backwards, do not add the message
				// if one has been previously added.
				if (!CP->hasCallStackMessage())
					CP->setCallStackMessage(stackMsg);
			}
	}
}

static void CompactPathDiagnostic(PathPieces &path, const SourceManager& SM);

static bool GenerateMinimalPathDiagnostic(
	PathDiagnostic &PD, PathDiagnosticBuilder &PDB, const ExplodedNode *N,
	LocationContextMap &LCM,
	ArrayRef<std::unique_ptr<BugReporterVisitor>> visitors) {

	SourceManager& SMgr = PDB.getSourceManager();
	const LocationContext *LC = PDB.LC;
	const ExplodedNode *NextNode = N->pred_empty()
		? nullptr : *(N->pred_begin());

	StackDiagVector CallStack;

	while (NextNode) {
		N = NextNode;
		PDB.LC = N->getLocationContext();
		NextNode = N->getFirstPred();

		ProgramPoint P = N->getLocation();

		do {
			if (Optional<CallExitEnd> CE = P.getAs<CallExitEnd>()) {
				PathDiagnosticCallPiece *C =
					PathDiagnosticCallPiece::construct(N, *CE, SMgr);
				// Record the mapping from call piece to LocationContext.
				LCM[&C->path] = CE->getCalleeContext();
				PD.getActivePath().push_front(C);
				PD.pushActivePath(&C->path);
				CallStack.push_back(StackDiagPair(C, N));
				break;
			}

			if (Optional<CallEnter> CE = P.getAs<CallEnter>()) {
				// Flush all locations, and pop the active path.
				bool VisitedEntireCall = PD.isWithinCall();
				PD.popActivePath();

				// Either we just added a bunch of stuff to the top-level path, or
				// we have a previous CallExitEnd.  If the former, it means that the
				// path terminated within a function call.  We must then take the
				// current contents of the active path and place it within
				// a new PathDiagnosticCallPiece.
				PathDiagnosticCallPiece *C;
				if (VisitedEntireCall) {
					C = cast<PathDiagnosticCallPiece>(PD.getActivePath().front());
				}
				else {
					const Decl *Caller = CE->getLocationContext()->getDecl();
					C = PathDiagnosticCallPiece::construct(PD.getActivePath(), Caller);
					// Record the mapping from call piece to LocationContext.
					LCM[&C->path] = CE->getCalleeContext();
				}

				C->setCallee(*CE, SMgr);
				if (!CallStack.empty()) {
					assert(CallStack.back().first == C);
					CallStack.pop_back();
				}
				break;
			}

			if (Optional<BlockEdge> BE = P.getAs<BlockEdge>()) {
				const CFGBlock *Src = BE->getSrc();
				const CFGBlock *Dst = BE->getDst();
				const Stmt *T = Src->getTerminator();

				if (!T)
					break;

				PathDiagnosticLocation Start =
					PathDiagnosticLocation::createBegin(T, SMgr,
					N->getLocationContext());

				switch (T->getStmtClass()) {
				default:
					break;

				case Stmt::GotoStmtClass:
				case Stmt::IndirectGotoStmtClass: {
					const Stmt *S = PathDiagnosticLocation::getNextStmt(N);

					if (!S)
						break;

					std::string sbuf;
					llvm::raw_string_ostream os(sbuf);
					const PathDiagnosticLocation &End = PDB.getEnclosingStmtLocation(S);

					os << "Control jumps to line "
						<< End.asLocation().getExpansionLineNumber();
					PD.getActivePath().push_front(new PathDiagnosticControlFlowPiece(
						Start, End, os.str()));
					break;
				}

				case Stmt::SwitchStmtClass: {
					// Figure out what case arm we took.
					std::string sbuf;
					llvm::raw_string_ostream os(sbuf);

					if (const Stmt *S = Dst->getLabel()) {
						PathDiagnosticLocation End(S, SMgr, LC);

						switch (S->getStmtClass()) {
						default:
							os << "No cases match in the switch statement. "
								"Control jumps to line "
								<< End.asLocation().getExpansionLineNumber();
							break;
						case Stmt::DefaultStmtClass:
							os << "Control jumps to the 'default' case at line "
								<< End.asLocation().getExpansionLineNumber();
							break;

						case Stmt::CaseStmtClass: {
							os << "Control jumps to 'case ";
							const CaseStmt *Case = cast<CaseStmt>(S);
							const Expr *LHS = Case->getLHS()->IgnoreParenCasts();

							// Determine if it is an enum.
							bool GetRawInt = true;

							if (const DeclRefExpr *DR = dyn_cast<DeclRefExpr>(LHS)) {
								// FIXME: Maybe this should be an assertion.  Are there cases
								// were it is not an EnumConstantDecl?
								const EnumConstantDecl *D =
									dyn_cast<EnumConstantDecl>(DR->getDecl());

								if (D) {
									GetRawInt = false;
									os << *D;
								}
							}

							if (GetRawInt)
								os << LHS->EvaluateKnownConstInt(PDB.getASTContext());

							os << ":'  at line "
								<< End.asLocation().getExpansionLineNumber();
							break;
						}
						}
						PD.getActivePath().push_front(new PathDiagnosticControlFlowPiece(
							Start, End, os.str()));
					}
					else {
						os << "'Default' branch taken. ";
						const PathDiagnosticLocation &End = PDB.ExecutionContinues(os, N);
						PD.getActivePath().push_front(new PathDiagnosticControlFlowPiece(
							Start, End, os.str()));
					}

					break;
				}

				case Stmt::BreakStmtClass:
				case Stmt::ContinueStmtClass: {
					std::string sbuf;
					llvm::raw_string_ostream os(sbuf);
					PathDiagnosticLocation End = PDB.ExecutionContinues(os, N);
					PD.getActivePath().push_front(new PathDiagnosticControlFlowPiece(
						Start, End, os.str()));
					break;
				}

											  // Determine control-flow for ternary '?'.
				case Stmt::BinaryConditionalOperatorClass:
				case Stmt::ConditionalOperatorClass: {
					std::string sbuf;
					llvm::raw_string_ostream os(sbuf);
					os << "'?' condition is ";

					if (*(Src->succ_begin() + 1) == Dst)
						os << "false";
					else
						os << "true";

					PathDiagnosticLocation End = PDB.ExecutionContinues(N);

					if (const Stmt *S = End.asStmt())
						End = PDB.getEnclosingStmtLocation(S);

					PD.getActivePath().push_front(new PathDiagnosticControlFlowPiece(
						Start, End, os.str()));
					break;
				}

													 // Determine control-flow for short-circuited '&&' and '||'.
				case Stmt::BinaryOperatorClass: {
					if (!PDB.supportsLogicalOpControlFlow())
						break;

					const BinaryOperator *B = cast<BinaryOperator>(T);
					std::string sbuf;
					llvm::raw_string_ostream os(sbuf);
					os << "Left side of '";

					if (B->getOpcode() == BO_LAnd) {
						os << "&&" << "' is ";

						if (*(Src->succ_begin() + 1) == Dst) {
							os << "false";
							PathDiagnosticLocation End(B->getLHS(), SMgr, LC);
							PathDiagnosticLocation Start =
								PathDiagnosticLocation::createOperatorLoc(B, SMgr);
							PD.getActivePath().push_front(new PathDiagnosticControlFlowPiece(
								Start, End, os.str()));
						}
						else {
							os << "true";
							PathDiagnosticLocation Start(B->getLHS(), SMgr, LC);
							PathDiagnosticLocation End = PDB.ExecutionContinues(N);
							PD.getActivePath().push_front(new PathDiagnosticControlFlowPiece(
								Start, End, os.str()));
						}
					}
					else {
						assert(B->getOpcode() == BO_LOr);
						os << "||" << "' is ";

						if (*(Src->succ_begin() + 1) == Dst) {
							os << "false";
							PathDiagnosticLocation Start(B->getLHS(), SMgr, LC);
							PathDiagnosticLocation End = PDB.ExecutionContinues(N);
							PD.getActivePath().push_front(new PathDiagnosticControlFlowPiece(
								Start, End, os.str()));
						}
						else {
							os << "true";
							PathDiagnosticLocation End(B->getLHS(), SMgr, LC);
							PathDiagnosticLocation Start =
								PathDiagnosticLocation::createOperatorLoc(B, SMgr);
							PD.getActivePath().push_front(new PathDiagnosticControlFlowPiece(
								Start, End, os.str()));
						}
					}

					break;
				}

				case Stmt::DoStmtClass:  {
					if (*(Src->succ_begin()) == Dst) {
						std::string sbuf;
						llvm::raw_string_ostream os(sbuf);

						os << "Loop condition is true. ";
						PathDiagnosticLocation End = PDB.ExecutionContinues(os, N);

						if (const Stmt *S = End.asStmt())
							End = PDB.getEnclosingStmtLocation(S);

						PD.getActivePath().push_front(new PathDiagnosticControlFlowPiece(
							Start, End, os.str()));
					}
					else {
						PathDiagnosticLocation End = PDB.ExecutionContinues(N);

						if (const Stmt *S = End.asStmt())
							End = PDB.getEnclosingStmtLocation(S);

						PD.getActivePath().push_front(new PathDiagnosticControlFlowPiece(
							Start, End, "Loop condition is false.  Exiting loop"));
					}

					break;
				}

				case Stmt::WhileStmtClass:
				case Stmt::ForStmtClass: {
					if (*(Src->succ_begin() + 1) == Dst) {
						std::string sbuf;
						llvm::raw_string_ostream os(sbuf);

						os << "Loop condition is false. ";
						PathDiagnosticLocation End = PDB.ExecutionContinues(os, N);
						if (const Stmt *S = End.asStmt())
							End = PDB.getEnclosingStmtLocation(S);

						PD.getActivePath().push_front(new PathDiagnosticControlFlowPiece(
							Start, End, os.str()));
					}
					else {
						PathDiagnosticLocation End = PDB.ExecutionContinues(N);
						if (const Stmt *S = End.asStmt())
							End = PDB.getEnclosingStmtLocation(S);

						PD.getActivePath().push_front(new PathDiagnosticControlFlowPiece(
							Start, End, "Loop condition is true.  Entering loop body"));
					}

					break;
				}

				case Stmt::IfStmtClass: {
					PathDiagnosticLocation End = PDB.ExecutionContinues(N);

					if (const Stmt *S = End.asStmt())
						End = PDB.getEnclosingStmtLocation(S);

					if (*(Src->succ_begin() + 1) == Dst)
						PD.getActivePath().push_front(new PathDiagnosticControlFlowPiece(
						Start, End, "Taking false branch"));
					else
						PD.getActivePath().push_front(new PathDiagnosticControlFlowPiece(
						Start, End, "Taking true branch"));

					break;
				}
				}
			}
		} while (0);

		if (NextNode) {
			// Add diagnostic pieces from custom visitors.
			BugReport *R = PDB.getBugReport();
			for (auto &V : visitors) {
				if (PathDiagnosticPiece *p = V->VisitNode(N, NextNode, PDB, *R)) {
					PD.getActivePath().push_front(p);
					updateStackPiecesWithMessage(p, CallStack);
				}
			}
		}
	}

	if (!PDB.getBugReport()->isValid())
		return false;

	// After constructing the full PathDiagnostic, do a pass over it to compact
	// PathDiagnosticPieces that occur within a macro.
	CompactPathDiagnostic(PD.getMutablePieces(), PDB.getSourceManager());
	return true;
}

//===----------------------------------------------------------------------===//
// "Extensive" PathDiagnostic generation.
//===----------------------------------------------------------------------===//

static bool IsControlFlowExpr(const Stmt *S) {
	const Expr *E = dyn_cast<Expr>(S);

	if (!E)
		return false;

	E = E->IgnoreParenCasts();

	if (isa<AbstractConditionalOperator>(E))
		return true;

	if (const BinaryOperator *B = dyn_cast<BinaryOperator>(E))
		if (B->isLogicalOp())
			return true;

	return false;
}

namespace {
	class ContextLocation : public PathDiagnosticLocation {
		bool IsDead;
	public:
		ContextLocation(const PathDiagnosticLocation &L, bool isdead = false)
			: PathDiagnosticLocation(L), IsDead(isdead) {}

		void markDead() { IsDead = true; }
		bool isDead() const { return IsDead; }
	};

	static PathDiagnosticLocation cleanUpLocation(PathDiagnosticLocation L,
		const LocationContext *LC,
		bool firstCharOnly = false) {
		if (const Stmt *S = L.asStmt()) {
			const Stmt *Original = S;
			while (1) {
				// Adjust the location for some expressions that are best referenced
				// by one of their subexpressions.
				switch (S->getStmtClass()) {
				default:
					break;
				case Stmt::ParenExprClass:
				case Stmt::GenericSelectionExprClass:
					S = cast<Expr>(S)->IgnoreParens();
					firstCharOnly = true;
					continue;
				case Stmt::BinaryConditionalOperatorClass:
				case Stmt::ConditionalOperatorClass:
					S = cast<AbstractConditionalOperator>(S)->getCond();
					firstCharOnly = true;
					continue;
				case Stmt::ChooseExprClass:
					S = cast<ChooseExpr>(S)->getCond();
					firstCharOnly = true;
					continue;
				case Stmt::BinaryOperatorClass:
					S = cast<BinaryOperator>(S)->getLHS();
					firstCharOnly = true;
					continue;
				}

				break;
			}

			if (S != Original)
				L = PathDiagnosticLocation(S, L.getManager(), LC);
		}

		if (firstCharOnly)
			L = PathDiagnosticLocation::createSingleLocation(L);

		return L;
	}

	class EdgeBuilder {
		std::vector<ContextLocation> CLocs;
		typedef std::vector<ContextLocation>::iterator iterator;
		PathDiagnostic &PD;
		PathDiagnosticBuilder &PDB;
		PathDiagnosticLocation PrevLoc;

		bool IsConsumedExpr(const PathDiagnosticLocation &L);

		bool containsLocation(const PathDiagnosticLocation &Container,
			const PathDiagnosticLocation &Containee);

		PathDiagnosticLocation getContextLocation(const PathDiagnosticLocation &L);



		void popLocation() {
			if (!CLocs.back().isDead() && CLocs.back().asLocation().isFileID()) {
				// For contexts, we only one the first character as the range.
				rawAddEdge(cleanUpLocation(CLocs.back(), PDB.LC, true));
			}
			CLocs.pop_back();
		}

	public:
		EdgeBuilder(PathDiagnostic &pd, PathDiagnosticBuilder &pdb)
			: PD(pd), PDB(pdb) {

			// If the PathDiagnostic already has pieces, add the enclosing statement
			// of the first piece as a context as well.
			if (!PD.path.empty()) {
				PrevLoc = (*PD.path.begin())->getLocation();

				if (const Stmt *S = PrevLoc.asStmt())
					addExtendedContext(PDB.getEnclosingStmtLocation(S).asStmt());
			}
		}

		~EdgeBuilder() {
			while (!CLocs.empty()) popLocation();

			// Finally, add an initial edge from the start location of the first
			// statement (if it doesn't already exist).
			PathDiagnosticLocation L = PathDiagnosticLocation::createDeclBegin(
				PDB.LC,
				PDB.getSourceManager());
			if (L.isValid())
				rawAddEdge(L);
		}

		void flushLocations() {
			while (!CLocs.empty())
				popLocation();
			PrevLoc = PathDiagnosticLocation();
		}

		void addEdge(PathDiagnosticLocation NewLoc, bool alwaysAdd = false,
			bool IsPostJump = false);

		void rawAddEdge(PathDiagnosticLocation NewLoc);

		void addContext(const Stmt *S);
		void addContext(const PathDiagnosticLocation &L);
		void addExtendedContext(const Stmt *S);
	};
} // end anonymous namespace

namespace {
	PathDiagnosticLocation
		EdgeBuilder::getContextLocation(const PathDiagnosticLocation &L) {
		if (const Stmt *S = L.asStmt()) {
			if (IsControlFlowExpr(S))
				return L;

			return PDB.getEnclosingStmtLocation(S);
		}

		return L;
	}

	bool EdgeBuilder::containsLocation(const PathDiagnosticLocation &Container,
		const PathDiagnosticLocation &Containee) {

		if (Container == Containee)
			return true;

		if (Container.asDecl())
			return true;

		if (const Stmt *S = Containee.asStmt())
			if (const Stmt *ContainerS = Container.asStmt()) {
				while (S) {
					if (S == ContainerS)
						return true;
					S = PDB.getParent(S);
				}
				return false;
			}

		// Less accurate: compare using source ranges.
		SourceRange ContainerR = Container.asRange();
		SourceRange ContaineeR = Containee.asRange();

		SourceManager &SM = PDB.getSourceManager();
		SourceLocation ContainerRBeg = SM.getExpansionLoc(ContainerR.getBegin());
		SourceLocation ContainerREnd = SM.getExpansionLoc(ContainerR.getEnd());
		SourceLocation ContaineeRBeg = SM.getExpansionLoc(ContaineeR.getBegin());
		SourceLocation ContaineeREnd = SM.getExpansionLoc(ContaineeR.getEnd());

		unsigned ContainerBegLine = SM.getExpansionLineNumber(ContainerRBeg);
		unsigned ContainerEndLine = SM.getExpansionLineNumber(ContainerREnd);
		unsigned ContaineeBegLine = SM.getExpansionLineNumber(ContaineeRBeg);
		unsigned ContaineeEndLine = SM.getExpansionLineNumber(ContaineeREnd);

		assert(ContainerBegLine <= ContainerEndLine);
		assert(ContaineeBegLine <= ContaineeEndLine);

		return (ContainerBegLine <= ContaineeBegLine &&
			ContainerEndLine >= ContaineeEndLine &&
			(ContainerBegLine != ContaineeBegLine ||
			SM.getExpansionColumnNumber(ContainerRBeg) <=
			SM.getExpansionColumnNumber(ContaineeRBeg)) &&
			(ContainerEndLine != ContaineeEndLine ||
			SM.getExpansionColumnNumber(ContainerREnd) >=
			SM.getExpansionColumnNumber(ContaineeREnd)));
	}

	void EdgeBuilder::rawAddEdge(PathDiagnosticLocation NewLoc) {
		if (!PrevLoc.isValid()) {
			PrevLoc = NewLoc;
			return;
		}

		const PathDiagnosticLocation &NewLocClean = cleanUpLocation(NewLoc, PDB.LC);
		const PathDiagnosticLocation &PrevLocClean = cleanUpLocation(PrevLoc, PDB.LC);

		if (PrevLocClean.asLocation().isInvalid()) {
			PrevLoc = NewLoc;
			return;
		}

		if (NewLocClean.asLocation() == PrevLocClean.asLocation())
			return;

		// FIXME: Ignore intra-macro edges for now.
		if (NewLocClean.asLocation().getExpansionLoc() ==
			PrevLocClean.asLocation().getExpansionLoc())
			return;

		PD.getActivePath().push_front(new PathDiagnosticControlFlowPiece(NewLocClean, PrevLocClean));
		PrevLoc = NewLoc;
	}

	void EdgeBuilder::addEdge(PathDiagnosticLocation NewLoc, bool alwaysAdd,
		bool IsPostJump) {

		if (!alwaysAdd && NewLoc.asLocation().isMacroID())
			return;

		const PathDiagnosticLocation &CLoc = getContextLocation(NewLoc);

		while (!CLocs.empty()) {
			ContextLocation &TopContextLoc = CLocs.back();

			// Is the top location context the same as the one for the new location?
			if (TopContextLoc == CLoc) {
				if (alwaysAdd) {
					if (IsConsumedExpr(TopContextLoc))
						TopContextLoc.markDead();

					rawAddEdge(NewLoc);
				}

				if (IsPostJump)
					TopContextLoc.markDead();
				return;
			}

			if (containsLocation(TopContextLoc, CLoc)) {
				if (alwaysAdd) {
					rawAddEdge(NewLoc);

					if (IsConsumedExpr(CLoc)) {
						CLocs.push_back(ContextLocation(CLoc, /*IsDead=*/true));
						return;
					}
				}

				CLocs.push_back(ContextLocation(CLoc, /*IsDead=*/IsPostJump));
				return;
			}

			// Context does not contain the location.  Flush it.
			popLocation();
		}

		// If we reach here, there is no enclosing context.  Just add the edge.
		rawAddEdge(NewLoc);
	}

	bool EdgeBuilder::IsConsumedExpr(const PathDiagnosticLocation &L) {
		if (const Expr *X = dyn_cast_or_null<Expr>(L.asStmt()))
			return PDB.getParentMap().isConsumedExpr(X) && !IsControlFlowExpr(X);

		return false;
	}

	void EdgeBuilder::addExtendedContext(const Stmt *S) {
		if (!S)
			return;

		const Stmt *Parent = PDB.getParent(S);
		while (Parent) {
			if (isa<CompoundStmt>(Parent))
				Parent = PDB.getParent(Parent);
			else
				break;
		}

		if (Parent) {
			switch (Parent->getStmtClass()) {
			case Stmt::DoStmtClass:
			case Stmt::ObjCAtSynchronizedStmtClass:
				addContext(Parent);
			default:
				break;
			}
		}

		addContext(S);
	}

	void EdgeBuilder::addContext(const Stmt *S) {
		if (!S)
			return;

		PathDiagnosticLocation L(S, PDB.getSourceManager(), PDB.LC);
		addContext(L);
	}

	void EdgeBuilder::addContext(const PathDiagnosticLocation &L) {
		while (!CLocs.empty()) {
			const PathDiagnosticLocation &TopContextLoc = CLocs.back();

			// Is the top location context the same as the one for the new location?
			if (TopContextLoc == L)
				return;

			if (containsLocation(TopContextLoc, L)) {
				CLocs.push_back(L);
				return;
			}

			// Context does not contain the location.  Flush it.
			popLocation();
		}

		CLocs.push_back(L);
	}
} // end of anonymous namespace

// Cone-of-influence: support the reverse propagation of "interesting" symbols
// and values by tracing interesting calculations backwards through evaluated
// expressions along a path.  This is probably overly complicated, but the idea
// is that if an expression computed an "interesting" value, the child
// expressions are are also likely to be "interesting" as well (which then
// propagates to the values they in turn compute).  This reverse propagation
// is needed to track interesting correlations across function call boundaries,
// where formal arguments bind to actual arguments, etc.  This is also needed
// because the constraint solver sometimes simplifies certain symbolic values
// into constants when appropriate, and this complicates reasoning about
// interesting values.
typedef llvm::DenseSet<const Expr *> InterestingExprs;

static void reversePropagateIntererstingSymbols(BugReport &R,
	InterestingExprs &IE,
	const ProgramState *State,
	const Expr *Ex,
	const LocationContext *LCtx) {
	SVal V = State->getSVal(Ex, LCtx);
	if (!(R.isInteresting(V) || IE.count(Ex)))
		return;

	switch (Ex->getStmtClass()) {
	default:
		if (!isa<CastExpr>(Ex))
			break;
		// Fall through.
	case Stmt::BinaryOperatorClass:
	case Stmt::UnaryOperatorClass: {
		for (Stmt::const_child_iterator CI = Ex->child_begin(),
			CE = Ex->child_end();
			CI != CE; ++CI) {
			if (const Expr *child = dyn_cast_or_null<Expr>(*CI)) {
				IE.insert(child);
				SVal ChildV = State->getSVal(child, LCtx);
				R.markInteresting(ChildV);
			}
		}
		break;
	}
	}

	R.markInteresting(V);
}

static void reversePropagateInterestingSymbols(BugReport &R,
	InterestingExprs &IE,
	const ProgramState *State,
	const LocationContext *CalleeCtx,
	const LocationContext *CallerCtx)
{
	// FIXME: Handle non-CallExpr-based CallEvents.
	const StackFrameContext *Callee = CalleeCtx->getCurrentStackFrame();
	const Stmt *CallSite = Callee->getCallSite();
	if (const CallExpr *CE = dyn_cast_or_null<CallExpr>(CallSite)) {
		if (const FunctionDecl *FD = dyn_cast<FunctionDecl>(CalleeCtx->getDecl())) {
			FunctionDecl::param_const_iterator PI = FD->param_begin(),
				PE = FD->param_end();
			CallExpr::const_arg_iterator AI = CE->arg_begin(), AE = CE->arg_end();
			for (; AI != AE && PI != PE; ++AI, ++PI) {
				if (const Expr *ArgE = *AI) {
					if (const ParmVarDecl *PD = *PI) {
						Loc LV = State->getLValue(PD, CalleeCtx);
						if (R.isInteresting(LV) || R.isInteresting(State->getRawSVal(LV)))
							IE.insert(ArgE);
					}
				}
			}
		}
	}
}

//===----------------------------------------------------------------------===//
// Functions for determining if a loop was executed 0 times.
//===----------------------------------------------------------------------===//

static bool isLoop(const Stmt *Term) {
	switch (Term->getStmtClass()) {
	case Stmt::ForStmtClass:
	case Stmt::WhileStmtClass:
	case Stmt::ObjCForCollectionStmtClass:
	case Stmt::CXXForRangeStmtClass:
		return true;
	default:
		// Note that we intentionally do not include do..while here.
		return false;
	}
}

static bool isJumpToFalseBranch(const BlockEdge *BE) {
	const CFGBlock *Src = BE->getSrc();
	assert(Src->succ_size() == 2);
	return (*(Src->succ_begin() + 1) == BE->getDst());
}

/// Return true if the terminator is a loop and the destination is the
/// false branch.
static bool isLoopJumpPastBody(const Stmt *Term, const BlockEdge *BE) {
	if (!isLoop(Term))
		return false;

	// Did we take the false branch?
	return isJumpToFalseBranch(BE);
}

static bool isContainedByStmt(ParentMap &PM, const Stmt *S, const Stmt *SubS) {
	while (SubS) {
		if (SubS == S)
			return true;
		SubS = PM.getParent(SubS);
	}
	return false;
}

static const Stmt *getStmtBeforeCond(ParentMap &PM, const Stmt *Term,
	const ExplodedNode *N) {
	while (N) {
		Optional<StmtPoint> SP = N->getLocation().getAs<StmtPoint>();
		if (SP) {
			const Stmt *S = SP->getStmt();
			if (!isContainedByStmt(PM, Term, S))
				return S;
		}
		N = N->getFirstPred();
	}
	return nullptr;
}

static bool isInLoopBody(ParentMap &PM, const Stmt *S, const Stmt *Term) {
	const Stmt *LoopBody = nullptr;
	switch (Term->getStmtClass()) {
	case Stmt::CXXForRangeStmtClass: {
		const CXXForRangeStmt *FR = cast<CXXForRangeStmt>(Term);
		if (isContainedByStmt(PM, FR->getInc(), S))
			return true;
		if (isContainedByStmt(PM, FR->getLoopVarStmt(), S))
			return true;
		LoopBody = FR->getBody();
		break;
	}
	case Stmt::ForStmtClass: {
		const ForStmt *FS = cast<ForStmt>(Term);
		if (isContainedByStmt(PM, FS->getInc(), S))
			return true;
		LoopBody = FS->getBody();
		break;
	}
	case Stmt::ObjCForCollectionStmtClass: {
		const ObjCForCollectionStmt *FC = cast<ObjCForCollectionStmt>(Term);
		LoopBody = FC->getBody();
		break;
	}
	case Stmt::WhileStmtClass:
		LoopBody = cast<WhileStmt>(Term)->getBody();
		break;
	default:
		return false;
	}
	return isContainedByStmt(PM, LoopBody, S);
}

//===----------------------------------------------------------------------===//
// Top-level logic for generating extensive path diagnostics.
//===----------------------------------------------------------------------===//

static bool GenerateExtensivePathDiagnostic(
	PathDiagnostic &PD, PathDiagnosticBuilder &PDB, const ExplodedNode *N,
	LocationContextMap &LCM,
	ArrayRef<std::unique_ptr<BugReporterVisitor>> visitors) {
	EdgeBuilder EB(PD, PDB);
	const SourceManager& SM = PDB.getSourceManager();
	StackDiagVector CallStack;
	InterestingExprs IE;

	const ExplodedNode *NextNode = N->pred_empty() ? nullptr : *(N->pred_begin());
	while (NextNode) {
		N = NextNode;
		NextNode = N->getFirstPred();
		ProgramPoint P = N->getLocation();

		do {
			if (Optional<PostStmt> PS = P.getAs<PostStmt>()) {
				if (const Expr *Ex = PS->getStmtAs<Expr>())
					reversePropagateIntererstingSymbols(*PDB.getBugReport(), IE,
					N->getState().get(), Ex,
					N->getLocationContext());
			}

			if (Optional<CallExitEnd> CE = P.getAs<CallExitEnd>()) {
				const Stmt *S = CE->getCalleeContext()->getCallSite();
				if (const Expr *Ex = dyn_cast_or_null<Expr>(S)) {
					reversePropagateIntererstingSymbols(*PDB.getBugReport(), IE,
						N->getState().get(), Ex,
						N->getLocationContext());
				}

				PathDiagnosticCallPiece *C =
					PathDiagnosticCallPiece::construct(N, *CE, SM);
				LCM[&C->path] = CE->getCalleeContext();

				EB.addEdge(C->callReturn, /*AlwaysAdd=*/true, /*IsPostJump=*/true);
				EB.flushLocations();

				PD.getActivePath().push_front(C);
				PD.pushActivePath(&C->path);
				CallStack.push_back(StackDiagPair(C, N));
				break;
			}

			// Pop the call hierarchy if we are done walking the contents
			// of a function call.
			if (Optional<CallEnter> CE = P.getAs<CallEnter>()) {
				// Add an edge to the start of the function.
				const Decl *D = CE->getCalleeContext()->getDecl();
				PathDiagnosticLocation pos =
					PathDiagnosticLocation::createBegin(D, SM);
				EB.addEdge(pos);

				// Flush all locations, and pop the active path.
				bool VisitedEntireCall = PD.isWithinCall();
				EB.flushLocations();
				PD.popActivePath();
				PDB.LC = N->getLocationContext();

				// Either we just added a bunch of stuff to the top-level path, or
				// we have a previous CallExitEnd.  If the former, it means that the
				// path terminated within a function call.  We must then take the
				// current contents of the active path and place it within
				// a new PathDiagnosticCallPiece.
				PathDiagnosticCallPiece *C;
				if (VisitedEntireCall) {
					C = cast<PathDiagnosticCallPiece>(PD.getActivePath().front());
				}
				else {
					const Decl *Caller = CE->getLocationContext()->getDecl();
					C = PathDiagnosticCallPiece::construct(PD.getActivePath(), Caller);
					LCM[&C->path] = CE->getCalleeContext();
				}

				C->setCallee(*CE, SM);
				EB.addContext(C->getLocation());

				if (!CallStack.empty()) {
					assert(CallStack.back().first == C);
					CallStack.pop_back();
				}
				break;
			}

			// Note that is important that we update the LocationContext
			// after looking at CallExits.  CallExit basically adds an
			// edge in the *caller*, so we don't want to update the LocationContext
			// too soon.
			PDB.LC = N->getLocationContext();

			// Block edges.
			if (Optional<BlockEdge> BE = P.getAs<BlockEdge>()) {
				// Does this represent entering a call?  If so, look at propagating
				// interesting symbols across call boundaries.
				if (NextNode) {
					const LocationContext *CallerCtx = NextNode->getLocationContext();
					const LocationContext *CalleeCtx = PDB.LC;
					if (CallerCtx != CalleeCtx) {
						reversePropagateInterestingSymbols(*PDB.getBugReport(), IE,
							N->getState().get(),
							CalleeCtx, CallerCtx);
					}
				}

				// Are we jumping to the head of a loop?  Add a special diagnostic.
				if (const Stmt *Loop = BE->getSrc()->getLoopTarget()) {
					PathDiagnosticLocation L(Loop, SM, PDB.LC);
					const CompoundStmt *CS = nullptr;

					if (const ForStmt *FS = dyn_cast<ForStmt>(Loop))
						CS = dyn_cast<CompoundStmt>(FS->getBody());
					else if (const WhileStmt *WS = dyn_cast<WhileStmt>(Loop))
						CS = dyn_cast<CompoundStmt>(WS->getBody());

					PathDiagnosticEventPiece *p =
						new PathDiagnosticEventPiece(L,
						"Looping back to the head of the loop");
					p->setPrunable(true);

					EB.addEdge(p->getLocation(), true);
					PD.getActivePath().push_front(p);

					if (CS) {
						PathDiagnosticLocation BL =
							PathDiagnosticLocation::createEndBrace(CS, SM);
						EB.addEdge(BL);
					}
				}

				const CFGBlock *BSrc = BE->getSrc();
				ParentMap &PM = PDB.getParentMap();

				if (const Stmt *Term = BSrc->getTerminator()) {
					// Are we jumping past the loop body without ever executing the
					// loop (because the condition was false)?
					if (isLoopJumpPastBody(Term, &*BE) &&
						!isInLoopBody(PM,
						getStmtBeforeCond(PM,
						BSrc->getTerminatorCondition(),
						N),
						Term)) {
						PathDiagnosticLocation L(Term, SM, PDB.LC);
						PathDiagnosticEventPiece *PE =
							new PathDiagnosticEventPiece(L, "Loop body executed 0 times");
						PE->setPrunable(true);

						EB.addEdge(PE->getLocation(), true);
						PD.getActivePath().push_front(PE);
					}

					// In any case, add the terminator as the current statement
					// context for control edges.
					EB.addContext(Term);
				}

				break;
			}

			if (Optional<BlockEntrance> BE = P.getAs<BlockEntrance>()) {
				Optional<CFGElement> First = BE->getFirstElement();
				if (Optional<CFGStmt> S = First ? First->getAs<CFGStmt>() : None) {
					const Stmt *stmt = S->getStmt();
					if (IsControlFlowExpr(stmt)) {
						// Add the proper context for '&&', '||', and '?'.
						EB.addContext(stmt);
					}
					else
						EB.addExtendedContext(PDB.getEnclosingStmtLocation(stmt).asStmt());
				}

				break;
			}


		} while (0);

		if (!NextNode)
			continue;

		// Add pieces from custom visitors.
		BugReport *R = PDB.getBugReport();
		for (auto &V : visitors) {
			if (PathDiagnosticPiece *p = V->VisitNode(N, NextNode, PDB, *R)) {
				const PathDiagnosticLocation &Loc = p->getLocation();
				EB.addEdge(Loc, true);
				PD.getActivePath().push_front(p);
				updateStackPiecesWithMessage(p, CallStack);

				if (const Stmt *S = Loc.asStmt())
					EB.addExtendedContext(PDB.getEnclosingStmtLocation(S).asStmt());
			}
		}
	}

	return PDB.getBugReport()->isValid();
}

/// \brief Adds a sanitized control-flow diagnostic edge to a path.
static void addEdgeToPath(PathPieces &path,
	PathDiagnosticLocation &PrevLoc,
	PathDiagnosticLocation NewLoc,
	const LocationContext *LC) {
	if (!NewLoc.isValid())
		return;

	SourceLocation NewLocL = NewLoc.asLocation();
	if (NewLocL.isInvalid())
		return;

	if (!PrevLoc.isValid() || !PrevLoc.asLocation().isValid()) {
		PrevLoc = NewLoc;
		return;
	}

	// Ignore self-edges, which occur when there are multiple nodes at the same
	// statement.
	if (NewLoc.asStmt() && NewLoc.asStmt() == PrevLoc.asStmt())
		return;

	path.push_front(new PathDiagnosticControlFlowPiece(NewLoc,
		PrevLoc));
	PrevLoc = NewLoc;
}

/// A customized wrapper for CFGBlock::getTerminatorCondition()
/// which returns the element for ObjCForCollectionStmts.
static const Stmt *getTerminatorCondition(const CFGBlock *B) {
	const Stmt *S = B->getTerminatorCondition();
	if (const ObjCForCollectionStmt *FS =
		dyn_cast_or_null<ObjCForCollectionStmt>(S))
		return FS->getElement();
	return S;
}

static const char StrEnteringLoop[] = "Entering loop body";
static const char StrLoopBodyZero[] = "Loop body executed 0 times";
static const char StrLoopRangeEmpty[] =
"Loop body skipped when range is empty";
static const char StrLoopCollectionEmpty[] =
"Loop body skipped when collection is empty";

static bool GenerateAlternateExtensivePathDiagnostic(
	PathDiagnostic &PD, PathDiagnosticBuilder &PDB, const ExplodedNode *N,
	LocationContextMap &LCM,
	ArrayRef<std::unique_ptr<BugReporterVisitor>> visitors) {

	BugReport *report = PDB.getBugReport();
	const SourceManager& SM = PDB.getSourceManager();
	StackDiagVector CallStack;
	InterestingExprs IE;

	PathDiagnosticLocation PrevLoc = PD.getLocation();

	const ExplodedNode *NextNode = N->getFirstPred();
	while (NextNode) {
		N = NextNode;
		NextNode = N->getFirstPred();
		ProgramPoint P = N->getLocation();

		do {
			// Have we encountered an entrance to a call?  It may be
			// the case that we have not encountered a matching
			// call exit before this point.  This means that the path
			// terminated within the call itself.
			if (Optional<CallEnter> CE = P.getAs<CallEnter>()) {
				// Add an edge to the start of the function.
				const StackFrameContext *CalleeLC = CE->getCalleeContext();
				const Decl *D = CalleeLC->getDecl();
				addEdgeToPath(PD.getActivePath(), PrevLoc,
					PathDiagnosticLocation::createBegin(D, SM),
					CalleeLC);

				// Did we visit an entire call?
				bool VisitedEntireCall = PD.isWithinCall();
				PD.popActivePath();

				PathDiagnosticCallPiece *C;
				if (VisitedEntireCall) {
					PathDiagnosticPiece *P = PD.getActivePath().front().get();
					C = cast<PathDiagnosticCallPiece>(P);
				}
				else {
					const Decl *Caller = CE->getLocationContext()->getDecl();
					C = PathDiagnosticCallPiece::construct(PD.getActivePath(), Caller);

					// Since we just transferred the path over to the call piece,
					// reset the mapping from active to location context.
					assert(PD.getActivePath().size() == 1 &&
						PD.getActivePath().front() == C);
					LCM[&PD.getActivePath()] = nullptr;

					// Record the location context mapping for the path within
					// the call.
					assert(LCM[&C->path] == nullptr ||
						LCM[&C->path] == CE->getCalleeContext());
					LCM[&C->path] = CE->getCalleeContext();

					// If this is the first item in the active path, record
					// the new mapping from active path to location context.
					const LocationContext *&NewLC = LCM[&PD.getActivePath()];
					if (!NewLC)
						NewLC = N->getLocationContext();

					PDB.LC = NewLC;
				}
				C->setCallee(*CE, SM);

				// Update the previous location in the active path.
				PrevLoc = C->getLocation();

				if (!CallStack.empty()) {
					assert(CallStack.back().first == C);
					CallStack.pop_back();
				}
				break;
			}

			// Query the location context here and the previous location
			// as processing CallEnter may change the active path.
			PDB.LC = N->getLocationContext();

			// Record the mapping from the active path to the location
			// context.
			assert(!LCM[&PD.getActivePath()] ||
				LCM[&PD.getActivePath()] == PDB.LC);
			LCM[&PD.getActivePath()] = PDB.LC;

			// Have we encountered an exit from a function call?
			if (Optional<CallExitEnd> CE = P.getAs<CallExitEnd>()) {
				const Stmt *S = CE->getCalleeContext()->getCallSite();
				// Propagate the interesting symbols accordingly.
				if (const Expr *Ex = dyn_cast_or_null<Expr>(S)) {
					reversePropagateIntererstingSymbols(*PDB.getBugReport(), IE,
						N->getState().get(), Ex,
						N->getLocationContext());
				}

				// We are descending into a call (backwards).  Construct
				// a new call piece to contain the path pieces for that call.
				PathDiagnosticCallPiece *C =
					PathDiagnosticCallPiece::construct(N, *CE, SM);

				// Record the location context for this call piece.
				LCM[&C->path] = CE->getCalleeContext();

				// Add the edge to the return site.
				addEdgeToPath(PD.getActivePath(), PrevLoc, C->callReturn, PDB.LC);
				PD.getActivePath().push_front(C);
				PrevLoc.invalidate();

				// Make the contents of the call the active path for now.
				PD.pushActivePath(&C->path);
				CallStack.push_back(StackDiagPair(C, N));
				break;
			}

			if (Optional<PostStmt> PS = P.getAs<PostStmt>()) {
				// For expressions, make sure we propagate the
				// interesting symbols correctly.
				if (const Expr *Ex = PS->getStmtAs<Expr>())
					reversePropagateIntererstingSymbols(*PDB.getBugReport(), IE,
					N->getState().get(), Ex,
					N->getLocationContext());

				// Add an edge.  If this is an ObjCForCollectionStmt do
				// not add an edge here as it appears in the CFG both
				// as a terminator and as a terminator condition.
				if (!isa<ObjCForCollectionStmt>(PS->getStmt())) {
					PathDiagnosticLocation L =
						PathDiagnosticLocation(PS->getStmt(), SM, PDB.LC);
					addEdgeToPath(PD.getActivePath(), PrevLoc, L, PDB.LC);
				}
				break;
			}

			// Block edges.
			if (Optional<BlockEdge> BE = P.getAs<BlockEdge>()) {
				// Does this represent entering a call?  If so, look at propagating
				// interesting symbols across call boundaries.
				if (NextNode) {
					const LocationContext *CallerCtx = NextNode->getLocationContext();
					const LocationContext *CalleeCtx = PDB.LC;
					if (CallerCtx != CalleeCtx) {
						reversePropagateInterestingSymbols(*PDB.getBugReport(), IE,
							N->getState().get(),
							CalleeCtx, CallerCtx);
					}
				}

				// Are we jumping to the head of a loop?  Add a special diagnostic.
				if (const Stmt *Loop = BE->getSrc()->getLoopTarget()) {
					PathDiagnosticLocation L(Loop, SM, PDB.LC);
					const Stmt *Body = nullptr;

					if (const ForStmt *FS = dyn_cast<ForStmt>(Loop))
						Body = FS->getBody();
					else if (const WhileStmt *WS = dyn_cast<WhileStmt>(Loop))
						Body = WS->getBody();
					else if (const ObjCForCollectionStmt *OFS =
						dyn_cast<ObjCForCollectionStmt>(Loop)) {
						Body = OFS->getBody();
					}
					else if (const CXXForRangeStmt *FRS =
						dyn_cast<CXXForRangeStmt>(Loop)) {
						Body = FRS->getBody();
					}
					// do-while statements are explicitly excluded here

					PathDiagnosticEventPiece *p =
						new PathDiagnosticEventPiece(L, "Looping back to the head "
						"of the loop");
					p->setPrunable(true);

					addEdgeToPath(PD.getActivePath(), PrevLoc, p->getLocation(), PDB.LC);
					PD.getActivePath().push_front(p);

					if (const CompoundStmt *CS = dyn_cast_or_null<CompoundStmt>(Body)) {
						addEdgeToPath(PD.getActivePath(), PrevLoc,
							PathDiagnosticLocation::createEndBrace(CS, SM),
							PDB.LC);
					}
				}

				const CFGBlock *BSrc = BE->getSrc();
				ParentMap &PM = PDB.getParentMap();

				if (const Stmt *Term = BSrc->getTerminator()) {
					// Are we jumping past the loop body without ever executing the
					// loop (because the condition was false)?
					if (isLoop(Term)) {
						const Stmt *TermCond = getTerminatorCondition(BSrc);
						bool IsInLoopBody =
							isInLoopBody(PM, getStmtBeforeCond(PM, TermCond, N), Term);

						const char *str = nullptr;

						if (isJumpToFalseBranch(&*BE)) {
							if (!IsInLoopBody) {
								if (isa<ObjCForCollectionStmt>(Term)) {
									str = StrLoopCollectionEmpty;
								}
								else if (isa<CXXForRangeStmt>(Term)) {
									str = StrLoopRangeEmpty;
								}
								else {
									str = StrLoopBodyZero;
								}
							}
						}
						else {
							str = StrEnteringLoop;
						}

						if (str) {
							PathDiagnosticLocation L(TermCond ? TermCond : Term, SM, PDB.LC);
							PathDiagnosticEventPiece *PE =
								new PathDiagnosticEventPiece(L, str);
							PE->setPrunable(true);
							addEdgeToPath(PD.getActivePath(), PrevLoc,
								PE->getLocation(), PDB.LC);
							PD.getActivePath().push_front(PE);
						}
					}
					else if (isa<BreakStmt>(Term) || isa<ContinueStmt>(Term) ||
						isa<GotoStmt>(Term)) {
						PathDiagnosticLocation L(Term, SM, PDB.LC);
						addEdgeToPath(PD.getActivePath(), PrevLoc, L, PDB.LC);
					}
				}
				break;
			}
		} while (0);

		if (!NextNode)
			continue;

		// Add pieces from custom visitors.
		for (auto &V : visitors) {
			if (PathDiagnosticPiece *p = V->VisitNode(N, NextNode, PDB, *report)) {
				addEdgeToPath(PD.getActivePath(), PrevLoc, p->getLocation(), PDB.LC);
				PD.getActivePath().push_front(p);
				updateStackPiecesWithMessage(p, CallStack);
			}
		}
	}

	// Add an edge to the start of the function.
	// We'll prune it out later, but it helps make diagnostics more uniform.
	const StackFrameContext *CalleeLC = PDB.LC->getCurrentStackFrame();
	const Decl *D = CalleeLC->getDecl();
	addEdgeToPath(PD.getActivePath(), PrevLoc,
		PathDiagnosticLocation::createBegin(D, SM),
		CalleeLC);

	return report->isValid();
}

static const Stmt *getLocStmt(PathDiagnosticLocation L) {
	if (!L.isValid())
		return nullptr;
	return L.asStmt();
}

static const Stmt *getStmtParent(const Stmt *S, const ParentMap &PM) {
	if (!S)
		return nullptr;

	while (true) {
		S = PM.getParentIgnoreParens(S);

		if (!S)
			break;

		if (isa<ExprWithCleanups>(S) ||
			isa<CXXBindTemporaryExpr>(S) ||
			isa<SubstNonTypeTemplateParmExpr>(S))
			continue;

		break;
	}

	return S;
}

static bool isConditionForTerminator(const Stmt *S, const Stmt *Cond) {
	switch (S->getStmtClass()) {
	case Stmt::BinaryOperatorClass: {
		const BinaryOperator *BO = cast<BinaryOperator>(S);
		if (!BO->isLogicalOp())
			return false;
		return BO->getLHS() == Cond || BO->getRHS() == Cond;
	}
	case Stmt::IfStmtClass:
		return cast<IfStmt>(S)->getCond() == Cond;
	case Stmt::ForStmtClass:
		return cast<ForStmt>(S)->getCond() == Cond;
	case Stmt::WhileStmtClass:
		return cast<WhileStmt>(S)->getCond() == Cond;
	case Stmt::DoStmtClass:
		return cast<DoStmt>(S)->getCond() == Cond;
	case Stmt::ChooseExprClass:
		return cast<ChooseExpr>(S)->getCond() == Cond;
	case Stmt::IndirectGotoStmtClass:
		return cast<IndirectGotoStmt>(S)->getTarget() == Cond;
	case Stmt::SwitchStmtClass:
		return cast<SwitchStmt>(S)->getCond() == Cond;
	case Stmt::BinaryConditionalOperatorClass:
		return cast<BinaryConditionalOperator>(S)->getCond() == Cond;
	case Stmt::ConditionalOperatorClass: {
		const ConditionalOperator *CO = cast<ConditionalOperator>(S);
		return CO->getCond() == Cond ||
			CO->getLHS() == Cond ||
			CO->getRHS() == Cond;
	}
	case Stmt::ObjCForCollectionStmtClass:
		return cast<ObjCForCollectionStmt>(S)->getElement() == Cond;
	case Stmt::CXXForRangeStmtClass: {
		const CXXForRangeStmt *FRS = cast<CXXForRangeStmt>(S);
		return FRS->getCond() == Cond || FRS->getRangeInit() == Cond;
	}
	default:
		return false;
	}
}

static bool isIncrementOrInitInForLoop(const Stmt *S, const Stmt *FL) {
	if (const ForStmt *FS = dyn_cast<ForStmt>(FL))
		return FS->getInc() == S || FS->getInit() == S;
	if (const CXXForRangeStmt *FRS = dyn_cast<CXXForRangeStmt>(FL))
		return FRS->getInc() == S || FRS->getRangeStmt() == S ||
		FRS->getLoopVarStmt() || FRS->getRangeInit() == S;
	return false;
}

typedef llvm::DenseSet<const PathDiagnosticCallPiece *>
OptimizedCallsSet;

/// Adds synthetic edges from top-level statements to their subexpressions.
///
/// This avoids a "swoosh" effect, where an edge from a top-level statement A
/// points to a sub-expression B.1 that's not at the start of B. In these cases,
/// we'd like to see an edge from A to B, then another one from B to B.1.
static void addContextEdges(PathPieces &pieces, SourceManager &SM,
	const ParentMap &PM, const LocationContext *LCtx) {
	PathPieces::iterator Prev = pieces.end();
	for (PathPieces::iterator I = pieces.begin(), E = Prev; I != E;
		Prev = I, ++I) {
		PathDiagnosticControlFlowPiece *Piece =
			dyn_cast<PathDiagnosticControlFlowPiece>(*I);

		if (!Piece)
			continue;

		PathDiagnosticLocation SrcLoc = Piece->getStartLocation();
		SmallVector<PathDiagnosticLocation, 4> SrcContexts;

		PathDiagnosticLocation NextSrcContext = SrcLoc;
		const Stmt *InnerStmt = nullptr;
		while (NextSrcContext.isValid() && NextSrcContext.asStmt() != InnerStmt) {
			SrcContexts.push_back(NextSrcContext);
			InnerStmt = NextSrcContext.asStmt();
			NextSrcContext = getEnclosingStmtLocation(InnerStmt, SM, PM, LCtx,
				/*allowNested=*/true);
		}

		// Repeatedly split the edge as necessary.
		// This is important for nested logical expressions (||, &&, ?:) where we
		// want to show all the levels of context.
		while (true) {
			const Stmt *Dst = getLocStmt(Piece->getEndLocation());

			// We are looking at an edge. Is the destination within a larger
			// expression?
			PathDiagnosticLocation DstContext =
				getEnclosingStmtLocation(Dst, SM, PM, LCtx, /*allowNested=*/true);
			if (!DstContext.isValid() || DstContext.asStmt() == Dst)
				break;

			// If the source is in the same context, we're already good.
			if (std::find(SrcContexts.begin(), SrcContexts.end(), DstContext) !=
				SrcContexts.end())
				break;

			// Update the subexpression node to point to the context edge.
			Piece->setStartLocation(DstContext);

			// Try to extend the previous edge if it's at the same level as the source
			// context.
			if (Prev != E) {
				PathDiagnosticControlFlowPiece *PrevPiece =
					dyn_cast<PathDiagnosticControlFlowPiece>(*Prev);

				if (PrevPiece) {
					if (const Stmt *PrevSrc = getLocStmt(PrevPiece->getStartLocation())) {
						const Stmt *PrevSrcParent = getStmtParent(PrevSrc, PM);
						if (PrevSrcParent == getStmtParent(getLocStmt(DstContext), PM)) {
							PrevPiece->setEndLocation(DstContext);
							break;
						}
					}
				}
			}

			// Otherwise, split the current edge into a context edge and a
			// subexpression edge. Note that the context statement may itself have
			// context.
			Piece = new PathDiagnosticControlFlowPiece(SrcLoc, DstContext);
			I = pieces.insert(I, Piece);
		}
	}
}

/// \brief Move edges from a branch condition to a branch target
///        when the condition is simple.
///
/// This restructures some of the work of addContextEdges.  That function
/// creates edges this may destroy, but they work together to create a more
/// aesthetically set of edges around branches.  After the call to
/// addContextEdges, we may have (1) an edge to the branch, (2) an edge from
/// the branch to the branch condition, and (3) an edge from the branch
/// condition to the branch target.  We keep (1), but may wish to remove (2)
/// and move the source of (3) to the branch if the branch condition is simple.
///
static void simplifySimpleBranches(PathPieces &pieces) {
	for (PathPieces::iterator I = pieces.begin(), E = pieces.end(); I != E; ++I) {

		PathDiagnosticControlFlowPiece *PieceI =
			dyn_cast<PathDiagnosticControlFlowPiece>(*I);

		if (!PieceI)
			continue;

		const Stmt *s1Start = getLocStmt(PieceI->getStartLocation());
		const Stmt *s1End = getLocStmt(PieceI->getEndLocation());

		if (!s1Start || !s1End)
			continue;

		PathPieces::iterator NextI = I; ++NextI;
		if (NextI == E)
			break;

		PathDiagnosticControlFlowPiece *PieceNextI = nullptr;

		while (true) {
			if (NextI == E)
				break;

			PathDiagnosticEventPiece *EV = dyn_cast<PathDiagnosticEventPiece>(*NextI);
			if (EV) {
				StringRef S = EV->getString();
				if (S == StrEnteringLoop || S == StrLoopBodyZero ||
					S == StrLoopCollectionEmpty || S == StrLoopRangeEmpty) {
					++NextI;
					continue;
				}
				break;
			}

			PieceNextI = dyn_cast<PathDiagnosticControlFlowPiece>(*NextI);
			break;
		}

		if (!PieceNextI)
			continue;

		const Stmt *s2Start = getLocStmt(PieceNextI->getStartLocation());
		const Stmt *s2End = getLocStmt(PieceNextI->getEndLocation());

		if (!s2Start || !s2End || s1End != s2Start)
			continue;

		// We only perform this transformation for specific branch kinds.
		// We don't want to do this for do..while, for example.
		if (!(isa<ForStmt>(s1Start) || isa<WhileStmt>(s1Start) ||
			isa<IfStmt>(s1Start) || isa<ObjCForCollectionStmt>(s1Start) ||
			isa<CXXForRangeStmt>(s1Start)))
			continue;

		// Is s1End the branch condition?
		if (!isConditionForTerminator(s1Start, s1End))
			continue;

		// Perform the hoisting by eliminating (2) and changing the start
		// location of (3).
		PieceNextI->setStartLocation(PieceI->getStartLocation());
		I = pieces.erase(I);
	}
}

/// Returns the number of bytes in the given (character-based) SourceRange.
///
/// If the locations in the range are not on the same line, returns None.
///
/// Note that this does not do a precise user-visible character or column count.
static Optional<size_t> getLengthOnSingleLine(SourceManager &SM,
	SourceRange Range) {
	SourceRange ExpansionRange(SM.getExpansionLoc(Range.getBegin()),
		SM.getExpansionRange(Range.getEnd()).second);

	FileID FID = SM.getFileID(ExpansionRange.getBegin());
	if (FID != SM.getFileID(ExpansionRange.getEnd()))
		return None;

	bool Invalid;
	const llvm::MemoryBuffer *Buffer = SM.getBuffer(FID, &Invalid);
	if (Invalid)
		return None;

	unsigned BeginOffset = SM.getFileOffset(ExpansionRange.getBegin());
	unsigned EndOffset = SM.getFileOffset(ExpansionRange.getEnd());
	StringRef Snippet = Buffer->getBuffer().slice(BeginOffset, EndOffset);

	// We're searching the raw bytes of the buffer here, which might include
	// escaped newlines and such. That's okay; we're trying to decide whether the
	// SourceRange is covering a large or small amount of space in the user's
	// editor.
	if (Snippet.find_first_of("\r\n") != StringRef::npos)
		return None;

	// This isn't Unicode-aware, but it doesn't need to be.
	return Snippet.size();
}

/// \sa getLengthOnSingleLine(SourceManager, SourceRange)
static Optional<size_t> getLengthOnSingleLine(SourceManager &SM,
	const Stmt *S) {
	return getLengthOnSingleLine(SM, S->getSourceRange());
}

/// Eliminate two-edge cycles created by addContextEdges().
///
/// Once all the context edges are in place, there are plenty of cases where
/// there's a single edge from a top-level statement to a subexpression,
/// followed by a single path note, and then a reverse edge to get back out to
/// the top level. If the statement is simple enough, the subexpression edges
/// just add noise and make it harder to understand what's going on.
///
/// This function only removes edges in pairs, because removing only one edge
/// might leave other edges dangling.
///
/// This will not remove edges in more complicated situations:
/// - if there is more than one "hop" leading to or from a subexpression.
/// - if there is an inlined call between the edges instead of a single event.
/// - if the whole statement is large enough that having subexpression arrows
///   might be helpful.
static void removeContextCycles(PathPieces &Path, SourceManager &SM,
	ParentMap &PM) {
	for (PathPieces::iterator I = Path.begin(), E = Path.end(); I != E;) {
		// Pattern match the current piece and its successor.
		PathDiagnosticControlFlowPiece *PieceI =
			dyn_cast<PathDiagnosticControlFlowPiece>(*I);

		if (!PieceI) {
			++I;
			continue;
		}

		const Stmt *s1Start = getLocStmt(PieceI->getStartLocation());
		const Stmt *s1End = getLocStmt(PieceI->getEndLocation());

		PathPieces::iterator NextI = I; ++NextI;
		if (NextI == E)
			break;

		PathDiagnosticControlFlowPiece *PieceNextI =
			dyn_cast<PathDiagnosticControlFlowPiece>(*NextI);

		if (!PieceNextI) {
			if (isa<PathDiagnosticEventPiece>(*NextI)) {
				++NextI;
				if (NextI == E)
					break;
				PieceNextI = dyn_cast<PathDiagnosticControlFlowPiece>(*NextI);
			}

			if (!PieceNextI) {
				++I;
				continue;
			}
		}

		const Stmt *s2Start = getLocStmt(PieceNextI->getStartLocation());
		const Stmt *s2End = getLocStmt(PieceNextI->getEndLocation());

		if (s1Start && s2Start && s1Start == s2End && s2Start == s1End) {
			const size_t MAX_SHORT_LINE_LENGTH = 80;
			Optional<size_t> s1Length = getLengthOnSingleLine(SM, s1Start);
			if (s1Length && *s1Length <= MAX_SHORT_LINE_LENGTH) {
				Optional<size_t> s2Length = getLengthOnSingleLine(SM, s2Start);
				if (s2Length && *s2Length <= MAX_SHORT_LINE_LENGTH) {
					Path.erase(I);
					I = Path.erase(NextI);
					continue;
				}
			}
		}

		++I;
	}
}

/// \brief Return true if X is contained by Y.
static bool lexicalContains(ParentMap &PM,
	const Stmt *X,
	const Stmt *Y) {
	while (X) {
		if (X == Y)
			return true;
		X = PM.getParent(X);
	}
	return false;
}

// Remove short edges on the same line less than 3 columns in difference.
static void removePunyEdges(PathPieces &path,
	SourceManager &SM,
	ParentMap &PM) {

	bool erased = false;

	for (PathPieces::iterator I = path.begin(), E = path.end(); I != E;
		erased ? I : ++I) {

		erased = false;

		PathDiagnosticControlFlowPiece *PieceI =
			dyn_cast<PathDiagnosticControlFlowPiece>(*I);

		if (!PieceI)
			continue;

		const Stmt *start = getLocStmt(PieceI->getStartLocation());
		const Stmt *end = getLocStmt(PieceI->getEndLocation());

		if (!start || !end)
			continue;

		const Stmt *endParent = PM.getParent(end);
		if (!endParent)
			continue;

		if (isConditionForTerminator(end, endParent))
			continue;

		SourceLocation FirstLoc = start->getLocStart();
		SourceLocation SecondLoc = end->getLocStart();

		if (!SM.isWrittenInSameFile(FirstLoc, SecondLoc))
			continue;
		if (SM.isBeforeInTranslationUnit(SecondLoc, FirstLoc))
			std::swap(SecondLoc, FirstLoc);

		SourceRange EdgeRange(FirstLoc, SecondLoc);
		Optional<size_t> ByteWidth = getLengthOnSingleLine(SM, EdgeRange);

		// If the statements are on different lines, continue.
		if (!ByteWidth)
			continue;

		const size_t MAX_PUNY_EDGE_LENGTH = 2;
		if (*ByteWidth <= MAX_PUNY_EDGE_LENGTH) {
			// FIXME: There are enough /bytes/ between the endpoints of the edge, but
			// there might not be enough /columns/. A proper user-visible column count
			// is probably too expensive, though.
			I = path.erase(I);
			erased = true;
			continue;
		}
	}
}

static void removeIdenticalEvents(PathPieces &path) {
	for (PathPieces::iterator I = path.begin(), E = path.end(); I != E; ++I) {
		PathDiagnosticEventPiece *PieceI =
			dyn_cast<PathDiagnosticEventPiece>(*I);

		if (!PieceI)
			continue;

		PathPieces::iterator NextI = I; ++NextI;
		if (NextI == E)
			return;

		PathDiagnosticEventPiece *PieceNextI =
			dyn_cast<PathDiagnosticEventPiece>(*NextI);

		if (!PieceNextI)
			continue;

		// Erase the second piece if it has the same exact message text.
		if (PieceI->getString() == PieceNextI->getString()) {
			path.erase(NextI);
		}
	}
}

static bool optimizeEdges(PathPieces &path, SourceManager &SM,
	OptimizedCallsSet &OCS,
	LocationContextMap &LCM) {
	bool hasChanges = false;
	const LocationContext *LC = LCM[&path];
	assert(LC);
	ParentMap &PM = LC->getParentMap();

	for (PathPieces::iterator I = path.begin(), E = path.end(); I != E;) {
		// Optimize subpaths.
		if (PathDiagnosticCallPiece *CallI = dyn_cast<PathDiagnosticCallPiece>(*I)){
			// Record the fact that a call has been optimized so we only do the
			// effort once.
			if (!OCS.count(CallI)) {
				while (optimizeEdges(CallI->path, SM, OCS, LCM)) {}
				OCS.insert(CallI);
			}
			++I;
			continue;
		}

		// Pattern match the current piece and its successor.
		PathDiagnosticControlFlowPiece *PieceI =
			dyn_cast<PathDiagnosticControlFlowPiece>(*I);

		if (!PieceI) {
			++I;
			continue;
		}

		const Stmt *s1Start = getLocStmt(PieceI->getStartLocation());
		const Stmt *s1End = getLocStmt(PieceI->getEndLocation());
		const Stmt *level1 = getStmtParent(s1Start, PM);
		const Stmt *level2 = getStmtParent(s1End, PM);

		PathPieces::iterator NextI = I; ++NextI;
		if (NextI == E)
			break;

		PathDiagnosticControlFlowPiece *PieceNextI =
			dyn_cast<PathDiagnosticControlFlowPiece>(*NextI);

		if (!PieceNextI) {
			++I;
			continue;
		}

		const Stmt *s2Start = getLocStmt(PieceNextI->getStartLocation());
		const Stmt *s2End = getLocStmt(PieceNextI->getEndLocation());
		const Stmt *level3 = getStmtParent(s2Start, PM);
		const Stmt *level4 = getStmtParent(s2End, PM);

		// Rule I.
		//
		// If we have two consecutive control edges whose end/begin locations
		// are at the same level (e.g. statements or top-level expressions within
		// a compound statement, or siblings share a single ancestor expression),
		// then merge them if they have no interesting intermediate event.
		//
		// For example:
		//
		// (1.1 -> 1.2) -> (1.2 -> 1.3) becomes (1.1 -> 1.3) because the common
		// parent is '1'.  Here 'x.y.z' represents the hierarchy of statements.
		//
		// NOTE: this will be limited later in cases where we add barriers
		// to prevent this optimization.
		//
		if (level1 && level1 == level2 && level1 == level3 && level1 == level4) {
			PieceI->setEndLocation(PieceNextI->getEndLocation());
			path.erase(NextI);
			hasChanges = true;
			continue;
		}

		// Rule II.
		//
		// Eliminate edges between subexpressions and parent expressions
		// when the subexpression is consumed.
		//
		// NOTE: this will be limited later in cases where we add barriers
		// to prevent this optimization.
		//
		if (s1End && s1End == s2Start && level2) {
			bool removeEdge = false;
			// Remove edges into the increment or initialization of a
			// loop that have no interleaving event.  This means that
			// they aren't interesting.
			if (isIncrementOrInitInForLoop(s1End, level2))
				removeEdge = true;
			// Next only consider edges that are not anchored on
			// the condition of a terminator.  This are intermediate edges
			// that we might want to trim.
			else if (!isConditionForTerminator(level2, s1End)) {
				// Trim edges on expressions that are consumed by
				// the parent expression.
				if (isa<Expr>(s1End) && PM.isConsumedExpr(cast<Expr>(s1End))) {
					removeEdge = true;
				}
				// Trim edges where a lexical containment doesn't exist.
				// For example:
				//
				//  X -> Y -> Z
				//
				// If 'Z' lexically contains Y (it is an ancestor) and
				// 'X' does not lexically contain Y (it is a descendant OR
				// it has no lexical relationship at all) then trim.
				//
				// This can eliminate edges where we dive into a subexpression
				// and then pop back out, etc.
				else if (s1Start && s2End &&
					lexicalContains(PM, s2Start, s2End) &&
					!lexicalContains(PM, s1End, s1Start)) {
					removeEdge = true;
				}
				// Trim edges from a subexpression back to the top level if the
				// subexpression is on a different line.
				//
				// A.1 -> A -> B
				// becomes
				// A.1 -> B
				//
				// These edges just look ugly and don't usually add anything.
				else if (s1Start && s2End &&
					lexicalContains(PM, s1Start, s1End)) {
					SourceRange EdgeRange(PieceI->getEndLocation().asLocation(),
						PieceI->getStartLocation().asLocation());
					if (!getLengthOnSingleLine(SM, EdgeRange).hasValue())
						removeEdge = true;
				}
			}

			if (removeEdge) {
				PieceI->setEndLocation(PieceNextI->getEndLocation());
				path.erase(NextI);
				hasChanges = true;
				continue;
			}
		}

		// Optimize edges for ObjC fast-enumeration loops.
		//
		// (X -> collection) -> (collection -> element)
		//
		// becomes:
		//
		// (X -> element)
		if (s1End == s2Start) {
			const ObjCForCollectionStmt *FS =
				dyn_cast_or_null<ObjCForCollectionStmt>(level3);
			if (FS && FS->getCollection()->IgnoreParens() == s2Start &&
				s2End == FS->getElement()) {
				PieceI->setEndLocation(PieceNextI->getEndLocation());
				path.erase(NextI);
				hasChanges = true;
				continue;
			}
		}

		// No changes at this index?  Move to the next one.
		++I;
	}

	if (!hasChanges) {
		// Adjust edges into subexpressions to make them more uniform
		// and aesthetically pleasing.
		addContextEdges(path, SM, PM, LC);
		// Remove "cyclical" edges that include one or more context edges.
		removeContextCycles(path, SM, PM);
		// Hoist edges originating from branch conditions to branches
		// for simple branches.
		simplifySimpleBranches(path);
		// Remove any puny edges left over after primary optimization pass.
		removePunyEdges(path, SM, PM);
		// Remove identical events.
		removeIdenticalEvents(path);
	}

	return hasChanges;
}

/// Drop the very first edge in a path, which should be a function entry edge.
///
/// If the first edge is not a function entry edge (say, because the first
/// statement had an invalid source location), this function does nothing.
// FIXME: We should just generate invalid edges anyway and have the optimizer
// deal with them.
static void dropFunctionEntryEdge(PathPieces &Path,
	LocationContextMap &LCM,
	SourceManager &SM) {
	const PathDiagnosticControlFlowPiece *FirstEdge =
		dyn_cast<PathDiagnosticControlFlowPiece>(Path.front());
	if (!FirstEdge)
		return;

	const Decl *D = LCM[&Path]->getDecl();
	PathDiagnosticLocation EntryLoc = PathDiagnosticLocation::createBegin(D, SM);
	if (FirstEdge->getStartLocation() != EntryLoc)
		return;

	Path.pop_front();
}


/// CompactPathDiagnostic - This function postprocesses a PathDiagnostic object
///  and collapses PathDiagosticPieces that are expanded by macros.
static void CompactPathDiagnostic(PathPieces &path, const SourceManager& SM) {
	typedef std::vector<std::pair<IntrusiveRefCntPtr<PathDiagnosticMacroPiece>,
		SourceLocation> > MacroStackTy;

	typedef std::vector<IntrusiveRefCntPtr<PathDiagnosticPiece> >
		PiecesTy;

	MacroStackTy MacroStack;
	PiecesTy Pieces;

	for (PathPieces::const_iterator I = path.begin(), E = path.end();
		I != E; ++I) {

		PathDiagnosticPiece *piece = I->get();

		// Recursively compact calls.
		if (PathDiagnosticCallPiece *call = dyn_cast<PathDiagnosticCallPiece>(piece)){
			CompactPathDiagnostic(call->path, SM);
		}

		// Get the location of the PathDiagnosticPiece.
		const FullSourceLoc Loc = piece->getLocation().asLocation();

		// Determine the instantiation location, which is the location we group
		// related PathDiagnosticPieces.
		SourceLocation InstantiationLoc = Loc.isMacroID() ?
			SM.getExpansionLoc(Loc) :
			SourceLocation();

		if (Loc.isFileID()) {
			MacroStack.clear();
			Pieces.push_back(piece);
			continue;
		}

		assert(Loc.isMacroID());

		// Is the PathDiagnosticPiece within the same macro group?
		if (!MacroStack.empty() && InstantiationLoc == MacroStack.back().second) {
			MacroStack.back().first->subPieces.push_back(piece);
			continue;
		}

		// We aren't in the same group.  Are we descending into a new macro
		// or are part of an old one?
		IntrusiveRefCntPtr<PathDiagnosticMacroPiece> MacroGroup;

		SourceLocation ParentInstantiationLoc = InstantiationLoc.isMacroID() ?
			SM.getExpansionLoc(Loc) :
			SourceLocation();

		// Walk the entire macro stack.
		while (!MacroStack.empty()) {
			if (InstantiationLoc == MacroStack.back().second) {
				MacroGroup = MacroStack.back().first;
				break;
			}

			if (ParentInstantiationLoc == MacroStack.back().second) {
				MacroGroup = MacroStack.back().first;
				break;
			}

			MacroStack.pop_back();
		}

		if (!MacroGroup || ParentInstantiationLoc == MacroStack.back().second) {
			// Create a new macro group and add it to the stack.
			PathDiagnosticMacroPiece *NewGroup =
				new PathDiagnosticMacroPiece(
				PathDiagnosticLocation::createSingleLocation(piece->getLocation()));

			if (MacroGroup)
				MacroGroup->subPieces.push_back(NewGroup);
			else {
				assert(InstantiationLoc.isFileID());
				Pieces.push_back(NewGroup);
			}

			MacroGroup = NewGroup;
			MacroStack.push_back(std::make_pair(MacroGroup, InstantiationLoc));
		}

		// Finally, add the PathDiagnosticPiece to the group.
		MacroGroup->subPieces.push_back(piece);
	}

	// Now take the pieces and construct a new PathDiagnostic.
	path.clear();

	path.insert(path.end(), Pieces.begin(), Pieces.end());
}






































bool MyBugReporter::generatePathDiagnostic(PathDiagnostic& PD,
	PathDiagnosticConsumer &PC,
	ArrayRef<BugReport *> &bugReports) {
	assert(!bugReports.empty());

	bool HasValid = false;
	bool HasInvalid = false;
	SmallVector<const ExplodedNode *, 32> errorNodes;
	for (ArrayRef<BugReport*>::iterator I = bugReports.begin(),
		E = bugReports.end(); I != E; ++I) {
		if ((*I)->isValid()) {
			HasValid = true;
			errorNodes.push_back((*I)->getErrorNode());
		}
		else {
			// Keep the errorNodes list in sync with the bugReports list.
			HasInvalid = true;
			errorNodes.push_back(nullptr);
		}
	}

	// If all the reports have been marked invalid by a previous path generation,
	// we're done.
	if (!HasValid)
		return false;

	typedef PathDiagnosticConsumer::PathGenerationScheme PathGenerationScheme;
	PathGenerationScheme ActiveScheme = PC.getGenerationScheme();

	if (ActiveScheme == PathDiagnosticConsumer::Extensive) {
		AnalyzerOptions &options = getAnalyzerOptions();
		if (options.getBooleanOption("path-diagnostics-alternate", true)) {
			ActiveScheme = PathDiagnosticConsumer::AlternateExtensive;
		}
	}

	TrimmedGraph TrimG(&getGraph(), errorNodes);
	ReportGraph ErrorGraph;

	while (TrimG.popNextReportGraph(ErrorGraph)) {
		// Find the BugReport with the original location.
		assert(ErrorGraph.Index < bugReports.size());
		BugReport *R = bugReports[ErrorGraph.Index];
		assert(R && "No original report found for sliced graph.");
		assert(R->isValid() && "Report selected by trimmed graph marked invalid.");

		// Start building the path diagnostic...
		PathDiagnosticBuilder PDB(*this, R, ErrorGraph.BackMap, &PC);
		const ExplodedNode *N = ErrorGraph.ErrorNode;

		// Register additional node visitors.
		R->addVisitor(llvm::make_unique<NilReceiverBRVisitor>());
		R->addVisitor(llvm::make_unique<ConditionBRVisitor>());
		R->addVisitor(llvm::make_unique<LikelyFalsePositiveSuppressionBRVisitor>());

		BugReport::VisitorList visitors;
		unsigned origReportConfigToken, finalReportConfigToken;
		LocationContextMap LCM;

		// While generating diagnostics, it's possible the visitors will decide
		// new symbols and regions are interesting, or add other visitors based on
		// the information they find. If they do, we need to regenerate the path
		// based on our new report configuration.
		do {
			// Get a clean copy of all the visitors.
			for (BugReport::visitor_iterator I = R->visitor_begin(),
				E = R->visitor_end(); I != E; ++I)
				visitors.push_back((*I)->clone());

			// Clear out the active path from any previous work.
			PD.resetPath();
			origReportConfigToken = R->getConfigurationChangeToken();

			// Generate the very last diagnostic piece - the piece is visible before 
			// the trace is expanded.
			std::unique_ptr<PathDiagnosticPiece> LastPiece;
			for (BugReport::visitor_iterator I = visitors.begin(), E = visitors.end();
				I != E; ++I) {
				if (std::unique_ptr<PathDiagnosticPiece> Piece =
					(*I)->getEndPath(PDB, N, *R)) {
					assert(!LastPiece &&
						"There can only be one final piece in a diagnostic.");
					LastPiece = std::move(Piece);
				}
			}

			if (ActiveScheme != PathDiagnosticConsumer::None) {
				if (!LastPiece)
					LastPiece = BugReporterVisitor::getDefaultEndPath(PDB, N, *R);
				assert(LastPiece);
				PD.setEndOfPath(std::move(LastPiece));
			}

			// Make sure we get a clean location context map so we don't
			// hold onto old mappings.
			LCM.clear();

			switch (ActiveScheme) {
			case PathDiagnosticConsumer::AlternateExtensive:
				GenerateAlternateExtensivePathDiagnostic(PD, PDB, N, LCM, visitors);
				break;
			case PathDiagnosticConsumer::Extensive:
				GenerateExtensivePathDiagnostic(PD, PDB, N, LCM, visitors);
				break;
			case PathDiagnosticConsumer::Minimal:
				GenerateMinimalPathDiagnostic(PD, PDB, N, LCM, visitors);
				break;
			case PathDiagnosticConsumer::None:
				GenerateVisitorsOnlyPathDiagnostic(PD, PDB, N, visitors);
				break;
			}

			// Clean up the visitors we used.
			visitors.clear();

			// Did anything change while generating this path?
			finalReportConfigToken = R->getConfigurationChangeToken();
		} while (finalReportConfigToken != origReportConfigToken);

		if (!R->isValid())
			continue;

		// Finally, prune the diagnostic path of uninteresting stuff.
		if (!PD.path.empty()) {
			if (R->shouldPrunePath() && getAnalyzerOptions().shouldPrunePaths()) {
				bool stillHasNotes = removeUnneededCalls(PD.getMutablePieces(), R, LCM);
				assert(stillHasNotes);
				(void)stillHasNotes;
			}

			// Redirect all call pieces to have valid locations.
			adjustCallLocations(PD.getMutablePieces());
			removePiecesWithInvalidLocations(PD.getMutablePieces());

			if (ActiveScheme == PathDiagnosticConsumer::AlternateExtensive) {
				SourceManager &SM = getSourceManager();

				// Reduce the number of edges from a very conservative set
				// to an aesthetically pleasing subset that conveys the
				// necessary information.
				OptimizedCallsSet OCS;
				while (optimizeEdges(PD.getMutablePieces(), SM, OCS, LCM)) {}

				// Drop the very first function-entry edge. It's not really necessary
				// for top-level functions.
				dropFunctionEntryEdge(PD.getMutablePieces(), LCM, SM);
			}

			// Remove messages that are basically the same, and edges that may not
			// make sense.
			// We have to do this after edge optimization in the Extensive mode.
			removeRedundantMsgs(PD.getMutablePieces());
			removeEdgesToDefaultInitializers(PD.getMutablePieces());
		}

		// We found a report and didn't suppress it.
		return true;
	}

	// We suppressed all the reports in this equivalence class.
	assert(!HasInvalid && "Inconsistent suppression");
	(void)HasInvalid;
	return false;
}