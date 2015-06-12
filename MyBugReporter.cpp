#include "MyBugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ExplodedGraph.h"

using namespace clang;
using namespace ento;

void MyBugReporter::diagnosePath(BugReport *report) {
	std::unique_ptr<BugReport> UniqueR(report);

	if (const ExplodedNode *E = report->getErrorNode()) {
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

	bool ValidSourceLoc = report->getLocation(reporter.getSourceManager()).isValid();
	assert(ValidSourceLoc);
	// If we mess up in a release build, we'd still prefer to just drop the bug
	// instead of trying to go on.
	if (!ValidSourceLoc)
		return;

	for (PathDiagnosticConsumer *PD : reporter.getPathDiagnosticConsumers()) {
		BugType& BT = report->getBugType();

		PathDiagnostic * D = new PathDiagnostic(
			report->getBugType().getCheckName(),
			report->getDeclWithIssue(), report->getBugType().getName(),
			report->getDescription(),
			report->getShortDescription(/*Fallback=*/false), BT.getCategory(),
			report->getUniqueingLocation(),
			report->getUniqueingDecl());
		SmallVector<BugReport *, 1> bugReports;
		bugReports.push_back(report);
		ArrayRef<BugReport *> tmp = bugReports;

		if (!reporter.generatePathDiagnostic(*D, *PD, tmp))
			return;
		for (PathDiagnosticEventPiece * piece : pieces) {
			D->getActivePath().push_back(std::move(piece));
			for (const SourceRange &Range : report->getRanges())
				D->getActivePath().back()->addRange(Range);
		}

		// Examine the report and see if the last piece is in a header. Reset the
		// report location to the last piece in the main source file.
		AnalyzerOptions& Opts = reporter.getAnalyzerOptions();
		if (Opts.shouldReportIssuesInMainSourceFile() && !Opts.AnalyzeAll)
			D->resetDiagnosticLocationToMainFile();

		// If the path is empty, generate a single step path with the location
		// of the issue.
		if (D->path.empty()) {
			PathDiagnosticLocation L = report->getLocation(reporter.getSourceManager());
			auto piece = llvm::make_unique<PathDiagnosticEventPiece>(
				L, report->getDescription());
			for (const SourceRange &Range : report->getRanges())
				piece->addRange(Range);
			D->setEndOfPath(std::move(piece));
		}

		// Get the meta data.
		const BugReport::ExtraTextList &Meta = report->getExtraText();
		for (BugReport::ExtraTextList::const_iterator i = Meta.begin(),
			e = Meta.end(); i != e; ++i) {
			D->addMeta(*i);
		}
		diagnosed.push_back(std::make_pair(PD, D));
	}
}

// just put pieces and conduct no path sensitive diagnosis
// @arg report specifies the end of anlaysis path
void MyBugReporter::diagnoseSimple(BugReport *report) {
	std::unique_ptr<BugReport> UniqueR(report);

	if (const ExplodedNode *E = report->getErrorNode()) {
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

	bool ValidSourceLoc = report->getLocation(reporter.getSourceManager()).isValid();
	assert(ValidSourceLoc);
	// If we mess up in a release build, we'd still prefer to just drop the bug
	// instead of trying to go on.
	if (!ValidSourceLoc)
		return;

	for (PathDiagnosticConsumer *PD : reporter.getPathDiagnosticConsumers()) {
		BugType& BT = report->getBugType();

		PathDiagnostic * D = new PathDiagnostic(
			report->getBugType().getCheckName(),
			report->getDeclWithIssue(), report->getBugType().getName(),
			report->getDescription(),
			report->getShortDescription(/*Fallback=*/false), BT.getCategory(),
			report->getUniqueingLocation(),
			report->getUniqueingDecl());
		SmallVector<BugReport *, 1> bugReports;
		bugReports.push_back(report);
		ArrayRef<BugReport *> tmp = bugReports;

		for (PathDiagnosticEventPiece * piece : pieces) {
			D->getActivePath().push_back(std::move(piece));
			for (const SourceRange &Range : report->getRanges())
				D->getActivePath().back()->addRange(Range);
		}

		// do not call generatePathDiagnostic()

		// Examine the report and see if the last piece is in a header. Reset the
		// report location to the last piece in the main source file.
		AnalyzerOptions& Opts = reporter.getAnalyzerOptions();
		if (Opts.shouldReportIssuesInMainSourceFile() && !Opts.AnalyzeAll)
			D->resetDiagnosticLocationToMainFile();

		// Path is always empty here
		PathDiagnosticLocation L = report->getLocation(reporter.getSourceManager());
		auto piece = llvm::make_unique<PathDiagnosticEventPiece>(
			L, report->getDescription());
		for (const SourceRange &Range : report->getRanges())
			piece->addRange(Range);
		D->setEndOfPath(std::move(piece));

		// Get the meta data.
		const BugReport::ExtraTextList &Meta = report->getExtraText();
		for (BugReport::ExtraTextList::const_iterator i = Meta.begin(),
			e = Meta.end(); i != e; ++i) {
			D->addMeta(*i);
		}
		diagnosed.push_back(std::make_pair(PD, D));
	}
}

void MyBugReporter::flush() {
	for (std::pair<PathDiagnosticConsumer *, PathDiagnostic *> d : diagnosed) {
		std::unique_ptr<PathDiagnostic> p(d.second);
		d.first->HandlePathDiagnostic(std::move(p));
	}
	diagnosed.clear();
}
