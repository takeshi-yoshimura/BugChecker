#ifndef MYBUGREPORTER_H
#define MYBUGREPORTER_H

#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/PathDiagnostic.h"

namespace clang {
	namespace ento {
		class MyBugReporter {
			BugReporter &reporter;
			std::vector<std::pair<PathDiagnosticConsumer *, PathDiagnostic *>> diagnosed;
			std::vector<PathDiagnosticEventPiece *> pieces;

		public:
			MyBugReporter(BugReporter &reporter_) : reporter(reporter_) {}
			//TODO: avoid leak or corruption when addPieces(non new'ed memory)
			virtual ~MyBugReporter() {
				for (std::pair<PathDiagnosticConsumer *, PathDiagnostic *> d: diagnosed) {
					delete d.second;
				}
				diagnosed.clear();
				clearPiece();
			}

			void addPiece(PathDiagnosticEventPiece * piece) {
				pieces.push_back(piece);
			}

			void clearPiece() {
				pieces.clear();
			}

			void diagnosePath(BugReport *report);
			void diagnoseSimple(BugReport * report);
			void flush();
		};
	}
}

#endif