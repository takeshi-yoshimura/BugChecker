/*
* BugChecker.cpp
*
*  Created on: 2014/06/03
*      Author: yoshimura
*/

#include "clang/StaticAnalyzer/Core/CheckerRegistry.h"

using namespace clang;
using namespace ento;

extern void registerIRQChecker(CheckerRegistry &registry);
extern void registerGetEntryExit(CheckerRegistry &registry);

// Register plugin!
extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
	registerIRQChecker(registry);
	registerGetEntryExit(registry);
}

extern "C" const char clang_analyzerAPIVersionString[] =
CLANG_ANALYZER_API_VERSION_STRING;


