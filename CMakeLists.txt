cmake_minimum_required(VERSION 2.8.8)
project(bugchecker)

find_package(LLVM REQUIRED CONFIG)

list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
set(LLVM_ENABLE_PLUGINS ON)
include(AddLLVM)
include(HandleLLVMOptions)

# workaround
set(LLVM_RUNTIME_OUTPUT_INTDIR ${CMAKE_BINARY_DIR}/${CMAKE_CFG_INTDIR}/bin)
set(LLVM_LIBRARY_OUTPUT_INTDIR ${CMAKE_BINARY_DIR}/${CMAKE_CFG_INTDIR}/lib)
set(LLVM_PLUGIN_EXT ".so")

add_definitions(${LLVM_DEFINITIONS})
include_directories(${LLVM_INCLUDE_DIRS})
link_directories(${LLVM_LIBRARY_DIRS})

# Link against LLVM libraries
if ( MSVC )
  add_library(bugchecker MODULE BugChecker.cpp GetEntryExit.cpp IRQChecker.cpp MyBugReporter.cpp)
  target_link_libraries(bugchecker clangAnalysis clangAST clangLex clangParse clangBasic clangStaticAnalyzerCore LLVMSupport)
else ()
  add_llvm_loadable_module(bugchecker BugChecker.cpp GetEntryExit.cpp IRQChecker.cpp MyBugReporter.cpp)
#  target_link_libraries(bugchecker clangStaticAnalyzerFrontend clangAnalysis clangAST clangLex clangParse clangBasic clangStaticAnalyzerCore LLVMSupport)
endif ()
