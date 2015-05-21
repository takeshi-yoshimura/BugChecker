CLANG_LEVEL := ../..
LIBRARYNAME = BugChecker

LINK_LIBS_IN_SHARED = 0
LOADABLE_MODULE = 1

include $(CLANG_LEVEL)/Makefile

ifeq ($(OS),Darwin)
  LDFLAGS=-Wl,-undefined,dynamic_lookup
endif  
