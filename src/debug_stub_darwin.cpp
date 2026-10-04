// The pipe debugger and the module hooks are Linux i386 work; on macOS the
// loader runs compilers and refuses a debugging request.
#include "debug_stub.h"

#include <cstdio>
#include <cstdlib>

namespace wibo::debugstub {
void install(intptr_t, const char *, uintptr_t) {
	if (std::getenv("WIBO_DEBUG_IN") || std::getenv("WIBO_DEBUG_OUT")) {
		std::fputs("wibo: the pipe debugger requires the Linux i386 loader\n", stderr);
		std::exit(2);
	}
}
void moduleMapped(const char *, uintptr_t, uintptr_t) {}
void moduleUnmapped(uintptr_t) {}
void reportExit(int) {}
} // namespace wibo::debugstub
