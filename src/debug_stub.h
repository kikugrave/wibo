#pragma once
#include <cstdint>
namespace wibo::debugstub {
// Connect to the controller named by WIBO_DEBUG_IN/WIBO_DEBUG_OUT (inherited
// fds), announce the image, and take breakpoint/watch commands before the
// guest entry runs. No-op when the variables are absent.
void install(intptr_t relocationDelta, const char *imageName, uintptr_t imageBase);
// Stable i386 cdecl observation hooks. No-op unless a debugger stops here.
void moduleMapped(const char *path, uintptr_t base, uintptr_t size);
void moduleUnmapped(uintptr_t base);
// Announce the guest's exit code to the controller, if connected.
void reportExit(int code);
} // namespace wibo::debugstub
