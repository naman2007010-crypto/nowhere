#pragma once
#include <cstdint>
#include <windows.h>


namespace xeno {
// Initialization and shutdown
extern "C" __declspec(dllexport) bool initialize();
extern "C" __declspec(dllexport) void xeno_shutdown();

// Script execution
extern "C" __declspec(dllexport) void execute(const char *script);

// State access
extern "C" __declspec(dllexport) uintptr_t GetLuaState();
extern "C" __declspec(dllexport) bool RefreshState();

// Internal state
extern bool initialized;
extern uintptr_t scriptContext;
extern uintptr_t luaState;
} // namespace xeno
