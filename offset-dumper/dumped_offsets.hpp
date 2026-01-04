#pragma once
#include <cstdint>

namespace internal_offsets {
    constexpr uintptr_t LuaVM_Load = 0x64ebd0;
    constexpr uintptr_t Luau_Execute = 0x0; // NOT FOUND
    constexpr uintptr_t ScriptContextResume = 0x927670;
    constexpr uintptr_t PushInstance = 0x6482b0;
    constexpr uintptr_t TaskDefer = 0x628320;
    constexpr uintptr_t Print = 0x1ab5740;
    constexpr uintptr_t GetLuaState = 0x4283d45;
}
