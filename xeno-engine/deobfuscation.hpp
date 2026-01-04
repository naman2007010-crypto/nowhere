// Lua State Deobfuscation Routines
// Based on common Roblox obfuscation patterns
// Version: version-f8f53a67efca4c34

#pragma once
#include "offsets.hpp"
#include <Windows.h>
#include <cstdint>


namespace deobfuscation {

// Check if pointer is valid and readable
inline bool IsValidPointer(uintptr_t ptr) {
  return ptr != 0 && ptr < 0x00007FFFFFFFFFFF &&
         (ptr & 7) == 0 && // 8-byte aligned for 64-bit
         !IsBadReadPtr((void *)ptr, 8);
}

// Verify the deobfuscated pointer points to a valid lua_State
inline bool VerifyLuaState(uintptr_t luaState) {
  if (luaState == 0)
    return false;

  __try {
    // lua_State typically starts with pointer to global_State
    uintptr_t globalState = *(uintptr_t *)luaState;

    // Validate basic structure members
    return globalState != 0 && (globalState & 0xFFF) == 0 && // Page-aligned
           *(uintptr_t *)(globalState + 0x20) != 0; // Check for string table
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return false;
  }
}

// Main deobfuscation function with multiple strategies
inline uintptr_t DeobfuscateLuaState(uintptr_t scriptContext) {
  if (!IsValidPointer(scriptContext))
    return 0;

  __try {
    uintptr_t obfuscated =
        *(uintptr_t *)(scriptContext + offsets::ScriptContext_Luastate);

    // Try multiple deobfuscation patterns
    uintptr_t candidates[] = {
        // Method 1: XOR with ScriptContext address (common 2018-2020)
        obfuscated ^ scriptContext,

        // Method 2: XOR with address of the Luastate field
        obfuscated ^ (scriptContext + offsets::ScriptContext_Luastate),

        // Method 3: Stored as signed offset
        scriptContext + (int32_t)obfuscated,

        // Method 4: XOR with rotated bits (newer versions)
        obfuscated ^ (scriptContext >> 5) ^ (scriptContext << 3),

        // Method 5: XOR with shifted values
        obfuscated ^ (scriptContext >> 8) ^ (scriptContext << 8),

        // Method 6: Two-step deobfuscation
        (obfuscated ^ (scriptContext + offsets::ScriptContext_Luastate)) ^
            (scriptContext >> 4),

        // Method 7: Raw pointer (no obfuscation)
        obfuscated};

    // Test each candidate
    for (int i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
      if (IsValidPointer(candidates[i]) && VerifyLuaState(candidates[i])) {
        return candidates[i];
      }
    }

    return 0; // No valid deobfuscation found
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return 0;
  }
}

// Get the identity/context level from lua_State
inline int GetIdentity(uintptr_t luaState) {
  if (!IsValidPointer(luaState))
    return 0;

  __try {
    uintptr_t extraSpace =
        *(uintptr_t *)(luaState + lua_offsets::Luastate_ExtraSpace);
    if (!IsValidPointer(extraSpace))
      return 0;

    return *(int *)(extraSpace + lua_offsets::ExtraSpace_Identity);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return 0;
  }
}

// Set identity level (for script execution privileges)
inline bool SetIdentity(uintptr_t luaState, int identity) {
  if (!IsValidPointer(luaState))
    return false;

  __try {
    uintptr_t extraSpace =
        *(uintptr_t *)(luaState + lua_offsets::Luastate_ExtraSpace);
    if (!IsValidPointer(extraSpace))
      return false;

    *(int *)(extraSpace + lua_offsets::ExtraSpace_Identity) = identity;
    return true;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return false;
  }
}

// Get capabilities from lua_State
inline uint64_t GetCapabilities(uintptr_t luaState) {
  if (!IsValidPointer(luaState))
    return 0;

  __try {
    uintptr_t extraSpace =
        *(uintptr_t *)(luaState + lua_offsets::Luastate_ExtraSpace);
    if (!IsValidPointer(extraSpace))
      return 0;

    return *(uint64_t *)(extraSpace + lua_offsets::ExtraSpace_Capabilities);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return 0;
  }
}

// Set capabilities (for full script access)
inline bool SetCapabilities(uintptr_t luaState, uint64_t capabilities) {
  if (!IsValidPointer(luaState))
    return false;

  __try {
    uintptr_t extraSpace =
        *(uintptr_t *)(luaState + lua_offsets::Luastate_ExtraSpace);
    if (!IsValidPointer(extraSpace))
      return false;

    *(uint64_t *)(extraSpace + lua_offsets::ExtraSpace_Capabilities) =
        capabilities;
    return true;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return false;
  }
}
} // namespace deobfuscation
