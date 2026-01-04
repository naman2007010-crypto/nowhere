// Luau Functions - Function pointers for Roblox's Lua VM
// These addresses must be found via AOB scanning or updated per version
//
// Reference:
// https://raw.githubusercontent.com/NtReadVirtualMemory/Roblox-Offsets-Website/main/internal-offsets.hpp

#pragma once
#include <Psapi.h>
#include <Windows.h>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#define REBASE(x) (x + reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr)))

namespace luau {

// ============================================================================
// IMPORTANT: These offsets are for internal use only
// They need to be updated for each Roblox version
// Current reference version: version-1849ecbff0824113
// Your version: version-f8f53a67efca4c34 (may differ!)
// ============================================================================

// Forward declarations
struct lua_State;
struct Proto;

// Result enum for script execution
enum class ScriptResumeResult { SUCCESS = 0, YIELD = 1, ERR = 2 };

// Weak thread reference structure
struct WeakThreadRef {
  std::atomic<int32_t> Refs;
  lua_State *L;
  int32_t ThreadRef;
  int32_t ObjectId;
  int32_t Unk1;
  int32_t Unk2;
};

// Debugger result structure
struct DebuggerResult {
  int32_t Result;
  int32_t Unk[4];
};

// ============================================================================
// Function Pointer Types
// ============================================================================

// Core Lua functions
typedef void (*luau_execute_t)(lua_State *L);
typedef int (*luavm_load_t)(uintptr_t L, std::string *bytecode,
                            const char *chunkname, int env);
typedef void (*luad_throw_t)(lua_State *L, int errcode);
typedef void *(*luag_errorl_t)(lua_State *L, const char *fmt, ...);

// Script execution
typedef int (*script_context_resume_t)(uintptr_t scriptContext,
                                       DebuggerResult *result,
                                       WeakThreadRef **threadRef,
                                       int32_t numArgs, bool something,
                                       const char *source);

// Instance manipulation
typedef uintptr_t *(*push_instance_t)(lua_State *L, uintptr_t instance);
typedef void (*print_t)(int type, const char *fmt, ...);

// Global state
typedef uintptr_t (*get_global_state_t)(uintptr_t L, uint64_t *a, uint64_t *b);
typedef uintptr_t (*get_lua_state_t)(uintptr_t scriptContext);

// Task scheduler
typedef int (*task_defer_t)(lua_State *L);
typedef int (*task_spawn_t)(lua_State *L);

// ============================================================================
// Internal Offsets (REBASE these!)
// These are example offsets from version-1849ecbff0824113
// You MUST update these for your Roblox version!
// ============================================================================

namespace internal_offsets {
// Offsets for Roblox Player (Game Client) - version-f8f53a67efca4c34
// These values are from the offset dumper scan
// Re-run offset-dumper/OffsetDumper.exe after Roblox updates!
// Last updated: 2026-01-05

// Core Luau Functions (from AOB scanning)
constexpr uintptr_t LuaVM_Load = 0x64ebd0; // Found via AOB
constexpr uintptr_t Luau_Execute =
    0x0; // Needs new pattern - will use AOB fallback
constexpr uintptr_t ScriptContextResume = 0x927670; // Found via AOB
constexpr uintptr_t PushInstance = 0x6482b0;        // Found via AOB
constexpr uintptr_t TaskDefer = 0x628320;           // Found via AOB
constexpr uintptr_t Print = 0x1ab5740;              // Found via AOB
constexpr uintptr_t GetLuaState = 0x0; // Suspicious value from dumper, use AOB

// Global structures (from offsets.hpp / worker API)
constexpr uintptr_t RawTaskScheduler = 0x79E1868;
constexpr uintptr_t FakeDataModelPointer = 0x78A24C8;

// Validation
constexpr uintptr_t ValidateBytecode = 0x117E350;
} // namespace internal_offsets

// ============================================================================
// Function Pointers (initialized at runtime)
// ============================================================================

inline luau_execute_t r_luau_execute = nullptr;
inline luavm_load_t r_luavm_load = nullptr;
inline script_context_resume_t r_script_context_resume = nullptr;
inline push_instance_t r_push_instance = nullptr;
inline print_t r_print = nullptr;
inline get_lua_state_t r_get_lua_state = nullptr;
inline task_defer_t r_task_defer = nullptr;
// ============================================================================
// AOB Patterns for dynamic scanning (future improvement)
// ============================================================================

namespace patterns {
// Primary patterns - these are the main patterns to search for
// Format: "48 89 5C 24 ?? 48 89 6C 24"

constexpr const char *LUAU_EXECUTE =
    "40 53 48 83 EC 20 48 8B 59 10 48 8B CB E8";

constexpr const char *LUAVM_LOAD =
    "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC 30";

constexpr const char *SCRIPT_CONTEXT_RESUME =
    "48 8B C4 48 89 58 ?? 48 89 68 ?? 48 89 70 ?? 48 89 78 ?? 41 54";

constexpr const char *PUSH_INSTANCE =
    "48 89 5C 24 ?? 57 48 83 EC 20 48 8B FA 48 8B D9 E8";

constexpr const char *TASK_DEFER =
    "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC 20 48 8B F9";

// Fallback patterns for Luau_Execute - try these if primary fails
constexpr const char *LUAU_EXECUTE_ALT1 = "48 83 EC ?? 48 8B 49 10 E8";
constexpr const char *LUAU_EXECUTE_ALT2 =
    "40 55 48 8D 6C 24 ?? 48 81 EC ?? ?? ?? ?? 48 8B 59 10";
constexpr const char *LUAU_EXECUTE_ALT3 =
    "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B 71 10";
constexpr const char *LUAU_EXECUTE_ALT4 =
    "40 53 48 83 EC ?? 48 8B D9 48 8B 49 10";
constexpr const char *LUAU_EXECUTE_ALT5 = "48 8B 41 10 48 8B D0 48 8B 48";
} // namespace patterns

// Convert hex string pattern to binary array
// Example: "48 89 5C 24 ??" -> bytes={0x48,0x89,0x5C,0x24,0x00}, mask="xxxx?"
inline bool ParsePattern(const char *pattern, std::vector<uint8_t> &bytes,
                         std::string &mask) {
  bytes.clear();
  mask.clear();

  std::string pat(pattern);
  for (size_t i = 0; i < pat.length(); i++) {
    if (pat[i] == ' ')
      continue;

    if (pat[i] == '?') {
      bytes.push_back(0);
      mask += '?';
      if (i + 1 < pat.length() && pat[i + 1] == '?')
        i++; // Skip second ?
    } else {
      if (i + 1 >= pat.length())
        return false;

      char hex[3] = {pat[i], pat[i + 1], 0};
      bytes.push_back((uint8_t)strtol(hex, nullptr, 16));
      mask += 'x';
      i++; // Skip second hex char
    }
  }
  return !bytes.empty();
}

// Pattern scanner with wildcard support
inline uintptr_t ScanForPattern(uintptr_t start, size_t size,
                                const std::vector<uint8_t> &pattern,
                                const std::string &mask) {
  if (pattern.empty() || mask.empty() || pattern.size() != mask.size())
    return 0;

  for (size_t i = 0; i < size - pattern.size(); i++) {
    bool found = true;
    for (size_t j = 0; j < pattern.size(); j++) {
      if (mask[j] == 'x' && pattern[j] != *(uint8_t *)(start + i + j)) {
        found = false;
        break;
      }
    }
    if (found)
      return start + i;
  }
  return 0;
}

// Helper to scan for patterns in the entire module
inline uintptr_t FindPattern(const char *hexPattern) {
  MODULEINFO modInfo;
  if (!GetModuleInformation(GetCurrentProcess(), GetModuleHandle(nullptr),
                            &modInfo, sizeof(MODULEINFO))) {
    return 0;
  }

  std::vector<uint8_t> bytes;
  std::string mask;
  if (!ParsePattern(hexPattern, bytes, mask)) {
    std::cout << "[LUAU] Failed to parse pattern: " << hexPattern << std::endl;
    return 0;
  }

  return ScanForPattern((uintptr_t)modInfo.lpBaseOfDll, modInfo.SizeOfImage,
                        bytes, mask);
}

// Validate that a found address looks like a valid function
inline bool ValidateFunctionAddress(uintptr_t addr) {
  if (addr == 0)
    return false;

  __try {
    // Check if readable
    volatile uint8_t test = *(uint8_t *)addr;

    // Check for common function prologues
    uint8_t byte1 = *(uint8_t *)addr;
    uint8_t byte2 = *(uint8_t *)(addr + 1);

    // Common x64 prologues: 48 89, 40 53, 48 83, etc.
    if ((byte1 == 0x48 || byte1 == 0x40 || byte1 == 0x55) ||
        (byte1 == 0x48 && (byte2 == 0x89 || byte2 == 0x8B || byte2 == 0x83))) {
      return true;
    }

    return false;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return false;
  }
}

// Set the identity of the current thread (Level 2 = Local, Level 7 = Admin)
// Set the identity of the current thread (Level 2 = Local, Level 7 = Admin)
inline void SetIdentity(uintptr_t L, int identity) {
  uintptr_t extra_space = *(uintptr_t *)(L + lua_offsets::Luastate_ExtraSpace);
  if (extra_space) {
    // Write identity to ExtraSpace + 0x30
    // (lua_offsets::ExtraSpace_Identity)
    *(int *)(extra_space + lua_offsets::ExtraSpace_Identity) = identity;

    // Also set capabilities to -1 (RunAnything) if we are elevating
    if (identity > 2) {
      *(uintptr_t *)(extra_space + lua_offsets::ExtraSpace_Capabilities) =
          0xFFFFFFFFFFFFFFFF;
    }
  }
}

// ============================================================================
// Initialization
// ============================================================================

// Initialize all function pointers
inline bool Initialize() {
  uintptr_t base = (uintptr_t)GetModuleHandle(nullptr);

  std::cout << "[LUAU] Initializing function pointers..." << std::endl;
  std::cout << "[LUAU] Base address: 0x" << std::hex << base << std::dec
            << std::endl;

  // ============================================================================
  // STEP 1: Try hardcoded internal offsets (fast path)
  // ============================================================================
  std::cout << "[LUAU] Trying hardcoded offsets..." << std::endl;

  r_luau_execute = (luau_execute_t)(base + internal_offsets::Luau_Execute);
  r_luavm_load = (luavm_load_t)(base + internal_offsets::LuaVM_Load);
  r_script_context_resume =
      (script_context_resume_t)(base + internal_offsets::ScriptContextResume);
  r_push_instance = (push_instance_t)(base + internal_offsets::PushInstance);
  r_print = (print_t)(base + internal_offsets::Print);
  r_get_lua_state = (get_lua_state_t)(base + internal_offsets::GetLuaState);
  r_task_defer = (task_defer_t)(base + internal_offsets::TaskDefer);

  // ============================================================================
  // STEP 2: Validate hardcoded offsets
  // ============================================================================
  bool offsets_valid =
      ValidateFunctionAddress((uintptr_t)r_luavm_load) &&
      ValidateFunctionAddress((uintptr_t)r_luau_execute) &&
      ValidateFunctionAddress((uintptr_t)r_script_context_resume);

  if (offsets_valid) {
    std::cout << "[LUAU] Hardcoded offsets appear valid!" << std::endl;
  } else {
    std::cout
        << "[LUAU] Hardcoded offsets invalid. Falling back to AOB scanning..."
        << std::endl;

    // ============================================================================
    // STEP 3: AOB Scanning Fallback
    // ============================================================================

    // Scan for LuaVM_Load
    uintptr_t found = FindPattern(patterns::LUAVM_LOAD);
    if (found) {
      r_luavm_load = (luavm_load_t)found;
      std::cout << "[LUAU] Found LuaVM_Load via AOB: 0x" << std::hex << found
                << std::dec << std::endl;
    } else {
      std::cout << "[LUAU] WARNING: Could not find LuaVM_Load!" << std::endl;
    }

    // Scan for Luau_Execute - try primary and all fallback patterns
    found = FindPattern(patterns::LUAU_EXECUTE);
    if (!found)
      found = FindPattern(patterns::LUAU_EXECUTE_ALT1);
    if (!found)
      found = FindPattern(patterns::LUAU_EXECUTE_ALT2);
    if (!found)
      found = FindPattern(patterns::LUAU_EXECUTE_ALT3);
    if (!found)
      found = FindPattern(patterns::LUAU_EXECUTE_ALT4);
    if (!found)
      found = FindPattern(patterns::LUAU_EXECUTE_ALT5);

    if (found) {
      r_luau_execute = (luau_execute_t)found;
      std::cout << "[LUAU] Found Luau_Execute via AOB: 0x" << std::hex << found
                << std::dec << std::endl;
    } else {
      std::cout
          << "[LUAU] WARNING: Could not find Luau_Execute (tried 6 patterns)!"
          << std::endl;
    }

    // Scan for ScriptContextResume
    found = FindPattern(patterns::SCRIPT_CONTEXT_RESUME);
    if (found) {
      r_script_context_resume = (script_context_resume_t)found;
      std::cout << "[LUAU] Found ScriptContextResume via AOB: 0x" << std::hex
                << found << std::dec << std::endl;
    } else {
      std::cout << "[LUAU] WARNING: Could not find ScriptContextResume!"
                << std::endl;
    }

    // Scan for PushInstance
    found = FindPattern(patterns::PUSH_INSTANCE);
    if (found) {
      r_push_instance = (push_instance_t)found;
      std::cout << "[LUAU] Found PushInstance via AOB: 0x" << std::hex << found
                << std::dec << std::endl;
    }

    // Scan for TaskDefer
    found = FindPattern(patterns::TASK_DEFER);
    if (found) {
      r_task_defer = (task_defer_t)found;
      std::cout << "[LUAU] Found TaskDefer via AOB: 0x" << std::hex << found
                << std::dec << std::endl;
    }
  }

  // ============================================================================
  // STEP 4: Final validation
  // ============================================================================
  // ============================================================================
  // STEP 4: Final validation
  // ============================================================================
  std::cout << "[LUAU] Final addresses:" << std::endl;
  std::cout << "[LUAU]   LuaVM_Load: 0x" << std::hex << (uintptr_t)r_luavm_load
            << std::endl;
  std::cout << "[LUAU]   Luau_Execute: 0x" << std::hex
            << (uintptr_t)r_luau_execute << std::endl;
  std::cout << "[LUAU]   ScriptContextResume: 0x" << std::hex
            << (uintptr_t)r_script_context_resume << std::dec << std::endl;
  std::cout << "[LUAU]   TaskDefer: 0x" << std::hex << (uintptr_t)r_task_defer
            << std::dec << std::endl;

  // We need LuaVM_Load and ScriptContextResume absolutely
  if (!r_luavm_load || !r_script_context_resume) {
    std::cout << "[LUAU] ERROR: Critical functions "
                 "(LuaVM_Load/ScriptContextResume) not found!"
              << std::endl;
    return false;
  }

  // For execution, we need EITHER Luau_Execute OR TaskDefer
  if (!r_luau_execute && !r_task_defer) {
    std::cout << "[LUAU] ERROR: No execution method found (neither "
                 "Luau_Execute nor TaskDefer)!"
              << std::endl;
    return false;
  }

  std::cout << "[LUAU] Initialization complete!" << std::endl;
  return true;
}

} // namespace luau
