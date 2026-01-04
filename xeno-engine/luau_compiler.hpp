// Luau Bytecode Compiler
// Compiles Luau source code to bytecode for execution
//
// Two approaches:
// 1. Use Roblox's internal compiler (preferred - always compatible)
// 2. Embed Luau compiler from https://github.com/Roblox/luau (standalone)

#pragma once
#include "luau_functions.hpp"
#include <Windows.h>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace compiler {

// Compilation result
struct CompileResult {
  bool success;
  std::vector<char> bytecode;
  std::string error;
};

// ============================================================================
// Method 1: Use Roblox's internal LuaVM_Load
// This is preferred because it always matches Roblox's expected bytecode format
// ============================================================================

// The internal approach works differently:
// Instead of compiling bytecode separately, we use Roblox's own loadstring
// equivalent which compiles and loads in one step.
//
// The flow is:
// 1. Create a new lua thread from our lua_State
// 2. Call LuaVM_Load with the source code
// 3. LuaVM_Load compiles and pushes the function onto the stack
// 4. Call lua_pcall to execute

// Wrapper that uses Roblox's internal functions
// Wrapper that uses Roblox's internal functions
inline bool ExecuteScriptInternal(uintptr_t luaState, const std::string &source,
                                  const std::string &chunkname = "@xeno") {
  if (luau::r_luavm_load == nullptr) {
    std::cout << "[COMPILER] ERROR: LuaVM_Load not initialized!" << std::endl;
    return false;
  }

  std::cout << "[COMPILER] Compiling script (" << source.length()
            << " bytes)..." << std::endl;

  std::string sourceStr = source;
  // 1. Load the script (pushes closure to stack)
  int result = luau::r_luavm_load(luaState, &sourceStr, chunkname.c_str(), 0);

  if (result != 0) {
    std::cout << "[COMPILER] LuaVM_Load failed with code: " << result
              << std::endl;
    return false;
  }

  std::cout << "[COMPILER] Script loaded successfully! Scheduling..."
            << std::endl;

  // 2. Execute it
  // Priority: TaskDefer (Safe, Scheduled) > Luau_Execute (Immediate, Risky)

  if (luau::r_task_defer) {
    // task.defer(function) - expects function at top of stack
    luau::r_task_defer((luau::lua_State *)luaState);
    std::cout << "[COMPILER] Scheduled script via task.defer!" << std::endl;
    return true;
  } else if (luau::r_luau_execute) {
    // Direct execution - risky if not on correct thread state
    luau::r_luau_execute((luau::lua_State *)luaState);
    std::cout << "[COMPILER] Executed script via Luau_Execute!" << std::endl;
    return true;
  } else {
    std::cout << "[COMPILER] ERROR: No execution method available!"
              << std::endl;
    return false;
  }
}

// ============================================================================
// Method 2: Embedded Luau Compiler (Standalone)
// This requires including Luau source from https://github.com/Roblox/luau
// Not implemented here - would require significant additional code
// ============================================================================

// Placeholder for embedded compiler
inline CompileResult CompileStandalone(const std::string &source,
                                       const std::string &chunkname = "@xeno") {
  CompileResult result;
  result.success = false;
  result.error =
      "Standalone compiler not implemented. Use ExecuteScriptInternal instead.";
  return result;
}

// ============================================================================
// Bytecode Format Reference (for future embedded compiler)
// ============================================================================
//
// Luau bytecode structure (simplified):
// - Header: Version, TypesVersion, String count
// - String table
// - Proto table (functions)
// - Main proto reference
//
// Each Proto contains:
// - Bytecode instructions
// - Constants (numbers, strings, closures)
// - Debug info (optional)
// - Child protos
//
// Bytecode is encoded with a custom compression and encryption
// that changes between Roblox versions. This is why using the
// internal compiler is strongly preferred.

// ============================================================================
// Script Wrapping (for special execution modes)
// ============================================================================

// Wrap script in a protected call with error handling
inline std::string WrapWithErrorHandler(const std::string &script) {
  return R"(
local success, err = pcall(function()
)" + script +
         R"(
end)
if not success then
    warn("[NOWHERE] Script error: " .. tostring(err))
end
)";
}

// Wrap script for deferred execution (runs on next heartbeat)
inline std::string WrapWithDefer(const std::string &script) {
  return R"(
task.defer(function()
)" + script +
         R"(
end)
)";
}

// Wrap script with getfenv/setfenv for sandboxing
inline std::string WrapWithSandbox(const std::string &script) {
  return R"(
local env = setmetatable({}, {__index = getfenv()})
setfenv(1, env)
)" + script;
}

} // namespace compiler
