#include "xeno.hpp"
#include "deobfuscation.hpp"
#include "offsets.hpp"
#include <iostream>
#include <mutex>
#include <queue>
#include <string>
#include <thread>

#include <psapi.h>
#include <tlhelp32.h>

namespace xeno {

bool initialized = false;
uintptr_t scriptContext = 0;
uintptr_t luaState = 0;
std::queue<std::string> scriptQueue;
std::mutex queueMutex;

// Pattern scanning utility
uintptr_t scan(const char *pattern, const char *mask) {
  MODULEINFO mi;
  GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(nullptr), &mi,
                       sizeof(mi));
  uintptr_t start = (uintptr_t)mi.lpBaseOfDll;
  uintptr_t end = start + mi.SizeOfImage;

  for (uintptr_t i = start; i < end - strlen(mask); i++) {
    bool found = true;
    for (uintptr_t j = 0; j < strlen(mask); j++) {
      if (mask[j] != '?' && pattern[j] != *(char *)(i + j)) {
        found = false;
        break;
      }
    }
    if (found)
      return i;
  }
  return 0;
}

// Find ScriptContext in the DataModel
uintptr_t FindScriptContext() {
  // Method 1: Use class descriptor address
  uintptr_t base = (uintptr_t)GetModuleHandleA(nullptr);

  // ScriptContext can be found via DataModel children enumeration
  // For now, return 0 - needs implementation based on game state
  return 0;
}

bool initialize() {
  uintptr_t base = (uintptr_t)GetModuleHandleA(nullptr);

  std::cout << "[NOWHERE] Initializing Xeno Engine..." << std::endl;
  std::cout << "[NOWHERE] Base Address: 0x" << std::hex << base << std::endl;
  std::cout << "[NOWHERE] Roblox Version: version-f8f53a67efca4c34"
            << std::endl;

  // Find ScriptContext
  scriptContext = FindScriptContext();
  if (scriptContext == 0) {
    std::cout << "[NOWHERE] Warning: ScriptContext not found yet (game may "
                 "not be loaded)"
              << std::endl;
  } else {
    std::cout << "[NOWHERE] ScriptContext: 0x" << std::hex << scriptContext
              << std::endl;

    // Deobfuscate Lua state
    luaState = deobfuscation::DeobfuscateLuaState(scriptContext);
    if (luaState == 0) {
      std::cout << "[NOWHERE] ERROR: Failed to deobfuscate lua_State!"
                << std::endl;
    } else {
      std::cout << "[NOWHERE] lua_State: 0x" << std::hex << luaState
                << std::endl;

      // Get current identity
      int identity = deobfuscation::GetIdentity(luaState);
      std::cout << "[NOWHERE] Current Identity: " << std::dec << identity
                << std::endl;

      // Elevate privileges (identity 8 = full access)
      deobfuscation::SetIdentity(luaState, 8);
      deobfuscation::SetCapabilities(luaState, 0xFFFFFFFFFFFFFFFF);
      std::cout << "[NOWHERE] Elevated to Identity 8 with full capabilities!"
                << std::endl;
    }
  }

  initialized = true;
  std::cout << "[NOWHERE] Xeno Engine initialized successfully!" << std::endl;
  return true;
}

void xeno_shutdown() {
  initialized = false;
  scriptContext = 0;
  luaState = 0;
  std::cout << "[NOWHERE] Xeno Engine shutdown." << std::endl;
}

void execute(const char *script) {
  if (!initialized) {
    std::cout << "[NOWHERE] ERROR: Engine not initialized!" << std::endl;
    return;
  }

  std::string scriptStr(script);

  // Add to execution queue
  {
    std::lock_guard<std::mutex> lock(queueMutex);
    scriptQueue.push(scriptStr);
  }

  std::cout << "[NOWHERE] Script queued for execution (" << scriptStr.length()
            << " bytes)" << std::endl;

  // If we have a valid lua_State, execute immediately
  if (luaState != 0) {
    // TODO: Implement actual Luau execution
    // This would involve:
    // 1. Compiling script to bytecode (or using loadstring)
    // 2. Pushing the compiled function to the stack
    // 3. Calling lua_pcall or similar
    std::cout << "[NOWHERE] Executing: " << scriptStr.substr(0, 50) << "..."
              << std::endl;
  } else {
    std::cout << "[NOWHERE] Warning: lua_State not available, script queued"
              << std::endl;
  }
}

// Get current lua_State (for external use)
uintptr_t GetLuaState() { return luaState; }

// Refresh ScriptContext and lua_State (call after game loads)
bool RefreshState() {
  scriptContext = FindScriptContext();
  if (scriptContext != 0) {
    luaState = deobfuscation::DeobfuscateLuaState(scriptContext);
    return luaState != 0;
  }
  return false;
}

} // namespace xeno

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call,
                      LPVOID lpReserved) {
  switch (ul_reason_for_call) {
  case DLL_PROCESS_ATTACH:
    DisableThreadLibraryCalls(hModule);
    // Start initialization in a separate thread
    CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)xeno::initialize, nullptr,
                 0, nullptr);
    break;
  case DLL_PROCESS_DETACH:
    xeno::xeno_shutdown();
    break;
  }
  return TRUE;
}
