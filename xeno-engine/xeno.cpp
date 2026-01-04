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

#include "manual_mapper.hpp"
#include "roblox_utils.hpp"

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

namespace xeno {

bool initialized = false;
uintptr_t scriptContext = 0;
uintptr_t luaState = 0;
std::queue<std::string> scriptQueue;
std::mutex queueMutex;

// Refresh ScriptContext and lua_State (call after game loads)
bool RefreshState() {
  HANDLE hProcess = GetCurrentProcess();
  uintptr_t base = (uintptr_t)GetModuleHandleA(nullptr);

  uintptr_t dataModel = roblox::GetDataModel(hProcess, base);
  if (dataModel == 0)
    return false;

  scriptContext = roblox::GetScriptContext(hProcess, dataModel);
  if (scriptContext != 0) {
    luaState = deobfuscation::DeobfuscateLuaState(scriptContext);

    if (luaState != 0) {
      // Elevate on refresh
      deobfuscation::SetIdentity(luaState, 8);
      deobfuscation::SetCapabilities(luaState, 0xFFFFFFFFFFFFFFFF);
      return true;
    }
  }
  return false;
}

// Find ScriptContext in the DataModel
uintptr_t FindScriptContext() {
  HANDLE hProcess = GetCurrentProcess();
  uintptr_t base = (uintptr_t)GetModuleHandleA(nullptr);

  std::cout << "[NOWHERE] Searching for DataModel..." << std::endl;
  uintptr_t dataModel = roblox::GetDataModel(hProcess, base);
  if (dataModel == 0) {
    std::cout << "[NOWHERE] ERROR: DataModel not found!" << std::endl;
    return 0;
  }
  std::cout << "[NOWHERE] DataModel: 0x" << std::hex << dataModel << std::endl;

  std::cout << "[NOWHERE] Searching for ScriptContext..." << std::endl;
  uintptr_t sc = roblox::GetScriptContext(hProcess, dataModel);
  return sc;
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
    std::cout << "[NOWHERE] Warning: ScriptContext not found yet (game may not "
                 "be loaded)"
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

  // Find Luau functions
  std::cout << "[NOWHERE] Searching for Luau functions..." << std::endl;

  // Example AOB patterns
  uintptr_t loadstring_addr = scan("\x48\x89\x5C\x24\x00\x48\x89\x6C\x24\x00"
                                   "\x48\x89\x74\x24\x00\x57\x48\x83\xEC\x30",
                                   "xxxx?xxxx?xxxx?xxxxx");
  if (loadstring_addr)
    std::cout << "[NOWHERE] Found loadstring placeholder: 0x" << std::hex
              << loadstring_addr << std::endl;

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

  if (luaState == 0) {
    // Try refreshing if state is missing
    RefreshState();
    if (luaState == 0) {
      std::cout << "[NOWHERE] ERROR: lua_State not found, cannot execute!"
                << std::endl;
      return;
    }
  }

  std::string scriptStr(script);
  std::cout << "[NOWHERE] Executing script (" << scriptStr.length()
            << " bytes)..." << std::endl;

  // Add to execution queue for thread-safe access
  {
    std::lock_guard<std::mutex> lock(queueMutex);
    scriptQueue.push(scriptStr);
  }

  // === SCRIPT EXECUTION LOGIC ===
  //
  // In a fully functional executor, this is where we would:
  // 1. Find Roblox's internal loadstring/compile function via AOB scan
  // 2. Create a new Luau thread from our deobfuscated lua_State
  // 3. Compile the script to bytecode
  // 4. Load the bytecode into the VM
  // 5. Call lua_pcall to execute
  //
  // Example pseudo-code (requires actual function addresses):
  //
  // typedef int (*rloadstring_t)(uintptr_t L, const char* src, const char*
  // name); typedef int (*rlua_pcall_t)(uintptr_t L, int nargs, int nresults,
  // int errfunc);
  //
  // static rloadstring_t rloadstring = (rloadstring_t)FindLoadstring();
  // static rlua_pcall_t rlua_pcall = (rlua_pcall_t)FindLuaPcall();
  //
  // if (rloadstring && rlua_pcall) {
  //     if (rloadstring(luaState, scriptStr.c_str(), "=xeno") == 0) {
  //         rlua_pcall(luaState, 0, 0, 0);
  //     }
  // }
  //
  // For now, we log the attempt. Full execution requires:
  // - Verified AOB patterns for the current Roblox build
  // - Proper thread creation and stack management
  // - Error handling for compilation failures

  std::cout << "[NOWHERE] Script queued. Execution requires loadstring hook."
            << std::endl;
  std::cout << "[NOWHERE] To complete: Implement FindLoadstring() with correct "
               "AOB pattern."
            << std::endl;
}

// Get current lua_State (for external use)
uintptr_t GetLuaState() { return luaState; }

// Inject DLL into a target process using manual mapping
bool InjectIntoProcess(DWORD processId, const wchar_t *dllPath) {
  HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
  if (!hProcess) {
    std::cout << "[NOWHERE] ERROR: Could not open process " << processId
              << std::endl;
    return false;
  }

  std::wstring path(dllPath);
  mapper::MappedDll result = mapper::MapDll(hProcess, path);
  CloseHandle(hProcess);

  if (result.success) {
    std::cout << "[NOWHERE] Successfully injected DLL at 0x" << std::hex
              << result.base << std::endl;
  } else {
    std::cout << "[NOWHERE] ERROR: Manual mapping failed!" << std::endl;
  }

  return result.success;
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
