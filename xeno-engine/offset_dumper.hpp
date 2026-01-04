// Offset Dumper - Verifies offsets against live Roblox
// This helps debug when offsets change between Roblox updates

#pragma once
#include "memory.hpp"
#include "offsets.hpp"
#include "roblox_utils.hpp"
#include <Windows.h>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace dumper {

struct OffsetResult {
  const char *name;
  uintptr_t offset;
  uintptr_t value;
  bool valid;
  std::string info;
};

// Check if a pointer looks valid (in typical heap/stack range)
inline bool IsLikelyValidPointer(uintptr_t ptr) {
  // x64 user-mode addresses are typically below 0x7FFFFFFFFFFF
  // and above 0x10000 (avoid null page)
  return ptr > 0x10000 && ptr < 0x00007FFFFFFFFFFF;
}

// Validate the DataModel pointer chain
inline OffsetResult ValidateDataModelChain(HANDLE hProcess, uintptr_t base) {
  OffsetResult result = {"FakeDataModelPointer", offsets::FakeDataModelPointer,
                         0, false, ""};

  uintptr_t fakeDataModelPtr =
      memory::Read<uintptr_t>(hProcess, base + offsets::FakeDataModelPointer);
  if (!IsLikelyValidPointer(fakeDataModelPtr)) {
    result.info = "FakeDataModelPtr is invalid or null";
    return result;
  }

  uintptr_t dataModel = memory::Read<uintptr_t>(
      hProcess, fakeDataModelPtr + offsets::FakeDatamodel_Datamodel);
  if (!IsLikelyValidPointer(dataModel)) {
    result.info = "DataModel is invalid or null";
    return result;
  }

  result.value = dataModel;
  result.valid = true;
  result.info = "DataModel found";
  return result;
}

// Validate ScriptContext can be found
inline OffsetResult ValidateScriptContext(HANDLE hProcess,
                                          uintptr_t dataModel) {
  OffsetResult result = {"ScriptContext", 0, 0, false, ""};

  if (!IsLikelyValidPointer(dataModel)) {
    result.info = "Invalid DataModel pointer";
    return result;
  }

  // Try to find ScriptContext as a child
  uintptr_t scriptContext =
      roblox::FindFirstChild(hProcess, dataModel, "ScriptContext");
  if (!IsLikelyValidPointer(scriptContext)) {
    result.info = "ScriptContext not found in DataModel children";
    return result;
  }

  result.value = scriptContext;
  result.valid = true;
  result.info = "ScriptContext found";
  return result;
}

// Validate lua_State offset within ScriptContext
inline OffsetResult ValidateLuaStateOffset(HANDLE hProcess,
                                           uintptr_t scriptContext) {
  OffsetResult result = {"ScriptContext_Luastate",
                         offsets::ScriptContext_Luastate, 0, false, ""};

  if (!IsLikelyValidPointer(scriptContext)) {
    result.info = "Invalid ScriptContext pointer";
    return result;
  }

  uintptr_t obfuscated = memory::Read<uintptr_t>(
      hProcess, scriptContext + offsets::ScriptContext_Luastate);
  if (obfuscated == 0) {
    result.info = "Obfuscated lua_State is null (game not loaded?)";
    return result;
  }

  result.value = obfuscated;
  result.valid = true;
  result.info = "Obfuscated lua_State found (needs deobfuscation)";
  return result;
}

// Validate Players service
inline OffsetResult ValidatePlayers(HANDLE hProcess, uintptr_t dataModel) {
  OffsetResult result = {"Players", 0, 0, false, ""};

  uintptr_t players = roblox::FindFirstChild(hProcess, dataModel, "Players");
  if (!IsLikelyValidPointer(players)) {
    result.info = "Players service not found";
    return result;
  }

  // Try to read LocalPlayer
  uintptr_t localPlayer =
      memory::Read<uintptr_t>(hProcess, players + offsets::Players_LocalPlayer);
  if (!IsLikelyValidPointer(localPlayer)) {
    result.info = "Players found but LocalPlayer offset may be wrong";
    result.value = players;
    result.valid = false;
    return result;
  }

  result.value = players;
  result.valid = true;
  result.info = "Players and LocalPlayer valid";
  return result;
}

// Get current Roblox version from file
inline std::string GetRobloxVersion() {
  // Check common installation paths
  char path[MAX_PATH];
  DWORD len = GetEnvironmentVariableA("LOCALAPPDATA", path, MAX_PATH);
  if (len == 0)
    return "Unknown";

  std::string versionsPath = std::string(path) + "\\Roblox\\Versions";

  WIN32_FIND_DATAA findData;
  HANDLE hFind =
      FindFirstFileA((versionsPath + "\\version-*").c_str(), &findData);
  if (hFind == INVALID_HANDLE_VALUE)
    return "Unknown";

  std::string version = findData.cFileName;
  FindClose(hFind);

  return version;
}

// Dump all offsets and validate them
inline std::vector<OffsetResult> DumpAllOffsets() {
  std::vector<OffsetResult> results;

  std::cout << "\n========== NOWHERE OFFSET DUMPER ==========" << std::endl;
  std::cout << "Expected Version: version-f8f53a67efca4c34" << std::endl;
  std::cout << "Detected Version: " << GetRobloxVersion() << std::endl;
  std::cout << "============================================\n" << std::endl;

  // Get Roblox handle
  HANDLE hProcess = memory::GetProcessHandle(L"RobloxPlayerBeta.exe");
  if (!hProcess) {
    std::cout << "[ERROR] Roblox not found! Please launch the game first."
              << std::endl;
    return results;
  }

  uintptr_t base = memory::GetModuleBase(hProcess, L"RobloxPlayerBeta.exe");
  if (base == 0) {
    std::cout << "[ERROR] Could not get Roblox base address!" << std::endl;
    CloseHandle(hProcess);
    return results;
  }

  std::cout << "[INFO] Roblox Base: 0x" << std::hex << base << std::dec
            << std::endl;

  // Validate DataModel chain
  auto dmResult = ValidateDataModelChain(hProcess, base);
  results.push_back(dmResult);
  std::cout << "[" << (dmResult.valid ? "OK" : "FAIL") << "] " << dmResult.name
            << ": " << dmResult.info;
  if (dmResult.valid)
    std::cout << " (0x" << std::hex << dmResult.value << std::dec << ")";
  std::cout << std::endl;

  if (!dmResult.valid) {
    std::cout << "\n[CRITICAL] DataModel not found. Offsets are likely wrong!"
              << std::endl;
    CloseHandle(hProcess);
    return results;
  }

  // Validate ScriptContext
  auto scResult = ValidateScriptContext(hProcess, dmResult.value);
  results.push_back(scResult);
  std::cout << "[" << (scResult.valid ? "OK" : "FAIL") << "] " << scResult.name
            << ": " << scResult.info;
  if (scResult.valid)
    std::cout << " (0x" << std::hex << scResult.value << std::dec << ")";
  std::cout << std::endl;

  // Validate lua_State offset
  if (scResult.valid) {
    auto lsResult = ValidateLuaStateOffset(hProcess, scResult.value);
    results.push_back(lsResult);
    std::cout << "[" << (lsResult.valid ? "OK" : "FAIL") << "] "
              << lsResult.name << " at offset 0x" << std::hex << lsResult.offset
              << std::dec << ": " << lsResult.info << std::endl;
  }

  // Validate Players
  auto playersResult = ValidatePlayers(hProcess, dmResult.value);
  results.push_back(playersResult);
  std::cout << "[" << (playersResult.valid ? "OK" : "FAIL") << "] "
            << playersResult.name << ": " << playersResult.info;
  if (playersResult.valid)
    std::cout << " (0x" << std::hex << playersResult.value << std::dec << ")";
  std::cout << std::endl;

  // Summary
  int passed = 0, failed = 0;
  for (const auto &r : results) {
    if (r.valid)
      passed++;
    else
      failed++;
  }

  std::cout << "\n============================================" << std::endl;
  std::cout << "SUMMARY: " << passed << " passed, " << failed << " failed"
            << std::endl;

  if (failed > 0) {
    std::cout << "\n[WARNING] Some offsets failed validation!" << std::endl;
    std::cout << "You may need to update offsets.hpp for this Roblox version."
              << std::endl;
    std::cout << "Get updated offsets from: "
                 "https://offsets.ntgetwritewatch.workers.dev/"
              << std::endl;
  } else {
    std::cout << "\n[SUCCESS] All offsets validated!" << std::endl;
  }

  CloseHandle(hProcess);
  return results;
}

// Export function for external use
inline bool VerifyOffsets() {
  auto results = DumpAllOffsets();
  for (const auto &r : results) {
    if (!r.valid)
      return false;
  }
  return true;
}

} // namespace dumper
