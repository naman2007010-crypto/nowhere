#include "pattern_scanner.hpp"
#include <Psapi.h>
#include <TlHelp32.h>
#include <Windows.h>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

// Function signatures to scan for (Primary patterns)
namespace Signatures {
const char *LuaVM_Load =
    "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC 30";
const char *Luau_Execute = "40 53 48 83 EC 20 48 8B 59 10 48 8B CB E8";
const char *ScriptContextResume =
    "48 8B C4 48 89 58 ?? 48 89 68 ?? 48 89 70 ?? 48 89 78 ?? 41 54";
const char *PushInstance = "48 89 5C 24 ?? 57 48 83 EC 20 48 8B FA 48 8B D9 E8";
const char *TaskDefer = "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC 20 48 8B F9";
const char *Print = "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC 20 8B 42";
const char *GetLuaState = "53 48 83 EC 20 48 8B D9 48 8B 0D";
} // namespace Signatures

// Alternative/fallback patterns for functions that may change between versions
namespace FallbackPatterns {
// Luau_Execute alternatives - most critical function
const char *Luau_Execute_Alt1 = "48 83 EC ?? 48 8B 49 10 E8";
const char *Luau_Execute_Alt2 =
    "40 55 48 8D 6C 24 ?? 48 81 EC ?? ?? ?? ?? 48 8B 59 10";
const char *Luau_Execute_Alt3 =
    "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B 71 10";
const char *Luau_Execute_Alt4 = "40 53 48 83 EC ?? 48 8B D9 48 8B 49 10";
const char *Luau_Execute_Alt5 =
    "48 8B 41 10 48 8B D0 48 8B 48"; // From call reference

// LuaVM_Load alternatives
const char *LuaVM_Load_Alt1 = "48 89 5C 24 ?? 55 56 57 48 83 EC 40";
const char *LuaVM_Load_Alt2 =
    "48 89 5C 24 ?? 48 89 6C 24 ?? 56 57 41 56 48 83 EC";

// TaskDefer alternatives
const char *TaskDefer_Alt1 =
    "48 89 5C 24 ?? 48 89 74 24 ?? 48 89 7C 24 ?? 41 54";
const char *TaskDefer_Alt2 = "40 53 48 83 EC 30 48 8B D9 E8 ?? ?? ?? ?? 84 C0";

// ScriptContextResume alternatives
const char *ScriptContextResume_Alt1 =
    "48 8B C4 48 89 58 ?? 48 89 68 ?? 48 89 70 ?? 57";
const char *ScriptContextResume_Alt2 =
    "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 48 89 7C 24 ?? 41 54 41 55";
} // namespace FallbackPatterns

// Get Process ID by name
DWORD GetProcessIdByName(const std::wstring &processName) {
  DWORD pid = 0;
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot != INVALID_HANDLE_VALUE) {
    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(snapshot, &entry)) {
      do {
        if (processName == entry.szExeFile) {
          pid = entry.th32ProcessID;
          break;
        }
      } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
  }
  return pid;
}

// Get Module Base Address and Size
struct ModuleInfo {
  uintptr_t baseAddr;
  size_t size;
};

ModuleInfo GetModuleInfo(DWORD pid, const std::wstring &moduleName) {
  ModuleInfo info = {0, 0};
  HANDLE snapshot =
      CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
  if (snapshot != INVALID_HANDLE_VALUE) {
    MODULEENTRY32W entry;
    entry.dwSize = sizeof(MODULEENTRY32W);
    if (Module32FirstW(snapshot, &entry)) {
      do {
        if (moduleName == entry.szModule) {
          info.baseAddr = (uintptr_t)entry.modBaseAddr;
          info.size = entry.modBaseSize;
          break;
        }
      } while (Module32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
  }
  return info;
}

int main() {
  SetConsoleTitleW(L"Nowhere Offset Dumper");
  std::cout << "============================================" << std::endl;
  std::cout << "       NOWHERE OFFSET DUMPER v1.0          " << std::endl;
  std::cout << "============================================" << std::endl;
  std::cout << "[*] Looking for RobloxPlayerBeta.exe..." << std::endl;

  DWORD pid = GetProcessIdByName(L"RobloxPlayerBeta.exe");
  if (pid == 0) {
    std::cout << "[*] Player not found. Trying RobloxStudioBeta.exe..."
              << std::endl;
    pid = GetProcessIdByName(L"RobloxStudioBeta.exe");
  }

  if (pid == 0) {
    std::cout << "[-] Roblox process not found. Please launch Roblox or Roblox "
                 "Studio."
              << std::endl;
    system("pause");
    return 1;
  }

  std::cout << "[+] Found Roblox PID: " << pid << std::endl;

  HANDLE hProcess =
      OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
  if (!hProcess) {
    std::cout << "[-] Failed to open process. Try running as Admin."
              << std::endl;
    system("pause");
    return 1;
  }

  // Try both possible module names
  ModuleInfo modInfo = GetModuleInfo(pid, L"RobloxPlayerBeta.exe");
  if (modInfo.baseAddr == 0) {
    modInfo = GetModuleInfo(pid, L"RobloxStudioBeta.exe");
  }

  if (modInfo.baseAddr == 0) {
    std::cout << "[-] Failed to get module base address." << std::endl;
    CloseHandle(hProcess);
    system("pause");
    return 1;
  }

  std::cout << "[+] Base Address: 0x" << std::hex << modInfo.baseAddr
            << std::dec << std::endl;
  std::cout << "[+] Module Size: " << modInfo.size << " bytes ("
            << (modInfo.size / 1024 / 1024) << " MB)" << std::endl;

  // Read entire module memory
  std::cout << "[*] Reading module memory... (this may take a moment)"
            << std::endl;
  std::vector<uint8_t> buffer(modInfo.size);
  SIZE_T bytesRead;
  if (!ReadProcessMemory(hProcess, (LPCVOID)modInfo.baseAddr, buffer.data(),
                         modInfo.size, &bytesRead)) {
    DWORD err = GetLastError();
    std::cout << "[-] Failed to read process memory. Error: " << err
              << std::endl;
    std::cout << "[-] This might be due to anti-cheat protection." << std::endl;
    CloseHandle(hProcess);
    system("pause");
    return 1;
  }

  std::cout << "[+] Read " << bytesRead << " bytes. Scanning for patterns..."
            << std::endl;

  std::ofstream outFile("dumped_offsets.hpp");
  outFile
      << "#pragma once\n#include <cstdint>\n\nnamespace internal_offsets {\n";

  auto RunScan = [&](const char *name, const char *pattern) -> uintptr_t {
    std::vector<uint8_t> bytes;
    std::string mask;
    if (!Scanner::ParsePattern(pattern, bytes, mask)) {
      std::cout << "[-] Failed to parse pattern for " << name << std::endl;
      return (uintptr_t)-1;
    }

    uintptr_t offset = Scanner::Scan(buffer.data(), bytesRead, bytes, mask);
    if (offset != (uintptr_t)-1) {
      std::cout << "[+] Found " << name << " at offset: 0x" << std::hex
                << offset << std::dec << std::endl;
      outFile << "    constexpr uintptr_t " << name << " = 0x" << std::hex
              << offset << ";\n";
      return offset;
    }
    std::cout << "[-] " << name << " NOT FOUND" << std::endl;
    outFile << "    constexpr uintptr_t " << name << " = 0x0; // NOT FOUND\n";
    return (uintptr_t)-1;
  };

  // Helper to try multiple patterns for a function
  auto RunScanWithFallbacks =
      [&](const char *name, std::vector<const char *> patterns) -> uintptr_t {
    for (size_t i = 0; i < patterns.size(); i++) {
      std::vector<uint8_t> bytes;
      std::string mask;
      if (!Scanner::ParsePattern(patterns[i], bytes, mask)) {
        continue;
      }

      uintptr_t offset = Scanner::Scan(buffer.data(), bytesRead, bytes, mask);
      if (offset != (uintptr_t)-1) {
        std::cout << "[+] Found " << name << " at offset: 0x" << std::hex
                  << offset << std::dec;
        if (i > 0) {
          std::cout << " (using fallback pattern #" << i << ")";
        }
        std::cout << std::endl;
        outFile << "    constexpr uintptr_t " << name << " = 0x" << std::hex
                << offset << ";\n";
        return offset;
      }
    }

    std::cout << "[-] " << name << " NOT FOUND (tried " << patterns.size()
              << " patterns)" << std::endl;
    outFile << "    constexpr uintptr_t " << name << " = 0x0; // NOT FOUND\n";
    return (uintptr_t)-1;
  };

  std::cout << "\n=== Scanning for Luau Functions ===\n" << std::endl;

  // LuaVM_Load - with fallbacks
  RunScanWithFallbacks("LuaVM_Load", {Signatures::LuaVM_Load,
                                      FallbackPatterns::LuaVM_Load_Alt1,
                                      FallbackPatterns::LuaVM_Load_Alt2});

  // Luau_Execute - CRITICAL: try many patterns
  RunScanWithFallbacks("Luau_Execute", {Signatures::Luau_Execute,
                                        FallbackPatterns::Luau_Execute_Alt1,
                                        FallbackPatterns::Luau_Execute_Alt2,
                                        FallbackPatterns::Luau_Execute_Alt3,
                                        FallbackPatterns::Luau_Execute_Alt4,
                                        FallbackPatterns::Luau_Execute_Alt5});

  // ScriptContextResume - with fallbacks
  RunScanWithFallbacks("ScriptContextResume",
                       {Signatures::ScriptContextResume,
                        FallbackPatterns::ScriptContextResume_Alt1,
                        FallbackPatterns::ScriptContextResume_Alt2});

  // PushInstance
  RunScan("PushInstance", Signatures::PushInstance);

  // TaskDefer - with fallbacks
  RunScanWithFallbacks("TaskDefer",
                       {Signatures::TaskDefer, FallbackPatterns::TaskDefer_Alt1,
                        FallbackPatterns::TaskDefer_Alt2});

  // Print
  RunScan("Print", Signatures::Print);

  // GetLuaState
  RunScan("GetLuaState", Signatures::GetLuaState);

  outFile << "}\n";
  outFile.close();

  std::cout << "\n[+] Scan complete! Offsets saved to dumped_offsets.hpp"
            << std::endl;
  std::cout << "[*] Copy these values to xeno-engine/luau_functions.hpp"
            << std::endl;
  CloseHandle(hProcess);
  system("pause");
  return 0;
}
