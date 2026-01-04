// ============================================================================
// Kernel-Mode Offset Dumper
// Uses the kernel driver to read Roblox memory and find function offsets
// ============================================================================

#include <TlHelp32.h>
#include <Windows.h>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>


#include "../offset-dumper/pattern_scanner.hpp"
#include "kernel_interface.h"


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

// Get module info from toolhelp (doesn't need kernel, just gets size)
struct ModuleInfo {
  ULONG64 baseAddr;
  ULONG64 size;
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
          info.baseAddr = (ULONG64)entry.modBaseAddr;
          info.size = entry.modBaseSize;
          break;
        }
      } while (Module32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
  }
  return info;
}

// Pattern signatures (same as user-mode dumper)
namespace Signatures {
const char *LuaVM_Load =
    "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC 30";
const char *Luau_Execute = "40 53 48 83 EC 20 48 8B 59 10 48 8B CB E8";
const char *Luau_Execute_Alt1 = "48 83 EC ?? 48 8B 49 10 E8";
const char *Luau_Execute_Alt2 =
    "40 55 48 8D 6C 24 ?? 48 81 EC ?? ?? ?? ?? 48 8B 59 10";
const char *Luau_Execute_Alt3 =
    "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B 71 10";
const char *ScriptContextResume =
    "48 8B C4 48 89 58 ?? 48 89 68 ?? 48 89 70 ?? 48 89 78 ?? 41 54";
const char *PushInstance = "48 89 5C 24 ?? 57 48 83 EC 20 48 8B FA 48 8B D9 E8";
const char *TaskDefer = "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC 20 48 8B F9";
const char *Print = "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC 20 8B 42";
} // namespace Signatures

int main() {
  SetConsoleTitleW(L"Nowhere Kernel Offset Dumper");
  std::cout << "============================================" << std::endl;
  std::cout << "   NOWHERE KERNEL OFFSET DUMPER v1.0" << std::endl;
  std::cout << "============================================" << std::endl;

  // Connect to kernel driver
  std::cout << "[*] Connecting to kernel driver..." << std::endl;
  KernelInterface kernel;

  if (!kernel.IsConnected()) {
    DWORD err = GetLastError();
    std::cout << "[-] Failed to connect to kernel driver! Error: " << err
              << std::endl;
    std::cout
        << "[-] Make sure the driver is loaded (run load_driver.bat as Admin)"
        << std::endl;
    system("pause");
    return 1;
  }

  std::cout << "[+] Connected to kernel driver!" << std::endl;

  // Find Roblox process
  std::cout << "[*] Looking for RobloxPlayerBeta.exe..." << std::endl;
  DWORD pid = GetProcessIdByName(L"RobloxPlayerBeta.exe");

  if (pid == 0) {
    std::cout << "[*] Player not found. Trying RobloxStudioBeta.exe..."
              << std::endl;
    pid = GetProcessIdByName(L"RobloxStudioBeta.exe");
  }

  if (pid == 0) {
    std::cout << "[-] Roblox process not found!" << std::endl;
    system("pause");
    return 1;
  }

  std::cout << "[+] Found Roblox PID: " << pid << std::endl;

  // Get module info
  ModuleInfo modInfo = GetModuleInfo(pid, L"RobloxPlayerBeta.exe");
  if (modInfo.baseAddr == 0) {
    modInfo = GetModuleInfo(pid, L"RobloxStudioBeta.exe");
  }

  if (modInfo.baseAddr == 0) {
    std::cout << "[-] Failed to get module info!" << std::endl;
    system("pause");
    return 1;
  }

  std::cout << "[+] Base Address: 0x" << std::hex << modInfo.baseAddr
            << std::dec << std::endl;
  std::cout << "[+] Module Size: " << modInfo.size << " bytes ("
            << (modInfo.size / 1024 / 1024) << " MB)" << std::endl;

  // Read module memory using kernel driver
  std::cout << "[*] Reading module memory via kernel driver..." << std::endl;
  std::cout << "[*] This bypasses Hyperion protection!" << std::endl;

  std::vector<uint8_t> buffer(modInfo.size);

  // Read in chunks to avoid issues
  const size_t CHUNK_SIZE = 0x100000; // 1MB chunks
  size_t totalRead = 0;

  for (size_t offset = 0; offset < modInfo.size; offset += CHUNK_SIZE) {
    size_t chunkSize = min(CHUNK_SIZE, modInfo.size - offset);

    if (kernel.ReadMemory(pid, modInfo.baseAddr + offset,
                          buffer.data() + offset, (ULONG)chunkSize)) {
      totalRead += chunkSize;
    } else {
      std::cout << "[!] Failed to read chunk at offset 0x" << std::hex << offset
                << std::dec << std::endl;
    }

    // Progress
    if (offset % 0x1000000 == 0 && offset > 0) {
      std::cout << "[*] Progress: " << (offset * 100 / modInfo.size) << "%"
                << std::endl;
    }
  }

  std::cout << "[+] Read " << totalRead << " bytes successfully!" << std::endl;

  if (totalRead < modInfo.size / 2) {
    std::cout << "[-] Less than 50% read, memory dump may be incomplete"
              << std::endl;
  }

  // Scan for patterns
  std::cout << "\n[*] Scanning for Luau function patterns..." << std::endl;

  std::ofstream outFile("kernel_dumped_offsets.hpp");
  outFile << "#pragma once\n#include <cstdint>\n\n// Dumped via kernel "
             "driver\nnamespace internal_offsets {\n";

  auto RunScan = [&](const char *name, std::vector<const char *> patterns) {
    for (const char *pattern : patterns) {
      std::vector<uint8_t> bytes;
      std::string mask;
      if (!Scanner::ParsePattern(pattern, bytes, mask))
        continue;

      uintptr_t offset = Scanner::Scan(buffer.data(), totalRead, bytes, mask);
      if (offset != (uintptr_t)-1) {
        std::cout << "[+] Found " << name << " at offset: 0x" << std::hex
                  << offset << std::dec << std::endl;
        outFile << "    constexpr uintptr_t " << name << " = 0x" << std::hex
                << offset << ";\n";
        return true;
      }
    }
    std::cout << "[-] " << name << " NOT FOUND" << std::endl;
    outFile << "    constexpr uintptr_t " << name << " = 0x0; // NOT FOUND\n";
    return false;
  };

  RunScan("LuaVM_Load", {Signatures::LuaVM_Load});
  RunScan("Luau_Execute",
          {Signatures::Luau_Execute, Signatures::Luau_Execute_Alt1,
           Signatures::Luau_Execute_Alt2, Signatures::Luau_Execute_Alt3});
  RunScan("ScriptContextResume", {Signatures::ScriptContextResume});
  RunScan("PushInstance", {Signatures::PushInstance});
  RunScan("TaskDefer", {Signatures::TaskDefer});
  RunScan("Print", {Signatures::Print});

  outFile << "}\n";
  outFile.close();

  std::cout << "\n[+] Scan complete! Offsets saved to kernel_dumped_offsets.hpp"
            << std::endl;
  std::cout << "[*] Copy these values to xeno-engine/luau_functions.hpp"
            << std::endl;

  system("pause");
  return 0;
}
