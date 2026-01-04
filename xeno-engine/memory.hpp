// External Memory Reading Utilities
// For reading Roblox process memory without injection
// Reference: https://github.com/bditt/External-Roblox-ESP

#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Psapi.h>
#include <TlHelp32.h>
#include <Windows.h>
#include <array>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>


namespace memory {

#ifdef XENOENGINE_EXPORTS
// Internal version (direct dereference)
template <typename T> inline T Read(HANDLE hProcess, uintptr_t address) {
  if (address == 0)
    return T{};
  try {
    return *reinterpret_cast<T *>(address);
  } catch (...) {
    return T{};
  }
}
#else
// External version (using ReadProcessMemory)
template <typename T> inline T Read(HANDLE hProcess, uintptr_t address) {
  T value{};
  if (address == 0)
    return value;
  ReadProcessMemory(hProcess, (LPCVOID)address, &value, sizeof(T), nullptr);
  return value;
}
#endif

// Get process ID by name
inline DWORD GetProcessId(const wchar_t *processName) {
  DWORD pid = 0;
  HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

  if (hSnapshot != INVALID_HANDLE_VALUE) {
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(hSnapshot, &pe)) {
      do {
        if (_wcsicmp(pe.szExeFile, processName) == 0) {
          pid = pe.th32ProcessID;
          break;
        }
      } while (Process32NextW(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
  }
  return pid;
}

// Get process handle with read access
inline HANDLE GetProcessHandle(const wchar_t *processName) {
  DWORD pid = GetProcessId(processName);
  if (pid == 0)
    return nullptr;
  return OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
}

// Get module base address in target process
inline uintptr_t GetModuleBase(HANDLE hProcess, const wchar_t *moduleName) {
  HMODULE hModules[1024];
  DWORD cbNeeded;

  if (EnumProcessModulesEx(hProcess, hModules, sizeof(hModules), &cbNeeded,
                           LIST_MODULES_ALL)) {
    for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
      wchar_t szModName[MAX_PATH];
      if (GetModuleBaseNameW(hProcess, hModules[i], szModName,
                             sizeof(szModName) / sizeof(wchar_t))) {
        if (_wcsicmp(szModName, moduleName) == 0) {
          MODULEINFO modInfo;
          if (GetModuleInformation(hProcess, hModules[i], &modInfo,
                                   sizeof(modInfo))) {
            return (uintptr_t)modInfo.lpBaseOfDll;
          }
        }
      }
    }
  }
  return 0;
}

// Read a pointer chain (follows multiple levels of indirection)
inline uintptr_t ReadPointerChain(HANDLE hProcess, uintptr_t base,
                                  const std::vector<uintptr_t> &offsets) {
  uintptr_t address = base;
  for (size_t i = 0; i < offsets.size(); i++) {
    address = Read<uintptr_t>(hProcess, address);
    if (address == 0)
      return 0;
    address += offsets[i];
  }
  return address;
}

// Read a string from memory (with length prefix at offset 0x10)
inline std::string ReadRobloxString(HANDLE hProcess, uintptr_t stringPtr) {
  if (stringPtr == 0)
    return "";

  uint32_t length = Read<uint32_t>(hProcess, stringPtr + 0x14);
  if (length == 0 || length > 1024)
    return ""; // Sanity check

  uintptr_t dataPtr = stringPtr + 0x18; // Inline string data

  std::string result;
  result.resize(length);
#ifdef XENOENGINE_EXPORTS
  memcpy(&result[0], (void *)dataPtr, length);
#else
  ReadProcessMemory(hProcess, (LPCVOID)dataPtr, &result[0], length, nullptr);
#endif
  return result;
}

// Read a fixed-length string
inline std::string ReadString(HANDLE hProcess, uintptr_t address,
                              size_t maxLen = 256) {
  std::string result;
  result.resize(maxLen);
  SIZE_T bytesRead = 0;
  ReadProcessMemory(hProcess, (LPCVOID)address, &result[0], maxLen, &bytesRead);

  // Find null terminator
  size_t nullPos = result.find('\0');
  if (nullPos != std::string::npos) {
    result.resize(nullPos);
  }
  return result;
}

// Read an array of values
template <typename T>
inline std::vector<T> ReadArray(HANDLE hProcess, uintptr_t address,
                                size_t count) {
  std::vector<T> result(count);
  if (address == 0 || count == 0)
    return result;
#ifdef XENOENGINE_EXPORTS
  memcpy(result.data(), (void *)address, count * sizeof(T));
#else
  ReadProcessMemory(hProcess, (LPCVOID)address, result.data(),
                    count * sizeof(T), nullptr);
#endif
  return result;
}

// Read a 4x4 matrix (for ViewMatrix)
inline std::array<float, 16> ReadMatrix4x4(HANDLE hProcess, uintptr_t address) {
  std::array<float, 16> matrix;
#ifdef XENOENGINE_EXPORTS
  if (address != 0)
    memcpy(matrix.data(), (void *)address, sizeof(float) * 16);
#else
  if (address != 0)
    ReadProcessMemory(hProcess, (LPCVOID)address, matrix.data(),
                      sizeof(float) * 16, nullptr);
#endif
  return matrix;
}

// Read Vector3 (x, y, z)
struct Vector3 {
  float x, y, z;
};

inline Vector3 ReadVector3(HANDLE hProcess, uintptr_t address) {
  return Read<Vector3>(hProcess, address);
}

// Check if handle is valid
inline bool IsValidHandle(HANDLE hProcess) {
  if (hProcess == nullptr || hProcess == INVALID_HANDLE_VALUE)
    return false;
  DWORD exitCode;
  return GetExitCodeProcess(hProcess, &exitCode) && exitCode == STILL_ACTIVE;
}

// Close handle safely
inline void CloseProcessHandle(HANDLE hProcess) {
  if (hProcess != nullptr && hProcess != INVALID_HANDLE_VALUE) {
    CloseHandle(hProcess);
  }
}

} // namespace memory
