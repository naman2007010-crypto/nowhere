// Manual Mapper - PE Manual Mapping
// Loads DLL into target process without using LoadLibrary
// Bypasses module detection by not appearing in PEB

#pragma once
#include "thread_hijack.hpp"
#include <Windows.h>
#include <cstdint>
#include <fstream>
#include <string>
#include <vector>


namespace mapper {

// PE Header structures (for clarity, using Windows types)
using BYTE_BUFFER = std::vector<BYTE>;

struct MappedDll {
  uintptr_t base;
  size_t size;
  bool success;
};

// Read DLL file from disk
inline BYTE_BUFFER ReadDllFile(const std::wstring &dllPath) {
  BYTE_BUFFER buffer;

  std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
  if (!file.is_open())
    return buffer;

  size_t size = file.tellg();
  file.seekg(0, std::ios::beg);

  buffer.resize(size);
  file.read(reinterpret_cast<char *>(buffer.data()), size);
  file.close();

  return buffer;
}

// Validate PE headers
inline bool ValidatePE(const BYTE_BUFFER &buffer) {
  if (buffer.size() < sizeof(IMAGE_DOS_HEADER))
    return false;

  auto dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER *>(buffer.data());
  if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    return false;

  if (buffer.size() < dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64))
    return false;

  auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS64 *>(
      buffer.data() + dosHeader->e_lfanew);
  if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    return false;

  // Check for 64-bit
  if (ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
    return false;

  return true;
}

// Get NT Headers from buffer
inline IMAGE_NT_HEADERS64 *GetNtHeaders(BYTE *buffer) {
  auto dosHeader = reinterpret_cast<IMAGE_DOS_HEADER *>(buffer);
  return reinterpret_cast<IMAGE_NT_HEADERS64 *>(buffer + dosHeader->e_lfanew);
}

// Get Section Headers
inline IMAGE_SECTION_HEADER *GetSectionHeaders(IMAGE_NT_HEADERS64 *ntHeaders) {
  return reinterpret_cast<IMAGE_SECTION_HEADER *>(
      reinterpret_cast<BYTE *>(&ntHeaders->OptionalHeader) +
      ntHeaders->FileHeader.SizeOfOptionalHeader);
}

// Allocate memory in target process
inline uintptr_t AllocateInTarget(HANDLE hProcess, size_t size) {
  return (uintptr_t)VirtualAllocEx(hProcess, nullptr, size,
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_EXECUTE_READWRITE);
}

// Copy PE sections to target
inline bool CopySections(HANDLE hProcess, uintptr_t targetBase,
                         BYTE *localImage, IMAGE_NT_HEADERS64 *ntHeaders) {
  auto sections = GetSectionHeaders(ntHeaders);

  for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
    if (sections[i].SizeOfRawData == 0)
      continue;

    uintptr_t destAddr = targetBase + sections[i].VirtualAddress;
    BYTE *srcData = localImage + sections[i].PointerToRawData;

    SIZE_T written;
    if (!WriteProcessMemory(hProcess, (LPVOID)destAddr, srcData,
                            sections[i].SizeOfRawData, &written)) {
      return false;
    }
  }
  return true;
}

// Fix base relocations
inline bool FixRelocations(HANDLE hProcess, uintptr_t targetBase,
                           BYTE *localImage, IMAGE_NT_HEADERS64 *ntHeaders) {
  auto &relocDir =
      ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  if (relocDir.Size == 0)
    return true; // No relocations needed

  uintptr_t preferredBase = ntHeaders->OptionalHeader.ImageBase;
  intptr_t delta = targetBase - preferredBase;

  if (delta == 0)
    return true; // Loaded at preferred address

  auto relocBlock = reinterpret_cast<IMAGE_BASE_RELOCATION *>(
      localImage + relocDir.VirtualAddress);

  while (relocBlock->VirtualAddress != 0) {
    size_t numEntries =
        (relocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) /
        sizeof(WORD);
    WORD *entries = reinterpret_cast<WORD *>(relocBlock + 1);

    for (size_t i = 0; i < numEntries; i++) {
      WORD type = entries[i] >> 12;
      WORD offset = entries[i] & 0xFFF;

      if (type == IMAGE_REL_BASED_DIR64) {
        uintptr_t patchAddr = targetBase + relocBlock->VirtualAddress + offset;

        // Read current value
        uintptr_t value;
        ReadProcessMemory(hProcess, (LPCVOID)patchAddr, &value, sizeof(value),
                          nullptr);

        // Apply delta
        value += delta;

        // Write back
        WriteProcessMemory(hProcess, (LPVOID)patchAddr, &value, sizeof(value),
                           nullptr);
      }
    }

    relocBlock = reinterpret_cast<IMAGE_BASE_RELOCATION *>(
        reinterpret_cast<BYTE *>(relocBlock) + relocBlock->SizeOfBlock);
  }

  return true;
}

// Resolve imports (IAT)
inline bool ResolveImports(HANDLE hProcess, uintptr_t targetBase,
                           BYTE *localImage, IMAGE_NT_HEADERS64 *ntHeaders) {
  auto &importDir =
      ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  if (importDir.Size == 0)
    return true; // No imports

  auto importDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR *>(
      localImage + importDir.VirtualAddress);

  while (importDesc->Name != 0) {
    const char *dllName =
        reinterpret_cast<const char *>(localImage + importDesc->Name);

    // Get module handle in our process (for GetProcAddress)
    // Note: This assumes the DLL is also loaded in our process
    // For a true external mapper, you'd need to resolve from target process
    HMODULE hModule = GetModuleHandleA(dllName);
    if (!hModule) {
      hModule = LoadLibraryA(dllName); // Load if not present
    }
    if (!hModule) {
      // Try to get from target process
      // This is more complex - skip for now
      importDesc++;
      continue;
    }

    // Resolve each function
    auto thunk = reinterpret_cast<IMAGE_THUNK_DATA64 *>(localImage +
                                                        importDesc->FirstThunk);
    auto originalThunk = importDesc->OriginalFirstThunk
                             ? reinterpret_cast<IMAGE_THUNK_DATA64 *>(
                                   localImage + importDesc->OriginalFirstThunk)
                             : thunk;

    while (originalThunk->u1.AddressOfData != 0) {
      uintptr_t funcAddr = 0;

      if (IMAGE_SNAP_BY_ORDINAL64(originalThunk->u1.Ordinal)) {
        // Import by ordinal
        funcAddr = (uintptr_t)GetProcAddress(
            hModule,
            MAKEINTRESOURCEA(IMAGE_ORDINAL64(originalThunk->u1.Ordinal)));
      } else {
        // Import by name
        auto importByName = reinterpret_cast<IMAGE_IMPORT_BY_NAME *>(
            localImage + originalThunk->u1.AddressOfData);
        funcAddr = (uintptr_t)GetProcAddress(hModule, importByName->Name);
      }

      if (funcAddr == 0) {
        thunk++;
        originalThunk++;
        continue;
      }

      // Write function address to IAT in target
      uintptr_t iatEntry =
          targetBase + importDesc->FirstThunk +
          ((BYTE *)thunk - (BYTE *)(localImage + importDesc->FirstThunk));
      WriteProcessMemory(hProcess, (LPVOID)iatEntry, &funcAddr,
                         sizeof(funcAddr), nullptr);

      thunk++;
      originalThunk++;
    }

    importDesc++;
  }

  return true;
}

// Execute DllMain in target using thread hijacking (stealth method)
// Falls back to CreateRemoteThread if hijacking fails
inline bool ExecuteEntry(HANDLE hProcess, uintptr_t entryPoint,
                         uintptr_t dllBase) {
  // Create shellcode that calls DllMain(hModule, DLL_PROCESS_ATTACH, nullptr)
  // DllMain signature: BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason,
  // LPVOID lpvReserved)

  BYTE shellcode[] = {
      // sub rsp, 0x28 (shadow space + alignment)
      0x48, 0x83, 0xEC, 0x28,
      // mov rcx, dllBase (hinstDLL)
      0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // mov rdx, 1 (DLL_PROCESS_ATTACH)
      0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00,
      // xor r8, r8 (lpvReserved = nullptr)
      0x4D, 0x31, 0xC0,
      // mov rax, entryPoint
      0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // call rax
      0xFF, 0xD0,
      // add rsp, 0x28
      0x48, 0x83, 0xC4, 0x28,
      // ret
      0xC3};

  // Patch in addresses
  *reinterpret_cast<uintptr_t *>(&shellcode[6]) = dllBase;
  *reinterpret_cast<uintptr_t *>(&shellcode[26]) = entryPoint;

  // Allocate shellcode in target
  uintptr_t shellcodeAddr = AllocateInTarget(hProcess, sizeof(shellcode));
  if (shellcodeAddr == 0)
    return false;

  // Write shellcode
  WriteProcessMemory(hProcess, (LPVOID)shellcodeAddr, shellcode,
                     sizeof(shellcode), nullptr);

  // ===========================================================================
  // TRY THREAD HIJACKING FIRST (Stealth - bypasses CreateRemoteThread
  // detection)
  // ===========================================================================

  bool hijackSuccess = hijack::ExecuteViaHijack(hProcess, shellcodeAddr, 0);
  if (hijackSuccess) {
    VirtualFreeEx(hProcess, (LPVOID)shellcodeAddr, 0, MEM_RELEASE);
    return true;
  }
  std::cout
      << "[MAPPER] Thread hijacking failed, falling back to CreateRemoteThread"
      << std::endl;

  // ===========================================================================
  // FALLBACK: CreateRemoteThread (Detected by Hyperion but works)
  // ===========================================================================
  HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
                                      (LPTHREAD_START_ROUTINE)shellcodeAddr,
                                      nullptr, 0, nullptr);
  if (hThread == nullptr) {
    VirtualFreeEx(hProcess, (LPVOID)shellcodeAddr, 0, MEM_RELEASE);
    return false;
  }

  // Wait for completion
  WaitForSingleObject(hThread, 5000);
  CloseHandle(hThread);

  // Free shellcode
  VirtualFreeEx(hProcess, (LPVOID)shellcodeAddr, 0, MEM_RELEASE);

  return true;
}

// Main mapping function
inline MappedDll MapDll(HANDLE hProcess, const std::wstring &dllPath) {
  MappedDll result = {0, 0, false};

  // 1. Read DLL file
  BYTE_BUFFER buffer = ReadDllFile(dllPath);
  if (buffer.empty())
    return result;

  // 2. Validate PE
  if (!ValidatePE(buffer))
    return result;

  // 3. Get headers
  auto ntHeaders = GetNtHeaders(buffer.data());
  size_t imageSize = ntHeaders->OptionalHeader.SizeOfImage;

  // 4. Allocate memory in target
  uintptr_t targetBase = AllocateInTarget(hProcess, imageSize);
  if (targetBase == 0)
    return result;

  // 5. Copy headers
  WriteProcessMemory(hProcess, (LPVOID)targetBase, buffer.data(),
                     ntHeaders->OptionalHeader.SizeOfHeaders, nullptr);

  // 6. Copy sections
  if (!CopySections(hProcess, targetBase, buffer.data(), ntHeaders)) {
    VirtualFreeEx(hProcess, (LPVOID)targetBase, 0, MEM_RELEASE);
    return result;
  }

  // 7. Fix relocations
  if (!FixRelocations(hProcess, targetBase, buffer.data(), ntHeaders)) {
    VirtualFreeEx(hProcess, (LPVOID)targetBase, 0, MEM_RELEASE);
    return result;
  }

  // 8. Resolve imports
  if (!ResolveImports(hProcess, targetBase, buffer.data(), ntHeaders)) {
    VirtualFreeEx(hProcess, (LPVOID)targetBase, 0, MEM_RELEASE);
    return result;
  }

  // 9. Execute entry point
  uintptr_t entryPoint =
      targetBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
  if (!ExecuteEntry(hProcess, entryPoint, targetBase)) {
    VirtualFreeEx(hProcess, (LPVOID)targetBase, 0, MEM_RELEASE);
    return result;
  }

  result.base = targetBase;
  result.size = imageSize;
  result.success = true;
  return result;
}

// Convenience wrapper
inline bool InjectDll(const wchar_t *processName, const std::wstring &dllPath) {
  // Open process
  HANDLE hProcess = nullptr;
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

  if (pid == 0)
    return false;

  hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
  if (!hProcess)
    return false;

  MappedDll result = MapDll(hProcess, dllPath);
  CloseHandle(hProcess);

  return result.success;
}

} // namespace mapper
