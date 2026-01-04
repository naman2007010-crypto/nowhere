// Thread Hijacking - Stealth code execution
// Executes code in target process by hijacking an existing thread
// This bypasses CreateRemoteThread detection by Hyperion
//
// Technique:
// 1. Find a thread in the target process
// 2. Suspend it and save its context
// 3. Modify RIP to point to our shellcode
// 4. Resume the thread
// 5. Wait for completion and restore original context

#pragma once
#include <TlHelp32.h>
#include <Windows.h>
#include <cstdint>
#include <iostream>
#include <vector>

// NT API function declarations
extern "C" {
NTSTATUS NTAPI NtSuspendThread(HANDLE ThreadHandle,
                               PULONG PreviousSuspendCount);
NTSTATUS NTAPI NtResumeThread(HANDLE ThreadHandle, PULONG SuspendCount);
NTSTATUS NTAPI NtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext);
NTSTATUS NTAPI NtSetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext);
NTSTATUS NTAPI NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress,
                                       ULONG_PTR ZeroBits, PSIZE_T RegionSize,
                                       ULONG AllocationType, ULONG Protect);
NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress,
                                    PVOID Buffer, SIZE_T NumberOfBytesToWrite,
                                    PSIZE_T NumberOfBytesWritten);
NTSTATUS NTAPI NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress,
                                   PSIZE_T RegionSize, ULONG FreeType);
}

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace hijack {

// Get all thread IDs for a process
inline std::vector<DWORD> GetProcessThreads(DWORD processId) {
  std::vector<DWORD> threads;

  HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (hSnapshot == INVALID_HANDLE_VALUE)
    return threads;

  THREADENTRY32 te;
  te.dwSize = sizeof(te);

  if (Thread32First(hSnapshot, &te)) {
    do {
      if (te.th32OwnerProcessID == processId) {
        threads.push_back(te.th32ThreadID);
      }
    } while (Thread32Next(hSnapshot, &te));
  }

  CloseHandle(hSnapshot);
  return threads;
}

// Open a thread with required access rights
inline HANDLE OpenThreadForHijack(DWORD threadId) {
  return OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                        THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
                    FALSE, threadId);
}

// Shellcode structure for hijacking
// This shellcode:
// 1. Saves all registers
// 2. Calls our target function with parameter
// 3. Sets completion flag
// 4. Restores registers
// 5. Jumps back to original RIP
#pragma pack(push, 1)
struct HijackShellcode {
  // push all volatile registers
  uint8_t push_rax[1] = {0x50};       // push rax
  uint8_t push_rcx[1] = {0x51};       // push rcx
  uint8_t push_rdx[1] = {0x52};       // push rdx
  uint8_t push_r8[2] = {0x41, 0x50};  // push r8
  uint8_t push_r9[2] = {0x41, 0x51};  // push r9
  uint8_t push_r10[2] = {0x41, 0x52}; // push r10
  uint8_t push_r11[2] = {0x41, 0x53}; // push r11

  // sub rsp, 0x28 (shadow space)
  uint8_t sub_rsp[4] = {0x48, 0x83, 0xEC, 0x28};

  // mov rcx, param (first argument)
  uint8_t mov_rcx[2] = {0x48, 0xB9};
  uint64_t param = 0;

  // mov rax, targetFunc
  uint8_t mov_rax[2] = {0x48, 0xB8};
  uint64_t targetFunc = 0;

  // call rax
  uint8_t call_rax[2] = {0xFF, 0xD0};

  // mov byte ptr [completionFlag], 1
  uint8_t mov_flag_prefix[2] = {0xC6, 0x05};
  int32_t flag_offset = 0; // Relative offset to completion flag
  uint8_t flag_value = 1;

  // add rsp, 0x28
  uint8_t add_rsp[4] = {0x48, 0x83, 0xC4, 0x28};

  // pop all volatile registers (reverse order)
  uint8_t pop_r11[2] = {0x41, 0x5B}; // pop r11
  uint8_t pop_r10[2] = {0x41, 0x5A}; // pop r10
  uint8_t pop_r9[2] = {0x41, 0x59};  // pop r9
  uint8_t pop_r8[2] = {0x41, 0x58};  // pop r8
  uint8_t pop_rdx[1] = {0x5A};       // pop rdx
  uint8_t pop_rcx[1] = {0x59};       // pop rcx
  uint8_t pop_rax[1] = {0x58};       // pop rax

  // jmp originalRip
  uint8_t jmp_prefix[2] = {0xFF, 0x25};
  int32_t jmp_offset = 0; // 0 means next 8 bytes
  uint64_t originalRip = 0;

  // Completion flag (set to 1 when done)
  uint8_t completionFlag = 0;
};
#pragma pack(pop)

// Wait for completion flag with timeout
inline bool WaitForCompletion(HANDLE hProcess, uintptr_t flagAddress,
                              DWORD timeoutMs) {
  DWORD startTime = GetTickCount();
  uint8_t flag = 0;

  while (flag == 0) {
    SIZE_T bytesRead;
    ReadProcessMemory(hProcess, (LPCVOID)flagAddress, &flag, 1, &bytesRead);

    if (GetTickCount() - startTime > timeoutMs) {
      std::cout << "[HIJACK] Timeout waiting for completion" << std::endl;
      return false;
    }

    Sleep(1);
  }

  return true;
}

// Main hijacking function
// Executes targetFunc(param) in the context of the target process
inline bool ExecuteViaHijack(HANDLE hProcess, uintptr_t targetFunc,
                             uintptr_t param) {
  // Get process ID from handle
  DWORD processId = GetProcessId(hProcess);
  if (processId == 0) {
    std::cout << "[HIJACK] Failed to get process ID" << std::endl;
    return false;
  }

  // Get threads
  auto threads = GetProcessThreads(processId);
  if (threads.empty()) {
    std::cout << "[HIJACK] No threads found" << std::endl;
    return false;
  }

  // Try to hijack the first available thread (skip main thread)
  HANDLE hThread = nullptr;
  DWORD targetThreadId = 0;

  for (size_t i = 1; i < threads.size(); i++) { // Skip first (usually main)
    hThread = OpenThreadForHijack(threads[i]);
    if (hThread != nullptr) {
      targetThreadId = threads[i];
      break;
    }
  }

  if (hThread == nullptr) {
    // Try main thread as fallback
    hThread = OpenThreadForHijack(threads[0]);
    if (hThread == nullptr) {
      std::cout << "[HIJACK] Failed to open any thread" << std::endl;
      return false;
    }
    targetThreadId = threads[0];
  }

  std::cout << "[HIJACK] Hijacking thread " << targetThreadId << std::endl;

  // Suspend the thread
  ULONG previousSuspendCount;
  NTSTATUS status = NtSuspendThread(hThread, &previousSuspendCount);
  if (!NT_SUCCESS(status)) {
    std::cout << "[HIJACK] Failed to suspend thread: 0x" << std::hex << status
              << std::endl;
    CloseHandle(hThread);
    return false;
  }

  // Get thread context
  CONTEXT ctx;
  ctx.ContextFlags = CONTEXT_FULL;
  status = NtGetContextThread(hThread, &ctx);
  if (!NT_SUCCESS(status)) {
    std::cout << "[HIJACK] Failed to get thread context: 0x" << std::hex
              << status << std::endl;
    NtResumeThread(hThread, nullptr);
    CloseHandle(hThread);
    return false;
  }

  // Allocate memory for shellcode
  SIZE_T shellcodeSize = sizeof(HijackShellcode);
  PVOID shellcodeAddr = nullptr;
  status =
      NtAllocateVirtualMemory(hProcess, &shellcodeAddr, 0, &shellcodeSize,
                              MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (!NT_SUCCESS(status)) {
    std::cout << "[HIJACK] Failed to allocate shellcode memory: 0x" << std::hex
              << status << std::endl;
    NtResumeThread(hThread, nullptr);
    CloseHandle(hThread);
    return false;
  }

  // Build shellcode
  HijackShellcode shellcode;
  shellcode.param = param;
  shellcode.targetFunc = targetFunc;
  shellcode.originalRip = ctx.Rip;

  // Calculate relative offset for completion flag
  // The flag is at the end of the shellcode struct
  uintptr_t flagAddr =
      (uintptr_t)shellcodeAddr + offsetof(HijackShellcode, completionFlag);

  // Calculate relative offset for the mov instruction
  // mov byte ptr [rip + offset], 1
  // The offset is relative to the instruction after the mov
  uintptr_t movInstrEnd =
      (uintptr_t)shellcodeAddr + offsetof(HijackShellcode, flag_value) + 1;
  shellcode.flag_offset = (int32_t)(flagAddr - movInstrEnd);

  // Write shellcode to target
  SIZE_T bytesWritten;
  status = NtWriteVirtualMemory(hProcess, shellcodeAddr, &shellcode,
                                sizeof(shellcode), &bytesWritten);
  if (!NT_SUCCESS(status)) {
    std::cout << "[HIJACK] Failed to write shellcode: 0x" << std::hex << status
              << std::endl;
    NtFreeVirtualMemory(hProcess, &shellcodeAddr, &shellcodeSize, MEM_RELEASE);
    NtResumeThread(hThread, nullptr);
    CloseHandle(hThread);
    return false;
  }

  // Modify thread context to jump to shellcode
  ctx.Rip = (DWORD64)shellcodeAddr;
  status = NtSetContextThread(hThread, &ctx);
  if (!NT_SUCCESS(status)) {
    std::cout << "[HIJACK] Failed to set thread context: 0x" << std::hex
              << status << std::endl;
    NtFreeVirtualMemory(hProcess, &shellcodeAddr, &shellcodeSize, MEM_RELEASE);
    NtResumeThread(hThread, nullptr);
    CloseHandle(hThread);
    return false;
  }

  // Resume thread
  status = NtResumeThread(hThread, nullptr);
  if (!NT_SUCCESS(status)) {
    std::cout << "[HIJACK] Failed to resume thread: 0x" << std::hex << status
              << std::endl;
    NtFreeVirtualMemory(hProcess, &shellcodeAddr, &shellcodeSize, MEM_RELEASE);
    CloseHandle(hThread);
    return false;
  }

  // Wait for completion
  bool success = WaitForCompletion(hProcess, flagAddr, 5000);

  // Cleanup
  NtFreeVirtualMemory(hProcess, &shellcodeAddr, &shellcodeSize, MEM_RELEASE);
  CloseHandle(hThread);

  if (success) {
    std::cout << "[HIJACK] Execution completed successfully" << std::endl;
  }

  return success;
}

// Simpler version - allocate shellcode with VirtualAllocEx for compatibility
inline bool ExecuteViaHijackSimple(HANDLE hProcess, uintptr_t entryPoint,
                                   uintptr_t dllBase) {
  // Create shellcode that calls DllMain(hModule, DLL_PROCESS_ATTACH, nullptr)
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
      // ret (returns to original code)
      0xC3,
      // Completion flag
      0x00};

  // Patch in addresses
  *reinterpret_cast<uintptr_t *>(&shellcode[6]) = dllBase;
  *reinterpret_cast<uintptr_t *>(&shellcode[26]) = entryPoint;

  // Use ExecuteViaHijack with a wrapper that just contains the call
  return ExecuteViaHijack(hProcess, entryPoint, dllBase);
}

} // namespace hijack
