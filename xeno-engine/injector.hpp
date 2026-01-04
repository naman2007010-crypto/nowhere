#pragma once
#include <iostream>
#include <tlhelp32.h>
#include <vector>
#include <windows.h>

namespace injector {
// Thread Hijacking injection method
// This bypasses many Hyperion detections that watch for CreateRemoteThread
bool inject_stealth(DWORD process_id, const std::string &dll_path) {
  HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
  if (!hProcess)
    return false;

  LPVOID pDllPath = VirtualAllocEx(hProcess, nullptr, dll_path.length() + 1,
                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!pDllPath)
    return false;

  WriteProcessMemory(hProcess, pDllPath, dll_path.c_str(),
                     dll_path.length() + 1, nullptr);

  // Find a thread to hijack
  HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  THREADENTRY32 te;
  te.dwSize = sizeof(te);

  DWORD targetThreadId = 0;
  if (Thread32First(hSnapshot, &te)) {
    do {
      if (te.th32OwnerProcessID == process_id) {
        targetThreadId = te.th32ThreadID;
        break;
      }
    } while (Thread32Next(hSnapshot, &te));
  }
  CloseHandle(hSnapshot);

  if (!targetThreadId)
    return false;

  HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, targetThreadId);
  SuspendThread(hThread);

  CONTEXT ctx;
  ctx.ContextFlags = CONTEXT_CONTROL;
  GetThreadContext(hThread, &ctx);

  // RIP hijacking for x64
  uintptr_t loadLibraryAddr = (uintptr_t)GetProcAddress(
      GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

  // shellcode for x64 thread hijacking
  unsigned char shellcode[] = {
      0x48, 0x83, 0xEC, 0x28, // sub rsp, 28h
      0x48, 0xB9, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, pDllPath (placeholder)
      0x48, 0xB8, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, LoadLibraryA (placeholder)
      0xFF, 0xD0,                   // call rax
      0x48, 0x83, 0xC4, 0x28,       // add rsp, 28h
      0x48, 0xB8, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, originalRIP (placeholder)
      0xFF, 0xE0                    // jmp rax
  };

  // Patch placeholders
  *(uintptr_t *)(shellcode + 6) = (uintptr_t)pDllPath;
  *(uintptr_t *)(shellcode + 16) = loadLibraryAddr;
  *(uintptr_t *)(shellcode + 32) = ctx.Rip;

  LPVOID pShellcode =
      VirtualAllocEx(hProcess, nullptr, sizeof(shellcode),
                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  WriteProcessMemory(hProcess, pShellcode, shellcode, sizeof(shellcode),
                     nullptr);

  ctx.Rip = (uintptr_t)pShellcode;
  SetThreadContext(hThread, &ctx);

  ResumeThread(hThread);
  CloseHandle(hThread);
  CloseHandle(hProcess);
  return true;
}
} // namespace injector
