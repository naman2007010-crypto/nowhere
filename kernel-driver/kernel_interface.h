#pragma once

// ============================================================================
// Kernel Driver Communication Header
// Shared between kernel-mode driver and user-mode application
// ============================================================================

#include <Windows.h>

// Device name and symbolic link
#define DRIVER_NAME L"NowhereDumper"
#define DEVICE_NAME L"\\Device\\NowhereDumper"
#define SYMBOLIC_LINK L"\\DosDevices\\NowhereDumper"
#define USER_DEVICE_PATH L"\\\\.\\NowhereDumper"

// IOCTL codes
#define IOCTL_BASE 0x800

#define IOCTL_READ_MEMORY                                                      \
  CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 1, METHOD_BUFFERED,               \
           FILE_ANY_ACCESS)
#define IOCTL_WRITE_MEMORY                                                     \
  CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 2, METHOD_BUFFERED,               \
           FILE_ANY_ACCESS)
#define IOCTL_GET_MODULE_BASE                                                  \
  CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 3, METHOD_BUFFERED,               \
           FILE_ANY_ACCESS)
#define IOCTL_GET_PROCESS_ID                                                   \
  CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 4, METHOD_BUFFERED,               \
           FILE_ANY_ACCESS)

// Request structures
#pragma pack(push, 1)

typedef struct _KERNEL_READ_REQUEST {
  ULONG ProcessId;  // Target process ID
  ULONG64 Address;  // Address to read from
  ULONG Size;       // Size to read
  ULONG64 Response; // Pointer to output buffer (user-mode)
} KERNEL_READ_REQUEST, *PKERNEL_READ_REQUEST;

typedef struct _KERNEL_WRITE_REQUEST {
  ULONG ProcessId; // Target process ID
  ULONG64 Address; // Address to write to
  ULONG Size;      // Size to write
  ULONG64 Value;   // Value to write (for small writes)
} KERNEL_WRITE_REQUEST, *PKERNEL_WRITE_REQUEST;

typedef struct _KERNEL_MODULE_REQUEST {
  ULONG ProcessId;       // Target process ID
  WCHAR ModuleName[256]; // Module name to find
  ULONG64 BaseAddress;   // Output: module base address
  ULONG64 ModuleSize;    // Output: module size
} KERNEL_MODULE_REQUEST, *PKERNEL_MODULE_REQUEST;

#pragma pack(pop)

// C++ wrapper for easy usage
#ifdef __cplusplus
#include <string>

class KernelInterface {
private:
  HANDLE hDriver = INVALID_HANDLE_VALUE;

public:
  KernelInterface() {
    hDriver = CreateFileW(USER_DEVICE_PATH, GENERIC_READ | GENERIC_WRITE,
                          FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                          OPEN_EXISTING, 0, nullptr);
  }

  ~KernelInterface() {
    if (hDriver != INVALID_HANDLE_VALUE) {
      CloseHandle(hDriver);
    }
  }

  bool IsConnected() const { return hDriver != INVALID_HANDLE_VALUE; }

  // Read memory from target process
  bool ReadMemory(ULONG processId, ULONG64 address, void *buffer, ULONG size) {
    if (!IsConnected())
      return false;

    KERNEL_READ_REQUEST request = {};
    request.ProcessId = processId;
    request.Address = address;
    request.Size = size;
    request.Response = (ULONG64)buffer;

    DWORD bytesReturned = 0;
    return DeviceIoControl(hDriver, IOCTL_READ_MEMORY, &request,
                           sizeof(request), &request, sizeof(request),
                           &bytesReturned, nullptr);
  }

  // Template read helper
  template <typename T> T Read(ULONG processId, ULONG64 address) {
    T value = {};
    ReadMemory(processId, address, &value, sizeof(T));
    return value;
  }

  // Read array
  template <typename T>
  bool ReadArray(ULONG processId, ULONG64 address, T *buffer, size_t count) {
    return ReadMemory(processId, address, buffer, (ULONG)(sizeof(T) * count));
  }

  // Get module base address
  ULONG64 GetModuleBase(ULONG processId, const std::wstring &moduleName) {
    if (!IsConnected())
      return 0;

    KERNEL_MODULE_REQUEST request = {};
    request.ProcessId = processId;
    wcsncpy_s(request.ModuleName, moduleName.c_str(), 255);

    DWORD bytesReturned = 0;
    if (DeviceIoControl(hDriver, IOCTL_GET_MODULE_BASE, &request,
                        sizeof(request), &request, sizeof(request),
                        &bytesReturned, nullptr)) {
      return request.BaseAddress;
    }
    return 0;
  }
};

#endif // __cplusplus
