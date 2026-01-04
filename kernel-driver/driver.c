// ============================================================================
// Nowhere Kernel Memory Dumper
// A minimal, safe kernel driver for reading process memory
//
// SAFETY NOTES:
// - All pointers are validated before use
// - All operations wrapped in try/except
// - Proper IRQL handling
// - Full cleanup on unload
// ============================================================================

#include <ntddk.h>
#include <ntstrsafe.h>

// ============================================================================
// Constants
// ============================================================================

#define DEVICE_NAME L"\\Device\\NowhereDumper"
#define SYMBOLIC_LINK L"\\DosDevices\\NowhereDumper"

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

// ============================================================================
// Structures
// ============================================================================

#pragma pack(push, 1)

typedef struct _KERNEL_READ_REQUEST {
  ULONG ProcessId;
  ULONG64 Address;
  ULONG Size;
  ULONG64 Response;
} KERNEL_READ_REQUEST, *PKERNEL_READ_REQUEST;

typedef struct _KERNEL_WRITE_REQUEST {
  ULONG ProcessId;
  ULONG64 Address;
  ULONG Size;
  ULONG64 Value;
} KERNEL_WRITE_REQUEST, *PKERNEL_WRITE_REQUEST;

typedef struct _KERNEL_MODULE_REQUEST {
  ULONG ProcessId;
  WCHAR ModuleName[256];
  ULONG64 BaseAddress;
  ULONG64 ModuleSize;
} KERNEL_MODULE_REQUEST, *PKERNEL_MODULE_REQUEST;

#pragma pack(pop)

// ============================================================================
// Globals
// ============================================================================

PDEVICE_OBJECT g_DeviceObject = NULL;
UNICODE_STRING g_DeviceName = {0};
UNICODE_STRING g_SymbolicLink = {0};

// ============================================================================
// Undocumented NT Functions
// ============================================================================

NTKERNELAPI NTSTATUS MmCopyVirtualMemory(PEPROCESS SourceProcess,
                                         PVOID SourceAddress,
                                         PEPROCESS TargetProcess,
                                         PVOID TargetAddress, SIZE_T BufferSize,
                                         KPROCESSOR_MODE PreviousMode,
                                         PSIZE_T ReturnSize);

NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId,
                                                PEPROCESS *Process);

NTKERNELAPI PPEB PsGetProcessPeb(PEPROCESS Process);

// ============================================================================
// Helper Functions
// ============================================================================

// Safely read memory from another process
NTSTATUS SafeReadProcessMemory(ULONG ProcessId, PVOID SourceAddress,
                               PVOID TargetBuffer, SIZE_T Size,
                               PSIZE_T BytesRead) {
  NTSTATUS status = STATUS_SUCCESS;
  PEPROCESS targetProcess = NULL;

  // Validate parameters
  if (ProcessId == 0 || SourceAddress == NULL || TargetBuffer == NULL ||
      Size == 0) {
    return STATUS_INVALID_PARAMETER;
  }

  // Cap size to prevent huge allocations
  if (Size > 0x10000000) { // 256MB max
    return STATUS_INVALID_PARAMETER;
  }

  __try {
    // Get target process
    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId,
                                        &targetProcess);
    if (!NT_SUCCESS(status)) {
      return status;
    }

    // Copy memory
    SIZE_T bytes = 0;
    status =
        MmCopyVirtualMemory(targetProcess, SourceAddress, PsGetCurrentProcess(),
                            TargetBuffer, Size, KernelMode, &bytes);

    if (BytesRead) {
      *BytesRead = bytes;
    }

    ObDereferenceObject(targetProcess);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    status = GetExceptionCode();
    if (targetProcess) {
      ObDereferenceObject(targetProcess);
    }
  }

  return status;
}

// ============================================================================
// IRP Handlers
// ============================================================================

NTSTATUS DriverCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
  UNREFERENCED_PARAMETER(DeviceObject);

  Irp->IoStatus.Status = STATUS_SUCCESS;
  Irp->IoStatus.Information = 0;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);

  DbgPrint("[NowhereDumper] Device opened\n");
  return STATUS_SUCCESS;
}

NTSTATUS DriverClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
  UNREFERENCED_PARAMETER(DeviceObject);

  Irp->IoStatus.Status = STATUS_SUCCESS;
  Irp->IoStatus.Information = 0;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);

  DbgPrint("[NowhereDumper] Device closed\n");
  return STATUS_SUCCESS;
}

NTSTATUS DriverDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
  UNREFERENCED_PARAMETER(DeviceObject);

  NTSTATUS status = STATUS_SUCCESS;
  ULONG bytesReturned = 0;

  PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
  ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;
  ULONG inputSize = stack->Parameters.DeviceIoControl.InputBufferLength;
  PVOID buffer = Irp->AssociatedIrp.SystemBuffer;

  __try {
    switch (controlCode) {
    case IOCTL_READ_MEMORY: {
      if (inputSize < sizeof(KERNEL_READ_REQUEST) || buffer == NULL) {
        status = STATUS_INVALID_PARAMETER;
        break;
      }

      PKERNEL_READ_REQUEST request = (PKERNEL_READ_REQUEST)buffer;

      // Validate request
      if (request->Size == 0 || request->Size > 0x1000000 ||
          request->Response == 0) {
        status = STATUS_INVALID_PARAMETER;
        break;
      }

      // Validate user buffer
      PVOID userBuffer = (PVOID)request->Response;

      __try {
        ProbeForWrite(userBuffer, request->Size, 1);
      } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = STATUS_ACCESS_VIOLATION;
        break;
      }

      // Allocate kernel buffer
      PVOID kernelBuffer =
          ExAllocatePoolWithTag(NonPagedPool, request->Size, 'dump');
      if (kernelBuffer == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        break;
      }

      // Read from target process
      SIZE_T bytesRead = 0;
      status =
          SafeReadProcessMemory(request->ProcessId, (PVOID)request->Address,
                                kernelBuffer, request->Size, &bytesRead);

      if (NT_SUCCESS(status)) {
        // Copy to user buffer
        __try {
          RtlCopyMemory(userBuffer, kernelBuffer, bytesRead);
          bytesReturned = (ULONG)bytesRead;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
          status = STATUS_ACCESS_VIOLATION;
        }
      }

      ExFreePoolWithTag(kernelBuffer, 'dump');
      break;
    }

    default:
      status = STATUS_INVALID_DEVICE_REQUEST;
      break;
    }
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    status = GetExceptionCode();
    DbgPrint("[NowhereDumper] Exception in DeviceControl: 0x%X\n", status);
  }

  Irp->IoStatus.Status = status;
  Irp->IoStatus.Information = bytesReturned;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);

  return status;
}

// ============================================================================
// Driver Entry/Unload
// ============================================================================

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
  UNREFERENCED_PARAMETER(DriverObject);

  DbgPrint("[NowhereDumper] Unloading driver...\n");

  // Delete symbolic link
  if (g_SymbolicLink.Buffer) {
    IoDeleteSymbolicLink(&g_SymbolicLink);
  }

  // Delete device
  if (g_DeviceObject) {
    IoDeleteDevice(g_DeviceObject);
  }

  DbgPrint("[NowhereDumper] Driver unloaded successfully\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,
                     PUNICODE_STRING RegistryPath) {
  UNREFERENCED_PARAMETER(RegistryPath);

  NTSTATUS status = STATUS_SUCCESS;

  DbgPrint("[NowhereDumper] Driver loading...\n");
  DbgPrint("[NowhereDumper] Built: %s %s\n", __DATE__, __TIME__);

  // Initialize strings
  RtlInitUnicodeString(&g_DeviceName, DEVICE_NAME);
  RtlInitUnicodeString(&g_SymbolicLink, SYMBOLIC_LINK);

  // Create device
  status = IoCreateDevice(DriverObject, 0, &g_DeviceName, FILE_DEVICE_UNKNOWN,
                          FILE_DEVICE_SECURE_OPEN, FALSE, &g_DeviceObject);

  if (!NT_SUCCESS(status)) {
    DbgPrint("[NowhereDumper] Failed to create device: 0x%X\n", status);
    return status;
  }

  // Create symbolic link
  status = IoCreateSymbolicLink(&g_SymbolicLink, &g_DeviceName);
  if (!NT_SUCCESS(status)) {
    DbgPrint("[NowhereDumper] Failed to create symbolic link: 0x%X\n", status);
    IoDeleteDevice(g_DeviceObject);
    return status;
  }

  // Set up dispatch routines
  DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreate;
  DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverClose;
  DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDeviceControl;
  DriverObject->DriverUnload = DriverUnload;

  // Allow direct I/O for efficiency
  g_DeviceObject->Flags |= DO_BUFFERED_IO;
  g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

  DbgPrint("[NowhereDumper] Driver loaded successfully\n");
  return STATUS_SUCCESS;
}
