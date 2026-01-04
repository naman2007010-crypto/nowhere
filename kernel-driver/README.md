# Nowhere Kernel Driver

A Windows kernel driver for reading process memory, bypassing user-mode anti-cheat protections.

## Files

| File | Description |
|------|-------------|
| `driver.c` | Kernel driver source code |
| `kernel_interface.h` | IOCTL definitions & C++ wrapper |
| `kernel_dumper.cpp` | User-mode offset scanner |
| `build_driver.bat` | Build driver (requires WDK) |
| `build_dumper.bat` | Build user-mode app |
| `load_driver.bat` | Load/unload driver |

## Requirements

1. **Windows Driver Kit (WDK)** - [Download](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)
2. **Visual Studio 2022** with C++ Desktop workload
3. **Test Signing Mode** enabled (for loading unsigned drivers)

## Usage (In VM)

### 1. Enable Test Signing (requires reboot)
```cmd
bcdedit /set testsigning on
shutdown /r /t 0
```

### 2. Build the Driver
```cmd
build_driver.bat
```

### 3. Build the Dumper
```cmd
build_dumper.bat
```

### 4. Load the Driver (as Admin)
```cmd
load_driver.bat
```
Select option [1] to load.

### 5. Run the Dumper
1. Launch Roblox/Roblox Studio
2. Run `build\KernelDumper.exe`
3. Offsets saved to `kernel_dumped_offsets.hpp`

### 6. Unload Driver When Done
```cmd
load_driver.bat
```
Select option [2] to unload.

## Safety Notes

- **Run in a VM** - BSOD won't affect host
- Driver uses `MmCopyVirtualMemory` - safe, standard API
- All operations wrapped in `__try/__except`
- Proper cleanup on unload

## Troubleshooting

| Error | Solution |
|-------|----------|
| Driver won't load | Enable test signing, disable Secure Boot |
| "Driver not found" error | Build the driver first |
| Access denied | Run as Administrator |
| Memory read fails | Roblox may have restarted, try again |
