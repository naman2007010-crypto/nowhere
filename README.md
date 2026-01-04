# Nowhere 🌌

Nowhere is a modernized, open-source Roblox script injector and executor. It has been revived to support the latest 64-bit Roblox client with Hyperion (Byfron) anti-cheat protection.

![image](https://user-images.githubusercontent.com/76164598/164978039-8194918e-7634-4824-a40a-058b2c9ebbe7.png)

## Features 🚀

- **x64 Support**: Fully compatible with the 64-bit Roblox client.
- **Hyperion Bypass**: Utilizes advanced thread hijacking and stealth injection techniques.
- **Xeno Engine**: Powered by a custom C++ execution engine for high-performance script execution.
- **AOB Scanning**: Dynamic pattern scanning to survive weekly Roblox updates.
- **Custom Environment**: Built-in support for standard exploit globals.

## Installation 📩

1. Clone this repository.
2. Build the `XenoEngine` C++ project in Visual Studio 2022 (Set to **x64**).
3. Build the `NowhereInjector1` C# project in Visual Studio 2022.
4. Ensure `XenoEngine.dll` is in the same directory as the executable.
5. Launch `Nowhere.exe`.

## Usage 👩‍💻

1. Launch Roblox.
2. Click **INJECT** to map the Xeno engine into the game.
3. Paste your script into the editor.
4. Click **EXEC** to run the script.

### Buttons
- **INJECT**: Injects the engine into Roblox.
- **EXEC**: Executes the script currently in the editor.
- **CLEAR**: Clears the editor.
- **OPEN**: Opens a `.txt` or `.lua` script.
- **SAVE**: Saves the current script to a file.

## Technical Details 🛠️

- **Language**: C#, C++
- **Architecture**: x64
- **Injection Method**: Thread Hijacking / Manual Mapping
- **LUA Engine**: Luau VM Hooking

## Disclaimer ❗

This project is for educational purposes only. Using third-party tools in Roblox may violate their Terms of Service and lead to account bans. Use at your own risk.

---
© 2026 Nowhere Project.
