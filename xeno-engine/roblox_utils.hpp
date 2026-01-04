// Roblox Utility Functions
// Functions for traversing Roblox's instance hierarchy
// Uses external memory reading

#pragma once
#include "memory.hpp"
#include "offsets.hpp"
#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>


namespace roblox {

// Get the Roblox process handle (caches result)
inline HANDLE GetRobloxHandle() {
  static HANDLE hProcess = nullptr;
  if (!memory::IsValidHandle(hProcess)) {
    hProcess = memory::GetProcessHandle(L"RobloxPlayerBeta.exe");
  }
  return hProcess;
}

// Get Roblox base address (caches result)
inline uintptr_t GetRobloxBase() {
  static uintptr_t base = 0;
  if (base == 0) {
    HANDLE hProcess = GetRobloxHandle();
    if (hProcess) {
      base = memory::GetModuleBase(hProcess, L"RobloxPlayerBeta.exe");
    }
  }
  return base;
}

// Read instance name from Roblox string structure
inline std::string GetInstanceName(HANDLE hProcess, uintptr_t instance) {
  if (instance == 0)
    return "";

  uintptr_t namePtr =
      memory::Read<uintptr_t>(hProcess, instance + offsets::Instance_Name);
  if (namePtr == 0)
    return "";

  return memory::ReadRobloxString(hProcess, namePtr);
}

// Get class name from instance's ClassDescriptor
inline std::string GetClassName(HANDLE hProcess, uintptr_t instance) {
  if (instance == 0)
    return "";

  uintptr_t classDescriptor = memory::Read<uintptr_t>(
      hProcess, instance + offsets::Instance_ClassDescriptor);
  if (classDescriptor == 0)
    return "";

  uintptr_t classNamePtr = memory::Read<uintptr_t>(
      hProcess, classDescriptor + 0x8); // ClassDescriptor_ClassName
  if (classNamePtr == 0)
    return "";

  return memory::ReadRobloxString(hProcess, classNamePtr);
}

// Get all children of an instance
inline std::vector<uintptr_t> GetChildren(HANDLE hProcess, uintptr_t parent) {
  std::vector<uintptr_t> children;
  if (parent == 0)
    return children;

  // Children is a std::vector at parent + Instance_Children
  // Vector structure: [begin pointer][end pointer][capacity pointer]
  uintptr_t childrenPtr = parent + offsets::Instance_Children;

  uintptr_t beginPtr = memory::Read<uintptr_t>(hProcess, childrenPtr);
  uintptr_t endPtr = memory::Read<uintptr_t>(hProcess, childrenPtr + 0x8);

  if (beginPtr == 0 || endPtr == 0 || endPtr < beginPtr)
    return children;

  size_t count = (size_t)((endPtr - beginPtr) / sizeof(uintptr_t));
  if (count > 10000)
    return children; // Sanity check

  children = memory::ReadArray<uintptr_t>(hProcess, beginPtr, count);
  return children;
}

// Find first child with matching name
inline uintptr_t FindFirstChild(HANDLE hProcess, uintptr_t parent,
                                const std::string &name) {
  if (parent == 0)
    return 0;

  auto children = GetChildren(hProcess, parent);
  for (uintptr_t child : children) {
    if (GetInstanceName(hProcess, child) == name) {
      return child;
    }
  }
  return 0;
}

// Find first child with matching class name
inline uintptr_t FindFirstChildOfClass(HANDLE hProcess, uintptr_t parent,
                                       const std::string &className) {
  if (parent == 0)
    return 0;

  auto children = GetChildren(hProcess, parent);
  for (uintptr_t child : children) {
    if (GetClassName(hProcess, child) == className) {
      return child;
    }
  }
  return 0;
}

// Get DataModel from static pointer
inline uintptr_t GetDataModel(HANDLE hProcess, uintptr_t base) {
  // FakeDataModelPointer -> FakeDataModel -> DataModel
  uintptr_t fakeDataModelPtr =
      memory::Read<uintptr_t>(hProcess, base + offsets::FakeDataModelPointer);
  if (fakeDataModelPtr == 0)
    return 0;

  return memory::Read<uintptr_t>(
      hProcess, fakeDataModelPtr + offsets::FakeDatamodel_Datamodel);
}

// Get Players service from DataModel
inline uintptr_t GetPlayers(HANDLE hProcess, uintptr_t dataModel) {
  return FindFirstChild(hProcess, dataModel, "Players");
}

// Get ScriptContext service from DataModel
inline uintptr_t GetScriptContext(HANDLE hProcess, uintptr_t dataModel) {
  return FindFirstChild(hProcess, dataModel, "ScriptContext");
}

// Get LocalPlayer from Players service
inline uintptr_t GetLocalPlayer(HANDLE hProcess, uintptr_t players) {
  if (players == 0)
    return 0;
  return memory::Read<uintptr_t>(hProcess,
                                 players + offsets::Players_LocalPlayer);
}

// Get Character from Player
inline uintptr_t GetCharacter(HANDLE hProcess, uintptr_t player) {
  if (player == 0)
    return 0;
  return memory::Read<uintptr_t>(hProcess, player + offsets::Player_Character);
}

// Get Humanoid from Character
inline uintptr_t GetHumanoid(HANDLE hProcess, uintptr_t character) {
  return FindFirstChildOfClass(hProcess, character, "Humanoid");
}

// Get HumanoidRootPart from Character
inline uintptr_t GetHumanoidRootPart(HANDLE hProcess, uintptr_t character) {
  return FindFirstChild(hProcess, character, "HumanoidRootPart");
}

// Get part position (CFrame position component)
inline memory::Vector3 GetPartPosition(HANDLE hProcess, uintptr_t part) {
  if (part == 0)
    return {0, 0, 0};

  // Part -> Primitive -> CFrame
  uintptr_t primitive =
      memory::Read<uintptr_t>(hProcess, part + offsets::BasePart_Primitive);
  if (primitive == 0)
    return {0, 0, 0};

  // CFrame: first 12 floats are rotation matrix, last 3 are position
  // Position is at CFrame + 0x30 (offset 48 bytes = 12 floats)
  return memory::ReadVector3(hProcess,
                             primitive + offsets::Primitive_CFrame + 0x30);
}

// Get Workspace from DataModel
inline uintptr_t GetWorkspace(HANDLE hProcess, uintptr_t dataModel) {
  return FindFirstChild(hProcess, dataModel, "Workspace");
}

// Get CurrentCamera from Workspace
inline uintptr_t GetCurrentCamera(HANDLE hProcess, uintptr_t workspace) {
  if (workspace == 0)
    return 0;
  return memory::Read<uintptr_t>(hProcess,
                                 workspace + offsets::Workspace_CurrentCamera);
}

// Get health from Humanoid
inline float GetHealth(HANDLE hProcess, uintptr_t humanoid) {
  if (humanoid == 0)
    return 0.0f;
  return memory::Read<float>(hProcess, humanoid + offsets::Humanoid_Health);
}

// Get max health from Humanoid
inline float GetMaxHealth(HANDLE hProcess, uintptr_t humanoid) {
  if (humanoid == 0)
    return 0.0f;
  return memory::Read<float>(hProcess, humanoid + offsets::Humanoid_MaxHealth);
}

// Get all players (excluding local player)
inline std::vector<uintptr_t> GetAllPlayers(HANDLE hProcess, uintptr_t players,
                                            uintptr_t localPlayer) {
  std::vector<uintptr_t> result;
  auto children = GetChildren(hProcess, players);

  for (uintptr_t child : children) {
    if (GetClassName(hProcess, child) == "Player" && child != localPlayer) {
      result.push_back(child);
    }
  }
  return result;
}

} // namespace roblox
