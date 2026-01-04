// Roblox Version: version-f8f53a67efca4c34
// Source: config.hscl by @99tracheae
// https://offsets.ntgetwritewatch.workers.dev/

#pragma once
#include <Windows.h>
#include <cstdint>

#define REBASE(x) (x + reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr)))

namespace offsets {
// === Instance Structure ===
constexpr uintptr_t Instance_This = 0x8;
constexpr uintptr_t Instance_Name = 0xB0;
constexpr uintptr_t Instance_Parent = 0x68;
constexpr uintptr_t Instance_Children = 0x70;
constexpr uintptr_t Instance_ClassDescriptor = 0x18;

// === ScriptContext (CRITICAL) ===
constexpr uintptr_t ScriptContext_Luastate = 0x3E0;
// Note: LuastateObfuscation = VMC (needs deobfuscation)

// === Players ===
constexpr uintptr_t Players_LocalPlayer = 0x130;

// === Player ===
constexpr uintptr_t Player_Character = 0x360;
constexpr uintptr_t Player_UserId = 0x2A8;
constexpr uintptr_t Player_DisplayName = 0x130;
constexpr uintptr_t Player_Mouse = 0xCD8;

// === Humanoid ===
constexpr uintptr_t Humanoid_Health = 0x194;
constexpr uintptr_t Humanoid_MaxHealth = 0x1B4;
constexpr uintptr_t Humanoid_WalkSpeed0 = 0x1D4;
constexpr uintptr_t Humanoid_WalkSpeed1 = 0x3C0;
constexpr uintptr_t Humanoid_JumpPower = 0x1B0;
constexpr uintptr_t Humanoid_HipHeight = 0x1A0;

// === Camera ===
constexpr uintptr_t Camera_CFrame = 0xF8;
constexpr uintptr_t Camera_Focus = 0x128;
constexpr uintptr_t Camera_FOV = 0x160;

// === Workspace ===
constexpr uintptr_t Workspace_CurrentCamera = 0x450;
constexpr uintptr_t Workspace_GravityInfo = 0x3C8;
constexpr uintptr_t GravityInfo_Gravity = 0x1D0;

// === BasePart / Primitive ===
constexpr uintptr_t BasePart_Primitive = 0x148;
constexpr uintptr_t Primitive_CFrame = 0xC0;
constexpr uintptr_t Primitive_Size = 0x1B0;
constexpr uintptr_t Primitive_Anchored = 0xD71;
constexpr uintptr_t Primitive_CanCollide = 0xB1F;

// === Script ===
constexpr uintptr_t Script_EmbeddedSource = 0x1A8;
constexpr uintptr_t LocalScript_EmbeddedSource = 0x1A8;
constexpr uintptr_t ModuleScript_EmbeddedSource = 0x150;
constexpr uintptr_t EmbeddedSource_Bytecode = 0x10;

// === DataModel ===
constexpr uintptr_t FakeDatamodel_Datamodel = 0x1C0;
} // namespace offsets

namespace lua_types {
// Lua type identifiers
constexpr int LUA_TNIL = 0;
constexpr int LUA_TBOOLEAN = 1;
constexpr int LUA_TNUMBER = 3;
constexpr int LUA_TVECTOR = 4;
constexpr int LUA_TSTRING = 5;
constexpr int LUA_TTABLE = 6;
constexpr int LUA_TFUNCTION = 7;
constexpr int LUA_TUSERDATA = 8;
constexpr int LUA_TTHREAD = 9;
constexpr int LUA_TBUFFER = 10;
} // namespace lua_types

namespace lua_offsets {
// === Lua Table ===
constexpr uintptr_t Table_TValueSize = 0x10;
constexpr uintptr_t Table_Array = 0x28;
constexpr uintptr_t Table_Node = 0x10;
constexpr uintptr_t Table_Metatable = 0x20;
constexpr uintptr_t Table_IsFrozen = 0x7;

// === Lua Userdata ===
constexpr uintptr_t Userdata_Metatable = 0x8;
constexpr uintptr_t Userdata_Size = 0x4;
constexpr uintptr_t Userdata_Data = 0x10;

// === Lua String ===
constexpr uintptr_t String_Data = 0x18;
constexpr uintptr_t String_Length = 0x14;

// === Lua Buffer ===
constexpr uintptr_t Buffer_Data = 0x8;
constexpr uintptr_t Buffer_Length = 0x4;

// === lua_State ===
constexpr uintptr_t Luastate_Namecall = 0x10;
constexpr uintptr_t Luastate_GlobalTable = 0x20;
constexpr uintptr_t Luastate_ExtraSpace = 0x8;
constexpr uintptr_t Luastate_Global = 0x48;

// === Closure ===
constexpr uintptr_t Closure_Proto = 0x18;

// === Proto ===
constexpr uintptr_t Proto_DebugName = 0x68;
constexpr uintptr_t Proto_Capabilities = 0x30;
constexpr uintptr_t Proto_Constant = 0x8;
constexpr uintptr_t Proto_ConstantSize = 0x88;

// === Global State ===
constexpr uintptr_t GlobalState_Registry = 0xC90;
constexpr uintptr_t GlobalState_Luastate = 0xB10;
constexpr uintptr_t GlobalState_TypeMetatables = 0xB28;

// === ExtraSpace ===
constexpr uintptr_t ExtraSpace_Script = 0x80;
constexpr uintptr_t ExtraSpace_Capabilities = 0x50;
constexpr uintptr_t ExtraSpace_Identity = 0x30;
} // namespace lua_offsets

namespace class_addresses {
// Static class descriptor addresses (REBASE these!)
constexpr uintptr_t ScriptContext = 0x57CB488;
constexpr uintptr_t Players = 0x58FDEE0;
constexpr uintptr_t Workspace = 0x58D4208;
constexpr uintptr_t DataModel = 0x588FC38;
constexpr uintptr_t CoreGui = 0x590D7E8;
constexpr uintptr_t LocalScript = 0x580F978;
constexpr uintptr_t ModuleScript = 0x57F4AF8;
constexpr uintptr_t RunService = 0x58CFB20;
constexpr uintptr_t UserInputService = 0x58CB8D8;
constexpr uintptr_t HttpService = 0x5899220;
constexpr uintptr_t TeleportService = 0x58D2978;
constexpr uintptr_t ReplicatedStorage = 0x58D92E0;
constexpr uintptr_t Lighting = 0x58A1B38;
constexpr uintptr_t Camera = 0x5893860;
constexpr uintptr_t Humanoid = 0x57CD768;
} // namespace class_addresses
