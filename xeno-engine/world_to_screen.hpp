// WorldToScreen - 3D to 2D Conversion
// Converts world coordinates to screen coordinates for ESP rendering
// Reference: https://github.com/nordlol/nord-external

#pragma once
#include "memory.hpp"
#include "offsets.hpp"
#include <array>
#include <cmath>

namespace rendering {

struct Vector2 {
  float x, y;

  Vector2() : x(0), y(0) {}
  Vector2(float _x, float _y) : x(_x), y(_y) {}

  bool IsValid() const { return x != 0 || y != 0; }
};

struct Vector3 {
  float x, y, z;

  Vector3() : x(0), y(0), z(0) {}
  Vector3(float _x, float _y, float _z) : x(_x), y(_y), z(_z) {}

  float Distance(const Vector3 &other) const {
    float dx = x - other.x;
    float dy = y - other.y;
    float dz = z - other.z;
    return std::sqrt(dx * dx + dy * dy + dz * dz);
  }
};

// 4x4 Matrix for ViewMatrix
struct Matrix4x4 {
  float m[4][4];

  Matrix4x4() { memset(m, 0, sizeof(m)); }
};

// Read ViewMatrix from Camera
inline Matrix4x4 GetViewMatrix(HANDLE hProcess, uintptr_t camera) {
  Matrix4x4 matrix;
  if (camera == 0)
    return matrix;

  // ViewMatrix is at Camera + 0x4B0
  ReadProcessMemory(hProcess, (LPCVOID)(camera + 0x4B0), &matrix,
                    sizeof(Matrix4x4), nullptr);
  return matrix;
}

// Get screen dimensions (you may need to read these from Roblox or use a fixed
// value)
inline void GetScreenSize(int &width, int &height) {
  // Default to common resolution, or read from system
  width = GetSystemMetrics(SM_CXSCREEN);
  height = GetSystemMetrics(SM_CYSCREEN);
}

// Convert 3D world position to 2D screen position
// Returns Vector2(0,0) if the point is behind the camera
inline Vector2 WorldToScreen(HANDLE hProcess, uintptr_t camera,
                             const Vector3 &worldPos) {
  if (camera == 0)
    return Vector2();

  Matrix4x4 viewMatrix = GetViewMatrix(hProcess, camera);

  // Get screen dimensions
  int screenWidth, screenHeight;
  GetScreenSize(screenWidth, screenHeight);

  // Transform world position by view-projection matrix
  // clipCoords = ViewMatrix * worldPos
  float clipX = worldPos.x * viewMatrix.m[0][0] +
                worldPos.y * viewMatrix.m[1][0] +
                worldPos.z * viewMatrix.m[2][0] + viewMatrix.m[3][0];
  float clipY = worldPos.x * viewMatrix.m[0][1] +
                worldPos.y * viewMatrix.m[1][1] +
                worldPos.z * viewMatrix.m[2][1] + viewMatrix.m[3][1];
  float clipZ = worldPos.x * viewMatrix.m[0][2] +
                worldPos.y * viewMatrix.m[1][2] +
                worldPos.z * viewMatrix.m[2][2] + viewMatrix.m[3][2];
  float clipW = worldPos.x * viewMatrix.m[0][3] +
                worldPos.y * viewMatrix.m[1][3] +
                worldPos.z * viewMatrix.m[2][3] + viewMatrix.m[3][3];

  // Check if point is behind camera
  if (clipW < 0.1f) {
    return Vector2(); // Invalid - behind camera
  }

  // Perspective divide (NDC coordinates)
  float ndcX = clipX / clipW;
  float ndcY = clipY / clipW;

  // Convert NDC to screen coordinates
  // NDC range is -1 to 1, screen range is 0 to width/height
  float screenX = (ndcX + 1.0f) * 0.5f * screenWidth;
  float screenY = (1.0f - ndcY) * 0.5f * screenHeight; // Y is inverted

  // Check if on screen
  if (screenX < 0 || screenX > screenWidth || screenY < 0 ||
      screenY > screenHeight) {
    // Optionally return invalid or clamp
    // For now, still return the position (useful for tracers)
  }

  return Vector2(screenX, screenY);
}

// Alternative W2S using Roblox's camera directly
// This reads the camera's CFrame and FOV to compute projection
inline Vector2 WorldToScreenAlt(HANDLE hProcess, uintptr_t camera,
                                const Vector3 &worldPos) {
  if (camera == 0)
    return Vector2();

  // Read camera CFrame (rotation matrix + position)
  // CFrame is at Camera + 0xF8
  float cframe[12]; // 3x3 rotation + 3 position
  ReadProcessMemory(hProcess, (LPCVOID)(camera + 0xF8), cframe, sizeof(cframe),
                    nullptr);

  // Read FOV
  float fov = memory::Read<float>(hProcess, camera + 0x160);
  if (fov <= 0)
    fov = 70.0f; // Default FOV

  // Camera position (last 3 floats of CFrame)
  Vector3 camPos(cframe[9], cframe[10], cframe[11]);

  // Camera look direction (second column of rotation matrix)
  Vector3 camLook(cframe[2], cframe[5], cframe[8]);

  // Camera right direction (first column)
  Vector3 camRight(cframe[0], cframe[3], cframe[6]);

  // Camera up direction (third column... wait, it's second)
  Vector3 camUp(cframe[1], cframe[4], cframe[7]);

  // Vector from camera to point
  Vector3 toPoint(worldPos.x - camPos.x, worldPos.y - camPos.y,
                  worldPos.z - camPos.z);

  // Project onto camera axes
  float forward =
      toPoint.x * camLook.x + toPoint.y * camLook.y + toPoint.z * camLook.z;
  float right =
      toPoint.x * camRight.x + toPoint.y * camRight.y + toPoint.z * camRight.z;
  float up = toPoint.x * camUp.x + toPoint.y * camUp.y + toPoint.z * camUp.z;

  // Behind camera check
  if (forward < 0.1f)
    return Vector2();

  // Get screen dimensions
  int screenWidth, screenHeight;
  GetScreenSize(screenWidth, screenHeight);

  // Calculate aspect ratio
  float aspectRatio = (float)screenWidth / (float)screenHeight;

  // Convert FOV to radians and calculate projection scale
  float fovRad = fov * 3.14159265f / 180.0f;
  float tanHalfFov = std::tan(fovRad / 2.0f);

  // Project to screen space
  float screenX = (screenWidth / 2.0f) + (right / forward) *
                                             (screenWidth / 2.0f) /
                                             (tanHalfFov * aspectRatio);
  float screenY = (screenHeight / 2.0f) -
                  (up / forward) * (screenHeight / 2.0f) / tanHalfFov;

  return Vector2(screenX, screenY);
}

// Helper: Check if screen position is visible
inline bool IsOnScreen(const Vector2 &pos) {
  int screenWidth, screenHeight;
  GetScreenSize(screenWidth, screenHeight);
  return pos.IsValid() && pos.x >= 0 && pos.x <= screenWidth && pos.y >= 0 &&
         pos.y <= screenHeight;
}

} // namespace rendering
