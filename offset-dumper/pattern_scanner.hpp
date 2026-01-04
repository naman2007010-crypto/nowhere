#pragma once
#include <Windows.h>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>


namespace Scanner {

// Convert hex string pattern to binary array
// Example: "48 89 5C 24 ??" -> bytes={0x48,0x89,0x5C,0x24,0x00}, mask="xxxx?"
inline bool ParsePattern(const char *pattern, std::vector<uint8_t> &bytes,
                         std::string &mask) {
  bytes.clear();
  mask.clear();

  std::string pat(pattern);
  for (size_t i = 0; i < pat.length(); i++) {
    if (pat[i] == ' ')
      continue;

    if (pat[i] == '?') {
      bytes.push_back(0);
      mask += '?';
      if (i + 1 < pat.length() && pat[i + 1] == '?')
        i++; // Skip second ?
    } else {
      if (i + 1 >= pat.length())
        return false;

      char hex[3] = {pat[i], pat[i + 1], 0};
      bytes.push_back((uint8_t)strtol(hex, nullptr, 16));
      mask += 'x';
      i++; // Skip second hex char
    }
  }
  return !bytes.empty();
}

// Scan for pattern in a memory buffer
inline uintptr_t Scan(const uint8_t *buffer, size_t size,
                      const std::vector<uint8_t> &pattern,
                      const std::string &mask) {
  if (pattern.empty() || mask.empty() || pattern.size() != mask.size())
    return 0;

  for (size_t i = 0; i < size - pattern.size(); i++) {
    bool found = true;
    for (size_t j = 0; j < pattern.size(); j++) {
      if (mask[j] == 'x' && pattern[j] != buffer[i + j]) {
        found = false;
        break;
      }
    }
    if (found)
      return i;
  }
  return -1; // Not found
}
} // namespace Scanner
