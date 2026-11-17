#pragma once

#include <string>
#include <array>
#include <cstdint>

using namespace std;

array<uint8_t, 6> convertMAC(const string &mac);

void loadConfig(const string& filePath);
