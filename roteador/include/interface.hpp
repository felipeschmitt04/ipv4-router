#pragma once

#include <vector>
#include <cstdint>
#include <string>
#include <array>
using namespace std;

struct interface{
     uint32_t interfaceIpAddr;
     uint8_t prefixLength;  
     string interfaceName;  
     array<uint8_t, 6> mac;
};

extern vector<interface> allInterfaces;

bool isLocal(uint32_t destinationIPAddr);
