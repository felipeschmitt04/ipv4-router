#pragma once

#include <vector>
#include <cstdint>
#include <string>
using namespace std;

struct interface{
     uint32_t interfaceIpAddr;
     uint8_t prefixLength;  
     string interfaceName;  
};

extern vector<interface> allInterfaces;

bool isLocal(uint32_t destinationIPAddr);
