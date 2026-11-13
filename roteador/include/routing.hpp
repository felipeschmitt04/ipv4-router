#pragma once
#include <vector>
#include <cstdint>
#include <string>
#include "interface.hpp"
using namespace std;

struct Route{
        uint32_t destinationNetwork;
        uint8_t prefixLenght;
        uint32_t nextHop;
        string interfaceName;
};

struct forwardingResult{
      bool found;
      string interfaceName;
      uint32_t nextHop;
}; 

forwardingResult forwarding(uint32_t destinationIPAddr, const vector<interface>& allInterfaces, const vector<Route>& routeTable);
extern vector<Route> routeTable;