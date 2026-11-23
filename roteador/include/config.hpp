#pragma once

#include <string>
#include <array>
#include <vector>
#include <cstdint>

enum class FilterAction
{
    Permitir,
    Negar
};

struct FilterRule
{
    uint32_t ruleNumber;      
    FilterAction action;
    uint8_t protocol;         
    bool anySrc;             
    uint32_t srcNetwork;
    uint8_t srcPrefixLength;
    bool anyDst;              
    uint32_t dstNetwork;
    uint8_t dstPrefixLength;
    uint16_t dstPort;         
};

extern std::string routerName;
extern std::vector<FilterRule> filterRules;

std::array<uint8_t, 6> convertMAC(const std::string &mac);

void loadConfig(const std::string &filePath);