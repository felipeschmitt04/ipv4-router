#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include "ipv4.hpp"

using namespace std;

struct ICMPInterpreterResult {
    bool valid = false;
    uint8_t type = 0;
    uint8_t code = 0;
    uint16_t checksum = 0;
    uint32_t restOfHeader = 0;
};

uint16_t calculateICMPChecksum(const vector<uint8_t>& data);

ICMPInterpreterResult icmpInterpreter(const vector<uint8_t>& packet);

vector<uint8_t> buildICMPEchoReply(const vector<uint8_t>& packet);

vector<uint8_t> buildICMPError(
    const vector<uint8_t>& packet,
    uint8_t type,
    uint8_t code,
    uint32_t sourceIP,
    bool ethernetBroadcast = false,
    const string& dropReason = ""
);