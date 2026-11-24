#pragma once

#include "interface.hpp"

#include <cstdint>
#include <vector>

bool handleMgmtMetricsUdpPacket(
    const interface& mgmtInterface,
    const std::vector<uint8_t>& ipv4Packet,
    std::vector<uint8_t>& outIpv4ResponsePacket,
    bool& outIncrementHttpResponses
);