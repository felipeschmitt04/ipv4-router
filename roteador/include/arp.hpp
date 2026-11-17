#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

struct ArpMessage
{
    std::uint16_t hardware_type;
    std::uint16_t protocol_type;
    std::uint8_t hardware_length;
    std::uint8_t protocol_length;
    std::uint16_t operation;
    std::array<std::uint8_t, 6> senderMAC;
    std::uint32_t senderIP;
    std::array<std::uint8_t, 6> targetMAC;
    std::uint32_t targetIP;
};

std::optional<ArpMessage> parseArpMessage(const std::vector<std::uint8_t> &bytes_Arp);

bool shouldReplyToArpRequest(
    const ArpMessage& message,
    std::uint32_t incomingInterfaceIp
);

std::vector<std::uint8_t> buildArpReply(
    const ArpMessage &request,
    const std::array<std::uint8_t, 6> &localMac,
    std::uint32_t localIp);