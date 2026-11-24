#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <vector>
#include <string>
#include <chrono>
#include <mutex>

struct ArpCacheEntry
{
    std::uint32_t neighborIp;
    std::array<std::uint8_t, 6> learnedMac;
    std::string interfaceName;
    std::chrono::steady_clock::time_point expirationTime;
};

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

class ArpCache
{
private:
    std::vector<ArpCacheEntry> cacheEntries;
    std::mutex cacheMutex;

public:
    void learn(
        std::uint32_t neighborIp,
        const std::array<std::uint8_t, 6> &learnedMac,
        const std::string &interfaceName,
        std::chrono::steady_clock::time_point now);

    std::optional<std::array<std::uint8_t, 6>> lookup(
        std::uint32_t neighborIp,
        const std::string &interfaceName,
        std::chrono::steady_clock::time_point now);
    void removeExpired(std::chrono::steady_clock::time_point now);

    std::size_t size()
    {
        std::lock_guard<std::mutex> lock(cacheMutex);
        return cacheEntries.size();
    }
};

std::optional<ArpMessage> parseArpMessage(const std::vector<std::uint8_t> &bytes_Arp);

bool shouldReplyToArpRequest(
    const ArpMessage &message,
    std::uint32_t incomingInterfaceIp);

std::vector<std::uint8_t> buildArpReply(
    const ArpMessage &request,
    const std::array<std::uint8_t, 6> &localMac,
    std::uint32_t localIp);

std::vector<std::uint8_t> buildArpRequest(
    const std::array<std::uint8_t, 6> &localMac,
    std::uint32_t localIp,
    std::uint32_t targetIp);