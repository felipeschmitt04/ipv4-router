#pragma once

#include "arp.hpp"
#include "interface.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <functional>
#include <vector>
#include <mutex>
#include <chrono>

enum class ArpResolutionStatus
{
    Resolved,
    Pending
};

struct ArpResolutionResult
{
    ArpResolutionStatus status;
    std::optional<std::array<uint8_t, 6>> mac;
};

using ArpFrameSender = std::function<void(
    const std::string &interfaceName,
    const std::vector<std::uint8_t> &frame)>;

class ArpResolver
{
private:
    struct PendingResolution
    {
        std::uint32_t nextHopIp;
        std::string interfaceName;
    };

    ArpCache cache;
    std::vector<PendingResolution> pendingResolutions;
    std::mutex pendingMutex;
    ArpFrameSender frameSender;

public:
    explicit ArpResolver(ArpFrameSender frameSender);

    ArpResolutionResult resolve(
        std::uint32_t nextHopIp,
        const interface& outputInterface,
        std::chrono::steady_clock::time_point now
    );

    void learnFromArp(
        const ArpMessage& message,
        const interface& incomingInterface,
        std::chrono::steady_clock::time_point now
    );

    void removeExpired(std::chrono::steady_clock::time_point now);
};