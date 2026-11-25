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
#include <deque>
#include <cstddef>

enum class ArpResolutionStatus
{
    Resolved,
    Pending
};

enum class ArpPacketStatus
{
    Sent,
    Queued,
    QueueFull
};

enum class PacketOrigin
{
    Received,
    Generated
};

struct ArpResolutionResult
{
    ArpResolutionStatus status;
    std::optional<std::array<uint8_t, 6>> mac;
};

using ArpFrameSender = std::function<void(
    const std::string &interfaceName,
    const std::vector<std::uint8_t> &frame)>;

using ArpFailureReporter = std::function<void(
    std::uint32_t nextHopIp,
    const std::string &interfaceName,
    std::size_t droppedPacketsCount)>;

struct ReceivedPacketContext
{
    std::vector<std::uint8_t> originalPacket;
    std::uint32_t incomingIp;
    bool ethBroadcast;
};

using ArpIcmpErrorHandler = std::function<void(
    const ReceivedPacketContext &context)>;

struct ArpStateSnapshot
{
    std::size_t entries;
    std::size_t pendingPackets;
};

class ArpResolver
{
private:
    struct PendingPacket
    {
        std::vector<std::uint8_t> ipv4Packet;
        PacketOrigin origin;
        std::optional<ReceivedPacketContext> context;
    };

    struct ArpRequestToSend
    {
        std::uint32_t nextHopIp;
        std::string interfaceName;
        std::array<std::uint8_t, 6> sourceMac;
        std::uint32_t sourceIp;
    };

    struct PendingResolution
    {
        std::uint32_t nextHopIp;
        std::string interfaceName;
        std::array<std::uint8_t, 6> sourceMac;
        std::uint32_t sourceIp;
        std::chrono::steady_clock::time_point firstRequestAt;
        std::uint8_t requestsSent;
        std::deque<PendingPacket> packets;
    };

    ArpCache cache;
    std::vector<PendingResolution> pendingResolutions;
    std::mutex pendingMutex;
    ArpFrameSender frameSender;
    ArpFailureReporter failureReporter;
    ArpIcmpErrorHandler icmpErrorHandler;

    static constexpr std::size_t maxPacketsPerResolution = 16;
    static constexpr auto resolutionTimeout = std::chrono::seconds(3);

    void reportFailure(const PendingResolution &failed);
    std::size_t pendingPacketsSizeLocked() const;

public:
    explicit ArpResolver(
        ArpFrameSender frameSender,
        ArpFailureReporter failureReporter = {},
        ArpIcmpErrorHandler icmpErrorHandler = {});

    ArpResolutionResult resolve(
        std::uint32_t nextHopIp,
        const interface &outputInterface,
        std::optional<std::chrono::steady_clock::time_point> suppliedTime = std::nullopt);

    void learnFromArp(
        const ArpMessage &message,
        const interface &incomingInterface,
        std::optional<std::chrono::steady_clock::time_point> suppliedTime = std::nullopt);

    void removeExpired(std::chrono::steady_clock::time_point now);

    ArpPacketStatus sendOrQueue(
        std::uint32_t nextHopIp,
        const interface &outputInterface,
        std::vector<std::uint8_t> ipv4Packet,
        std::optional<std::chrono::steady_clock::time_point> suppliedTime = std::nullopt,
        PacketOrigin origin = PacketOrigin::Received,
        std::optional<ReceivedPacketContext> context = std::nullopt);

    void processTimeouts(
        std::optional<std::chrono::steady_clock::time_point> suppliedTime = std::nullopt);

    std::size_t cacheSize();
    std::size_t pendingPacketsSize();
    ArpStateSnapshot snapshot();
};
