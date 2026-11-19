#include "../include/arp_resolver.hpp"
#include "../include/ethernet.hpp"

#include <algorithm>
#include <utility>

ArpResolver::ArpResolver(ArpFrameSender frameSender) : frameSender(std::move(frameSender))
{
}

ArpResolutionResult ArpResolver::resolve(
    std::uint32_t nextHopIp,
    const interface &outputInterface,
    std::chrono::steady_clock::time_point now)
{
    const auto learnedMac = cache.lookup(
        nextHopIp,
        outputInterface.interfaceName,
        now);

    if (learnedMac.has_value())
    {
        return {ArpResolutionStatus::Resolved, learnedMac};
    }

    bool shouldSendRequest = false;
    {
        std::lock_guard<std::mutex> lock(pendingMutex);

        const auto pending = std::find_if(
            pendingResolutions.begin(),
            pendingResolutions.end(),
            [&](const PendingResolution &entry)
            {
                return entry.nextHopIp == nextHopIp &&
                       entry.interfaceName == outputInterface.interfaceName;
            });

        if (pending == pendingResolutions.end())
        {
            pendingResolutions.push_back(
                {nextHopIp, outputInterface.interfaceName});
            shouldSendRequest = true;
        }
    }

    if (!shouldSendRequest)
    {
        return {ArpResolutionStatus::Pending, std::nullopt};
    }

    const std::array<std::uint8_t, 6> broadcast = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    const auto arpPayload = buildArpRequest(
        outputInterface.mac,
        outputInterface.interfaceIpAddr,
        nextHopIp);

    const auto arpFrame = buildEthernetFrame(
        broadcast,
        outputInterface.mac,
        0x0806,
        arpPayload);

    frameSender(outputInterface.interfaceName, arpFrame);

    return {ArpResolutionStatus::Pending, std::nullopt};
}

void ArpResolver::learnFromArp(const ArpMessage &message,
                               const interface &incomingInterface,
                               std::chrono::steady_clock::time_point now)
{
    if (message.targetIP != incomingInterface.interfaceIpAddr)
    {
        return;
    }

    if (message.senderIP == 0)
    {
        return;
    }

    cache.learn(
        message.senderIP,
        message.senderMAC,
        incomingInterface.interfaceName,
        now);

    std::lock_guard<std::mutex> lock(pendingMutex);

    const auto firstFinished = std::remove_if(
        pendingResolutions.begin(),
        pendingResolutions.end(),
        [&](const PendingResolution &entry)
        {
            return entry.nextHopIp == message.senderIP &&
                   entry.interfaceName == incomingInterface.interfaceName;
        });
    pendingResolutions.erase(
        firstFinished,
        pendingResolutions.end());
}

void ArpResolver::removeExpired(std::chrono::steady_clock::time_point now){
    cache.removeExpired(now);
}