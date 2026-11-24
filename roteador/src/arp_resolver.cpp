#include "../include/arp_resolver.hpp"
#include "../include/ethernet.hpp"
#include "../include/ipv4.hpp"
#include "../include/logger.hpp"

#include <algorithm>
#include <utility>

ArpResolver::ArpResolver(ArpFrameSender frameSender,
                         ArpFailureReporter failureReporter,
                         ArpIcmpErrorHandler icmpErrorHandler) : frameSender(std::move(frameSender)),
                                                                 failureReporter(std::move(failureReporter)),
                                                                 icmpErrorHandler(std::move(icmpErrorHandler))
{
}

ArpResolutionResult ArpResolver::resolve(
    std::uint32_t nextHopIp,
    const interface &outputInterface,
    std::chrono::steady_clock::time_point now)
{
    // Serializa consulta ao cache, fila e envio de quadros.
    std::lock_guard<std::mutex> lock(pendingMutex);

    const auto learnedMac = cache.lookup(
        nextHopIp,
        outputInterface.interfaceName,
        now);

    if (learnedMac.has_value())
    {
        return {ArpResolutionStatus::Resolved, learnedMac};
    }

    bool shouldSendRequest = false;

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
            {nextHopIp, outputInterface.interfaceName, outputInterface.mac, outputInterface.interfaceIpAddr, now, 1, {}});
        shouldSendRequest = true;
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
    // Serializa consulta ao cache, fila e envio de quadros.
    std::lock_guard<std::mutex> lock(pendingMutex);

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

    std::optional<PendingResolution> completedResolution;


    const auto pending = std::find_if(
        pendingResolutions.begin(),
        pendingResolutions.end(),
        [&](const PendingResolution &entry)
        {
            return entry.nextHopIp == message.senderIP &&
                   entry.interfaceName == incomingInterface.interfaceName;
        });

    if (pending != pendingResolutions.end())
    {
        completedResolution = std::move(*pending);
        pendingResolutions.erase(pending);
    }

    if (!completedResolution.has_value())
    {
        return;
    }

    for (const PendingPacket &packet : completedResolution->packets)
    {
        const auto ethernetFrame = buildEthernetFrame(
            message.senderMAC,
            completedResolution->sourceMac,
            0x0800,
            packet.ipv4Packet);

        frameSender(completedResolution->interfaceName, ethernetFrame);
    }
}

void ArpResolver::removeExpired(std::chrono::steady_clock::time_point now)
{
    std::lock_guard<std::mutex> lock(pendingMutex);
    cache.removeExpired(now);
}

ArpPacketStatus ArpResolver::sendOrQueue(
    std::uint32_t nextHopIp,
    const interface &outputInterface,
    std::vector<std::uint8_t> ipv4Packet,
    std::chrono::steady_clock::time_point now,
    PacketOrigin origin,
    std::optional<ReceivedPacketContext> context)
{
    // Serializa consulta ao cache, fila e envio de quadros.
    std::lock_guard<std::mutex> lock(pendingMutex);

    const auto learnedMac = cache.lookup(
        nextHopIp,
        outputInterface.interfaceName,
        now);

    if (learnedMac.has_value())
    {
        const auto ethernetFrame = buildEthernetFrame(
            *learnedMac,
            outputInterface.mac,
            0x0800,
            ipv4Packet);

        frameSender(outputInterface.interfaceName, ethernetFrame);
        return ArpPacketStatus::Sent;
    }


    const auto pending = std::find_if(
        pendingResolutions.begin(),
        pendingResolutions.end(),
        [&](const PendingResolution &entry)
        {
            return entry.nextHopIp == nextHopIp &&
                   entry.interfaceName == outputInterface.interfaceName;
        });

    if (pending != pendingResolutions.end())
    {
        if (pending->packets.size() >= maxPacketsPerResolution)
        {
            const ipv4Header header = ipv4Interpreter(ipv4Packet);
            if (header.valid)
            {
                logDescarte("fila_arp", header.sourceIPAddr, header.destinationIPAddr, header.protocol);
            }
            return ArpPacketStatus::QueueFull;
        }

        pending->packets.push_back(
            PendingPacket{std::move(ipv4Packet), origin, std::move(context)});

        return ArpPacketStatus::Queued;
    }

    PendingResolution newPending{
        nextHopIp,
        outputInterface.interfaceName,
        outputInterface.mac,
        outputInterface.interfaceIpAddr,
        now,
        1,
        {}};

    newPending.packets.push_back(
        PendingPacket{std::move(ipv4Packet), origin, std::move(context)});

    pendingResolutions.push_back(std::move(newPending));

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

    return ArpPacketStatus::Queued;
}

void ArpResolver::processTimeouts(
    std::chrono::steady_clock::time_point now)
{
    std::vector<ArpRequestToSend> requestsToSend;
    std::vector<PendingResolution> failedResolutions;

    {
        std::lock_guard<std::mutex> lock(pendingMutex);

        for (auto pending = pendingResolutions.begin();
             pending != pendingResolutions.end();)
        {
            const auto elapsed = now - pending->firstRequestAt;

            if (elapsed >= std::chrono::seconds(3))
            {
                failedResolutions.push_back(std::move(*pending));
                pending = pendingResolutions.erase(pending);
                continue;
            }

            const bool retryDue =
                (pending->requestsSent == 1 &&
                 elapsed >= std::chrono::seconds(1)) ||
                (pending->requestsSent == 2 &&
                 elapsed >= std::chrono::seconds(2));

            if (retryDue)
            {
                requestsToSend.push_back({pending->nextHopIp,
                                          pending->interfaceName,
                                          pending->sourceMac,
                                          pending->sourceIp});

                ++pending->requestsSent;
            }

            ++pending;
        }

        const std::array<std::uint8_t, 6> broadcast = {
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

        for (const ArpRequestToSend &request : requestsToSend)
        {
            const auto arpPayload = buildArpRequest(
                request.sourceMac,
                request.sourceIp,
                request.nextHopIp);

            const auto arpFrame = buildEthernetFrame(
                broadcast,
                request.sourceMac,
                0x0806,
                arpPayload);

            frameSender(request.interfaceName, arpFrame);
        }
    }

    // Os callbacks podem chamar sendOrQueue novamente: executar sem o mutex.
    for (const PendingResolution &failed : failedResolutions)
    {
        logArpFalhou(failed.nextHopIp, failed.interfaceName);

        for (const PendingPacket &packet : failed.packets)
        {
            const ipv4Header header = ipv4Interpreter(packet.ipv4Packet);
            if (header.valid)
            {
                logDescarte("arp", header.sourceIPAddr, header.destinationIPAddr, header.protocol);
            }
        }
        
        if (failureReporter)
        {
            failureReporter(failed.nextHopIp, failed.interfaceName, failed.packets.size());
        }

        if (!icmpErrorHandler)
        {
            continue;
        }

        for (const PendingPacket &packet : failed.packets)
        {
            if (packet.origin == PacketOrigin::Received && packet.context.has_value())
            {
                icmpErrorHandler(*packet.context);
            }
        }
    }
}

std::size_t ArpResolver::cacheSize()
{
    std::lock_guard<std::mutex> lock(pendingMutex);
    return cache.size();
}

std::size_t ArpResolver::pendingPacketsSize()
{
    std::lock_guard<std::mutex> lock(pendingMutex);
    std::size_t total = 0;
    for (const auto &entry : pendingResolutions)
    {
        total += entry.packets.size();
    }
    return total;
}