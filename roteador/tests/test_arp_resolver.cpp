#include "../include/arp_resolver.hpp"

#include <cassert>
#include <iostream>
#include <vector>

void testResolvedNextHopUsesCachedMac()
{
    std::vector<std::string> sentInterfaces;
    std::vector<std::vector<std::uint8_t>> sentFrames;

    ArpResolver resolver(
        [&](const std::string &interfaceName,
            const std::vector<std::uint8_t> &frame)
        {
            sentInterfaces.push_back(interfaceName);
            sentFrames.push_back(frame);
        });

    const interface outputInterface{
        0x0A000101,
        24,
        "eth0",
        {0x02, 0x00, 0x00, 0x00, 0x01, 0x00}};
    const auto now = std::chrono::steady_clock::time_point{};

    ArpMessage message{};
    message.senderIP = 0x0A000102;
    message.senderMAC = {0x02, 0x00, 0x00, 0x00, 0x01, 0x02};
    message.targetIP = outputInterface.interfaceIpAddr;

    resolver.learnFromArp(message, outputInterface, now);

    const auto result = resolver.resolve(
        message.senderIP,
        outputInterface,
        now);

    assert(result.status == ArpResolutionStatus::Resolved);
    assert(result.mac.has_value());
    assert(*result.mac == message.senderMAC);
    assert(sentInterfaces.empty());
    assert(sentFrames.empty());
}

void testMissingNextHopSendsOneBroadcastRequest()
{
    std::vector<std::string> sentInterfaces;
    std::vector<std::vector<std::uint8_t>> sentFrames;

    ArpResolver resolver(
        [&](const std::string &interfaceName,
            const std::vector<std::uint8_t> &frame)
        {
            sentInterfaces.push_back(interfaceName);
            sentFrames.push_back(frame);
        });

    const interface outputInterface{
        0x0A000101,
        24,
        "eth0",
        {0x02, 0x00, 0x00, 0x00, 0x01, 0x00}};
    const auto now = std::chrono::steady_clock::time_point{};
    constexpr std::uint32_t nextHopIp = 0x0A000102;

    const auto firstResult = resolver.resolve(nextHopIp, outputInterface, now);

    assert(firstResult.status == ArpResolutionStatus::Pending);
    assert(!firstResult.mac.has_value());
    assert(sentInterfaces.size() == 1);
    assert(sentInterfaces[0] == "eth0");
    assert(sentFrames.size() == 1);

    const auto &frame = sentFrames[0];
    assert(frame.size() >= 42);
    for (std::size_t index = 0; index < 6; ++index)
    {
        assert(frame[index] == 0xff);
        assert(frame[6 + index] == outputInterface.mac[index]);
    }
    assert(frame[12] == 0x08 && frame[13] == 0x06);
    assert(frame[20] == 0x00 && frame[21] == 0x01);
    assert(frame[38] == 10);
    assert(frame[39] == 0);
    assert(frame[40] == 1);
    assert(frame[41] == 2);

    const auto secondResult = resolver.resolve(nextHopIp, outputInterface, now);
    assert(secondResult.status == ArpResolutionStatus::Pending);
    assert(sentFrames.size() == 1);
}

void testLearningConcludesPendingResolution()
{
    std::vector<std::vector<std::uint8_t>> sentFrames;
    ArpResolver resolver(
        [&](const std::string &, const std::vector<std::uint8_t> &frame)
        {
            sentFrames.push_back(frame);
        });

    const interface outputInterface{
        0x0A000101,
        24,
        "eth0",
        {0x02, 0x00, 0x00, 0x00, 0x01, 0x00}};
    const auto start = std::chrono::steady_clock::time_point{};
    constexpr std::uint32_t nextHopIp = 0x0A000102;

    resolver.resolve(nextHopIp, outputInterface, start);
    assert(sentFrames.size() == 1);

    ArpMessage reply{};
    reply.senderIP = nextHopIp;
    reply.senderMAC = {0x02, 0x00, 0x00, 0x00, 0x01, 0x02};
    reply.targetIP = outputInterface.interfaceIpAddr;
    resolver.learnFromArp(reply, outputInterface, start + std::chrono::seconds(1));

    const auto resolved = resolver.resolve(
        nextHopIp,
        outputInterface,
        start + std::chrono::seconds(1));
    assert(resolved.status == ArpResolutionStatus::Resolved);
    assert(resolved.mac.has_value());
    assert(*resolved.mac == reply.senderMAC);

    resolver.resolve(
        nextHopIp,
        outputInterface,
        start + std::chrono::seconds(31));
    assert(sentFrames.size() == 2);
}

void testQueuedPacketsAreReleasedInArrivalOrder()
{
    std::vector<std::vector<std::uint8_t>> sentFrames;
    ArpResolver resolver(
        [&](const std::string &, const std::vector<std::uint8_t> &frame)
        {
            sentFrames.push_back(frame);
        });

    const interface outputInterface{
        0x0A000101,
        24,
        "eth0",
        {0x02, 0x00, 0x00, 0x00, 0x01, 0x00}};
    const auto now = std::chrono::steady_clock::time_point{};
    constexpr std::uint32_t nextHopIp = 0x0A000102;
    const std::vector<std::uint8_t> firstPacket = {0x45, 0x01, 0xa1};
    const std::vector<std::uint8_t> secondPacket = {0x45, 0x02, 0xb2};

    assert(resolver.sendOrQueue(nextHopIp, outputInterface, firstPacket, now) ==
           ArpPacketStatus::Queued);
    assert(resolver.sendOrQueue(nextHopIp, outputInterface, secondPacket, now) ==
           ArpPacketStatus::Queued);
    assert(sentFrames.size() == 1);

    ArpMessage reply{};
    reply.senderIP = nextHopIp;
    reply.senderMAC = {0x02, 0x00, 0x00, 0x00, 0x01, 0x02};
    reply.targetIP = outputInterface.interfaceIpAddr;
    resolver.learnFromArp(reply, outputInterface, now);

    assert(sentFrames.size() == 3);
    for (std::size_t index = 0; index < 6; ++index)
    {
        assert(sentFrames[1][index] == reply.senderMAC[index]);
        assert(sentFrames[1][6 + index] == outputInterface.mac[index]);
    }
    assert(sentFrames[1][12] == 0x08 && sentFrames[1][13] == 0x00);
    assert(sentFrames[1][14] == firstPacket[0]);
    assert(sentFrames[1][15] == firstPacket[1]);
    assert(sentFrames[1][16] == firstPacket[2]);
    assert(sentFrames[2][14] == secondPacket[0]);
    assert(sentFrames[2][15] == secondPacket[1]);
    assert(sentFrames[2][16] == secondPacket[2]);
}

void testCachedMacSendsIpv4Immediately()
{
    std::vector<std::vector<std::uint8_t>> sentFrames;
    ArpResolver resolver(
        [&](const std::string &, const std::vector<std::uint8_t> &frame)
        {
            sentFrames.push_back(frame);
        });

    const interface outputInterface{
        0x0A000101,
        24,
        "eth0",
        {0x02, 0x00, 0x00, 0x00, 0x01, 0x00}};
    const auto now = std::chrono::steady_clock::time_point{};
    constexpr std::uint32_t nextHopIp = 0x0A000102;
    const std::array<std::uint8_t, 6> nextHopMac = {
        0x02, 0x00, 0x00, 0x00, 0x01, 0x02};

    ArpMessage reply{};
    reply.senderIP = nextHopIp;
    reply.senderMAC = nextHopMac;
    reply.targetIP = outputInterface.interfaceIpAddr;
    resolver.learnFromArp(reply, outputInterface, now);

    assert(resolver.sendOrQueue(
               nextHopIp,
               outputInterface,
               {0x45, 0xaa},
               now) == ArpPacketStatus::Sent);
    assert(sentFrames.size() == 1);
    assert(sentFrames[0][0] == nextHopMac[0]);
    assert(sentFrames[0][12] == 0x08 && sentFrames[0][13] == 0x00);
    assert(sentFrames[0][14] == 0x45 && sentFrames[0][15] == 0xaa);
}

void testQueueRejectsSeventeenthPacket()
{
    std::vector<std::vector<std::uint8_t>> sentFrames;
    ArpResolver resolver(
        [&](const std::string &, const std::vector<std::uint8_t> &frame)
        {
            sentFrames.push_back(frame);
        });

    const interface outputInterface{
        0x0A000101,
        24,
        "eth0",
        {0x02, 0x00, 0x00, 0x00, 0x01, 0x00}};
    const auto now = std::chrono::steady_clock::time_point{};
    constexpr std::uint32_t nextHopIp = 0x0A000102;

    for (std::uint8_t index = 0; index < 16; ++index)
    {
        assert(resolver.sendOrQueue(
                   nextHopIp,
                   outputInterface,
                   {0x45, index},
                   now) == ArpPacketStatus::Queued);
    }

    assert(resolver.sendOrQueue(
               nextHopIp,
               outputInterface,
               {0x45, 0xff},
               now) == ArpPacketStatus::QueueFull);
    assert(sentFrames.size() == 1);

    ArpMessage reply{};
    reply.senderIP = nextHopIp;
    reply.senderMAC = {0x02, 0x00, 0x00, 0x00, 0x01, 0x02};
    reply.targetIP = outputInterface.interfaceIpAddr;
    resolver.learnFromArp(reply, outputInterface, now);

    assert(sentFrames.size() == 17);
    for (std::uint8_t index = 0; index < 16; ++index)
    {
        assert(sentFrames[index + 1][15] == index);
    }
}

void testArpRequestsAreRetransmittedAtOneAndTwoSeconds()
{
    std::vector<std::vector<std::uint8_t>> sentFrames;
    ArpResolver resolver(
        [&](const std::string &, const std::vector<std::uint8_t> &frame)
        {
            sentFrames.push_back(frame);
        });

    const interface outputInterface{
        0x0A000101,
        24,
        "eth0",
        {0x02, 0x00, 0x00, 0x00, 0x01, 0x00}};
    const auto start = std::chrono::steady_clock::time_point{};
    constexpr std::uint32_t nextHopIp = 0x0A000102;

    resolver.sendOrQueue(nextHopIp, outputInterface, {0x45}, start);
    assert(sentFrames.size() == 1);

    resolver.processTimeouts(start + std::chrono::milliseconds(999));
    assert(sentFrames.size() == 1);

    resolver.processTimeouts(start + std::chrono::seconds(1));
    assert(sentFrames.size() == 2);

    resolver.processTimeouts(start + std::chrono::seconds(1));
    assert(sentFrames.size() == 2);

    resolver.processTimeouts(start + std::chrono::seconds(2));
    assert(sentFrames.size() == 3);

    for (const auto &frame : sentFrames)
    {
        assert(frame[12] == 0x08 && frame[13] == 0x06);
        assert(frame[20] == 0x00 && frame[21] == 0x01);
        assert(frame[38] == 10);
        assert(frame[39] == 0);
        assert(frame[40] == 1);
        assert(frame[41] == 2);
    }
}

void testTimeoutReportsFailureAndNotifiesOnlyReceivedPackets()
{
    std::vector<std::vector<std::uint8_t>> sentFrames;
    std::vector<std::pair<std::uint32_t, std::string>> reportedFailures;
    std::vector<std::vector<std::uint8_t>> icmpOriginalPackets;
    ArpResolver resolver(
        [&](const std::string &, const std::vector<std::uint8_t> &frame)
        {
            sentFrames.push_back(frame);
        },
        [&](std::uint32_t nextHopIp, const std::string &interfaceName)
        {
            reportedFailures.push_back({nextHopIp, interfaceName});
        },
        [&](const std::vector<std::uint8_t> &originalPacket)
        {
            icmpOriginalPackets.push_back(originalPacket);
        });

    const interface outputInterface{
        0x0A000101,
        24,
        "eth0",
        {0x02, 0x00, 0x00, 0x00, 0x01, 0x00}};
    const auto start = std::chrono::steady_clock::time_point{};
    constexpr std::uint32_t nextHopIp = 0x0A000102;
    const std::vector<std::uint8_t> receivedPacket = {0x45, 0x01};
    const std::vector<std::uint8_t> generatedPacket = {0x45, 0x02};

    resolver.sendOrQueue(nextHopIp, outputInterface, receivedPacket, start);
    resolver.sendOrQueue(
        nextHopIp,
        outputInterface,
        generatedPacket,
        start,
        PacketOrigin::Generated);

    resolver.processTimeouts(start + std::chrono::seconds(1));
    resolver.processTimeouts(start + std::chrono::seconds(2));
    assert(sentFrames.size() == 3);

    resolver.processTimeouts(start + std::chrono::seconds(3));
    assert(sentFrames.size() == 3);
    assert(reportedFailures.size() == 1);
    assert(reportedFailures[0].first == nextHopIp);
    assert(reportedFailures[0].second == "eth0");
    assert(icmpOriginalPackets.size() == 1);
    assert(icmpOriginalPackets[0] == receivedPacket);

    resolver.processTimeouts(start + std::chrono::seconds(4));
    assert(reportedFailures.size() == 1);
    assert(icmpOriginalPackets.size() == 1);

    assert(resolver.sendOrQueue(
               nextHopIp,
               outputInterface,
               receivedPacket,
               start + std::chrono::seconds(4)) == ArpPacketStatus::Queued);
    assert(sentFrames.size() == 4);
}

int main()
{
    testResolvedNextHopUsesCachedMac();
    testMissingNextHopSendsOneBroadcastRequest();
    testLearningConcludesPendingResolution();
    testQueuedPacketsAreReleasedInArrivalOrder();
    testCachedMacSendsIpv4Immediately();
    testQueueRejectsSeventeenthPacket();
    testArpRequestsAreRetransmittedAtOneAndTwoSeconds();
    testTimeoutReportsFailureAndNotifiesOnlyReceivedPackets();

    std::cout << "Todos os testes do resolvedor ARP passaram.\n";
}
