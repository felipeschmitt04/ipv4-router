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

int main()
{
    testResolvedNextHopUsesCachedMac();
    testMissingNextHopSendsOneBroadcastRequest();
    testLearningConcludesPendingResolution();

    std::cout << "Todos os testes do resolvedor ARP passaram.\n";
}
