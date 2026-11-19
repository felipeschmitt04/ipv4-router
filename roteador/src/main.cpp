#include "../include/arp.hpp"
#include "../include/ethernet.hpp"
#include "../include/config.hpp"
#include "../include/interface.hpp"
#include "../include/arp_resolver.hpp"

#include <array>
#include <cassert>
#include <cstdint>
#include <vector>
#include <iostream>
#include <exception>
#include <thread>
#include <functional>
#include <chrono>

void handleArpFrame(
    EthernetInterface &ethernet,
    const interface &incomingInterface,
    const ReceivedFrame &receivedFrame,
    ArpResolver& arpResolver)
{
    constexpr std::size_t ethernetHeaderSize = 14;

    const auto ethernetHeader = parseEthernetHeader(receivedFrame);

    if (!ethernetHeader.has_value())
    {
        return;
    }

    if (!isFrameForInterface(*ethernetHeader, incomingInterface.mac))
    {
        return;
    }

    if (ethernetHeader->etherType != 0x0806)
    {
        return;
    }

    const std::vector<std::uint8_t> arpPayload(
        receivedFrame.data.begin() + ethernetHeaderSize,
        receivedFrame.data.end());

    const auto request = parseArpMessage(arpPayload);

    if (!request.has_value())
    {
        return;
    }

    if (request->targetIP == incomingInterface.interfaceIpAddr &&
        request->senderIP != 0)
    {
        arpResolver.learnFromArp(
            *request,
            incomingInterface,
            std::chrono::steady_clock::now());
    }

    if (!shouldReplyToArpRequest(
            *request,
            incomingInterface.interfaceIpAddr))
    {
        return;
    }

    const auto arpReply = buildArpReply(
        *request,
        incomingInterface.mac,
        incomingInterface.interfaceIpAddr);

    const auto replyFrame = buildEthernetFrame(
        request->senderMAC,
        incomingInterface.mac,
        0x0806,
        arpReply);

    ethernet.send(replyFrame);
}

void runInterface(interface incomingInterface, ArpResolver& arpResolver)
{
    EthernetInterface ethernet(incomingInterface.interfaceName);

    while (true)
    {
        const ReceivedFrame receivedFrame = ethernet.receive();

        handleArpFrame(
            ethernet,
            incomingInterface,
            receivedFrame,
            arpResolver);
    }
}

void runCacheExpiration(ArpResolver& arpResolver)
{
    while (true)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        const auto now = std::chrono::steady_clock::now();
        arpResolver.processTimeouts(now);
        arpResolver.removeExpired(now);
    }
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        std::cerr << "Uso: " << argv[0] << " ARQUIVO_DE_CONFIGURACAO\n";
        return 1;
    }

    loadConfig(argv[1]);

    ArpResolver arpResolver(
        [](const std::string &interfaceName,
           const std::vector<std::uint8_t> &frame)
        {
            EthernetInterface output(interfaceName);
            output.send(frame);
        });

    std::vector<std::thread> workers;

    for (const interface &configuredInterface : allInterfaces)
    {
        workers.emplace_back(runInterface, configuredInterface, std::ref(arpResolver));
    }

    workers.emplace_back(runCacheExpiration, std::ref(arpResolver));

    for (std::thread &worker : workers)
    {
        worker.join();
    }
}
