#include "../include/arp.hpp"
#include "../include/ethernet.hpp"
#include "../include/config.hpp"
#include "../include/interface.hpp"

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
    ArpCache &arpCache)
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
        arpCache.learn(
            request->senderIP,
            request->senderMAC,
            incomingInterface.interfaceName,
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

void runInterface(interface incomingInterface, ArpCache &arpCache)
{
    EthernetInterface ethernet(incomingInterface.interfaceName);

    while (true)
    {
        const ReceivedFrame receivedFrame = ethernet.receive();

        handleArpFrame(
            ethernet,
            incomingInterface,
            receivedFrame,
            arpCache);
    }
}

void runCacheExpiration(ArpCache& arpCache){
    while(true){
        std::this_thread::sleep_for(std::chrono::seconds(1));
        arpCache.removeExpired(std::chrono::steady_clock::now());
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

    ArpCache arpCache;

    std::vector<std::thread> workers;

    for (const interface &configuredInterface : allInterfaces)
    {
        workers.emplace_back(runInterface, configuredInterface, std::ref(arpCache));
    }

    workers.emplace_back(runCacheExpiration, std::ref(arpCache));

    for (std::thread &worker : workers)
    {
        worker.join();
    }
}
