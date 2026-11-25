#include "../include/arp.hpp"
#include "../include/arp_resolver.hpp"
#include "../include/config.hpp"
#include "../include/ethernet.hpp"
#include "../include/filter.hpp"
#include "../include/icmp.hpp"
#include "../include/interface.hpp"
#include "../include/ipv4.hpp"
#include "../include/logger.hpp"
#include "../include/metrics.hpp"
#include "../include/metrics_http.hpp"
#include "../include/roteador.hpp"
#include "../include/routing.hpp"

#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdint>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include <utility>
#include <pthread.h>
#include <signal.h>
#include <system_error>

namespace {

std::mutex sendMutex;

// Mantem um socket Ethernet persistente por interface.
std::unordered_map<std::string, std::unique_ptr<EthernetInterface>>
    ethernetInterfaces;

std::optional<interface> findInterface(const std::string& name) {
    for (const auto& iface : allInterfaces) {
        if (iface.interfaceName == name) {
            return iface;
        }
    }
    return std::nullopt;
}

std::optional<interface> findMgmtInterface() {
    return findInterface("mgmt0");
}

bool isBroadcastMac(const std::array<std::uint8_t, 6>& mac) {
    static constexpr std::array<std::uint8_t, 6> bcast{
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    return mac == bcast;
}

uint16_t udpChecksumCheck(
    uint32_t srcIp,
    uint32_t dstIp,
    const std::vector<uint8_t>& udpSegment) {
    uint32_t sum = 0;
    sum += (srcIp >> 16) & 0xFFFFu;
    sum += srcIp & 0xFFFFu;
    sum += (dstIp >> 16) & 0xFFFFu;
    sum += dstIp & 0xFFFFu;
    sum += 17u;
    sum += static_cast<uint32_t>(udpSegment.size());

    for (size_t i = 0; i < udpSegment.size(); i += 2) {
        uint8_t hi = udpSegment[i];
        uint8_t lo = (i + 1 < udpSegment.size()) ? udpSegment[i + 1] : 0u;
        sum += (static_cast<uint16_t>(hi) << 8) | static_cast<uint16_t>(lo);
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum) & 0xFFFFu;
}

// Conta a métrica e registra o descarte "local".
void recordLocalDiscard(
    std::uint32_t srcIp,
    std::uint32_t dstIp,
    std::uint8_t protocol,
    bool countMetric = true) {
    if (countMetric) {
        globalMetrics().incDescartePorMotivo("local");
    }
    logDescarte("local", srcIp, dstIp, protocol);
}

void sendFrame(
    EthernetInterface& ethernet,
    const std::string& ifaceName,
    const std::vector<std::uint8_t>& frame) {
    std::lock_guard<std::mutex> lock(sendMutex);
    if (ethernet.send(frame)) {
        globalMetrics().incQuadrosEnviados(ifaceName);
    }
}

void sendFrameByName(
    const std::string& ifaceName,
    const std::vector<std::uint8_t>& frame) {
    sendFrame(*ethernetInterfaces.at(ifaceName), ifaceName, frame);
}

void dispatchQueuedPacket(
    ArpResolver& arpResolver,
    std::uint32_t nextHopIp,
    const interface& outIface,
    const std::vector<std::uint8_t>& pkt,
    PacketOrigin origin,
    std::optional<ReceivedPacketContext> context = std::nullopt) {
    const ArpPacketStatus st = arpResolver.sendOrQueue(
        nextHopIp,
        outIface,
        pkt,
        std::nullopt,
        origin,
        std::move(context));
    if (st == ArpPacketStatus::QueueFull) {
        globalMetrics().incDescartePorMotivo("fila_arp");
    }
}

void sendIcmpError(
    const std::vector<std::uint8_t>& originalPacket,
    std::uint8_t type,
    std::uint8_t code,
    bool ethBroadcast,
    const std::string& dropReason,
    ArpResolver& arpResolver,
    std::uint32_t srcIp,
    bool fromMgmt = false) {
    const ipv4Header origHdr = ipv4Interpreter(originalPacket);
    if (!origHdr.valid) {
        return;
    }

    const auto icmpPkt = buildICMPError(
        originalPacket, type, code, srcIp, ethBroadcast, dropReason);
    if (icmpPkt.empty()) {
        return;
    }

    globalMetrics().incIcmpGerados();

    if (fromMgmt) {
        const auto mgmtIface = findMgmtInterface();
        if (mgmtIface.has_value()) {
            dispatchQueuedPacket(
                arpResolver, origHdr.sourceIPAddr, *mgmtIface,
                icmpPkt, PacketOrigin::Generated);
        }
        return;
    }

    const forwardingResult route = forwarding(
        origHdr.sourceIPAddr, allInterfaces, routeTable);
    if (!route.found) {
        globalMetrics().incDescartePorMotivo("sem_rota");
        logDescarte("sem_rota", srcIp, origHdr.sourceIPAddr, 1);
        return;
    }

    const auto outIface = findInterface(route.interfaceName);
    if (outIface.has_value()) {
        dispatchQueuedPacket(
            arpResolver, route.nextHop, *outIface,
            icmpPkt, PacketOrigin::Generated);
    }
}

void handleArpFrame(
    EthernetInterface& ethernet,
    const interface& incomingInterface,
    const ReceivedFrame& receivedFrame,
    ArpResolver& arpResolver) {
    constexpr std::size_t ethernetHeaderSize = 14;

    if (receivedFrame.data.size() < ethernetHeaderSize + 28) {
        globalMetrics().incDescartesQuadro();
        return;
    }

    const std::vector<std::uint8_t> arpPayload(
        receivedFrame.data.begin() + ethernetHeaderSize,
        receivedFrame.data.end());

    const auto request = parseArpMessage(arpPayload);
    if (!request.has_value()) {
        globalMetrics().incDescartesQuadro();
        return;
    }

    if (request->targetIP == incomingInterface.interfaceIpAddr &&
        request->senderIP != 0) {
        arpResolver.learnFromArp(
            *request,
            incomingInterface);
    }

    if (!shouldReplyToArpRequest(
            *request,
            incomingInterface.interfaceIpAddr)) {
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

    sendFrame(ethernet, incomingInterface.interfaceName, replyFrame);
}

void handleLocalPacket(
    const interface& incomingInterface,
    const std::vector<std::uint8_t>& ipv4Packet,
    const ipv4Header& rawHdr,
    bool ethBroadcast,
    ArpResolver& arpResolver) {
    const auto mgmtIface = findMgmtInterface();
    const bool isMgmtIp = mgmtIface.has_value() &&
        rawHdr.destinationIPAddr == mgmtIface->interfaceIpAddr;

    const bool crossesMgmtBoundary =
        (incomingInterface.interfaceName == "mgmt0") != isMgmtIp;

    if (rawHdr.protocol == 1) {
        const size_t ipHdrLen = static_cast<size_t>(rawHdr.IHL) * 4u;
        if (rawHdr.totalLength < ipHdrLen + 8u || ipv4Packet.size() < rawHdr.totalLength) {
            globalMetrics().incDescartesCabecalho();
            return;
        }

        const std::uint8_t icmpType = ipv4Packet[ipHdrLen];
        const std::uint8_t icmpCode = ipv4Packet[ipHdrLen + 1u];

        const ICMPInterpreterResult icmp = icmpInterpreter(ipv4Packet);
        if (icmpType == 8 && icmpCode == 0 && !icmp.valid) {
            globalMetrics().incDescartesCabecalho();
            return;
        }

        if (crossesMgmtBoundary) {
            recordLocalDiscard(rawHdr.sourceIPAddr, rawHdr.destinationIPAddr, rawHdr.protocol, true);
            return;
        }

        if (icmp.valid && icmp.type == 8 && icmp.code == 0) {
            const std::vector<std::uint8_t> echoReply = buildICMPEchoReply(ipv4Packet);
            if (!echoReply.empty()) {
                globalMetrics().incIcmpGerados();
                if (incomingInterface.interfaceName == "mgmt0" &&
                    rawHdr.destinationIPAddr == incomingInterface.interfaceIpAddr) {
                    dispatchQueuedPacket(
                        arpResolver,
                        rawHdr.sourceIPAddr,
                        incomingInterface,
                        echoReply,
                        PacketOrigin::Generated);
                    return;
                }

                const forwardingResult route = forwarding(
                    rawHdr.sourceIPAddr,
                    allInterfaces,
                    routeTable);
                if (route.found) {
                    const auto outIface = findInterface(route.interfaceName);
                    if (outIface.has_value()) {
                        dispatchQueuedPacket(
                            arpResolver,
                            route.nextHop,
                            *outIface,
                            echoReply,
                            PacketOrigin::Generated);
                        return;
                    }
                } else {
                    // Resposta gerada, mas sem rota para enviá-la.
                    globalMetrics().incDescartePorMotivo("sem_rota");
                    logDescarte("sem_rota", rawHdr.destinationIPAddr, rawHdr.sourceIPAddr, 1);
                    return;
                }
            }
        }

        recordLocalDiscard(rawHdr.sourceIPAddr, rawHdr.destinationIPAddr, rawHdr.protocol, true);
        return;
    }

    if (rawHdr.protocol == 17) {
        const size_t ipHdrLen = static_cast<size_t>(rawHdr.IHL) * 4u;
        if (rawHdr.totalLength < ipHdrLen + 8u || ipv4Packet.size() < rawHdr.totalLength) {
            globalMetrics().incDescartesCabecalho();
            return;
        }

        std::vector<uint8_t> udpSeg(
            ipv4Packet.begin() + static_cast<ptrdiff_t>(ipHdrLen),
            ipv4Packet.begin() + static_cast<ptrdiff_t>(rawHdr.totalLength));

        const uint16_t udpLen = (static_cast<uint16_t>(udpSeg[4]) << 8) | udpSeg[5];
        const uint16_t udpCsum = (static_cast<uint16_t>(udpSeg[6]) << 8) | udpSeg[7];

        if (udpLen < 8u || udpLen > udpSeg.size()) {
            globalMetrics().incDescartesCabecalho();
            return;
        }

        // Considera apenas os bytes declarados no cabecalho UDP.
        udpSeg.resize(udpLen);

        if (udpCsum != 0u &&
            udpChecksumCheck(rawHdr.sourceIPAddr, rawHdr.destinationIPAddr, udpSeg) != 0u) {
            globalMetrics().incDescartesCabecalho();
            return;
        }

        if (crossesMgmtBoundary) {
            recordLocalDiscard(rawHdr.sourceIPAddr, rawHdr.destinationIPAddr, rawHdr.protocol, true);
            return;
        }

        recordLocalDiscard(rawHdr.sourceIPAddr, rawHdr.destinationIPAddr, rawHdr.protocol, true);
        sendIcmpError(
            ipv4Packet,
            3,
            3,
            ethBroadcast,
            "local",
            arpResolver,
            rawHdr.destinationIPAddr,
            incomingInterface.interfaceName == "mgmt0");
        return;
    }

    recordLocalDiscard(rawHdr.sourceIPAddr, rawHdr.destinationIPAddr, rawHdr.protocol, true);
}

void handleIPv4Frame(
    const interface& incomingInterface,
    const EthernetHeader& ethHeader,
    const ReceivedFrame& receivedFrame,
    ArpResolver& arpResolver) {
    constexpr std::size_t ethernetHeaderSize = 14;

    if (receivedFrame.data.size() < ethernetHeaderSize) {
        globalMetrics().incDescartesQuadro();
        return;
    }

    std::vector<std::uint8_t> ipv4Packet(
        receivedFrame.data.begin() + ethernetHeaderSize,
        receivedFrame.data.end());

    const ipv4Header rawHdr = ipv4Interpreter(ipv4Packet);
    if (!rawHdr.valid) {
        globalMetrics().incDescartesCabecalho();
        return;
    }

    if (ipv4Packet.size() > rawHdr.totalLength) {
        ipv4Packet.resize(rawHdr.totalLength);
    }

    const bool ethBroadcast = isBroadcastMac(ethHeader.destination);
    const bool fragmented = rawHdr.fragmentOffset != 0 || (rawHdr.flag & 0x01u) != 0;

    if (!fragmented && incomingInterface.interfaceName == "mgmt0") {
        std::vector<std::uint8_t> httpRespPacket;
        bool incHttp = false;
        if (handleMgmtMetricsUdpPacket(
                incomingInterface,
                ipv4Packet,
                httpRespPacket,
                incHttp,
                arpResolver)) {
            if (!httpRespPacket.empty()) {
                if (incHttp) {
                    globalMetrics().incRespostasHttp();
                }
                dispatchQueuedPacket(
                    arpResolver,
                    rawHdr.sourceIPAddr,
                    incomingInterface,
                    httpRespPacket,
                    PacketOrigin::Generated);
            }
            return;
        }
    }

    const std::vector<std::uint8_t> originalPacket = ipv4Packet;

    const IPv4Result res = processIPv4(
        ipv4Packet,
        incomingInterface.interfaceName,
        evaluateIPv4FilterIndexed);

    if (res.action == IPv4Action::Local) {
        if (fragmented) {
            recordLocalDiscard(rawHdr.sourceIPAddr, rawHdr.destinationIPAddr, rawHdr.protocol);
            return;
        }
        handleLocalPacket(
            incomingInterface,
            originalPacket,
            rawHdr,
            ethBroadcast,
            arpResolver);
        return;
    }

    if (res.action == IPv4Action::Drop) {
        // O log do descarte (local/filtro) já foi emitido dentro de processIPv4;
        // aqui só contamos a métrica.
        globalMetrics().incDescartePorMotivo(res.dropReason);
        return;
    }

    if (res.action == IPv4Action::TTLExpired) {
        globalMetrics().incDescartePorMotivo("ttl");
        sendIcmpError(originalPacket, 11, 0, ethBroadcast, "ttl", arpResolver,
                      incomingInterface.interfaceIpAddr);
        return;
    }

    if (res.action == IPv4Action::NoRoute) {
        globalMetrics().incDescartePorMotivo("sem_rota");
        sendIcmpError(originalPacket, 3, 0, ethBroadcast, "sem_rota", arpResolver,
                      incomingInterface.interfaceIpAddr);
        return;
    }

    if (res.action == IPv4Action::Forward) {
        globalMetrics().incPacotesEncaminhados();
        const auto outIface = findInterface(res.outputInterface);
        if (outIface.has_value()) {
            dispatchQueuedPacket(
                arpResolver,
                res.nextHop,
                *outIface,
                ipv4Packet,
                PacketOrigin::Received,
                ReceivedPacketContext{originalPacket, incomingInterface.interfaceIpAddr, ethBroadcast});
        }
    }
}

void runInterface(const interface& incomingInterface, ArpResolver& arpResolver,
                  const std::atomic<bool>& stopping) {
    EthernetInterface& ethernet =
        *ethernetInterfaces.at(incomingInterface.interfaceName);

    while (!stopping.load()) {
        const auto receivedFrame = ethernet.receive();
        if (!receivedFrame || stopping.load()) {
            continue;
        }
        globalMetrics().incQuadrosRecebidos(incomingInterface.interfaceName);

        const auto ethHeader = parseEthernetHeader(*receivedFrame);
        if (!ethHeader.has_value()) {
            globalMetrics().incDescartesQuadro();
            continue;
        }

        if (!isFrameForInterface(*ethHeader, incomingInterface.mac)) {
            globalMetrics().incDescartesQuadro();
            continue;
        }

        if (ethHeader->etherType == 0x0806) {
            handleArpFrame(
                ethernet,
                incomingInterface,
                *receivedFrame,
                arpResolver);
        } else if (ethHeader->etherType == 0x0800) {
            handleIPv4Frame(
                incomingInterface,
                *ethHeader,
                *receivedFrame,
                arpResolver);
        } else {
            globalMetrics().incDescartesQuadro();
        }
    }
}

void runCacheExpiration(ArpResolver& arpResolver, const std::atomic<bool>& stopping) {
    while (!stopping.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (stopping.load()) {
            break;
        }
        arpResolver.processTimeouts();
        arpResolver.removeExpired(std::chrono::steady_clock::now());
    }
}

} // namespace

int main(int argc, char* argv[]) try {
    if (argc != 2) {
        std::cerr << "Uso: " << argv[0] << " ARQUIVO_DE_CONFIGURACAO\n";
        return 1;
    }

    // As threads herdam a mascara. Somente a thread principal recebe SIGTERM.
    sigset_t terminationSignals;
    sigemptyset(&terminationSignals);
    sigaddset(&terminationSignals, SIGTERM);
    const int maskError = pthread_sigmask(SIG_BLOCK, &terminationSignals, nullptr);
    if (maskError != 0) {
        throw std::system_error(maskError, std::generic_category(), "pthread_sigmask");
    }

    loadConfig(argv[1]);

    // Cria os sockets Ethernet antes de iniciar as threads.
    for (const interface& configuredInterface : allInterfaces) {
        ethernetInterfaces.emplace(
            configuredInterface.interfaceName,
            std::make_unique<EthernetInterface>(
                configuredInterface.interfaceName));
    }

    logInicio(routerName);

    ArpResolver arpResolver(
        [](const std::string& interfaceName,
           const std::vector<std::uint8_t>& frame) {
            sendFrameByName(interfaceName, frame);
        },
        [](std::uint32_t, const std::string&, std::size_t droppedPacketsCount) {
            for (std::size_t i = 0; i < droppedPacketsCount; ++i) {
                globalMetrics().incDescartePorMotivo("arp");
            }
        },
        [&](const ReceivedPacketContext& context) {
            sendIcmpError(context.originalPacket, 3, 1, context.ethBroadcast,
                          "arp", arpResolver, context.incomingIp);
        });

    std::atomic<bool> stopping{false};
    std::atomic<bool> failed{false};
    const auto fail = [&](const char* reason) {
        stopping.store(true);
        if (!failed.exchange(true)) {
            std::fprintf(stderr, "Erro fatal do roteador: %s\n", reason);
        }
    };

    const auto runWorker = [&](auto work) {
        try {
            work();
        } catch (const std::exception& error) {
            fail(error.what());
        } catch (...) {
            fail("excecao desconhecida na thread");
        }
    };

    std::vector<std::thread> workers;
    try {
        for (const interface& configuredInterface : allInterfaces) {
            workers.emplace_back(runWorker, [&, iface = &configuredInterface] {
                runInterface(*iface, arpResolver, stopping);
            });
        }
        workers.emplace_back(runWorker, [&] {
            runCacheExpiration(arpResolver, stopping);
        });
    } catch (const std::exception& error) {
        fail(error.what());
    }

    while (!stopping.load()) {
        const timespec wait{0, 100000000};
        if (sigtimedwait(&terminationSignals, nullptr, &wait) == SIGTERM) {
            stopping.store(true);
        } else {
            const int error = errno;
            if (error != EAGAIN && error != EINTR) {
                fail("falha em sigtimedwait");
            }
        }
    }

    for (std::thread& worker : workers) {
        worker.join();
    }
    return failed.load() ? 1 : 0;
} catch (const std::exception& error) {
    std::fprintf(stderr, "Erro fatal do roteador: %s\n", error.what());
    return 1;
}
