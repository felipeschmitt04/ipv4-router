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
#include <chrono>
#include <cstdint>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

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

void updateArpGauges(ArpResolver& arpResolver) {
    globalMetrics().setArpEntradas(arpResolver.cacheSize());
    globalMetrics().setArpPendentes(arpResolver.pendingPacketsSize());
}

void sendFrame(
    EthernetInterface& ethernet,
    const std::string& ifaceName,
    const std::vector<std::uint8_t>& frame) {
    std::lock_guard<std::mutex> lock(sendMutex);
    ethernet.send(frame);
    globalMetrics().incQuadrosEnviados(ifaceName);
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
    PacketOrigin origin) {
    const ArpPacketStatus st = arpResolver.sendOrQueue(
        nextHopIp,
        outIface,
        pkt,
        std::chrono::steady_clock::now(),
        origin);
    if (st == ArpPacketStatus::QueueFull) {
        globalMetrics().incDescartePorMotivo("fila_arp");
    }
    updateArpGauges(arpResolver);
}

void sendIcmpError(
    const std::vector<std::uint8_t>& originalPacket,
    std::uint8_t type,
    std::uint8_t code,
    bool ethBroadcast,
    const std::string& dropReason,
    ArpResolver& arpResolver,
    std::optional<std::uint32_t> overrideSrcIp = std::nullopt,
    bool fromMgmt = false) {
    const ipv4Header origHdr = ipv4Interpreter(originalPacket);
    if (!origHdr.valid) {
        return;
    }

    // O 3/1 ainda nao possui o contexto da interface de chegada.
    // A etapa seguinte preservara esse contexto na fila ARP.
    std::uint32_t srcIp = overrideSrcIp.value_or(0u);
    if (!overrideSrcIp.has_value()) {
        const forwardingResult fallback = forwarding(
            origHdr.sourceIPAddr, allInterfaces, routeTable);
        if (fallback.found) {
            const auto iface = findInterface(fallback.interfaceName);
            if (iface.has_value()) {
                srcIp = iface->interfaceIpAddr;
            }
        } else if (!allInterfaces.empty()) {
            srcIp = allInterfaces.front().interfaceIpAddr;
        }
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

    const auto now = std::chrono::steady_clock::now();
    if (request->targetIP == incomingInterface.interfaceIpAddr &&
        request->senderIP != 0) {
        arpResolver.learnFromArp(
            *request,
            incomingInterface,
            now);
        updateArpGauges(arpResolver);
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

        const std::vector<uint8_t> udpSeg(
            ipv4Packet.begin() + static_cast<ptrdiff_t>(ipHdrLen),
            ipv4Packet.begin() + static_cast<ptrdiff_t>(rawHdr.totalLength));

        const uint16_t udpLen = (static_cast<uint16_t>(udpSeg[4]) << 8) | udpSeg[5];
        const uint16_t udpCsum = (static_cast<uint16_t>(udpSeg[6]) << 8) | udpSeg[7];

        if (udpLen < 8u || udpLen != udpSeg.size()) {
            globalMetrics().incDescartesCabecalho();
            return;
        }

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

    if (receivedFrame.data.size() <= ethernetHeaderSize) {
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

    if (incomingInterface.interfaceName == "mgmt0") {
        std::vector<std::uint8_t> httpRespPacket;
        bool incHttp = false;
        if (handleMgmtMetricsUdpPacket(
                incomingInterface,
                ipv4Packet,
                httpRespPacket,
                incHttp)) {
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
                PacketOrigin::Received);
        }
    }
}

void runInterface(interface incomingInterface, ArpResolver& arpResolver) {
    EthernetInterface& ethernet =
        *ethernetInterfaces.at(incomingInterface.interfaceName);

    while (true) {
        const ReceivedFrame receivedFrame = ethernet.receive();
        globalMetrics().incQuadrosRecebidos(incomingInterface.interfaceName);

        const auto ethHeader = parseEthernetHeader(receivedFrame);
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
                receivedFrame,
                arpResolver);
        } else if (ethHeader->etherType == 0x0800) {
            handleIPv4Frame(
                incomingInterface,
                *ethHeader,
                receivedFrame,
                arpResolver);
        } else {
            globalMetrics().incDescartesQuadro();
        }
    }
}

void runCacheExpiration(ArpResolver& arpResolver) {
    while (true) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        const auto now = std::chrono::steady_clock::now();
        arpResolver.processTimeouts(now);
        arpResolver.removeExpired(now);
        updateArpGauges(arpResolver);
    }
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Uso: " << argv[0] << " ARQUIVO_DE_CONFIGURACAO\n";
        return 1;
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
        [&](const std::vector<std::uint8_t>& forwardedPacket) {
            std::vector<std::uint8_t> original = forwardedPacket;
            if (original.size() >= 20) {
                original[8] = static_cast<std::uint8_t>(original[8] + 1);
                const uint8_t ihl = original[0] & 0x0Fu;
                const uint16_t csum = calculateCheckSum(original, ihl);
                original[10] = static_cast<uint8_t>(csum >> 8);
                original[11] = static_cast<uint8_t>(csum & 0xFFu);
            }
            sendIcmpError(original, 3, 1, false, "arp", arpResolver);
        });

    std::vector<std::thread> workers;

    for (const interface& configuredInterface : allInterfaces) {
        workers.emplace_back(runInterface, configuredInterface, std::ref(arpResolver));
    }

    workers.emplace_back(runCacheExpiration, std::ref(arpResolver));

    for (std::thread& worker : workers) {
        worker.join();
    }
}
