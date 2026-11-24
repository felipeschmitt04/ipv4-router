#include "../include/arp_resolver.hpp"
#include "../include/interface.hpp"
#include "../include/ipv4.hpp"
#include "../include/metrics.hpp"
#include "../include/metrics_http.hpp"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace {

uint16_t udpChecksum(
    uint32_t srcIp,
    uint32_t dstIp,
    const std::vector<uint8_t>& udpSegment
) {
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

    uint16_t csum = static_cast<uint16_t>(~sum) & 0xFFFFu;
    return (csum == 0u) ? 0xFFFFu : csum;
}

std::vector<uint8_t> makeIpv4UdpPacket(
    uint32_t srcIp,
    uint32_t dstIp,
    uint16_t srcPort,
    uint16_t dstPort,
    const std::string& payload,
    bool corruptChecksum = false
) {
    const uint16_t udpLen = static_cast<uint16_t>(8u + payload.size());
    const uint16_t ipLen = static_cast<uint16_t>(20u + udpLen);

    std::vector<uint8_t> udp(udpLen, 0u);
    udp[0] = static_cast<uint8_t>(srcPort >> 8);
    udp[1] = static_cast<uint8_t>(srcPort & 0xFFu);
    udp[2] = static_cast<uint8_t>(dstPort >> 8);
    udp[3] = static_cast<uint8_t>(dstPort & 0xFFu);
    udp[4] = static_cast<uint8_t>(udpLen >> 8);
    udp[5] = static_cast<uint8_t>(udpLen & 0xFFu);

    for (size_t i = 0; i < payload.size(); ++i) {
        udp[8u + i] = static_cast<uint8_t>(payload[i]);
    }

    uint16_t csum = udpChecksum(srcIp, dstIp, udp);
    if (corruptChecksum) {
        csum ^= 0x0001u;
    }
    udp[6] = static_cast<uint8_t>(csum >> 8);
    udp[7] = static_cast<uint8_t>(csum & 0xFFu);

    std::vector<uint8_t> pkt(ipLen, 0u);
    pkt[0] = 0x45u;
    pkt[2] = static_cast<uint8_t>(ipLen >> 8);
    pkt[3] = static_cast<uint8_t>(ipLen & 0xFFu);
    pkt[8] = 64u;
    pkt[9] = 17u;

    pkt[12] = static_cast<uint8_t>(srcIp >> 24);
    pkt[13] = static_cast<uint8_t>((srcIp >> 16) & 0xFFu);
    pkt[14] = static_cast<uint8_t>((srcIp >> 8) & 0xFFu);
    pkt[15] = static_cast<uint8_t>(srcIp & 0xFFu);

    pkt[16] = static_cast<uint8_t>(dstIp >> 24);
    pkt[17] = static_cast<uint8_t>((dstIp >> 16) & 0xFFu);
    pkt[18] = static_cast<uint8_t>((dstIp >> 8) & 0xFFu);
    pkt[19] = static_cast<uint8_t>(dstIp & 0xFFu);

    const uint16_t ipCsum = calculateCheckSum(pkt, 5u);
    pkt[10] = static_cast<uint8_t>(ipCsum >> 8);
    pkt[11] = static_cast<uint8_t>(ipCsum & 0xFFu);

    for (size_t i = 0; i < udp.size(); ++i) {
        pkt[20u + i] = udp[i];
    }

    return pkt;
}

std::string extractUdpPayload(const std::vector<uint8_t>& ipv4Pkt) {
    assert(ipv4Pkt.size() >= 28u);
    return std::string(ipv4Pkt.begin() + 28, ipv4Pkt.end());
}

} // namespace

int main() {
    const uint32_t mgmtIp = (10u << 24) | (0u << 16) | (0u << 8) | 1u;   // 10.0.0.1
    const uint32_t clientIp = (10u << 24) | (0u << 16) | (0u << 8) | 2u; // 10.0.0.2

    interface mgmtIface{};
    mgmtIface.interfaceName = "mgmt0";
    mgmtIface.interfaceIpAddr = mgmtIp;
    mgmtIface.prefixLength = 24;
    mgmtIface.mac = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};

    ArpResolver arpResolver([](const auto&, const auto&) {});
    const auto now = std::chrono::steady_clock::time_point{};
    ArpMessage reply{};
    reply.operation = 2;
    reply.senderIP = clientIp;
    reply.senderMAC = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
    reply.targetIP = mgmtIp;
    arpResolver.learnFromArp(reply, mgmtIface, now);

    globalMetrics().incPacotesEncaminhados(7);

    // 1. GET /metrics HTTP/1.1 -> 200 OK
    {
        const auto req = makeIpv4UdpPacket(clientIp, mgmtIp, 45123, 9100, "GET /metrics HTTP/1.1\r\nHost: mgmt0\r\n\r\n");
        const auto unresolvedIp = clientIp + 1;
        const auto pendingPacket = makeIpv4UdpPacket(mgmtIp, unresolvedIp, 9100, 45123, "");
        assert(arpResolver.sendOrQueue(unresolvedIp, mgmtIface, pendingPacket, now) == ArpPacketStatus::Queued);
        assert(arpResolver.sendOrQueue(unresolvedIp, mgmtIface, pendingPacket, now) == ArpPacketStatus::Queued);
        std::vector<uint8_t> resp;
        bool incHttp = false;
        const bool handled = handleMgmtMetricsUdpPacket(mgmtIface, req, resp, incHttp, arpResolver);
        assert(handled);
        assert(incHttp);
        assert(!resp.empty());

        const std::string raw = extractUdpPayload(resp);
        assert(raw.find("HTTP/1.1 200 OK\r\n") == 0);
        assert(raw.find("Content-Type: text/plain; version=0.0.4\r\n") != std::string::npos);
        assert(raw.find("pacotes_encaminhados 7\n") != std::string::npos);
        assert(raw.find("# TYPE arp_entradas gauge\narp_entradas 1\n") != std::string::npos);
        assert(raw.find("# TYPE arp_pendentes gauge\narp_pendentes 2\n") != std::string::npos);
    }

    // 2. GET /outro HTTP/1.1 -> 404 Not Found
    {
        const auto req = makeIpv4UdpPacket(clientIp, mgmtIp, 45124, 9100, "GET /outro HTTP/1.1\r\n\r\n");
        std::vector<uint8_t> resp;
        bool incHttp = false;
        assert(handleMgmtMetricsUdpPacket(mgmtIface, req, resp, incHttp, arpResolver));
        assert(incHttp);
        assert(extractUdpPayload(resp) == "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
    }

    // 3. POST /metrics HTTP/1.1 -> 501 Not Implemented
    {
        const auto req = makeIpv4UdpPacket(clientIp, mgmtIp, 45125, 9100, "POST /metrics HTTP/1.1\r\n\r\n");
        std::vector<uint8_t> resp;
        bool incHttp = false;
        assert(handleMgmtMetricsUdpPacket(mgmtIface, req, resp, incHttp, arpResolver));
        assert(incHttp);
        assert(extractUdpPayload(resp) == "HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\n\r\n");
    }

    // 4. Requisição malformada -> 400 Bad Request
    {
        const auto req = makeIpv4UdpPacket(clientIp, mgmtIp, 45126, 9100, "GET /metrics HTTP/1.1\r\n");
        std::vector<uint8_t> resp;
        bool incHttp = false;
        assert(handleMgmtMetricsUdpPacket(mgmtIface, req, resp, incHttp, arpResolver));
        assert(incHttp);
        assert(extractUdpPayload(resp) == "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
    }

    // 5. Checksum UDP inválido -> descarte cabecalho sem resposta
    {
        const auto arp = arpResolver.snapshot();
        const uint64_t beforeDrops = globalMetrics().snapshot(arp.entries, arp.pendingPackets).descartes_cabecalho;
        const auto req = makeIpv4UdpPacket(clientIp, mgmtIp, 45127, 9100, "GET /metrics HTTP/1.1\r\n\r\n", true);
        std::vector<uint8_t> resp;
        bool incHttp = false;
        assert(handleMgmtMetricsUdpPacket(mgmtIface, req, resp, incHttp, arpResolver));
        assert(!incHttp);
        assert(resp.empty());
        assert(globalMetrics().snapshot(arp.entries, arp.pendingPackets).descartes_cabecalho == beforeDrops + 1);
    }

    // 6. Sintaxe da requisição e precedência dos códigos HTTP.
    {
        struct RequestCase {
            std::string payload;
            std::string status;
        };
        const RequestCase cases[] = {
            {"GET /metrics HTTP/1.0\r\n\r\n", "200 OK"},
            {"GET /metrics HTTP/1.1\r\nsem dois-pontos\r\n\tvalor ignorado\r\n\r\n", "200 OK"},
            {"GET /metrics HTTP/1.1\r\n\r\n\t\rX\n" + std::string(1, '\0'), "200 OK"},
            {"GET outro HTTP/1.1\r\n\r\n", "404 Not Found"},
            {"POST outro HTTP/1.1\r\n\r\n", "501 Not Implemented"},
            {"GET /metrics HTTP/2.0\r\n\r\n", "400 Bad Request"},
            {"GET  /metrics HTTP/1.1\r\n\r\n", "400 Bad Request"},
            {" GET /metrics HTTP/1.1\r\n\r\n", "400 Bad Request"},
            {"GET /metrics HTTP/1.1 \r\n\r\n", "400 Bad Request"},
            {"GET\t/metrics HTTP/1.1\r\n\r\n", "400 Bad Request"},
            {"GE\tT /metrics HTTP/1.1\r\n\r\n", "400 Bad Request"},
            {"GET /met\trics HTTP/1.1\r\n\r\n", "400 Bad Request"},
            {"GET /metrics \r\n\r\n", "400 Bad Request"},
            {"GET /metrics extra HTTP/1.1\r\n\r\n", "400 Bad Request"},
            {"GE\nT /metrics HTTP/1.1\r\n\r\n", "400 Bad Request"},
            {"GET /met\rrics HTTP/1.1\r\n\r\n", "400 Bad Request"},
            {"GET /metrics HTTP/1.1\r\nX: a\nY: b\r\n\r\n", "400 Bad Request"},
            {"GET /metrics HTTP/1.1\r\nX: a\rY: b\r\n\r\n", "400 Bad Request"},
            {"GET /metrics HTTP/1.1\r\nHost: mgmt0\r\n", "400 Bad Request"},
            {"POST /metrics HTTP/1.1\r\nHost: mgmt0\n\r\n\r\n", "400 Bad Request"},
            {"GET outro HTTP/1.0\r\nHost: mgmt0\r", "400 Bad Request"},
        };

        for (const auto& test : cases) {
            const auto req = makeIpv4UdpPacket(clientIp, mgmtIp, 45128, 9100, test.payload);
            std::vector<uint8_t> resp;
            bool incHttp = false;
            assert(handleMgmtMetricsUdpPacket(mgmtIface, req, resp, incHttp, arpResolver));
            assert(incHttp);
            const auto raw = extractUdpPayload(resp);
            const auto statusLine = "HTTP/1.1 " + test.status + "\r\n";
            if (test.status == "200 OK") {
                assert(raw.find(statusLine) == 0);
                assert(raw.find("\narp_entradas 1\n") != std::string::npos);
                assert(raw.find("\narp_pendentes 2\n") != std::string::npos);
            } else {
                assert(raw == statusLine + "Content-Length: 0\r\n\r\n");
            }
        }
    }

    std::cout << "test_metrics_http: todos os testes passaram!\n";
    return 0;
}
