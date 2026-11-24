#include "../include/metrics_http.hpp"
#include "../include/ipv4.hpp"
#include "../include/metrics.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace {

uint16_t udpChecksumWithPseudoHeader(
    uint32_t srcIp,
    uint32_t dstIp,
    const std::vector<uint8_t>& udpSegment,
    bool zeroChecksumFieldBeforeCalc
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
        if (zeroChecksumFieldBeforeCalc && (i == 6 || i + 1 == 6)) {
            hi = 0u;
        }
        if (zeroChecksumFieldBeforeCalc && (i == 7 || i + 1 == 7)) {
            lo = 0u;
        }
        const uint16_t word = (static_cast<uint16_t>(hi) << 8) | static_cast<uint16_t>(lo);
        sum += word;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }

    return static_cast<uint16_t>(~sum) & 0xFFFFu;
}

std::string buildHttpResponse(
    const char* statusLine,
    const std::string& body
) {
    std::string resp = "HTTP/1.1 ";
    resp += statusLine;
    resp += "\r\n";
    if (!body.empty()) {
        resp += "Content-Type: text/plain; version=0.0.4\r\n";
    }
    resp += "Content-Length: ";
    resp += std::to_string(body.size());
    resp += "\r\n\r\n";
    resp += body;
    return resp;
}

std::string evaluateHttpRequest(const std::string& payload) {
    const size_t headerEnd = payload.find("\r\n\r\n");
    if (headerEnd == std::string::npos) {
        return buildHttpResponse("400 Bad Request", "");
    }

    const size_t firstCrlf = payload.find("\r\n");
    if (firstCrlf == std::string::npos || firstCrlf == 0) {
        return buildHttpResponse("400 Bad Request", "");
    }

    const std::string requestLine = payload.substr(0, firstCrlf);

    const size_t sp1 = requestLine.find(' ');
    if (sp1 == std::string::npos || sp1 == 0) {
        return buildHttpResponse("400 Bad Request", "");
    }

    const size_t sp2 = requestLine.find(' ', sp1 + 1);
    if (sp2 == std::string::npos || sp2 == sp1 + 1) {
        return buildHttpResponse("400 Bad Request", "");
    }

    if (requestLine.find(' ', sp2 + 1) != std::string::npos) {
        return buildHttpResponse("400 Bad Request", "");
    }

    const std::string method = requestLine.substr(0, sp1);
    const std::string target = requestLine.substr(sp1 + 1, sp2 - (sp1 + 1));
    const std::string version = requestLine.substr(sp2 + 1);

    if (version != "HTTP/1.1" && version != "HTTP/1.0") {
        return buildHttpResponse("400 Bad Request", "");
    }

    if (method != "GET") {
        return buildHttpResponse("501 Not Implemented", "");
    }

    if (target != "/metrics") {
        return buildHttpResponse("404 Not Found", "");
    }

    const std::string body = globalMetrics().renderPrometheus();
    return buildHttpResponse("200 OK", body);
}

std::vector<uint8_t> buildIpv4UdpDatagram(
    uint32_t srcIp,
    uint32_t dstIp,
    uint16_t srcPort,
    uint16_t dstPort,
    const std::string& appPayload
) {
    if (appPayload.size() > 65535u - 28u) {
        return {};
    }

    const uint16_t udpLen = static_cast<uint16_t>(8u + appPayload.size());
    const uint16_t ipLen = static_cast<uint16_t>(20u + udpLen);

    std::vector<uint8_t> udp(udpLen, 0u);
    udp[0] = static_cast<uint8_t>((srcPort >> 8) & 0xFFu);
    udp[1] = static_cast<uint8_t>(srcPort & 0xFFu);
    udp[2] = static_cast<uint8_t>((dstPort >> 8) & 0xFFu);
    udp[3] = static_cast<uint8_t>(dstPort & 0xFFu);
    udp[4] = static_cast<uint8_t>((udpLen >> 8) & 0xFFu);
    udp[5] = static_cast<uint8_t>(udpLen & 0xFFu);
    udp[6] = 0u;
    udp[7] = 0u;

    for (size_t i = 0; i < appPayload.size(); ++i) {
        udp[8u + i] = static_cast<uint8_t>(appPayload[i]);
    }

    uint16_t udpCsum = udpChecksumWithPseudoHeader(srcIp, dstIp, udp, false);
    if (udpCsum == 0u) {
        udpCsum = 0xFFFFu;
    }
    udp[6] = static_cast<uint8_t>((udpCsum >> 8) & 0xFFu);
    udp[7] = static_cast<uint8_t>(udpCsum & 0xFFu);

    std::vector<uint8_t> pkt(ipLen, 0u);
    pkt[0] = 0x45u;
    pkt[2] = static_cast<uint8_t>((ipLen >> 8) & 0xFFu);
    pkt[3] = static_cast<uint8_t>(ipLen & 0xFFu);
    pkt[8] = 64u;
    pkt[9] = 17u;

    pkt[12] = static_cast<uint8_t>((srcIp >> 24) & 0xFFu);
    pkt[13] = static_cast<uint8_t>((srcIp >> 16) & 0xFFu);
    pkt[14] = static_cast<uint8_t>((srcIp >> 8) & 0xFFu);
    pkt[15] = static_cast<uint8_t>(srcIp & 0xFFu);

    pkt[16] = static_cast<uint8_t>((dstIp >> 24) & 0xFFu);
    pkt[17] = static_cast<uint8_t>((dstIp >> 16) & 0xFFu);
    pkt[18] = static_cast<uint8_t>((dstIp >> 8) & 0xFFu);
    pkt[19] = static_cast<uint8_t>(dstIp & 0xFFu);

    const uint16_t ipCsum = calculateCheckSum(pkt, 5u);
    pkt[10] = static_cast<uint8_t>((ipCsum >> 8) & 0xFFu);
    pkt[11] = static_cast<uint8_t>(ipCsum & 0xFFu);

    for (size_t i = 0; i < udp.size(); ++i) {
        pkt[20u + i] = udp[i];
    }

    return pkt;
}

} // namespace

bool handleMgmtMetricsUdpPacket(
    const interface& mgmtInterface,
    const std::vector<uint8_t>& ipv4Packet,
    std::vector<uint8_t>& outIpv4ResponsePacket,
    bool& outIncrementHttpResponses
) {
    outIpv4ResponsePacket.clear();
    outIncrementHttpResponses = false;

    const ipv4Header hdr = ipv4Interpreter(ipv4Packet);
    if (!hdr.valid || hdr.protocol != 17u) {
        return false;
    }

    if (hdr.destinationIPAddr != mgmtInterface.interfaceIpAddr) {
        return false;
    }

    const size_t ipHdrLen = static_cast<size_t>(hdr.IHL) * 4u;
    if (hdr.totalLength < ipHdrLen + 8u || ipv4Packet.size() < hdr.totalLength) {
        globalMetrics().incDescartesCabecalho();
        return true;
    }

    const std::vector<uint8_t> udpSegment(
        ipv4Packet.begin() + static_cast<ptrdiff_t>(ipHdrLen),
        ipv4Packet.begin() + static_cast<ptrdiff_t>(hdr.totalLength)
    );

    const uint16_t udpSrcPort =
        (static_cast<uint16_t>(udpSegment[0]) << 8) | static_cast<uint16_t>(udpSegment[1]);
    const uint16_t udpDstPort =
        (static_cast<uint16_t>(udpSegment[2]) << 8) | static_cast<uint16_t>(udpSegment[3]);
    const uint16_t udpLength =
        (static_cast<uint16_t>(udpSegment[4]) << 8) | static_cast<uint16_t>(udpSegment[5]);
    const uint16_t udpChecksum =
        (static_cast<uint16_t>(udpSegment[6]) << 8) | static_cast<uint16_t>(udpSegment[7]);

    if (udpDstPort != 9100u) {
        return false;
    }

    if (udpLength < 8u || udpLength > udpSegment.size()) {
        globalMetrics().incDescartesCabecalho();
        return true;
    }

    const std::vector<uint8_t> exactUdp(
        udpSegment.begin(),
        udpSegment.begin() + static_cast<ptrdiff_t>(udpLength)
    );

    if (udpChecksum != 0u) {
        const uint16_t calc = udpChecksumWithPseudoHeader(
            hdr.sourceIPAddr,
            hdr.destinationIPAddr,
            exactUdp,
            false
        );
        if (calc != 0u) {
            globalMetrics().incDescartesCabecalho();
            return true;
        }
    }

    const std::string httpPayload(
        exactUdp.begin() + 8,
        exactUdp.end()
    );

    const std::string httpResponse = evaluateHttpRequest(httpPayload);
    outIpv4ResponsePacket = buildIpv4UdpDatagram(
        mgmtInterface.interfaceIpAddr,
        hdr.sourceIPAddr,
        9100u,
        udpSrcPort,
        httpResponse
    );
    outIncrementHttpResponses = !outIpv4ResponsePacket.empty();
    return true;
}