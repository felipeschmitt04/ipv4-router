#include "../include/icmp.hpp"
#include "../include/interface.hpp"
#include <algorithm>

using namespace std;

// Calcula o checksum de uma sequência de bytes
uint16_t calculateICMPChecksum(const vector<uint8_t>& data) {
    uint32_t sum = 0;
    for (size_t i = 0; i < data.size(); i += 2) {
        uint16_t word = uint16_t(data[i]) << 8;
        if (i + 1 < data.size()) {
            word |= data[i + 1];
        }
        sum += word;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return uint16_t(~sum);
}

// Interpreta uma mensagem ICMP
ICMPInterpreterResult icmpInterpreter(const vector<uint8_t>& packet) {
    ICMPInterpreterResult result{};
    ipv4Header header = ipv4Interpreter(packet);
    if (!header.valid || header.protocol != 1) {
        return result;
    }
    size_t offset = header.IHL * 4;
    if (header.totalLength < offset + 8 ||
        packet.size() < header.totalLength) {
        return result;
    }
    result.type = packet[offset];
    result.code = packet[offset + 1];
    result.checksum = (uint16_t(packet[offset + 2]) << 8) |
                       packet[offset + 3];
    result.restOfHeader =
        (uint32_t(packet[offset + 4]) << 24) |
        (uint32_t(packet[offset + 5]) << 16) |
        (uint32_t(packet[offset + 6]) << 8) |
        packet[offset + 7];
    if (result.type == 8 && result.code == 0) {
        vector<uint8_t> data(
            packet.begin() + offset,
            packet.begin() + header.totalLength
        );
        if (calculateICMPChecksum(data) != 0) {
            return result;
        }
    }

    result.valid = true;
    return result;
}

// Monta o cabeçalho IPv4 e adiciona a mensagem ICMP
static vector<uint8_t> buildIPv4(
    uint32_t sourceIP,
    uint32_t destinationIP,
    const vector<uint8_t>& icmp
) {
    if (icmp.size() > 65515) {
        return {};
    }

    vector<uint8_t> packet(20 + icmp.size(), 0);

    packet[0] = 0x45;
    packet[2] = uint8_t(packet.size() >> 8);
    packet[3] = uint8_t(packet.size());
    packet[8] = 64;
    packet[9] = 1;

    for (int i = 0; i < 4; i++) {
        packet[12 + i] = uint8_t(sourceIP >> (24 - 8 * i));
        packet[16 + i] = uint8_t(destinationIP >> (24 - 8 * i));
    }

    copy(icmp.begin(), icmp.end(), packet.begin() + 20);

    vector<uint8_t> ipHeader(packet.begin(), packet.begin() + 20);
    uint16_t checksum = calculateICMPChecksum(ipHeader);

    packet[10] = uint8_t(checksum >> 8);
    packet[11] = uint8_t(checksum);

    return packet;
}

// Constrói a resposta de um Echo Request
vector<uint8_t> buildICMPEchoReply(const vector<uint8_t>& packet) {
    ICMPInterpreterResult icmp = icmpInterpreter(packet);

    if (!icmp.valid || icmp.type != 8 || icmp.code != 0) {
        return {};
    }

    ipv4Header header = ipv4Interpreter(packet);
    size_t offset = header.IHL * 4;

    vector<uint8_t> reply(
        packet.begin() + offset,
        packet.begin() + header.totalLength
    );

    reply[0] = 0;
    reply[1] = 0;
    reply[2] = 0;
    reply[3] = 0;

    uint16_t checksum = calculateICMPChecksum(reply);

    reply[2] = uint8_t(checksum >> 8);
    reply[3] = uint8_t(checksum);

    return buildIPv4(
        header.destinationIPAddr,
        header.sourceIPAddr,
        reply
    );
}

// Constrói os erros ICMP 11/0, 3/0, 3/1 e 3/3
vector<uint8_t> buildICMPError(
    const vector<uint8_t>& packet,
    uint8_t type,
    uint8_t code,
    uint32_t sourceIP,
    bool ethernetBroadcast,
    const string& dropReason
) {
    bool allowed =
        (type == 11 && code == 0) ||
        (type == 3 && (code == 0 || code == 1 || code == 3));

    if (!allowed || ethernetBroadcast ||
        dropReason == "cabecalho" ||
        dropReason == "quadro" ||
        dropReason == "filtro") {
        return {};
    }

    ipv4Header header = ipv4Interpreter(packet);

    if (!header.valid || packet.size() < header.totalLength) {
        return {};
    }

    uint32_t source = header.sourceIPAddr;

    if (source == 0 ||
        source == 0xFFFFFFFFu ||
        (source & 0xFF000000u) == 0x7F000000u ||
        (source & 0xE0000000u) == 0xE0000000u) {
        return {};
    }

    // Não responder a pacotes vindos de broadcast
    for (const auto& iface : allInterfaces) {
        if (iface.prefixLength > 30) {
            continue;
        }

        uint32_t mask = iface.prefixLength == 0
            ? 0
            : (0xFFFFFFFFu << (32 - iface.prefixLength));

        uint32_t broadcast =
            (iface.interfaceIpAddr & mask) | ~mask;

        if (source == broadcast) {
            return {};
        }
    }

    // Não gerar erro para fragmentos não iniciais
    uint16_t fragment =
        (uint16_t(packet[6]) << 8) | packet[7];

    if ((fragment & 0x1FFF) != 0) {
        return {};
    }

    // Não gerar erros ICMP em resposta a outros erros ICMP
    if (header.protocol == 1) {
        size_t offset = header.IHL * 4;

        if (header.totalLength < offset + 8) {
            return {};
        }

        uint8_t originalType = packet[offset];

        if (originalType == 3 || originalType == 4 ||
            originalType == 5 || originalType == 11 ||
            originalType == 12) {
            return {};
        }
    }

    size_t headerLength = header.IHL * 4;
    size_t copiedLength = min(
        size_t(header.totalLength),
        headerLength + size_t(8)
    );

    vector<uint8_t> error(8 + copiedLength, 0);

    error[0] = type;
    error[1] = code;

    copy(
        packet.begin(),
        packet.begin() + copiedLength,
        error.begin() + 8
    );

    uint16_t checksum = calculateICMPChecksum(error);

    error[2] = uint8_t(checksum >> 8);
    error[3] = uint8_t(checksum);

    return buildIPv4(sourceIP, source, error);
}