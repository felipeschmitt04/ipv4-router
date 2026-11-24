#include "../include/filter.hpp"

namespace {

uint32_t prefixMaskHostOrder(uint8_t prefixLength) {
    if (prefixLength == 0) {
        return 0u;
    }
    if (prefixLength >= 32) {
        return 0xFFFFFFFFu;
    }
    return 0xFFFFFFFFu << (32 - prefixLength);
}

bool matchesCIDR(uint32_t ipHostOrder, bool anyAddr, uint32_t networkHostOrder, uint8_t prefixLength) {
    if (anyAddr) {
        return true;
    }
    const uint32_t mask = prefixMaskHostOrder(prefixLength);
    return (ipHostOrder & mask) == (networkHostOrder & mask);
}

bool isNonInitialFragment(const std::vector<uint8_t>& packet) {
    if (packet.size() < 8) {
        return false;
    }
    // Bytes 6-7 do cabeçalho IPv4 contêm Flags (3 bits) + Fragment Offset (13 bits) em network byte order.
    const uint16_t flagsAndOffset =
        (static_cast<uint16_t>(packet[6]) << 8) |
        static_cast<uint16_t>(packet[7]);
    const uint16_t fragmentOffsetBlocks = flagsAndOffset & 0x1FFFu;
    return fragmentOffsetBlocks != 0;
}

bool extractUdpDestinationPort(const std::vector<uint8_t>& packet, uint16_t& outPort) {
    if (packet.empty()) {
        return false;
    }
    const size_t ihlWords = static_cast<size_t>(packet[0] & 0x0Fu);
    const size_t ihlBytes = ihlWords * 4u;
    // Cabeçalho IPv4 mínimo (20 bytes) + primeiros 4 bytes do UDP (srcPort + dstPort).
    if (ihlBytes < 20u || packet.size() < ihlBytes + 4u) {
        return false;
    }
    outPort =
        (static_cast<uint16_t>(packet[ihlBytes + 2u]) << 8) |
        static_cast<uint16_t>(packet[ihlBytes + 3u]);
    return true;
}

bool ruleMatchesPacket(
    const FilterRule& rule,
    const std::vector<uint8_t>& packet,
    const ipv4Header& header
) {
    // 1. Protocolo: 0 significa curinga '*' (qualquer protocolo); caso contrário deve bater (ex.: 1 ICMP, 17 UDP).
    if (rule.protocol != 0 && header.protocol != rule.protocol) {
        return false;
    }

    // 2. Origem e destino IPv4.
    if (!matchesCIDR(header.sourceIPAddr, rule.anySrc, rule.srcNetwork, rule.srcPrefixLength)) {
        return false;
    }
    if (!matchesCIDR(header.destinationIPAddr, rule.anyDst, rule.dstNetwork, rule.dstPrefixLength)) {
        return false;
    }

    // 3. Porta UDP de destino: se regra exige porta específica (dstPort != 0),
    // exige protocolo UDP (17), pacote UDP completo e fragmentOffset == 0.
    if (rule.dstPort != 0) {
        if (header.protocol != 17) {
            return false;
        }
        if (isNonInitialFragment(packet)) {
            return false;
        }
        uint16_t udpDstPort = 0;
        if (!extractUdpDestinationPort(packet, udpDstPort)) {
            return false;
        }
        if (udpDstPort != rule.dstPort) {
            return false;
        }
    }

    return true;
}

} // namespace

bool evaluateFilterRules(
    const std::vector<uint8_t>& packet,
    const ipv4Header& header,
    const std::string& interfaceName,
    const std::vector<FilterRule>& rules,
    size_t& matchedRuleNumber
) {
    (void)interfaceName;
    matchedRuleNumber = 0;

    if (!header.valid) {
        return true;
    }

    for (const FilterRule& rule : rules) {
        if (ruleMatchesPacket(rule, packet, header)) {
            if (rule.action == FilterAction::Negar) {
                matchedRuleNumber = static_cast<size_t>(rule.ruleNumber);
                return false;
            }
            // Regra Permitir encontrada em política first-match: libera imediatamente.
            return true;
        }
    }

    // Nenhuma regra correspondeu: ação padrão é permitir.
    return true;
}

bool evaluateIPv4FilterIndexed(
    const std::vector<uint8_t>& packet,
    const ipv4Header& header,
    const std::string& inputInterface,
    size_t& matchedRuleNumber
) {
    return evaluateFilterRules(packet, header, inputInterface, filterRules, matchedRuleNumber);
}

bool evaluateIPv4Filter(
    const std::vector<uint8_t>& packet,
    const ipv4Header& header,
    const std::string& inputInterface
) {
    size_t ignoredRule = 0;
    return evaluateFilterRules(packet, header, inputInterface, filterRules, ignoredRule);
}