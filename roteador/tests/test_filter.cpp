#include "../include/filter.hpp"
#include "../include/roteador.hpp"
#include "../include/ipv4.hpp"
#include "../include/interface.hpp"
#include "../include/routing.hpp"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace {

uint32_t ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return (static_cast<uint32_t>(a) << 24) |
           (static_cast<uint32_t>(b) << 16) |
           (static_cast<uint32_t>(c) << 8)  |
           static_cast<uint32_t>(d);
}

uint16_t calcChecksum(const std::vector<uint8_t>& hdr, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < len; i += 2) {
        if (i == 10) {
            continue;
        }
        uint16_t word = (static_cast<uint16_t>(hdr[i]) << 8) | hdr[i + 1];
        sum += word;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}

std::vector<uint8_t> makePacket(
    uint32_t src,
    uint32_t dst,
    uint8_t proto,
    uint8_t ttl,
    uint16_t flagsAndFragOffset,
    bool withUdp,
    uint16_t udpSrcPort,
    uint16_t udpDstPort
) {
    const size_t udpLen = withUdp ? 8 : 0;
    const size_t totalLen = 20 + udpLen;
    std::vector<uint8_t> pkt(totalLen, 0);

    pkt[0] = 0x45; // IPv4, IHL = 5 (20 bytes)
    pkt[2] = static_cast<uint8_t>((totalLen >> 8) & 0xFF);
    pkt[3] = static_cast<uint8_t>(totalLen & 0xFF);
    pkt[5] = 0x01;
    pkt[6] = static_cast<uint8_t>((flagsAndFragOffset >> 8) & 0xFF);
    pkt[7] = static_cast<uint8_t>(flagsAndFragOffset & 0xFF);
    pkt[8] = ttl;
    pkt[9] = proto;

    pkt[12] = static_cast<uint8_t>((src >> 24) & 0xFF);
    pkt[13] = static_cast<uint8_t>((src >> 16) & 0xFF);
    pkt[14] = static_cast<uint8_t>((src >> 8) & 0xFF);
    pkt[15] = static_cast<uint8_t>(src & 0xFF);

    pkt[16] = static_cast<uint8_t>((dst >> 24) & 0xFF);
    pkt[17] = static_cast<uint8_t>((dst >> 16) & 0xFF);
    pkt[18] = static_cast<uint8_t>((dst >> 8) & 0xFF);
    pkt[19] = static_cast<uint8_t>(dst & 0xFF);

    if (withUdp) {
        pkt[20] = static_cast<uint8_t>((udpSrcPort >> 8) & 0xFF);
        pkt[21] = static_cast<uint8_t>(udpSrcPort & 0xFF);
        pkt[22] = static_cast<uint8_t>((udpDstPort >> 8) & 0xFF);
        pkt[23] = static_cast<uint8_t>(udpDstPort & 0xFF);
        pkt[24] = static_cast<uint8_t>((udpLen >> 8) & 0xFF);
        pkt[25] = static_cast<uint8_t>(udpLen & 0xFF);
    }

    const uint16_t csum = calcChecksum(pkt, 20);
    pkt[10] = static_cast<uint8_t>((csum >> 8) & 0xFF);
    pkt[11] = static_cast<uint8_t>(csum & 0xFF);
    return pkt;
}

void resetGlobals() {
    filterRules.clear();
    allInterfaces.clear();
    routeTable.clear();
}

} // namespace

int main() {
    resetGlobals();

    // Regra 1: negar UDP de 10.0.1.0/24 para 10.0.4.0/24 porta 53
    FilterRule r1{};
    r1.ruleNumber = 1;
    r1.action = FilterAction::Negar;
    r1.protocol = 17;
    r1.anySrc = false;
    r1.srcNetwork = ip(10, 0, 1, 0);
    r1.srcPrefixLength = 24;
    r1.anyDst = false;
    r1.dstNetwork = ip(10, 0, 4, 0);
    r1.dstPrefixLength = 24;
    r1.dstPort = 53;

    // Regra 2: permitir UDP de 10.0.1.0/24 para 10.0.4.0/24 porta 53 (fica apos regra 1)
    FilterRule r2 = r1;
    r2.ruleNumber = 2;
    r2.action = FilterAction::Permitir;

    // Regra 3: negar ICMP de 10.0.1.0/24 para 10.0.4.0/24 (qualquer porta / sem porta)
    FilterRule r3{};
    r3.ruleNumber = 3;
    r3.action = FilterAction::Negar;
    r3.protocol = 1;
    r3.anySrc = false;
    r3.srcNetwork = ip(10, 0, 1, 0);
    r3.srcPrefixLength = 24;
    r3.anyDst = false;
    r3.dstNetwork = ip(10, 0, 4, 0);
    r3.dstPrefixLength = 24;
    r3.dstPort = 0;

    filterRules = {r1, r2, r3};

    // 1. First-match: regra 1 (negar) vem antes da regra 2 (permitir)
    {
        auto pkt = makePacket(ip(10, 0, 1, 10), ip(10, 0, 4, 10), 17, 64, 0x0000, true, 12345, 53);
        ipv4Header hdr = ipv4Interpreter(pkt);
        size_t matched = 0;
        assert(evaluateIPv4FilterIndexed(pkt, hdr, "eth0", matched) == false);
        assert(matched == 1);
    }

    // 2. Fragmento nao inicial (fragmentOffset != 0) nao casa com regra que especifica porta UDP
    {
        auto pkt = makePacket(ip(10, 0, 1, 10), ip(10, 0, 4, 10), 17, 64, 0x0001, true, 12345, 53);
        ipv4Header hdr = ipv4Interpreter(pkt);
        size_t matched = 0;
        assert(evaluateIPv4FilterIndexed(pkt, hdr, "eth0", matched) == true);
        assert(matched == 0);
    }

    // 3. Correspondencia de protocolo ICMP (1) e numero da regra (3)
    {
        auto pkt = makePacket(ip(10, 0, 1, 10), ip(10, 0, 4, 10), 1, 64, 0x0000, false, 0, 0);
        ipv4Header hdr = ipv4Interpreter(pkt);
        size_t matched = 0;
        assert(evaluateIPv4FilterIndexed(pkt, hdr, "eth0", matched) == false);
        assert(matched == 3);
    }

    // 4. Acao padrao permitir quando nenhuma regra corresponde
    {
        auto pkt = makePacket(ip(10, 0, 2, 10), ip(10, 0, 5, 10), 17, 64, 0x0000, true, 12345, 8080);
        ipv4Header hdr = ipv4Interpreter(pkt);
        size_t matched = 0;
        assert(evaluateIPv4FilterIndexed(pkt, hdr, "eth0", matched) == true);
    }

    // 5. Integracao com processIPv4: pacote local nao passa pelo filtro
    {
        interface iface{};
        iface.interfaceName = "eth0";
        iface.interfaceIpAddr = ip(10, 0, 1, 1);
        iface.prefixLength = 24;
        allInterfaces.push_back(iface);

        auto pktLocal = makePacket(ip(10, 0, 1, 10), ip(10, 0, 1, 1), 17, 64, 0x0000, true, 12345, 53);
        IPv4Result res = processIPv4(pktLocal, "eth0", evaluateIPv4FilterIndexed);
        assert(res.action == IPv4Action::Local);
    }

    // 6. Integracao com processIPv4: pacote encaminhado bloqueado retorna Drop ("filtro") e rule 1
    {
        resetGlobals();
        filterRules = {r1};

        interface inIface{};
        inIface.interfaceName = "eth0";
        inIface.interfaceIpAddr = ip(10, 0, 1, 1);
        inIface.prefixLength = 24;

        interface outIface{};
        outIface.interfaceName = "eth1";
        outIface.interfaceIpAddr = ip(10, 0, 4, 1);
        outIface.prefixLength = 24;

        allInterfaces = {inIface, outIface};

        auto pktBlocked = makePacket(ip(10, 0, 1, 10), ip(10, 0, 4, 10), 17, 64, 0x0000, true, 12345, 53);
        IPv4Result res = processIPv4(pktBlocked, "eth0", evaluateIPv4FilterIndexed);
        assert(res.action == IPv4Action::Drop);
        assert(res.dropReason == "filtro");
        assert(res.filterRule == 1);
    }

    std::cout << "test_filter: todos os testes passaram!\n";
    return 0;
}