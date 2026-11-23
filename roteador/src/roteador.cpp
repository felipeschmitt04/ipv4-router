#include "../include/roteador.hpp"
#include "../include/ipv4.hpp"
#include "../include/interface.hpp"
#include "../include/routing.hpp"
#include "../include/logger.hpp"

using namespace std;

namespace {
IPv4Result processIPv4Internal(
    vector<uint8_t>& packet,
    const string& inputInterface,
    const IPv4IndexedFilter& indexedFilter
) {
    IPv4Result result{};

    ipv4Header header = ipv4Interpreter(packet);

    if (!header.valid) {
        result.action = IPv4Action::Drop;
        result.dropReason = "ipv4_invalido";
        return result;
    }

    uint32_t destinationIP = header.destinationIPAddr;

    //de acordo com a especificação do trabalho, caso o roteador receba um broadcast ou multicast, o pacote deve ser descartado.
    bool limitedBroadcast = (destinationIP == 0xFFFFFFFFu);
    bool multicast = (destinationIP & 0xF0000000u) == 0xE0000000u;

    bool directedBroadcast = false;
    for (const auto& iface : allInterfaces) {
        uint8_t prefix = iface.prefixLength;

        if (prefix > 30) {
            continue;
        }

        uint32_t mask = prefix == 0
            ? 0
            : (0xFFFFFFFFu << (32 - prefix));
        uint32_t network = iface.interfaceIpAddr & mask;
        uint32_t broadcast = network | (~mask);

        if (destinationIP == broadcast) {
            directedBroadcast = true;
            break;
        }
    }

    if (limitedBroadcast || multicast || directedBroadcast) {
        result.action = IPv4Action::Drop;
        result.dropReason = "local";
        logDescarte("local", header.sourceIPAddr, header.destinationIPAddr, header.protocol);
        return result;
    }

    if (isLocal(destinationIP)) {
        result.action = IPv4Action::Local;
        return result;
    }

    //De acordo com a especificação do trabalho, não encaminhar pacotes recebidos pela gerência
    if (inputInterface == "mgmt0") {
        result.action = IPv4Action::Drop;
        result.dropReason = "local";
        logDescarte("local", header.sourceIPAddr, header.destinationIPAddr, header.protocol);
        return result;
    }

    //Aplicar filtragem
    if (!indexedFilter) {
        result.action = IPv4Action::AwaitingFilter;
        return result;
    }

    size_t matchedRule = 1;
    if (!indexedFilter(packet, header, inputInterface, matchedRule)) {
        result.action = IPv4Action::Drop;
        result.dropReason = "filtro";
        result.filterRule = matchedRule > 0 ? matchedRule : 1;
        logDescarteFiltro(header.sourceIPAddr, header.destinationIPAddr, header.protocol, result.filterRule);
        return result;
    }

    if (header.TTL <= 1) {
        result.action = IPv4Action::TTLExpired;
        result.dropReason = "ttl";
        logDescarte("ttl", header.sourceIPAddr, header.destinationIPAddr, header.protocol);
        return result;
    }

    // 7. Consultar a tabela de roteamento
    forwardingResult route = forwarding(
        destinationIP,
        allInterfaces,
        routeTable
    );

    if (!route.found) {
        result.action = IPv4Action::NoRoute;
        result.dropReason = "sem_rota";
        logDescarte("sem_rota", header.sourceIPAddr, header.destinationIPAddr, header.protocol);
        return result;
    }

    //Decrementar TTL e atualizar checksum
    newTTL(packet);

    //Preparar o encaminhamento
    result.action = IPv4Action::Forward;
    result.outputInterface = route.interfaceName;
    result.nextHop = route.nextHop;

    return result;
}
} // namespace

IPv4Result processIPv4(
    vector<uint8_t>& packet,
    const string& inputInterface,
    const IPv4Filter& filter
) {
    if (!filter) {
        return processIPv4Internal(packet, inputInterface, nullptr);
    }
    return processIPv4Internal(
        packet,
        inputInterface,
        [&filter](const vector<uint8_t>& pkt, const ipv4Header& hdr, const string& iface, size_t& rule) {
            rule = 1;
            return filter(pkt, hdr, iface);
        }
    );
}

IPv4Result processIPv4(
    vector<uint8_t>& packet,
    const string& inputInterface,
    const IPv4IndexedFilter& filter
) {
    return processIPv4Internal(packet, inputInterface, filter);
}