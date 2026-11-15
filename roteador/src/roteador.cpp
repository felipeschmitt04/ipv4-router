
#include "../include/roteador.hpp"
#include "../include/ipv4.hpp"
#include "../include/interface.hpp"
#include "../include/routing.hpp"

using namespace std;

IPv4Result processIPv4(
    vector<uint8_t>& packet,
    const string& inputInterface,
    const IPv4Filter& filter
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
    //todo multicast começa com 1110, ou seja, os 4 bits mais significativos são 1110. Portanto, para verificar se o pacote é multicast,
    // podemos fazer uma operação AND com a máscara 0xF0000000 e comparar com 0xE0000000.
    bool multicast =
        (destinationIP & 0xF0000000u) == 0xE0000000u;
    //verificar se o endereço de destino é um broadcast de qualquer rede de alguma interface.

    bool directedBroadcast = false;
    //for each iterando sobre todas as interfaces do reteador.
    //para cada, o prefixo é armazenado.
    for (const auto& iface : allInterfaces) {
        uint8_t prefix = iface.prefixLength;

        if (prefix > 30) {
            continue;
        }

        uint32_t mask = prefix == 0
            ? 0
            : (0xFFFFFFFFu << (32 - prefix));
        //rede = Ip & máscara
        uint32_t network = iface.interfaceIpAddr & mask;
        //ao inverter os bits da máscara, obtemos apenas os bits de interface em 255 (útilimo endereço)
        //ao fazer um OR entre a rede e os bits de interface, obtemos o endereço de broadcast da rede.
        uint32_t broadcast = network | (~mask);

        if (destinationIP == broadcast) {
            directedBroadcast = true;
            break;
        }
    }

    if (limitedBroadcast || multicast || directedBroadcast) {
        result.action = IPv4Action::Drop;
        result.dropReason = "local";
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
        return result;
    }

    //Aplicar filtragem
    if (!filter) {
        result.action = IPv4Action::AwaitingFilter;
        return result;
    }

    if (!filter(packet, header, inputInterface)) {
        result.action = IPv4Action::Drop;
        result.dropReason = "filtro";
        return result;
    }

    if (header.TTL <= 1) {
        result.action = IPv4Action::TTLExpired;
        result.dropReason = "ttl";
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

