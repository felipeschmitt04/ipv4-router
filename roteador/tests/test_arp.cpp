#include "../include/arp.hpp"
#include <cassert>
#include <iostream>

void testaArpCurto(){
    std::vector<uint8_t> bytes(27, 0);

    assert(!parseArpMessage(bytes).has_value());
}

void testArpParser()
{
    std::vector<std::uint8_t> bytes = {
        0x00, 0x01,                         // hardware type: Ethernet
        0x08, 0x00,                         // protocol type: IPv4
        0x06,                               // tamanho do MAC
        0x04,                               // tamanho do IPv4
        0x00, 0x01,                         // operacao: request
        0x02, 0x00, 0x00, 0x00, 0x01, 0x0A, // MAC sender
        192, 168, 1, 10,                    // IP sender
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MAC target
        192, 168, 1, 1                      // IP target
    };

    const auto arp = parseArpMessage(bytes);
    assert(arp.has_value());
    assert(arp->hardware_type == 1);
    assert(arp->protocol_type == 0x0800);
    assert(arp->operation == 1);
    assert(arp->senderMAC[5] == 0x0A);
    assert(arp->senderIP == 0xC0A8010A);
    assert(arp->targetIP == 0xC0A80101);
}

int main()
{
    testArpParser();
    testaArpCurto();

    std::cout << "Todos os testes ARP passaram.\n";
}