#include "../include/arp.hpp"
#include <cassert>
#include <iostream>

void testaArpCurto()
{
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

void testaAprendizadoArp()
{
    ArpCache cache;
    const auto start = std::chrono::steady_clock::time_point{};
    const std::array<std::uint8_t, 6> mac = {0x02, 0, 0, 0, 1, 10};

    cache.learn(0xC0A8010A, mac, "eth0", start);

    const auto learned = cache.lookup(0xC0A8010A, "eth0", start);
    assert(learned.has_value());
    assert(*learned == mac);
}

void testaAtualizacaoArp()
{
    ArpCache cache;
    const auto start = std::chrono::steady_clock::time_point{};
    const std::array<std::uint8_t, 6> macAntigo = {0x02, 0, 0, 0, 1, 10};
    const std::array<std::uint8_t, 6> macNovo = {0x02, 0, 0, 0, 10, 0x0a};

    cache.learn(0xC0A8010A, macAntigo, "eth0", start);
    cache.learn(0xC0A8010A, macNovo, "eth0", start + std::chrono::seconds(1));

    const auto learned = cache.lookup(0xC0A8010A, "eth0", start + std::chrono::seconds(30));
    assert(learned.has_value());
    assert(*learned == macNovo);
}

void testaInterfaceDoCacheArp()
{
    ArpCache cache;
    const auto start = std::chrono::steady_clock::time_point{};
    const std::array<std::uint8_t, 6> macEth0 = {0x02, 0, 0, 0, 1, 10};
    const std::array<std::uint8_t, 6> macEth1 = {0x02, 0, 0, 0, 10, 0x0a};

    cache.learn(0xC0A8010A, macEth0, "eth0", start);
    cache.learn(0xC0A8010A, macEth1, "eth1", start);

    const auto learnedEth0 = cache.lookup(0xC0A8010A, "eth0", start);
    const auto learnedEth1 = cache.lookup(0xC0A8010A, "eth1", start);

    assert(learnedEth0.has_value());
    assert(learnedEth1.has_value());

    assert(*learnedEth0 == macEth0);
    assert(*learnedEth1 == macEth1);
}

void testaExpiracaoArp()
{
    ArpCache cache;
    const auto start = std::chrono::steady_clock::time_point{};
    const std::array<std::uint8_t, 6> mac = {0x02, 0, 0, 0, 1, 10};

    cache.learn(0xC0A8010A, mac, "eth0", start);

    assert(cache.lookup(
                    0xC0A8010A, "eth0", start + std::chrono::seconds(29))
               .has_value());

    assert(!cache.lookup(
                     0xC0A8010A, "eth0", start + std::chrono::seconds(30))
                .has_value());
}

int main()
{
    testArpParser();
    testaArpCurto();
    testaAprendizadoArp();
    testaAtualizacaoArp();
    testaInterfaceDoCacheArp();
    testaExpiracaoArp();

    std::cout << "Todos os testes ARP passaram.\n";
}