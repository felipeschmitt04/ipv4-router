#include "../include/logger.hpp"
#include "../include/arp.hpp"
#include "../include/arp_resolver.hpp"
#include "../include/ethernet.hpp"
#include "../include/interface.hpp"
#include "../include/ipv4.hpp"
#include "../include/roteador.hpp"
#include "../include/routing.hpp"

#include <unistd.h>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

// Captura a saida escrita em stdout durante a execucao de uma funcao
template <typename Func>
std::string capturarStdout(Func fn)
{
    std::fflush(stdout);
    FILE *temp = std::tmpfile();
    assert(temp != nullptr);

    int stdoutBackup = dup(fileno(stdout));
    dup2(fileno(temp), fileno(stdout));

    fn();

    std::fflush(stdout);
    dup2(stdoutBackup, fileno(stdout));
    close(stdoutBackup);

    std::rewind(temp);
    std::string saida;
    char buffer[512];
    while (std::fgets(buffer, sizeof(buffer), temp) != nullptr)
    {
        saida += buffer;
    }
    std::fclose(temp);
    return saida;
}

std::vector<uint8_t> criarPacoteIpv4Valido(
    uint32_t origem,
    uint32_t destino,
    uint8_t ttl,
    uint8_t protocolo)
{
    std::vector<uint8_t> pkt(20, 0);
    pkt[0] = 0x45; // IPv4, IHL=5
    pkt[2] = 0x00;
    pkt[3] = 20;   // Total Length = 20
    pkt[8] = ttl;
    pkt[9] = protocolo;

    pkt[12] = static_cast<uint8_t>((origem >> 24) & 0xFF);
    pkt[13] = static_cast<uint8_t>((origem >> 16) & 0xFF);
    pkt[14] = static_cast<uint8_t>((origem >> 8) & 0xFF);
    pkt[15] = static_cast<uint8_t>(origem & 0xFF);

    pkt[16] = static_cast<uint8_t>((destino >> 24) & 0xFF);
    pkt[17] = static_cast<uint8_t>((destino >> 16) & 0xFF);
    pkt[18] = static_cast<uint8_t>((destino >> 8) & 0xFF);
    pkt[19] = static_cast<uint8_t>(destino & 0xFF);

    uint16_t csum = calculateCheckSum(pkt, 5);
    pkt[10] = static_cast<uint8_t>((csum >> 8) & 0xFF);
    pkt[11] = static_cast<uint8_t>(csum & 0xFF);
    return pkt;
}

void testaFormatacaoIpEMac()
{
    assert(formatIp(0x0A000101) == "10.0.1.1");
    assert(formatIp(0xC0A800FE) == "192.168.0.254");
    assert(formatIp(0x00000000) == "0.0.0.0");

    const std::array<uint8_t, 6> mac = {0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x0F};
    assert(formatMacLower(mac) == "aa:bb:cc:01:02:0f");
}

void testaLogInicio()
{
    std::string linha = capturarStdout([]() {
        logInicio("r1");
    });

    assert(linha.find("\"evento\": \"inicio\"") != std::string::npos);
    assert(linha.find("\"roteador\": \"r1\"") != std::string::npos);
    assert(linha.back() == '\n');
}

void testaLogsArp()
{
    const std::array<uint8_t, 6> mac = {0x02, 0x00, 0x00, 0x00, 0x01, 0x0A};

    std::string aprendido = capturarStdout([&]() {
        logArpAprendido(0x0A00010A, mac, "eth0");
    });
    assert(aprendido.find("\"evento\": \"arp_aprendido\"") != std::string::npos);
    assert(aprendido.find("\"ip\": \"10.0.1.10\"") != std::string::npos);
    assert(aprendido.find("\"mac\": \"02:00:00:00:01:0a\"") != std::string::npos);
    assert(aprendido.find("\"interface\": \"eth0\"") != std::string::npos);

    std::string expirado = capturarStdout([]() {
        logArpExpirado(0x0A00010A);
    });
    assert(expirado.find("\"evento\": \"arp_expirado\"") != std::string::npos);
    assert(expirado.find("\"ip\": \"10.0.1.10\"") != std::string::npos);

    std::string falhou = capturarStdout([]() {
        logArpFalhou(0x0A000102, "eth1");
    });
    assert(falhou.find("\"evento\": \"arp_falhou\"") != std::string::npos);
    assert(falhou.find("\"ip\": \"10.0.1.2\"") != std::string::npos);
    assert(falhou.find("\"interface\": \"eth1\"") != std::string::npos);
}

void testaIntegracaoCacheArp()
{
    ArpCache cache;
    const auto inicio = std::chrono::steady_clock::time_point{};
    const std::array<uint8_t, 6> mac = {0x02, 0x00, 0x00, 0x00, 0x01, 0x0A};

    std::string saidaLearn = capturarStdout([&]() {
        cache.learn(0x0A00010A, mac, "eth0", inicio);
    });
    assert(saidaLearn.find("\"evento\": \"arp_aprendido\"") != std::string::npos);

    std::string saidaExpire = capturarStdout([&]() {
        cache.removeExpired(inicio + std::chrono::seconds(30));
    });
    assert(saidaExpire.find("\"evento\": \"arp_expirado\"") != std::string::npos);
}

void testaDescartesProcessIpv4()
{
    allInterfaces = {
        {0x0A000101, 24, "eth0", {0x02, 0x00, 0x00, 0x00, 0x01, 0x00}},
        {0x0A000201, 24, "eth1", {0x02, 0x00, 0x00, 0x00, 0x01, 0x01}}
    };
    routeTable = {
        {0x0A000300, 24, 0x0A000202, "eth1"}
    };

    IPv4Filter permiteTudo = [](const std::vector<uint8_t>&, const ipv4Header&, const std::string&) {
        return true;
    };

    // 1. Quadro Ethernet invalido e cabecalho IPv4 invalido devem ser silenciosos
    std::string saidaInvalida = capturarStdout([&]() {
        ReceivedFrame quadroCurto{{0x01, 0x02}, 1};
        assert(!parseEthernetHeader(quadroCurto).has_value());

        std::vector<uint8_t> ipv4Invalido(20, 0); // version 0 != 4
        auto res = processIPv4(ipv4Invalido, "eth0", permiteTudo);
        assert(res.action == IPv4Action::Drop);
    });
    assert(saidaInvalida.empty());

    // 2. Descarte motivo "local" (broadcast dirigido e mgmt0)
    std::string saidaLocal = capturarStdout([&]() {
        auto pktBroadcast = criarPacoteIpv4Valido(0x0A00010A, 0x0A0001FF, 64, 17);
        auto res1 = processIPv4(pktBroadcast, "eth0", permiteTudo);
        assert(res1.action == IPv4Action::Drop);
        assert(res1.dropReason == "local");

        auto pktMgmt = criarPacoteIpv4Valido(0x0A00010A, 0x0A00030A, 64, 6);
        auto res2 = processIPv4(pktMgmt, "mgmt0", permiteTudo);
        assert(res2.action == IPv4Action::Drop);
        assert(res2.dropReason == "local");
    });
    assert(saidaLocal.find("\"motivo\": \"local\"") != std::string::npos);
    assert(saidaLocal.find("\"origem\": \"10.0.1.10\"") != std::string::npos);
    assert(saidaLocal.find("\"destino\": \"10.0.1.255\"") != std::string::npos);
    assert(saidaLocal.find("\"protocolo\": 17") != std::string::npos);

    // 3. Descarte motivo "filtro" com indice baseado em 1
    std::string saidaFiltro = capturarStdout([&]() {
        IPv4IndexedFilter bloqueiaRegra3 = [](const std::vector<uint8_t>&, const ipv4Header&, const std::string&, size_t& regra) {
            regra = 3;
            return false;
        };
        auto pkt = criarPacoteIpv4Valido(0x0A00010A, 0x0A00030A, 64, 6);
        auto res = processIPv4(pkt, "eth0", bloqueiaRegra3);
        assert(res.action == IPv4Action::Drop);
        assert(res.dropReason == "filtro");
        assert(res.filterRule == 3);
    });
    assert(saidaFiltro.find("\"motivo\": \"filtro\"") != std::string::npos);
    assert(saidaFiltro.find("\"protocolo\": 6") != std::string::npos);
    assert(saidaFiltro.find("\"regra\": 3") != std::string::npos);

    // 4. Descarte motivo "ttl"
    std::string saidaTtl = capturarStdout([&]() {
        auto pkt = criarPacoteIpv4Valido(0x0A00010A, 0x0A00030A, 1, 1);
        auto res = processIPv4(pkt, "eth0", permiteTudo);
        assert(res.action == IPv4Action::TTLExpired);
    });
    assert(saidaTtl.find("\"motivo\": \"ttl\"") != std::string::npos);
    assert(saidaTtl.find("\"destino\": \"10.0.3.10\"") != std::string::npos);
    assert(saidaTtl.find("\"protocolo\": 1") != std::string::npos);

    // 5. Descarte motivo "sem_rota"
    std::string saidaSemRota = capturarStdout([&]() {
        auto pkt = criarPacoteIpv4Valido(0x0A00010A, 0x08080808, 64, 17);
        auto res = processIPv4(pkt, "eth0", permiteTudo);
        assert(res.action == IPv4Action::NoRoute);
    });
    assert(saidaSemRota.find("\"motivo\": \"sem_rota\"") != std::string::npos);
    assert(saidaSemRota.find("\"destino\": \"8.8.8.8\"") != std::string::npos);
    assert(saidaSemRota.find("\"protocolo\": 17") != std::string::npos);
}

void testaDescartesArpEFilaArp()
{
    ArpResolver resolver([](const std::string&, const std::vector<uint8_t>&) {});
    const interface eth1{0x0A000201, 24, "eth1", {0x02, 0x00, 0x00, 0x00, 0x01, 0x01}};
    const auto inicio = std::chrono::steady_clock::time_point{};
    constexpr uint32_t nextHop = 0x0A000202;

    // Enfileira 16 pacotes e tenta o 17o -> gera descarte "fila_arp"
    std::string saidaFilaCheia = capturarStdout([&]() {
        for (int i = 0; i < 16; ++i)
        {
            auto pkt = criarPacoteIpv4Valido(0x0A00010A, 0x0A00030A, 63, 1);
            assert(resolver.sendOrQueue(nextHop, eth1, pkt, inicio) == ArpPacketStatus::Queued);
        }
        auto pkt17 = criarPacoteIpv4Valido(0x0A00010B, 0x0A00030B, 63, 6);
        assert(resolver.sendOrQueue(nextHop, eth1, pkt17, inicio) == ArpPacketStatus::QueueFull);
    });
    assert(saidaFilaCheia.find("\"motivo\": \"fila_arp\"") != std::string::npos);
    assert(saidaFilaCheia.find("\"origem\": \"10.0.1.11\"") != std::string::npos);
    assert(saidaFilaCheia.find("\"destino\": \"10.0.3.11\"") != std::string::npos);
    assert(saidaFilaCheia.find("\"protocolo\": 6") != std::string::npos);

    // Timeout de 3s -> gera arp_falhou + descarte "arp"
    std::string saidaTimeout = capturarStdout([&]() {
        resolver.processTimeouts(inicio + std::chrono::seconds(3));
    });
    assert(saidaTimeout.find("\"evento\": \"arp_falhou\"") != std::string::npos);
    assert(saidaTimeout.find("\"motivo\": \"arp\"") != std::string::npos);
    assert(saidaTimeout.find("\"origem\": \"10.0.1.10\"") != std::string::npos);
    assert(saidaTimeout.find("\"destino\": \"10.0.3.10\"") != std::string::npos);
    assert(saidaTimeout.find("\"protocolo\": 1") != std::string::npos);
}

int main()
{
    testaFormatacaoIpEMac();
    testaLogInicio();
    testaLogsArp();
    testaIntegracaoCacheArp();
    testaDescartesProcessIpv4();
    testaDescartesArpEFilaArp();

    std::cout << "Todos os testes de logger e descarte passaram.\n";
    return 0;
}