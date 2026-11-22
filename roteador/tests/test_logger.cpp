#include "../include/logger.hpp"
#include "../include/arp.hpp"
#include <unistd.h>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

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

void testaLogsDescarte()
{
    std::string descarteTtl = capturarStdout([]() {
        logDescarte("ttl", 0x0A00010A, 0x0A000214, 1);
    });
    assert(descarteTtl.find("\"evento\": \"descarte\"") != std::string::npos);
    assert(descarteTtl.find("\"motivo\": \"ttl\"") != std::string::npos);
    assert(descarteTtl.find("\"origem\": \"10.0.1.10\"") != std::string::npos);
    assert(descarteTtl.find("\"destino\": \"10.0.2.20\"") != std::string::npos);
    assert(descarteTtl.find("\"protocolo\": 1") != std::string::npos);

    std::string descarteFiltro = capturarStdout([]() {
        logDescarteFiltro(0x0A00010A, 0x0A000214, 17, 2);
    });
    assert(descarteFiltro.find("\"motivo\": \"filtro\"") != std::string::npos);
    assert(descarteFiltro.find("\"protocolo\": 17") != std::string::npos);
    assert(descarteFiltro.find("\"regra\": 2") != std::string::npos);
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

int main()
{
    testaFormatacaoIpEMac();
    testaLogInicio();
    testaLogsArp();
    testaLogsDescarte();
    testaIntegracaoCacheArp();

    std::cout << "Todos os testes de logger passaram.\n";
    return 0;
}