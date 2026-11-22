#include "../include/logger.hpp"

#include <chrono>
#include <cstdio>
#include <mutex>

namespace {
std::mutex logMutex;

double currentUnixTimestamp() {
    using namespace std::chrono;
    const auto now = system_clock::now().time_since_epoch();
    const auto ms = duration_cast<milliseconds>(now).count();
    return static_cast<double>(ms) / 1000.0;
}
} // namespace

std::string formatIp(uint32_t ip) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                  (ip >> 24) & 0xFFu,
                  (ip >> 16) & 0xFFu,
                  (ip >> 8) & 0xFFu,
                  ip & 0xFFu);
    return std::string(buf);
}

std::string formatMacLower(const std::array<uint8_t, 6>& mac) {
    char buf[18];
    std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

void logInicio(const std::string& nomeRoteador) {
    std::lock_guard<std::mutex> lock(logMutex);
    std::printf("{\"t\": %.3f, \"evento\": \"inicio\", \"roteador\": \"%s\"}\n",
                currentUnixTimestamp(),
                nomeRoteador.c_str());
    std::fflush(stdout);
}

void logArpAprendido(uint32_t ip, const std::array<uint8_t, 6>& mac, const std::string& interfaceName) {
    std::lock_guard<std::mutex> lock(logMutex);
    std::printf("{\"t\": %.3f, \"evento\": \"arp_aprendido\", \"ip\": \"%s\", \"mac\": \"%s\", \"interface\": \"%s\"}\n",
                currentUnixTimestamp(),
                formatIp(ip).c_str(),
                formatMacLower(mac).c_str(),
                interfaceName.c_str());
    std::fflush(stdout);
}

void logArpExpirado(uint32_t ip) {
    std::lock_guard<std::mutex> lock(logMutex);
    std::printf("{\"t\": %.3f, \"evento\": \"arp_expirado\", \"ip\": \"%s\"}\n",
                currentUnixTimestamp(),
                formatIp(ip).c_str());
    std::fflush(stdout);
}

void logArpFalhou(uint32_t ip, const std::string& interfaceName) {
    std::lock_guard<std::mutex> lock(logMutex);
    std::printf("{\"t\": %.3f, \"evento\": \"arp_falhou\", \"ip\": \"%s\", \"interface\": \"%s\"}\n",
                currentUnixTimestamp(),
                formatIp(ip).c_str(),
                interfaceName.c_str());
    std::fflush(stdout);
}

void logDescarte(const std::string& motivo, uint32_t origem, uint32_t destino, uint8_t protocolo) {
    std::lock_guard<std::mutex> lock(logMutex);
    std::printf("{\"t\": %.3f, \"evento\": \"descarte\", \"motivo\": \"%s\", \"origem\": \"%s\", \"destino\": \"%s\", \"protocolo\": %u}\n",
                currentUnixTimestamp(),
                motivo.c_str(),
                formatIp(origem).c_str(),
                formatIp(destino).c_str(),
                static_cast<unsigned int>(protocolo));
    std::fflush(stdout);
}

void logDescarteFiltro(uint32_t origem, uint32_t destino, uint8_t protocolo, std::size_t regra) {
    std::lock_guard<std::mutex> lock(logMutex);
    std::printf("{\"t\": %.3f, \"evento\": \"descarte\", \"motivo\": \"filtro\", \"origem\": \"%s\", \"destino\": \"%s\", \"protocolo\": %u, \"regra\": %zu}\n",
                currentUnixTimestamp(),
                formatIp(origem).c_str(),
                formatIp(destino).c_str(),
                static_cast<unsigned int>(protocolo),
                regra);
    std::fflush(stdout);
}