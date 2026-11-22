#pragma once

#include <array>
#include <cstdint>
#include <string>

// Formata IP uint32_t (host order) para "a.b.c.d"
std::string formatIp(uint32_t ip);

// Formata MAC para "xx:xx:xx:xx:xx:xx" em minúsculo
std::string formatMacLower(const std::array<uint8_t, 6>& mac);

// 1. Início do roteador
void logInicio(const std::string& nomeRoteador);

// 2. ARP aprendido (criação ou atualização)
void logArpAprendido(uint32_t ip, const std::array<uint8_t, 6>& mac, const std::string& interfaceName);

// 3. ARP expirado (após 30s)
void logArpExpirado(uint32_t ip);

// 4. Falha de ARP (após 3s sem resposta)
void logArpFalhou(uint32_t ip, const std::string& interfaceName);

// 5. Descarte de pacote IPv4 (ttl, sem_rota, arp, fila_arp, local)
void logDescarte(const std::string& motivo, uint32_t origem, uint32_t destino, uint8_t protocolo);

// 6. Descarte por regra de filtro (regra começa em 1)
void logDescarteFiltro(uint32_t origem, uint32_t destino, uint8_t protocolo, std::size_t regra);