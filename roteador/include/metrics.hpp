#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <string_view>

struct MetricsSnapshot {
    std::uint64_t quadros_recebidos_eth0 = 0;
    std::uint64_t quadros_enviados_eth0 = 0;
    std::uint64_t quadros_recebidos_eth1 = 0;
    std::uint64_t quadros_enviados_eth1 = 0;
    std::uint64_t quadros_recebidos_mgmt0 = 0;
    std::uint64_t quadros_enviados_mgmt0 = 0;

    std::uint64_t pacotes_encaminhados = 0;
    std::uint64_t icmp_gerados = 0;
    std::uint64_t respostas_http = 0;

    std::uint64_t arp_entradas = 0;
    std::uint64_t arp_pendentes = 0;

    std::uint64_t descartes_quadro = 0;
    std::uint64_t descartes_cabecalho = 0;
    std::uint64_t descartes_ttl = 0;
    std::uint64_t descartes_sem_rota = 0;
    std::uint64_t descartes_arp = 0;
    std::uint64_t descartes_fila_arp = 0;
    std::uint64_t descartes_filtro = 0;
    std::uint64_t descartes_local = 0;
};

class RouterMetrics {
public:
    RouterMetrics() = default;

    void incQuadrosRecebidos(std::string_view iface, std::uint64_t delta = 1);
    void incQuadrosEnviados(std::string_view iface, std::uint64_t delta = 1);

    void incPacotesEncaminhados(std::uint64_t delta = 1);
    void incIcmpGerados(std::uint64_t delta = 1);
    void incRespostasHttp(std::uint64_t delta = 1);

    void incDescartesQuadro(std::uint64_t delta = 1);
    void incDescartesCabecalho(std::uint64_t delta = 1);
    void incDescartesTtl(std::uint64_t delta = 1);
    void incDescartesSemRota(std::uint64_t delta = 1);
    void incDescartesArp(std::uint64_t delta = 1);
    void incDescartesFilaArp(std::uint64_t delta = 1);
    void incDescartesFiltro(std::uint64_t delta = 1);
    void incDescartesLocal(std::uint64_t delta = 1);

    void incDescartePorMotivo(std::string_view motivo, std::uint64_t delta = 1);

    MetricsSnapshot snapshot(std::uint64_t arpEntries, std::uint64_t arpPendingPackets) const;
    std::string renderPrometheus(std::uint64_t arpEntries, std::uint64_t arpPendingPackets) const;

private:
    std::atomic<std::uint64_t> quadros_recebidos_eth0_{0};
    std::atomic<std::uint64_t> quadros_enviados_eth0_{0};
    std::atomic<std::uint64_t> quadros_recebidos_eth1_{0};
    std::atomic<std::uint64_t> quadros_enviados_eth1_{0};
    std::atomic<std::uint64_t> quadros_recebidos_mgmt0_{0};
    std::atomic<std::uint64_t> quadros_enviados_mgmt0_{0};

    std::atomic<std::uint64_t> pacotes_encaminhados_{0};
    std::atomic<std::uint64_t> icmp_gerados_{0};
    std::atomic<std::uint64_t> respostas_http_{0};

    std::atomic<std::uint64_t> descartes_quadro_{0};
    std::atomic<std::uint64_t> descartes_cabecalho_{0};
    std::atomic<std::uint64_t> descartes_ttl_{0};
    std::atomic<std::uint64_t> descartes_sem_rota_{0};
    std::atomic<std::uint64_t> descartes_arp_{0};
    std::atomic<std::uint64_t> descartes_fila_arp_{0};
    std::atomic<std::uint64_t> descartes_filtro_{0};
    std::atomic<std::uint64_t> descartes_local_{0};
};

RouterMetrics& globalMetrics();
