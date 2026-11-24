#include "../include/metrics.hpp"

#include <cassert>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace {

void testInitialZeroesAndOrder() {
    RouterMetrics m;
    const std::string expected =
        "# TYPE quadros_recebidos_eth0 counter\n"
        "quadros_recebidos_eth0 0\n"
        "# TYPE quadros_enviados_eth0 counter\n"
        "quadros_enviados_eth0 0\n"
        "# TYPE quadros_recebidos_eth1 counter\n"
        "quadros_recebidos_eth1 0\n"
        "# TYPE quadros_enviados_eth1 counter\n"
        "quadros_enviados_eth1 0\n"
        "# TYPE quadros_recebidos_mgmt0 counter\n"
        "quadros_recebidos_mgmt0 0\n"
        "# TYPE quadros_enviados_mgmt0 counter\n"
        "quadros_enviados_mgmt0 0\n"
        "# TYPE pacotes_encaminhados counter\n"
        "pacotes_encaminhados 0\n"
        "# TYPE icmp_gerados counter\n"
        "icmp_gerados 0\n"
        "# TYPE respostas_http counter\n"
        "respostas_http 0\n"
        "# TYPE arp_entradas gauge\n"
        "arp_entradas 0\n"
        "# TYPE arp_pendentes gauge\n"
        "arp_pendentes 0\n"
        "# TYPE descartes_quadro counter\n"
        "descartes_quadro 0\n"
        "# TYPE descartes_cabecalho counter\n"
        "descartes_cabecalho 0\n"
        "# TYPE descartes_ttl counter\n"
        "descartes_ttl 0\n"
        "# TYPE descartes_sem_rota counter\n"
        "descartes_sem_rota 0\n"
        "# TYPE descartes_arp counter\n"
        "descartes_arp 0\n"
        "# TYPE descartes_fila_arp counter\n"
        "descartes_fila_arp 0\n"
        "# TYPE descartes_filtro counter\n"
        "descartes_filtro 0\n"
        "# TYPE descartes_local counter\n"
        "descartes_local 0\n";

    assert(m.renderPrometheus(0, 0) == expected);
}

void testCountersGaugesAndSizeLimit() {
    RouterMetrics m;
    m.incQuadrosRecebidos("eth0", 2);
    m.incQuadrosEnviados("eth1", 3);
    m.incQuadrosRecebidos("mgmt0");
    m.incPacotesEncaminhados(5);
    m.incIcmpGerados(2);
    m.incRespostasHttp(1);

    const auto before = m.snapshot(4, 2);
    assert(before.arp_entradas == 4);
    assert(before.arp_pendentes == 2);

    m.incDescartePorMotivo("ttl");
    m.incDescartePorMotivo("filtro", 2);

    const MetricsSnapshot s = m.snapshot(1, 0);
    assert(s.quadros_recebidos_eth0 == 2);
    assert(s.quadros_enviados_eth1 == 3);
    assert(s.quadros_recebidos_mgmt0 == 1);
    assert(s.pacotes_encaminhados == 5);
    assert(s.icmp_gerados == 2);
    assert(s.respostas_http == 1);
    assert(s.arp_entradas == 1);
    assert(s.arp_pendentes == 0);
    assert(s.descartes_ttl == 1);
    assert(s.descartes_filtro == 2);

    const std::string body = m.renderPrometheus(1, 0);
    assert(body.find("arp_entradas 1\n") != std::string::npos);
    assert(body.find("arp_pendentes 0\n") != std::string::npos);
    assert(body.find("descartes_filtro 2\n") != std::string::npos);
    assert(body.size() < 1472);
}

void testConcurrentIncrements() {
    RouterMetrics m;
    constexpr int numThreads = 4;
    constexpr int iterations = 10000;

    std::vector<std::thread> threads;
    threads.reserve(numThreads);
    for (int i = 0; i < numThreads; ++i) {
        threads.emplace_back([&m]() {
            for (int j = 0; j < iterations; ++j) {
                m.incPacotesEncaminhados();
                m.incDescartesLocal();
            }
        });
    }
    for (auto& t : threads) {
        t.join();
    }

    const MetricsSnapshot s = m.snapshot(0, 0);
    assert(s.pacotes_encaminhados == numThreads * iterations);
    assert(s.descartes_local == numThreads * iterations);
}

} // namespace

int main() {
    testInitialZeroesAndOrder();
    testCountersGaugesAndSizeLimit();
    testConcurrentIncrements();
    std::cout << "test_metrics: todos os testes passaram!\n";
    return 0;
}
