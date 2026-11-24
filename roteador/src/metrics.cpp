#include "metrics.hpp"

#include <sstream>

namespace {

void addCounter(std::atomic<std::uint64_t>& counter, std::uint64_t delta) {
    if (delta == 0) {
        return;
    }
    counter.fetch_add(delta, std::memory_order_relaxed);
}

void appendMetric(
    std::ostringstream& out,
    const char* name,
    const char* type,
    std::uint64_t value
) {
    out << "# TYPE " << name << " " << type << "\n";
    out << name << " " << value << "\n";
}

} // namespace

void RouterMetrics::incQuadrosRecebidos(std::string_view iface, std::uint64_t delta) {
    if (iface == "eth0") {
        addCounter(quadros_recebidos_eth0_, delta);
    } else if (iface == "eth1") {
        addCounter(quadros_recebidos_eth1_, delta);
    } else if (iface == "mgmt0") {
        addCounter(quadros_recebidos_mgmt0_, delta);
    }
}

void RouterMetrics::incQuadrosEnviados(std::string_view iface, std::uint64_t delta) {
    if (iface == "eth0") {
        addCounter(quadros_enviados_eth0_, delta);
    } else if (iface == "eth1") {
        addCounter(quadros_enviados_eth1_, delta);
    } else if (iface == "mgmt0") {
        addCounter(quadros_enviados_mgmt0_, delta);
    }
}

void RouterMetrics::incPacotesEncaminhados(std::uint64_t delta) {
    addCounter(pacotes_encaminhados_, delta);
}

void RouterMetrics::incIcmpGerados(std::uint64_t delta) {
    addCounter(icmp_gerados_, delta);
}

void RouterMetrics::incRespostasHttp(std::uint64_t delta) {
    addCounter(respostas_http_, delta);
}

void RouterMetrics::setArpEntradas(std::uint64_t value) {
    arp_entradas_.store(value, std::memory_order_relaxed);
}

void RouterMetrics::setArpPendentes(std::uint64_t value) {
    arp_pendentes_.store(value, std::memory_order_relaxed);
}

void RouterMetrics::incDescartesQuadro(std::uint64_t delta) {
    addCounter(descartes_quadro_, delta);
}

void RouterMetrics::incDescartesCabecalho(std::uint64_t delta) {
    addCounter(descartes_cabecalho_, delta);
}

void RouterMetrics::incDescartesTtl(std::uint64_t delta) {
    addCounter(descartes_ttl_, delta);
}

void RouterMetrics::incDescartesSemRota(std::uint64_t delta) {
    addCounter(descartes_sem_rota_, delta);
}

void RouterMetrics::incDescartesArp(std::uint64_t delta) {
    addCounter(descartes_arp_, delta);
}

void RouterMetrics::incDescartesFilaArp(std::uint64_t delta) {
    addCounter(descartes_fila_arp_, delta);
}

void RouterMetrics::incDescartesFiltro(std::uint64_t delta) {
    addCounter(descartes_filtro_, delta);
}

void RouterMetrics::incDescartesLocal(std::uint64_t delta) {
    addCounter(descartes_local_, delta);
}

void RouterMetrics::incDescartePorMotivo(std::string_view motivo, std::uint64_t delta) {
    if (motivo == "quadro") {
        incDescartesQuadro(delta);
    } else if (motivo == "cabecalho") {
        incDescartesCabecalho(delta);
    } else if (motivo == "ttl") {
        incDescartesTtl(delta);
    } else if (motivo == "sem_rota") {
        incDescartesSemRota(delta);
    } else if (motivo == "arp") {
        incDescartesArp(delta);
    } else if (motivo == "fila_arp") {
        incDescartesFilaArp(delta);
    } else if (motivo == "filtro") {
        incDescartesFiltro(delta);
    } else if (motivo == "local") {
        incDescartesLocal(delta);
    }
}

MetricsSnapshot RouterMetrics::snapshot() const {
    MetricsSnapshot s;
    s.quadros_recebidos_eth0 = quadros_recebidos_eth0_.load(std::memory_order_relaxed);
    s.quadros_enviados_eth0 = quadros_enviados_eth0_.load(std::memory_order_relaxed);
    s.quadros_recebidos_eth1 = quadros_recebidos_eth1_.load(std::memory_order_relaxed);
    s.quadros_enviados_eth1 = quadros_enviados_eth1_.load(std::memory_order_relaxed);
    s.quadros_recebidos_mgmt0 = quadros_recebidos_mgmt0_.load(std::memory_order_relaxed);
    s.quadros_enviados_mgmt0 = quadros_enviados_mgmt0_.load(std::memory_order_relaxed);

    s.pacotes_encaminhados = pacotes_encaminhados_.load(std::memory_order_relaxed);
    s.icmp_gerados = icmp_gerados_.load(std::memory_order_relaxed);
    s.respostas_http = respostas_http_.load(std::memory_order_relaxed);

    s.arp_entradas = arp_entradas_.load(std::memory_order_relaxed);
    s.arp_pendentes = arp_pendentes_.load(std::memory_order_relaxed);

    s.descartes_quadro = descartes_quadro_.load(std::memory_order_relaxed);
    s.descartes_cabecalho = descartes_cabecalho_.load(std::memory_order_relaxed);
    s.descartes_ttl = descartes_ttl_.load(std::memory_order_relaxed);
    s.descartes_sem_rota = descartes_sem_rota_.load(std::memory_order_relaxed);
    s.descartes_arp = descartes_arp_.load(std::memory_order_relaxed);
    s.descartes_fila_arp = descartes_fila_arp_.load(std::memory_order_relaxed);
    s.descartes_filtro = descartes_filtro_.load(std::memory_order_relaxed);
    s.descartes_local = descartes_local_.load(std::memory_order_relaxed);
    return s;
}

std::string RouterMetrics::renderPrometheus() const {
    const MetricsSnapshot s = snapshot();
    std::ostringstream out;

    appendMetric(out, "quadros_recebidos_eth0", "counter", s.quadros_recebidos_eth0);
    appendMetric(out, "quadros_enviados_eth0", "counter", s.quadros_enviados_eth0);
    appendMetric(out, "quadros_recebidos_eth1", "counter", s.quadros_recebidos_eth1);
    appendMetric(out, "quadros_enviados_eth1", "counter", s.quadros_enviados_eth1);
    appendMetric(out, "quadros_recebidos_mgmt0", "counter", s.quadros_recebidos_mgmt0);
    appendMetric(out, "quadros_enviados_mgmt0", "counter", s.quadros_enviados_mgmt0);

    appendMetric(out, "pacotes_encaminhados", "counter", s.pacotes_encaminhados);
    appendMetric(out, "icmp_gerados", "counter", s.icmp_gerados);
    appendMetric(out, "respostas_http", "counter", s.respostas_http);

    appendMetric(out, "arp_entradas", "gauge", s.arp_entradas);
    appendMetric(out, "arp_pendentes", "gauge", s.arp_pendentes);

    appendMetric(out, "descartes_quadro", "counter", s.descartes_quadro);
    appendMetric(out, "descartes_cabecalho", "counter", s.descartes_cabecalho);
    appendMetric(out, "descartes_ttl", "counter", s.descartes_ttl);
    appendMetric(out, "descartes_sem_rota", "counter", s.descartes_sem_rota);
    appendMetric(out, "descartes_arp", "counter", s.descartes_arp);
    appendMetric(out, "descartes_fila_arp", "counter", s.descartes_fila_arp);
    appendMetric(out, "descartes_filtro", "counter", s.descartes_filtro);
    appendMetric(out, "descartes_local", "counter", s.descartes_local);

    return out.str();
}

RouterMetrics& globalMetrics() {
    static RouterMetrics instance;
    return instance;
}