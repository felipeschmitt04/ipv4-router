#include "../include/config.hpp"
#include "../include/interface.hpp"
#include "../include/routing.hpp"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <sys/wait.h>
#include <unistd.h>

using namespace std;

namespace
{
    string writeTempConf(const string &content)
    {
        static int counter = 0;
        string path = "/tmp/test_router_" + to_string(getpid()) + "_" + to_string(++counter) + ".conf";
        ofstream out(path);
        assert(out.is_open());
        out << content;
        out.close();
        return path;
    }

    void expectConfigFails(const string &content, const string &caseName)
    {
        string path = writeTempConf(content);

        pid_t pid = fork();
        assert(pid >= 0);

        if (pid == 0)
        {
            FILE *nullOut = freopen("/dev/null", "w", stderr);
            (void)nullOut;
            loadConfig(path);
            _exit(0);
        }

        int status = 0;
        assert(waitpid(pid, &status, 0) == pid);
        remove(path.c_str());

        if (!WIFEXITED(status) || WEXITSTATUS(status) == 0)
        {
            cerr << "FALHA: caso invalido nao foi rejeitado -> " << caseName << endl;
            exit(1);
        }
    }

    void testRealConfigFiles()
    {
        loadConfig("../configuracao/r1.conf");
        assert(routerName == "r1");
        assert(allInterfaces.size() == 3);
        assert(routeTable.size() == 2);
        assert(filterRules.size() == 1);
        assert(filterRules[0].ruleNumber == 1);
        assert(filterRules[0].action == FilterAction::Negar);
        assert(filterRules[0].protocol == 17);
        assert(!filterRules[0].anySrc);
        assert(!filterRules[0].anyDst);
        assert(filterRules[0].dstPort == 53);

        loadConfig("../configuracao/r2.conf");
        assert(routerName == "r2");
        assert(allInterfaces.size() == 3);
        assert(routeTable.size() == 2);
        assert(filterRules.empty());

        loadConfig("../configuracao/r3.conf");
        assert(routerName == "r3");
        assert(allInterfaces.size() == 3);
        assert(routeTable.size() == 2);
        assert(filterRules.empty());
    }

    void testValidCompleteConfig()
    {
        string conf =
            "# Comentario inicial\n"
            "   \n"
            "  nome   roteador-teste   # comentario inline\n"
            "interface eth0 10.0.1.1/24 02:00:00:00:01:00\n"
            "interface eth1 10.0.2.1/30 02:00:00:00:01:01\n"
            "gerencia mgmt0 192.168.100.1/24 02:00:00:00:01:ff\n"
            "rota 0.0.0.0/0 via 10.0.2.2\n"
            "rota 172.16.0.0/16 via 10.0.1.254\n"
            "filtro permitir icmp 10.0.1.0/24 10.0.2.0/30 *\n"
            "filtro negar udp 10.0.1.0/24 * 5353\n"
            "filtro negar * * 10.0.0.0/8 *\n";

        string path = writeTempConf(conf);
        loadConfig(path);
        remove(path.c_str());

        assert(routerName == "roteador-teste");
        assert(allInterfaces.size() == 3);
        assert(routeTable.size() == 2);
        assert(routeTable[0].destinationNetwork == 0u);
        assert(routeTable[0].prefixLenght == 0);
        assert(routeTable[0].interfaceName == "eth1");

        assert(filterRules.size() == 3);
        assert(filterRules[0].ruleNumber == 1);
        assert(filterRules[0].action == FilterAction::Permitir);
        assert(filterRules[0].protocol == 1);
        assert(!filterRules[0].anySrc && !filterRules[0].anyDst);
        assert(filterRules[0].dstPort == 0);

        assert(filterRules[1].ruleNumber == 2);
        assert(filterRules[1].action == FilterAction::Negar);
        assert(filterRules[1].protocol == 17);
        assert(!filterRules[1].anySrc && filterRules[1].anyDst);
        assert(filterRules[1].dstPort == 5353);

        assert(filterRules[2].ruleNumber == 3);
        assert(filterRules[2].protocol == 0);
        assert(filterRules[2].anySrc && !filterRules[2].anyDst);
        assert(filterRules[2].dstPort == 0);
    }

    void testInvalidCases()
    {
        expectConfigFails(
            "interface eth0 10.0.1.1/24 02:00:00:00:01:00\n"
            "gerencia mgmt0 192.168.100.1/24 02:00:00:00:01:ff\n",
            "sem diretiva nome");

        expectConfigFails(
            "nome r1\n"
            "nome r2\n"
            "interface eth0 10.0.1.1/24 02:00:00:00:01:00\n"
            "gerencia mgmt0 192.168.100.1/24 02:00:00:00:01:ff\n",
            "nome duplicado");

        expectConfigFails(
            "nome r1\n"
            "interface eth0 10.0.1.1/24 02:00:00:00:01:00\n",
            "sem diretiva gerencia");

        expectConfigFails(
            "nome r1\n"
            "interface eth0 10.0.1.1/24 02:00:00:00:01:00\n"
            "gerencia mgmt0 192.168.100.1/24 02:00:00:00:01:ff\n"
            "gerencia mgmt0 192.168.101.1/24 02:00:00:00:01:fe\n",
            "gerencia duplicada");

        expectConfigFails(
            "nome r1\n"
            "gerencia mgmt0 192.168.100.1/24 02:00:00:00:01:ff\n",
            "zero interfaces de dados");

        expectConfigFails(
            "nome r1\n"
            "interface eth0 10.0.1.1/24 02:00:00:00:01:00\n"
            "interface eth1 10.0.2.1/24 02:00:00:00:01:01\n"
            "interface eth2 10.0.3.1/24 02:00:00:00:01:02\n"
            "interface eth3 10.0.4.1/24 02:00:00:00:01:03\n"
            "interface eth4 10.0.5.1/24 02:00:00:00:01:04\n"
            "interface eth5 10.0.6.1/24 02:00:00:00:01:05\n"
            "interface eth6 10.0.7.1/24 02:00:00:00:01:06\n"
            "interface eth7 10.0.8.1/24 02:00:00:00:01:07\n"
            "interface eth8 10.0.9.1/24 02:00:00:00:01:08\n"
            "gerencia mgmt0 192.168.100.1/24 02:00:00:00:01:ff\n",
            "mais de 8 interfaces");

        expectConfigFails(
            "nome r1\n"
            "interface eth0 10.0.1.1/24 02:00:00:00:01:00\n"
            "interface eth0 10.0.2.1/24 02:00:00:00:01:01\n"
            "gerencia mgmt0 192.168.100.1/24 02:00:00:00:01:ff\n",
            "nome de interface duplicado");

        expectConfigFails(
            "nome r1\n"
            "interface eth0 10.0.1.1/24 02:00:00:00:01:00\n"
            "interface eth1 10.0.1.1/24 02:00:00:00:01:01\n"
            "gerencia mgmt0 192.168.100.1/24 02:00:00:00:01:ff\n",
            "IP duplicado");

        expectConfigFails(
            "nome r1\n"
            "interface eth0 10.0.1.1/24 02:00:00:00:01:00\n"
            "interface eth1 10.0.2.1/24 02:00:00:00:01:00\n"
            "gerencia mgmt0 192.168.100.1/24 02:00:00:00:01:ff\n",
            "MAC duplicado");

        expectConfigFails(
            "nome r1\n"
            "interface eth0 10.0.1.1/24 02:00:00:00:01:AA\n"
            "gerencia mgmt0 192.168.100.1/24 02:00:00:00:01:ff\n",
            "MAC com letras maiusculas");

        expectConfigFails(
            "nome r1\n"
            "interface eth0 10.0.1.1/31 02:00:00:00:01:00\n"
            "gerencia mgmt0 192.168.100.1/24 02:00:00:00:01:ff\n",
            "prefixo /31");

        expectConfigFails(
            "nome r1\n"
            "interface eth0 10.0.0.1/16 02:00:00:00:01:00\n"
            "interface eth1 10.0.1.1/24 02:00:00:00:01:01\n"
            "gerencia mgmt0 192.168.100.1/24 02:00:00:00:01:ff\n",
            "sobreposicao de redes");

        expectConfigFails(
            "nome r1\n"
            "interface eth0 10.0.1.0/24 02:00:00:00:01:00\n"
            "gerencia mgmt0 192.168.100.1/24 02:00:00:00:01:ff\n",
            "IP de rede");

        expectConfigFails(
            "nome r1\n"
            "interface eth0 10.0.1.255/24 02:00:00:00:01:00\n"
            "gerencia mgmt0 192.168.100.1/24 02:00:00:00:01:ff\n",
            "IP de broadcast");

        expectConfigFails(
            "nome r1\n"
            "interface eth0 10.0.1.1/24 02:00:00:00:01:00\n"
            "gerencia mgmt0 192.168.100.1/24 02:00:00:00:01:ff\n"
            "rota 10.0.4.5/24 via 10.0.1.2\n",
            "rota com bits de host");

        expectConfigFails(
            "nome r1\n"
            "interface eth0 10.0.1.1/24 02:00:00:00:01:00\n"
            "gerencia mgmt0 192.168.100.1/24 02:00:00:00:01:ff\n"
            "rota 10.0.4.0/24 via 10.0.1.2\n"
            "rota 10.0.4.0/24 via 10.0.1.3\n",
            "rota com prefixo duplicado");

        expectConfigFails(
            "nome r1\n"
            "interface eth0 10.0.1.1/24 02:00:00:00:01:00\n"
            "gerencia mgmt0 192.168.100.1/24 02:00:00:00:01:ff\n"
            "rota 10.0.4.0/24 via 192.168.100.2\n",
            "next hop na rede mgmt0");

        expectConfigFails(
            "nome r1\n"
            "interface eth0 10.0.1.1/24 02:00:00:00:01:00\n"
            "gerencia mgmt0 192.168.100.1/24 02:00:00:00:01:ff\n"
            "rota 10.0.4.0/24 via 10.0.1.1\n",
            "next hop igual ao IP do roteador");

        expectConfigFails(
            "nome r1\n"
            "interface eth0 10.0.1.1/24 02:00:00:00:01:00\n"
            "gerencia mgmt0 192.168.100.1/24 02:00:00:00:01:ff\n"
            "filtro negar udp 10.0.1.0/24 10.0.4.0/24\n",
            "filtro sem campo porta");

        expectConfigFails(
            "nome r1\n"
            "interface eth0 10.0.1.1/24 02:00:00:00:01:00\n"
            "gerencia mgmt0 192.168.100.1/24 02:00:00:00:01:ff\n"
            "filtro bloquear udp 10.0.1.0/24 10.0.4.0/24 53\n",
            "filtro com acao invalida");

        expectConfigFails(
            "nome r1\n"
            "interface eth0 10.0.1.1/24 02:00:00:00:01:00\n"
            "gerencia mgmt0 192.168.100.1/24 02:00:00:00:01:ff\n"
            "filtro negar tcp 10.0.1.0/24 10.0.4.0/24 80\n",
            "filtro com protocolo tcp");

        expectConfigFails(
            "nome r1\n"
            "interface eth0 10.0.1.1/24 02:00:00:00:01:00\n"
            "gerencia mgmt0 192.168.100.1/24 02:00:00:00:01:ff\n"
            "filtro negar icmp 10.0.1.0/24 10.0.4.0/24 53\n",
            "filtro icmp com porta numerica");

        expectConfigFails(
            "nome r1\n"
            "interface eth0 10.0.1.1/24 02:00:00:00:01:00\n"
            "gerencia mgmt0 192.168.100.1/24 02:00:00:00:01:ff\n"
            "filtro negar udp 10.0.1.0/24 10.0.4.0/24 0\n",
            "filtro udp com porta 0");

        expectConfigFails(
            "nome r1\n"
            "interface eth0 10.0.1.1/24 02:00:00:00:01:00\n"
            "gerencia mgmt0 192.168.100.1/24 02:00:00:00:01:ff\n"
            "filtro negar udp 10.0.1.0/24 10.0.4.0/24 65536\n",
            "filtro udp com porta > 65535");
    }
} // namespace

int main()
{
    testRealConfigFiles();
    testValidCompleteConfig();
    testInvalidCases();
    cout << "Todos os testes de leitura e validacao de configuracao passaram." << endl;
    return 0;
}