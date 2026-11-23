#include "../include/config.hpp"
#include "../include/interface.hpp"
#include "../include/routing.hpp"

#include <fstream>
#include <sstream>
#include <iostream>
#include <utility>
#include <set>
#include <algorithm>
#include <cctype>
#include <arpa/inet.h>
#include <cstdlib>

using namespace std;

extern vector<interface> allInterfaces;
extern vector<Route> routeTable;

string routerName;
vector<FilterRule> filterRules;

namespace
{
    [[noreturn]] void configError(const string &msg, size_t lineNum = 0)
    {
        if (lineNum > 0)
        {
            cerr << "Erro de configuracao (linha " << lineNum << "): " << msg << endl;
        }
        else
        {
            cerr << "Erro de configuracao: " << msg << endl;
        }
        exit(1);
    }

    string trim(const string &s)
    {
        size_t start = 0;
        while (start < s.size() && isspace(static_cast<unsigned char>(s[start])))
        {
            ++start;
        }
        size_t end = s.size();
        while (end > start && isspace(static_cast<unsigned char>(s[end - 1])))
        {
            --end;
        }
        return s.substr(start, end - start);
    }

    uint32_t prefixToMask(uint8_t prefix)
    {
        if (prefix == 0)
        {
            return 0u;
        }
        return 0xFFFFFFFFu << (32 - prefix);
    }

    bool parseStrictInt(const string &str, int &outValue)
    {
        if (str.empty())
        {
            return false;
        }
        for (size_t i = 0; i < str.size(); ++i)
        {
            if (i == 0 && (str[i] == '+' || str[i] == '-'))
            {
                if (str.size() == 1)
                {
                    return false;
                }
                continue;
            }
            if (!isdigit(static_cast<unsigned char>(str[i])))
            {
                return false;
            }
        }
        try
        {
            size_t idx = 0;
            long val = stol(str, &idx, 10);
            if (idx != str.size() || val < -2147483648L || val > 2147483647L)
            {
                return false;
            }
            outValue = static_cast<int>(val);
            return true;
        }
        catch (...)
        {
            return false;
        }
    }

    uint32_t parseIPv4Strict(const string &ip, size_t lineNum = 0)
    {
        in_addr endereco{};
        if (ip.empty() || inet_pton(AF_INET, ip.c_str(), &endereco) != 1)
        {
            configError("Endereco IPv4 invalido: '" + ip + "'", lineNum);
        }
        return ntohl(endereco.s_addr);
    }

    pair<uint32_t, uint8_t> parseCIDR(
        const string &cidrStr,
        int minPrefix,
        int maxPrefix,
        bool requireZeroHostBits,
        size_t lineNum)
    {
        size_t slashPos = cidrStr.find('/');
        if (slashPos == string::npos || cidrStr.find('/', slashPos + 1) != string::npos)
        {
            configError("Notacao CIDR invalida (esperado IP/prefixo): '" + cidrStr + "'", lineNum);
        }

        string ipPart = cidrStr.substr(0, slashPos);
        string prefixPart = cidrStr.substr(slashPos + 1);

        uint32_t ipVal = parseIPv4Strict(ipPart, lineNum);

        int prefixVal = 0;
        if (!parseStrictInt(prefixPart, prefixVal) || prefixVal < minPrefix || prefixVal > maxPrefix)
        {
            configError("Prefixo fora do intervalo permitido (" +
                            to_string(minPrefix) + ".." + to_string(maxPrefix) +
                            "): '" + cidrStr + "'",
                        lineNum);
        }

        uint8_t prefix = static_cast<uint8_t>(prefixVal);
        uint32_t mask = prefixToMask(prefix);

        if (requireZeroHostBits && ((ipVal & ~mask) != 0u))
        {
            configError("Bits de host devem ser zerados para o prefixo: '" + cidrStr + "'", lineNum);
        }

        return {ipVal, prefix};
    }

    bool validaCharHexLower(char caractere)
    {
        return (caractere >= '0' && caractere <= '9') ||
               (caractere >= 'a' && caractere <= 'f');
    }

    array<uint8_t, 6> parseMACStrict(const string &mac, size_t lineNum = 0)
    {
        if (mac.empty() || mac.front() == ':' || mac.back() == ':')
        {
            configError("Endereco MAC invalido: '" + mac + "'", lineNum);
        }

        array<uint8_t, 6> resultado{};
        stringstream partes(mac);
        string octeto;
        size_t indice = 0;

        while (getline(partes, octeto, ':'))
        {
            if (indice >= resultado.size() || octeto.size() != 2 ||
                !validaCharHexLower(octeto[0]) || !validaCharHexLower(octeto[1]))
            {
                configError("Endereco MAC invalido: '" + mac + "'", lineNum);
            }
            resultado[indice] = static_cast<uint8_t>(stoi(octeto, nullptr, 16));
            indice += 1;
        }

        if (indice != resultado.size())
        {
            configError("Endereco MAC incompleto: '" + mac + "'", lineNum);
        }

        return resultado;
    }

    bool isValidIdentifier(const string &name)
    {
        if (name.empty())
        {
            return false;
        }
        for (char c : name)
        {
            if (!isalnum(static_cast<unsigned char>(c)) && c != '_' && c != '-')
            {
                return false;
            }
        }
        return true;
    }

    bool networksOverlap(uint32_t ipA, uint8_t prefA, uint32_t ipB, uint8_t prefB)
    {
        uint8_t minPref = min(prefA, prefB);
        uint32_t mask = prefixToMask(minPref);
        return (ipA & mask) == (ipB & mask);
    }

    struct RawRoute
    {
        string cidr;
        string nextHop;
        size_t lineNum;
    };
} // namespace

array<uint8_t, 6> convertMAC(const string &mac)
{
    return parseMACStrict(mac, 0);
}

void loadConfig(const string &filePath)
{
    ifstream arquivo(filePath);
    if (!arquivo.is_open())
    {
        configError("Nao foi possivel abrir o arquivo: " + filePath);
    }

    routerName.clear();
    allInterfaces.clear();
    routeTable.clear();
    filterRules.clear();

    bool hasRouterName = false;
    bool hasMgmtInterface = false;
    size_t dataInterfaceCount = 0;

    set<string> seenInterfaceNames;
    set<uint32_t> seenInterfaceIPs;
    set<array<uint8_t, 6>> seenInterfaceMACs;
    set<pair<uint32_t, uint8_t>> seenRoutePrefixes;

    vector<RawRoute> rawRoutes;

    string rawLine;
    size_t lineNum = 0;

    while (getline(arquivo, rawLine))
    {
        ++lineNum;

        size_t commentPos = rawLine.find('#');
        if (commentPos != string::npos)
        {
            rawLine = rawLine.substr(0, commentPos);
        }

        string line = trim(rawLine);
        if (line.empty())
        {
            continue;
        }

        istringstream iss(line);
        vector<string> tokens;
        string tok;
        while (iss >> tok)
        {
            tokens.push_back(tok);
        }

        const string &directive = tokens[0];

        if (directive == "nome")
        {
            if (tokens.size() != 2 || !isValidIdentifier(tokens[1]))
            {
                configError("Sintaxe invalida para 'nome' (esperado: nome <identificador>)", lineNum);
            }
            if (hasRouterName)
            {
                configError("Diretiva 'nome' duplicada", lineNum);
            }
            routerName = tokens[1];
            hasRouterName = true;
        }
        else if (directive == "interface" || directive == "gerencia")
        {
            if (tokens.size() != 4)
            {
                configError("Sintaxe invalida para '" + directive + "'", lineNum);
            }

            const string &ifaceName = tokens[1];
            const string &ipPrefix = tokens[2];
            const string &macStr = tokens[3];

            if (!isValidIdentifier(ifaceName))
            {
                configError("Nome de interface invalido: '" + ifaceName + "'", lineNum);
            }

            if (directive == "gerencia")
            {
                if (ifaceName != "mgmt0")
                {
                    configError("Interface de gerencia deve obrigatoriamente se chamar 'mgmt0'", lineNum);
                }
                if (hasMgmtInterface)
                {
                    configError("Diretiva 'gerencia' duplicada", lineNum);
                }
                hasMgmtInterface = true;
            }
            else
            {
                if (ifaceName == "mgmt0")
                {
                    configError("'mgmt0' e reservado para a diretiva 'gerencia'", lineNum);
                }
                ++dataInterfaceCount;
                if (dataInterfaceCount > 8)
                {
                    configError("Numero maximo de interfaces de dados excedido (maximo 8)", lineNum);
                }
            }

            if (!seenInterfaceNames.insert(ifaceName).second)
            {
                configError("Nome de interface duplicado: '" + ifaceName + "'", lineNum);
            }

            auto [ipAddr, prefix] = parseCIDR(ipPrefix, 1, 30, false, lineNum);
            uint32_t mask = prefixToMask(prefix);
            uint32_t hostBits = ipAddr & ~mask;

            if (hostBits == 0u)
            {
                configError("IP da interface '" + ifaceName + "' nao pode ser o endereco de rede: " + ipPrefix, lineNum);
            }
            if (hostBits == ~mask)
            {
                configError("IP da interface '" + ifaceName + "' nao pode ser o endereco de broadcast: " + ipPrefix, lineNum);
            }

            if (!seenInterfaceIPs.insert(ipAddr).second)
            {
                configError("Endereco IP duplicado entre interfaces: " + ipPrefix, lineNum);
            }

            array<uint8_t, 6> macAddr = parseMACStrict(macStr, lineNum);
            if (!seenInterfaceMACs.insert(macAddr).second)
            {
                configError("Endereco MAC duplicado entre interfaces: " + macStr, lineNum);
            }

            for (const auto &existing : allInterfaces)
            {
                if (networksOverlap(ipAddr, prefix, existing.interfaceIpAddr, existing.prefixLength))
                {
                    configError("Sobreposicao de sub-rede entre interfaces '" + ifaceName +
                                    "' e '" + existing.interfaceName + "'",
                                lineNum);
                }
            }

            allInterfaces.push_back({ipAddr, prefix, ifaceName, macAddr});
        }
        else if (directive == "rota")
        {
            if (tokens.size() != 4 || tokens[2] != "via")
            {
                configError("Sintaxe invalida para 'rota' (esperado: rota <rede/prefixo> via <proximo_salto>)", lineNum);
            }
            rawRoutes.push_back({tokens[1], tokens[3], lineNum});
        }
        else if (directive == "filtro")
        {
            if (tokens.size() != 6)
            {
                configError("Sintaxe invalida para 'filtro' (esperado: filtro <permitir|negar> <icmp|udp|*> <origem|*> <destino|*> <porta|*>)", lineNum);
            }

            FilterAction action;
            if (tokens[1] == "permitir")
            {
                action = FilterAction::Permitir;
            }
            else if (tokens[1] == "negar")
            {
                action = FilterAction::Negar;
            }
            else
            {
                configError("Acao de filtro invalida: '" + tokens[1] + "'", lineNum);
            }

            uint8_t protocol = 0;
            if (tokens[2] == "icmp" || tokens[2] == "1")
            {
                protocol = 1;
            }
            else if (tokens[2] == "udp" || tokens[2] == "17")
            {
                protocol = 17;
            }
            else if (tokens[2] == "*")
            {
                protocol = 0;
            }
            else
            {
                configError("Protocolo invalido no filtro (esperado icmp, udp, 1, 17 ou *): '" + tokens[2] + "'", lineNum);
            }

            bool anySrc = false;
            uint32_t srcNet = 0;
            uint8_t srcPref = 0;
            if (tokens[3] == "*")
            {
                anySrc = true;
            }
            else
            {
                auto [net, pref] = parseCIDR(tokens[3], 0, 32, true, lineNum);
                srcNet = net;
                srcPref = pref;
            }

            bool anyDst = false;
            uint32_t dstNet = 0;
            uint8_t dstPref = 0;
            if (tokens[4] == "*")
            {
                anyDst = true;
            }
            else
            {
                auto [net, pref] = parseCIDR(tokens[4], 0, 32, true, lineNum);
                dstNet = net;
                dstPref = pref;
            }

            uint16_t dstPort = 0;
            if (tokens[5] == "*")
            {
                dstPort = 0;
            }
            else
            {
                if (protocol != 17)
                {
                    configError("Porta numerica no filtro so e permitida quando o protocolo for 'udp' (17)", lineNum);
                }
                int portVal = 0;
                if (!parseStrictInt(tokens[5], portVal) || portVal < 1 || portVal > 65535)
                {
                    configError("Porta UDP invalida no filtro (esperado 1..65535 ou *): '" + tokens[5] + "'", lineNum);
                }
                dstPort = static_cast<uint16_t>(portVal);
            }

            uint32_t ruleNumber = static_cast<uint32_t>(filterRules.size() + 1);
            filterRules.push_back({
                ruleNumber,
                action,
                protocol,
                anySrc,
                srcNet,
                srcPref,
                anyDst,
                dstNet,
                dstPref,
                dstPort
            });
        }
        else
        {
            configError("Diretiva desconhecida: '" + directive + "'", lineNum);
        }
    }

    if (!hasRouterName)
    {
        configError("Diretiva obrigatoria 'nome' ausente no arquivo de configuracao");
    }

    if (!hasMgmtInterface)
    {
        configError("Diretiva obrigatoria 'gerencia' (mgmt0) ausente no arquivo de configuracao");
    }

    if (dataInterfaceCount < 1)
    {
        configError("O roteador deve possuir ao menos 1 interface de dados");
    }

    for (const auto &rawRoute : rawRoutes)
    {
        auto [destNet, destPref] = parseCIDR(rawRoute.cidr, 0, 32, true, rawRoute.lineNum);

        if (!seenRoutePrefixes.insert({destNet, destPref}).second)
        {
            configError("Prefixo de rota duplicado: '" + rawRoute.cidr + "'", rawRoute.lineNum);
        }

        uint32_t nextHopIP = parseIPv4Strict(rawRoute.nextHop, rawRoute.lineNum);

        string outInterface;
        for (const auto &iface : allInterfaces)
        {
            if (iface.interfaceName == "mgmt0")
            {
                continue;
            }

            uint32_t mask = prefixToMask(iface.prefixLength);
            if ((nextHopIP & mask) == (iface.interfaceIpAddr & mask))
            {
                if (nextHopIP == iface.interfaceIpAddr)
                {
                    configError("Proximo salto da rota nao pode ser o proprio IP do roteador: " + rawRoute.nextHop, rawRoute.lineNum);
                }
                uint32_t nhHostBits = nextHopIP & ~mask;
                if (nhHostBits == 0u || nhHostBits == ~mask)
                {
                    configError("Proximo salto da rota nao pode ser endereco de rede ou broadcast: " + rawRoute.nextHop, rawRoute.lineNum);
                }
                outInterface = iface.interfaceName;
                break;
            }
        }

        if (outInterface.empty())
        {
            configError("Proximo salto '" + rawRoute.nextHop + "' nao pertence a nenhuma interface de dados", rawRoute.lineNum);
        }

        routeTable.push_back({destNet, destPref, nextHopIP, outInterface});
    }
}