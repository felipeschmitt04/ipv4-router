
#include "../include/config.hpp"
#include "../include/interface.hpp"
#include "../include/routing.hpp"

#include <fstream>
#include <sstream>
#include <iostream>
#include <utility>
#include <arpa/inet.h>
#include <cstdlib>

using namespace std;

extern vector<interface> allInterfaces;
extern vector<Route> routeTable;

uint32_t convertIP(const string &ip)
{
    in_addr endereco{};

    if (inet_pton(AF_INET, ip.c_str(), &endereco) != 1)
    {
        cerr << "Endereco IP invalido: " << ip << endl;
        exit(1);
    }

    return ntohl(endereco.s_addr);
}

bool validaChar(char caractere)
{
    return (caractere >= '0' && caractere <= '9') ||
           (caractere >= 'a' && caractere <= 'f');
}

array<uint8_t, 6> convertMAC(const string &mac)
{
    if(mac.empty() || mac.back() == ':'){
        cerr << "Erro ao converter MAC, formato invalido" << endl;
        exit(1);
    }

    array<uint8_t, 6> resultado{};
    stringstream partes(mac);
    string octeto;
    size_t indice = 0;

    while (getline(partes, octeto, ':'))
    {
        if (indice >= resultado.size())
        {
            cerr << "Erro ao converter MAC, indice invalido" << endl;
            exit(1);
        }
        if (octeto.size() != 2)
        {
            cerr << "Erro ao converter MAC, octeto invalido" << endl;
            exit(1);
        }
        if (!validaChar(octeto[0]))
        {
            cerr << "Erro ao converter MAC, caractere invalido" << endl;
            exit(1);
        }
        if (!validaChar(octeto[1]))
        {
            cerr << "Erro ao converter MAC, caractere invalido" << endl;
            exit(1);
        }
        resultado[indice] = static_cast<uint8_t>(stoi(octeto, nullptr, 16));
        indice += 1;
    }
    if (indice != resultado.size())
    {
        cerr << "Erro ao converter MAC, indice invalido" << endl;
        exit(1);
    }
    return resultado;
}

void loadConfig(const string &filePath)
{
    ifstream arquivo(filePath);

    if (!arquivo.is_open())
    {
        cerr << "Erro ao abrir arquivo" << endl;
        exit(1);
    }

    allInterfaces.clear();
    routeTable.clear();

    string linha;
    vector<pair<string, string>> rotas;

    while (getline(arquivo, linha))
    {
        stringstream ss(linha);

        string tipo, nome, ipPrefixo, mac;
        ss >> tipo;

        if (tipo == "interface" || tipo == "gerencia")
        {
            ss >> nome >> ipPrefixo >> mac;

            size_t pos = ipPrefixo.find('/');

            string ip = ipPrefixo.substr(0, pos);
            int prefixo = stoi(ipPrefixo.substr(pos + 1));

            allInterfaces.push_back({
                convertIP(ip),
                static_cast<uint8_t>(prefixo),
                nome,
                convertMAC(mac),
            });
        }

        else if (tipo == "rota")
        {
            string rede, via, nextHop;
            ss >> rede >> via >> nextHop;

            rotas.push_back({rede, nextHop});
        }
    }

    for (const auto &rota : rotas)
    {
        size_t pos = rota.first.find('/');

        string ip = rota.first.substr(0, pos);
        int prefixo = stoi(rota.first.substr(pos + 1));

        uint32_t destino = convertIP(ip);
        uint32_t nextHop = convertIP(rota.second);

        string interfaceSaida;

        for (const auto &iface : allInterfaces)
        {
            if (iface.interfaceName == "mgmt0")
            {
                continue;
            }

            uint32_t mask = iface.prefixLength == 0
                                ? 0
                                : (0xFFFFFFFFu << (32 - iface.prefixLength));

            if ((nextHop & mask) == (iface.interfaceIpAddr & mask))
            {
                interfaceSaida = iface.interfaceName;
                break;
            }
        }

        if (interfaceSaida.empty())
        {
            cerr << "Proximo salto sem interface de saida" << endl;
            exit(1);
        }

        routeTable.push_back({destino,
                              static_cast<uint8_t>(prefixo),
                              nextHop,
                              interfaceSaida});
    }
}
