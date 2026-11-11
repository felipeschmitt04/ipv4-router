#include "../include/config.hpp"
#include "../include/interface.hpp"

#include <fstream>
#include <sstream>
#include <iostream>
#include <arpa/inet.h>

using namespace std;

extern vector<interface> allInterfaces;

void loadConfig(const string& filePath) {
    ifstream arquivo(filePath);

    if (!arquivo.is_open()) {
        cerr << "Erro ao abrir arquivo" << endl;
        exit(1);
    }

    string linha;

    while (getline(arquivo, linha)) {
        stringstream ss(linha);

        string tipo, nome, ipPrefixo, mac;
        ss >> tipo;

        if (tipo == "interface" || tipo == "gerencia") {
            ss >> nome >> ipPrefixo >> mac;

            size_t pos = ipPrefixo.find('/');

            string ip = ipPrefixo.substr(0, pos);
            int prefixo = stoi(ipPrefixo.substr(pos + 1));

            in_addr endereco;
            inet_pton(AF_INET, ip.c_str(), &endereco);

            uint32_t ipNumerico = ntohl(endereco.s_addr);

            allInterfaces.push_back({
                ipNumerico,
                static_cast<uint8_t>(prefixo),
                nome
            });
        }
    }
}