#include "../include/ethernet.hpp"
#include <cerrno>
#include <net/if.h>
#include <system_error>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>

EthernetInterface::EthernetInterface(const std::string& interface_name) : interfaceName(interface_name){
    interfaceIndex = if_nametoindex(interfaceName.c_str()); // converte uma string para index

    if(interfaceIndex == 0){ // valida o index
        throw std::system_error(
            errno,
            std::generic_category(),
            "falha ao obter indice da interface " + interfaceName
        );
    }

    // criando o socket
    fileDescriptor = socket(
        AF_PACKET, // indica que o socket vai trabalhar com pacotes Ethernet no Linux
        SOCK_RAW, // indica que o programa vai receber o quadro bruto, incluindo MAC destino, MAC origem, EtherType e payload
        htons(ETH_P_ALL) // ETH_P_ALL aceita todos os protocolos Ethernet, htons converte esse valor para a ordem de bytes usada na rede
    );

    if(fileDescriptor == -1){ // testar se a criação funcionou
        throw std::system_error(
            errno,
            std::generic_category(),
            "falha ao criar socket para a interface " + interfaceName
        );
    }

    sockaddr_ll endereco{}; // cria e zera a estrutura para enderecos AF_PACKET

    endereco.sll_family = AF_PACKET; // atribui que o endereco é da familia AF_PACKET
    endereco.sll_protocol = htons(ETH_P_ALL); // socket recebera todos os EtherTypes
    endereco.sll_ifindex = interfaceIndex; // associa o socket a interface recebida antes

    if(bind( // associa o socket a interface definida em endereco
            fileDescriptor,
            reinterpret_cast<sockaddr*>(&endereco), // converte sockaddr_l para sockaddr esperado pelo bind
            sizeof(endereco)
    ) == -1){ // valida bind
        close(fileDescriptor); // fecha o descritor, porque o destrutor nao é chamado durante a construcao
        fileDescriptor = -1;

        throw std::system_error(
            errno,
            std::generic_category(),
            "falha ao assocciar socket a interface " + interfaceName
        );
    }
}

EthernetInterface::~EthernetInterface(){
    if(fileDescriptor != -1){
        close(fileDescriptor);
        fileDescriptor = -1;
    }
}