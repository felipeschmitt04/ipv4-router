#include "../include/ethernet.hpp"
#include <cerrno>
#include <net/if.h>
#include <system_error>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <utility>
#include <optional>
#include <iomanip>
#include <sstream>
#include <cstring>

EthernetInterface::EthernetInterface(const std::string &interface_name) : interfaceName(interface_name)
{
    interfaceIndex = if_nametoindex(interfaceName.c_str()); // converte uma string para index

    if (interfaceIndex == 0)
    { // valida o index
        throw std::system_error(
            errno,
            std::generic_category(),
            "falha ao obter indice da interface " + interfaceName);
    }

    // criando o socket
    fileDescriptor = socket(
        AF_PACKET,       // indica que o socket vai trabalhar com pacotes Ethernet no Linux
        SOCK_RAW,        // indica que o programa vai receber o quadro bruto, incluindo MAC destino, MAC origem, EtherType e payload
        htons(ETH_P_ALL) // ETH_P_ALL aceita todos os protocolos Ethernet, htons converte esse valor para a ordem de bytes usada na rede
    );

    if (fileDescriptor == -1)
    { // testar se a criação funcionou
        throw std::system_error(
            errno,
            std::generic_category(),
            "falha ao criar socket para a interface " + interfaceName);
    }

    sockaddr_ll endereco{}; // cria e zera a estrutura para enderecos AF_PACKET

    endereco.sll_family = AF_PACKET;          // atribui que o endereco é da familia AF_PACKET
    endereco.sll_protocol = htons(ETH_P_ALL); // socket recebera todos os EtherTypes
    endereco.sll_ifindex = interfaceIndex;    // associa o socket a interface recebida antes

    if (bind( // associa o socket a interface definida em endereco
            fileDescriptor,
            reinterpret_cast<sockaddr *>(&endereco), // converte sockaddr_l para sockaddr esperado pelo bind
            sizeof(endereco)) == -1)
    { // valida bind
        int error = errno;

        close(fileDescriptor); // fecha o descritor, porque o destrutor nao é chamado durante a construcao
        fileDescriptor = -1;

        throw std::system_error(
            error,
            std::generic_category(),
            "falha ao assocciar socket a interface " + interfaceName);
    }
}

EthernetInterface::~EthernetInterface()
{
    if (fileDescriptor != -1)
    {
        close(fileDescriptor);
        fileDescriptor = -1;
    }
}

ReceivedFrame EthernetInterface::receive() // função que bloqueia ate chegar um quadro Ethernet pela interface associada ao socket
{
    std::vector<std::uint8_t> buffer(65536); // limite de buffer para receber o quadro, 65536 é um limite seguro

    sockaddr_ll address{};
    socklen_t addressLength = sizeof(address);

    while (true)
    {
        ssize_t received = recvfrom( // copia os bytes recebidos para o buffer
            fileDescriptor,
            buffer.data(),
            buffer.size(),
            0,
            reinterpret_cast<sockaddr *>(&address),
            &addressLength);

        if (received >= 0)
        {
            if (received == 0)
            {
                throw std::system_error(
                    EPROTO,
                    std::generic_category(),
                    "quadro Ethernet vazio recebido");
            }

            buffer.resize(static_cast<std::size_t>(received)); // deixa o vetor com o tamanho real do quadro recebido

            return ReceivedFrame{// retorna os bytes completos do quadro e o indice da interface que o recebeu
                                 std::move(buffer),
                                 static_cast<unsigned int>(address.sll_ifindex)};
        }

        if (errno == EINTR)
        {
            continue;
        }

        throw std::system_error(
            errno,
            std::generic_category(),
            "falha ao receber quadro Ethernet");
    }
}

void EthernetInterface::send(
    const std::vector<std::uint8_t> &frame)
{
    constexpr std::size_t EthernetHeaderSize = 14;

    if (frame.size() < EthernetHeaderSize)
    {
        throw std::invalid_argument(
            "quadro Ethernet menor que o cabecalho");
    }

    sockaddr_ll address{};
    address.sll_family = AF_PACKET;
    address.sll_protocol = htons(
        static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(frame[12]) << 8) |
            frame[13]));
    address.sll_ifindex = static_cast<int>(interfaceIndex);
    address.sll_halen = ETH_ALEN;

    std::memcpy( // copia o MAC destino
        address.sll_addr,
        frame.data(),
        ETH_ALEN);

    while (true)
    {
        ssize_t sent = sendto(
            fileDescriptor,
            frame.data(),
            frame.size(),
            0,
            reinterpret_cast<sockaddr *>(&address),
            sizeof(address));

        if (sent >= 0)
        {
            if (static_cast<std::size_t>(sent) != frame.size())
            {
                throw std::system_error(
                    EIO,
                    std::generic_category(),
                    "transmissao parcial de quadro Ethernet");
            }
            return;
        }
        if (errno == EINTR)
        {
            continue;
        }

        throw std::system_error(
            errno,
            std::generic_category(),
            "falha ao transmitir quadro Ethernet");
    }
}

std::optional<EthernetHeader> parseEthernetHeader( // interpreta o cabeçalho
    const ReceivedFrame &frame)
{
    constexpr std::size_t ethernetHeaderSize = 14;

    if (frame.data.size() < ethernetHeaderSize)
    {
        return std::nullopt;
    }

    EthernetHeader header{};

    for (std::size_t i = 0; i < 6; ++i)
    {
        header.destination[i] = frame.data[i];
        header.source[i] = frame.data[i + 6];
    }

    header.etherType =
        (static_cast<std::uint16_t>(frame.data[12]) << 8) |
        static_cast<std::uint16_t>(frame.data[13]);

    return header;
}

std::string formatMac(
    const std::array<std::uint8_t, 6> &mac)
{
    std::ostringstream result;

    for (std::size_t i = 0; i < mac.size(); ++i)
    {
        if (i != 0)
        {
            result << ':';
        }
        // cada byte é impresso em
        result << std::hex                           // hexadecimal
               << std::setw(2)                       // com largura minima de dois caracteres
               << std::setfill('0')                  // preenchimento de zero a esquerda
               << static_cast<unsigned int>(mac[i]); // garante que o valor vai ser impresso numericamente
    }

    return result.str();
}

std::vector<std::uint8_t> buildEthernetFrame(
    const std::array<std::uint8_t, 6> &destination,
    const std::array<std::uint8_t, 6> &source,
    std::uint16_t etherType,
    const std::vector<std::uint8_t> &payload)
{
    constexpr std::size_t ethernetHeaderSize = 14;
    constexpr std::size_t minimumFrameSize = 60;

    std::vector<std::uint8_t> frame;
    frame.reserve(ethernetHeaderSize + payload.size()); // aloca espaço no vector

    frame.insert(frame.end(), destination.begin(), destination.end());
    frame.insert(frame.end(), source.begin(), source.end());

    frame.push_back(static_cast<std::uint8_t>(etherType >> 8));
    frame.push_back(static_cast<std::uint8_t>(etherType & 0xff));

    frame.insert(frame.end(), payload.begin(), payload.end()); // insere o payload depois do cabeçalho

    if (frame.size() < minimumFrameSize)
    {
        frame.resize(minimumFrameSize, 0); // preenche o vetor com zeros, caso nao tenha o tamanho minimo
    }

    return frame;
}