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
#include <chrono>
#include <cstdio>
#include <poll.h>
#include <thread>

namespace
{
constexpr int ioWaitMs = 100;
constexpr unsigned maxInterruptedSendAttempts = 3;

bool isRecoverableIoError(int error)
{
    return error == EAGAIN || error == EWOULDBLOCK ||
           error == ENOBUFS || error == ENOMEM ||
           error == ENETDOWN || error == ENODEV || error == ENXIO;
}

void reportIoErrorOnce(std::atomic_flag &reported, const std::string &interfaceName,
                       const char *operation, int error)
{
    if (!reported.test_and_set())
    {
        std::fprintf(stderr, "%s: %s falhou (errno=%d)\n",
                     interfaceName.c_str(), operation, error);
    }
}
}

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

std::optional<ReceivedFrame> EthernetInterface::receive()
{
    pollfd descriptor{fileDescriptor, POLLIN, 0};
    const int ready = poll(&descriptor, 1, ioWaitMs);
    if (ready < 0)
    {
        const int error = errno;
        if (error == EINTR)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            return std::nullopt;
        }
        if (isRecoverableIoError(error))
        {
            reportIoErrorOnce(receiveErrorReported, interfaceName, "poll", error);
            std::this_thread::sleep_for(std::chrono::milliseconds(ioWaitMs));
            return std::nullopt;
        }
        throw std::system_error(error, std::generic_category(), "poll em " + interfaceName);
    }
    if (ready == 0)
    {
        return std::nullopt;
    }
    if (descriptor.revents & (POLLNVAL | POLLHUP))
    {
        const int error = descriptor.revents & POLLNVAL ? EBADF : EIO;
        throw std::system_error(error, std::generic_category(), "poll em " + interfaceName);
    }

    std::vector<std::uint8_t> buffer(65536);
    sockaddr_ll address{};
    socklen_t addressLength = sizeof(address);
    const ssize_t received = recvfrom(fileDescriptor, buffer.data(), buffer.size(), MSG_DONTWAIT,
                                      reinterpret_cast<sockaddr *>(&address), &addressLength);
    if (received < 0)
    {
        const int error = errno;
        if (error == EINTR)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            return std::nullopt;
        }
        if (isRecoverableIoError(error))
        {
            reportIoErrorOnce(receiveErrorReported, interfaceName, "recvfrom", error);
            std::this_thread::sleep_for(std::chrono::milliseconds(ioWaitMs));
            return std::nullopt;
        }
        throw std::system_error(error, std::generic_category(), "recvfrom em " + interfaceName);
    }
    if (address.sll_pkttype == PACKET_OUTGOING)
    {
        return std::nullopt;
    }

    buffer.resize(static_cast<std::size_t>(received));
    return ReceivedFrame{std::move(buffer), static_cast<unsigned int>(address.sll_ifindex)};
}

bool EthernetInterface::send(
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

    for (unsigned interruptedAttempts = 0;;)
    {
        ssize_t sent = sendto(
            fileDescriptor,
            frame.data(),
            frame.size(),
            MSG_DONTWAIT | MSG_NOSIGNAL,
            reinterpret_cast<sockaddr *>(&address),
            sizeof(address));

        if (sent >= 0)
        {
            if (static_cast<std::size_t>(sent) != frame.size())
            {
                throw std::system_error(
                    EIO,
                    std::generic_category(),
                    "transmissao parcial de quadro Ethernet em " + interfaceName);
            }
            return true;
        }
        const int error = errno;
        if (error == EINTR && ++interruptedAttempts < maxInterruptedSendAttempts)
        {
            continue;
        }
        if (error == EINTR || isRecoverableIoError(error) || error == EMSGSIZE)
        {
            reportIoErrorOnce(sendErrorReported, interfaceName, "sendto", error);
            return false;
        }

        throw std::system_error(error, std::generic_category(), "sendto em " + interfaceName);
    }
}

std::optional<EthernetHeader> parseEthernetHeader( // interpreta o cabeçalho
    const ReceivedFrame &frame)
{
    constexpr std::size_t ethernetHeaderSize = 14;

    if (frame.data.size() < ethernetHeaderSize || frame.data.size() > 1514)
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

bool isFrameForInterface(
    const EthernetHeader &header,
    const std::array<std::uint8_t, 6> &localMac)
{
    const std::array<std::uint8_t, 6> broadcast = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    if (header.destination == localMac)
        return true;
    if (header.destination == broadcast)
        return true;

    return false;
}
