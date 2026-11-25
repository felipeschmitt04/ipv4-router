#pragma once
#include <string>
#include <cstdint>
#include <vector>
#include <array>
#include <optional>
#include <atomic>

struct ReceivedFrame
{
  std::vector<std::uint8_t> data; // bytes completos do quadro Ethernet
  unsigned int interfaceIndex;    // interface Linux que recebeu o quadro
};

struct EthernetHeader
{
  std::array<std::uint8_t, 6> destination;
  std::array<std::uint8_t, 6> source;
  std::uint16_t etherType;
};

std::optional<EthernetHeader> parseEthernetHeader(
    const ReceivedFrame &frame);

std::string formatMac(
    const std::array<std::uint8_t, 6> &mac);

std::vector<std::uint8_t> buildEthernetFrame(
    const std::array<std::uint8_t, 6> &destination,
    const std::array<std::uint8_t, 6> &source,
    std::uint16_t etherType,
    const std::vector<std::uint8_t> &payload);

bool isFrameForInterface(
    const EthernetHeader &header,
    const std::array<std::uint8_t, 6> &localMac);

// classe que representa uma interface Ethernet que sera controlada pelo programa
class EthernetInterface
{
private:
  int fileDescriptor = -1;         // numero inteiro retornado pelo Linux quando o socket é criado
  std::string interfaceName;       // nome da interface
  unsigned int interfaceIndex = 0; // identificador da interface usado pelo Linux
  std::atomic_flag receiveErrorReported = ATOMIC_FLAG_INIT;
  std::atomic_flag sendErrorReported = ATOMIC_FLAG_INIT;

public:
  EthernetInterface(const std::string &interface_name);
  ~EthernetInterface();

  EthernetInterface(const EthernetInterface &) = delete;            // construtor de copia
  EthernetInterface &operator=(const EthernetInterface &) = delete; // operador de atribuição por copia

  std::optional<ReceivedFrame> receive();

  bool send(const std::vector<std::uint8_t> &frame);
};
