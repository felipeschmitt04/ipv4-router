#pragma once
#include<string>

// classe que representa uma interface Ethernet que sera controlada pelo programa
class EthernetInterface {
  private:
    int fileDescriptor = -1; // numero inteiro retornado pelo Linux quando o socket é criado
    std::string interfaceName; // nome da interface
    unsigned int interfaceIndex = 0; // identificador da interface usado pelo Linux

  public:
    EthernetInterface(const std::string& interface_name);
    ~EthernetInterface();
};

