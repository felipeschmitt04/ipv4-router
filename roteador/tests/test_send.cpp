#include "ethernet.hpp"
#include <array>
#include <cstdint>
#include <thread>
#include <vector>
#include <chrono>

int main(){
    const std::array<std::uint8_t, 6> macH1{
        0x02, 0x00, 0x00, 0x00, 0x0a, 0x01
    };
    const std::array<std::uint8_t, 6> macR1{
        0x02, 0x00, 0x00, 0x00, 0x01, 0x00
    };

    std::vector<std::uint8_t> arpPayLoad{
        0x00, 0x01, // Ethernet
        0x08, 0x00, // ipv4
        0x06, // tamanho do endereco MAC
        0x04, // tamanho do endereco ip
        0x00, 0x02, // operacao de reply

        macR1[0], macR1[1], macR1[2],
        macR1[3], macR1[4], macR1[5],

        0x0a, 0x00, 0x01, 0x01,

        macH1[0], macH1[1], macH1[2],
        macH1[3], macH1[4], macH1[5],
        
        0x0a, 0x00, 0x01, 0x0a
    };

    auto frame = buildEthernetFrame(
        macH1,
        macR1,
        0x0806,
        arpPayLoad
    );

    EthernetInterface eth0("eth0");
    eth0.send(frame);

    std::this_thread::sleep_for(std::chrono::milliseconds(500));
}