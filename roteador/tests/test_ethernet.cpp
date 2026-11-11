#include "../include/ethernet.hpp"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <vector>

ReceivedFrame quadroComEtherType(std::uint16_t etherType)
{
    return ReceivedFrame{
        {0x02, 0x00, 0x00, 0x00, 0x0a, 0x01,
         0x02, 0x00, 0x00, 0x00, 0x01, 0x00,
         static_cast<std::uint8_t>(etherType >> 8),
         static_cast<std::uint8_t>(etherType & 0xff)},
        2};
}

void testaQuadroIPv4()
{
    auto resultado = parseEthernetHeader(quadroComEtherType(0x0800));

    assert(resultado.has_value());
    const std::array<std::uint8_t, 6> destinoEsperado{
        0x02, 0x00, 0x00, 0x00, 0x0a, 0x01};

    const std::array<std::uint8_t, 6> origemEsperada{
        0x02, 0x00, 0x00, 0x00, 0x01, 0x00};

    assert(resultado->destination == destinoEsperado);
    assert(resultado->source == origemEsperada);
    assert(resultado->etherType == 0x0800);
}

void testaQuadroARP()
{
    auto resultado = parseEthernetHeader(quadroComEtherType(0x0806));

    assert(resultado.has_value());
    assert(resultado->etherType == 0x0806);
}

void testaQuadroTruncado()
{
    ReceivedFrame frame{
        {0x02, 0x00, 0x00, 0x00, 0x0a, 0x01},
        2};

    auto resultado = parseEthernetHeader(frame);

    assert(!resultado.has_value());
}

void testaQuadroExatamenteCabecalho()
{
    auto resultado = parseEthernetHeader(quadroComEtherType(0x1234));

    assert(resultado.has_value());
    assert(resultado->etherType == 0x1234);
}

void testaEtherTypeNaoSuportado()
{
    auto resultado = parseEthernetHeader(quadroComEtherType(0x86dd));

    assert(resultado.has_value());
    assert(resultado->etherType == 0x86dd);

    bool suportado =
        resultado->etherType == 0x0800 ||
        resultado->etherType == 0x0806;

    assert(!suportado);
}

int main()
{
    testaQuadroIPv4();
    testaQuadroARP();
    testaQuadroTruncado();
    testaQuadroExatamenteCabecalho();
    testaEtherTypeNaoSuportado();

    std::cout << "Todos os testes Ethernet passaram.\n";
}