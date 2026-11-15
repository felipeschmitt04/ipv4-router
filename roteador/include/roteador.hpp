
#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <functional>

#include "ipv4.hpp"

using namespace std;

//enum para representar as ações possíveis após o processamento de um pacote IPv4.
//forward: O pacote será encaminhado para outra interface.
//local: O pacote é destinado ao próprio roteador.
//drop: O pacote será descartado.
//TTLExpired: O pacote será descartado devido ao tempo de vida (TTL) expirado
//NoRoute: O pacote será descartado porque não há uma rota correspondente na tabela de roteamento.
//AwaitingFilter: O pacote está aguardando a aplicação de um filtro antes de decidir a ação.
enum class IPv4Action {
    Forward,
    Local,
    Drop,
    TTLExpired,
    NoRoute,
    AwaitingFilter
};

struct IPv4Result {
    IPv4Action action = IPv4Action::Drop;
    string outputInterface;
    uint32_t nextHop = 0;
    string dropReason;
};


//Responsável pela filtragem, chamar essa função!!!
using IPv4Filter = function<bool(
    const vector<uint8_t>&,
    const ipv4Header&,
    const string&
)>;

IPv4Result processIPv4(vector<uint8_t>& packet,const string& inputInterface,const IPv4Filter& filter);
