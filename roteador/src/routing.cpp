
#include "../include/routing.hpp"

using namespace std;

vector<Route> routeTable;

forwardingResult forwarding(
    uint32_t destinationIPAddr,
    const vector<interface>& allInterfaces,
    const vector<Route>& routeTable
) {
    //bool directlyConnected significa que a rota analisada possui uma interface diretamente conectada
    //com o destino. Portanto o código primeiro analisa todas as interfaces verificando se existe alguma 
    //diretamente conectada. Caso exista, a rota diretamente conectada será escolhida. Caso não exista,
    // o código analisa as rotas estáticas.
    int biggestPrefix = -1;

    forwardingResult result{};

    // Verificar redes diretamente conectadas
    for (size_t i = 0; i < allInterfaces.size(); i++) {
        if (allInterfaces[i].interfaceName == "mgmt0") {
            continue;
        }
        uint8_t prefix = allInterfaces[i].prefixLength;
        uint32_t mask = prefix == 0
            ? 0
            : (0xFFFFFFFFu << (32 - prefix));
        if ((destinationIPAddr & mask) ==
            (allInterfaces[i].interfaceIpAddr & mask)) {
            if (prefix > biggestPrefix) {
                biggestPrefix = prefix;
                result.found = true;
                result.interfaceName = allInterfaces[i].interfaceName;
                result.nextHop = destinationIPAddr;
            }
        }
    }   

    // Verificar rotas estáticas
    for (size_t i = 0; i < routeTable.size(); i++) {
        uint8_t prefix = routeTable[i].prefixLenght;
        uint32_t mask = prefix == 0
            ? 0
            : (0xFFFFFFFFu << (32 - prefix));
        if ((destinationIPAddr & mask) ==
            (routeTable[i].destinationNetwork & mask)) {
            if (prefix > biggestPrefix) {
                biggestPrefix = prefix;
                result.found = true;
                result.interfaceName = routeTable[i].interfaceName;
                result.nextHop = routeTable[i].nextHop;
            }
        }
    }
    return result;
}
