#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "config.hpp"
#include "ipv4.hpp"

// Avalia um pacote IPv4 encaminhado contra uma lista de regras (politica first-match).
// Retorna true se permitido (incluindo acao padrao permitir quando nenhuma regra casa)
// e false se negado; quando negado por regra, matchedRuleNumber recebe rule.ruleNumber.
bool evaluateFilterRules(
    const std::vector<uint8_t>& packet,
    const ipv4Header& header,
    const std::string& interfaceName,
    const std::vector<FilterRule>& rules,
    size_t& matchedRuleNumber
);

// Sobrecarga compatível com IPv4IndexedFilter usando as regras carregadas em filterRules.
bool evaluateIPv4FilterIndexed(
    const std::vector<uint8_t>& packet,
    const ipv4Header& header,
    const std::string& inputInterface,
    size_t& matchedRuleNumber
);

// Sobrecarga compatível com o callback IPv4Filter de processIPv4().
bool evaluateIPv4Filter(
    const std::vector<uint8_t>& packet,
    const ipv4Header& header,
    const std::string& inputInterface
);