#ifndef IPV4_HPP
#define IPV4_HPP

#include <vector>
#include <cstdint>
using namespace std;

struct ipv4Header{
    bool valid;
    uint8_t version;
    uint8_t IHL;
    uint16_t totalLength;
    uint16_t identifier;
    uint8_t flag;
    uint16_t fragmentOffset;
    uint8_t TTL;
    uint8_t protocol;
    uint16_t headerChecksum;
    uint32_t sourceIPAddr;
    uint32_t destinationIPAddr;
};

ipv4Header ipv4Interpreter(const vector<uint8_t> &packet);
bool verifyCheckSum (const vector<uint8_t> &packet, uint8_t IHL);
uint16_t calculateCheckSum(const vector<uint8_t> &packet, uint8_t IHL);
bool newTTL(vector<uint8_t> &packet);


#endif