#include "../include/ipv4.hpp"
#include <iostream>
#include <cstdint>  //biblioteca para usar bit
#include <vector>
using namespace std;


ipv4Header ipv4Interpreter(const vector<uint8_t> &packet){ //vetor onde cada posição do vetor é um número de 8 bits (1 byte)

    ipv4Header header{};
    header.valid = false;

    //verificação se o ipv4 tem no mínimo 20bytes, caso tenha menos que isso, ele é descartado
    if(packet.size()<20){
       return header;
    }

    //COLETA DOS CAMPOS DO IPv4:

    uint8_t version = packet[0] >> 4;

    uint8_t IHL = packet[0] & 0b00001111;

    uint16_t totalLength = (uint16_t(packet[2])<<8 | packet[3]);

    uint16_t identifier = (uint16_t(packet[4])<<8 | packet[5]);

    uint8_t flag = packet[6]>>5;

    uint16_t fragmentOffset = ((uint16_t(packet[6] & 0b00011111) << 8) | packet[7]);

    uint8_t TTL = packet[8];

    uint8_t protocol = packet[9];

    uint16_t headerChecksum = (uint16_t(packet[10])<<8 | packet[11]);

    uint32_t sourceIPAddr = (uint32_t(packet[12])<<24  | uint32_t(packet[13])<<16 | uint32_t(packet[14])<<8 | packet[15]);

    uint32_t destinationIPAddr = (uint32_t(packet[16])<<24  | uint32_t(packet[17])<<16 | uint32_t(packet[18])<<8 | packet[19]);

    //VERIFICAÇÕES:

    //verificação se a versão confere com a do IPv4 (0100)
    if(version != 0b0100){
        return header;
    }
    
    //verificação de o IHL é menor que o mínimo possível
    if(IHL < 5){
        return header;
    }

    //verificação se o tamanho total do pacote não é menor do que o mínimo ou maior do que o máximo
    if(totalLength < IHL*4 || totalLength > packet.size()){
        return header;
    }

    bool validCheckSum = verifyCheckSum(packet,IHL);
    if(!validCheckSum){
        return header;
    }

    //criação da estrutura ipv4Header com os valores coletados
    header.version = version;
    header.IHL = IHL;
    header.totalLength = totalLength;
    header.identifier = identifier;
    header.flag = flag;
    header.fragmentOffset = fragmentOffset;
    header.TTL = TTL;
    header.protocol = protocol;
    header.headerChecksum = headerChecksum;
    header.sourceIPAddr = sourceIPAddr;
    header.destinationIPAddr = destinationIPAddr;
    header.valid = true;
    return header;
};

bool verifyCheckSum (const vector<uint8_t> &packet, uint8_t IHL){
    int index = IHL*4;
    uint32_t checkSum = 0;
    for(int i =0; i<index; i+=2){
        checkSum += (uint16_t(packet[i])<<8 | packet[i+1]);
    };
    while(checkSum>>16){
        checkSum = (checkSum>>16) + (checkSum & 0b1111111111111111);
    }
    return checkSum == 0xFFFF;
};

uint16_t calculateCheckSum(const vector<uint8_t> &packet, uint8_t IHL){
    int index = IHL*4;
    uint32_t checkSum = 0;
    for(int i =0; i<index; i+=2){
        if(i == 10){ 
            continue;
        }
        checkSum += (uint16_t(packet[i])<<8 | packet[i+1]);
    };
    while(checkSum>>16){
        checkSum = (checkSum>>16) + (checkSum & 0b1111111111111111);
    }
    return (~checkSum) & 0xFFFF;
};
