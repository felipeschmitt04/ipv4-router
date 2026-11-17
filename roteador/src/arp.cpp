#include "../include/arp.hpp"

#include <algorithm>

void ArpCache::learn(
    std::uint32_t neighborIp,
    const std::array<std::uint8_t, 6> &learnedMac,
    const std::string &interfaceName,
    std::chrono::steady_clock::time_point now)
{
    std::lock_guard<std::mutex> lock(cacheMutex);

    auto existingEntry = std::find_if(
        cacheEntries.begin(),
        cacheEntries.end(),
        [&](const ArpCacheEntry &entry)
        {
            return entry.neighborIp == neighborIp &&
                   entry.interfaceName == interfaceName;
        });

    const auto expirationTime = now + std::chrono::seconds(30);

    if (existingEntry != cacheEntries.end())
    {
        existingEntry->learnedMac = learnedMac;
        existingEntry->expirationTime = expirationTime;
        return;
    }

    cacheEntries.push_back({neighborIp,
                            learnedMac,
                            interfaceName,
                            expirationTime});
}

std::optional<ArpMessage> parseArpMessage(const std::vector<std::uint8_t> &bytes_Arp)
{
    if (bytes_Arp.size() < 28)
    {
        return std::nullopt;
    }
    ArpMessage mensagem{};
    mensagem.hardware_type = (static_cast<std::uint16_t>(bytes_Arp[0]) << 8) | bytes_Arp[1];
    mensagem.protocol_type = (static_cast<std::uint16_t>(bytes_Arp[2]) << 8) | bytes_Arp[3];
    mensagem.hardware_length = bytes_Arp[4];
    mensagem.protocol_length = bytes_Arp[5];
    mensagem.operation = (static_cast<std::uint16_t>(bytes_Arp[6]) << 8) | bytes_Arp[7];

    if (mensagem.hardware_type != 1 ||
        mensagem.protocol_type != 0x0800 ||
        mensagem.hardware_length != 6 ||
        mensagem.protocol_length != 4 ||
        (mensagem.operation != 1 && mensagem.operation != 2))
    {
        return std::nullopt;
    }

    for (std::size_t i = 0; i < 6; ++i)
    {
        mensagem.senderMAC[i] = bytes_Arp[8 + i];
        mensagem.targetMAC[i] = bytes_Arp[18 + i];
    }

    mensagem.senderIP =
        (static_cast<std::uint32_t>(bytes_Arp[14]) << 24) |
        (static_cast<std::uint32_t>(bytes_Arp[15]) << 16) |
        (static_cast<std::uint32_t>(bytes_Arp[16]) << 8) |
        (static_cast<std::uint32_t>(bytes_Arp[17]));

    mensagem.targetIP =
        (static_cast<std::uint32_t>(bytes_Arp[24]) << 24) |
        (static_cast<std::uint32_t>(bytes_Arp[25]) << 16) |
        (static_cast<std::uint32_t>(bytes_Arp[26]) << 8) |
        (static_cast<std::uint32_t>(bytes_Arp[27]));

    return mensagem;
}

std::optional<std::array<std::uint8_t, 6>> ArpCache::lookup(
    std::uint32_t neighborIp,
    const std::string &interfaceName,
    std::chrono::steady_clock::time_point now)
{
    std::lock_guard<std::mutex> lock(cacheMutex);

    auto existingEntry = std::find_if(
        cacheEntries.begin(),
        cacheEntries.end(),
        [&](const ArpCacheEntry &entry)
        {
            return entry.neighborIp == neighborIp &&
                   entry.interfaceName == interfaceName;
        });

    if(existingEntry == cacheEntries.end()){
        return std::nullopt;
    }

    if(now >= existingEntry->expirationTime){
        cacheEntries.erase(existingEntry);
        return std::nullopt;
    }

    return existingEntry->learnedMac;
}

void ArpCache::removeExpired(std::chrono::steady_clock::time_point now){
    std::lock_guard<std::mutex> lock(cacheMutex);

    const auto firstExpired = std::remove_if(
        cacheEntries.begin(),
        cacheEntries.end(),
        [now](const ArpCacheEntry& entry){
            return now >= entry.expirationTime;
        }
    );

    cacheEntries.erase(firstExpired, cacheEntries.end());
}

bool shouldReplyToArpRequest(
    const ArpMessage &message,
    std::uint32_t incomingInterfaceIp)
{
    if (message.operation != 1)
        return false;
    if (message.senderIP == 0)
        return false;
    if (message.targetIP != incomingInterfaceIp)
        return false;

    return true;
}

std::vector<std::uint8_t> buildArpReply(
    const ArpMessage &request,
    const std::array<std::uint8_t, 6> &localMac,
    std::uint32_t localIp)
{
    std::vector<std::uint8_t> reply = {
        0x00, 0x01, // Ethernet
        0x08, 0x00, // IPv4
        0x06,       // MAC
        0x04,       // IP
        0x00, 0x02  // operacao: reply
    };

    reply.insert(reply.end(), localMac.begin(), localMac.end());

    reply.push_back(static_cast<std::uint8_t>(localIp >> 24));
    reply.push_back(static_cast<std::uint8_t>(localIp >> 16));
    reply.push_back(static_cast<std::uint8_t>(localIp >> 8));
    reply.push_back(static_cast<std::uint8_t>(localIp));

    reply.insert(reply.end(), request.senderMAC.begin(), request.senderMAC.end());

    reply.push_back(static_cast<std::uint8_t>(request.senderIP >> 24));
    reply.push_back(static_cast<std::uint8_t>(request.senderIP >> 16));
    reply.push_back(static_cast<std::uint8_t>(request.senderIP >> 8));
    reply.push_back(static_cast<std::uint8_t>(request.senderIP));

    return reply;
}