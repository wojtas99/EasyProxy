#ifndef EASYPROXY_H
#define EASYPROXY_H
#include "Logger.h"
#include <vector>
#include <winsock2.h>
#include <windows.h>
#include <WinDivert.h>
#include <mutex>

#define LOG_TO_FILE true
#define LOG_TO_CONSOLE true

class EasyProxy {
private:

    // Logger
    Logger* logger = new Logger(LOG_TO_FILE, LOG_TO_CONSOLE, "EasyLogger.txt");
    std::string targetIP;
    int targetPort = 0;

    // TCP State Tracking
    uint32_t seqOffset = 0;
    uint32_t serverSeqOffset = 0;

    std::vector<uint8_t> packetTemplate;
    WINDIVERT_ADDRESS clientAddrTemplate;
    bool hasTemplate = false;
    uint32_t lastClientSeq = 0;
    uint32_t lastClientAck = 0;

    std::vector<uint8_t> serverPacketTemplate;
    WINDIVERT_ADDRESS serverAddrTemplate;
    bool hasServerTemplate = false;
    uint32_t lastServerSeq = 0;
    uint32_t lastServerAck = 0;

    std::mutex proxyMutex;

public:
    EasyProxy(const std::string& ip, int port);
    ~EasyProxy();
    void startProxy();
};



#endif //EASYPROXY_H
