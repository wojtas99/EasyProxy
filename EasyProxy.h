#ifndef EASYPROXY_H
#define EASYPROXY_H
#include "Logger.h"

#define LOG_TO_FILE true
#define LOG_TO_CONSOLE true

class EasyProxy {
private:

    // Logger
    Logger* logger = new Logger(LOG_TO_FILE, LOG_TO_CONSOLE, "EasyLogger.txt");
    std::string targetIP;
    int targetPort = 0;

public:
    EasyProxy(const std::string& ip, int port);
    ~EasyProxy();
    void startProxy();
};



#endif //EASYPROXY_H
