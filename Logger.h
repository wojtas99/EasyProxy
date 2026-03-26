#ifndef LOGGER_H
#define LOGGER_H

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <windows.h>

class Logger {

private:
    bool enable_logger;
    bool enable_console;
    std::ofstream file;
    std::string pipeName = "\\\\.\\pipe\\EasyProxyPipe";
    
    HANDLE hPipe;
    std::string pipe_name;

    void tryConnectPipe();

public:
    Logger(bool log_to_file, bool log_to_console, const std::string& filename = "EasyLogger.txt");
    ~Logger();

    void log(const std::string& message);
    bool hasData();
    std::string readData();
};

#endif //LOGGER_H
