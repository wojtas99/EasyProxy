#ifndef LOGGER_H
#define LOGGER_H

#include <iostream>
#include <fstream>
#include <string>
#include <windows.h>

class Logger {

private:
    bool enable_logger;
    bool enable_console;
    std::ofstream file;
    std::string pipeName = "\\\\.\\pipe\\EasyProxyPipe";
    
    HANDLE hPipe;
    std::string pipe_name;

    void tryConnectPipe() {
        if (hPipe == INVALID_HANDLE_VALUE) {
            hPipe = CreateFileA(
                pipe_name.c_str(),
                GENERIC_WRITE,
                0,
                NULL,
                OPEN_EXISTING,
                0,
                NULL
            );
        }
    }

public:
    Logger(bool log_to_file, bool log_to_console, const std::string& filename = "EasyLogger.txt")
        : enable_logger(log_to_file), enable_console(log_to_console)
    {
        hPipe = INVALID_HANDLE_VALUE;
        this->pipe_name = pipeName;
        tryConnectPipe();
        file.open(filename, std::ios::out | std::ios::trunc);
    }

    ~Logger() {
        if (file.is_open()) {
            file.close();
        }
        if (hPipe != INVALID_HANDLE_VALUE) {
            CloseHandle(hPipe);
        }
    }

    void log(const std::string& message) {
        if (enable_console) {
            std::cout << message << std::endl;
        }

        if (enable_logger && file.is_open()) {
            file << message << std::endl;
        }

        if (hPipe == INVALID_HANDLE_VALUE) {
            tryConnectPipe();
        }
        if (hPipe != INVALID_HANDLE_VALUE) {
            std::string msgWithEndl = message + "\n";
            DWORD bytesWritten;
            BOOL success = WriteFile(
                hPipe,
                msgWithEndl.c_str(),
                (DWORD)msgWithEndl.length(),
                &bytesWritten,
                NULL
            );
            if (!success) {
                CloseHandle(hPipe);
                hPipe = INVALID_HANDLE_VALUE;
            }
        }
    }
};

#endif //LOGGER_H
