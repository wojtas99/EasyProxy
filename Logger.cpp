#include "Logger.h"

void Logger::tryConnectPipe() {
    if (hPipe == INVALID_HANDLE_VALUE) {
        hPipe = CreateFileA(
            pipe_name.c_str(),
            GENERIC_READ |GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );
    }
}

Logger::Logger(bool log_to_file, bool log_to_console, const std::string& filename)
    : enable_logger(log_to_file), enable_console(log_to_console)
{
    hPipe = INVALID_HANDLE_VALUE;
    this->pipe_name = pipeName;
    tryConnectPipe();
    file.open(filename, std::ios::out | std::ios::trunc);
}

Logger::~Logger() {
    if (file.is_open()) file.close();
    if (hPipe != INVALID_HANDLE_VALUE) CloseHandle(hPipe);
}

void Logger::log(const std::string& message) {
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

bool Logger::hasData() {
    if (hPipe == INVALID_HANDLE_VALUE) return false;
    DWORD bytesAvailable = 0;
    BOOL success = PeekNamedPipe(hPipe, NULL, 0, NULL, &bytesAvailable, NULL);
    return (success && bytesAvailable > 0);
}

std::string Logger::readData() {
    if (hPipe == INVALID_HANDLE_VALUE) return "";

    DWORD bytesAvailable = 0;
    if (!PeekNamedPipe(hPipe, NULL, 0, NULL, &bytesAvailable, NULL) || bytesAvailable == 0) {
        return "";
    }

    std::vector<char> buffer(bytesAvailable + 1);
    DWORD bytesRead;

    if (ReadFile(hPipe, &buffer[0], bytesAvailable, &bytesRead, NULL)) {
        buffer[bytesRead] = '\0';
        return std::string(buffer.data(), bytesRead);
    }

    return "";
}
