#ifndef LOGGER_H
#define LOGGER_H


#include <iostream>
#include <fstream>
#include <string>

class Logger {
private:
    bool enable_logger;
    bool enable_console;
    std::ofstream file;

public:
    Logger(bool log_to_file, bool log_to_console, const std::string& filename = "EasyLogger.txt")
        : enable_logger(log_to_file), enable_console(log_to_console)
    {
        if (enable_logger) {
            file.open(filename, std::ios::out | std::ios::trunc);
        }
    }

    ~Logger() {
        if (file.is_open()) {
            file.close();
        }
    }

    void log(const std::string& message) {
        if (enable_console) {
            std::cout << message << std::endl;
        }

        if (enable_logger && file.is_open()) {
            file << message << std::endl;
        }
    }
};



#endif //LOGGER_H
