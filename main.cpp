#include <iostream>
#include "EasyProxy.h"


#include <string>

using namespace std;

int main(int argc, char* argv[]) {
    std::string ip = "127.0.0.1";
    int port = 7172;
    if (argc == 3) {
        ip = argv[1];
        port = std::stoi(argv[2]);
    }

    EasyProxy easy_proxy(ip, port);
    easy_proxy.startProxy();
    return 0;
}
