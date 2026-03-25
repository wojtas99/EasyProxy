#include "EasyProxy.h"
#include "Windows.h"
#include <WinDivert.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>

EasyProxy::EasyProxy(const std::string& ip, int port) : targetIP(ip), targetPort(port) {
    logger->log("EasyProxy Started");
    logger->log(std::string("LOG_TO_FILE = ") + (LOG_TO_FILE ? "ON" : "OFF") + " LOG_TO_CONSOLE = " + (LOG_TO_CONSOLE ? "ON" : "OFF"));
}

EasyProxy::~EasyProxy() {
    delete logger;
}


void EasyProxy::startProxy() {
    logger->log("Starting proxy on IP=" + targetIP + " Port=" + std::to_string(targetPort) + "\n");

    HANDLE handle;
    char packet[0xFFFF];
    UINT readLen;
    WINDIVERT_ADDRESS addr;

    std::string filter = "tcp && (ip.SrcAddr == " + targetIP +
                         " || ip.DstAddr == " + targetIP +
                         ") && (tcp.SrcPort == " + std::to_string(targetPort) +
                         " || tcp.DstPort == " + std::to_string(targetPort) + ")";

    handle = WinDivertOpen(filter.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);
    if (handle == INVALID_HANDLE_VALUE) {
        logger->log("Failed to open WinDivert handle. Error: " + std::to_string(GetLastError()));
        return;
    }

    long int packetID = 1;

    while (true)
    {
        if (WinDivertRecv(handle, packet, sizeof(packet), &readLen, &addr)) {
            std::string direction = "Packet ID: " + std::to_string(packetID) + (addr.Outbound ? " [Client->Server]" : " [Server->Client]");

            PWINDIVERT_IPHDR ip_header = nullptr;
            PWINDIVERT_TCPHDR tcp_header = nullptr;
            PVOID payload = nullptr;
            UINT payload_len = 0;

            WinDivertHelperParsePacket(
                packet, readLen,
                &ip_header, nullptr, nullptr, nullptr, nullptr,
                &tcp_header, nullptr,
                &payload, &payload_len, nullptr, nullptr
            );

            if (payload != nullptr && payload_len > 0) {
                direction += " Size " + std::to_string(payload_len) + " bytes\n";
                std::vector<uint8_t> packetData;
                packetData.assign(static_cast<uint8_t*>(payload), static_cast<uint8_t*>(payload) + payload_len);
                std::stringstream dump;
                for (size_t i = 0; i < packetData.size(); i += 16) {
                    std::stringstream hexPart;
                    for (size_t j = 0; j < 16; ++j) {
                        if (i + j < packetData.size()) {
                            hexPart << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (int)packetData[i + j] << " ";
                        } else {
                            hexPart << "   ";
                        }
                    }
                    dump << hexPart.str() << "\n";
                }
                logger->log(direction + dump.str());
                ++packetID;
            }
            UINT writeLen;
            if (!WinDivertSend(handle, packet, readLen, &writeLen, &addr)) {
                logger->log("Failed to re-inject packet. Error: " + std::to_string(GetLastError()));
            }
        } else {
            logger->log("Failed to receive packet. Error: " + std::to_string(GetLastError()));
        }
    }
    WinDivertClose(handle);
}