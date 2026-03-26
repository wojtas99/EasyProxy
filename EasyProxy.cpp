#include "EasyProxy.h"
#include <sstream>
#include <iomanip>
#include <string>
#include <thread>

namespace {
    std::string hexDump(const uint8_t* data, size_t size) {
        std::stringstream dump;
        for (size_t i = 0; i < size; i += 16) {
            std::stringstream hexPart;
            for (size_t j = 0; j < 16; ++j) {
                if (i + j < size) {
                    hexPart << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (int)data[i + j] << " ";
                } else {
                    hexPart << "   ";
                }
            }
            dump << hexPart.str() << "\n";
        }
        return dump.str();
    }
}

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

    std::thread pipeThread([this, handle]() {
        while (true) {
            if (logger->hasData()) {
                std::string dataFromPipe = logger->readData();
                if (!dataFromPipe.empty() && dataFromPipe.length() > 1) {
                    uint8_t direction = static_cast<uint8_t>(dataFromPipe[0]);
                    std::string payload = dataFromPipe.substr(1);

                    std::lock_guard<std::mutex> lock(proxyMutex);
                    
                    bool useC2S = (direction == 0);
                    bool useS2C = (direction == 1);

                    if (useC2S && !hasTemplate) {
                        logger->log("Cannot inject C->S: No client template captured yet! Move your character first.");
                        continue;
                    }
                    if (useS2C && !hasServerTemplate) {
                        logger->log("Cannot inject S2C: No server template captured yet!");
                        continue;
                    }

                    if (useC2S || useS2C) {
                        std::vector<uint8_t> injPacket = (useC2S ? packetTemplate : serverPacketTemplate);
                        WINDIVERT_ADDRESS* addrTemplate = (useC2S ? &clientAddrTemplate : &serverAddrTemplate);
                        
                        injPacket.insert(injPacket.end(), payload.begin(), payload.end());

                        PWINDIVERT_IPHDR temp_ip_header = reinterpret_cast<PWINDIVERT_IPHDR>(injPacket.data());
                        if (temp_ip_header) {
                            temp_ip_header->Length = htons(static_cast<uint16_t>(injPacket.size()));
                        }

                        PWINDIVERT_IPHDR inj_ip_header = nullptr;
                        PWINDIVERT_TCPHDR inj_tcp_header = nullptr;

                        WinDivertHelperParsePacket(
                            reinterpret_cast<PVOID>(injPacket.data()), injPacket.size(),
                            &inj_ip_header, nullptr, nullptr, nullptr, nullptr,
                            &inj_tcp_header, nullptr,
                            nullptr, nullptr, nullptr, nullptr
                        );

                        if (inj_ip_header && inj_tcp_header) {
                            if (useC2S) {
                                inj_tcp_header->SeqNum = htonl(lastClientSeq + seqOffset);
                                inj_tcp_header->AckNum = htonl(lastClientAck);
                                seqOffset += static_cast<uint32_t>(payload.length());
                            } else {
                                inj_tcp_header->SeqNum = htonl(lastServerSeq + serverSeqOffset);
                                inj_tcp_header->AckNum = htonl(lastServerAck);
                                serverSeqOffset += static_cast<uint32_t>(payload.length());
                            }

                            inj_tcp_header->Psh = 1;
                            inj_tcp_header->Ack = 1;

                            WinDivertHelperCalcChecksums(reinterpret_cast<PVOID>(injPacket.data()), injPacket.size(), addrTemplate, 0);

                            std::string dumpStr = hexDump(reinterpret_cast<const uint8_t*>(payload.data()), payload.size());
                            
                            UINT writeLen;
                            if (!WinDivertSend(handle, reinterpret_cast<PVOID>(injPacket.data()), injPacket.size(), &writeLen, addrTemplate)) {
                                logger->log("Failed to inject packet. Error: " + std::to_string(GetLastError()));
                            } else {
                                logger->log("Successfully injected " + std::to_string(payload.length()) + " bytes " + (useC2S ? " [Client->Server]" : " [Server->Client]") + "\n" + dumpStr);
                            }
                        } else {
                            logger->log("Failed to parse injected packet headers! Injection aborted.");
                        }
                    }
                }
            }
            Sleep(10);
        }
    });
    pipeThread.detach();

    long int packetID = 1;

    while (true) {
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

            bool modified = false;

            if (ip_header && tcp_header) {
                std::lock_guard<std::mutex> lock(proxyMutex);
                if (addr.Outbound) {
                    UINT header_len = readLen - payload_len;
                    packetTemplate.assign(packet, packet + header_len);
                    clientAddrTemplate = addr;
                    hasTemplate = true;

                    lastClientSeq = ntohl(tcp_header->SeqNum) + payload_len;
                    lastClientAck = ntohl(tcp_header->AckNum);

                    if (seqOffset > 0) {
                        uint32_t originalSeq = ntohl(tcp_header->SeqNum);
                        tcp_header->SeqNum = htonl(originalSeq + seqOffset);
                        modified = true;
                    }

                    if (serverSeqOffset > 0) {
                        uint32_t originalAck = ntohl(tcp_header->AckNum);
                        tcp_header->AckNum = htonl(originalAck - serverSeqOffset);
                        modified = true;
                    }
                } else {
                    if (seqOffset > 0) {
                        uint32_t originalAck = ntohl(tcp_header->AckNum);
                        tcp_header->AckNum = htonl(originalAck - seqOffset);
                        modified = true;
                    }

                    UINT header_len = readLen - payload_len;
                    serverPacketTemplate.assign(packet, packet + header_len);
                    serverAddrTemplate = addr;
                    hasServerTemplate = true;

                    lastServerSeq = ntohl(tcp_header->SeqNum) + payload_len;
                    lastServerAck = ntohl(tcp_header->AckNum);

                    if (serverSeqOffset > 0) {
                        uint32_t originalSeq = ntohl(tcp_header->SeqNum);
                        tcp_header->SeqNum = htonl(originalSeq + serverSeqOffset);
                        modified = true;
                    }
                }
            }

            if (modified) {
                WinDivertHelperCalcChecksums(packet, readLen, &addr, 0);
            }

            if (payload != nullptr && payload_len > 0) {
                direction += " Size " + std::to_string(payload_len) + " bytes\n";
                std::string dumpStr = hexDump(static_cast<const uint8_t*>(payload), payload_len);
                logger->log(direction + dumpStr);
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
