#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace GlassPane::Core
{
    struct NetworkConnection
    {
        std::uint32_t owningPid = 0;
        std::wstring processName;
        std::wstring protocol;
        std::wstring localAddress;
        std::uint16_t localPort = 0;
        std::wstring remoteAddress;
        std::uint16_t remotePort = 0;
        std::wstring state;
        std::wstring addressFamily;
        bool isListening = false;
        bool isLoopback = false;
        bool isLan = false;
        bool isPublicRemote = false;
    };

    struct NetworkCollectionResult
    {
        bool success = false;
        std::wstring statusMessage;
        std::vector<NetworkConnection> connections;
    };
}
