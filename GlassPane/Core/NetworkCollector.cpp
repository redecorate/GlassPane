#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "NetworkCollector.h"

#include <winsock2.h>
#include <Windows.h>
#include <iphlpapi.h>

#include <algorithm>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")

namespace GlassPane::Core
{
    namespace
    {
        std::uint16_t NetworkPortToHost(DWORD port)
        {
            const std::uint16_t raw = static_cast<std::uint16_t>(port);
            return static_cast<std::uint16_t>(((raw & 0x00ffu) << 8) | ((raw & 0xff00u) >> 8));
        }

        std::wstring Ipv4ToString(DWORD address)
        {
            const auto* bytes = reinterpret_cast<const unsigned char*>(&address);
            std::wstringstream output;
            output << static_cast<unsigned int>(bytes[0]) << L'.'
                << static_cast<unsigned int>(bytes[1]) << L'.'
                << static_cast<unsigned int>(bytes[2]) << L'.'
                << static_cast<unsigned int>(bytes[3]);
            return output.str();
        }

        std::wstring TcpStateToString(DWORD state)
        {
            switch (state)
            {
            case MIB_TCP_STATE_CLOSED:
                return L"CLOSED";
            case MIB_TCP_STATE_LISTEN:
                return L"LISTEN";
            case MIB_TCP_STATE_SYN_SENT:
                return L"SYN_SENT";
            case MIB_TCP_STATE_SYN_RCVD:
                return L"SYN_RCVD";
            case MIB_TCP_STATE_ESTAB:
                return L"ESTABLISHED";
            case MIB_TCP_STATE_FIN_WAIT1:
                return L"FIN_WAIT1";
            case MIB_TCP_STATE_FIN_WAIT2:
                return L"FIN_WAIT2";
            case MIB_TCP_STATE_CLOSE_WAIT:
                return L"CLOSE_WAIT";
            case MIB_TCP_STATE_CLOSING:
                return L"CLOSING";
            case MIB_TCP_STATE_LAST_ACK:
                return L"LAST_ACK";
            case MIB_TCP_STATE_TIME_WAIT:
                return L"TIME_WAIT";
            case MIB_TCP_STATE_DELETE_TCB:
                return L"DELETE_TCB";
            default:
                return L"UNKNOWN";
            }
        }

        bool IsLoopbackAddress(DWORD address)
        {
            const auto* bytes = reinterpret_cast<const unsigned char*>(&address);
            return bytes[0] == 127;
        }

        bool IsLanAddress(DWORD address)
        {
            const auto* bytes = reinterpret_cast<const unsigned char*>(&address);
            if (bytes[0] == 10)
            {
                return true;
            }
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
            {
                return true;
            }
            if (bytes[0] == 192 && bytes[1] == 168)
            {
                return true;
            }
            if (bytes[0] == 169 && bytes[1] == 254)
            {
                return true;
            }
            return false;
        }

        bool IsPublicAddress(DWORD address)
        {
            const auto* bytes = reinterpret_cast<const unsigned char*>(&address);
            if (address == 0 || IsLoopbackAddress(address) || IsLanAddress(address))
            {
                return false;
            }
            if (bytes[0] >= 224)
            {
                return false;
            }
            return true;
        }

        void AppendStatus(std::wstring& status, const std::wstring& message)
        {
            if (!status.empty())
            {
                status += L" ";
            }
            status += message;
        }

        bool AppendTcpConnections(std::vector<NetworkConnection>& connections, std::wstring& status)
        {
            DWORD tableSize = 0;
            DWORD result = GetExtendedTcpTable(
                nullptr,
                &tableSize,
                FALSE,
                AF_INET,
                TCP_TABLE_OWNER_PID_ALL,
                0);
            if (result != ERROR_INSUFFICIENT_BUFFER || tableSize == 0)
            {
                AppendStatus(status, L"Could not size TCP owner table.");
                return false;
            }

            std::vector<unsigned char> buffer(tableSize);
            auto* table = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());
            result = GetExtendedTcpTable(
                table,
                &tableSize,
                FALSE,
                AF_INET,
                TCP_TABLE_OWNER_PID_ALL,
                0);
            if (result != NO_ERROR)
            {
                AppendStatus(status, L"Could not read TCP owner table.");
                return false;
            }

            for (DWORD index = 0; index < table->dwNumEntries; ++index)
            {
                const MIB_TCPROW_OWNER_PID& row = table->table[index];
                NetworkConnection connection;
                connection.owningPid = row.dwOwningPid;
                connection.protocol = L"TCP";
                connection.localAddress = Ipv4ToString(row.dwLocalAddr);
                connection.localPort = NetworkPortToHost(row.dwLocalPort);
                connection.remoteAddress = Ipv4ToString(row.dwRemoteAddr);
                connection.remotePort = NetworkPortToHost(row.dwRemotePort);
                connection.state = TcpStateToString(row.dwState);
                connection.addressFamily = L"IPv4";
                connection.isListening = row.dwState == MIB_TCP_STATE_LISTEN;
                const DWORD scopeAddress = connection.isListening ? row.dwLocalAddr : row.dwRemoteAddr;
                connection.isLoopback = IsLoopbackAddress(scopeAddress);
                connection.isLan = IsLanAddress(scopeAddress);
                connection.isPublicRemote = !connection.isListening && IsPublicAddress(row.dwRemoteAddr);
                connections.push_back(std::move(connection));
            }

            return true;
        }

        bool AppendUdpConnections(std::vector<NetworkConnection>& connections, std::wstring& status)
        {
            DWORD tableSize = 0;
            DWORD result = GetExtendedUdpTable(
                nullptr,
                &tableSize,
                FALSE,
                AF_INET,
                UDP_TABLE_OWNER_PID,
                0);
            if (result != ERROR_INSUFFICIENT_BUFFER || tableSize == 0)
            {
                AppendStatus(status, L"Could not size UDP owner table.");
                return false;
            }

            std::vector<unsigned char> buffer(tableSize);
            auto* table = reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(buffer.data());
            result = GetExtendedUdpTable(
                table,
                &tableSize,
                FALSE,
                AF_INET,
                UDP_TABLE_OWNER_PID,
                0);
            if (result != NO_ERROR)
            {
                AppendStatus(status, L"Could not read UDP owner table.");
                return false;
            }

            for (DWORD index = 0; index < table->dwNumEntries; ++index)
            {
                const MIB_UDPROW_OWNER_PID& row = table->table[index];
                NetworkConnection connection;
                connection.owningPid = row.dwOwningPid;
                connection.protocol = L"UDP";
                connection.localAddress = Ipv4ToString(row.dwLocalAddr);
                connection.localPort = NetworkPortToHost(row.dwLocalPort);
                connection.remoteAddress = L"";
                connection.remotePort = 0;
                connection.state = L"";
                connection.addressFamily = L"IPv4";
                connection.isListening = true;
                connection.isLoopback = IsLoopbackAddress(row.dwLocalAddr);
                connection.isLan = IsLanAddress(row.dwLocalAddr);
                connection.isPublicRemote = false;
                connections.push_back(std::move(connection));
            }

            return true;
        }
    }

    NetworkCollectionResult CollectNetworkConnectionSnapshot()
    {
        NetworkCollectionResult result;
        const bool tcpOk = AppendTcpConnections(result.connections, result.statusMessage);
        const bool udpOk = AppendUdpConnections(result.connections, result.statusMessage);

        result.success = tcpOk || udpOk;
        if (result.statusMessage.empty())
        {
            result.statusMessage = L"Network owner tables collected.";
        }

        std::sort(result.connections.begin(), result.connections.end(), [](const NetworkConnection& left, const NetworkConnection& right) {
            if (left.owningPid != right.owningPid)
            {
                return left.owningPid < right.owningPid;
            }
            if (left.protocol != right.protocol)
            {
                return left.protocol < right.protocol;
            }
            if (left.localAddress != right.localAddress)
            {
                return left.localAddress < right.localAddress;
            }
            return left.localPort < right.localPort;
        });

        return result;
    }

    NetworkCollectionResult CollectNetworkConnectionsForPidDetailed(std::uint32_t pid)
    {
        NetworkCollectionResult result = CollectNetworkConnectionSnapshot();
        std::vector<NetworkConnection> filtered;
        filtered.reserve(result.connections.size());
        for (const NetworkConnection& connection : result.connections)
        {
            if (connection.owningPid == pid)
            {
                filtered.push_back(connection);
            }
        }
        result.connections = std::move(filtered);
        return result;
    }

    std::vector<NetworkConnection> CollectNetworkConnections()
    {
        return CollectNetworkConnectionSnapshot().connections;
    }

    std::vector<NetworkConnection> CollectNetworkConnectionsForPid(std::uint32_t pid)
    {
        return CollectNetworkConnectionsForPidDetailed(pid).connections;
    }
}
