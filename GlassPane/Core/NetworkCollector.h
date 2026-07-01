#pragma once

#include "NetworkConnection.h"

#include <cstdint>
#include <vector>

namespace GlassPane::Core
{
    NetworkCollectionResult CollectNetworkConnectionSnapshot();
    NetworkCollectionResult CollectNetworkConnectionsForPidDetailed(std::uint32_t pid);
    std::vector<NetworkConnection> CollectNetworkConnections();
    std::vector<NetworkConnection> CollectNetworkConnectionsForPid(std::uint32_t pid);
}
