#pragma once

#include "NetworkIndicatorFeed.h"

#include <cstdint>
#include <string>
#include <vector>

namespace GlassPane::Core
{
    std::wstring NormalizeIpIndicatorValue(const std::wstring& value);

    NetworkIndicatorLoadResult LoadNetworkIndicatorFeedFromFile(const std::wstring& filePath);

    std::vector<NetworkIndicatorMatch> MatchNetworkIndicators(
        const std::vector<NetworkConnection>& connections,
        const NetworkIndicatorFeed& feed);

    std::vector<NetworkIndicatorMatch> MatchNetworkIndicatorsForPid(
        const std::vector<NetworkConnection>& connections,
        const NetworkIndicatorFeed& feed,
        std::uint32_t pid);
}
