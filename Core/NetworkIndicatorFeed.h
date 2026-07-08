#pragma once

#include "NetworkIndicator.h"

#include <cstddef>
#include <string>
#include <vector>

namespace GlassPane::Core
{
    struct NetworkIndicatorFeedMetadata
    {
        std::wstring feedName;
        int schemaVersion = 0;
        std::wstring generatedAt;
        std::wstring expiresAt;
        std::wstring sourcePath;
        std::wstring loadedAt;
        std::size_t indicatorCount = 0;
        std::wstring loadError;
    };

    struct NetworkIndicatorFeed
    {
        bool loaded = false;
        NetworkIndicatorFeedMetadata metadata;
        std::vector<NetworkIndicator> indicators;
    };

    struct NetworkIndicatorLoadResult
    {
        bool success = false;
        bool missing = false;
        bool malformed = false;
        std::wstring statusMessage;
        NetworkIndicatorFeed feed;
    };
}
