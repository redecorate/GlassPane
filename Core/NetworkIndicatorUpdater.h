#pragma once

#include "NetworkIndicatorFeed.h"

#include <cstddef>
#include <string>

namespace GlassPane::Core
{
    struct NetworkIndicatorUpdateResult
    {
        bool success = false;
        bool jsonDownloaded = false;
        bool shaDownloaded = false;
        bool checksumParsed = false;
        bool shaVerified = false;
        bool jsonValidated = false;
        bool filesReplaced = false;
        bool cleanupWarning = false;

        std::wstring statusMessage;
        std::wstring detail;
        std::wstring jsonTempPath;
        std::wstring shaTempPath;
        std::wstring finalJsonPath;
        std::wstring finalShaPath;
        std::size_t downloadedJsonBytes = 0;
        std::size_t downloadedShaBytes = 0;
        std::string expectedSha256;
        std::string computedSha256;

        NetworkIndicatorLoadResult loadResult;
    };

    NetworkIndicatorUpdateResult UpdateNetworkIndicatorFeed(
        const std::wstring& indicatorsDirectory);
}
