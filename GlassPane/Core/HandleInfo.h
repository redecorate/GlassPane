#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace GlassPane::Core
{
    struct HandleInfo
    {
        std::uint32_t owningPid = 0;
        std::uint64_t handleValue = 0;
        std::wstring objectType;
        std::wstring objectName;
        std::wstring grantedAccess;
        std::uint32_t grantedAccessRaw = 0;
        std::optional<std::uint32_t> targetPid;
        std::wstring targetProcessName;
        bool isSensitive = false;
        bool typeResolved = false;
        bool nameResolved = false;
        std::wstring errorMessage;
        std::vector<std::wstring> decodedAccess;
        std::vector<std::wstring> indicators;
    };

    struct HandleCollectionResult
    {
        std::uint32_t pid = 0;
        bool success = false;
        std::wstring statusMessage;
        std::size_t systemHandleCount = 0;
        std::size_t sensitiveCount = 0;
        std::vector<HandleInfo> handles;
    };
}
