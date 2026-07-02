#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace GlassPane::Core
{
    struct PrivilegeInfo
    {
        std::wstring name;
        std::wstring displayName;
        bool enabled = false;
        bool enabledByDefault = false;
        bool removed = false;
        bool usedForAccess = false;
    };

    struct TokenInfo
    {
        bool success = false;
        std::wstring errorMessage;
        std::wstring userName;
        std::wstring domainName;
        std::wstring userSid;
        std::wstring integrityLevelName;
        std::uint32_t integrityRid = 0;
        std::wstring elevationType;
        bool isElevated = false;
        bool isAdmin = false;
        bool isAppContainer = false;
        std::optional<std::uint32_t> sessionId;
        std::wstring tokenType;
        std::wstring impersonationLevel;
        std::vector<PrivilegeInfo> privileges;
    };
}
