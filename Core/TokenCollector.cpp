#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "TokenCollector.h"

#include <Windows.h>
#include <sddl.h>

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#pragma comment(lib, "Advapi32.lib")

namespace GlassPane::Core
{
    namespace
    {
        void AppendError(TokenInfo& token, const std::wstring& message)
        {
            if (message.empty())
            {
                return;
            }

            if (!token.errorMessage.empty())
            {
                token.errorMessage += L" ";
            }
            token.errorMessage += message;
        }

        std::wstring WindowsErrorMessage(DWORD error)
        {
            wchar_t* buffer = nullptr;
            const DWORD length = FormatMessageW(
                FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                nullptr,
                error,
                0,
                reinterpret_cast<LPWSTR>(&buffer),
                0,
                nullptr);

            if (length == 0 || buffer == nullptr)
            {
                return L"Windows error " + std::to_wstring(error);
            }

            std::wstring message(buffer, length);
            LocalFree(buffer);
            while (!message.empty() && (message.back() == L'\r' || message.back() == L'\n' || message.back() == L'.'))
            {
                message.pop_back();
            }
            return message;
        }

        std::vector<unsigned char> QueryTokenBuffer(
            HANDLE tokenHandle,
            TOKEN_INFORMATION_CLASS tokenClass,
            TokenInfo& tokenInfo,
            const wchar_t* fieldName)
        {
            DWORD requiredBytes = 0;
            if (GetTokenInformation(tokenHandle, tokenClass, nullptr, 0, &requiredBytes) != FALSE ||
                GetLastError() != ERROR_INSUFFICIENT_BUFFER ||
                requiredBytes == 0)
            {
                AppendError(tokenInfo, std::wstring(L"Could not size ") + fieldName + L": " + WindowsErrorMessage(GetLastError()) + L".");
                return {};
            }

            std::vector<unsigned char> buffer(requiredBytes);
            if (GetTokenInformation(tokenHandle, tokenClass, buffer.data(), requiredBytes, &requiredBytes) == FALSE)
            {
                AppendError(tokenInfo, std::wstring(L"Could not read ") + fieldName + L": " + WindowsErrorMessage(GetLastError()) + L".");
                return {};
            }

            return buffer;
        }

        std::wstring SidToString(PSID sid)
        {
            if (sid == nullptr || IsValidSid(sid) == FALSE)
            {
                return {};
            }

            LPWSTR sidText = nullptr;
            if (ConvertSidToStringSidW(sid, &sidText) == FALSE || sidText == nullptr)
            {
                return {};
            }

            std::wstring result(sidText);
            LocalFree(sidText);
            return result;
        }

        void PopulateUser(HANDLE tokenHandle, TokenInfo& tokenInfo)
        {
            const std::vector<unsigned char> buffer = QueryTokenBuffer(tokenHandle, TokenUser, tokenInfo, L"TokenUser");
            if (buffer.empty())
            {
                return;
            }

            const auto* tokenUser = reinterpret_cast<const TOKEN_USER*>(buffer.data());
            tokenInfo.userSid = SidToString(tokenUser->User.Sid);

            DWORD nameLength = 0;
            DWORD domainLength = 0;
            SID_NAME_USE use = SidTypeUnknown;
            LookupAccountSidW(
                nullptr,
                tokenUser->User.Sid,
                nullptr,
                &nameLength,
                nullptr,
                &domainLength,
                &use);

            if (nameLength == 0)
            {
                return;
            }

            std::wstring name(nameLength, L'\0');
            std::wstring domain(domainLength, L'\0');
            if (LookupAccountSidW(
                nullptr,
                tokenUser->User.Sid,
                name.data(),
                &nameLength,
                domain.empty() ? nullptr : domain.data(),
                &domainLength,
                &use) == FALSE)
            {
                AppendError(tokenInfo, L"Could not resolve token user SID: " + WindowsErrorMessage(GetLastError()) + L".");
                return;
            }

            name.resize(nameLength);
            domain.resize(domainLength);
            tokenInfo.userName = name;
            tokenInfo.domainName = domain;
        }

        std::wstring IntegrityNameFromRid(std::uint32_t rid)
        {
            if (rid >= SECURITY_MANDATORY_PROTECTED_PROCESS_RID)
            {
                return L"Protected Process";
            }
            if (rid >= SECURITY_MANDATORY_SYSTEM_RID)
            {
                return L"System";
            }
            if (rid >= SECURITY_MANDATORY_HIGH_RID)
            {
                return L"High";
            }
            if (rid >= SECURITY_MANDATORY_MEDIUM_RID + 0x100)
            {
                return L"Medium Plus";
            }
            if (rid >= SECURITY_MANDATORY_MEDIUM_RID)
            {
                return L"Medium";
            }
            if (rid >= SECURITY_MANDATORY_LOW_RID)
            {
                return L"Low";
            }
            return L"Untrusted";
        }

        void PopulateIntegrity(HANDLE tokenHandle, TokenInfo& tokenInfo)
        {
            const std::vector<unsigned char> buffer = QueryTokenBuffer(tokenHandle, TokenIntegrityLevel, tokenInfo, L"TokenIntegrityLevel");
            if (buffer.empty())
            {
                return;
            }

            const auto* label = reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(buffer.data());
            if (label->Label.Sid == nullptr || IsValidSid(label->Label.Sid) == FALSE)
            {
                AppendError(tokenInfo, L"Token integrity SID is invalid.");
                return;
            }

            const UCHAR subAuthorityCount = *GetSidSubAuthorityCount(label->Label.Sid);
            if (subAuthorityCount == 0)
            {
                AppendError(tokenInfo, L"Token integrity SID has no RID.");
                return;
            }

            tokenInfo.integrityRid = *GetSidSubAuthority(label->Label.Sid, subAuthorityCount - 1);
            tokenInfo.integrityLevelName = IntegrityNameFromRid(tokenInfo.integrityRid);
        }

        std::wstring ElevationTypeText(TOKEN_ELEVATION_TYPE type)
        {
            switch (type)
            {
            case TokenElevationTypeDefault:
                return L"Default";
            case TokenElevationTypeFull:
                return L"Full";
            case TokenElevationTypeLimited:
                return L"Limited";
            default:
                return L"Unknown";
            }
        }

        void PopulateElevation(HANDLE tokenHandle, TokenInfo& tokenInfo)
        {
            TOKEN_ELEVATION elevation = {};
            DWORD returnedBytes = 0;
            if (GetTokenInformation(
                tokenHandle,
                TokenElevation,
                &elevation,
                sizeof(elevation),
                &returnedBytes) != FALSE)
            {
                tokenInfo.isElevated = elevation.TokenIsElevated != 0;
            }
            else
            {
                AppendError(tokenInfo, L"Could not read TokenElevation: " + WindowsErrorMessage(GetLastError()) + L".");
            }

            TOKEN_ELEVATION_TYPE elevationType = TokenElevationTypeDefault;
            if (GetTokenInformation(
                tokenHandle,
                TokenElevationType,
                &elevationType,
                sizeof(elevationType),
                &returnedBytes) != FALSE)
            {
                tokenInfo.elevationType = ElevationTypeText(elevationType);
            }
            else
            {
                AppendError(tokenInfo, L"Could not read TokenElevationType: " + WindowsErrorMessage(GetLastError()) + L".");
            }
        }

        std::wstring TokenTypeText(TOKEN_TYPE type)
        {
            switch (type)
            {
            case TokenPrimary:
                return L"Primary";
            case TokenImpersonation:
                return L"Impersonation";
            default:
                return L"Unknown";
            }
        }

        std::wstring ImpersonationLevelText(SECURITY_IMPERSONATION_LEVEL level)
        {
            switch (level)
            {
            case SecurityAnonymous:
                return L"Anonymous";
            case SecurityIdentification:
                return L"Identification";
            case SecurityImpersonation:
                return L"Impersonation";
            case SecurityDelegation:
                return L"Delegation";
            default:
                return L"Unknown";
            }
        }

        void PopulateTokenType(HANDLE tokenHandle, TokenInfo& tokenInfo)
        {
            TOKEN_TYPE tokenType = TokenPrimary;
            DWORD returnedBytes = 0;
            if (GetTokenInformation(
                tokenHandle,
                TokenType,
                &tokenType,
                sizeof(tokenType),
                &returnedBytes) == FALSE)
            {
                AppendError(tokenInfo, L"Could not read TokenType: " + WindowsErrorMessage(GetLastError()) + L".");
                return;
            }

            tokenInfo.tokenType = TokenTypeText(tokenType);
            if (tokenType != TokenImpersonation)
            {
                return;
            }

            SECURITY_IMPERSONATION_LEVEL level = SecurityAnonymous;
            if (GetTokenInformation(
                tokenHandle,
                TokenImpersonationLevel,
                &level,
                sizeof(level),
                &returnedBytes) != FALSE)
            {
                tokenInfo.impersonationLevel = ImpersonationLevelText(level);
            }
            else
            {
                AppendError(tokenInfo, L"Could not read TokenImpersonationLevel: " + WindowsErrorMessage(GetLastError()) + L".");
            }
        }

        void PopulateAppContainerAndSession(HANDLE tokenHandle, TokenInfo& tokenInfo)
        {
            DWORD returnedBytes = 0;
            DWORD appContainer = 0;
            if (GetTokenInformation(
                tokenHandle,
                TokenIsAppContainer,
                &appContainer,
                sizeof(appContainer),
                &returnedBytes) != FALSE)
            {
                tokenInfo.isAppContainer = appContainer != 0;
            }
            else
            {
                AppendError(tokenInfo, L"Could not read TokenIsAppContainer: " + WindowsErrorMessage(GetLastError()) + L".");
            }

            DWORD sessionId = 0;
            if (GetTokenInformation(
                tokenHandle,
                TokenSessionId,
                &sessionId,
                sizeof(sessionId),
                &returnedBytes) != FALSE)
            {
                tokenInfo.sessionId = static_cast<std::uint32_t>(sessionId);
            }
            else
            {
                AppendError(tokenInfo, L"Could not read TokenSessionId: " + WindowsErrorMessage(GetLastError()) + L".");
            }
        }

        bool LookupPrivilegeName(const LUID& luid, std::wstring& name)
        {
            DWORD length = 0;
            LookupPrivilegeNameW(nullptr, const_cast<PLUID>(&luid), nullptr, &length);
            if (length == 0 && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            {
                return false;
            }

            std::wstring buffer(length + 1, L'\0');
            if (LookupPrivilegeNameW(nullptr, const_cast<PLUID>(&luid), buffer.data(), &length) == FALSE)
            {
                return false;
            }

            buffer.resize(length);
            name = buffer;
            return true;
        }

        std::wstring ResolvePrivilegeDisplayName(const std::wstring& privilegeName)
        {
            if (privilegeName.empty())
            {
                return {};
            }

            DWORD length = 0;
            DWORD languageId = 0;
            LookupPrivilegeDisplayNameW(nullptr, privilegeName.c_str(), nullptr, &length, &languageId);
            if (length == 0 && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            {
                return {};
            }

            std::wstring buffer(length + 1, L'\0');
            if (LookupPrivilegeDisplayNameW(nullptr, privilegeName.c_str(), buffer.data(), &length, &languageId) == FALSE)
            {
                return {};
            }

            buffer.resize(length);
            return buffer;
        }

        void PopulatePrivileges(HANDLE tokenHandle, TokenInfo& tokenInfo)
        {
            const std::vector<unsigned char> buffer = QueryTokenBuffer(tokenHandle, TokenPrivileges, tokenInfo, L"TokenPrivileges");
            if (buffer.empty())
            {
                return;
            }

            const auto* privileges = reinterpret_cast<const TOKEN_PRIVILEGES*>(buffer.data());
            tokenInfo.privileges.reserve(privileges->PrivilegeCount);
            for (DWORD index = 0; index < privileges->PrivilegeCount; ++index)
            {
                const LUID_AND_ATTRIBUTES& source = privileges->Privileges[index];
                PrivilegeInfo privilege;
                if (!LookupPrivilegeName(source.Luid, privilege.name))
                {
                    privilege.name = L"(unknown privilege)";
                }
                privilege.displayName = ResolvePrivilegeDisplayName(privilege.name);
                privilege.enabled = (source.Attributes & SE_PRIVILEGE_ENABLED) != 0;
                privilege.enabledByDefault = (source.Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT) != 0;
                privilege.removed = (source.Attributes & SE_PRIVILEGE_REMOVED) != 0;
                privilege.usedForAccess = (source.Attributes & SE_PRIVILEGE_USED_FOR_ACCESS) != 0;
                tokenInfo.privileges.push_back(std::move(privilege));
            }

            std::sort(tokenInfo.privileges.begin(), tokenInfo.privileges.end(), [](const PrivilegeInfo& left, const PrivilegeInfo& right) {
                return left.name < right.name;
            });
        }

        void PopulateAdminMembership(HANDLE tokenHandle, TokenInfo& tokenInfo)
        {
            BYTE adminSidBuffer[SECURITY_MAX_SID_SIZE] = {};
            DWORD adminSidSize = sizeof(adminSidBuffer);
            if (CreateWellKnownSid(
                WinBuiltinAdministratorsSid,
                nullptr,
                adminSidBuffer,
                &adminSidSize) == FALSE)
            {
                AppendError(tokenInfo, L"Could not build Administrators SID: " + WindowsErrorMessage(GetLastError()) + L".");
                return;
            }

            const std::vector<unsigned char> buffer = QueryTokenBuffer(tokenHandle, TokenGroups, tokenInfo, L"TokenGroups");
            if (buffer.empty())
            {
                return;
            }

            const auto* groups = reinterpret_cast<const TOKEN_GROUPS*>(buffer.data());
            for (DWORD index = 0; index < groups->GroupCount; ++index)
            {
                const SID_AND_ATTRIBUTES& group = groups->Groups[index];
                if (EqualSid(group.Sid, adminSidBuffer) == FALSE)
                {
                    continue;
                }

                const DWORD enabledMask = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_OWNER;
                tokenInfo.isAdmin =
                    (group.Attributes & SE_GROUP_USE_FOR_DENY_ONLY) == 0 &&
                    (group.Attributes & enabledMask) != 0;
                return;
            }
        }
    }

    TokenInfo CollectProcessTokenInfo(const ProcessInfo& process)
    {
        TokenInfo tokenInfo;

        HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process.pid);
        if (processHandle == nullptr)
        {
            tokenInfo.errorMessage = L"Could not open process for token inspection: " + WindowsErrorMessage(GetLastError()) + L".";
            return tokenInfo;
        }

        HANDLE tokenHandle = nullptr;
        if (OpenProcessToken(processHandle, TOKEN_QUERY, &tokenHandle) == FALSE)
        {
            tokenInfo.errorMessage = L"Could not open process token: " + WindowsErrorMessage(GetLastError()) + L".";
            CloseHandle(processHandle);
            return tokenInfo;
        }

        tokenInfo.success = true;
        PopulateUser(tokenHandle, tokenInfo);
        PopulateIntegrity(tokenHandle, tokenInfo);
        PopulateElevation(tokenHandle, tokenInfo);
        PopulateTokenType(tokenHandle, tokenInfo);
        PopulateAppContainerAndSession(tokenHandle, tokenInfo);
        PopulateAdminMembership(tokenHandle, tokenInfo);
        PopulatePrivileges(tokenHandle, tokenInfo);

        CloseHandle(tokenHandle);
        CloseHandle(processHandle);
        return tokenInfo;
    }
}
