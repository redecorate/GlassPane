#pragma once

#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace GlassPane::Core
{
    constexpr std::size_t ServiceMaxRecords = 4096;
    constexpr std::size_t ServiceNameMaxCharacters = 256;
    constexpr std::size_t ServiceDisplayNameMaxCharacters = 512;
    constexpr std::size_t ServiceDescriptionMaxCharacters = 4096;
    constexpr std::size_t ServiceAccountMaxCharacters = 512;
    constexpr std::size_t ServiceImagePathMaxCharacters = 4096;
    constexpr std::size_t ServiceSvchostGroupMaxCharacters = 256;
    constexpr std::size_t ServiceMessageMaxCharacters = 512;

    enum class ServiceProcessModel : std::uint32_t
    {
        Unknown,
        OwnProcess,
        SharedProcess
    };

    enum class ServicePathParseStatus : std::uint32_t
    {
        NotAttempted,
        Empty,
        ParsedQuoted,
        ParsedUnquoted,
        AmbiguousUnquoted,
        RelativeExecutable,
        UnmatchedQuote,
        ExpansionFailed,
        UnresolvedEnvironment,
        InputTruncated
    };

    enum class ServicePathConfidence : std::uint32_t
    {
        None,
        Low,
        Medium,
        High
    };

    namespace Detail
    {
        inline std::wstring HexValue(std::uint32_t value)
        {
            std::wostringstream stream;
            stream << L"0x"
                   << std::uppercase
                   << std::hex
                   << std::setw(8)
                   << std::setfill(L'0')
                   << value;
            return stream.str();
        }

        inline std::wstring UnknownValue(std::uint32_t value)
        {
            return L"Unknown (" + HexValue(value) + L")";
        }

        inline void AppendLabel(std::wstring& text, const wchar_t* label)
        {
            if (!text.empty())
            {
                text += L" | ";
            }
            text += label;
        }
    }

    inline std::wstring ServiceStateDisplayText(std::uint32_t rawValue)
    {
        switch (rawValue)
        {
        case 0x00000001:
            return L"Stopped";
        case 0x00000002:
            return L"Start pending";
        case 0x00000003:
            return L"Stop pending";
        case 0x00000004:
            return L"Running";
        case 0x00000005:
            return L"Continue pending";
        case 0x00000006:
            return L"Pause pending";
        case 0x00000007:
            return L"Paused";
        default:
            return Detail::UnknownValue(rawValue);
        }
    }

    inline std::wstring ServiceStartTypeDisplayText(std::uint32_t rawValue)
    {
        switch (rawValue)
        {
        case 0x00000000:
            return L"Boot";
        case 0x00000001:
            return L"System";
        case 0x00000002:
            return L"Automatic";
        case 0x00000003:
            return L"Manual (demand)";
        case 0x00000004:
            return L"Disabled";
        default:
            return Detail::UnknownValue(rawValue);
        }
    }

    inline ServiceProcessModel ServiceProcessModelFromType(std::uint32_t rawValue)
    {
        constexpr std::uint32_t OwnProcess = 0x00000010;
        constexpr std::uint32_t SharedProcess = 0x00000020;
        const bool hasOwnProcess = (rawValue & OwnProcess) != 0;
        const bool hasSharedProcess = (rawValue & SharedProcess) != 0;

        if (hasOwnProcess == hasSharedProcess)
        {
            return ServiceProcessModel::Unknown;
        }
        return hasOwnProcess ? ServiceProcessModel::OwnProcess : ServiceProcessModel::SharedProcess;
    }

    inline std::wstring ServiceTypeDisplayText(std::uint32_t rawValue)
    {
        constexpr std::uint32_t KernelDriver = 0x00000001;
        constexpr std::uint32_t FileSystemDriver = 0x00000002;
        constexpr std::uint32_t Adapter = 0x00000004;
        constexpr std::uint32_t RecognizerDriver = 0x00000008;
        constexpr std::uint32_t Win32OwnProcess = 0x00000010;
        constexpr std::uint32_t Win32SharedProcess = 0x00000020;
        constexpr std::uint32_t UserService = 0x00000040;
        constexpr std::uint32_t UserServiceInstance = 0x00000080;
        constexpr std::uint32_t InteractiveProcess = 0x00000100;
        constexpr std::uint32_t PackagedService = 0x00000200;
        constexpr std::uint32_t KnownMask =
            KernelDriver |
            FileSystemDriver |
            Adapter |
            RecognizerDriver |
            Win32OwnProcess |
            Win32SharedProcess |
            UserService |
            UserServiceInstance |
            InteractiveProcess |
            PackagedService;

        std::wstring text;
        if ((rawValue & KernelDriver) != 0)
        {
            Detail::AppendLabel(text, L"Kernel driver");
        }
        if ((rawValue & FileSystemDriver) != 0)
        {
            Detail::AppendLabel(text, L"File-system driver");
        }
        if ((rawValue & Adapter) != 0)
        {
            Detail::AppendLabel(text, L"Adapter");
        }
        if ((rawValue & RecognizerDriver) != 0)
        {
            Detail::AppendLabel(text, L"Recognizer driver");
        }

        const std::uint32_t processBits = rawValue & (Win32OwnProcess | Win32SharedProcess | UserService);
        if (processBits == (Win32OwnProcess | UserService))
        {
            Detail::AppendLabel(text, L"User own process");
        }
        else if (processBits == (Win32SharedProcess | UserService))
        {
            Detail::AppendLabel(text, L"User shared process");
        }
        else
        {
            if ((rawValue & Win32OwnProcess) != 0)
            {
                Detail::AppendLabel(text, L"Win32 own process");
            }
            if ((rawValue & Win32SharedProcess) != 0)
            {
                Detail::AppendLabel(text, L"Win32 shared process");
            }
            if ((rawValue & UserService) != 0)
            {
                Detail::AppendLabel(text, L"User service");
            }
        }

        if ((rawValue & UserServiceInstance) != 0)
        {
            Detail::AppendLabel(text, L"User-service instance");
        }
        if ((rawValue & InteractiveProcess) != 0)
        {
            Detail::AppendLabel(text, L"Interactive process");
        }
        if ((rawValue & PackagedService) != 0)
        {
            Detail::AppendLabel(text, L"Packaged service");
        }

        const std::uint32_t unknownBits = rawValue & ~KnownMask;
        if (text.empty())
        {
            return Detail::UnknownValue(rawValue);
        }
        if (unknownBits != 0)
        {
            text += L" | Unknown bits (" + Detail::HexValue(unknownBits) + L")";
        }
        return text;
    }

    inline std::wstring ServiceProcessModelDisplayText(ServiceProcessModel model)
    {
        switch (model)
        {
        case ServiceProcessModel::OwnProcess:
            return L"Own process";
        case ServiceProcessModel::SharedProcess:
            return L"Shared process";
        case ServiceProcessModel::Unknown:
            return L"Unknown";
        default:
            return Detail::UnknownValue(static_cast<std::uint32_t>(model));
        }
    }

    inline std::wstring ServicePathParseStatusDisplayText(ServicePathParseStatus status)
    {
        switch (status)
        {
        case ServicePathParseStatus::NotAttempted:
            return L"Not attempted";
        case ServicePathParseStatus::Empty:
            return L"Empty";
        case ServicePathParseStatus::ParsedQuoted:
            return L"Parsed (quoted)";
        case ServicePathParseStatus::ParsedUnquoted:
            return L"Parsed (unquoted)";
        case ServicePathParseStatus::AmbiguousUnquoted:
            return L"Ambiguous unquoted path";
        case ServicePathParseStatus::RelativeExecutable:
            return L"Relative executable";
        case ServicePathParseStatus::UnmatchedQuote:
            return L"Unmatched quote";
        case ServicePathParseStatus::ExpansionFailed:
            return L"Environment expansion failed";
        case ServicePathParseStatus::UnresolvedEnvironment:
            return L"Unresolved environment variable";
        case ServicePathParseStatus::InputTruncated:
            return L"Input truncated";
        default:
            return Detail::UnknownValue(static_cast<std::uint32_t>(status));
        }
    }

    inline std::wstring ServicePathConfidenceDisplayText(ServicePathConfidence confidence)
    {
        switch (confidence)
        {
        case ServicePathConfidence::None:
            return L"None";
        case ServicePathConfidence::Low:
            return L"Low";
        case ServicePathConfidence::Medium:
            return L"Medium";
        case ServicePathConfidence::High:
            return L"High";
        default:
            return Detail::UnknownValue(static_cast<std::uint32_t>(confidence));
        }
    }

    struct ServiceInfo
    {
        std::wstring serviceName;
        std::wstring displayName;
        std::wstring description;

        std::uint32_t stateRaw = 0;
        std::uint32_t startTypeRaw = 0;
        std::uint32_t serviceTypeRaw = 0;
        std::uint32_t serviceFlagsRaw = 0;

        std::wstring serviceAccount;
        std::wstring rawImagePath;
        std::wstring expandedImagePath;
        std::wstring executablePath;
        ServicePathParseStatus pathParseStatus = ServicePathParseStatus::NotAttempted;
        ServicePathConfidence pathConfidence = ServicePathConfidence::None;
        std::wstring pathParseMessage;

        std::uint32_t scmProcessId = 0;
        bool pidReliableForState = false;
        ServiceProcessModel processModel = ServiceProcessModel::Unknown;
        std::wstring svchostGroup;

        bool configurationAvailable = false;
        bool descriptionAvailable = false;

        bool serviceNameTruncated = false;
        bool displayNameTruncated = false;
        bool descriptionTruncated = false;
        bool serviceAccountTruncated = false;
        bool rawImagePathTruncated = false;
        bool expandedImagePathTruncated = false;
        bool svchostGroupTruncated = false;
        bool pathParseMessageTruncated = false;
        bool statusMessageTruncated = false;

        std::wstring statusMessage;
    };

    struct ServiceCollectionResult
    {
        bool attempted = false;
        bool success = false;
        bool partial = false;
        bool truncated = false;
        std::size_t totalEnumerated = 0;
        std::size_t configurationUnavailableCount = 0;
        std::size_t descriptionUnavailableCount = 0;
        std::wstring statusMessage;
        std::vector<ServiceInfo> services;

        // Derived indexes are rebuilt from services and are not persistence fields.
        std::unordered_map<std::uint32_t, std::vector<std::size_t>> serviceIndexesByPid;

        void ReindexCorrelations()
        {
            serviceIndexesByPid.clear();
            for (std::size_t index = 0; index < services.size(); ++index)
            {
                const ServiceInfo& service = services[index];
                if (service.scmProcessId == 0 || !service.pidReliableForState)
                {
                    continue;
                }
                serviceIndexesByPid[service.scmProcessId].push_back(index);
            }
        }
    };
}
