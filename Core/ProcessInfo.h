#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace GlassPane::Core
{
    enum class Severity
    {
        None,
        Info,
        Low,
        Medium,
        High
    };

    inline int SeverityRank(Severity severity)
    {
        switch (severity)
        {
        case Severity::High:
            return 4;
        case Severity::Medium:
            return 3;
        case Severity::Low:
            return 2;
        case Severity::Info:
            return 1;
        case Severity::None:
        default:
            return 0;
        }
    }

    inline const wchar_t* SeverityToString(Severity severity)
    {
        switch (severity)
        {
        case Severity::High:
            return L"High";
        case Severity::Medium:
            return L"Medium";
        case Severity::Low:
            return L"Low";
        case Severity::Info:
            return L"Info";
        case Severity::None:
        default:
            return L"None";
        }
    }

    struct ProcessInfo
    {
        std::uint32_t pid = 0;
        std::uint32_t parentPid = 0;
        std::wstring name;
        std::wstring executablePath;
        std::wstring commandLine;
        bool commandLineAccessible = false;
        std::optional<std::uint32_t> sessionId;
        std::wstring architecture = L"Unknown";
        std::wstring creationTimeLocal;
        bool hasCreationTime = false;
        std::vector<std::uint32_t> children;
        bool suspicious = false;
        Severity severity = Severity::None;
        std::vector<std::wstring> indicators;
        std::vector<std::wstring> contextNotes;

        bool IsSuspicious() const
        {
            return suspicious;
        }
    };

    struct ProcessSnapshot
    {
        std::vector<ProcessInfo> processes;
        std::unordered_map<std::uint32_t, std::size_t> indexByPid;
        std::vector<std::size_t> roots;

        void Reindex()
        {
            indexByPid.clear();
            for (std::size_t index = 0; index < processes.size(); ++index)
            {
                indexByPid[processes[index].pid] = index;
            }
        }
    };
}
