#pragma once

#include <string>
#include <vector>

namespace GlassPane::Core
{
    enum class FindingSeverity
    {
        Info,
        Low,
        Medium,
        High
    };

    struct Finding
    {
        FindingSeverity severity = FindingSeverity::Info;
        std::wstring title;
        std::wstring description;
        std::vector<std::wstring> evidence;
        std::wstring category;
    };

    inline int FindingSeverityRank(FindingSeverity severity)
    {
        switch (severity)
        {
        case FindingSeverity::High:
            return 4;
        case FindingSeverity::Medium:
            return 3;
        case FindingSeverity::Low:
            return 2;
        case FindingSeverity::Info:
        default:
            return 1;
        }
    }

    inline const wchar_t* FindingSeverityToString(FindingSeverity severity)
    {
        switch (severity)
        {
        case FindingSeverity::High:
            return L"High";
        case FindingSeverity::Medium:
            return L"Medium";
        case FindingSeverity::Low:
            return L"Low";
        case FindingSeverity::Info:
        default:
            return L"Info";
        }
    }
}
