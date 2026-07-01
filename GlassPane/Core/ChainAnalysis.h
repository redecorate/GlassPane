#pragma once

#include "ProcessInfo.h"

#include <cstdint>
#include <string>
#include <vector>

namespace GlassPane::Core
{
    struct ChainProcessSummary
    {
        std::uint32_t pid = 0;
        std::wstring name;
        Severity severity = Severity::None;
    };

    struct ChainAnalysisResult
    {
        std::uint32_t pid = 0;
        std::vector<ChainProcessSummary> parentChain;
        std::wstring formattedParentChain;
        Severity chainSeverity = Severity::None;
        std::vector<std::wstring> chainIndicators;
    };

    const ProcessInfo* FindProcessByPid(const ProcessSnapshot& snapshot, std::uint32_t pid);
    std::vector<const ProcessInfo*> GetChildren(const ProcessSnapshot& snapshot, std::uint32_t pid);
    std::vector<const ProcessInfo*> GetParentChain(const ProcessSnapshot& snapshot, std::uint32_t pid);
    std::wstring FormatParentChain(const ProcessSnapshot& snapshot, std::uint32_t pid);
    ChainAnalysisResult AnalyzeChain(const ProcessSnapshot& snapshot, std::uint32_t pid);
}
