#pragma once

#include "ProcessInfo.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace GlassPane::Core
{
    constexpr std::size_t ChainIndicatorFactMaxCount = 128;
    constexpr std::size_t ChainIndicatorFactRuleIdMaxCharacters = 128;
    constexpr std::size_t ChainIndicatorFactValueMaxCharacters = 4096;

    enum class ChainIndicatorFactKind : std::uint32_t
    {
        Unknown = 0,
        EncodedCommand = 1,
        ProcessRelationship = 2
    };

    struct ChainIndicatorFact
    {
        ChainIndicatorFactKind kind = ChainIndicatorFactKind::Unknown;
        std::string sourceRuleId;
        std::uint32_t sourcePid = 0;
        std::uint32_t targetPid = 0;
        std::wstring rawValue;
        std::wstring normalizedValue;
        std::size_t sourceIndicatorOrdinal = 0;
    };

    struct ChainProcessSummary
    {
        std::uint32_t pid = 0;
        std::wstring name;
    };

    struct ChainAnalysisResult
    {
        std::uint32_t pid = 0;
        std::vector<ChainProcessSummary> parentChain;
        std::wstring formattedParentChain;
        std::vector<ChainIndicatorFact> chainIndicatorFacts;
        bool chainIndicatorFactsTruncated = false;
    };

    const ProcessInfo* FindProcessByPid(const ProcessSnapshot& snapshot, std::uint32_t pid);
    std::vector<const ProcessInfo*> GetChildren(const ProcessSnapshot& snapshot, std::uint32_t pid);
    std::vector<const ProcessInfo*> GetParentChain(const ProcessSnapshot& snapshot, std::uint32_t pid);
    std::wstring FormatParentChain(const ProcessSnapshot& snapshot, std::uint32_t pid);
    ChainAnalysisResult AnalyzeChain(const ProcessSnapshot& snapshot, std::uint32_t pid);
}
