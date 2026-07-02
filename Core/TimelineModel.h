#pragma once

#include "ProcessInfo.h"

#include <cstdint>
#include <string>
#include <vector>

namespace GlassPane::Core
{
    enum class TimelineFilter
    {
        All,
        SuspiciousOnly,
        HighSeverityOnly
    };

    struct TimelineRow
    {
        std::uint32_t pid = 0;
        std::uint32_t parentPid = 0;
        std::wstring parentName;
        std::wstring processName;
        std::wstring creationTimeLocal;
        bool hasCreationTime = false;
        Severity severity = Severity::None;
        std::wstring firstIndicator;
    };

    std::vector<TimelineRow> BuildTimelineRows(
        const ProcessSnapshot& snapshot,
        TimelineFilter filter);
}
