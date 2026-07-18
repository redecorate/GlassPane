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
        // Ephemeral index into the ProcessSnapshot used to build this row.
        // This is not serialized and prevents PID reuse/duplicate-PID rows
        // from borrowing another process identity's authority projection.
        std::size_t sourceProcessIndex = 0;
        std::uint32_t pid = 0;
        std::uint32_t parentPid = 0;
        std::wstring parentName;
        std::wstring processName;
        std::wstring creationTimeLocal;
        bool hasCreationTime = false;
        bool authorityAvailable = false;
        Severity severity = Severity::None;
    };

    // Authority vectors are aligned to snapshot.processes. Missing authority
    // is neutral and excluded from suspicious/high filters; ProcessInfo legacy
    // severity is never consulted by the timeline model.
    std::vector<TimelineRow> BuildTimelineRows(
        const ProcessSnapshot& snapshot,
        TimelineFilter filter,
        const std::vector<Severity>& authoritativeSeverities,
        const std::vector<std::uint8_t>& authoritativeSuspicious,
        const std::vector<std::uint8_t>& authoritativeAvailable);
}
