#include "TimelineModel.h"

#include "ChainAnalysis.h"
#include "ProcessTree.h"

#include <algorithm>

namespace GlassPane::Core
{
    namespace
    {
        bool IncludeProcess(
            Severity severity,
            bool suspicious,
            TimelineFilter filter)
        {
            switch (filter)
            {
            case TimelineFilter::SuspiciousOnly:
                return suspicious;
            case TimelineFilter::HighSeverityOnly:
                return severity == Severity::High;
            case TimelineFilter::All:
            default:
                return true;
            }
        }
    }

    std::vector<TimelineRow> BuildTimelineRows(
        const ProcessSnapshot& snapshot,
        TimelineFilter filter,
        const std::vector<Severity>& authoritativeSeverities,
        const std::vector<std::uint8_t>& authoritativeSuspicious,
        const std::vector<std::uint8_t>& authoritativeAvailable)
    {
        std::vector<TimelineRow> rows;
        rows.reserve(snapshot.processes.size());

        for (std::size_t processIndex = 0;
            processIndex < snapshot.processes.size();
            ++processIndex)
        {
            const ProcessInfo& process = snapshot.processes[processIndex];
            const bool authorityAvailable =
                processIndex < authoritativeSeverities.size() &&
                processIndex < authoritativeSuspicious.size() &&
                processIndex < authoritativeAvailable.size() &&
                authoritativeAvailable[processIndex] != 0;
            const Severity severity = authorityAvailable
                ? authoritativeSeverities[processIndex]
                : Severity::None;
            const bool suspicious = authorityAvailable
                ? authoritativeSuspicious[processIndex] != 0
                : false;
            if (!IncludeProcess(severity, suspicious, filter))
            {
                continue;
            }

            const ProcessInfo* parent =
                IsUsableParentRelationship(GetParentRelationshipStatus(snapshot, process))
                    ? FindProcessByPid(snapshot, process.parentPid)
                    : nullptr;
            TimelineRow row;
            row.sourceProcessIndex = processIndex;
            row.pid = process.pid;
            row.parentPid = process.parentPid;
            row.parentName = parent == nullptr ? L"" : parent->name;
            row.processName = process.name;
            row.creationTimeLocal = process.creationTimeLocal;
            row.hasCreationTime = process.hasCreationTime;
            row.authorityAvailable = authorityAvailable;
            row.severity = severity;
            rows.push_back(std::move(row));
        }

        std::sort(rows.begin(), rows.end(), [](const TimelineRow& left, const TimelineRow& right) {
            if (left.hasCreationTime != right.hasCreationTime)
            {
                return left.hasCreationTime && !right.hasCreationTime;
            }

            if (left.creationTimeLocal != right.creationTimeLocal)
            {
                return left.creationTimeLocal < right.creationTimeLocal;
            }

            if (left.processName != right.processName)
            {
                return left.processName < right.processName;
            }

            return left.pid < right.pid;
        });

        return rows;
    }
}
