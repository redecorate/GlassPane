#include "TimelineModel.h"

#include "ChainAnalysis.h"
#include "ProcessTree.h"

#include <algorithm>

namespace GlassPane::Core
{
    namespace
    {
        bool IncludeProcess(const ProcessInfo& process, TimelineFilter filter)
        {
            switch (filter)
            {
            case TimelineFilter::SuspiciousOnly:
                return process.IsSuspicious();
            case TimelineFilter::HighSeverityOnly:
                return process.severity == Severity::High;
            case TimelineFilter::All:
            default:
                return true;
            }
        }
    }

    std::vector<TimelineRow> BuildTimelineRows(
        const ProcessSnapshot& snapshot,
        TimelineFilter filter)
    {
        std::vector<TimelineRow> rows;
        rows.reserve(snapshot.processes.size());

        for (const ProcessInfo& process : snapshot.processes)
        {
            if (!IncludeProcess(process, filter))
            {
                continue;
            }

            const ProcessInfo* parent =
                IsUsableParentRelationship(GetParentRelationshipStatus(snapshot, process))
                    ? FindProcessByPid(snapshot, process.parentPid)
                    : nullptr;
            TimelineRow row;
            row.pid = process.pid;
            row.parentPid = process.parentPid;
            row.parentName = parent == nullptr ? L"" : parent->name;
            row.processName = process.name;
            row.creationTimeLocal = process.creationTimeLocal;
            row.hasCreationTime = process.hasCreationTime;
            row.severity = process.severity;
            row.firstIndicator = process.indicators.empty() ? L"" : process.indicators.front();
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
