#pragma once

#include "ProcessInfo.h"

#include <cstddef>
#include <vector>

namespace GlassPane::Core
{
    enum class ParentRelationshipStatus
    {
        NoParent,
        MissingParent,
        Verified,
        Unverified,
        InvalidPidReuse
    };

    struct TreeRow
    {
        std::size_t processIndex = 0;
        std::size_t depth = 0;
    };

    ParentRelationshipStatus ValidateParentChildRelationship(
        const ProcessInfo& parent,
        const ProcessInfo& child);
    ParentRelationshipStatus GetParentRelationshipStatus(
        const ProcessSnapshot& snapshot,
        const ProcessInfo& child);
    bool IsUsableParentRelationship(ParentRelationshipStatus status);
    void BuildProcessTree(ProcessSnapshot& snapshot);
    std::vector<TreeRow> BuildTreeRows(const ProcessSnapshot& snapshot);
}
