#pragma once

#include "ProcessInfo.h"

#include <cstddef>
#include <vector>

namespace GlassPane::Core
{
    struct TreeRow
    {
        std::size_t processIndex = 0;
        std::size_t depth = 0;
    };

    void BuildProcessTree(ProcessSnapshot& snapshot);
    std::vector<TreeRow> BuildTreeRows(const ProcessSnapshot& snapshot);
}
