#pragma once

#include "HandleInfo.h"
#include "ProcessInfo.h"

namespace GlassPane::Core
{
    HandleCollectionResult CollectProcessHandles(
        const ProcessInfo& process,
        const ProcessSnapshot* snapshot = nullptr);
}
