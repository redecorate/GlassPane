#pragma once

#include "ProcessInfo.h"
#include "RuntimeInfo.h"

namespace GlassPane::Core
{
    RuntimeInfo CollectProcessRuntimeInfo(const ProcessInfo& process);
}
