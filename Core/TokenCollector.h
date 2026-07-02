#pragma once

#include "ProcessInfo.h"
#include "TokenInfo.h"

namespace GlassPane::Core
{
    TokenInfo CollectProcessTokenInfo(const ProcessInfo& process);
}
