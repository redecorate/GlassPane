#pragma once

#include "MemoryRegionInfo.h"

#include <cstdint>

namespace GlassPane::Core
{
    MemoryCollectionResult CollectMemoryRegionsForPid(std::uint32_t pid);
}
