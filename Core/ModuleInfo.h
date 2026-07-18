#pragma once

#include "ProcessInfo.h"

#include <cstdint>
#include <string>
#include <vector>

namespace GlassPane::Core
{
    struct ModuleInfo
    {
        std::wstring moduleName;
        std::wstring modulePath;
        std::wstring baseAddress;
        std::uint32_t sizeBytes = 0;
        bool readable = false;
        // Schema 1-4 historical compatibility metadata only.
        std::vector<std::wstring> indicators;
    };

    struct ModuleCollectionResult
    {
        std::uint32_t pid = 0;
        bool success = false;
        std::wstring statusMessage;
        std::vector<ModuleInfo> modules;
        // Schema 1-4 historical compatibility metadata only.
        std::vector<std::wstring> indicators;
    };
}
