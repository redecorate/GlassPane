#pragma once

#include "ChainAnalysis.h"
#include "FileIdentity.h"
#include "Finding.h"
#include "HandleInfo.h"
#include "MemoryRegionInfo.h"
#include "ModuleInfo.h"
#include "NetworkConnection.h"
#include "ProcessInfo.h"
#include "RuntimeInfo.h"
#include "TokenInfo.h"

#include <string>
#include <vector>

namespace GlassPane::Core
{
    struct CorrelationContext
    {
        const ProcessInfo* process = nullptr;
        const ChainAnalysisResult* chain = nullptr;
        const ModuleCollectionResult* modules = nullptr;
        const std::vector<NetworkConnection>* networkConnections = nullptr;
        const FileIdentity* fileIdentity = nullptr;
        const TokenInfo* token = nullptr;
        const HandleCollectionResult* handles = nullptr;
        const RuntimeInfo* runtime = nullptr;
        const MemoryCollectionResult* memory = nullptr;
    };

    std::vector<Finding> CorrelateFindings(const CorrelationContext& context);

    FindingSeverity HighestFindingSeverity(const std::vector<Finding>& findings);
    std::wstring TriageSummary(const std::vector<Finding>& findings);
}
