#pragma once

#include "HandleInfo.h"
#include "ProcessInfo.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace GlassPane::Core
{
    constexpr std::size_t HandleQueryMinimumBudgetBytes = 32ULL << 20;
    constexpr std::size_t HandleQueryMaximumBudgetBytes = 512ULL << 20;
    constexpr std::size_t HandleQueryInitialBufferBytes = 1ULL << 20;
    constexpr std::size_t HandleCollectionMaxRetainedHandles = 4096;
    constexpr std::size_t HandleCollectionMaxNameResolutions = 512;
    constexpr std::size_t HandleCollectionMaxTypeResolutions = 128;
    constexpr std::size_t HandleCollectionMaxObjectMetadataBytes = 64ULL << 10;

    constexpr bool HandleOptionalEnrichmentBudgetAvailable(
        std::size_t attempted,
        std::size_t limit) noexcept
    {
        return attempted < limit;
    }

    struct HandleQueryGrowthDecision
    {
        bool canRetry = false;
        bool budgetExceeded = false;
        std::size_t nextBufferBytes = 0;
    };

    std::size_t CalculateAdaptiveHandleQueryBudget(
        std::uint64_t availablePhysicalBytes,
        std::uint64_t totalPhysicalBytes) noexcept;

    HandleQueryGrowthDecision PlanHandleQueryBufferGrowth(
        std::size_t currentBufferBytes,
        std::size_t requiredBufferBytes,
        std::size_t budgetBytes) noexcept;

    struct HandleTableCoreEntry
    {
        std::uint32_t owningPid = 0;
        std::uint64_t handleValue = 0;
        std::uint16_t objectTypeIndex = 0;
        std::uint32_t grantedAccess = 0;
    };

    struct HandleCoreProjectionResult
    {
        bool success = false;
        bool queryBufferTruncated = false;
        bool retentionCapReached = false;
        std::size_t systemEntriesReported = 0;
        std::size_t entriesScanned = 0;
        std::size_t selectedEntriesMatched = 0;
        std::size_t selectedEntriesOmitted = 0;
        std::vector<HandleTableCoreEntry> records;
    };

    // Pure compact projection used by production collection and deterministic
    // fixtures. It performs no native calls, enrichment, I/O, or mutation.
    HandleCoreProjectionResult ProjectSelectedHandleCoreRecords(
        std::uint32_t selectedPid,
        const std::vector<HandleTableCoreEntry>& availableEntries,
        std::size_t systemEntriesReported,
        std::size_t retentionLimit =
            HandleCollectionMaxRetainedHandles) noexcept;

    HandleCollectionResult CollectProcessHandles(
        const ProcessInfo& process,
        const ProcessSnapshot* snapshot = nullptr);
}
