#pragma once

#include "ServiceInfo.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace GlassPane::Core
{
    // Pending, stopped, and unknown states remain conservative SCM context.
    // Running and the stable Paused state are the only reliable states here.
    bool ServiceStateHasReliableProcessId(std::uint32_t stateRaw);

    // Returns true when source was truncated to maxCharacters.
    bool AssignBoundedServiceText(
        std::wstring& destination,
        std::wstring_view source,
        std::size_t maxCharacters);

    // Accounts for one enumeration row and returns whether the caller may
    // decode and retain it under ServiceMaxRecords.
    bool RegisterEnumeratedService(ServiceCollectionResult& result);

    void SortServicesByNameCaseInsensitive(std::vector<ServiceInfo>& services);

    // Pure finalization seam used by the collector and deterministic tests.
    void FinalizeServiceCollectionResult(
        ServiceCollectionResult& result,
        bool enumerationCompleted,
        std::uint32_t enumerationError);

    ServiceCollectionResult CollectServiceSnapshot();
}
