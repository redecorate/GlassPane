#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace GlassPane::Core
{
    struct ThreadInfo
    {
        std::uint32_t threadId = 0;
        std::uint32_t ownerProcessId = 0;
        int basePriority = 0;
        int currentPriority = 0;
        bool hasCurrentPriority = false;
        std::wstring startAddress;
        std::wstring startAddressResolvedModule;
        std::wstring state;
        std::wstring errorMessage;
    };

    struct RuntimeInfo
    {
        bool success = false;
        std::wstring errorMessage;
        std::uint32_t processId = 0;
        std::uint32_t priorityClassRaw = 0;
        std::wstring priorityClassName;
        int basePriority = 0;
        std::uint64_t processAffinityMask = 0;
        std::uint64_t systemAffinityMask = 0;
        std::wstring affinityMaskString;
        std::wstring processorGroup;
        std::uint32_t threadCount = 0;
        std::uint32_t handleCount = 0;
        std::uint64_t workingSetSize = 0;
        std::uint64_t peakWorkingSetSize = 0;
        std::uint64_t privateBytes = 0;
        std::uint64_t pagefileUsage = 0;
        std::uint64_t peakPagefileUsage = 0;
        std::wstring userCpuTime;
        std::wstring kernelCpuTime;
        std::wstring totalCpuTime;
        std::uint64_t userCpuTime100ns = 0;
        std::uint64_t kernelCpuTime100ns = 0;
        std::uint64_t totalCpuTime100ns = 0;
        std::wstring architecture;
        bool isWow64 = false;
        std::vector<ThreadInfo> threads;
        std::vector<std::wstring> contextNotes;
    };
}
