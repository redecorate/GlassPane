#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace GlassPane::Core
{
    struct MemoryRegionInfo
    {
        std::uint64_t baseAddress = 0;
        std::wstring baseAddressString;
        std::uint64_t allocationBase = 0;
        std::wstring allocationBaseString;
        std::uint64_t regionSize = 0;
        std::wstring regionSizeString;
        std::uint32_t stateRaw = 0;
        std::wstring stateName;
        std::uint32_t typeRaw = 0;
        std::wstring typeName;
        std::uint32_t protectRaw = 0;
        std::wstring protectName;
        std::uint32_t allocationProtectRaw = 0;
        std::wstring allocationProtectName;
        std::wstring mappedFilePath;
        bool isReadable = false;
        bool isWritable = false;
        bool isExecutable = false;
        bool isCopyOnWrite = false;
        bool isGuard = false;
        bool isPrivate = false;
        bool isImage = false;
        bool isMapped = false;
        std::vector<std::wstring> indicators;
    };

    struct MemoryCollectionResult
    {
        std::uint32_t pid = 0;
        bool success = false;
        std::wstring statusMessage;
        std::size_t totalRegions = 0;
        std::size_t executableRegions = 0;
        std::size_t privateExecutableRegions = 0;
        std::size_t rwxRegions = 0;
        std::size_t guardRegions = 0;
        std::vector<MemoryRegionInfo> regions;
    };
}
