#pragma once

#include "../Core/HandleInfo.h"
#include "../Core/MemoryRegionInfo.h"
#include "../Core/ModuleInfo.h"
#include "../Core/NetworkConnection.h"
#include "../Core/ProcessInfo.h"
#include "../Core/RuntimeInfo.h"

#include <cstdint>
#include <string>
#include <vector>

namespace GlassPane::Export
{
    bool ExportSnapshotToJson(
        const Core::ProcessSnapshot& snapshot,
        const std::wstring& filePath,
        std::wstring* errorMessage = nullptr);

    bool ExportSelectedProcessDetailsToJson(
        const Core::ProcessSnapshot& snapshot,
        std::uint32_t pid,
        const Core::ModuleCollectionResult& modules,
        const std::vector<Core::NetworkConnection>& networkConnections,
        const Core::HandleCollectionResult* handles,
        const Core::RuntimeInfo* runtime,
        const Core::MemoryCollectionResult* memory,
        const std::wstring& filePath,
        std::wstring* errorMessage = nullptr);

    bool ExportSelectedProcessDetailsToJson(
        const Core::ProcessSnapshot& snapshot,
        std::uint32_t pid,
        const Core::ModuleCollectionResult& modules,
        const std::vector<Core::NetworkConnection>& networkConnections,
        const Core::HandleCollectionResult* handles,
        const Core::RuntimeInfo* runtime,
        const std::wstring& filePath,
        std::wstring* errorMessage = nullptr);

    bool ExportSelectedProcessDetailsToJson(
        const Core::ProcessSnapshot& snapshot,
        std::uint32_t pid,
        const Core::ModuleCollectionResult& modules,
        const std::vector<Core::NetworkConnection>& networkConnections,
        const Core::HandleCollectionResult* handles,
        const std::wstring& filePath,
        std::wstring* errorMessage = nullptr);

    bool ExportSelectedProcessDetailsToJson(
        const Core::ProcessSnapshot& snapshot,
        std::uint32_t pid,
        const Core::ModuleCollectionResult& modules,
        const std::vector<Core::NetworkConnection>& networkConnections,
        const std::wstring& filePath,
        std::wstring* errorMessage = nullptr);

    bool ExportSelectedProcessDetailsToJson(
        const Core::ProcessSnapshot& snapshot,
        std::uint32_t pid,
        const Core::ModuleCollectionResult& modules,
        const std::wstring& filePath,
        std::wstring* errorMessage = nullptr);
}
