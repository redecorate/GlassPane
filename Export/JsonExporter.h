#pragma once

#include "../Core/HandleInfo.h"
#include "../Core/FileIdentity.h"
#include "../Core/Finding.h"
#include "../Core/MemoryRegionInfo.h"
#include "../Core/NativeSourceEvidence.h"
#include "../Core/ModuleInfo.h"
#include "../Core/NetworkConnection.h"
#include "../Core/PersistedTriage.h"
#include "../Core/ProcessInfo.h"
#include "../Core/RuntimeInfo.h"
#include "../Core/TokenInfo.h"

#include <cstdint>
#include <string>
#include <vector>

namespace GlassPane::Export
{
    // All evidence consumed by the selected-process JSON serializer is
    // captured by the caller. This keeps serialization deterministic and,
    // critically, prevents loaded-snapshot export from consulting the live
    // endpoint for file identities or token state.
    struct SelectedProcessJsonEvidenceContext
    {
        bool identityCaptured = false;
        Core::ProcessIdentityKey identity;

        bool processFileIdentityCaptured = false;
        Core::FileIdentity processFileIdentity;

        bool tokenCaptured = false;
        Core::TokenInfo token;

        // When captured, entries correspond one-to-one with the module array.
        bool moduleFileIdentitiesCaptured = false;
        std::vector<Core::FileIdentity> moduleFileIdentities;
    };

    bool ExportSelectedProcessDetailsToJson(
        const Core::ProcessSnapshot& snapshot,
        std::uint32_t pid,
        const Core::ModuleCollectionResult& modules,
        const std::vector<Core::NetworkConnection>& networkConnections,
        const Core::HandleCollectionResult* handles,
        const Core::RuntimeInfo* runtime,
        const Core::MemoryCollectionResult* memory,
        const SelectedProcessJsonEvidenceContext& capturedEvidence,
        const Core::PersistedTriageSummary& authoritativeTriage,
        const std::vector<Core::NativeSourceEvidenceRecord>* nativeSourceEvidence,
        const std::vector<Core::Finding>* historicalLegacyEvidence,
        const std::wstring& filePath,
        std::wstring* errorMessage = nullptr);

    // Compatibility overload for callers without captured ObservationEngine
    // authority. It emits an explicit NotCaptured authoritative_triage object.
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
