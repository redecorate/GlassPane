#pragma once

#include "../Core/HandleInfo.h"
#include "../Core/MemoryRegionInfo.h"
#include "../Core/ModuleInfo.h"
#include "../Core/NetworkConnection.h"
#include "../Core/NetworkIndicatorFeed.h"
#include "../Core/ProcessInfo.h"
#include "../Core/RuntimeInfo.h"
#include "../Core/ServiceInfo.h"
#include "../Core/TokenInfo.h"

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace GlassPane::Export
{
    constexpr int GlassPaneSnapshotSchemaVersion = 3;
    constexpr int GlassPaneSnapshotPreviousSchemaVersion = 2;
    constexpr int GlassPaneSnapshotLegacySchemaVersion = 1;
    constexpr const wchar_t* GlassPaneSnapshotFormat = L"glasspane_snapshot";

    constexpr std::size_t SnapshotMaxStringLength = 4096;

    constexpr std::size_t SnapshotDefaultMaxIndicatorModulesPerProcess = 64;

    constexpr std::size_t SnapshotDeepMaxModulesPerProcess = 256;
    constexpr std::size_t SnapshotDeepMaxHandlesPerProcess = 256;
    constexpr std::size_t SnapshotDeepMaxMemoryRegionsPerProcess = 512;
    constexpr std::size_t SnapshotDeepMaxThreadsPerProcess = 256;
    constexpr std::size_t SnapshotDeepMaxPrivilegesPerProcess = 256;
    constexpr std::size_t SnapshotDeepMaxTotalHandles = 25000;
    constexpr std::size_t SnapshotDeepMaxTotalMemoryRegions = 50000;

    enum class SavedSnapshotEvidenceMode
    {
        Default,
        Deep
    };

    struct EvidenceCollectionStatus
    {
        std::wstring status = L"not_attempted";
        std::wstring message;
        bool truncated = false;
        std::size_t originalCount = 0;
        std::size_t savedCount = 0;
    };

    struct ProcessEvidenceSnapshot
    {
        std::uint32_t pid = 0;
        std::wstring processName;

        EvidenceCollectionStatus runtimeStatus;
        EvidenceCollectionStatus tokenStatus;
        EvidenceCollectionStatus modulesStatus;
        EvidenceCollectionStatus handlesStatus;
        EvidenceCollectionStatus memoryStatus;

        Core::RuntimeInfo runtime;
        Core::TokenInfo token;
        Core::ModuleCollectionResult modules;
        Core::HandleCollectionResult handles;
        Core::MemoryCollectionResult memory;
    };

    struct FullEvidenceCollectionSummary
    {
        std::size_t processCount = 0;
        std::size_t runtimeOk = 0;
        std::size_t runtimeFailed = 0;
        std::size_t tokenOk = 0;
        std::size_t tokenFailed = 0;
        std::size_t modulesOk = 0;
        std::size_t modulesFailed = 0;
        std::size_t handlesOk = 0;
        std::size_t handlesFailed = 0;
        std::size_t memoryOk = 0;
        std::size_t memoryFailed = 0;
        std::size_t truncatedCollections = 0;
    };

    struct NetworkIntelligenceSnapshotMetadata
    {
        bool loaded = false;
        std::wstring feedName;
        int schemaVersion = 0;
        std::wstring generatedAt;
        std::wstring expiresAt;
        std::size_t indicatorCount = 0;
        std::wstring source;
        std::wstring status;
        std::wstring localFeedSha256;
    };

    struct SavedSnapshotMetadata
    {
        int schemaVersion = GlassPaneSnapshotSchemaVersion;
        std::wstring format = GlassPaneSnapshotFormat;
        std::wstring glassPaneVersion;
        std::wstring capturedAt;
        std::wstring hostname;
        std::wstring currentUser;
        std::wstring osBuild;
        std::wstring sourcePath;
        std::wstring evidenceMode = L"default";
        std::uint32_t selectedPid = 0;
    };

    struct SavedSnapshotDocument
    {
        SavedSnapshotMetadata metadata;
        Core::ProcessSnapshot snapshot;
        bool networkLoaded = false;
        Core::NetworkCollectionResult network;
        Core::ServiceCollectionResult serviceContext;
        NetworkIntelligenceSnapshotMetadata networkIntel;
        std::vector<Core::NetworkIndicatorMatch> networkIndicatorMatches;
        std::vector<ProcessEvidenceSnapshot> processEvidence;
    };

    struct SavedSnapshotExportContext
    {
        const Core::ProcessSnapshot* snapshot = nullptr;
        bool networkLoaded = false;
        const Core::NetworkCollectionResult* network = nullptr;
        const Core::ServiceCollectionResult* serviceContext = nullptr;
        const std::vector<Core::NetworkIndicatorMatch>* networkIndicatorMatches = nullptr;
        NetworkIntelligenceSnapshotMetadata networkIntel;
        std::wstring glassPaneVersion;
        std::wstring capturedAt;
        std::wstring hostname;
        std::wstring currentUser;
        std::wstring osBuild;
        std::wstring evidenceMode = L"default";
        std::uint32_t selectedPid = 0;
        const std::vector<ProcessEvidenceSnapshot>* processEvidence = nullptr;
    };

    bool SaveGlassPaneSnapshot(
        const SavedSnapshotExportContext& context,
        const std::wstring& filePath,
        std::wstring* errorMessage = nullptr);

    bool LoadGlassPaneSnapshot(
        const std::wstring& filePath,
        SavedSnapshotDocument& document,
        std::wstring* errorMessage = nullptr);

    bool ExportNetworkIntelligenceMetadataJson(
        const NetworkIntelligenceSnapshotMetadata& metadata,
        const std::wstring& filePath,
        std::wstring* errorMessage = nullptr);

    bool WriteEvidencePackageReadme(
        const std::wstring& filePath,
        const std::wstring& generatedAt,
        const std::wstring& glassPaneVersion,
        bool generatedFromLoadedSnapshot,
        const std::vector<std::wstring>& packageFiles,
        std::wstring* errorMessage = nullptr);

    bool ComputeFileSha256Hex(
        const std::wstring& filePath,
        std::string& sha256,
        std::wstring* errorMessage = nullptr);

    bool WriteSha256Manifest(
        const std::wstring& packageDirectory,
        const std::vector<std::wstring>& relativeFiles,
        const std::wstring& manifestFileName,
        std::wstring* errorMessage = nullptr);
}
