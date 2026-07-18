#pragma once

#include "../Core/HandleInfo.h"
#include "../Core/MemoryRegionInfo.h"
#include "../Core/ModuleInfo.h"
#include "../Core/NetworkConnection.h"
#include "../Core/NetworkIndicatorFeed.h"
#include "../Core/NativeSourceEvidence.h"
#include "../Core/PersistedTriage.h"
#include "../Core/ProcessInfo.h"
#include "../Core/RuntimeInfo.h"
#include "../Core/ServiceInfo.h"
#include "../Core/TokenInfo.h"

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace GlassPane::Export
{
    // Schema 4 introduced captured TriageEngine summaries while retaining
    // finding-shaped source metadata. Schema 5 is the first native-evidence
    // schema and must not reinterpret schema-4 fields in place.
    constexpr int GlassPaneSnapshotSchemaVersion = 5;
    constexpr int GlassPaneSnapshotPreviousSchemaVersion = 4;
    constexpr int GlassPaneSnapshotNativeEvidenceSchemaVersion = 5;
    constexpr int GlassPaneSnapshotTriageSchemaVersion = 4;
    constexpr int GlassPaneSnapshotLegacyAggregateMaxSchemaVersion = 3;
    constexpr int GlassPaneSnapshotServiceContextSchemaVersion = 3;
    constexpr int GlassPaneSnapshotPreServiceSchemaVersion = 2;
    constexpr int GlassPaneSnapshotLegacySchemaVersion = 1;
    constexpr const wchar_t* GlassPaneSnapshotFormat = L"glasspane_snapshot";

    constexpr std::size_t SnapshotMaxStringLength = 4096;
    constexpr std::size_t SnapshotMaxProcesses =
        Core::PersistedTriageMaxProcessRecords;

    constexpr std::size_t SnapshotDeepMaxModulesPerProcess = 256;
    constexpr std::size_t SnapshotDeepMaxHandlesPerProcess = 256;
    constexpr std::size_t SnapshotDeepMaxMemoryRegionsPerProcess = 512;
    constexpr std::size_t SnapshotDeepMaxThreadsPerProcess = 256;
    constexpr std::size_t SnapshotDeepMaxPrivilegesPerProcess = 256;
    constexpr std::size_t SnapshotDeepMaxTotalHandles = 25000;
    constexpr std::size_t SnapshotDeepMaxTotalMemoryRegions = 50000;
    constexpr std::uint32_t SnapshotHistoricalEvidenceModelVersion = 1;
    constexpr std::size_t SnapshotHistoricalMaxRecordsPerProcess = 512;

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

    struct SavedNativeSourceEvidenceRecord
    {
        Core::ProcessIdentityKey identity;
        std::vector<Core::NativeSourceEvidenceRecord> records;
    };

    struct SavedNativeSourceEvidenceContext
    {
        std::uint32_t modelVersion =
            Core::NativeSourceEvidenceModelVersion;
        // No record means no selected native evidence was captured. An
        // engaged record with an empty vector is an explicit successful empty
        // evidence capture, including for PID zero.
        std::optional<SavedNativeSourceEvidenceRecord> selectedRecord;
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
        Core::PersistedTriageContext triageContext;
        bool nativeSourceEvidenceCaptured = false;
        SavedNativeSourceEvidenceContext nativeSourceEvidence;
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
        const Core::PersistedTriageContext* triageContext = nullptr;
        // Value-owned so snapshot and package workers never retain pointers to
        // observation/refinement state.
        SavedNativeSourceEvidenceContext nativeSourceEvidence;
        // Set only while resaving an imported historical snapshot. Current
        // live/schema-5-native capture must never infer this sidecar merely
        // from compatibility-shaped ProcessInfo fields.
        bool preserveHistoricalLegacyEvidence = false;
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
