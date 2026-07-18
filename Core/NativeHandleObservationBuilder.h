#pragma once

#include "HandleInfo.h"
#include "ObservationInventory.h"
#include "ProcessTriageCache.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace GlassPane::Core
{
    constexpr std::size_t NativeHandleObservationMaxRows = 4096;
    constexpr std::size_t NativeHandleObservationMaxTargetIdentities = 4096;
    constexpr std::size_t NativeHandleObservationMaxOutputRecords = 4096;
    constexpr std::size_t NativeHandleObservationDiagnosticMaxCharacters = 1024;
    constexpr std::size_t NativeHandleObservationSemanticKeyMaxCharacters = 256;

    inline constexpr char NativeHandleObservationSourceCategory[] =
        "Native selected-process evidence";
    inline constexpr char NativeHandleMappingCollectionUnavailable[] =
        "native.collection.handle-enumeration-unavailable";
    inline constexpr char NativeHandleMappingCollectionTruncated[] =
        "native.collection.handle-enumeration-truncated";
    inline constexpr char NativeHandleMappingSelfAccessContext[] =
        "native.handle.self-access-context";
    inline constexpr char NativeHandleMappingExternalAccessContext[] =
        "native.handle.external-access-context";
    inline constexpr char NativeHandleMappingExternalVmRead[] =
        "native.handle.external-process-vm-read";
    inline constexpr char NativeHandleMappingSensitiveExternalAccess[] =
        "native.handle.external-process-sensitive-access";
    inline constexpr char NativeHandleMappingSensitiveExternalThreadAccess[] =
        "native.handle.external-thread-sensitive-access";
    inline constexpr char NativeHandleMappingTokenContext[] =
        "native.handle.token-context";
    inline constexpr char NativeHandleMappingTokenManipulationRights[] =
        "native.handle.token-manipulation-rights";
    inline constexpr char NativeHandleMappingGenericContext[] =
        "native.handle.object-context";

    enum class NativeHandleObjectKind : std::uint32_t
    {
        Unknown = 0,
        Process = 1,
        Thread = 2,
        Token = 3,
        Section = 4,
        File = 5,
        RegistryKey = 6,
        Other = 7
    };

    enum class NativeHandleObservationBuildStatus : std::uint32_t
    {
        NotAttempted = 0,
        Success = 1,
        InvalidIdentity = 2,
        InputLimitExceeded = 3,
        InvalidTypedFact = 4,
        PolicyValidationFailed = 5
    };

    struct NativeHandleAccessCategories
    {
        bool synchronize = false;
        bool query = false;
        bool vmRead = false;
        bool vmWrite = false;
        bool vmOperation = false;
        bool createThread = false;
        bool duplicateHandle = false;
        bool createProcess = false;
        bool threadSetContext = false;
        bool threadImpersonate = false;
        bool tokenDuplicate = false;
        bool tokenAssignPrimary = false;

        bool HasSensitiveProcessAccess() const;
        bool HasSensitiveThreadAccess() const;
        bool HasTokenManipulationAccess() const;
    };

    // Exact canonical object-type metadata is classified without consulting
    // decoded access labels, indicators, object names, target names, or other
    // display prose.
    NativeHandleObjectKind ClassifyNativeHandleObjectKind(
        const HandleInfo& handle);
    std::string NativeHandleObjectKindDisplayText(NativeHandleObjectKind kind);
    NativeHandleAccessCategories CategorizeNativeHandleAccess(
        NativeHandleObjectKind kind,
        std::uint32_t accessMask);

    struct NativeHandleObservationSource
    {
        ObservationSourceKind sourceKind = ObservationSourceKind::Direct;
        std::string sourceIdentifier;
        std::string collectionMethod;
        std::string collectionTimestamp;
        std::string requiredPrivilege;
        std::string rawSourceReference;
        std::vector<std::string> limitations;
    };

    // A target binding is supplied from the already-captured process snapshot.
    // It never resolves a PID, opens a handle, or performs collection.
    struct NativeHandleTargetIdentity
    {
        std::uint64_t handleValue = 0;
        NativeHandleObjectKind objectKind = NativeHandleObjectKind::Unknown;
        std::uint32_t targetPid = 0;
        bool identityResolved = false;
        ProcessIdentityKey identity;
        bool pidReuseAmbiguous = false;
    };

    struct NativeHandleObservationInput
    {
        ProcessIdentityKey sourceIdentity;
        std::string entityScope;
        bool supplied = false;
        bool collectionAttempted = false;
        HandleCollectionResult collection;
        std::vector<NativeHandleTargetIdentity> targetIdentities;
        bool sourceTruncated = false;
        std::size_t omittedHandleCount = 0;
        NativeHandleObservationSource source;
        std::vector<std::string> limitations;
    };

    struct NativeHandleObservationRecord
    {
        ObservationRecord record;
        std::string semanticFactKey;
    };

    struct NativeHandleObservationBuildResult
    {
        bool attempted = false;
        bool success = false;
        bool truncated = false;
        bool materialEvidenceOmitted = false;
        NativeHandleObservationBuildStatus status =
            NativeHandleObservationBuildStatus::NotAttempted;
        std::vector<NativeHandleObservationRecord> records;
        ObservationInventory inventory;
        std::size_t sourceRowCount = 0;
        std::size_t representedArtifactCount = 0;
        std::size_t duplicateRowCount = 0;
        std::size_t omittedHandleCount = 0;
        std::string diagnostic;

        bool Succeeded() const;
    };

    // Pure conversion of already-collected selected-process handle rows. This
    // function performs no collection, handle duplication, target resolution,
    // UI work, verdict calculation, I/O, or endpoint mutation.
    NativeHandleObservationBuildResult BuildNativeHandleObservations(
        const NativeHandleObservationInput& input) noexcept;
}
