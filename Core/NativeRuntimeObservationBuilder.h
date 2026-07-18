#pragma once

#include "ObservationInventory.h"
#include "ProcessTriageCache.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace GlassPane::Core
{
    constexpr std::size_t NativeRuntimeObservationMaxThreads = 256;
    constexpr std::size_t NativeRuntimeObservationMaxRelationships = 64;
    constexpr std::size_t NativeRuntimeObservationMaxRecords = 384;
    constexpr std::size_t NativeRuntimeObservationMaxLimitations = 32;
    constexpr std::size_t NativeRuntimeObservationSemanticKeyMaxCharacters = 256;
    constexpr std::size_t NativeRuntimeObservationDiagnosticMaxCharacters = 1024;

    inline constexpr char NativeRuntimeMappingCaptureContext[] =
        "native.runtime.capture-context";
    inline constexpr char NativeRuntimeMappingThreadContext[] =
        "native.runtime.thread-context";
    inline constexpr char NativeRuntimeMappingExplicitRelationship[] =
        "native.runtime.explicit-relationship";
    inline constexpr char NativeRuntimeMappingCollectionUnavailable[] =
        "native.collection.runtime-unavailable";
    inline constexpr char NativeRuntimeMappingCollectionTruncated[] =
        "native.collection.runtime-truncated";
    inline constexpr char NativePriorityMappingProcessContext[] =
        "native.priority.process-context";
    inline constexpr char NativePriorityMappingCollectionUnavailable[] =
        "native.collection.priority-unavailable";
    inline constexpr char NativePriorityMappingCollectionTruncated[] =
        "native.collection.priority-truncated";

    enum class NativeRuntimeThreadStartKind : std::uint32_t
    {
        NotEvaluated = 0,
        ImageBacked = 1,
        Unresolved = 2,
        PrivateExecutableMetadata = 3,
        OutsideKnownModule = 4
    };

    enum class NativeRuntimeThreadState : std::uint32_t
    {
        Unknown = 0,
        Ready = 1,
        Running = 2,
        Waiting = 3,
        Transition = 4,
        Terminated = 5,
        Suspended = 6
    };

    enum class NativeRuntimeRelationshipKind : std::uint32_t
    {
        CrossProcessThreadCreation = 0,
        ExternalThreadStartAttribution = 1
    };

    enum class NativeProcessPriorityClass : std::uint32_t
    {
        NotEvaluated = 0,
        Idle = 1,
        BelowNormal = 2,
        Normal = 3,
        AboveNormal = 4,
        High = 5,
        Realtime = 6,
        Unknown = 7
    };

    enum class NativeRuntimeObservationBuildStatus : std::uint32_t
    {
        NotAttempted = 0,
        Success = 1,
        InvalidIdentity = 2,
        InputLimitExceeded = 3,
        InvalidTypedFact = 4,
        PolicyValidationFailed = 5
    };

    enum class NativeRuntimeSourceCompleteness : std::uint32_t
    {
        Complete = 0,
        Partial = 1,
        Unavailable = 2
    };

    std::string NativeRuntimeThreadStartKindDisplayText(
        NativeRuntimeThreadStartKind kind);
    std::string NativeRuntimeThreadStateDisplayText(
        NativeRuntimeThreadState state);
    std::string NativeRuntimeRelationshipKindDisplayText(
        NativeRuntimeRelationshipKind kind);
    std::string NativeProcessPriorityClassDisplayText(
        NativeProcessPriorityClass priorityClass);
    NativeProcessPriorityClass ClassifyNativeProcessPriorityClass(
        std::uint32_t rawPriorityClass);
    std::string NativeRuntimeObservationBuildStatusDisplayText(
        NativeRuntimeObservationBuildStatus status);

    struct NativeRuntimeObservationSource
    {
        ObservationSourceKind sourceKind = ObservationSourceKind::Direct;
        NativeRuntimeSourceCompleteness completeness =
            NativeRuntimeSourceCompleteness::Complete;
        std::string sourceIdentifier;
        std::string collectionMethod;
        std::string collectionTimestamp;
        std::string requiredPrivilege;
        std::string rawSourceReference;
        std::vector<std::string> limitations;
    };

    // This is a typed projection of already-collected thread metadata. The
    // builder never parses collector display strings to infer these states.
    struct NativeRuntimeThreadInput
    {
        std::uint32_t threadId = 0;
        std::uint32_t ownerProcessId = 0;
        bool ownerIdentityKnown = false;
        bool ownerMatchesSelectedProcess = false;

        bool startAddressAvailable = false;
        std::uint64_t startAddress = 0;
        NativeRuntimeThreadStartKind startKind =
            NativeRuntimeThreadStartKind::NotEvaluated;
        std::string resolvedModuleIdentity;

        NativeRuntimeThreadState state = NativeRuntimeThreadState::Unknown;
        bool basePriorityAvailable = false;
        int basePriority = 0;
        bool currentPriorityAvailable = false;
        int currentPriority = 0;

        std::vector<std::string> evidence;
        std::vector<std::string> limitations;
        NativeRuntimeObservationSource source;
    };

    // CorrelatedOnly runtime facts require an explicit, already-collected
    // source/target relationship. Static thread attributes never synthesize
    // one of these records.
    struct NativeRuntimeRelationshipInput
    {
        ProcessIdentityKey selectedIdentity;
        ProcessIdentityKey sourceIdentity;
        ProcessIdentityKey targetIdentity;
        std::uint32_t sourceThreadId = 0;
        std::uint32_t targetThreadId = 0;
        NativeRuntimeRelationshipKind kind =
            NativeRuntimeRelationshipKind::CrossProcessThreadCreation;
        bool verified = false;
        std::string sourceRuleId;
        std::vector<std::string> evidence;
        std::vector<std::string> limitations;
        NativeRuntimeObservationSource source;
    };

    struct NativeRuntimeObservationInput
    {
        ProcessIdentityKey identity;
        std::string entityScope;
        bool supplied = false;
        bool collectionAttempted = false;
        bool available = false;
        bool sourceFactsTruncated = false;
        std::size_t omittedMaterialFactCount = 0;
        std::uint32_t declaredThreadCount = 0;
        std::uint32_t declaredHandleCount = 0;
        bool processBasePriorityAvailable = false;
        int processBasePriority = 0;
        std::vector<NativeRuntimeThreadInput> threads;
        std::vector<NativeRuntimeRelationshipInput> relationships;
        std::vector<std::string> limitations;
        NativeRuntimeObservationSource source;
    };

    struct NativePriorityObservationInput
    {
        ProcessIdentityKey identity;
        std::string entityScope;
        bool supplied = false;
        bool collectionAttempted = false;
        bool available = false;
        bool sourceFactsTruncated = false;
        std::size_t omittedMaterialFactCount = 0;
        NativeProcessPriorityClass priorityClass =
            NativeProcessPriorityClass::NotEvaluated;
        std::uint32_t rawPriorityClass = 0;
        bool basePriorityAvailable = false;
        int basePriority = 0;
        std::vector<std::string> evidence;
        std::vector<std::string> limitations;
        NativeRuntimeObservationSource source;
    };

    struct NativeRuntimeObservationRecord
    {
        ObservationRecord record;
        std::string semanticFactKey;
        NativeRuntimeSourceCompleteness completeness =
            NativeRuntimeSourceCompleteness::Complete;
        bool material = false;
        bool primary = true;
        std::string primaryObservationId;
    };

    struct NativeRuntimeObservationBuildResult
    {
        bool attempted = false;
        bool success = false;
        bool truncated = false;
        NativeRuntimeObservationBuildStatus status =
            NativeRuntimeObservationBuildStatus::NotAttempted;
        std::vector<NativeRuntimeObservationRecord> records;
        ObservationInventory inventory;
        std::size_t nativeFactCount = 0;
        std::size_t representedFactCount = 0;
        std::size_t duplicateCount = 0;
        std::size_t materialFactCount = 0;
        std::size_t omittedMaterialFactCount = 0;
        std::string diagnostic;

        bool Succeeded() const;
    };

    // Both builders are pure projections over supplied values. They perform no
    // collection, process access, memory inspection, file/network I/O, UI work,
    // or final-verdict calculation.
    NativeRuntimeObservationBuildResult BuildNativeRuntimeObservations(
        const NativeRuntimeObservationInput& input) noexcept;

    NativeRuntimeObservationBuildResult BuildNativePriorityObservations(
        const NativePriorityObservationInput& input) noexcept;
}
