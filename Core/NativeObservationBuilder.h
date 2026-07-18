#pragma once

#include "ObservationInventory.h"
#include "MemoryRegionInfo.h"
#include "ModuleInfo.h"
#include "NativeHandleObservationBuilder.h"
#include "NativeRuntimeObservationBuilder.h"
#include "NativeTokenObservationBuilder.h"
#include "NetworkConnection.h"
#include "NetworkIndicator.h"
#include "ProcessTriageCache.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace GlassPane::Core
{
    constexpr std::size_t NativeObservationMaxCommandLineCharacters = 16384;
    constexpr std::size_t NativeObservationMaxCommandTokens = 256;
    constexpr std::size_t NativeObservationMaxEncodedSwitches = 16;
    constexpr std::size_t NativeObservationMaxEncodedPayloadCharacters = 8192;
    constexpr std::size_t NativeObservationMaxDecodedPayloadBytes = 4096;
    constexpr std::size_t NativeObservationMaxDecodedPreviewCharacters = 1024;
    constexpr std::size_t NativeObservationMaxRelationshipFacts = 64;
    constexpr std::size_t NativeObservationMaxNetworkConnections = 64;
    constexpr std::size_t NativeObservationMaxNetworkIndicators = 64;
    constexpr std::size_t NativeObservationMaxModules = 256;
    constexpr std::size_t NativeObservationMaxMemoryRegions = 512;
    constexpr std::size_t NativeObservationMaxOutputRecords =
        ObservationInventoryMaxObservations;
    constexpr std::size_t NativeObservationMaxMergeRecords =
        ObservationInventoryMaxObservations;
    constexpr std::size_t NativeObservationMaxWarnings = 64;
    constexpr std::size_t NativeObservationWarningMaxCharacters = 1024;
    constexpr std::size_t NativeObservationSemanticFactKeyMaxCharacters = 256;
    constexpr std::size_t NativeObservationDiagnosticMaxCharacters = 1024;

    // Existing policy-recognized mapping identities are reused when the native
    // typed fact has exactly the same semantics. Context-only native facts use
    // new IDs and require no correlation aliases.
    inline constexpr char NativeMappingEncodedCommand[] =
        "baseline.command.encoded-switch";
    inline constexpr char NativeMappingTypedRelationship[] =
        "baseline.relationship.typed-context";
    inline constexpr char NativeMappingRelationshipContext[] =
        "native.relationship.verified-context";
    inline constexpr char NativeMappingExecutablePath[] =
        "baseline.file.executable-path-context";
    inline constexpr char NativeMappingUserWritablePath[] =
        "baseline.file.user-path-context";
    inline constexpr char NativeMappingInvalidSignature[] =
        "baseline.file.signature-invalid";
    inline constexpr char NativeMappingValidSignature[] =
        "native.file.signature-valid";
    inline constexpr char NativeMappingSignatureAbsent[] =
        "native.file.signature-absent";
    inline constexpr char NativeMappingCommandLineUnavailable[] =
        "native.collection.command-line-unavailable";
    inline constexpr char NativeMappingRelationshipUnavailable[] =
        "native.collection.relationship-unavailable";
    inline constexpr char NativeMappingFileIdentityUnavailable[] =
        "native.collection.file-identity-unavailable";
    inline constexpr char NativeMappingPublicNetworkContext[] =
        "native.network.public-activity-context";
    inline constexpr char NativeMappingExactNetworkIndicator[] =
        "baseline.network.indicator-exact-match";
    inline constexpr char NativeMappingNetworkUnavailable[] =
        "native.collection.network-unavailable";
    inline constexpr char NativeMappingNetworkTruncated[] =
        "native.collection.network-truncated";
    inline constexpr char NativeMappingModuleContext[] =
        "native.module.loaded-image-context";
    inline constexpr char NativeMappingModuleUserWritablePath[] =
        "native.module.user-path-context";
    inline constexpr char NativeMappingModulePathUnavailable[] =
        "native.collection.module-path-unavailable";
    inline constexpr char NativeMappingModulesUnavailable[] =
        "native.collection.modules-unavailable";
    inline constexpr char NativeMappingModulesTruncated[] =
        "native.collection.modules-truncated";
    inline constexpr char NativeMappingStaticMemoryContext[] =
        "native.memory.static-region-context";
    inline constexpr char NativeMappingMemoryUnavailable[] =
        "native.collection.memory-unavailable";
    inline constexpr char NativeMappingMemoryTruncated[] =
        "native.collection.memory-truncated";
    inline constexpr char NativeMappingAffinityContext[] =
        "native.runtime.affinity-context";
    inline constexpr char NativeMappingAffinityUnavailable[] =
        "native.collection.affinity-unavailable";

    enum class ObservationSourceCompleteness : std::uint32_t
    {
        Complete = 0,
        Partial = 1,
        Unavailable = 2
    };

    enum class ObservationDuplicateRole : std::uint32_t
    {
        Primary = 0,
        SupportingDuplicate = 1
    };

    enum class NativeEncodedPayloadEncoding : std::uint32_t
    {
        None = 0,
        Utf8 = 1,
        Utf16LittleEndian = 2,
        Binary = 3,
        InvalidBase64 = 4,
        LimitExceeded = 5
    };

    enum class NativeRelationshipKind : std::uint32_t
    {
        DirectParent = 0,
        Ancestor = 1
    };

    enum class NativeRelationshipSemantics : std::uint32_t
    {
        Context = 0,
        ExecutionCorrelation = 1
    };

    enum class NativeFileSignatureState : std::uint32_t
    {
        NotEvaluated = 0,
        AuthenticatedValid = 1,
        AuthenticatedInvalid = 2,
        SignatureAbsent = 3,
        Unavailable = 4
    };

    enum class NativeFilePathContext : std::uint32_t
    {
        NotEvaluated = 0,
        Available = 1,
        UserWritable = 2,
        Unavailable = 3
    };

    enum class NativeObservationBuildStatus : std::uint32_t
    {
        NotAttempted = 0,
        Success = 1,
        InvalidIdentity = 2,
        InputLimitExceeded = 3,
        InvalidTypedFact = 4,
        PolicyValidationFailed = 5
    };

    std::string ObservationSourceCompletenessDisplayText(
        ObservationSourceCompleteness completeness);
    std::string NativeEncodedPayloadEncodingDisplayText(
        NativeEncodedPayloadEncoding encoding);
    std::string NativeObservationBuildStatusDisplayText(
        NativeObservationBuildStatus status);

    // Generic typed path classification shared by runtime plumbing and tests.
    // It does not inspect process names, products, publishers, or signers.
    NativeFilePathContext ClassifyNativeFilePathContext(
        std::string_view normalizedExecutablePath);

    struct NativeObservationSource
    {
        ObservationSourceKind sourceKind = ObservationSourceKind::Direct;
        ObservationSourceCompleteness completeness =
            ObservationSourceCompleteness::Complete;
        std::string sourceIdentifier;
        std::string collectionMethod;
        std::string collectionTimestamp;
        std::string requiredPrivilege;
        std::string rawSourceReference;
        std::vector<std::string> limitations;
    };

    struct NativeCommandLineInput
    {
        ProcessIdentityKey identity;
        bool supplied = false;
        bool collectionAttempted = false;
        bool available = false;
        std::string commandLine;
        NativeObservationSource source;
    };

    struct NativeRelationshipFact
    {
        ProcessIdentityKey subjectIdentity;
        ProcessIdentityKey relatedIdentity;
        NativeRelationshipKind kind = NativeRelationshipKind::DirectParent;
        NativeRelationshipSemantics semantics =
            NativeRelationshipSemantics::Context;
        bool verified = true;
        std::string semanticFactKey;
        std::string sourceRuleId;
        std::string rawValue;
        std::string normalizedValue;
        std::vector<std::string> evidence;
        NativeObservationSource source;
    };

    struct NativeFileIdentityInput
    {
        ProcessIdentityKey identity;
        bool supplied = false;
        std::string artifactKey;
        std::string rawPath;
        std::string normalizedPath;
        NativeFilePathContext pathContext =
            NativeFilePathContext::NotEvaluated;
        NativeFileSignatureState signatureState =
            NativeFileSignatureState::NotEvaluated;

        // These are authenticated-source metadata only. Their values never
        // alter disposition, strength, confidence, or verdict contribution.
        std::string signerSubject;
        std::string signerIssuer;
        std::string signerThumbprint;
        std::vector<std::string> evidence;
        NativeObservationSource source;
    };

    // All inputs below are value-owned projections of already-collected
    // selected-process evidence. The native builder never invokes a collector.
    struct NativeNetworkObservationInput
    {
        ProcessIdentityKey identity;
        bool supplied = false;
        bool collectionAttempted = false;
        bool available = false;
        bool truncated = false;
        std::size_t omittedContextFactCount = 0;
        std::size_t omittedMaterialFactCount = 0;
        std::vector<NetworkConnection> connections;
        std::vector<NetworkIndicatorMatch> exactIndicatorMatches;
        NativeObservationSource source;
    };

    struct NativeModuleObservationInput
    {
        ProcessIdentityKey identity;
        bool supplied = false;
        bool collectionAttempted = false;
        bool available = false;
        bool truncated = false;
        std::size_t omittedContextFactCount = 0;
        ModuleCollectionResult collection;
        NativeObservationSource source;
    };

    struct NativeMemoryObservationInput
    {
        ProcessIdentityKey identity;
        bool supplied = false;
        bool collectionAttempted = false;
        bool available = false;
        bool truncated = false;
        std::size_t omittedContextFactCount = 0;
        MemoryCollectionResult collection;
        NativeObservationSource source;
    };

    struct NativeAffinityObservationInput
    {
        ProcessIdentityKey identity;
        bool supplied = false;
        bool collectionAttempted = false;
        bool available = false;
        std::uint64_t processAffinityMask = 0;
        std::uint64_t systemAffinityMask = 0;
        NativeObservationSource source;
    };

    struct NativeSelectedProcessObservationInput
    {
        ProcessIdentityKey identity;
        // Empty derives the same PID + creation-time scope used by the existing
        // process-wide cache. A supplied scope remains data identity only.
        std::string entityScope;
        NativeCommandLineInput commandLine;
        std::vector<NativeRelationshipFact> relationships;
        NativeFileIdentityInput fileIdentity;
        NativeNetworkObservationInput network;
        NativeModuleObservationInput modules;
        NativeMemoryObservationInput memory;
        NativeAffinityObservationInput affinity;
        NativeTokenObservationInput token;
        NativeHandleObservationInput handles;
        NativeRuntimeObservationInput runtime;
        NativePriorityObservationInput priority;
        std::vector<std::string> limitations;
    };

    struct NativeObservationRecord
    {
        ObservationRecord record;
        ObservationSourceCompleteness completeness =
            ObservationSourceCompleteness::Complete;
        std::string semanticFactKey;
        std::string sourceRecordId;
        ObservationDuplicateRole duplicateRole =
            ObservationDuplicateRole::Primary;
        std::string primaryObservationId;
    };


    struct NativeObservationMergeResult
    {
        bool success = false;
        std::vector<NativeObservationRecord> records;
        ObservationInventory inventory;
        std::size_t completeSourceCount = 0;
        std::size_t partialSourceCount = 0;
        std::size_t unavailableSourceCount = 0;
        std::size_t primaryCount = 0;
        std::size_t duplicateCount = 0;
        std::string diagnostic;
    };

    // Same nonempty entity scope + semantic fact key defines a duplicate set.
    // Completeness selects the primary and input order breaks exact ties.
    // Every record remains recoverable; only primary records enter the merged
    // inventory. Equivalent native records remain audit-visible as supporting
    // duplicates and cannot reinforce the verdict.
    NativeObservationMergeResult MergeNativeObservationRecords(
        const std::vector<NativeObservationRecord>& records);

    struct NativeObservationBuildResult
    {
        bool attempted = false;
        bool success = false;
        bool truncated = false;
        NativeObservationBuildStatus status =
            NativeObservationBuildStatus::NotAttempted;
        std::vector<NativeObservationRecord> records;
        ObservationInventory inventory;
        std::size_t nativeFactCount = 0;
        std::size_t representedFactCount = 0;
        std::size_t duplicateCount = 0;
        std::size_t omittedFactCount = 0;
        std::size_t completeFactCount = 0;
        std::size_t partialFactCount = 0;
        std::size_t unavailableFactCount = 0;
        std::size_t commandRelationshipFileFactCount = 0;
        std::size_t tokenFactCount = 0;
        std::size_t handleFactCount = 0;
        std::size_t runtimeFactCount = 0;
        std::size_t priorityFactCount = 0;
        std::size_t networkFactCount = 0;
        std::size_t moduleFactCount = 0;
        std::size_t memoryFactCount = 0;
        std::size_t affinityFactCount = 0;
        std::size_t handleDuplicateRowCount = 0;
        bool tokenProducerAttempted = false;
        bool tokenProducerSucceeded = false;
        bool handleProducerAttempted = false;
        bool handleProducerSucceeded = false;
        bool runtimeProducerAttempted = false;
        bool runtimeProducerSucceeded = false;
        bool priorityProducerAttempted = false;
        bool priorityProducerSucceeded = false;
        bool warningsTruncated = false;
        std::vector<std::string> warnings;
        std::string diagnostic;

        bool Succeeded() const;
    };

    // Pure selected-process construction. It performs no collection, file or
    // network access, decoding execution, script interpretation, UI work, or
    // final-verdict calculation.
    NativeObservationBuildResult BuildNativeSelectedProcessObservations(
        const NativeSelectedProcessObservationInput& input) noexcept;
}
