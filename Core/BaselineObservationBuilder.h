#pragma once

#include "ObservationInventory.h"
#include "ProcessInfo.h"
#include "ServiceInfo.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace GlassPane::Core
{
    // The baseline path consumes only bounded, already-collected process-wide
    // facts. These caps prevent endpoint-wide evaluation from turning into a
    // deep or unbounded evidence scan.
    constexpr std::size_t BaselineObservationMaxTypedProcessFacts = 64;
    constexpr std::size_t BaselineObservationMaxNetworkConnections = 64;
    constexpr std::size_t BaselineObservationMaxNetworkIndicatorFacts = 64;
    constexpr std::size_t BaselineObservationMaxServiceAssociations = 64;
    constexpr std::size_t BaselineObservationMaxCollectionFacts = 32;
    constexpr std::size_t BaselineObservationMaxSourceFacts = 256;
    constexpr std::size_t BaselineObservationMaxLimitations = 32;
    constexpr std::size_t BaselineObservationFactKeyMaxCharacters = 256;
    constexpr std::size_t BaselineObservationFactValueMaxCharacters =
        ObservationRawValueMaxCharacters;
    constexpr std::size_t BaselineObservationDiagnosticMaxCharacters = 1024;

    // Stable native mapping identities. They describe typed baseline facts and
    // are intentionally independent of legacy Finding titles and severities.
    inline constexpr char BaselineMappingProcessIdentity[] =
        "baseline.process.identity";
    inline constexpr char BaselineMappingExecutablePath[] =
        "baseline.file.executable-path-context";
    inline constexpr char BaselineMappingUserWritablePath[] =
        "baseline.file.user-path-context";
    inline constexpr char BaselineMappingEncodedCommand[] =
        "baseline.command.encoded-switch";
    inline constexpr char BaselineMappingProcessRelationship[] =
        "baseline.relationship.typed-context";
    inline constexpr char BaselineMappingProcessRelationshipContext[] =
        "baseline.relationship.parent-link-context";
    inline constexpr char BaselineMappingInvalidFileSignature[] =
        "baseline.file.signature-invalid";
    inline constexpr char BaselineMappingPublicNetworkConnection[] =
        "baseline.network.public-activity-context";
    inline constexpr char BaselineMappingExactNetworkIndicator[] =
        "baseline.network.indicator-exact-match";
    inline constexpr char BaselineMappingServiceAssociation[] =
        "baseline.service.scm-pid-association";
    inline constexpr char BaselineMappingCommandLineUnavailable[] =
        "baseline.collection.command-line-unavailable";
    inline constexpr char BaselineMappingRelationshipUnavailable[] =
        "baseline.collection.relationship-unavailable";
    inline constexpr char BaselineMappingNetworkCollectionUnavailable[] =
        "baseline.collection.network-unavailable";
    inline constexpr char BaselineMappingServiceCollectionUnavailable[] =
        "baseline.collection.service-unavailable";

    enum class BaselineTypedProcessFactKind : std::uint32_t
    {
        Unknown = 0,
        ReviewRelevantProcessRelationship = 1,
        InvalidFileSignature = 2
    };

    struct BaselineTypedProcessFact
    {
        BaselineTypedProcessFactKind kind =
            BaselineTypedProcessFactKind::Unknown;
        std::string sourceRuleId;
        std::string factKey;
        std::string rawValue;
        std::string normalizedValue;
        std::uint32_t relatedPid = 0;
        ObservationConfidence confidence = ObservationConfidence::High;
        ObservationSourceKind sourceKind = ObservationSourceKind::Direct;
        std::string sourceIdentifier;
        std::string collectionMethod;
        std::vector<std::string> evidence;
        std::vector<std::string> limitations;
    };

    struct BaselineNetworkConnectionFact
    {
        std::string artifactKey;
        std::string protocol;
        std::string localAddress;
        std::uint16_t localPort = 0;
        std::string remoteAddress;
        std::uint16_t remotePort = 0;
        std::string state;
        bool publicRemote = false;
        ObservationSourceKind sourceKind = ObservationSourceKind::Direct;
        std::string sourceIdentifier;
        std::string collectionMethod;
        std::vector<std::string> limitations;
    };

    struct BaselineNetworkIndicatorFact
    {
        std::string artifactKey;
        std::string sourceRuleId;
        std::string indicatorType;
        std::string rawValue;
        std::string normalizedValue;
        ObservationStrength strength = ObservationStrength::Moderate;
        ObservationConfidence confidence = ObservationConfidence::Medium;
        ObservationSourceKind sourceKind = ObservationSourceKind::Imported;
        std::string sourceIdentifier;
        std::string collectionMethod;
        std::string assessmentRationale;
        std::vector<std::string> limitations;
    };

    struct BaselineServiceAssociationFact
    {
        std::string artifactKey;
        std::string serviceName;
        std::string displayName;
        ServiceProcessModel processModel = ServiceProcessModel::Unknown;
        std::uint32_t stateRaw = 0;
        ObservationSourceKind sourceKind = ObservationSourceKind::Direct;
        std::string sourceIdentifier;
        std::string collectionMethod;
        std::vector<std::string> limitations;
    };

    enum class BaselineCollectionFactKind : std::uint32_t
    {
        Unknown = 0,
        NetworkUnavailable = 1,
        ServiceUnavailable = 2
    };

    // Explicit endpoint collection outcome supplied by the cache owner. The
    // builder never invents one from absent optional/deep evidence.
    struct BaselineCollectionFact
    {
        BaselineCollectionFactKind kind = BaselineCollectionFactKind::Unknown;
        std::string sourceRuleId;
        std::string statusMessage;
        std::string sourceIdentifier;
        std::string collectionMethod;
        std::vector<std::string> limitations;
    };

    struct BaselineObservationContext
    {
        // If empty, the builder derives a stable scope from PID plus the
        // available process creation time. This scope is data identity, not a
        // display label or policy input.
        std::string entityScope;
        ObservationSourceKind sourceKind = ObservationSourceKind::Direct;
        std::string collectionTimestamp;
        bool importedEvidence = false;

        // Native process path/command/relationship producers can be disabled
        // in focused tests. Production cache construction leaves them enabled.
        bool includeNativeProcessIdentity = true;
        bool includeNativeExecutablePath = true;
        bool includeNativeCommandLine = true;
        bool includeNativeRelationshipContext = true;

        std::vector<BaselineTypedProcessFact> typedProcessFacts;
        std::vector<BaselineNetworkConnectionFact> networkConnections;
        std::vector<BaselineNetworkIndicatorFact> networkIndicatorFacts;
        std::vector<BaselineServiceAssociationFact> serviceAssociations;
        std::vector<BaselineCollectionFact> collectionFacts;
        std::vector<std::string> limitations;

        // A process-wide cache may need to bound globally pre-indexed facts
        // before calling this per-process builder. These fields carry that
        // omission forward so the result remains honestly truncated even
        // though the rejected facts are no longer present in the vectors.
        bool preboundedSourceFactsTruncated = false;
        std::size_t preboundedOmittedSourceFactCount = 0;
    };

    enum class BaselineObservationStatus : std::uint32_t
    {
        NotAttempted = 0,
        Success = 1,
        InvalidEntityScope = 2,
        InvalidTypedFact = 3,
        OutputLimitExceeded = 4,
        InternalPolicyFailure = 5
    };

    std::string BaselineObservationStatusDisplayText(
        BaselineObservationStatus status);

    struct BaselineObservationResult
    {
        bool attempted = false;
        bool success = false;
        bool truncated = false;
        BaselineObservationStatus status =
            BaselineObservationStatus::NotAttempted;

        ObservationInventory inventory;
        std::size_t nativeFactCount = 0;
        std::size_t omittedFactCount = 0;
        std::size_t duplicateExcludedCount = 0;
        std::vector<std::string> limitations;
        std::string diagnostic;

        bool Succeeded() const;
    };

    // Pure baseline observation construction. The snapshot is inspected only
    // for typed process identity/relationship context; no collector, file,
    // network, service, or UI operation is performed.
    BaselineObservationResult BuildBaselineObservations(
        const ProcessInfo& process,
        const ProcessSnapshot& snapshot,
        const BaselineObservationContext& context);
}
