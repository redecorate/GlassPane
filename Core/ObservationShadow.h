#pragma once

#include "NativeObservationBuilder.h"
#include "ObservationRefinement.h"
#include "TriageEngine.h"


#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace GlassPane::Core
{
    constexpr std::size_t ObservationShadowDiagnosticMaxCharacters = 1024;

    // Caller-owned source context keeps live and imported evidence provenance
    // explicit. It carries no collector pointers and performs no collection.
    struct ObservationShadowSourceContext
    {
        std::string entityScope;
        ObservationSourceKind sourceKind = ObservationSourceKind::Derived;
        std::string producerIdentifier = "core.native-observation-builder";
        std::string collectionMethod = "selected-process-triage-recomputation";
        std::string collectionTimestamp;
        std::string requiredPrivilege;
        bool sourceAvailable = true;
        std::string rawSourceReference;
        std::vector<std::string> limitations;
        std::vector<std::string> provenanceLimitations;
        bool nativeInputSupplied = false;
        NativeSelectedProcessObservationInput nativeInput;
    };

    struct ObservationShadowDecisionSummary
    {
        bool attempted = false;
        bool success = false;
        TriageVerdict verdict = TriageVerdict::Informational;
        std::size_t rawObservationCount = 0;
        std::size_t refinedGroupCount = 0;
        std::size_t artifactGroupCount = 0;
        std::size_t distinctArtifactCount = 0;
        std::size_t artifactAttributeCount = 0;
        std::size_t activatedCorrelationCount = 0;
        std::size_t contributingObservationCount = 0;
        std::size_t contributingCorrelationCount = 0;
        std::size_t contributingDomainCount = 0;
        std::size_t maximumContributingCorrelationDomainCount = 0;
        std::size_t sameDomainContributingCorrelationCount = 0;
        bool sameDomainVerdictCeilingApplied = false;
        bool qualifiedStandaloneStrongHighGateSatisfied = false;
        bool coherentMultiDomainHighGateSatisfied = false;
        std::size_t collectionNoteCount = 0;
        std::size_t contextCount = 0;
        std::size_t unresolvedCorrelationCount = 0;
        std::size_t typedSourceFactCount = 0;
        std::size_t declaredSourceFactCount = 0;
        std::size_t typedSourceFactDuplicateCount = 0;
        std::size_t nativeObservationCount = 0;
        std::size_t nativeCommandRelationshipFileCount = 0;
        std::size_t nativeTokenObservationCount = 0;
        std::size_t nativeHandleObservationCount = 0;
        std::size_t nativeRuntimeObservationCount = 0;
        std::size_t nativePriorityObservationCount = 0;
        std::size_t nativeHandleDuplicateRowCount = 0;
        bool nativeBuildAttempted = false;
        bool nativeBuildSucceeded = false;
        bool nativeMaterialEvidenceTruncated = false;
        std::uint64_t nativeBuildDurationMicroseconds = 0;
        std::uint64_t refinementDurationMicroseconds = 0;
        std::uint64_t correlationDurationMicroseconds = 0;
        std::uint64_t triageDurationMicroseconds = 0;
        std::uint64_t rationaleAggregationDurationMicroseconds = 0;
        std::uint64_t totalPipelineDurationMicroseconds = 0;
    };

    struct ObservationShadowState
    {
        bool attempted = false;
        bool success = false;

        // hasEntity distinguishes no selection from the valid synthetic PID 0.
        bool hasEntity = false;
        std::uint32_t selectedPid = 0;
        std::uint64_t entityCreationTime = 0;
        std::uint64_t sourceEvidenceGeneration = 0;
        std::string entityScope;

        ObservationInventory inventory;
        NativeObservationBuildResult nativeObservations;
        ObservationShadowSummary summary;
        ObservationRefinementResult refinement;
        ObservationCorrelationResult correlation;
        TriageResult triage;
        ObservationShadowDecisionSummary decisionSummary;
        std::string diagnosticMessage;
        std::uint64_t nativeBuildDurationMicroseconds = 0;
    };


    // Builds the current selected-process pipeline exclusively from producer-
    // authored native typed input. This path never constructs adapter inputs and
    // never invokes Finding compatibility adaptation. The generation parameter
    // remains the caller-owned selected-evidence generation stamp.
    ObservationShadowState BuildNativeObservationShadowState(
        const ObservationShadowSourceContext& sourceContext,
        bool hasEntity,
        std::uint32_t selectedPid,
        std::uint64_t entityCreationTime,
        std::uint64_t sourceEvidenceGeneration);

    // Runtime exception isolation can use this helper to stamp a failed source
    // generation atomically. A stamped failure matches that generation and is
    // therefore not retried on idle frames.
    ObservationShadowState MakeFailedObservationShadowState(
        const ObservationShadowSourceContext& sourceContext,
        bool hasEntity,
        std::uint32_t selectedPid,
        std::uint64_t entityCreationTime,
        std::uint64_t sourceEvidenceGeneration,
        std::string diagnosticMessage,
        std::uint64_t nativeBuildDurationMicroseconds = 0);

    bool ObservationShadowMatches(
        const ObservationShadowState& state,
        bool hasEntity,
        std::uint32_t selectedPid,
        std::uint64_t entityCreationTime,
        std::uint64_t sourceEvidenceGeneration);

    // Attaches one value-owned refinement to a successful raw shadow. The
    // operation is idempotent for a state and isolates refinement failure from
    // the raw native inventory already stored in it.
    bool TryRefineObservationShadowState(ObservationShadowState& state) noexcept;

    // Attaches one typed correlation result to a successful refinement. A
    // stamped failure is retained and never retried by idle-frame calls.
    bool TryActivateObservationShadowCorrelations(
        ObservationShadowState& state) noexcept;

    // Builds one native triage verdict after successful correlation
    // activation from native typed evidence only.
    bool TryBuildObservationShadowTriage(
        ObservationShadowState& state) noexcept;

    void ClearObservationShadowState(ObservationShadowState& state);
}
