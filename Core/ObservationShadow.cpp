#include "ObservationShadow.h"

#include <algorithm>
#include <chrono>
#include <cwctype>
#include <exception>
#include <iomanip>
#include <iterator>
#include <set>
#include <sstream>
#include <string_view>
#include <utility>

namespace GlassPane::Core
{
    namespace
    {
        using ShadowClock = std::chrono::steady_clock;

        std::uint64_t ElapsedMicroseconds(ShadowClock::time_point started)
        {
            return static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ShadowClock::now() - started).count());
        }

        std::string BoundedUtf8(std::string value, std::size_t maximumCharacters)
        {
            if (value.size() <= maximumCharacters)
            {
                return value;
            }

            std::size_t retained = maximumCharacters;
            while (retained > 0 &&
                (static_cast<unsigned char>(value[retained]) & 0xC0U) == 0x80U)
            {
                --retained;
            }
            value.resize(retained);
            return value;
        }


        std::string FailureDiagnostic(
            ObservationInventoryStatus status,
            const std::vector<std::string>& warnings)
        {
            std::string diagnostic = "Native observation production failed: " +
                ObservationInventoryStatusDisplayText(status) + ".";
            if (!warnings.empty())
            {
                diagnostic += " " + warnings.front();
            }
            return BoundedUtf8(
                std::move(diagnostic),
                ObservationShadowDiagnosticMaxCharacters);
        }

        void ResetObservationDispositionCounts(
            ObservationInventory& inventory)
        {
            inventory.informationalCount = 0;
            inventory.contextCount = 0;
            inventory.reviewRelevantCount = 0;
            inventory.correlatedOnlyCount = 0;
            inventory.collectionNoteCount = 0;
            inventory.evidenceIntegrityNoteCount = 0;
            inventory.suppressedExpectedCount = 0;
        }

        void CountObservationDisposition(
            ObservationInventory& inventory,
            ObservationDisposition disposition)
        {
            switch (disposition)
            {
            case ObservationDisposition::Informational:
                ++inventory.informationalCount;
                break;
            case ObservationDisposition::Context:
                ++inventory.contextCount;
                break;
            case ObservationDisposition::ReviewRelevant:
                ++inventory.reviewRelevantCount;
                break;
            case ObservationDisposition::CorrelatedOnly:
                ++inventory.correlatedOnlyCount;
                break;
            case ObservationDisposition::CollectionNote:
                ++inventory.collectionNoteCount;
                break;
            case ObservationDisposition::EvidenceIntegrityNote:
                ++inventory.evidenceIntegrityNoteCount;
                break;
            case ObservationDisposition::SuppressedExpected:
                ++inventory.suppressedExpectedCount;
                break;
            default:
                break;
            }
        }




        void UpdateDecisionSummary(ObservationShadowState& state) noexcept
        {
            ObservationShadowDecisionSummary& decision = state.decisionSummary;
            decision.attempted = state.attempted;
            decision.success = state.triage.Succeeded();
            decision.verdict = state.triage.verdict;
            decision.rawObservationCount = state.inventory.records.size();
            decision.refinedGroupCount = state.refinement.groups.size();
            decision.artifactGroupCount =
                state.refinement.summary.artifactGroupCount;
            decision.distinctArtifactCount =
                state.refinement.summary.distinctArtifactCount;
            decision.artifactAttributeCount =
                state.refinement.summary.artifactAttributeCount;
            decision.activatedCorrelationCount =
                state.correlation.summary.activatedCorrelationCount;
            decision.contributingObservationCount =
                state.triage.contributingObservationIds.size();
            decision.contributingCorrelationCount =
                state.triage.contributingCorrelationIds.size();
            decision.contributingDomainCount =
                state.triage.contributingDomains.size();
            decision.maximumContributingCorrelationDomainCount =
                state.triage.
                    maximumContributingCorrelationDomainCount;
            decision.sameDomainContributingCorrelationCount =
                state.triage.sameDomainContributingCorrelationCount;
            decision.sameDomainVerdictCeilingApplied =
                state.triage.sameDomainVerdictCeilingApplied;
            decision.qualifiedStandaloneStrongHighGateSatisfied =
                state.triage.
                    qualifiedStandaloneStrongHighGateSatisfied;
            decision.coherentMultiDomainHighGateSatisfied =
                state.triage.coherentMultiDomainHighGateSatisfied;
            decision.collectionNoteCount =
                state.triage.collectionNoteIds.size();
            decision.contextCount =
                state.triage.contextObservationIds.size();
            decision.unresolvedCorrelationCount =
                state.triage.unresolvedCorrelationKeys.size();
            decision.typedSourceFactCount =
                state.inventory.typedSourceFactCount;
            decision.declaredSourceFactCount =
                state.inventory.declaredSourceFactCount;
            decision.typedSourceFactDuplicateCount =
                state.refinement.summary.typedSourceFactDuplicateCount;
            decision.nativeObservationCount =
                state.nativeObservations.inventory.records.size();
            decision.nativeCommandRelationshipFileCount =
                state.nativeObservations.
                    commandRelationshipFileFactCount;
            decision.nativeTokenObservationCount =
                state.nativeObservations.tokenFactCount;
            decision.nativeHandleObservationCount =
                state.nativeObservations.handleFactCount;
            decision.nativeRuntimeObservationCount =
                state.nativeObservations.runtimeFactCount;
            decision.nativePriorityObservationCount =
                state.nativeObservations.priorityFactCount;
            decision.nativeHandleDuplicateRowCount =
                state.nativeObservations.handleDuplicateRowCount;
            decision.nativeBuildAttempted =
                state.nativeObservations.attempted;
            decision.nativeBuildSucceeded =
                state.nativeObservations.Succeeded();
            decision.nativeMaterialEvidenceTruncated =
                state.nativeObservations.omittedFactCount != 0;
            decision.nativeBuildDurationMicroseconds =
                state.nativeBuildDurationMicroseconds;
            decision.refinementDurationMicroseconds =
                state.refinement.summary.refinementDurationMicroseconds;
            decision.correlationDurationMicroseconds =
                state.correlation.summary.correlationDurationMicroseconds;
            decision.triageDurationMicroseconds =
                state.triage.triageDurationMicroseconds;
            decision.rationaleAggregationDurationMicroseconds =
                state.triage.rationaleAggregationDurationMicroseconds;
            decision.totalPipelineDurationMicroseconds =
                decision.nativeBuildDurationMicroseconds +
                decision.refinementDurationMicroseconds +
                decision.correlationDurationMicroseconds +
                decision.triageDurationMicroseconds;
        }
    }

    ObservationShadowState BuildNativeObservationShadowState(
        const ObservationShadowSourceContext& sourceContext,
        bool hasEntity,
        std::uint32_t selectedPid,
        std::uint64_t entityCreationTime,
        std::uint64_t sourceEvidenceGeneration)
    {
        const ShadowClock::time_point started = ShadowClock::now();

        try
        {
            if (!sourceContext.nativeInputSupplied)
            {
                return MakeFailedObservationShadowState(
                    sourceContext,
                    hasEntity,
                    selectedPid,
                    entityCreationTime,
                    sourceEvidenceGeneration,
                    "Native selected-process evidence was not supplied for this generation.",
                    ElapsedMicroseconds(started));
            }
            if (sourceContext.entityScope.empty() ||
                sourceContext.entityScope.size() >
                    ObservationEntityScopeMaxCharacters)
            {
                return MakeFailedObservationShadowState(
                    sourceContext,
                    hasEntity,
                    selectedPid,
                    entityCreationTime,
                    sourceEvidenceGeneration,
                    "Native selected-process observation construction failed: entity scope was missing or exceeded its cap.",
                    ElapsedMicroseconds(started));
            }

            ObservationShadowState state;
            state.attempted = true;
            state.hasEntity = hasEntity;
            state.selectedPid = selectedPid;
            state.entityCreationTime = entityCreationTime;
            state.sourceEvidenceGeneration = sourceEvidenceGeneration;
            state.entityScope = sourceContext.entityScope;

            const ShadowClock::time_point nativeStarted = ShadowClock::now();
            state.nativeObservations = BuildNativeSelectedProcessObservations(
                sourceContext.nativeInput);
            state.nativeBuildDurationMicroseconds =
                ElapsedMicroseconds(nativeStarted);
            if (!state.nativeObservations.Succeeded())
            {
                state.inventory = state.nativeObservations.inventory;
                state.summary = SummarizeObservationShadow(state.inventory);
                state.success = false;
                state.diagnosticMessage =
                    state.nativeObservations.diagnostic.empty()
                        ? "Native selected-process observation construction failed."
                        : state.nativeObservations.diagnostic;
                UpdateDecisionSummary(state);
                return state;
            }

            state.inventory = state.nativeObservations.inventory;
            state.summary = SummarizeObservationShadow(state.inventory);
            state.success = state.inventory.Succeeded();
            state.diagnosticMessage = state.success
                ? state.nativeObservations.diagnostic
                : FailureDiagnostic(
                    state.inventory.status,
                    state.nativeObservations.warnings);
            UpdateDecisionSummary(state);
            return state;
        }
        catch (...)
        {
            return MakeFailedObservationShadowState(
                sourceContext,
                hasEntity,
                selectedPid,
                entityCreationTime,
                sourceEvidenceGeneration,
                "Native selected-process observation construction failed internally.",
                ElapsedMicroseconds(started));
        }
    }

    ObservationShadowState MakeFailedObservationShadowState(
        const ObservationShadowSourceContext& sourceContext,
        bool hasEntity,
        std::uint32_t selectedPid,
        std::uint64_t entityCreationTime,
        std::uint64_t sourceEvidenceGeneration,
        std::string diagnosticMessage,
        std::uint64_t nativeBuildDurationMicroseconds)
    {
        ObservationShadowState state;
        state.attempted = true;
        state.success = false;
        state.hasEntity = hasEntity;
        state.selectedPid = selectedPid;
        state.entityCreationTime = entityCreationTime;
        state.sourceEvidenceGeneration = sourceEvidenceGeneration;
        if (sourceContext.entityScope.size() <= ObservationEntityScopeMaxCharacters)
        {
            state.entityScope = sourceContext.entityScope;
        }
        state.summary = SummarizeObservationShadow(state.inventory);
        state.nativeBuildDurationMicroseconds = nativeBuildDurationMicroseconds;
        if (diagnosticMessage.empty())
        {
            diagnosticMessage = "Native observation production failed.";
        }
        state.diagnosticMessage = BoundedUtf8(
            std::move(diagnosticMessage),
            ObservationShadowDiagnosticMaxCharacters);
        UpdateDecisionSummary(state);
        return state;
    }

    bool ObservationShadowMatches(
        const ObservationShadowState& state,
        bool hasEntity,
        std::uint32_t selectedPid,
        std::uint64_t entityCreationTime,
        std::uint64_t sourceEvidenceGeneration)
    {
        return state.attempted &&
            state.hasEntity == hasEntity &&
            state.selectedPid == selectedPid &&
            state.entityCreationTime == entityCreationTime &&
            state.sourceEvidenceGeneration == sourceEvidenceGeneration;
    }

    bool TryRefineObservationShadowState(ObservationShadowState& state) noexcept
    {
        if (!state.attempted || !state.success || state.refinement.attempted)
        {
            return false;
        }

        try
        {
            ObservationRefinementResult refinement =
                RefineObservationInventory(state.inventory);
            if (!refinement.attempted)
            {
                refinement = {};
                refinement.attempted = true;
                refinement.success = false;
                refinement.status = ObservationRefinementStatus::InternalPolicyFailure;
                refinement.summary.rawObservationCount = state.inventory.records.size();
            }
            state.refinement = std::move(refinement);
        }
        catch (...)
        {
            // Refinement is strictly subordinate to the already-complete raw
            // inventory. Stamp a bounded, value-only failure without
            // disturbing the retained native evidence summary.
            state.refinement.attempted = true;
            state.refinement.success = false;
            state.refinement.status =
                ObservationRefinementStatus::InternalPolicyFailure;
            state.refinement.summary.rawObservationCount =
                state.inventory.records.size();
        }
        UpdateDecisionSummary(state);
        return true;
    }

    bool TryActivateObservationShadowCorrelations(
        ObservationShadowState& state) noexcept
    {
        if (!state.attempted || !state.success ||
            !state.refinement.Succeeded() || state.correlation.attempted)
        {
            return false;
        }

        try
        {
            ObservationCorrelationResult correlation =
                ActivateObservationCorrelations(state.refinement);
            if (!correlation.attempted)
            {
                correlation = {};
                correlation.attempted = true;
                correlation.success = false;
                correlation.status =
                    ObservationCorrelationStatus::InternalPolicyFailure;
                correlation.summary.preparedCorrelationCount =
                    state.refinement.correlations.size();
            }
            state.correlation = std::move(correlation);
        }
        catch (...)
        {
            state.correlation = {};
            state.correlation.attempted = true;
            state.correlation.success = false;
            state.correlation.status =
                ObservationCorrelationStatus::InternalPolicyFailure;
            state.correlation.summary.preparedCorrelationCount =
                state.refinement.correlations.size();
        }
        UpdateDecisionSummary(state);
        return true;
    }

    bool TryBuildObservationShadowTriage(
        ObservationShadowState& state) noexcept
    {
        if (!state.attempted || !state.success ||
            !state.refinement.Succeeded() || !state.correlation.Succeeded() ||
            state.triage.attempted)
        {
            return false;
        }

        try
        {
            TriageResult triage = BuildTriageResult(
                state.refinement,
                state.correlation);
            if (!triage.attempted)
            {
                triage = {};
                triage.attempted = true;
                triage.success = false;
                triage.status = TriageEngineStatus::InternalPolicyFailure;
                triage.statusMessage =
                    "The current TriageEngine result could not be built; native selected-process authority is unavailable unless a current baseline result exists.";
            }
            state.triage = std::move(triage);
        }
        catch (...)
        {
            state.triage = {};
            state.triage.attempted = true;
            state.triage.success = false;
            state.triage.status =
                TriageEngineStatus::InternalPolicyFailure;
            try
            {
                state.triage.statusMessage =
                    "The current TriageEngine result could not be built; native selected-process authority is unavailable unless a current baseline result exists.";
            }
            catch (...)
            {
                // The status fields remain sufficient for failure isolation.
            }
        }
        UpdateDecisionSummary(state);
        return true;
    }

    void ClearObservationShadowState(ObservationShadowState& state)
    {
        state = {};
    }
}
