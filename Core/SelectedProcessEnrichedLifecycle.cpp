#include "SelectedProcessEnrichedLifecycle.h"

namespace GlassPane::Core
{
    namespace
    {
        std::string BoundedDiagnostic(std::string value)
        {
            if (value.size() >
                SelectedProcessEnrichedLifecycleDiagnosticMaxCharacters)
            {
                value.resize(
                    SelectedProcessEnrichedLifecycleDiagnosticMaxCharacters);
            }
            return value;
        }

        bool SameSelectedEntityAndScope(
            const SelectedProcessEnrichedSourceStamp& left,
            const SelectedProcessEnrichedSourceStamp& right)
        {
            return left.hasEntity == right.hasEntity &&
                (!left.hasEntity || left.identity == right.identity) &&
                left.scope == right.scope;
        }

        SelectedProcessEnrichedRejection IdentityRejection(
            const ProcessIdentityKey& expected,
            const ProcessIdentityKey& actual)
        {
            if (expected.pid != actual.pid)
            {
                return SelectedProcessEnrichedRejection::PidMismatch;
            }
            if (expected.hasCreationTime != actual.hasCreationTime)
            {
                return SelectedProcessEnrichedRejection::
                    CreationTimeAvailabilityMismatch;
            }
            if (expected.hasCreationTime &&
                expected.creationTimeFileTime != actual.creationTimeFileTime)
            {
                return SelectedProcessEnrichedRejection::CreationTimeMismatch;
            }
            return SelectedProcessEnrichedRejection::None;
        }

        SelectedProcessEnrichedRejection SourceRejection(
            const SelectedProcessEnrichedSourceStamp& expected,
            const SelectedProcessEnrichedSourceStamp& actual)
        {
            if (!actual.hasEntity)
            {
                return SelectedProcessEnrichedRejection::NoSelectedEntity;
            }
            if (actual.scope == SelectedProcessAnalysisScope::LoadedSnapshot)
            {
                return SelectedProcessEnrichedRejection::LoadedSnapshotScope;
            }
            const SelectedProcessEnrichedRejection identity =
                IdentityRejection(expected.identity, actual.identity);
            if (identity != SelectedProcessEnrichedRejection::None)
            {
                return identity;
            }
            if (expected.processGeneration != actual.processGeneration)
            {
                return SelectedProcessEnrichedRejection::
                    ProcessGenerationMismatch;
            }
            if (expected.evidenceGeneration != actual.evidenceGeneration)
            {
                return SelectedProcessEnrichedRejection::
                    EvidenceGenerationMismatch;
            }
            if (expected.scopeGeneration != actual.scopeGeneration)
            {
                return SelectedProcessEnrichedRejection::
                    ScopeGenerationMismatch;
            }
            if (expected.scope != actual.scope ||
                expected.entityScope != actual.entityScope)
            {
                return SelectedProcessEnrichedRejection::ScopeMismatch;
            }
            return SelectedProcessEnrichedRejection::None;
        }

        void QueueLatestAfterStaleBuild(
            SelectedProcessEnrichedLifecycleState& state,
            const SelectedProcessEnrichedSourceStamp& currentSource)
        {
            if (!currentSource.hasEntity ||
                currentSource.scope ==
                    SelectedProcessAnalysisScope::LoadedSnapshot)
            {
                return;
            }
            if (!state.buildPending || state.requestedSource != currentSource)
            {
                state.requestedSource = currentSource;
                state.buildPending = true;
                state.buildRequested = true;
                state.lastRequestReason = SelectedProcessEnrichedRebuildReason::
                    GenerationChangedDuringBuild;
                ++state.requestGeneration;
            }
        }
    }

    bool operator==(
        const SelectedProcessEnrichedSourceStamp& left,
        const SelectedProcessEnrichedSourceStamp& right)
    {
        return left.hasEntity == right.hasEntity &&
            left.identity == right.identity &&
            left.scope == right.scope &&
            left.processGeneration == right.processGeneration &&
            left.evidenceGeneration == right.evidenceGeneration &&
            left.scopeGeneration == right.scopeGeneration &&
            left.entityScope == right.entityScope;
    }

    bool operator!=(
        const SelectedProcessEnrichedSourceStamp& left,
        const SelectedProcessEnrichedSourceStamp& right)
    {
        return !(left == right);
    }

    bool UpdateSelectedProcessEnrichedSelection(
        SelectedProcessEnrichedLifecycleState& state,
        const SelectedProcessEnrichedSourceStamp& currentSource)
    {
        const bool changed = !SameSelectedEntityAndScope(
            state.currentSource,
            currentSource);
        if (changed)
        {
            const std::uint64_t nextSelectionGeneration =
                state.selectionGeneration + 1;
            state = {};
            state.selectionGeneration = nextSelectionGeneration;
        }
        state.currentSource = currentSource;
        return changed;
    }

    bool RequestSelectedProcessEnrichedRebuild(
        SelectedProcessEnrichedLifecycleState& state,
        const SelectedProcessEnrichedSourceStamp& currentSource,
        SelectedProcessEnrichedRebuildReason reason)
    {
        UpdateSelectedProcessEnrichedSelection(state, currentSource);
        if (!currentSource.hasEntity)
        {
            state.rejection =
                SelectedProcessEnrichedRejection::NoSelectedEntity;
            return false;
        }
        if (currentSource.scope ==
            SelectedProcessAnalysisScope::LoadedSnapshot)
        {
            state.rejection =
                SelectedProcessEnrichedRejection::LoadedSnapshotScope;
            return false;
        }
        if (SelectedProcessEnrichedPublicationMatches(state, currentSource))
        {
            return false;
        }
        if (state.buildPending && state.requestedSource == currentSource)
        {
            return false;
        }
        if (state.buildInProgress && state.activeBuildSource == currentSource)
        {
            return false;
        }

        state.currentSource = currentSource;
        state.requestedSource = currentSource;
        state.buildRequested = true;
        state.buildPending = true;
        state.buildCompleted = false;
        state.publicationAttempted = false;
        state.publicationAccepted = false;
        state.storedSource = {};
        state.lastRequestReason = reason;
        state.rejection = SelectedProcessEnrichedRejection::None;
        state.diagnostic.clear();
        ++state.requestGeneration;
        return true;
    }

    bool TryBeginSelectedProcessEnrichedBuild(
        SelectedProcessEnrichedLifecycleState& state,
        SelectedProcessEnrichedSourceStamp& capturedSource)
    {
        if (!state.buildPending || state.buildInProgress ||
            !state.requestedSource.hasEntity ||
            state.requestedSource.scope ==
                SelectedProcessAnalysisScope::LoadedSnapshot)
        {
            return false;
        }

        state.buildPending = false;
        state.buildInProgress = true;
        state.buildStarted = true;
        state.buildCompleted = false;
        state.activeBuildSource = state.requestedSource;
        capturedSource = state.activeBuildSource;
        ++state.buildInvocationCount;
        return true;
    }

    bool CompleteSelectedProcessEnrichedBuild(
        SelectedProcessEnrichedLifecycleState& state,
        const SelectedProcessEnrichedSourceStamp& capturedSource,
        const SelectedProcessEnrichedSourceStamp& currentSource,
        const ObservationShadowState& candidate,
        std::uint64_t completionTimestampMilliseconds,
        std::uint64_t completionDurationMicroseconds)
    {
        state.currentSource = currentSource;
        state.buildInProgress = false;
        state.buildCompleted = true;
        state.publicationAttempted = true;
        state.publicationAccepted = false;
        state.storedSource = {};
        state.completionTimestampMilliseconds =
            completionTimestampMilliseconds;
        state.completionDurationMicroseconds =
            completionDurationMicroseconds;

        state.nativeObservationBuildSuccess = candidate.success &&
            candidate.inventory.Succeeded() &&
            candidate.nativeObservations.Succeeded();
        state.refinementSuccess = candidate.refinement.Succeeded();
        state.correlationSuccess = candidate.correlation.Succeeded();
        state.triageSuccess = candidate.triage.Succeeded();
        state.completenessSufficientForAuthority =
            candidate.nativeObservations.omittedFactCount == 0;

        SelectedProcessEnrichedRejection rejection =
            SourceRejection(capturedSource, currentSource);
        if (rejection == SelectedProcessEnrichedRejection::None)
        {
            const ProcessIdentityKey candidateIdentity = {
                candidate.selectedPid,
                capturedSource.identity.hasCreationTime,
                capturedSource.identity.hasCreationTime
                    ? candidate.entityCreationTime
                    : 0
            };
            rejection = IdentityRejection(
                capturedSource.identity,
                candidateIdentity);
        }
        if (rejection == SelectedProcessEnrichedRejection::None &&
            candidate.sourceEvidenceGeneration !=
                capturedSource.evidenceGeneration)
        {
            rejection = SelectedProcessEnrichedRejection::
                EvidenceGenerationMismatch;
        }
        if (rejection == SelectedProcessEnrichedRejection::None &&
            candidate.entityScope != capturedSource.entityScope)
        {
            rejection = SelectedProcessEnrichedRejection::ScopeMismatch;
        }
        if (rejection == SelectedProcessEnrichedRejection::None &&
            !state.nativeObservationBuildSuccess)
        {
            rejection = SelectedProcessEnrichedRejection::
                NativeObservationBuildFailed;
        }
        if (rejection == SelectedProcessEnrichedRejection::None &&
            !state.refinementSuccess)
        {
            rejection =
                SelectedProcessEnrichedRejection::RefinementFailed;
        }
        if (rejection == SelectedProcessEnrichedRejection::None &&
            !state.correlationSuccess)
        {
            rejection =
                SelectedProcessEnrichedRejection::CorrelationFailed;
        }
        if (rejection == SelectedProcessEnrichedRejection::None &&
            !state.triageSuccess)
        {
            rejection = SelectedProcessEnrichedRejection::TriageFailed;
        }
        if (rejection == SelectedProcessEnrichedRejection::None &&
            !state.completenessSufficientForAuthority)
        {
            rejection = SelectedProcessEnrichedRejection::
                MaterialEvidenceIncomplete;
        }

        state.rejection = rejection;
        state.diagnostic = BoundedDiagnostic(candidate.diagnosticMessage);
        if (rejection == SelectedProcessEnrichedRejection::None)
        {
            state.publicationAccepted = true;
            state.storedSource = capturedSource;
            ++state.acceptedPublicationCount;
            return true;
        }

        ++state.rejectedPublicationCount;
        if (rejection ==
                SelectedProcessEnrichedRejection::ProcessGenerationMismatch ||
            rejection ==
                SelectedProcessEnrichedRejection::EvidenceGenerationMismatch ||
            rejection ==
                SelectedProcessEnrichedRejection::ScopeGenerationMismatch ||
            rejection == SelectedProcessEnrichedRejection::PidMismatch ||
            rejection == SelectedProcessEnrichedRejection::
                CreationTimeAvailabilityMismatch ||
            rejection ==
                SelectedProcessEnrichedRejection::CreationTimeMismatch ||
            rejection == SelectedProcessEnrichedRejection::ScopeMismatch)
        {
            QueueLatestAfterStaleBuild(state, currentSource);
        }
        return false;
    }

    bool SelectedProcessEnrichedPublicationMatches(
        const SelectedProcessEnrichedLifecycleState& state,
        const SelectedProcessEnrichedSourceStamp& currentSource)
    {
        return state.publicationAccepted &&
            state.storedSource == currentSource;
    }

    void ClearSelectedProcessEnrichedLifecycle(
        SelectedProcessEnrichedLifecycleState& state)
    {
        state = {};
    }
}
