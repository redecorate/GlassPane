#pragma once

#include "ObservationShadow.h"
#include "ProcessTriageCache.h"

#include <cstddef>
#include <cstdint>
#include <string>

namespace GlassPane::Core
{
    constexpr std::size_t SelectedProcessEnrichedLifecycleDiagnosticMaxCharacters = 1024;

    enum class SelectedProcessAnalysisScope : std::uint32_t
    {
        Live = 0,
        LoadedSnapshot = 1
    };

    enum class SelectedProcessEnrichedRebuildReason : std::uint32_t
    {
        None = 0,
        SelectionChanged = 1,
        ProcessSnapshotChanged = 2,
        FileIdentityChanged = 3,
        ChainChanged = 4,
        ModulesChanged = 5,
        MemoryChanged = 6,
        HandlesChanged = 7,
        TokenChanged = 8,
        RuntimeChanged = 9,
        NetworkChanged = 10,
        ServiceAssociationChanged = 11,
        ExactIndicatorMatchesChanged = 12,
        CollectionStateChanged = 13,
        AllSelectedEvidenceChanged = 14,
        ReturnToLive = 15,
        GenerationChangedDuringBuild = 16
    };

    // Publication failures remain typed so Debug presentation never has to
    // parse diagnostics. These categories are not persisted or exported.
    enum class SelectedProcessEnrichedRejection : std::uint32_t
    {
        None = 0,
        NoSelectedEntity = 1,
        LoadedSnapshotScope = 2,
        PidMismatch = 3,
        CreationTimeAvailabilityMismatch = 4,
        CreationTimeMismatch = 5,
        ProcessGenerationMismatch = 6,
        EvidenceGenerationMismatch = 7,
        ScopeGenerationMismatch = 8,
        ScopeMismatch = 9,
        NativeObservationBuildFailed = 10,
        RefinementFailed = 11,
        CorrelationFailed = 12,
        TriageFailed = 13,
        MaterialEvidenceIncomplete = 14,
        InvalidResult = 15
    };

    struct SelectedProcessEnrichedSourceStamp
    {
        bool hasEntity = false;
        ProcessIdentityKey identity;
        SelectedProcessAnalysisScope scope = SelectedProcessAnalysisScope::Live;
        std::uint64_t processGeneration = 0;
        std::uint64_t evidenceGeneration = 0;
        std::uint64_t scopeGeneration = 0;
        std::string entityScope;
    };

    bool operator==(
        const SelectedProcessEnrichedSourceStamp& left,
        const SelectedProcessEnrichedSourceStamp& right);
    bool operator!=(
        const SelectedProcessEnrichedSourceStamp& left,
        const SelectedProcessEnrichedSourceStamp& right);

    struct SelectedProcessEnrichedLifecycleState
    {
        SelectedProcessEnrichedSourceStamp currentSource;
        SelectedProcessEnrichedSourceStamp requestedSource;
        SelectedProcessEnrichedSourceStamp activeBuildSource;
        SelectedProcessEnrichedSourceStamp storedSource;

        std::uint64_t selectionGeneration = 0;
        std::uint64_t requestGeneration = 0;
        std::uint64_t buildInvocationCount = 0;
        std::uint64_t acceptedPublicationCount = 0;
        std::uint64_t rejectedPublicationCount = 0;

        bool buildRequested = false;
        bool buildPending = false;
        bool buildInProgress = false;
        bool buildStarted = false;
        bool buildCompleted = false;

        bool nativeObservationBuildSuccess = false;
        bool refinementSuccess = false;
        bool correlationSuccess = false;
        bool triageSuccess = false;
        bool completenessSufficientForAuthority = false;

        bool publicationAttempted = false;
        bool publicationAccepted = false;
        SelectedProcessEnrichedRebuildReason lastRequestReason =
            SelectedProcessEnrichedRebuildReason::None;
        SelectedProcessEnrichedRejection rejection =
            SelectedProcessEnrichedRejection::None;
        std::string diagnostic;
        std::uint64_t completionTimestampMilliseconds = 0;
        std::uint64_t completionDurationMicroseconds = 0;
    };

    // Returns true only for an exact selected-entity or live/snapshot scope
    // change. Source-generation changes are handled by rebuild requests and do
    // not inflate the selection generation.
    bool UpdateSelectedProcessEnrichedSelection(
        SelectedProcessEnrichedLifecycleState& state,
        const SelectedProcessEnrichedSourceStamp& currentSource);

    // Coalesces updates to the latest source stamp. A current accepted result,
    // a duplicate pending request, and a duplicate active build are no-ops.
    bool RequestSelectedProcessEnrichedRebuild(
        SelectedProcessEnrichedLifecycleState& state,
        const SelectedProcessEnrichedSourceStamp& currentSource,
        SelectedProcessEnrichedRebuildReason reason);

    // Begins at most one pending build and captures all publication inputs by
    // value. Loaded snapshots can never begin a live build.
    bool TryBeginSelectedProcessEnrichedBuild(
        SelectedProcessEnrichedLifecycleState& state,
        SelectedProcessEnrichedSourceStamp& capturedSource);

    // Validates an already-built value against both its captured source and the
    // latest source. A stale build is rejected and exactly one latest rebuild
    // remains pending. Optional metadata truncation is authoritative; only
    // omitted verdict-material facts fail completeness.
    bool CompleteSelectedProcessEnrichedBuild(
        SelectedProcessEnrichedLifecycleState& state,
        const SelectedProcessEnrichedSourceStamp& capturedSource,
        const SelectedProcessEnrichedSourceStamp& currentSource,
        const ObservationShadowState& candidate,
        std::uint64_t completionTimestampMilliseconds,
        std::uint64_t completionDurationMicroseconds);

    bool SelectedProcessEnrichedPublicationMatches(
        const SelectedProcessEnrichedLifecycleState& state,
        const SelectedProcessEnrichedSourceStamp& currentSource);

    void ClearSelectedProcessEnrichedLifecycle(
        SelectedProcessEnrichedLifecycleState& state);
}
