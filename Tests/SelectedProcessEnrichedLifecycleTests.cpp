#include "Core/AuthoritativeTriage.h"
#include "Core/SelectedProcessEnrichedLifecycle.h"
#include "UI/InspectorPresentation.h"

#include <cstdint>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace GlassPane::Tests
{
    namespace
    {
        using namespace Core;

        int failureCount = 0;

        void Check(bool condition, const wchar_t* name)
        {
            if (!condition)
            {
                std::wcerr << L"FAILED: " << name << L'\n';
                ++failureCount;
            }
        }

        SelectedProcessEnrichedSourceStamp MakeStamp(
            std::uint32_t pid = 6100,
            std::uint64_t creationTime = 610000,
            std::uint64_t processGeneration = 7,
            std::uint64_t evidenceGeneration = 11,
            std::uint64_t scopeGeneration = 3,
            SelectedProcessAnalysisScope scope =
                SelectedProcessAnalysisScope::Live,
            bool hasCreationTime = true)
        {
            SelectedProcessEnrichedSourceStamp stamp;
            stamp.hasEntity = true;
            stamp.identity = { pid, hasCreationTime, creationTime };
            stamp.scope = scope;
            stamp.processGeneration = processGeneration;
            stamp.evidenceGeneration = evidenceGeneration;
            stamp.scopeGeneration = scopeGeneration;
            stamp.entityScope = scope == SelectedProcessAnalysisScope::Live
                ? "selected-process/live/pid:"
                : "selected-process/snapshot/pid:";
            stamp.entityScope += std::to_string(pid);
            stamp.entityScope += hasCreationTime
                ? "/created:" + std::to_string(creationTime)
                : "/creation:unavailable";
            return stamp;
        }

        enum class CandidateFixture
        {
            Empty,
            ContextOnly,
            CollectionNoteOnly,
            OptionalHandleMetadata
        };

        ObservationShadowState MakeCompletedCandidate(
            const SelectedProcessEnrichedSourceStamp& stamp,
            CandidateFixture fixture = CandidateFixture::Empty)
        {
            ObservationShadowSourceContext context;
            context.entityScope = stamp.entityScope;
            context.nativeInputSupplied = true;
            context.nativeInput.identity = stamp.identity;
            context.nativeInput.entityScope = stamp.entityScope;

            if (fixture == CandidateFixture::ContextOnly)
            {
                NativeMemoryObservationInput& memory =
                    context.nativeInput.memory;
                memory.identity = stamp.identity;
                memory.supplied = true;
                memory.collectionAttempted = true;
                memory.available = true;
                memory.collection.pid = stamp.identity.pid;
                memory.collection.success = true;
                MemoryRegionInfo region;
                region.baseAddress = 0x100000;
                region.allocationBase = 0x100000;
                region.regionSize = 0x4000;
                region.isWritable = true;
                region.isExecutable = true;
                region.isPrivate = true;
                memory.collection.regions.push_back(region);
            }
            else if (fixture == CandidateFixture::CollectionNoteOnly)
            {
                NativeCommandLineInput& commandLine =
                    context.nativeInput.commandLine;
                commandLine.identity = stamp.identity;
                commandLine.supplied = true;
                commandLine.collectionAttempted = true;
                commandLine.available = false;
                commandLine.source.sourceKind =
                    ObservationSourceKind::Unavailable;
                commandLine.source.completeness =
                    ObservationSourceCompleteness::Unavailable;
                commandLine.source.sourceIdentifier =
                    "test.command-line-unavailable";
                commandLine.source.collectionMethod = "fixture";
            }
            else if (fixture == CandidateFixture::OptionalHandleMetadata)
            {
                NativeHandleObservationInput& handles =
                    context.nativeInput.handles;
                handles.sourceIdentity = stamp.identity;
                handles.entityScope = stamp.entityScope;
                handles.supplied = true;
                handles.collectionAttempted = true;
                handles.collection.pid = stamp.identity.pid;
                handles.collection.state = HandleCollectionState::Partial;
                handles.collection.success = true;
                handles.collection.selectedProcessHandlesMatched = 1;
                handles.collection.selectedProcessHandlesOmitted = 0;
                handles.collection.namesSkipped = 1;
                handles.collection.typeResolutionsFailed = 1;
                handles.collection.targetsUnresolved = 1;
                handles.collection.typeOrTargetResolutionPartial = true;
                handles.collection.statusMessage =
                    L"Optional names and target metadata were unavailable.";
                HandleInfo row;
                row.owningPid = stamp.identity.pid;
                row.handleValue = 0x88;
                row.objectTypeIndex = 31;
                row.grantedAccessRaw = 0x00100000U;
                row.errorMessage = L"Object type and name unavailable.";
                handles.collection.handles.push_back(row);
                handles.source.sourceKind = ObservationSourceKind::Direct;
                handles.source.sourceIdentifier = "test.handles";
                handles.source.collectionMethod = "fixture";
                handles.limitations.push_back(
                    "Administrator privileges may improve optional handle metadata.");
            }

            ObservationShadowState candidate =
                BuildNativeObservationShadowState(
                    context,
                    true,
                    stamp.identity.pid,
                    stamp.identity.hasCreationTime
                        ? stamp.identity.creationTimeFileTime
                        : 0,
                    stamp.evidenceGeneration);
            TryRefineObservationShadowState(candidate);
            TryActivateObservationShadowCorrelations(candidate);
            TryBuildObservationShadowTriage(candidate);
            return candidate;
        }

        bool PublishCandidate(
            SelectedProcessEnrichedLifecycleState& state,
            const SelectedProcessEnrichedSourceStamp& stamp,
            const ObservationShadowState& candidate,
            SelectedProcessEnrichedRebuildReason reason =
                SelectedProcessEnrichedRebuildReason::SelectionChanged)
        {
            RequestSelectedProcessEnrichedRebuild(state, stamp, reason);
            SelectedProcessEnrichedSourceStamp captured;
            if (!TryBeginSelectedProcessEnrichedBuild(state, captured))
            {
                return false;
            }
            return CompleteSelectedProcessEnrichedBuild(
                state,
                captured,
                stamp,
                candidate,
                100,
                25);
        }

        ProcessInfo MakeProcess(
            const SelectedProcessEnrichedSourceStamp& stamp)
        {
            ProcessInfo process;
            process.pid = stamp.identity.pid;
            process.hasCreationTime = stamp.identity.hasCreationTime;
            process.creationTimeFileTime =
                stamp.identity.creationTimeFileTime;
            process.name = L"ordinary-process.exe";
            process.executablePath = L"C:\\Program Files\\Ordinary\\ordinary-process.exe";
            process.commandLine = process.executablePath;
            process.commandLineAccessible = true;
            return process;
        }

        ProcessTriageCacheSourceStamp MakeBaselineStamp()
        {
            ProcessTriageCacheSourceStamp stamp;
            stamp.processGeneration = 7;
            stamp.evidenceGeneration = 11;
            stamp.scopeGeneration = 3;
            return stamp;
        }

        ProcessTriageCache MakeBaselineCache(const ProcessInfo& process)
        {
            ProcessSnapshot snapshot;
            snapshot.processes.push_back(process);
            ProcessTriageCacheBuildOptions options;
            options.sourceStamp = MakeBaselineStamp();
            return BuildProcessTriageCache(
                snapshot,
                std::vector<BaselineObservationContext>{},
                options);
        }

        void TestSelectionLifecycle()
        {
            const SelectedProcessEnrichedSourceStamp stamp = MakeStamp();
            SelectedProcessEnrichedLifecycleState state;
            Check(RequestSelectedProcessEnrichedRebuild(
                    state,
                    stamp,
                    SelectedProcessEnrichedRebuildReason::SelectionChanged) &&
                    state.buildPending && state.requestGeneration == 1,
                L"1 selecting an ordinary live process schedules one enriched build");

            const UI::EnrichedAnalysisPresentationPlan pending =
                UI::PlanEnrichedAnalysisPresentation(false, true, false, false);
            Check(pending.state ==
                    UI::EnrichedAnalysisPresentationState::Pending &&
                    std::string_view(pending.message) ==
                        UI::EnrichedAnalysisPendingMessage,
                L"2 baseline is shown while enriched analysis is pending");

            SelectedProcessEnrichedSourceStamp captured;
            Check(TryBeginSelectedProcessEnrichedBuild(state, captured),
                L"selection request begins exactly once");
            const ObservationShadowState contextOnly =
                MakeCompletedCandidate(stamp, CandidateFixture::ContextOnly);
            Check(CompleteSelectedProcessEnrichedBuild(
                    state, captured, stamp, contextOnly, 100, 25) &&
                    contextOnly.triage.verdict == TriageVerdict::Informational,
                L"3 ordinary context-only process becomes enriched informational");

            SelectedProcessEnrichedLifecycleState emptyState;
            const ObservationShadowState empty = MakeCompletedCandidate(stamp);
            Check(empty.inventory.records.empty() &&
                    PublishCandidate(emptyState, stamp, empty),
                L"4 zero native source-evidence cards still becomes enriched");
            Check(empty.correlation.correlations.empty() &&
                    emptyState.publicationAccepted,
                L"5 zero correlations still becomes enriched");

            SelectedProcessEnrichedLifecycleState notesState;
            const ObservationShadowState notes = MakeCompletedCandidate(
                stamp,
                CandidateFixture::CollectionNoteOnly);
            Check(notes.decisionSummary.collectionNoteCount != 0 &&
                    PublishCandidate(notesState, stamp, notes),
                L"6 collection-note-only evidence still becomes enriched");

            SelectedProcessEnrichedLifecycleState duplicateState;
            Check(RequestSelectedProcessEnrichedRebuild(
                    duplicateState,
                    stamp,
                    SelectedProcessEnrichedRebuildReason::SelectionChanged),
                L"duplicate fixture schedules its initial build");
            Check(!RequestSelectedProcessEnrichedRebuild(
                    duplicateState,
                    stamp,
                    SelectedProcessEnrichedRebuildReason::SelectionChanged),
                L"7 same exact selection does not reschedule while pending");
            SelectedProcessEnrichedSourceStamp duplicateCaptured;
            Check(TryBeginSelectedProcessEnrichedBuild(
                    duplicateState, duplicateCaptured) &&
                    !RequestSelectedProcessEnrichedRebuild(
                        duplicateState,
                        stamp,
                        SelectedProcessEnrichedRebuildReason::SelectionChanged),
                L"same exact selection does not duplicate an active build");
            CompleteSelectedProcessEnrichedBuild(
                duplicateState,
                duplicateCaptured,
                stamp,
                empty,
                100,
                25);
            Check(!RequestSelectedProcessEnrichedRebuild(
                    duplicateState,
                    stamp,
                    SelectedProcessEnrichedRebuildReason::SelectionChanged) &&
                    duplicateState.buildInvocationCount == 1,
                L"same exact accepted selection does not rebuild every frame");

            SelectedProcessEnrichedSourceStamp replacement =
                MakeStamp(6200, 620000);
            Check(RequestSelectedProcessEnrichedRebuild(
                    duplicateState,
                    replacement,
                    SelectedProcessEnrichedRebuildReason::SelectionChanged) &&
                    duplicateState.selectionGeneration == 2 &&
                    duplicateState.buildPending,
                L"8 a new exact process identity schedules a new build");
        }

        void TestGenerationValidationAndRecovery()
        {
            const SelectedProcessEnrichedSourceStamp stamp = MakeStamp();
            const ObservationShadowState candidate =
                MakeCompletedCandidate(stamp);
            SelectedProcessEnrichedLifecycleState stable;
            Check(PublishCandidate(stable, stamp, candidate) &&
                    SelectedProcessEnrichedPublicationMatches(stable, stamp),
                L"9 stable evidence generation accepts publication");

            SelectedProcessEnrichedLifecycleState raced;
            RequestSelectedProcessEnrichedRebuild(
                raced,
                stamp,
                SelectedProcessEnrichedRebuildReason::SelectionChanged);
            SelectedProcessEnrichedSourceStamp captured;
            TryBeginSelectedProcessEnrichedBuild(raced, captured);
            SelectedProcessEnrichedSourceStamp latest = stamp;
            ++latest.evidenceGeneration;
            const ObservationShadowState staleCandidate =
                MakeCompletedCandidate(stamp);
            Check(!CompleteSelectedProcessEnrichedBuild(
                    raced,
                    captured,
                    latest,
                    staleCandidate,
                    100,
                    25) &&
                    raced.rejection ==
                        SelectedProcessEnrichedRejection::EvidenceGenerationMismatch,
                L"10 evidence generation change rejects the stale result");
            Check(raced.buildPending &&
                    raced.lastRequestReason ==
                        SelectedProcessEnrichedRebuildReason::GenerationChangedDuringBuild,
                L"11 the latest generation automatically queues one rebuild");
            SelectedProcessEnrichedSourceStamp latestCaptured;
            Check(TryBeginSelectedProcessEnrichedBuild(
                    raced, latestCaptured) && latestCaptured == latest,
                L"latest queued rebuild captures coherent current values");
            const ObservationShadowState latestCandidate =
                MakeCompletedCandidate(latest);
            Check(CompleteSelectedProcessEnrichedBuild(
                    raced,
                    latestCaptured,
                    latest,
                    latestCandidate,
                    101,
                    26) &&
                    !raced.buildPending &&
                    raced.buildInvocationCount == 2 &&
                    SelectedProcessEnrichedPublicationMatches(raced, latest),
                L"12 generation race recovers without permanent baseline or a loop");

            auto RejectionFor = [&](SelectedProcessEnrichedSourceStamp current)
            {
                SelectedProcessEnrichedLifecycleState local;
                RequestSelectedProcessEnrichedRebuild(
                    local,
                    stamp,
                    SelectedProcessEnrichedRebuildReason::SelectionChanged);
                SelectedProcessEnrichedSourceStamp localCaptured;
                TryBeginSelectedProcessEnrichedBuild(local, localCaptured);
                CompleteSelectedProcessEnrichedBuild(
                    local,
                    localCaptured,
                    current,
                    candidate,
                    100,
                    25);
                return local.rejection;
            };

            SelectedProcessEnrichedSourceStamp processMismatch = stamp;
            ++processMismatch.processGeneration;
            Check(RejectionFor(processMismatch) ==
                    SelectedProcessEnrichedRejection::ProcessGenerationMismatch,
                L"13 process generation mismatch is rejected");

            SelectedProcessEnrichedSourceStamp scopeMismatch = stamp;
            scopeMismatch.entityScope += "/different-scope";
            Check(RejectionFor(scopeMismatch) ==
                    SelectedProcessEnrichedRejection::ScopeMismatch,
                L"14 scope mismatch is rejected");

            ObservationShadowState wrongPid = candidate;
            ++wrongPid.selectedPid;
            SelectedProcessEnrichedLifecycleState pidState;
            RequestSelectedProcessEnrichedRebuild(
                pidState,
                stamp,
                SelectedProcessEnrichedRebuildReason::SelectionChanged);
            SelectedProcessEnrichedSourceStamp pidCaptured;
            TryBeginSelectedProcessEnrichedBuild(pidState, pidCaptured);
            Check(!CompleteSelectedProcessEnrichedBuild(
                    pidState,
                    pidCaptured,
                    stamp,
                    wrongPid,
                    100,
                    25) &&
                    pidState.rejection ==
                        SelectedProcessEnrichedRejection::PidMismatch,
                L"15 PID identity mismatch cannot publish across PID reuse");

            SelectedProcessEnrichedSourceStamp reusedPid = stamp;
            ++reusedPid.identity.creationTimeFileTime;
            Check(RejectionFor(reusedPid) ==
                    SelectedProcessEnrichedRejection::CreationTimeMismatch,
                L"16 creation-time mismatch rejects a reused PID");

            SelectedProcessEnrichedSourceStamp missingCreation = stamp;
            missingCreation.identity.hasCreationTime = false;
            missingCreation.identity.creationTimeFileTime = 0;
            missingCreation.entityScope =
                "selected-process/live/pid:6100/creation:unavailable";
            Check(RejectionFor(missingCreation) ==
                    SelectedProcessEnrichedRejection::
                        CreationTimeAvailabilityMismatch,
                L"creation-time availability mismatch is typed and rejected");
        }

        void TestDomainRefreshCoalescing()
        {
            const SelectedProcessEnrichedSourceStamp initial = MakeStamp();
            SelectedProcessEnrichedLifecycleState state;
            PublishCandidate(state, initial, MakeCompletedCandidate(initial));

            const struct RefreshCase
            {
                SelectedProcessEnrichedRebuildReason reason;
                const wchar_t* name;
            } cases[] = {
                { SelectedProcessEnrichedRebuildReason::HandlesChanged,
                    L"17 handle refresh republishes enriched" },
                { SelectedProcessEnrichedRebuildReason::MemoryChanged,
                    L"18 memory refresh republishes enriched" },
                { SelectedProcessEnrichedRebuildReason::ModulesChanged,
                    L"19 module refresh republishes enriched" },
                { SelectedProcessEnrichedRebuildReason::RuntimeChanged,
                    L"20 runtime refresh republishes enriched" },
                { SelectedProcessEnrichedRebuildReason::TokenChanged,
                    L"21 token refresh republishes enriched" },
                { SelectedProcessEnrichedRebuildReason::NetworkChanged,
                    L"network refresh republishes enriched" }
            };

            SelectedProcessEnrichedSourceStamp current = initial;
            for (const RefreshCase& refresh : cases)
            {
                ++current.evidenceGeneration;
                const bool requested = RequestSelectedProcessEnrichedRebuild(
                    state,
                    current,
                    refresh.reason);
                SelectedProcessEnrichedSourceStamp captured;
                const bool began = TryBeginSelectedProcessEnrichedBuild(
                    state, captured);
                const bool accepted = began &&
                    CompleteSelectedProcessEnrichedBuild(
                        state,
                        captured,
                        current,
                        MakeCompletedCandidate(current),
                        100,
                        25);
                Check(requested && accepted &&
                        SelectedProcessEnrichedPublicationMatches(state, current),
                    refresh.name);
            }

            SelectedProcessEnrichedLifecycleState coalesced;
            SelectedProcessEnrichedSourceStamp modules = initial;
            ++modules.evidenceGeneration;
            SelectedProcessEnrichedSourceStamp memory = modules;
            ++memory.evidenceGeneration;
            SelectedProcessEnrichedSourceStamp handles = memory;
            ++handles.evidenceGeneration;
            RequestSelectedProcessEnrichedRebuild(
                coalesced,
                modules,
                SelectedProcessEnrichedRebuildReason::ModulesChanged);
            RequestSelectedProcessEnrichedRebuild(
                coalesced,
                memory,
                SelectedProcessEnrichedRebuildReason::MemoryChanged);
            RequestSelectedProcessEnrichedRebuild(
                coalesced,
                handles,
                SelectedProcessEnrichedRebuildReason::HandlesChanged);
            SelectedProcessEnrichedSourceStamp coalescedCaptured;
            const bool coalescedBegin = TryBeginSelectedProcessEnrichedBuild(
                coalesced,
                coalescedCaptured);
            Check(coalescedBegin && coalescedCaptured == handles &&
                    coalesced.buildInvocationCount == 1,
                L"22 multiple domain completions coalesce into one latest build");

            SelectedProcessEnrichedLifecycleState renderIndependent;
            RequestSelectedProcessEnrichedRebuild(
                renderIndependent,
                initial,
                SelectedProcessEnrichedRebuildReason::SelectionChanged);
            Check(renderIndependent.buildInvocationCount == 0 &&
                    renderIndependent.buildPending,
                L"23 requesting and rendering state do not execute a build");
        }

        void TestOptionalAndMaterialEvidence()
        {
            const SelectedProcessEnrichedSourceStamp stamp = MakeStamp();
            const ObservationShadowState optionalHandles =
                MakeCompletedCandidate(
                    stamp,
                    CandidateFixture::OptionalHandleMetadata);
            SelectedProcessEnrichedLifecycleState handleState;
            Check(optionalHandles.nativeObservations.omittedFactCount == 0 &&
                    PublishCandidate(handleState, stamp, optionalHandles),
                L"24 retained handle core rows with unresolved names publish enriched");

            const ObservationShadowState optionalUnavailable =
                MakeCompletedCandidate(
                    stamp,
                    CandidateFixture::CollectionNoteOnly);
            SelectedProcessEnrichedLifecycleState unavailableState;
            Check(PublishCandidate(
                    unavailableState,
                    stamp,
                    optionalUnavailable),
                L"25 an optional unavailable collector still publishes enriched");

            ObservationShadowState optionalTruncation =
                MakeCompletedCandidate(stamp);
            optionalTruncation.nativeObservations.truncated = true;
            optionalTruncation.nativeObservations.omittedFactCount = 0;
            optionalTruncation.decisionSummary.
                nativeMaterialEvidenceTruncated = false;
            SelectedProcessEnrichedLifecycleState truncationState;
            const bool optionalAccepted = PublishCandidate(
                truncationState,
                stamp,
                optionalTruncation);
            const AuthoritativeTriageView optionalAuthority =
                SelectNativeAuthoritativeTriage(
                    optionalTruncation,
                    true,
                    stamp.identity.pid,
                    stamp.identity.creationTimeFileTime,
                    stamp.evidenceGeneration,
                    stamp.entityScope);
            Check(optionalAccepted && optionalAuthority.UsesTriageEngine(),
                L"26 optional metadata truncation still publishes enriched authority");

            ObservationShadowState materialOmission =
                MakeCompletedCandidate(stamp);
            materialOmission.nativeObservations.truncated = true;
            materialOmission.nativeObservations.omittedFactCount = 1;
            materialOmission.decisionSummary.
                nativeMaterialEvidenceTruncated = true;
            SelectedProcessEnrichedLifecycleState materialState;
            Check(!PublishCandidate(materialState, stamp, materialOmission) &&
                    materialState.rejection ==
                        SelectedProcessEnrichedRejection::
                            MaterialEvidenceIncomplete,
                L"27 omitted material evidence blocks enriched authority");

            ObservationShadowSourceContext failureContext;
            failureContext.entityScope = stamp.entityScope;
            const ObservationShadowState failure =
                MakeFailedObservationShadowState(
                    failureContext,
                    true,
                    stamp.identity.pid,
                    stamp.identity.creationTimeFileTime,
                    stamp.evidenceGeneration,
                    "Material native producer failed.");
            const ProcessInfo process = MakeProcess(stamp);
            const ProcessTriageCache baseline = MakeBaselineCache(process);
            const SelectedProcessTriageAuthority authority =
                SelectNativeSelectedProcessTriageAuthority(
                    failure,
                    true,
                    process,
                    stamp.evidenceGeneration,
                    stamp.entityScope,
                    baseline,
                    MakeBaselineStamp());
            Check(authority.UsesBaselineTriage() &&
                    authority.analysisLevel ==
                        SelectedTriageAnalysisLevel::Baseline,
                L"28 material enriched failure falls back to valid native baseline");
        }

        void TestSnapshotIsolationAndReleasePresentation()
        {
            const SelectedProcessEnrichedSourceStamp snapshot = MakeStamp(
                6100,
                610000,
                7,
                11,
                4,
                SelectedProcessAnalysisScope::LoadedSnapshot);
            SelectedProcessEnrichedLifecycleState snapshotState;
            SelectedProcessEnrichedSourceStamp captured;
            Check(!RequestSelectedProcessEnrichedRebuild(
                    snapshotState,
                    snapshot,
                    SelectedProcessEnrichedRebuildReason::SelectionChanged) &&
                    !TryBeginSelectedProcessEnrichedBuild(
                        snapshotState, captured) &&
                    snapshotState.buildInvocationCount == 0,
                L"29 loaded schema-5 scope performs zero live collection or build");

            const ProcessInfo process = MakeProcess(snapshot);
            const PersistedTriageContext oldSnapshot;
            const SelectedProcessTriageAuthority oldAuthority =
                SelectCapturedSelectedProcessTriageAuthority(
                    oldSnapshot,
                    true,
                    process);
            Check(oldAuthority.notCaptured &&
                    oldAuthority.analysisLevel ==
                        SelectedTriageAnalysisLevel::NotCaptured &&
                    !oldAuthority.enrichedAvailable,
                L"30 schemas 1-4 not-captured state stays honest");

            SelectedProcessEnrichedSourceStamp live = MakeStamp();
            Check(RequestSelectedProcessEnrichedRebuild(
                    snapshotState,
                    live,
                    SelectedProcessEnrichedRebuildReason::ReturnToLive) &&
                    snapshotState.buildPending,
                L"31 return to live schedules enriched analysis again");

            SelectedProcessEnrichedLifecycleState preserved;
            PublishCandidate(
                preserved,
                live,
                MakeCompletedCandidate(live));
            const SelectedProcessEnrichedLifecycleState beforeFailedLoad =
                preserved;
            Check(SelectedProcessEnrichedPublicationMatches(
                    preserved,
                    live) &&
                    preserved.acceptedPublicationCount ==
                        beforeFailedLoad.acceptedPublicationCount,
                L"32 failed snapshot load leaves current enriched state untouched");

            std::string releaseText = UI::AnalysisLevelBaselineText;
            releaseText += UI::AnalysisLevelEnrichedText;
            releaseText += UI::AnalysisLevelUnavailableText;
            releaseText += UI::EnrichedAnalysisPendingMessage;
            releaseText += UI::EnrichedAnalysisRefreshingMessage;
            releaseText += UI::EnrichedAnalysisFailedMessage;
            releaseText += UI::AuthoritativeTriageUnavailableMessage;
            Check(releaseText.find("generation") == std::string::npos &&
                    releaseText.find("rejection") == std::string::npos &&
                    releaseText.find("Selected Enriched Lifecycle (Debug)") ==
                        std::string::npos,
                L"37 normal Release presentation contains no lifecycle internals");
        }
    }

    int RunSelectedProcessEnrichedLifecycleTests()
    {
        failureCount = 0;
        TestSelectionLifecycle();
        TestGenerationValidationAndRecovery();
        TestDomainRefreshCoalescing();
        TestOptionalAndMaterialEvidence();
        TestSnapshotIsolationAndReleasePresentation();
        if (failureCount == 0)
        {
            std::wcout <<
                L"Selected-process enriched lifecycle tests passed.\n";
        }
        return failureCount;
    }
}
