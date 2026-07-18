#include "Core/NativeObservationBuilder.h"
#include "Core/ObservationCorrelation.h"
#include "Core/ObservationRefinement.h"
#include "Core/TriageEngine.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <string>

namespace GlassPane::Tests
{
    namespace
    {
        using namespace GlassPane::Core;

        int failureCount = 0;

        void Check(bool condition, const wchar_t* name)
        {
            if (!condition)
            {
                std::wcerr << L"FAILED: " << name << L'\n';
                ++failureCount;
            }
        }

        template <typename Value>
        void CheckEqual(
            const Value& actual,
            const Value& expected,
            const wchar_t* name)
        {
            Check(actual == expected, name);
        }

        ProcessIdentityKey Identity(
            std::uint32_t pid,
            std::uint64_t created)
        {
            ProcessIdentityKey identity;
            identity.pid = pid;
            identity.hasCreationTime = true;
            identity.creationTimeFileTime = created;
            return identity;
        }

        NativeSelectedProcessObservationInput EmptyInput()
        {
            NativeSelectedProcessObservationInput input;
            input.identity = Identity(8100, 81000);
            input.entityScope =
                "selected-process/live/pid:8100/created:81000";
            return input;
        }

        void AddToken(
            NativeSelectedProcessObservationInput& input,
            bool debugEnabled)
        {
            input.token.identity = input.identity;
            input.token.entityScope = input.entityScope;
            input.token.supplied = true;
            input.token.collectionAttempted = true;
            input.token.token.success = true;
            input.token.token.integrityRid = 0x00003000U;
            input.token.token.integrityLevelName = L"High";
            input.token.token.isElevated = true;
            input.token.token.privileges.push_back({
                L"SeDebugPrivilege",
                L"Debug programs",
                debugEnabled,
                false,
                false,
                false
            });
            input.token.source.sourceKind = ObservationSourceKind::Direct;
            input.token.source.sourceIdentifier = "test.token";
            input.token.source.collectionMethod = "fixture";
        }

        void AddSensitiveHandle(
            NativeSelectedProcessObservationInput& input,
            bool duplicate)
        {
            input.handles.sourceIdentity = input.identity;
            input.handles.entityScope = input.entityScope;
            input.handles.supplied = true;
            input.handles.collectionAttempted = true;
            input.handles.collection.pid = input.identity.pid;
            input.handles.collection.success = true;
            input.handles.source.sourceKind =
                ObservationSourceKind::Direct;
            input.handles.source.sourceIdentifier = "test.handles";
            input.handles.source.collectionMethod = "fixture";

            HandleInfo handle;
            handle.owningPid = input.identity.pid;
            handle.handleValue = 0x58U;
            handle.objectType = L"Process";
            handle.typeResolved = true;
            handle.targetPid = 8200;
            handle.grantedAccessRaw = 0x0020U | 0x0008U | 0x0002U;
            input.handles.collection.handles.push_back(handle);
            if (duplicate)
            {
                input.handles.collection.handles.push_back(handle);
            }

            NativeHandleTargetIdentity target;
            target.handleValue = handle.handleValue;
            target.objectKind = NativeHandleObjectKind::Process;
            target.targetPid = handle.targetPid.value();
            target.identityResolved = true;
            target.identity = Identity(8200, 82000);
            input.handles.targetIdentities.push_back(target);
        }

        TriageResult CompleteTriage(
            const NativeObservationBuildResult& native,
            ObservationCorrelationResult* correlations = nullptr)
        {
            if (!native.Succeeded())
            {
                return {};
            }
            const ObservationRefinementResult refined =
                RefineObservationInventory(native.inventory);
            if (!refined.Succeeded())
            {
                return {};
            }
            ObservationCorrelationResult activated =
                ActivateObservationCorrelations(refined);
            if (correlations != nullptr)
            {
                *correlations = activated;
            }
            if (!activated.Succeeded())
            {
                return {};
            }
            return BuildTriageResult(refined, activated);
        }

        void TestContextOnlyNativeDomainsRemainInformational()
        {
            NativeSelectedProcessObservationInput input = EmptyInput();
            AddToken(input, false);

            input.runtime.identity = input.identity;
            input.runtime.entityScope = input.entityScope;
            input.runtime.supplied = true;
            input.runtime.collectionAttempted = true;
            input.runtime.available = true;
            input.runtime.declaredThreadCount = 200;
            input.runtime.declaredHandleCount = 4000;
            input.runtime.source.sourceKind = ObservationSourceKind::Direct;
            input.runtime.source.sourceIdentifier = "test.runtime";
            input.runtime.source.collectionMethod = "fixture";

            NativeRuntimeThreadInput thread;
            thread.threadId = 9100;
            thread.ownerProcessId = input.identity.pid;
            thread.ownerIdentityKnown = true;
            thread.ownerMatchesSelectedProcess = true;
            thread.startAddressAvailable = true;
            thread.startAddress = 0x100000U;
            thread.startKind =
                NativeRuntimeThreadStartKind::PrivateExecutableMetadata;
            thread.state = NativeRuntimeThreadState::Suspended;
            thread.source = input.runtime.source;
            input.runtime.threads.push_back(thread);

            input.priority.identity = input.identity;
            input.priority.entityScope = input.entityScope;
            input.priority.supplied = true;
            input.priority.collectionAttempted = true;
            input.priority.available = true;
            input.priority.priorityClass =
                NativeProcessPriorityClass::Realtime;
            input.priority.rawPriorityClass = 0x00000100U;
            input.priority.source = input.runtime.source;

            const NativeObservationBuildResult native =
                BuildNativeSelectedProcessObservations(input);
            Check(native.Succeeded(),
                L"context-only native multi-producer build succeeds");
            Check(native.tokenFactCount != 0 &&
                    native.runtimeFactCount != 0 &&
                    native.priorityFactCount != 0,
                L"token runtime and priority producers are composed");
            const TriageResult triage = CompleteTriage(native);
            Check(triage.Succeeded(),
                L"context-only native triage completes");
            CheckEqual(
                triage.verdict,
                TriageVerdict::Informational,
                L"high integrity counts static runtime and realtime priority stay informational");
            Check(triage.contributingDomains.empty(),
                L"context-only native domains do not contribute");
        }

        void TestDebugPrivilegeSensitiveAccessCorrelation()
        {
            NativeSelectedProcessObservationInput input = EmptyInput();
            AddToken(input, true);
            AddSensitiveHandle(input, true);

            const NativeObservationBuildResult native =
                BuildNativeSelectedProcessObservations(input);
            Check(native.Succeeded(),
                L"token and handle native composition succeeds");
            CheckEqual(native.handleFactCount, std::size_t(1),
                L"one handle with many access bits and duplicate rows is one evidence artifact");
            CheckEqual(native.handleDuplicateRowCount, std::size_t(1),
                L"duplicate handle row is retained diagnostically");

            ObservationCorrelationResult correlations;
            const TriageResult triage =
                CompleteTriage(native, &correlations);
            Check(correlations.Succeeded(),
                L"native token handle correlation pass succeeds");
            const auto completed = std::find_if(
                correlations.correlations.begin(),
                correlations.correlations.end(),
                [](const ObservationCorrelation& correlation)
                {
                    return correlation.ruleId ==
                        "correlation.access.enabled-debug-privilege";
                });
            Check(completed != correlations.correlations.end(),
                L"enabled debug privilege and sensitive access complete typed correlation");
            if (completed != correlations.correlations.end())
            {
                CheckEqual(
                    completed->participatingDomains.size(),
                    std::size_t(2),
                    L"token access correlation retains two independent domains");
                CheckEqual(
                    completed->participatingObservationIds.size(),
                    std::size_t(2),
                    L"token access correlation retains exact participants");
            }
            Check(triage.Succeeded(),
                L"native token handle correlated triage succeeds");
            CheckEqual(
                triage.verdict,
                TriageVerdict::MediumAttention,
                L"typed sensitive access correlation remains conservative");
        }

        void TestDebugPrivilegeWithoutAccessDoesNotContribute()
        {
            NativeSelectedProcessObservationInput input = EmptyInput();
            AddToken(input, true);
            const NativeObservationBuildResult native =
                BuildNativeSelectedProcessObservations(input);
            const TriageResult triage = CompleteTriage(native);
            Check(triage.Succeeded(),
                L"debug privilege without partner is a valid triage result");
            CheckEqual(
                triage.verdict,
                TriageVerdict::Informational,
                L"enabled debug privilege alone remains informational");
        }

        void TestExplicitRuntimeRelationshipSensitiveAccessCorrelation()
        {
            NativeSelectedProcessObservationInput input = EmptyInput();
            AddSensitiveHandle(input, false);

            input.runtime.identity = input.identity;
            input.runtime.entityScope = input.entityScope;
            input.runtime.supplied = true;
            input.runtime.collectionAttempted = true;
            input.runtime.available = true;
            input.runtime.source.sourceKind = ObservationSourceKind::Direct;
            input.runtime.source.sourceIdentifier = "test.runtime";
            input.runtime.source.collectionMethod = "fixture";

            NativeRuntimeRelationshipInput relationship;
            relationship.selectedIdentity = input.identity;
            relationship.sourceIdentity = input.identity;
            relationship.targetIdentity = Identity(8200, 82000);
            relationship.sourceThreadId = 9300;
            relationship.targetThreadId = 9400;
            relationship.kind =
                NativeRuntimeRelationshipKind::CrossProcessThreadCreation;
            relationship.verified = true;
            relationship.sourceRuleId =
                "fixture.runtime.cross-process-thread-creation";
            relationship.source = input.runtime.source;
            input.runtime.relationships.push_back(relationship);

            const NativeObservationBuildResult native =
                BuildNativeSelectedProcessObservations(input);
            Check(native.Succeeded(),
                L"explicit runtime relationship composition succeeds");

            ObservationCorrelationResult correlations;
            const TriageResult triage =
                CompleteTriage(native, &correlations);
            const auto completed = std::find_if(
                correlations.correlations.begin(),
                correlations.correlations.end(),
                [](const ObservationCorrelation& correlation)
                {
                    return correlation.ruleId ==
                        "correlation.runtime.explicit-relationship-sensitive-access";
                });
            Check(completed != correlations.correlations.end(),
                L"verified runtime relationship and sensitive access complete typed correlation");
            if (completed != correlations.correlations.end())
            {
                CheckEqual(
                    completed->participatingDomains.size(),
                    std::size_t(2),
                    L"runtime access correlation requires independent domains");
            }
            Check(triage.Succeeded(),
                L"runtime access correlated triage succeeds");
            CheckEqual(
                triage.verdict,
                TriageVerdict::MediumAttention,
                L"runtime access correlation remains at the conservative medium level");

            input.runtime.relationships.front().targetIdentity =
                Identity(8300, 83000);
            const NativeObservationBuildResult mismatchedNative =
                BuildNativeSelectedProcessObservations(input);
            Check(mismatchedNative.Succeeded(),
                L"mismatched runtime and handle targets remain valid evidence");
            ObservationCorrelationResult mismatchedCorrelations;
            const TriageResult mismatchedTriage = CompleteTriage(
                mismatchedNative,
                &mismatchedCorrelations);
            const auto mismatched = std::find_if(
                mismatchedCorrelations.correlations.begin(),
                mismatchedCorrelations.correlations.end(),
                [](const ObservationCorrelation& correlation)
                {
                    return correlation.ruleId ==
                        "correlation.runtime.explicit-relationship-sensitive-access";
                });
            Check(mismatched == mismatchedCorrelations.correlations.end(),
                L"unrelated runtime and handle target identities do not correlate");
            Check(mismatchedTriage.Succeeded(),
                L"mismatched target triage remains a valid result");
            CheckEqual(
                mismatchedTriage.verdict,
                TriageVerdict::MediumAttention,
                L"sensitive access retains its standalone ceiling without false target correlation");

            input.runtime.relationships.front().sourceIdentity =
                Identity(8200, 82000);
            input.runtime.relationships.front().targetIdentity =
                input.identity;
            const NativeObservationBuildResult reverseNative =
                BuildNativeSelectedProcessObservations(input);
            Check(reverseNative.Succeeded(),
                L"reverse-direction runtime relationship remains valid evidence");
            ObservationCorrelationResult reverseCorrelations;
            const TriageResult reverseTriage = CompleteTriage(
                reverseNative,
                &reverseCorrelations);
            const auto reverse = std::find_if(
                reverseCorrelations.correlations.begin(),
                reverseCorrelations.correlations.end(),
                [](const ObservationCorrelation& correlation)
                {
                    return correlation.ruleId ==
                        "correlation.runtime.explicit-relationship-sensitive-access";
                });
            Check(reverse == reverseCorrelations.correlations.end(),
                L"reverse runtime direction does not corroborate an outbound selected-process handle");
            Check(reverseTriage.Succeeded(),
                L"reverse-direction target triage remains valid");
        }

        void TestNativeProducerPerformance()
        {
            NativeSelectedProcessObservationInput input = EmptyInput();
            AddToken(input, true);
            AddSensitiveHandle(input, false);

            input.runtime.identity = input.identity;
            input.runtime.entityScope = input.entityScope;
            input.runtime.supplied = true;
            input.runtime.collectionAttempted = true;
            input.runtime.available = true;
            input.runtime.declaredThreadCount = 1;
            input.runtime.declaredHandleCount = 1;
            input.runtime.source.sourceKind = ObservationSourceKind::Direct;
            input.runtime.source.sourceIdentifier = "test.runtime";
            input.runtime.source.collectionMethod = "fixture";
            NativeRuntimeThreadInput thread;
            thread.threadId = 9300;
            thread.ownerProcessId = input.identity.pid;
            thread.ownerIdentityKnown = true;
            thread.ownerMatchesSelectedProcess = true;
            thread.source = input.runtime.source;
            input.runtime.threads.push_back(thread);

            input.priority.identity = input.identity;
            input.priority.entityScope = input.entityScope;
            input.priority.supplied = true;
            input.priority.collectionAttempted = true;
            input.priority.available = true;
            input.priority.priorityClass =
                NativeProcessPriorityClass::High;
            input.priority.rawPriorityClass = 0x00000080U;
            input.priority.source = input.runtime.source;

            constexpr std::size_t Iterations = 200;
            const auto measure = [&](auto&& operation)
            {
                const auto started = std::chrono::steady_clock::now();
                for (std::size_t iteration = 0;
                    iteration < Iterations;
                    ++iteration)
                {
                    operation();
                }
                return std::chrono::duration_cast<
                    std::chrono::microseconds>(
                        std::chrono::steady_clock::now() - started).count();
            };

            const auto tokenUs = measure([&]()
            {
                Check(BuildNativeTokenObservations(input.token).Succeeded(),
                    L"timed token producer succeeds");
            });
            const auto handleUs = measure([&]()
            {
                Check(BuildNativeHandleObservations(input.handles).Succeeded(),
                    L"timed handle producer succeeds");
            });
            const auto runtimeUs = measure([&]()
            {
                Check(BuildNativeRuntimeObservations(input.runtime).Succeeded(),
                    L"timed runtime producer succeeds");
            });
            const auto priorityUs = measure([&]()
            {
                Check(BuildNativePriorityObservations(input.priority).Succeeded(),
                    L"timed priority producer succeeds");
            });
            const auto enrichedUs = measure([&]()
            {
                const NativeObservationBuildResult native =
                    BuildNativeSelectedProcessObservations(input);
                Check(native.Succeeded(),
                    L"timed full native enriched build succeeds");
                const TriageResult triage = CompleteTriage(native);
                Check(triage.Succeeded(),
                    L"timed full native enriched triage succeeds");
            });

            std::wcout
                << L"Native domain fixture (" << Iterations
                << L" iterations): token=" << tokenUs
                << L" us, handle=" << handleUs
                << L" us, runtime=" << runtimeUs
                << L" us, priority=" << priorityUs
                << L" us, full-enriched=" << enrichedUs << L" us.\n";

            NativeHandleObservationInput largeHandles = input.handles;
            largeHandles.collection.handles.clear();
            largeHandles.targetIdentities.clear();
            constexpr std::size_t LargeHandleCount = 1000;
            largeHandles.collection.handles.reserve(LargeHandleCount);
            largeHandles.targetIdentities.reserve(LargeHandleCount);
            for (std::size_t index = 0; index < LargeHandleCount; ++index)
            {
                HandleInfo handle;
                handle.owningPid = input.identity.pid;
                handle.handleValue = 0x1000U + index;
                handle.objectType = L"Process";
                handle.typeResolved = true;
                handle.targetPid = static_cast<std::uint32_t>(10000 + index);
                handle.grantedAccessRaw = 0x0010U;
                largeHandles.collection.handles.push_back(handle);

                NativeHandleTargetIdentity target;
                target.handleValue = handle.handleValue;
                target.objectKind = NativeHandleObjectKind::Process;
                target.targetPid = handle.targetPid.value();
                target.identityResolved = true;
                target.identity = Identity(
                    target.targetPid,
                    100000U + index);
                largeHandles.targetIdentities.push_back(target);
            }
            const auto largeStarted = std::chrono::steady_clock::now();
            const NativeHandleObservationBuildResult largeResult =
                BuildNativeHandleObservations(largeHandles);
            const auto largeHandleUs = std::chrono::duration_cast<
                std::chrono::microseconds>(
                    std::chrono::steady_clock::now() - largeStarted).count();
            Check(largeResult.Succeeded(),
                L"1000-handle indexed target fixture succeeds");
            CheckEqual(
                largeResult.inventory.records.size(),
                LargeHandleCount,
                L"1000 distinct handles retain 1000 bounded artifacts");
            std::wcout
                << L"Indexed handle-target fixture: " << LargeHandleCount
                << L" handles in " << largeHandleUs << L" us.\n";
        }
    }

    int RunNativeObservationIntegrationTests()
    {
        failureCount = 0;
        TestContextOnlyNativeDomainsRemainInformational();
        TestDebugPrivilegeSensitiveAccessCorrelation();
        TestDebugPrivilegeWithoutAccessDoesNotContribute();
        TestExplicitRuntimeRelationshipSensitiveAccessCorrelation();
        TestNativeProducerPerformance();
        return failureCount;
    }
}
