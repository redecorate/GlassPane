#include "Core/ObservationShadow.h"

#include <iostream>
#include <string>

namespace GlassPane::Tests
{
    namespace
    {
        using namespace GlassPane::Core;

        int failures = 0;

        void Check(bool condition, const wchar_t* name)
        {
            if (!condition)
            {
                std::wcerr << L"FAILED: " << name << L'\n';
                ++failures;
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

        ObservationShadowSourceContext MakeContext(
            std::uint32_t pid,
            std::uint64_t creationTime)
        {
            ObservationShadowSourceContext context;
            context.entityScope = "process:pid=" + std::to_string(pid) +
                ";creation=" + std::to_string(creationTime);
            context.nativeInputSupplied = true;
            context.nativeInput.identity = { pid, true, creationTime };
            context.nativeInput.entityScope = context.entityScope;
            return context;
        }

        void CompletePipeline(ObservationShadowState& state)
        {
            Check(
                TryRefineObservationShadowState(state),
                L"native shadow refinement runs once");
            Check(
                TryActivateObservationShadowCorrelations(state),
                L"native shadow correlation runs once");
            Check(
                TryBuildObservationShadowTriage(state),
                L"native shadow triage runs once");
        }

        void TestEmptyNativePipelineIsValidInformational()
        {
            constexpr std::uint32_t pid = 4100;
            constexpr std::uint64_t creation = 410000;
            constexpr std::uint64_t generation = 9;
            const ObservationShadowSourceContext context =
                MakeContext(pid, creation);
            ObservationShadowState state = BuildNativeObservationShadowState(
                context,
                true,
                pid,
                creation,
                generation);

            Check(state.attempted && state.success,
                L"empty native evidence is a successful pipeline input");
            Check(state.nativeObservations.Succeeded(),
                L"empty native producer succeeds");
            Check(state.inventory.records.empty(),
                L"empty native input produces no fabricated observation");
            CheckEqual(state.inventory.typedSourceFactCount, std::size_t(0),
                L"empty native input represents no typed source facts");
            CompletePipeline(state);
            Check(state.triage.Succeeded(),
                L"empty native triage succeeds");
            CheckEqual(
                state.triage.verdict,
                TriageVerdict::Informational,
                L"empty native triage is Informational");
            CheckEqual(
                state.decisionSummary.contributingDomainCount,
                std::size_t(0),
                L"empty native triage has no contributing domain");
            Check(!TryRefineObservationShadowState(state),
                L"native refinement is not repeated");
            Check(!TryActivateObservationShadowCorrelations(state),
                L"native correlation is not repeated");
            Check(!TryBuildObservationShadowTriage(state),
                L"native triage is not repeated");
        }

        void TestStaticMemoryRemainsContext()
        {
            constexpr std::uint32_t pid = 4200;
            constexpr std::uint64_t creation = 420000;
            ObservationShadowSourceContext context = MakeContext(pid, creation);
            NativeMemoryObservationInput& memory = context.nativeInput.memory;
            memory.identity = context.nativeInput.identity;
            memory.supplied = true;
            memory.collectionAttempted = true;
            memory.available = true;
            memory.collection.pid = pid;
            memory.collection.success = true;
            MemoryRegionInfo region;
            region.baseAddress = 0x100000;
            region.allocationBase = 0x100000;
            region.regionSize = 0x4000;
            region.isWritable = true;
            region.isExecutable = true;
            region.isPrivate = true;
            region.isGuard = true;
            memory.collection.regions.push_back(region);

            ObservationShadowState state = BuildNativeObservationShadowState(
                context,
                true,
                pid,
                creation,
                10);
            Check(state.success, L"static-memory native shadow succeeds");
            CheckEqual(state.inventory.records.size(), std::size_t(1),
                L"one region projects one artifact-level record");
            CheckEqual(
                state.inventory.records.front().observation.disposition,
                ObservationDisposition::Context,
                L"static memory remains Context");
            Check(
                !state.inventory.records.front().observation.contributesToVerdict,
                L"static memory is non-contributing");
            CompletePipeline(state);
            CheckEqual(
                state.triage.verdict,
                TriageVerdict::Informational,
                L"static memory alone remains Informational");
            Check(state.correlation.correlations.empty(),
                L"static memory activates no correlation");
        }

        void TestIdentityGenerationAndPidZeroLifecycle()
        {
            constexpr std::uint64_t generation = 11;
            ObservationShadowSourceContext context = MakeContext(0, 0);
            context.nativeInput.identity = { 0, false, 0 };
            ObservationShadowState state = BuildNativeObservationShadowState(
                context,
                true,
                0,
                0,
                generation);
            Check(state.success, L"PID zero is a valid explicit entity");
            Check(
                ObservationShadowMatches(state, true, 0, 0, generation),
                L"PID zero exact generation matches");
            Check(
                !ObservationShadowMatches(state, false, 0, 0, generation),
                L"PID zero is distinct from no selection");
            Check(
                !ObservationShadowMatches(state, true, 0, 0, generation + 1),
                L"stale generation is rejected");
            ClearObservationShadowState(state);
            Check(!state.attempted && state.inventory.records.empty(),
                L"clear removes native shadow state");
        }

        void TestFailureIsStampedAndBounded()
        {
            ObservationShadowSourceContext missing;
            missing.entityScope = "process:pid=4300;creation=430000";
            ObservationShadowState failed = BuildNativeObservationShadowState(
                missing,
                true,
                4300,
                430000,
                12);
            Check(failed.attempted && !failed.success,
                L"missing native input stamps a failure");
            Check(
                ObservationShadowMatches(failed, true, 4300, 430000, 12),
                L"failed generation remains matchable and is not retried per frame");
            Check(
                failed.diagnosticMessage.size() <=
                    ObservationShadowDiagnosticMaxCharacters,
                L"failure diagnostic is bounded");
            Check(!TryRefineObservationShadowState(failed),
                L"failed native production does not enter refinement");

            ObservationShadowSourceContext context = MakeContext(4400, 440000);
            ObservationShadowState explicitFailure =
                MakeFailedObservationShadowState(
                    context,
                    true,
                    4400,
                    440000,
                    13,
                    std::string(
                        ObservationShadowDiagnosticMaxCharacters + 20,
                        'x'));
            Check(
                explicitFailure.diagnosticMessage.size() ==
                    ObservationShadowDiagnosticMaxCharacters,
                L"explicit failure helper truncates diagnostics atomically");
        }
    }

    int RunObservationShadowTests()
    {
        failures = 0;
        TestEmptyNativePipelineIsValidInformational();
        TestStaticMemoryRemainsContext();
        TestIdentityGenerationAndPidZeroLifecycle();
        TestFailureIsStampedAndBounded();
        if (failures == 0)
        {
            std::wcout << L"Observation shadow native tests passed.\n";
        }
        return failures;
    }
}
