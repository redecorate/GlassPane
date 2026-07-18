#include "Core/AuthoritativeTriage.h"

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace GlassPane::Tests
{
    namespace
    {
        using namespace Core;

        int failureCount = 0;

        void Check(bool condition, const wchar_t* testName)
        {
            if (!condition)
            {
                std::wcerr << L"FAILED: " << testName << L'\n';
                ++failureCount;
            }
        }

        template <typename Value>
        void CheckEqual(
            const Value& actual,
            const Value& expected,
            const wchar_t* testName)
        {
            Check(actual == expected, testName);
        }

        ProcessInfo MakeProcess(
            std::uint32_t pid,
            std::uint64_t creationTime,
            bool hasCreationTime = true)
        {
            ProcessInfo process;
            process.pid = pid;
            process.parentPid = 0;
            process.name = L"generic-native-authority.exe";
            process.executablePath =
                L"C:\\Program Files\\Generic\\generic-native-authority.exe";
            process.commandLine = L"generic-native-authority.exe --run";
            process.commandLineAccessible = true;
            process.hasCreationTime = hasCreationTime;
            process.creationTimeFileTime = hasCreationTime ? creationTime : 0;

            // Historical fields deliberately disagree with the expected native
            // result. Current selectors must never read either field.
            process.severity = Severity::High;
            process.suspicious = true;
            return process;
        }

        ProcessTriageCacheSourceStamp MakeStamp()
        {
            return { 17, 29, 41, false };
        }

        ProcessTriageCache BuildBaselineCache(const ProcessInfo& process)
        {
            ProcessSnapshot snapshot;
            snapshot.processes = { process };
            snapshot.Reindex();

            ProcessTriageCacheBuildOptions options;
            options.sourceStamp = MakeStamp();
            options.collectionTimestamp = "2026-07-17T12:00:00Z";
            return BuildProcessTriageCache(
                snapshot,
                std::vector<BaselineObservationContext>{},
                options);
        }

        std::string EntityScope(
            std::uint32_t pid,
            std::uint64_t creationTime)
        {
            return "process:pid=" + std::to_string(pid) +
                ";creation=" + std::to_string(creationTime);
        }

        ObservationShadowSourceContext MakeNativeContext(
            const ProcessInfo& process)
        {
            ObservationShadowSourceContext context;
            context.entityScope = EntityScope(
                process.pid,
                process.hasCreationTime
                    ? process.creationTimeFileTime
                    : 0);
            context.nativeInputSupplied = true;
            context.nativeInput.identity = MakeProcessIdentityKey(process);
            context.nativeInput.entityScope = context.entityScope;
            return context;
        }

        ObservationShadowState BuildCompletedNativeShadow(
            const ProcessInfo& process,
            std::uint64_t generation)
        {
            const ObservationShadowSourceContext context =
                MakeNativeContext(process);
            ObservationShadowState state = BuildNativeObservationShadowState(
                context,
                true,
                process.pid,
                process.hasCreationTime
                    ? process.creationTimeFileTime
                    : 0,
                generation);
            Check(state.success, L"native fixture production succeeds");
            Check(
                TryRefineObservationShadowState(state),
                L"native fixture refinement succeeds");
            Check(
                TryActivateObservationShadowCorrelations(state),
                L"native fixture correlation succeeds");
            Check(
                TryBuildObservationShadowTriage(state),
                L"native fixture triage succeeds");
            return state;
        }

        void TestVerdictConversion()
        {
            const struct
            {
                TriageVerdict verdict;
                Severity severity;
                bool suspicious;
            } cases[] = {
                { TriageVerdict::Informational, Severity::None, false },
                { TriageVerdict::LowAttention, Severity::Low, true },
                { TriageVerdict::MediumAttention, Severity::Medium, true },
                { TriageVerdict::HighAttention, Severity::High, true }
            };

            for (const auto& item : cases)
            {
                const TriageSurfaceClassification classification =
                    ClassifyTriageVerdictForSurfaces(item.verdict);
                CheckEqual(
                    classification.severity,
                    item.severity,
                    L"surface severity conversion is exact");
                CheckEqual(
                    classification.suspicious,
                    item.suspicious,
                    L"surface suspicious membership is exact");
                CheckEqual(
                    TriageVerdictToSeverity(item.verdict),
                    item.severity,
                    L"shared severity helper matches surface conversion");
                CheckEqual(
                    IsSuspiciousTriageVerdict(item.verdict),
                    item.suspicious,
                    L"shared suspicious helper matches surface conversion");
            }

            const TriageSurfaceClassification unknown =
                ClassifyTriageVerdictForSurfaces(
                    static_cast<TriageVerdict>(999));
            CheckEqual(
                unknown.severity,
                Severity::None,
                L"unknown verdict remains neutral");
            Check(!unknown.suspicious,
                L"unknown verdict is excluded from suspicious membership");
        }

        void TestProcessAuthorityIdentityAndGeneration()
        {
            const ProcessInfo process = MakeProcess(5100, 600);
            const ProcessTriageCache cache = BuildBaselineCache(process);
            const ProcessTriageAuthority authority =
                SelectNativeProcessTriageAuthority(
                    cache,
                    process,
                    MakeStamp());

            Check(authority.UsesBaselineTriage(),
                L"exact native baseline is authoritative");
            Check(!authority.unavailable,
                L"successful native baseline is available");
            Check(authority.baselineAvailable,
                L"successful native baseline is marked available");
            CheckEqual(
                authority.verdict,
                TriageVerdict::Informational,
                L"historical High metadata cannot alter native Informational");

            ProcessTriageCacheSourceStamp staleStamp = MakeStamp();
            ++staleStamp.evidenceGeneration;
            const ProcessTriageAuthority stale =
                SelectNativeProcessTriageAuthority(
                    cache,
                    process,
                    staleStamp);
            Check(!stale.UsesBaselineTriage(),
                L"stale source generation is rejected");
            CheckEqual(
                stale.verdict,
                TriageVerdict::Informational,
                L"stale native baseline becomes neutral unavailable");
            CheckEqual(
                stale.unavailableKind,
                ProcessTriageUnavailableKind::CacheGenerationMismatch,
                L"stale source generation has a typed reason");

            const ProcessInfo reusedPid = MakeProcess(5100, 601);
            const ProcessTriageAuthority reused =
                SelectNativeProcessTriageAuthority(
                    cache,
                    reusedPid,
                    MakeStamp());
            Check(!reused.UsesBaselineTriage(),
                L"PID reuse cannot select an old cache entry");
            CheckEqual(
                reused.unavailableKind,
                ProcessTriageUnavailableKind::ProcessIdentityMismatch,
                L"PID reuse reports exact identity mismatch");
            CheckEqual(
                reused.verdict,
                TriageVerdict::Informational,
                L"PID reuse never resurrects historical severity");
        }

        void TestPidZeroAndUnavailableBaseline()
        {
            const ProcessInfo pidZero = MakeProcess(0, 0, false);
            const ProcessTriageCache cache = BuildBaselineCache(pidZero);
            const ProcessTriageAuthority current =
                SelectNativeProcessTriageAuthority(
                    cache,
                    pidZero,
                    MakeStamp());
            Check(current.UsesBaselineTriage(),
                L"PID zero is a valid exact cache identity");

            ProcessTriageCache notAttempted;
            const ProcessTriageAuthority unavailable =
                SelectNativeProcessTriageAuthority(
                    notAttempted,
                    pidZero,
                    MakeStamp());
            Check(!unavailable.UsesBaselineTriage(),
                L"missing native cache is explicitly unavailable");
            CheckEqual(
                unavailable.verdict,
                TriageVerdict::Informational,
                L"unavailable baseline remains neutral despite legacy High");
            CheckEqual(
                unavailable.unavailableKind,
                ProcessTriageUnavailableKind::CacheNotAttempted,
                L"unavailable baseline retains bounded typed reason");
            Check(
                unavailable.unavailableReason.size() <=
                    AuthoritativeTriageUnavailableReasonMaxCharacters,
                L"unavailable baseline diagnostic is bounded");
        }

        void TestNativeEnrichedAuthorityValidation()
        {
            constexpr std::uint64_t generation = 77;
            const ProcessInfo process = MakeProcess(5200, 700);
            const std::string scope = EntityScope(5200, 700);
            const ObservationShadowState shadow =
                BuildCompletedNativeShadow(process, generation);

            const AuthoritativeTriageView exact =
                SelectNativeAuthoritativeTriage(
                    shadow,
                    true,
                    process.pid,
                    process.creationTimeFileTime,
                    generation,
                    scope);
            Check(exact.UsesTriageEngine(),
                L"exact enriched native result is authoritative");
            CheckEqual(
                exact.verdict,
                TriageVerdict::Informational,
                L"zero-correlation native result remains valid Informational");
            CheckEqual(
                shadow.correlation.correlations.size(),
                std::size_t(0),
                L"zero-correlation fixture is explicit");

            const AuthoritativeTriageView stale =
                SelectNativeAuthoritativeTriage(
                    shadow,
                    true,
                    process.pid,
                    process.creationTimeFileTime,
                    generation + 1,
                    scope);
            Check(!stale.UsesTriageEngine(),
                L"stale enriched generation is rejected");
            CheckEqual(
                stale.verdict,
                TriageVerdict::Informational,
                L"rejected enriched result is neutral unavailable");

            const AuthoritativeTriageView wrongIdentity =
                SelectNativeAuthoritativeTriage(
                    shadow,
                    true,
                    process.pid + 1,
                    process.creationTimeFileTime,
                    generation,
                    scope);
            Check(!wrongIdentity.UsesTriageEngine(),
                L"wrong enriched process identity is rejected");

            const AuthoritativeTriageView wrongScope =
                SelectNativeAuthoritativeTriage(
                    shadow,
                    true,
                    process.pid,
                    process.creationTimeFileTime,
                    generation,
                    scope + "/snapshot");
            CheckEqual(
                wrongScope.unavailableKind,
                AuthoritativeTriageUnavailableKind::EntityScopeMismatch,
                L"live/snapshot scope mismatch is rejected explicitly");
        }

        void TestSelectedPrecedence()
        {
            constexpr std::uint64_t generation = 88;
            const ProcessInfo process = MakeProcess(5300, 800);
            const std::string scope = EntityScope(5300, 800);
            const ObservationShadowState shadow =
                BuildCompletedNativeShadow(process, generation);
            const ProcessTriageCache baseline = BuildBaselineCache(process);

            const SelectedProcessTriageAuthority enriched =
                SelectNativeSelectedProcessTriageAuthority(
                    shadow,
                    true,
                    process,
                    generation,
                    scope,
                    baseline,
                    MakeStamp());
            Check(enriched.UsesEnrichedTriage(),
                L"valid enriched result takes precedence over baseline");
            Check(enriched.baselineAvailable,
                L"enriched authority retains exact baseline comparison");
            CheckEqual(
                enriched.analysisLevel,
                SelectedTriageAnalysisLevel::Enriched,
                L"selected authority reports Enriched analysis");

            const SelectedProcessTriageAuthority baselineOnly =
                SelectNativeSelectedProcessTriageAuthority(
                    shadow,
                    true,
                    process,
                    generation + 1,
                    scope,
                    baseline,
                    MakeStamp());
            Check(baselineOnly.UsesBaselineTriage(),
                L"failed enriched validation uses only the native baseline");
            CheckEqual(
                baselineOnly.analysisLevel,
                SelectedTriageAnalysisLevel::Baseline,
                L"baseline-only authority reports Baseline analysis");
            Check(!baselineOnly.unavailable,
                L"native baseline precedence remains available");

            ProcessTriageCache missingBaseline;
            const SelectedProcessTriageAuthority unavailable =
                SelectNativeSelectedProcessTriageAuthority(
                    shadow,
                    true,
                    process,
                    generation + 1,
                    scope,
                    missingBaseline,
                    MakeStamp());
            Check(unavailable.unavailable,
                L"enriched and baseline failure produces unavailable state");
            CheckEqual(
                unavailable.analysisLevel,
                SelectedTriageAnalysisLevel::Unavailable,
                L"unavailable state never reports Legacy fallback");
            Check(!unavailable.historicalFallbackCaptured,
                L"current native unavailable state never uses historical authority");
            CheckEqual(
                unavailable.verdict,
                TriageVerdict::Informational,
                L"current unavailable state remains neutral");
        }

        PersistedProcessTriageRecord MakePersistedRecord(
            const ProcessInfo& process,
            const PersistedTriageSummary& summary)
        {
            PersistedProcessTriageRecord record;
            record.identity = MakeProcessIdentityKey(process);
            record.summary = summary;
            return record;
        }

        void TestCapturedNativeAndHistoricalStates()
        {
            constexpr std::uint64_t generation = 99;
            const ProcessInfo process = MakeProcess(5400, 900);
            const ProcessTriageCache baselineCache = BuildBaselineCache(process);
            const CachedBaselineTriage* baseline = baselineCache.Find(process);
            Check(baseline != nullptr && baseline->triage.Succeeded(),
                L"captured fixture has a successful baseline");
            if (baseline == nullptr || !baseline->triage.Succeeded())
            {
                return;
            }

            const PersistedTriageProjectionResult baselineProjection =
                ProjectPersistedTriageSummary(
                    baseline->triage,
                    PersistedTriageAnalysisLevel::Baseline,
                    0);
            Check(baselineProjection.success,
                L"native baseline projects into captured triage");
            PersistedProcessTriageRecord baselineRecord = MakePersistedRecord(
                process,
                baselineProjection.summary);
            const PersistedTriageContext baselineContext =
                MakePersistedTriageContext({ baselineRecord }, baselineRecord);
            const SelectedProcessTriageAuthority capturedBaseline =
                SelectCapturedSelectedProcessTriageAuthority(
                    baselineContext,
                    true,
                    process);
            Check(capturedBaseline.UsesBaselineTriage(),
                L"captured baseline is selected without recomputation");

            const ObservationShadowState shadow =
                BuildCompletedNativeShadow(process, generation);
            const PersistedTriageProjectionResult enrichedProjection =
                ProjectPersistedTriageSummary(
                    shadow.triage,
                    PersistedTriageAnalysisLevel::Enriched,
                    0,
                    &baseline->triage);
            Check(enrichedProjection.success,
                L"native enriched result projects with baseline relationship");
            PersistedProcessTriageRecord enrichedRecord = MakePersistedRecord(
                process,
                enrichedProjection.summary);
            const PersistedTriageContext enrichedContext =
                MakePersistedTriageContext({ baselineRecord }, enrichedRecord);
            const SelectedProcessTriageAuthority capturedEnriched =
                SelectCapturedSelectedProcessTriageAuthority(
                    enrichedContext,
                    true,
                    process);
            Check(capturedEnriched.UsesEnrichedTriage(),
                L"captured enriched result takes selected-process precedence");
            Check(capturedEnriched.baselineAvailable,
                L"captured enriched result retains baseline verdict");

            const PersistedTriageContext olderSnapshot;
            const SelectedProcessTriageAuthority notCaptured =
                SelectCapturedSelectedProcessTriageAuthority(
                    olderSnapshot,
                    true,
                    process);
            Check(notCaptured.notCaptured,
                L"older snapshot remains explicitly Not captured");
            CheckEqual(
                notCaptured.analysisLevel,
                SelectedTriageAnalysisLevel::NotCaptured,
                L"older snapshot does not fabricate a native verdict");

            PersistedTriageSummary historicalFallback;
            historicalFallback.captured = true;
            historicalFallback.evaluationSucceeded = false;
            historicalFallback.usingFallback = true;
            historicalFallback.analysisLevel =
                PersistedTriageAnalysisLevel::LegacyFallback;
            historicalFallback.authoritativeVerdict =
                TriageVerdict::HighAttention;
            historicalFallback.triageModelVersion =
                PersistedTriageModelVersion;
            historicalFallback.fallbackReason =
                "Captured schema-4 compatibility record.";
            Check(
                ValidatePersistedTriageSummary(historicalFallback).valid,
                L"historical schema-4 fallback record remains readable");
            PersistedProcessTriageRecord historicalRecord =
                MakePersistedRecord(process, historicalFallback);
            const PersistedTriageContext historicalContext =
                MakePersistedTriageContext(
                    { historicalRecord },
                    historicalRecord);
            const SelectedProcessTriageAuthority historical =
                SelectCapturedSelectedProcessTriageAuthority(
                    historicalContext,
                    true,
                    process);
            CheckEqual(
                historical.analysisLevel,
                SelectedTriageAnalysisLevel::LegacyFallback,
                L"historical captured fallback remains compatibility metadata");
            Check(historical.historicalFallbackCaptured,
                L"historical fallback state is explicitly compatibility-only");
            Check(historical.persistedSummary != nullptr,
                L"historical captured fallback points only to persisted data");
            Check(historical.triageResult == nullptr,
                L"historical captured fallback never fabricates native analysis");
        }

        void TestCopySummaryAndDeterminism()
        {
            constexpr std::uint64_t generation = 111;
            const ProcessInfo process = MakeProcess(5500, 1000);
            const std::string scope = EntityScope(5500, 1000);
            const ObservationShadowState shadow =
                BuildCompletedNativeShadow(process, generation);
            const ProcessTriageCache baseline = BuildBaselineCache(process);
            const SelectedProcessTriageAuthority authority =
                SelectNativeSelectedProcessTriageAuthority(
                    shadow,
                    true,
                    process,
                    generation,
                    scope,
                    baseline,
                    MakeStamp());

            const std::string summary = FormatSelectedProcessTriageSummary(
                authority,
                "generic-native-authority.exe",
                process.pid);
            const std::string repeated = FormatSelectedProcessTriageSummary(
                authority,
                "generic-native-authority.exe",
                process.pid);
            CheckEqual(summary, repeated,
                L"copy summary formatting is deterministic");
            Check(summary.find("Verdict: Informational") != std::string::npos,
                L"copy summary contains authoritative verdict");
            Check(summary.find("Analysis level: Enriched") != std::string::npos,
                L"copy summary contains native analysis level");
            Check(summary.find("Source evidence:") != std::string::npos,
                L"copy summary retains native source-evidence count");
            Check(summary.find("observation.") == std::string::npos,
                L"copy summary omits internal observation IDs");
            Check(summary.find("correlation.") == std::string::npos,
                L"copy summary omits internal correlation IDs");
            Check(summary.find("artifact key") == std::string::npos,
                L"copy summary omits artifact keys");
            Check(summary.find("adapter") == std::string::npos,
                L"copy summary omits retired adapter terminology");
            Check(summary.find("Legacy fallback") == std::string::npos,
                L"current native copy summary has no legacy authority wording");

            const std::string oversizedName(
                AuthoritativeTriageSummaryMaxCharacters * 2,
                'x');
            const std::string bounded = FormatSelectedProcessTriageSummary(
                authority,
                oversizedName,
                process.pid);
            Check(
                bounded.size() <= AuthoritativeTriageSummaryMaxCharacters,
                L"copy summary is bounded");

            for (std::size_t index = 0; index < 1000; ++index)
            {
                const ProcessTriageAuthority lookup =
                    SelectNativeProcessTriageAuthority(
                        baseline,
                        process,
                        MakeStamp());
                Check(lookup.UsesBaselineTriage(),
                    L"repeated authority lookup stays deterministic");
                Check(lookup.baseline == baseline.Find(process),
                    L"repeated authority lookup retains exact cached identity");
            }
        }
    }

    int RunAuthoritativeTriageTests()
    {
        failureCount = 0;
        TestVerdictConversion();
        TestProcessAuthorityIdentityAndGeneration();
        TestPidZeroAndUnavailableBaseline();
        TestNativeEnrichedAuthorityValidation();
        TestSelectedPrecedence();
        TestCapturedNativeAndHistoricalStates();
        TestCopySummaryAndDeterminism();
        if (failureCount == 0)
        {
            std::wcout << L"Authoritative triage native tests passed.\n";
        }
        return failureCount;
    }
}
