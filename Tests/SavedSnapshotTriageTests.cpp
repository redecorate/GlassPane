#include "Export/SavedSnapshot.h"

#include "Core/AuthoritativeTriage.h"
#include "Core/ProcessTree.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace GlassPane::Tests
{
    namespace
    {
        using namespace GlassPane::Core;
        using namespace GlassPane::Export;

        int failures = 0;

        void Check(bool condition, const wchar_t* name)
        {
            if (!condition)
            {
                std::wcerr << L"FAILED: " << name << L'\n';
                ++failures;
            }
        }

        std::filesystem::path TempPath(const wchar_t* suffix)
        {
            return std::filesystem::temp_directory_path() /
                (std::wstring(L"glasspane-triage-") + suffix + L".json");
        }

        ProcessSnapshot MakeSnapshot(bool includePidZero = false)
        {
            ProcessSnapshot snapshot;
            ProcessInfo first;
            first.pid = includePidZero ? 0U : 120U;
            first.parentPid = 4;
            first.name = includePidZero ? L"system-entry" : L"generic-one";
            first.hasCreationTime = !includePidZero;
            first.creationTimeFileTime = includePidZero ? 0 : 1200;
            first.severity = Severity::High;
            first.suspicious = true;
            first.indicators = { L"legacy source record" };
            snapshot.processes.push_back(first);

            ProcessInfo second;
            second.pid = 220;
            second.parentPid = first.pid;
            second.name = L"generic-two";
            second.hasCreationTime = true;
            second.creationTimeFileTime = 2200;
            second.severity = Severity::Low;
            second.suspicious = true;
            snapshot.processes.push_back(second);
            BuildProcessTree(snapshot);
            return snapshot;
        }

        ProcessSnapshot MakeLargeSnapshot(std::size_t processCount)
        {
            ProcessSnapshot snapshot;
            snapshot.processes.reserve(processCount);
            for (std::size_t index = 0; index < processCount; ++index)
            {
                ProcessInfo process;
                process.pid = 10000U + static_cast<std::uint32_t>(index);
                process.parentPid = index == 0 ? 0U : 10000U;
                process.name = L"generic-baseline-" + std::to_wstring(index);
                process.hasCreationTime = true;
                process.creationTimeFileTime =
                    1000000ULL + static_cast<std::uint64_t>(index);
                process.severity = Severity::None;
                process.suspicious = false;
                process.indicators = { L"legacy source record" };
                snapshot.processes.push_back(std::move(process));
            }
            BuildProcessTree(snapshot);
            return snapshot;
        }

        TriageResult MakeTriage(TriageVerdict verdict)
        {
            TriageResult result;
            result.attempted = true;
            result.success = true;
            result.status = TriageEngineStatus::Success;
            result.verdict = verdict;
            if (verdict != TriageVerdict::Informational)
            {
                result.contributingDomains.insert(EvidenceDomain::FileSignature);
            }
            result.previewRationaleEntries.push_back({
                TriageRationaleSection::VerdictBasis,
                verdict == TriageVerdict::Informational
                    ? "No review-relevant baseline evidence contributed."
                    : "Typed baseline evidence contributed to this attention level."
            });
            result.previewRationaleEntries.push_back({
                TriageRationaleSection::SupportingContext,
                "Neutral source context remained available for review."
            });
            result.statusMessage = "Captured deterministically.";
            return result;
        }

        TriageVerdict HistoricalSeverityVerdict(Severity severity)
        {
            switch (severity)
            {
            case Severity::Low:
                return TriageVerdict::LowAttention;
            case Severity::Medium:
                return TriageVerdict::MediumAttention;
            case Severity::High:
                return TriageVerdict::HighAttention;
            case Severity::None:
            case Severity::Info:
            default:
                return TriageVerdict::Informational;
            }
        }

        PersistedTriageSummary MakeHistoricalLegacyFallbackSummary(
            TriageVerdict verdict,
            std::size_t sourceEvidenceCount,
            std::string reason)
        {
            PersistedTriageSummary summary;
            summary.captured = true;
            summary.evaluationSucceeded = false;
            summary.usingFallback = true;
            summary.analysisLevel =
                PersistedTriageAnalysisLevel::LegacyFallback;
            summary.authoritativeVerdict = verdict;
            summary.triageModelVersion = PersistedTriageModelVersion;
            summary.sourceEvidenceCount = sourceEvidenceCount;
            summary.fallbackReason = std::move(reason);
            return summary;
        }

        PersistedTriageContext MakeContext(
            const ProcessSnapshot& snapshot,
            TriageVerdict baselineVerdict,
            bool enriched,
            bool fallback)
        {
            std::vector<PersistedProcessTriageRecord> records;
            for (const ProcessInfo& process : snapshot.processes)
            {
                PersistedProcessTriageRecord record;
                record.identity = MakeProcessIdentityKey(process);
                if (fallback && process.pid == snapshot.processes.front().pid)
                {
                    record.summary = MakeHistoricalLegacyFallbackSummary(
                        HistoricalSeverityVerdict(process.severity),
                        process.indicators.size(),
                        "Baseline evaluation was unavailable at capture time.");
                }
                else
                {
                    const TriageResult triage = MakeTriage(baselineVerdict);
                    const PersistedTriageProjectionResult projected =
                        ProjectPersistedTriageSummary(
                            triage,
                            PersistedTriageAnalysisLevel::Baseline,
                            process.indicators.size());
                    record.summary = projected.summary;
                }
                records.push_back(record);
            }

            PersistedProcessTriageRecord selected = records.front();
            if (enriched)
            {
                const TriageResult baseline = MakeTriage(baselineVerdict);
                const TriageResult enrichedResult =
                    MakeTriage(TriageVerdict::MediumAttention);
                const PersistedTriageProjectionResult projected =
                    ProjectPersistedTriageSummary(
                        enrichedResult,
                        PersistedTriageAnalysisLevel::Enriched,
                        3,
                        &baseline);
                selected.summary = projected.summary;
            }
            return MakePersistedTriageContext(
                std::move(records),
                std::move(selected));
        }

        SavedSnapshotExportContext MakeExportContext(
            const ProcessSnapshot& snapshot,
            const ServiceCollectionResult& services,
            const PersistedTriageContext& triage)
        {
            SavedSnapshotExportContext context;
            context.snapshot = &snapshot;
            context.serviceContext = &services;
            context.glassPaneVersion = L"V0.8.0-Test";
            context.capturedAt = L"2026-01-01T00:00:00Z";
            context.hostname = L"test-host";
            context.currentUser = L"test-user";
            context.osBuild = L"test-os";
            context.selectedPid = snapshot.processes.front().pid;
            context.triageContext = &triage;
            return context;
        }

        std::string ReadAll(const std::filesystem::path& path)
        {
            std::ifstream input(path, std::ios::binary);
            return std::string(
                std::istreambuf_iterator<char>(input),
                std::istreambuf_iterator<char>());
        }

        void WriteAll(const std::filesystem::path& path, const std::string& text)
        {
            std::ofstream output(path, std::ios::binary | std::ios::trunc);
            output << text;
        }

        bool ReplaceOnce(
            std::string& text,
            const std::string& before,
            const std::string& after)
        {
            const std::size_t position = text.find(before);
            if (position == std::string::npos)
            {
                return false;
            }
            text.replace(position, before.size(), after);
            return true;
        }

        void TestVerdictAndEnrichedRoundTrips()
        {
            const TriageVerdict verdicts[] = {
                TriageVerdict::Informational,
                TriageVerdict::LowAttention,
                TriageVerdict::MediumAttention,
                TriageVerdict::HighAttention
            };
            for (std::size_t index = 0; index < 4; ++index)
            {
                const ProcessSnapshot snapshot = MakeSnapshot();
                const ServiceCollectionResult services;
                const PersistedTriageContext triage =
                    MakeContext(snapshot, verdicts[index], false, false);
                const std::filesystem::path path =
                    TempPath((L"verdict-" + std::to_wstring(index)).c_str());
                std::wstring error;
                Check(
                    SaveGlassPaneSnapshot(
                        MakeExportContext(snapshot, services, triage),
                        path.wstring(),
                        &error),
                    L"schema4 verdict save");
                SavedSnapshotDocument loaded;
                Check(
                    LoadGlassPaneSnapshot(path.wstring(), loaded, &error),
                    L"schema4 verdict load");
                Check(
                    loaded.metadata.schemaVersion ==
                        GlassPaneSnapshotSchemaVersion,
                    L"current native-evidence schema metadata version");
                const PersistedProcessTriageRecord* record =
                    loaded.triageContext.FindProcess(
                        MakeProcessIdentityKey(snapshot.processes.front()));
                Check(record != nullptr, L"schema4 exact identity retained");
                Check(
                    record != nullptr &&
                        record->summary.authoritativeVerdict == verdicts[index],
                    L"schema4 verdict retained");
                std::error_code ignored;
                std::filesystem::remove(path, ignored);
            }

            const ProcessSnapshot snapshot = MakeSnapshot();
            const ServiceCollectionResult services;
            const PersistedTriageContext triage =
                MakeContext(snapshot, TriageVerdict::Informational, true, false);
            const std::filesystem::path path = TempPath(L"enriched");
            std::wstring error;
            Check(
                SaveGlassPaneSnapshot(
                    MakeExportContext(snapshot, services, triage),
                    path.wstring(),
                    &error),
                L"schema4 enriched save");
            SavedSnapshotDocument loaded;
            Check(
                LoadGlassPaneSnapshot(path.wstring(), loaded, &error),
                L"schema4 enriched load");
            Check(
                loaded.triageContext.selectedRecord.has_value() &&
                    loaded.triageContext.selectedRecord->summary.analysisLevel ==
                        PersistedTriageAnalysisLevel::Enriched &&
                    loaded.triageContext.selectedRecord->summary.enrichedChangedVerdict,
                L"schema4 enriched difference retained");
            std::error_code ignored;
            std::filesystem::remove(path, ignored);
        }

        void TestPidZeroAndDuplicateRejection()
        {
            const ProcessSnapshot snapshot = MakeSnapshot(true);
            const ServiceCollectionResult services;
            const PersistedTriageContext legacyFallback =
                MakeContext(snapshot, TriageVerdict::LowAttention, false, true);
            const std::filesystem::path path = TempPath(L"fallback-pid-zero");
            std::wstring error;
            Check(
                !SaveGlassPaneSnapshot(
                    MakeExportContext(snapshot, services, legacyFallback),
                    path.wstring(),
                    &error),
                L"schema5 rejects legacy fallback authority for PID zero");

            PersistedTriageContext triage =
                MakeContext(snapshot, TriageVerdict::LowAttention, false, false);
            Check(
                SaveGlassPaneSnapshot(
                    MakeExportContext(snapshot, services, triage),
                    path.wstring(),
                    &error),
                L"schema5 native PID zero save");
            SavedSnapshotDocument loaded;
            Check(
                LoadGlassPaneSnapshot(path.wstring(), loaded, &error),
                L"schema5 native PID zero load");
            Check(
                loaded.triageContext.selectedRecord.has_value() &&
                    loaded.triageContext.selectedRecord->identity.pid == 0 &&
                    !loaded.triageContext.selectedRecord->summary.usingFallback &&
                    loaded.triageContext.selectedRecord->summary.analysisLevel ==
                        PersistedTriageAnalysisLevel::Baseline,
                L"schema5 native PID zero authority retained");

            triage.processRecords.push_back(triage.processRecords.front());
            Check(
                !SaveGlassPaneSnapshot(
                    MakeExportContext(snapshot, services, triage),
                    path.wstring(),
                    &error),
                L"schema4 duplicate identity rejected before write");

            const ProcessSnapshot ordinarySnapshot = MakeSnapshot();
            PersistedTriageContext baselineOnly =
                MakeContext(
                    ordinarySnapshot,
                    TriageVerdict::Informational,
                    false,
                    false);
            baselineOnly.selectedRecord.reset();
            Check(
                SaveGlassPaneSnapshot(
                    MakeExportContext(
                        ordinarySnapshot,
                        services,
                        baselineOnly),
                    path.wstring(),
                    &error),
                L"schema4 selected process may persist baseline only");
            Check(
                LoadGlassPaneSnapshot(path.wstring(), loaded, &error) &&
                    !loaded.triageContext.selectedRecord.has_value(),
                L"schema4 null selected enriched record round-trips");

            const PersistedTriageContext distinctContext =
                MakeContext(
                    ordinarySnapshot,
                    TriageVerdict::Informational,
                    false,
                    false);
            ProcessSnapshot duplicateSnapshot = ordinarySnapshot;
            duplicateSnapshot.processes[1].pid =
                duplicateSnapshot.processes[0].pid;
            duplicateSnapshot.processes[1].hasCreationTime =
                duplicateSnapshot.processes[0].hasCreationTime;
            duplicateSnapshot.processes[1].creationTimeFileTime =
                duplicateSnapshot.processes[0].creationTimeFileTime;
            Check(
                !SaveGlassPaneSnapshot(
                    MakeExportContext(
                        duplicateSnapshot,
                        services,
                        distinctContext),
                    path.wstring(),
                    &error),
                L"schema4 duplicate saved process identity rejected");

            ProcessSnapshot overCapSnapshot;
            overCapSnapshot.processes.resize(SnapshotMaxProcesses + 1);
            Check(
                !SaveGlassPaneSnapshot(
                    MakeExportContext(
                        overCapSnapshot,
                        services,
                        baselineOnly),
                    path.wstring(),
                    &error),
                L"schema4 process cap plus one rejected before write");
            std::error_code ignored;
            std::filesystem::remove(path, ignored);
        }

        void TestMalformedTransactionalRejection()
        {
            const ProcessSnapshot snapshot = MakeSnapshot();
            const ServiceCollectionResult services;
            const PersistedTriageContext triage =
                MakeContext(snapshot, TriageVerdict::MediumAttention, false, false);
            const std::filesystem::path validPath = TempPath(L"valid-for-mutation");
            std::wstring error;
            Check(
                SaveGlassPaneSnapshot(
                    MakeExportContext(snapshot, services, triage),
                    validPath.wstring(),
                    &error),
                L"schema4 mutation source save");
            const std::string valid = ReadAll(validPath);

            const struct Mutation
            {
                const char* before;
                const char* after;
                const wchar_t* name;
            } mutations[] = {
                { "\"authoritative_verdict\": \"medium_attention\"",
                  "\"authoritative_verdict\": \"unknown_value\"",
                  L"unknown verdict rejected" },
                { "\"analysis_level\": \"baseline\"",
                  "\"analysis_level\": \"unknown_level\"",
                  L"unknown analysis level rejected" },
                { "\"contributing_domains\": [\"file_signature\"]",
                  "\"contributing_domains\": [\"unknown_domain\"]",
                  L"unknown domain rejected" },
                { "\"evaluation_succeeded\": true",
                  "\"evaluation_succeeded\": false",
                  L"contradictory success state rejected" }
            };

            for (std::size_t index = 0; index < 4; ++index)
            {
                std::string malformed = valid;
                Check(
                    ReplaceOnce(
                        malformed,
                        mutations[index].before,
                        mutations[index].after),
                    L"schema4 mutation applied");
                const std::filesystem::path malformedPath =
                    TempPath((L"malformed-" + std::to_wstring(index)).c_str());
                WriteAll(malformedPath, malformed);

                SavedSnapshotDocument sentinel;
                sentinel.metadata.hostname = L"sentinel-host";
                sentinel.metadata.selectedPid = 0;
                sentinel.snapshot = MakeSnapshot(true);
                sentinel.networkLoaded = true;
                sentinel.network.statusMessage = L"sentinel-network";
                sentinel.serviceContext.attempted = true;
                sentinel.serviceContext.statusMessage = L"sentinel-service";
                sentinel.triageContext = MakeContext(
                    sentinel.snapshot,
                    TriageVerdict::HighAttention,
                    false,
                    true);
                Check(
                    !LoadGlassPaneSnapshot(
                        malformedPath.wstring(),
                        sentinel,
                        &error),
                    mutations[index].name);
                Check(
                    sentinel.metadata.hostname == L"sentinel-host" &&
                        sentinel.metadata.selectedPid == 0 &&
                        sentinel.snapshot.processes.front().pid == 0 &&
                        sentinel.networkLoaded &&
                        sentinel.network.statusMessage == L"sentinel-network" &&
                        sentinel.serviceContext.attempted &&
                        sentinel.serviceContext.statusMessage == L"sentinel-service" &&
                        sentinel.triageContext.selectedRecord.has_value() &&
                        sentinel.triageContext.selectedRecord->summary.usingFallback,
                    L"malformed schema4 load is transactional");
                std::error_code ignored;
                std::filesystem::remove(malformedPath, ignored);
            }

            const struct RawMutation
            {
                std::string replacement;
                const wchar_t* name;
            } rawMutations[] = {
                { std::string("\"") + std::string("\xC0\xAF", 2) + "\"",
                  L"invalid raw UTF-8 rejected" },
                { "\"\\uD800\"", L"lone JSON high surrogate rejected" },
                { "\"first\", \"triage_model_version\": 1",
                  L"duplicate JSON key rejected" }
            };
            for (std::size_t index = 0; index < 3; ++index)
            {
                std::string malformed = valid;
                bool replaced = false;
                if (index < 2)
                {
                    replaced = ReplaceOnce(
                        malformed,
                        "\"Captured deterministically.\"",
                        rawMutations[index].replacement);
                }
                else
                {
                    replaced = ReplaceOnce(
                        malformed,
                        "\"triage_model_version\": 1",
                        "\"triage_model_version\": 1, \"triage_model_version\": 1");
                }
                Check(replaced, L"schema4 raw mutation applied");
                const std::filesystem::path malformedPath =
                    TempPath((L"raw-malformed-" + std::to_wstring(index)).c_str());
                WriteAll(malformedPath, malformed);
                SavedSnapshotDocument sentinel;
                sentinel.metadata.hostname = L"sentinel-host";
                Check(
                    !LoadGlassPaneSnapshot(
                        malformedPath.wstring(),
                        sentinel,
                        &error),
                    rawMutations[index].name);
                Check(
                    sentinel.metadata.hostname == L"sentinel-host",
                    L"raw malformed schema4 load is transactional");
                std::error_code ignored;
                std::filesystem::remove(malformedPath, ignored);
            }
            std::error_code ignored;
            std::filesystem::remove(validPath, ignored);
        }

        void TestSupplementaryUnicodeRoundTrip()
        {
            const ProcessSnapshot snapshot = MakeSnapshot();
            const ServiceCollectionResult services;
            PersistedTriageContext triage =
                MakeContext(
                    snapshot,
                    TriageVerdict::Informational,
                    false,
                    false);
            const std::string supplementaryRationale =
                "Supplementary evidence \xF0\x9F\x94\x8D and \xF0\xA0\x80\x8B retained.";
            const std::string supplementaryStatus =
                "Unicode status \xF0\x9F\xA7\xAA retained.";
            triage.processRecords.front().summary.verdictBasis = {
                supplementaryRationale
            };
            triage.processRecords.front().summary.status = supplementaryStatus;

            Check(
                ValidatePersistedTriageContext(triage).valid,
                L"schema4 supplementary Unicode source context is valid");

            const std::filesystem::path path =
                TempPath(L"supplementary-unicode");
            std::wstring error;
            Check(
                SaveGlassPaneSnapshot(
                    MakeExportContext(snapshot, services, triage),
                    path.wstring(),
                    &error),
                L"schema4 supplementary Unicode save");

            SavedSnapshotDocument loaded;
            const bool loadedSuccessfully =
                LoadGlassPaneSnapshot(path.wstring(), loaded, &error);
            Check(
                loadedSuccessfully,
                L"schema4 supplementary Unicode load");
            const PersistedProcessTriageRecord* record =
                loadedSuccessfully
                    ? loaded.triageContext.FindProcess(
                        MakeProcessIdentityKey(snapshot.processes.front()))
                    : nullptr;
            Check(
                record != nullptr &&
                    record->summary.verdictBasis.size() == 1 &&
                    record->summary.verdictBasis.front() ==
                        supplementaryRationale &&
                    record->summary.status == supplementaryStatus,
                L"schema4 supplementary Unicode bytes round-trip exactly");
            Check(
                loadedSuccessfully &&
                    ValidatePersistedTriageContext(loaded.triageContext).valid,
                L"schema4 supplementary Unicode loaded context is valid");

            std::error_code ignored;
            std::filesystem::remove(path, ignored);
        }

        void TestThousandProcessPerformanceRoundTrip()
        {
            constexpr std::size_t ProcessCount = 1000;
            const ProcessSnapshot snapshot = MakeLargeSnapshot(ProcessCount);
            const ServiceCollectionResult services;
            const PersistedTriageContext triage =
                MakeContext(
                    snapshot,
                    TriageVerdict::Informational,
                    false,
                    false);

            Check(
                snapshot.processes.size() == ProcessCount &&
                    snapshot.processes.size() <= SnapshotMaxProcesses,
                L"schema4 1000-process fixture respects snapshot cap");
            Check(
                triage.processRecords.size() == ProcessCount &&
                    triage.processRecords.size() <=
                        PersistedTriageMaxProcessRecords &&
                    ValidatePersistedTriageContext(triage).valid,
                L"schema4 1000-process source triage is bounded and valid");

            const std::filesystem::path path =
                TempPath(L"1000-process-performance");
            std::wstring error;
            const auto serializeStarted = std::chrono::steady_clock::now();
            const bool saved = SaveGlassPaneSnapshot(
                MakeExportContext(snapshot, services, triage),
                path.wstring(),
                &error);
            const auto serializeElapsed =
                std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now() - serializeStarted);
            Check(saved, L"schema4 1000-process serialize");

            SavedSnapshotDocument loaded;
            const auto parseStarted = std::chrono::steady_clock::now();
            const bool parsed = saved && LoadGlassPaneSnapshot(
                path.wstring(),
                loaded,
                &error);
            const auto parseElapsed =
                std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now() - parseStarted);
            Check(parsed, L"schema4 1000-process parse");

            bool everyIdentityRetained = parsed;
            if (parsed)
            {
                for (const ProcessInfo& process : snapshot.processes)
                {
                    const PersistedProcessTriageRecord* record =
                        loaded.triageContext.FindProcess(
                            MakeProcessIdentityKey(process));
                    if (record == nullptr ||
                        !record->summary.captured ||
                        !record->summary.evaluationSucceeded ||
                        record->summary.usingFallback ||
                        record->summary.authoritativeVerdict !=
                            TriageVerdict::Informational)
                    {
                        everyIdentityRetained = false;
                        break;
                    }
                }
            }
            Check(
                parsed &&
                    loaded.snapshot.processes.size() == ProcessCount &&
                    loaded.triageContext.processRecords.size() == ProcessCount &&
                    loaded.triageContext.processRecords.size() <=
                        PersistedTriageMaxProcessRecords &&
                    ValidatePersistedTriageContext(
                        loaded.triageContext).valid,
                L"schema4 1000-process parsed context is bounded and valid");
            Check(
                everyIdentityRetained,
                L"schema4 1000-process identities and semantics retained");

            std::error_code fileSizeError;
            const std::uintmax_t serializedBytes =
                std::filesystem::file_size(path, fileSizeError);
            std::wcout
                << L"Schema 5 1000-process fixture: serialize "
                << serializeElapsed.count()
                << L" us, parse "
                << parseElapsed.count()
                << L" us, "
                << (fileSizeError ? 0 : serializedBytes)
                << L" bytes.\n";

            std::error_code ignored;
            std::filesystem::remove(path, ignored);
        }
    }

    int RunSavedSnapshotTriageTests()
    {
        failures = 0;
        TestVerdictAndEnrichedRoundTrips();
        TestPidZeroAndDuplicateRejection();
        TestMalformedTransactionalRejection();
        TestSupplementaryUnicodeRoundTrip();
        TestThousandProcessPerformanceRoundTrip();
        if (failures == 0)
        {
            std::wcout << L"Saved Snapshot triage tests passed.\n";
        }
        return failures;
    }
}
