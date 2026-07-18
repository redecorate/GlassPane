#include "Export/SavedSnapshot.h"

#include "Core/Finding.h"
#include "Core/ProcessTree.h"
#include "Core/SnapshotCompare.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

namespace GlassPane::Tests
{
    namespace
    {
        using namespace GlassPane::Core;
        using namespace GlassPane::Export;

        int failures = 0;

        void Check(bool condition, const wchar_t* message)
        {
            if (!condition)
            {
                ++failures;
                std::wcerr << L"FAIL: " << message << L'\n';
            }
        }

        std::filesystem::path Path(const wchar_t* name)
        {
            return std::filesystem::temp_directory_path() /
                (std::wstring(L"glasspane-native-evidence-") + name + L".json");
        }

        ProcessSnapshot MakeSnapshot(std::uint32_t pid = 7300)
        {
            ProcessSnapshot snapshot;
            ProcessInfo process;
            process.pid = pid;
            process.parentPid = 4;
            process.name = L"generic-process";
            process.hasCreationTime = pid != 0;
            process.creationTimeFileTime = pid == 0 ? 0 : 730099;
            process.suspicious = true;
            process.severity = Severity::High;
            process.historicalSuspiciousCaptured = true;
            process.historicalSeverityCaptured = true;
            process.indicators = { L"legacy source metadata must not serialize" };
            process.contextNotes = {
                L"legacy process context metadata must not serialize"
            };
            snapshot.processes.push_back(std::move(process));
            BuildProcessTree(snapshot);
            return snapshot;
        }

        TriageResult MakeTriage()
        {
            TriageResult triage;
            triage.attempted = true;
            triage.success = true;
            triage.status = TriageEngineStatus::Success;
            triage.verdict = TriageVerdict::MediumAttention;
            triage.contributingDomains.insert(EvidenceDomain::Handle);
            triage.previewRationaleEntries.push_back({
                TriageRationaleSection::VerdictBasis,
                "Typed handle evidence contributed."
            });
            return triage;
        }

        PersistedTriageContext MakeTriageContext(
            const ProcessSnapshot& snapshot)
        {
            PersistedProcessTriageRecord record;
            record.identity = MakeProcessIdentityKey(snapshot.processes.front());
            record.summary = ProjectPersistedTriageSummary(
                MakeTriage(),
                PersistedTriageAnalysisLevel::Baseline,
                1).summary;
            return MakePersistedTriageContext({ record }, record);
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

        NativeSourceEvidenceRecord MakeEvidence()
        {
            NativeSourceEvidenceRecord record;
            record.stableRuleId = "native.handle.external-sensitive-access";
            record.title = "Sensitive external process access";
            record.summary =
                "A typed external-process handle granted sensitive access rights.";
            record.details = {
                "Target identity was resolved.",
                "VM operation and write rights were present."
            };
            record.limitations = { "Point-in-time handle metadata." };
            record.domain = EvidenceDomain::Handle;
            record.disposition = ObservationDisposition::ReviewRelevant;
            record.strength = ObservationStrength::Moderate;
            record.confidence = ObservationConfidence::High;
            record.artifactFamily = "Handle";
            record.provenanceSummary = "Direct evidence";
            record.contributedToVerdict = true;
            return record;
        }

        SavedSnapshotExportContext MakeExportContext(
            const ProcessSnapshot& snapshot,
            const ServiceCollectionResult& services,
            const PersistedTriageContext& triage,
            bool includeNativeEvidence = true)
        {
            SavedSnapshotExportContext context;
            context.snapshot = &snapshot;
            context.serviceContext = &services;
            context.glassPaneVersion = L"V0.8.0-Test";
            context.capturedAt = L"2026-07-17T12:00:00Z";
            context.hostname = L"fixture-host";
            context.currentUser = L"fixture-user";
            context.osBuild = L"fixture-build";
            context.selectedPid = snapshot.processes.front().pid;
            context.triageContext = &triage;
            if (includeNativeEvidence)
            {
                SavedNativeSourceEvidenceRecord selected;
                selected.identity = MakeProcessIdentityKey(
                    snapshot.processes.front());
                selected.records = { MakeEvidence() };
                context.nativeSourceEvidence.selectedRecord =
                    std::move(selected);
            }
            return context;
        }

        std::string Read(const std::filesystem::path& path)
        {
            std::ifstream input(path, std::ios::binary);
            return std::string(
                std::istreambuf_iterator<char>(input),
                std::istreambuf_iterator<char>());
        }

        void Write(const std::filesystem::path& path, const std::string& text)
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

        std::size_t AddSchemaFourFallbackFields(std::string& text)
        {
            std::size_t replacements = 0;
            std::size_t position = 0;
            constexpr const char* evaluationField =
                "\"evaluation_succeeded\": true,";
            while ((position = text.find(evaluationField, position)) !=
                std::string::npos)
            {
                const std::size_t lineStart = text.rfind('\n', position);
                const std::size_t lineEnd = text.find('\n', position);
                if (lineEnd == std::string::npos)
                {
                    return 0;
                }
                const std::string indent = text.substr(
                    lineStart == std::string::npos ? 0 : lineStart + 1,
                    position - (lineStart == std::string::npos ? 0 : lineStart + 1));
                const std::string flag =
                    indent + "\"using_fallback\": false,\n";
                text.insert(lineEnd + 1, flag);

                const std::size_t nextEvaluation = text.find(
                    evaluationField,
                    lineEnd + 1 + flag.size());
                const std::size_t status = text.find(
                    "\"status\":",
                    lineEnd + 1 + flag.size());
                if (status == std::string::npos ||
                    (nextEvaluation != std::string::npos && nextEvaluation < status))
                {
                    return 0;
                }
                const std::size_t statusLineStart = text.rfind('\n', status);
                const std::size_t statusIndentStart =
                    statusLineStart == std::string::npos ? 0 : statusLineStart + 1;
                const std::string statusIndent = text.substr(
                    statusIndentStart,
                    status - statusIndentStart);
                const std::string reason =
                    statusIndent + "\"fallback_reason\": \"\",\n";
                text.insert(statusIndentStart, reason);
                position = status + reason.size();
                ++replacements;
            }
            return replacements;
        }

        void TestSchemaFiveNativeEvidenceRoundTrip()
        {
            const ProcessSnapshot snapshot = MakeSnapshot();
            const ServiceCollectionResult services;
            const PersistedTriageContext triage = MakeTriageContext(snapshot);
            const SavedSnapshotExportContext context =
                MakeExportContext(snapshot, services, triage);
            const std::filesystem::path path = Path(L"round-trip");
            std::wstring error;
            Check(
                SaveGlassPaneSnapshot(context, path.wstring(), &error),
                L"schema-5 native evidence snapshot saves");

            const std::string json = Read(path);
            Check(
                json.find("\"schema_version\": 5") != std::string::npos,
                L"schema-5 version emitted");
            Check(
                json.find("\"native_source_evidence\"") != std::string::npos,
                L"native evidence object emitted");
            Check(
                json.find("internal-observation") == std::string::npos,
                L"internal observation IDs are absent");
            Check(
                json.find("legacy_source_suspicious") == std::string::npos &&
                    json.find("legacy_source_severity") == std::string::npos,
                L"schema-5 process rows omit legacy severity fields");
            Check(
                json.find("\"using_fallback\"") == std::string::npos &&
                    json.find("\"fallback_reason\"") == std::string::npos,
                L"schema-5 triage omits legacy fallback fields");
            Check(
                json.find("\"historical_legacy_evidence\"") ==
                    std::string::npos,
                L"live schema-5 capture never infers a historical sidecar from compatibility-shaped fields");
            Check(
                json.find("legacy source metadata must not serialize") ==
                    std::string::npos &&
                    json.find("legacy process context metadata must not serialize") ==
                        std::string::npos,
                L"schema-5 process rows omit legacy source strings");

            SavedSnapshotDocument loaded;
            Check(
                LoadGlassPaneSnapshot(path.wstring(), loaded, &error),
                L"schema-5 native evidence snapshot loads");
            Check(
                loaded.metadata.schemaVersion == 5 &&
                    loaded.nativeSourceEvidenceCaptured,
                L"loaded document identifies captured native evidence");
            Check(
                loaded.nativeSourceEvidence.selectedRecord.has_value() &&
                    loaded.nativeSourceEvidence.selectedRecord->records.size() == 1,
                L"selected native evidence round trips");
            Check(
                !loaded.snapshot.processes.empty() &&
                    !loaded.snapshot.processes.front().suspicious &&
                    loaded.snapshot.processes.front().severity == Severity::None &&
                    !loaded.snapshot.processes.front().historicalSuspiciousCaptured &&
                    !loaded.snapshot.processes.front().historicalSeverityCaptured &&
                    loaded.snapshot.processes.front().indicators.empty() &&
                    loaded.snapshot.processes.front().contextNotes.empty(),
                L"schema-5 process rows do not resurrect legacy source metadata");
            if (loaded.nativeSourceEvidence.selectedRecord.has_value() &&
                !loaded.nativeSourceEvidence.selectedRecord->records.empty())
            {
                const NativeSourceEvidenceRecord& record =
                    loaded.nativeSourceEvidence.selectedRecord->records.front();
                Check(
                    record.stableRuleId ==
                        "native.handle.external-sensitive-access" &&
                        record.contributedToVerdict &&
                        record.domain == EvidenceDomain::Handle,
                    L"native record typed fields round trip");
            }
            std::error_code ignored;
            std::filesystem::remove(path, ignored);
        }

        void TestSchemaFivePartialHandleEvidenceRoundTrip()
        {
            const ProcessSnapshot snapshot = MakeSnapshot();
            const ServiceCollectionResult services;
            const PersistedTriageContext triage = MakeTriageContext(snapshot);
            SavedSnapshotExportContext context =
                MakeExportContext(snapshot, services, triage);

            ProcessEvidenceSnapshot evidence;
            evidence.pid = snapshot.processes.front().pid;
            evidence.processName = snapshot.processes.front().name;
            evidence.handlesStatus.status = L"partial";
            evidence.handlesStatus.message =
                L"Retained handle rows with bounded optional metadata.";
            evidence.handlesStatus.truncated = true;
            evidence.handlesStatus.originalCount = 3;
            evidence.handlesStatus.savedCount = 1;
            evidence.handles.pid = evidence.pid;
            evidence.handles.state = HandleCollectionState::Partial;
            evidence.handles.success = true;
            evidence.handles.statusMessage =
                L"1 handle collected. Additional handles or metadata may not have been evaluated.";
            evidence.handles.systemHandleCount = 120000;
            evidence.handles.systemEntriesScanned = 120000;
            evidence.handles.selectedProcessHandlesMatched = 3;
            evidence.handles.selectedProcessHandlesOmitted = 2;
            evidence.handles.namesAttempted = 1;
            evidence.handles.namesFailed = 1;
            evidence.handles.typeResolutionsAttempted = 1;
            evidence.handles.typeResolutionsResolved = 1;
            evidence.handles.targetsResolved = 1;
            evidence.handles.retentionCapReached = true;
            evidence.handles.nameResolutionCapReached = true;
            evidence.handles.typeOrTargetResolutionPartial = true;

            HandleInfo handle;
            handle.owningPid = evidence.pid;
            handle.handleValue = 0x44;
            handle.objectTypeIndex = 7;
            handle.objectType = L"Thread";
            handle.typeResolved = true;
            handle.grantedAccess = L"0x00000010";
            handle.grantedAccessRaw = 0x10;
            handle.targetPid = 9000;
            handle.targetThreadId = 9010;
            handle.errorMessage = L"Optional object name was not resolved.";
            evidence.handles.handles.push_back(std::move(handle));

            std::vector<ProcessEvidenceSnapshot> processEvidence = {
                evidence
            };
            context.processEvidence = &processEvidence;
            const std::filesystem::path path = Path(L"partial-handles");
            std::wstring error;
            Check(
                SaveGlassPaneSnapshot(context, path.wstring(), &error),
                L"schema-5 partial handle evidence saves");
            const std::string json = Read(path);
            Check(
                json.find("\"schema_version\": 5") != std::string::npos &&
                    json.find("\"collection_state\": \"partial\"") !=
                        std::string::npos &&
                    json.find("\"query_failure_kind\": \"none\"") !=
                        std::string::npos &&
                    json.find("\"selected_process_handles_omitted\": 2") !=
                        std::string::npos,
                L"schema-5 writes additive typed handle partial fields");

            SavedSnapshotDocument loaded;
            Check(
                LoadGlassPaneSnapshot(path.wstring(), loaded, &error),
                L"schema-5 partial handle evidence loads");
            Check(
                loaded.processEvidence.size() == 1,
                L"partial handle process evidence round trips");
            if (loaded.processEvidence.size() == 1)
            {
                const ProcessEvidenceSnapshot& restored =
                    loaded.processEvidence.front();
                Check(
                    restored.handlesStatus.status == L"partial" &&
                        restored.handlesStatus.truncated,
                    L"outer partial handle status round trips");
                Check(
                    restored.handles.state == HandleCollectionState::Partial &&
                        restored.handles.success &&
                        restored.handles.selectedProcessHandlesMatched == 3 &&
                        restored.handles.selectedProcessHandlesOmitted == 2 &&
                        restored.handles.retentionCapReached &&
                        restored.handles.nameResolutionCapReached &&
                        restored.handles.typeOrTargetResolutionPartial,
                    L"typed partial handle state and counters round trip");
                Check(
                    restored.handles.handles.size() == 1 &&
                        restored.handles.handles.front().objectTypeIndex == 7 &&
                        restored.handles.handles.front().targetThreadId == 9010,
                    L"retained handle typed identity round trips");
            }

            std::string oldSchemaFive = json;
            Check(
                ReplaceOnce(
                    oldSchemaFive,
                    "\"collection_state\": \"partial\",\n",
                    ""),
                L"old schema-5 compatibility fixture removes additive state");
            const std::filesystem::path oldPath =
                Path(L"partial-handles-old-schema-five");
            Write(oldPath, oldSchemaFive);
            SavedSnapshotDocument oldLoaded;
            Check(
                LoadGlassPaneSnapshot(oldPath.wstring(), oldLoaded, &error) &&
                    oldLoaded.processEvidence.size() == 1 &&
                    oldLoaded.processEvidence.front().handles.state ==
                        HandleCollectionState::Partial,
                L"old schema-5 success plus outer partial status derives typed partial state");

            std::error_code ignored;
            std::filesystem::remove(path, ignored);
            std::filesystem::remove(oldPath, ignored);
        }

        void TestPidZeroAndEmptyCaptureAreDistinct()
        {
            const ProcessSnapshot snapshot = MakeSnapshot(0);
            const ServiceCollectionResult services;
            const PersistedTriageContext triage = MakeTriageContext(snapshot);
            SavedSnapshotExportContext context =
                MakeExportContext(snapshot, services, triage);
            const std::filesystem::path pidZeroPath = Path(L"pid-zero");
            std::wstring error;
            Check(
                SaveGlassPaneSnapshot(
                    context,
                    pidZeroPath.wstring(),
                    &error),
                L"PID-zero native evidence saves");
            SavedSnapshotDocument loaded;
            Check(
                LoadGlassPaneSnapshot(
                    pidZeroPath.wstring(),
                    loaded,
                    &error) &&
                    loaded.nativeSourceEvidence.selectedRecord.has_value() &&
                    loaded.nativeSourceEvidence.selectedRecord->identity.pid == 0,
                L"PID-zero selected identity remains explicit");

            context.nativeSourceEvidence.selectedRecord.reset();
            const std::filesystem::path emptyPath = Path(L"empty");
            Check(
                SaveGlassPaneSnapshot(context, emptyPath.wstring(), &error),
                L"explicit no-selected-evidence context saves");
            Check(
                LoadGlassPaneSnapshot(emptyPath.wstring(), loaded, &error) &&
                    loaded.nativeSourceEvidenceCaptured &&
                    !loaded.nativeSourceEvidence.selectedRecord.has_value(),
                L"schema-5 empty capture is distinct from PID zero");
            std::error_code ignored;
            std::filesystem::remove(pidZeroPath, ignored);
            std::filesystem::remove(emptyPath, ignored);
        }

        void TestSchemaFourDoesNotRequireNativeEvidence()
        {
            const ProcessSnapshot snapshot = MakeSnapshot();
            const ServiceCollectionResult services;
            const PersistedTriageContext triage = MakeTriageContext(snapshot);
            const SavedSnapshotExportContext context =
                MakeExportContext(snapshot, services, triage);
            const std::filesystem::path path = Path(L"schema-four");
            std::wstring error;
            Check(
                SaveGlassPaneSnapshot(context, path.wstring(), &error),
                L"source schema-5 fixture saves");
            std::string json = Read(path);
            Check(
                ReplaceOnce(
                    json,
                    "\"schema_version\": 5",
                    "\"schema_version\": 4"),
                L"schema version changed for compatibility fixture");
            Check(
                AddSchemaFourFallbackFields(json) == 2,
                L"schema-4 compatibility fixture restores fallback fields");
            const std::size_t nativeStart =
                json.find("  \"native_source_evidence\": {");
            const std::size_t processesStart =
                json.find("  \"processes\": [", nativeStart);
            Check(
                nativeStart != std::string::npos &&
                    processesStart != std::string::npos,
                L"native evidence block located");
            if (nativeStart != std::string::npos &&
                processesStart != std::string::npos)
            {
                json.erase(nativeStart, processesStart - nativeStart);
            }
            Write(path, json);

            SavedSnapshotDocument loaded;
            Check(
                LoadGlassPaneSnapshot(path.wstring(), loaded, &error),
                L"schema 4 loads without native evidence field");
            Check(
                loaded.metadata.schemaVersion == 4 &&
                    !loaded.nativeSourceEvidenceCaptured &&
                    !loaded.nativeSourceEvidence.selectedRecord.has_value(),
                L"schema 4 reports native evidence not captured");
            Check(
                loaded.triageContext.selectedRecord.has_value(),
                L"schema-4 captured triage semantics remain available");
            std::error_code ignored;
            std::filesystem::remove(path, ignored);
        }

        void TestMalformedEvidenceRejectsTransactionally()
        {
            const ProcessSnapshot snapshot = MakeSnapshot();
            const ServiceCollectionResult services;
            const PersistedTriageContext triage = MakeTriageContext(snapshot);
            const SavedSnapshotExportContext context =
                MakeExportContext(snapshot, services, triage);
            const std::filesystem::path path = Path(L"malformed");
            std::wstring error;
            Check(
                SaveGlassPaneSnapshot(context, path.wstring(), &error),
                L"malformed source fixture saves");
            std::string json = Read(path);
            Check(
                ReplaceOnce(
                    json,
                    "\"domain\": \"handle\"",
                    "\"domain\": \"unknown_future_domain\""),
                L"domain token corrupted");
            Write(path, json);

            SavedSnapshotDocument sentinel;
            sentinel.metadata.hostname = L"sentinel";
            sentinel.nativeSourceEvidenceCaptured = true;
            Check(
                !LoadGlassPaneSnapshot(path.wstring(), sentinel, &error),
                L"unknown native evidence enum is rejected");
            Check(
                sentinel.metadata.hostname == L"sentinel" &&
                    sentinel.nativeSourceEvidenceCaptured,
                L"malformed native evidence preserves destination transactionally");

            Check(
                SaveGlassPaneSnapshot(context, path.wstring(), &error),
                L"contradictory source fixture saves before mutation");
            json = Read(path);
            Check(
                ReplaceOnce(
                    json,
                    "\"domain\": \"handle\"",
                    "\"domain\": \"collection_quality\""),
                L"contributing domain changed to a non-behavior domain");
            Write(path, json);

            sentinel.metadata.hostname = L"sentinel-two";
            sentinel.nativeSourceEvidenceCaptured = true;
            Check(
                !LoadGlassPaneSnapshot(path.wstring(), sentinel, &error),
                L"contradictory native evidence contribution is rejected by the schema parser");
            Check(
                sentinel.metadata.hostname == L"sentinel-two" &&
                    sentinel.nativeSourceEvidenceCaptured,
                L"contradictory native evidence preserves destination transactionally");
            std::error_code ignored;
            std::filesystem::remove(path, ignored);
        }

        void TestCapsAndIdentityValidation()
        {
            const ProcessSnapshot snapshot = MakeSnapshot();
            const ServiceCollectionResult services;
            const PersistedTriageContext triage = MakeTriageContext(snapshot);
            SavedSnapshotExportContext context =
                MakeExportContext(snapshot, services, triage);
            context.nativeSourceEvidence.selectedRecord->records.assign(
                NativeSourceEvidenceMaxRecords + 1,
                MakeEvidence());
            const std::filesystem::path path = Path(L"over-cap");
            std::wstring error;
            Check(
                !SaveGlassPaneSnapshot(context, path.wstring(), &error),
                L"native evidence cap plus one is rejected");

            context = MakeExportContext(snapshot, services, triage);
            ++context.nativeSourceEvidence.selectedRecord->identity.creationTimeFileTime;
            Check(
                !SaveGlassPaneSnapshot(context, path.wstring(), &error),
                L"native evidence identity mismatch is rejected");
            std::error_code ignored;
            std::filesystem::remove(path, ignored);
        }

        void TestHistoricalFindingKindsRemainStable()
        {
            static_assert(
                static_cast<std::uint32_t>(
                    ExistingFindingKind::RelationshipEncodedCommand) == 1U,
                "Historical relationship finding identity changed.");
            static_assert(
                static_cast<std::uint32_t>(
                    ExistingFindingKind::IdentitySignerMismatch) == 6U,
                "Historical identity/signer finding identity changed.");
            static_assert(
                static_cast<std::uint32_t>(
                    ExistingFindingKind::AggregatedModuleIndicators) == 29U,
                "Historical finding identity range changed.");

            const std::vector<Finding> historical = {
                { FindingSeverity::Low, L"low", L"", {}, L"", ExistingFindingKind::RelationshipEncodedCommand },
                { FindingSeverity::High, L"high", L"", {}, L"", ExistingFindingKind::AggregatedModuleIndicators }
            };
            Check(
                HighestFindingSeverity(historical) == FindingSeverity::High,
                L"historical Finding severity helper remains available without the legacy runtime engine");
        }

        void TestSchemaFiveRejectsLegacyFallbackAuthority()
        {
            const ProcessSnapshot snapshot = MakeSnapshot();
            const ServiceCollectionResult services;
            PersistedProcessTriageRecord record;
            record.identity = MakeProcessIdentityKey(snapshot.processes.front());
            record.summary = MakeHistoricalLegacyFallbackSummary(
                    TriageVerdict::HighAttention,
                    1,
                    "historical compatibility fallback");
            Check(
                ValidatePersistedTriageSummary(record.summary).valid,
                L"legacy fallback fixture is valid persisted compatibility data");
            const PersistedTriageContext triage =
                MakePersistedTriageContext({ record }, record);
            const SavedSnapshotExportContext context =
                MakeExportContext(snapshot, services, triage);
            const std::filesystem::path path = Path(L"legacy-fallback-rejected");
            std::wstring error;
            Check(
                !SaveGlassPaneSnapshot(context, path.wstring(), &error),
                L"schema-5 current capture rejects legacy fallback authority");
            Check(
                error.find(L"legacy-fallback") != std::wstring::npos,
                L"schema-5 legacy fallback rejection is explicit");
            std::error_code ignored;
            std::filesystem::remove(path, ignored);
        }

        void TestHistoricalSchemaResavePreservesHonestSidecar()
        {
            const ProcessSnapshot snapshot = MakeSnapshot();
            const ServiceCollectionResult services;
            const PersistedTriageContext triage = MakeTriageContext(snapshot);
            const SavedSnapshotExportContext sourceContext =
                MakeExportContext(snapshot, services, triage);
            const std::filesystem::path oldPath = Path(L"historical-source");
            const std::filesystem::path upgradedPath = Path(L"historical-upgraded");
            std::wstring error;
            Check(
                SaveGlassPaneSnapshot(sourceContext, oldPath.wstring(), &error),
                L"historical conversion source fixture saves");
            std::string json = Read(oldPath);
            Check(
                ReplaceOnce(
                    json,
                    "\"schema_version\": 5",
                    "\"schema_version\": 4"),
                L"historical conversion fixture becomes schema 4");
            Check(
                AddSchemaFourFallbackFields(json) == 2,
                L"historical conversion fixture receives schema-4 fields");
            const std::size_t nativeStart =
                json.find("  \"native_source_evidence\": {");
            const std::size_t processesStart =
                json.find("  \"processes\": [", nativeStart);
            Check(
                nativeStart != std::string::npos &&
                    processesStart != std::string::npos,
                L"historical conversion native block located");
            if (nativeStart != std::string::npos &&
                processesStart != std::string::npos)
            {
                json.erase(nativeStart, processesStart - nativeStart);
            }
            Check(
                ReplaceOnce(
                    json,
                    "      \"creation_time_filetime\": \"730099\"\n",
                    "      \"creation_time_filetime\": \"730099\",\n"
                    "      \"legacy_source_suspicious\": false,\n"
                    "      \"legacy_source_severity\": \"None\",\n"
                    "      \"indicators\": [\"historical typed wording\"],\n"
                    "      \"context_notes\": [\"historical collection note\"]\n"),
                L"schema-4 historical metadata injected");
            Write(oldPath, json);

            SavedSnapshotDocument oldDocument;
            Check(
                LoadGlassPaneSnapshot(oldPath.wstring(), oldDocument, &error),
                L"schema-4 historical source fixture loads");
            Check(
                !oldDocument.snapshot.processes.empty() &&
                    oldDocument.snapshot.processes.front().historicalSeverityCaptured &&
                    oldDocument.snapshot.processes.front().severity == Severity::None &&
                    oldDocument.snapshot.processes.front().indicators.size() == 1,
                L"captured historical None remains distinct from uncaptured row severity");

            SavedSnapshotExportContext upgraded;
            upgraded.snapshot = &oldDocument.snapshot;
            upgraded.serviceContext = &oldDocument.serviceContext;
            upgraded.glassPaneVersion = L"V0.8.0-Test";
            upgraded.capturedAt = L"2026-07-17T12:00:00Z";
            upgraded.hostname = L"fixture-host";
            upgraded.currentUser = L"fixture-user";
            upgraded.osBuild = L"fixture-build";
            upgraded.selectedPid = oldDocument.metadata.selectedPid;
            upgraded.triageContext = &oldDocument.triageContext;
            upgraded.preserveHistoricalLegacyEvidence = true;
            Check(
                SaveGlassPaneSnapshot(upgraded, upgradedPath.wstring(), &error),
                L"historical schema-4 state resaves as schema 5");

            const std::string upgradedJson = Read(upgradedPath);
            Check(
                upgradedJson.find("\"historical_legacy_evidence\"") !=
                    std::string::npos &&
                    upgradedJson.find("historical typed wording") !=
                        std::string::npos &&
                    upgradedJson.find("\"process_severity_captured\": true") !=
                        std::string::npos &&
                    upgradedJson.find("\"process_severity\": \"None\"") !=
                        std::string::npos,
                L"schema-5 sidecar preserves captured process metadata and source wording");

            SavedSnapshotDocument upgradedDocument;
            Check(
                LoadGlassPaneSnapshot(
                    upgradedPath.wstring(),
                    upgradedDocument,
                    &error),
                L"schema-5 historical sidecar loads");
            const ProcessInfo& restored =
                upgradedDocument.snapshot.processes.front();
            Check(
                restored.historicalSeverityCaptured &&
                    restored.severity == Severity::None &&
                    restored.indicators ==
                        std::vector<std::wstring>{ L"historical typed wording" } &&
                    restored.contextNotes ==
                        std::vector<std::wstring>{ L"historical collection note" },
                L"schema-5 historical sidecar round trips without native fabrication");

            SnapshotSourceEvidenceCaptureContext compareContext;
            compareContext.modelKind =
                SnapshotSourceEvidenceModelKind::HistoricalLegacy;
            const ProcessSnapshotCapture compareCapture =
                CaptureProcessSnapshotForCompare(
                    upgradedDocument.snapshot,
                    nullptr,
                    false,
                    L"historical-upgraded",
                    &upgradedDocument.triageContext,
                    &compareContext);
            const auto indicator = std::find_if(
                compareCapture.findings.begin(),
                compareCapture.findings.end(),
                [](const SnapshotFindingRecord& record) {
                    return record.title == L"historical typed wording";
                });
            Check(
                indicator != compareCapture.findings.end() &&
                    !indicator->severityCaptured &&
                    std::wstring(SnapshotFindingSeverityText(*indicator)) ==
                        L"Not captured",
                L"historical indicator row severity remains explicitly not captured");

            std::error_code ignored;
            std::filesystem::remove(oldPath, ignored);
            std::filesystem::remove(upgradedPath, ignored);
        }

        void TestHistoricalSidecarValidationIsTransactional()
        {
            ProcessSnapshot snapshot = MakeSnapshot();
            snapshot.processes.front().historicalSeverityCaptured = true;
            snapshot.processes.front().historicalSuspiciousCaptured = true;
            const ServiceCollectionResult services;
            const PersistedTriageContext triage = MakeTriageContext(snapshot);
            SavedSnapshotExportContext context =
                MakeExportContext(snapshot, services, triage);
            context.preserveHistoricalLegacyEvidence = true;
            const std::filesystem::path path = Path(L"historical-malformed");
            std::wstring error;
            Check(
                SaveGlassPaneSnapshot(context, path.wstring(), &error),
                L"historical validation source fixture saves");
            std::string json = Read(path);
            Check(
                ReplaceOnce(
                    json,
                    "\"model_version\": 1,\n    \"process_records\"",
                    "\"model_version\": 2,\n    \"process_records\""),
                L"historical sidecar model version corrupted");
            Write(path, json);

            SavedSnapshotDocument sentinel;
            sentinel.metadata.hostname = L"sentinel";
            Check(
                !LoadGlassPaneSnapshot(path.wstring(), sentinel, &error),
                L"malformed historical sidecar is rejected");
            Check(
                sentinel.metadata.hostname == L"sentinel",
                L"malformed historical sidecar preserves destination transactionally");

            snapshot.processes.front().historicalSeverityCaptured = false;
            snapshot.processes.front().severity = Severity::High;
            context = MakeExportContext(snapshot, services, triage);
            context.preserveHistoricalLegacyEvidence = true;
            Check(
                !SaveGlassPaneSnapshot(context, path.wstring(), &error),
                L"contradictory historical capture metadata is rejected before writing");
            std::error_code ignored;
            std::filesystem::remove(path, ignored);
        }
    }

    int RunSavedSnapshotNativeEvidenceTests()
    {
        failures = 0;
        TestSchemaFiveNativeEvidenceRoundTrip();
        TestSchemaFivePartialHandleEvidenceRoundTrip();
        TestPidZeroAndEmptyCaptureAreDistinct();
        TestSchemaFourDoesNotRequireNativeEvidence();
        TestMalformedEvidenceRejectsTransactionally();
        TestCapsAndIdentityValidation();
        TestHistoricalFindingKindsRemainStable();
        TestSchemaFiveRejectsLegacyFallbackAuthority();
        TestHistoricalSchemaResavePreservesHonestSidecar();
        TestHistoricalSidecarValidationIsTransactional();
        if (failures == 0)
        {
            std::wcout << L"Saved snapshot native evidence tests passed.\n";
        }
        return failures;
    }
}
