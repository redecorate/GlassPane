#include "Core/SnapshotCompare.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <optional>
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
            std::uint32_t pid = 42,
            std::uint64_t creationTime = 100)
        {
            ProcessInfo process;
            process.pid = pid;
            process.parentPid = 4;
            process.name = L"generic-process.exe";
            process.executablePath = L"C:\\Generic\\generic-process.exe";
            process.commandLine = L"generic-process.exe --mode audit";
            process.architecture = L"x64";
            process.hasCreationTime = true;
            process.creationTimeFileTime = creationTime;
            process.creationTimeLocal = L"2026-07-16 10:00:00";
            process.severity = Severity::Low;
            process.suspicious = true;
            process.historicalSeverityCaptured = true;
            process.historicalSuspiciousCaptured = true;
            process.indicators = { L"Generic legacy indicator" };
            process.contextNotes = { L"Generic context note" };
            return process;
        }

        ProcessSnapshot MakeSnapshot(const ProcessInfo& process)
        {
            ProcessSnapshot snapshot;
            snapshot.processes.push_back(process);
            snapshot.indexByPid.emplace(process.pid, 0);
            return snapshot;
        }

        NativeSourceEvidenceRecord MakeNativeEvidence(
            const std::string& stableRuleId,
            const std::string& title = "Presentation title")
        {
            NativeSourceEvidenceRecord record;
            record.stableRuleId = stableRuleId;
            record.title = title;
            record.summary = "Presentation summary";
            record.details = { "Detail A", "Detail B" };
            record.domain = EvidenceDomain::CommandLine;
            record.disposition =
                ObservationDisposition::ReviewRelevant;
            record.strength = ObservationStrength::Weak;
            record.confidence = ObservationConfidence::Medium;
            record.artifactFamily = "Process";
            record.provenanceSummary = "Derived evidence";
            return record;
        }

        SnapshotSelectedNativeSourceEvidenceRecord MakeSelectedNativeEvidence(
            const ProcessInfo& process,
            std::vector<NativeSourceEvidenceRecord> records)
        {
            SnapshotSelectedNativeSourceEvidenceRecord selected;
            selected.processKey = {
                process.pid,
                process.hasCreationTime,
                process.creationTimeFileTime
            };
            selected.pid = process.pid;
            selected.processName = process.name;
            selected.records = std::move(records);
            return selected;
        }

        ProcessSnapshotCapture MakeNativeCapture(
            const ProcessInfo& process,
            std::vector<NativeSourceEvidenceRecord> records,
            std::uint32_t modelVersion =
                NativeSourceEvidenceModelVersion)
        {
            ProcessSnapshotCapture capture;
            capture.captured = true;
            capture.sourceEvidenceModelKind =
                SnapshotSourceEvidenceModelKind::Native;
            capture.nativeSourceEvidenceCaptured = true;
            capture.nativeSourceEvidenceModelVersion = modelVersion;
            capture.selectedNativeSourceEvidence =
                MakeSelectedNativeEvidence(
                    process,
                    std::move(records));
            return capture;
        }

        TriageResult MakeTriageResult(
            TriageVerdict verdict,
            std::vector<EvidenceDomain> contributingDomains,
            std::vector<TriageRationaleEntry> previewRationale,
            const std::string& status)
        {
            TriageResult result;
            result.attempted = true;
            result.success = true;
            result.status = TriageEngineStatus::Success;
            result.verdict = verdict;
            result.contributingDomains.insert(
                contributingDomains.begin(),
                contributingDomains.end());
            result.previewRationaleEntries = std::move(previewRationale);
            result.statusMessage = status;
            return result;
        }

        PersistedTriageSummary MakeBaselineSummary(
            const TriageResult& result,
            std::size_t sourceEvidenceCount)
        {
            const PersistedTriageProjectionResult projection =
                ProjectPersistedTriageSummary(
                    result,
                    PersistedTriageAnalysisLevel::Baseline,
                    sourceEvidenceCount);
            Check(projection.success, L"baseline persisted projection succeeds");
            return projection.summary;
        }

        PersistedTriageSummary MakeEnrichedSummary(
            const TriageResult& result,
            const TriageResult& baseline,
            std::size_t sourceEvidenceCount)
        {
            const PersistedTriageProjectionResult projection =
                ProjectPersistedTriageSummary(
                    result,
                    PersistedTriageAnalysisLevel::Enriched,
                    sourceEvidenceCount,
                    &baseline);
            Check(projection.success, L"enriched persisted projection succeeds");
            return projection.summary;
        }

        PersistedTriageSummary MakeHistoricalLegacyFallbackSummary(
            TriageVerdict verdict,
            std::size_t sourceEvidenceCount,
            std::string reason,
            std::string status = {})
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
            summary.status = std::move(status);
            return summary;
        }

        PersistedTriageContext MakeContext(
            const ProcessInfo& process,
            PersistedTriageSummary summary,
            std::optional<PersistedTriageSummary> selectedSummary =
                std::nullopt)
        {
            PersistedProcessTriageRecord record;
            record.identity = MakeProcessIdentityKey(process);
            record.summary = std::move(summary);
            std::optional<PersistedProcessTriageRecord> selectedRecord;
            if (selectedSummary.has_value())
            {
                selectedRecord = PersistedProcessTriageRecord{
                    MakeProcessIdentityKey(process),
                    std::move(selectedSummary.value())
                };
            }
            PersistedTriageContext context = MakePersistedTriageContext(
                { std::move(record) },
                std::move(selectedRecord));
            Check(
                ValidatePersistedTriageContext(context).valid,
                L"test persisted context validates");
            return context;
        }

        const SnapshotChangedField* FindField(
            const SnapshotProcessChange& change,
            const std::wstring& name)
        {
            const auto iterator = std::find_if(
                change.fields.begin(),
                change.fields.end(),
                [&](const SnapshotChangedField& field) {
                    return field.field == name;
                });
            return iterator == change.fields.end() ? nullptr : &*iterator;
        }

        const SnapshotChangedField* FindField(
            const std::vector<SnapshotChangedField>& fields,
            const std::wstring& name)
        {
            const auto iterator = std::find_if(
                fields.begin(),
                fields.end(),
                [&](const SnapshotChangedField& field) {
                    return field.field == name;
                });
            return iterator == fields.end() ? nullptr : &*iterator;
        }

        bool SameFields(
            const std::vector<SnapshotChangedField>& left,
            const std::vector<SnapshotChangedField>& right)
        {
            if (left.size() != right.size())
            {
                return false;
            }
            for (std::size_t index = 0; index < left.size(); ++index)
            {
                if (left[index].field != right[index].field ||
                    left[index].baselineValue != right[index].baselineValue ||
                    left[index].currentValue != right[index].currentValue)
                {
                    return false;
                }
            }
            return true;
        }

        void TestCaptureUsesExactProcessIdentity()
        {
            const ProcessInfo process = MakeProcess();
            const ProcessSnapshot snapshot = MakeSnapshot(process);
            const TriageResult result = MakeTriageResult(
                TriageVerdict::LowAttention,
                { EvidenceDomain::FilePath },
                {
                    { TriageRationaleSection::VerdictBasis,
                        "One weak path observation contributed." }
                },
                "Baseline triage completed.");
            PersistedTriageContext context = MakeContext(
                process,
                MakeBaselineSummary(result, 2));

            const ProcessSnapshotCapture capture =
                CaptureProcessSnapshotForCompare(
                    snapshot,
                    nullptr,
                    false,
                    L"capture-one",
                    &context);
            Check(capture.triageContextCaptured, L"triage context captured flag");
            Check(capture.triageContextValid, L"triage context valid flag");
            CheckEqual(capture.triageCapturedProcessCount, std::size_t{ 1 }, L"captured triage process count");
            CheckEqual(capture.triageNotCapturedProcessCount, std::size_t{ 0 }, L"not-captured triage process count");
            Check(capture.processes.front().authoritativeTriage.captured, L"exact identity triage attached");
            CheckEqual(
                capture.processes.front().authoritativeTriage.authoritativeVerdict,
                TriageVerdict::LowAttention,
                L"exact identity captured verdict");

            context.processRecords.front().identity.creationTimeFileTime += 1;
            const ProcessSnapshotCapture mismatched =
                CaptureProcessSnapshotForCompare(
                    snapshot,
                    nullptr,
                    false,
                    L"capture-mismatch",
                    &context);
            Check(!mismatched.processes.front().authoritativeTriage.captured, L"creation-time mismatch remains not captured");
            CheckEqual(mismatched.triageCapturedProcessCount, std::size_t{ 0 }, L"mismatch captured count zero");
        }

        void TestMixedCapturedAndNotCapturedComparison()
        {
            const ProcessInfo process = MakeProcess();
            const ProcessSnapshot snapshot = MakeSnapshot(process);
            const ProcessSnapshotCapture legacyCapture =
                CaptureProcessSnapshotForCompare(
                    snapshot,
                    nullptr,
                    false,
                    L"legacy");

            const TriageResult result = MakeTriageResult(
                TriageVerdict::Informational,
                {},
                {
                    { TriageRationaleSection::VerdictBasis,
                        "No review-relevant baseline evidence contributed." }
                },
                "Baseline triage completed.");
            PersistedTriageContext context = MakeContext(
                process,
                MakeBaselineSummary(result, 1));
            const ProcessSnapshotCapture semanticCapture =
                CaptureProcessSnapshotForCompare(
                    snapshot,
                    nullptr,
                    false,
                    L"semantic",
                    &context);

            const SnapshotCompareResult comparison = CompareSnapshots(
                legacyCapture,
                semanticCapture);
            Check(comparison.triageCompared, L"mixed triage comparison attempted");
            CheckEqual(comparison.baselineTriageCapturedProcessCount, std::size_t{ 0 }, L"mixed baseline captured count");
            CheckEqual(comparison.currentTriageCapturedProcessCount, std::size_t{ 1 }, L"mixed current captured count");
            CheckEqual(comparison.comparableTriageProcessCount, std::size_t{ 0 }, L"mixed comparable count");
            CheckEqual(comparison.triageAvailabilityMismatchCount, std::size_t{ 1 }, L"mixed availability mismatch count");
            CheckEqual(comparison.changedProcesses.size(), std::size_t{ 1 }, L"mixed capture emits one process change");
            const SnapshotProcessChange& change = comparison.changedProcesses.front();
            const SnapshotChangedField* captureField = FindField(
                change,
                L"Authoritative triage capture");
            Check(captureField != nullptr, L"mixed capture field exists");
            if (captureField != nullptr)
            {
                CheckEqual(captureField->baselineValue, std::wstring(L"Not captured"), L"mixed baseline not captured text");
                CheckEqual(captureField->currentValue, std::wstring(L"Captured"), L"mixed current captured text");
            }
            Check(
                FindField(change, L"Authoritative triage verdict") == nullptr,
                L"mixed capture does not compare fabricated default verdict");
        }

        void TestSemanticTriageFieldsAndStableOrder()
        {
            const ProcessInfo process = MakeProcess();
            const ProcessSnapshot snapshot = MakeSnapshot(process);
            const TriageResult baselineResult = MakeTriageResult(
                TriageVerdict::LowAttention,
                { EvidenceDomain::FilePath },
                {
                    { TriageRationaleSection::VerdictBasis,
                        "One weak path observation contributed." },
                    { TriageRationaleSection::SupportingContext,
                        "A neutral service association was observed." },
                    { TriageRationaleSection::CollectionLimitations,
                        "Module metadata was not captured." },
                    { TriageRationaleSection::EvidenceIntegrityContext,
                        "Imported evidence scope was bounded." },
                    { TriageRationaleSection::UnresolvedCorrelations,
                        "A path correlation remained incomplete." }
                },
                "Baseline triage completed.");
            const TriageResult enrichedResult = MakeTriageResult(
                TriageVerdict::MediumAttention,
                { EvidenceDomain::FilePath, EvidenceDomain::FileSignature },
                {
                    { TriageRationaleSection::VerdictBasis,
                        "Independent path and signature evidence contributed." },
                    { TriageRationaleSection::CompletedCorrelations,
                        "Executable path and signature evidence were correlated." },
                    { TriageRationaleSection::SupportingContext,
                        "Public network activity was retained as context." },
                    { TriageRationaleSection::CollectionLimitations,
                        "Token details were not captured." },
                    { TriageRationaleSection::EvidenceIntegrityContext,
                        "Evidence was imported from a bounded local snapshot." }
                },
                "Enriched triage completed.");

            PersistedTriageContext baselineContext = MakeContext(
                process,
                MakeBaselineSummary(baselineResult, 4),
                MakeBaselineSummary(baselineResult, 4));
            PersistedTriageContext currentContext = MakeContext(
                process,
                MakeBaselineSummary(baselineResult, 4),
                MakeEnrichedSummary(enrichedResult, baselineResult, 6));
            const ProcessSnapshotCapture baseline =
                CaptureProcessSnapshotForCompare(
                    snapshot, nullptr, false, L"baseline", &baselineContext);
            const ProcessSnapshotCapture current =
                CaptureProcessSnapshotForCompare(
                    snapshot, nullptr, false, L"current", &currentContext);
            CheckEqual(
                current.processes.front().authoritativeTriage.analysisLevel,
                PersistedTriageAnalysisLevel::Baseline,
                L"selected enriched record does not override process-wide baseline");
            Check(current.selectedAuthoritativeTriage.has_value(), L"selected enriched record captured separately");
            if (current.selectedAuthoritativeTriage.has_value())
            {
                CheckEqual(
                    current.selectedAuthoritativeTriage->summary.analysisLevel,
                    PersistedTriageAnalysisLevel::Enriched,
                    L"separate selected record retains enriched analysis");
            }

            const SnapshotCompareResult first = CompareSnapshots(baseline, current);
            const SnapshotCompareResult second = CompareSnapshots(baseline, current);
            CheckEqual(first.comparableTriageProcessCount, std::size_t{ 1 }, L"semantic comparable triage count");
            Check(first.changedProcesses.empty(), L"selected enrichment does not create process-wide change");
            Check(first.selectedTriage.sameIdentity, L"selected triage exact identity matched");
            Check(first.selectedTriage.safeIdentity, L"selected triage identity is safe");
            Check(first.selectedTriage.semanticCompared, L"selected triage compared separately");
            const std::vector<SnapshotChangedField>& fields =
                first.selectedTriage.fields;
            Check(FindField(fields, L"Authoritative triage verdict") != nullptr, L"selected verdict field compared");
            Check(FindField(fields, L"Triage analysis level") != nullptr, L"selected analysis level compared");
            Check(FindField(fields, L"Enriched evidence changed verdict") != nullptr, L"selected enriched-change flag compared");
            Check(FindField(fields, L"Triage contributing domains") != nullptr, L"selected domains compared");
            Check(FindField(fields, L"Triage completed correlations") != nullptr, L"selected correlation summaries compared");
            Check(FindField(fields, L"Triage collection limitations") != nullptr, L"selected limitations compared");
            Check(FindField(fields, L"Triage evidence-integrity context") != nullptr, L"selected integrity context compared");
            Check(FindField(fields, L"Triage source-evidence count") != nullptr, L"selected source evidence count compared");
            Check(FindField(fields, L"Triage status") != nullptr, L"selected status compared");
            Check(
                SameFields(fields, second.selectedTriage.fields),
                L"selected semantic changed-field order deterministic");

            for (const SnapshotChangedField& field : fields)
            {
                Check(field.baselineValue.find(L"observation:") == std::wstring::npos, L"baseline compare output has no observation ID");
                Check(field.currentValue.find(L"observation:") == std::wstring::npos, L"current compare output has no observation ID");
                Check(field.baselineValue.find(L"correlation:") == std::wstring::npos, L"baseline compare output has no correlation ID");
                Check(field.currentValue.find(L"correlation:") == std::wstring::npos, L"current compare output has no correlation ID");
            }
        }

        void TestValidNotCapturedContextsAreNotCompared()
        {
            const ProcessInfo process = MakeProcess();
            const ProcessSnapshot snapshot = MakeSnapshot(process);
            PersistedTriageContext baselineContext = MakeContext(
                process,
                MakeNotCapturedPersistedTriageSummary());
            PersistedTriageContext currentContext = MakeContext(
                process,
                MakeNotCapturedPersistedTriageSummary());

            const SnapshotCompareResult comparison = CompareSnapshots(
                CaptureProcessSnapshotForCompare(
                    snapshot, nullptr, false, L"baseline", &baselineContext),
                CaptureProcessSnapshotForCompare(
                    snapshot, nullptr, false, L"current", &currentContext));
            Check(!comparison.triageCompared, L"valid not-captured contexts do not claim semantic comparison");
            CheckEqual(comparison.comparableTriageProcessCount, std::size_t{ 0 }, L"not-captured comparable count zero");
            CheckEqual(comparison.triageAvailabilityMismatchCount, std::size_t{ 0 }, L"not-captured mismatch count zero");
            Check(comparison.changedProcesses.empty(), L"not-captured contexts do not create a process change");
        }

        void TestValidNotCapturedToCapturedIsAvailabilityMismatch()
        {
            const ProcessInfo process = MakeProcess();
            const ProcessSnapshot snapshot = MakeSnapshot(process);
            PersistedTriageContext baselineContext = MakeContext(
                process,
                MakeNotCapturedPersistedTriageSummary());
            const TriageResult result = MakeTriageResult(
                TriageVerdict::Informational,
                {},
                {
                    { TriageRationaleSection::VerdictBasis,
                        "No review-relevant baseline evidence contributed." }
                },
                "Baseline triage completed.");
            PersistedTriageContext currentContext = MakeContext(
                process,
                MakeBaselineSummary(result, 0));

            const SnapshotCompareResult comparison = CompareSnapshots(
                CaptureProcessSnapshotForCompare(
                    snapshot, nullptr, false, L"baseline", &baselineContext),
                CaptureProcessSnapshotForCompare(
                    snapshot, nullptr, false, L"current", &currentContext));
            Check(comparison.triageCompared, L"captured availability mismatch is compared");
            CheckEqual(comparison.triageAvailabilityMismatchCount, std::size_t{ 1 }, L"valid-context availability mismatch count");
            CheckEqual(comparison.changedProcesses.size(), std::size_t{ 1 }, L"valid-context mismatch emits change");
        }

        void TestPidOnlyIdentityDoesNotCompareSemanticTriage()
        {
            ProcessInfo process = MakeProcess(43, 0);
            process.hasCreationTime = false;
            process.creationTimeFileTime = 0;
            const ProcessSnapshot snapshot = MakeSnapshot(process);
            const TriageResult result = MakeTriageResult(
                TriageVerdict::LowAttention,
                { EvidenceDomain::FilePath },
                {
                    { TriageRationaleSection::VerdictBasis,
                        "One weak path observation contributed." }
                },
                "Baseline triage completed.");
            PersistedTriageContext context = MakeContext(
                process,
                MakeBaselineSummary(result, 1));

            const SnapshotCompareResult comparison = CompareSnapshots(
                CaptureProcessSnapshotForCompare(
                    snapshot, nullptr, false, L"baseline", &context),
                CaptureProcessSnapshotForCompare(
                    snapshot, nullptr, false, L"current", &context));
            Check(!comparison.triageCompared, L"PID-only semantic triage is not compared");
            CheckEqual(comparison.comparableTriageProcessCount, std::size_t{ 0 }, L"PID-only comparable count zero");
            CheckEqual(comparison.triageIdentityUnavailableCount, std::size_t{ 1 }, L"PID-only identity-unavailable count");
            Check(comparison.changedProcesses.empty(), L"PID-only identical records remain unchanged");
        }

        void TestFallbackSemanticsRemainExplicit()
        {
            const ProcessInfo process = MakeProcess();
            const ProcessSnapshot snapshot = MakeSnapshot(process);
            const TriageResult baselineResult = MakeTriageResult(
                TriageVerdict::LowAttention,
                { EvidenceDomain::FilePath },
                {
                    { TriageRationaleSection::VerdictBasis,
                        "One weak path observation contributed." }
                },
                "Baseline triage completed.");
            PersistedTriageContext baselineContext = MakeContext(
                process,
                MakeBaselineSummary(baselineResult, 2));
            const PersistedTriageSummary historicalFallback =
                MakeHistoricalLegacyFallbackSummary(
                    TriageVerdict::HighAttention,
                    2,
                    "Baseline evaluation was unavailable.",
                    "Legacy fallback captured.");
            Check(ValidatePersistedTriageSummary(historicalFallback).valid,
                L"schema-4 historical fallback fixture validates");
            PersistedTriageContext currentContext = MakeContext(
                process,
                historicalFallback);

            const SnapshotCompareResult comparison = CompareSnapshots(
                CaptureProcessSnapshotForCompare(
                    snapshot, nullptr, false, L"baseline", &baselineContext),
                CaptureProcessSnapshotForCompare(
                    snapshot, nullptr, false, L"current", &currentContext));
            CheckEqual(comparison.changedProcesses.size(), std::size_t{ 1 }, L"fallback compare changed process count");
            const SnapshotProcessChange& change = comparison.changedProcesses.front();
            Check(FindField(change, L"Triage fallback") != nullptr, L"fallback state compared");
            const SnapshotChangedField* reason = FindField(
                change,
                L"Triage fallback reason");
            Check(reason != nullptr, L"fallback reason compared");
            if (reason != nullptr)
            {
                Check(reason->currentValue.find(L"unavailable") != std::wstring::npos, L"fallback reason retained");
            }
            Check(FindField(change, L"Authoritative triage verdict") != nullptr, L"fallback authoritative verdict compared");
            Check(FindField(change, L"Triage evaluation succeeded") != nullptr, L"fallback evaluation status compared");
        }

        void TestInvalidContextIsNotAttached()
        {
            const ProcessInfo process = MakeProcess();
            const ProcessSnapshot snapshot = MakeSnapshot(process);
            PersistedTriageContext context;
            context.modelVersion = PersistedTriageModelVersion + 1;

            const ProcessSnapshotCapture capture =
                CaptureProcessSnapshotForCompare(
                    snapshot,
                    nullptr,
                    false,
                    L"invalid",
                    &context);
            Check(capture.triageContextCaptured, L"invalid context was supplied");
            Check(!capture.triageContextValid, L"invalid context rejected");
            Check(!capture.processes.front().authoritativeTriage.captured, L"invalid context does not attach semantic triage");
            Check(capture.triageStatusMessage.find(L"rejected") != std::wstring::npos, L"invalid context diagnostic retained");
        }

        void TestHistoricalLegacySourceSeverityComparisonPreservedAndRelabeled()
        {
            ProcessInfo baselineProcess = MakeProcess();
            baselineProcess.severity = Severity::Low;
            ProcessInfo currentProcess = baselineProcess;
            currentProcess.severity = Severity::High;

            const ProcessSnapshotCapture baseline =
                CaptureProcessSnapshotForCompare(
                    MakeSnapshot(baselineProcess), nullptr, false, L"baseline");
            const ProcessSnapshotCapture current =
                CaptureProcessSnapshotForCompare(
                    MakeSnapshot(currentProcess), nullptr, false, L"current");
            const SnapshotCompareResult comparison = CompareSnapshots(
                baseline,
                current);

            Check(!comparison.triageCompared, L"legacy-only captures do not fabricate triage comparison");
            CheckEqual(comparison.changedProcesses.size(), std::size_t{ 1 }, L"legacy severity change retained");
            const SnapshotProcessChange& change = comparison.changedProcesses.front();
            Check(FindField(change, L"Historical legacy source severity") != nullptr, L"historical legacy source severity field explicit");
            Check(FindField(change, L"Severity") == nullptr, L"ambiguous severity label removed");
            Check(
                std::any_of(
                    current.findings.begin(),
                    current.findings.end(),
                    [](const SnapshotFindingRecord& finding) {
                        return finding.title == L"Historical legacy source severity: High";
                    }),
                L"legacy synthetic finding retained with explicit source label");
            const auto indicator = std::find_if(
                current.findings.begin(),
                current.findings.end(),
                [](const SnapshotFindingRecord& finding) {
                    return finding.title == L"Generic legacy indicator";
                });
            Check(
                indicator != current.findings.end() &&
                    !indicator->severityCaptured &&
                    std::wstring(SnapshotFindingSeverityText(*indicator)) ==
                        L"Not captured",
                L"historical indicator comparison does not inherit process severity");
            Check(comparison.findingsCompared, L"historical findings compared");
            Check(comparison.sourceEvidenceCompared, L"historical source evidence comparison reported");
            CheckEqual(
                comparison.baselineSourceEvidenceModelKind,
                SnapshotSourceEvidenceModelKind::HistoricalLegacy,
                L"historical baseline model explicit");
        }

        void TestNativeCaptureKeepsHistoricalFindingsSeparate()
        {
            const ProcessInfo process = MakeProcess();
            NativeSourceEvidenceRecord later =
                MakeNativeEvidence("rule.z");
            NativeSourceEvidenceRecord earlier =
                MakeNativeEvidence("rule.a");
            SnapshotSourceEvidenceCaptureContext evidenceContext;
            evidenceContext.modelKind =
                SnapshotSourceEvidenceModelKind::Native;
            evidenceContext.selectedNativeEvidence =
                MakeSelectedNativeEvidence(
                    process,
                    { later, earlier });

            const ProcessSnapshotCapture capture =
                CaptureProcessSnapshotForCompare(
                    MakeSnapshot(process),
                    nullptr,
                    false,
                    L"native",
                    nullptr,
                    &evidenceContext);
            Check(capture.nativeSourceEvidenceCaptured, L"native evidence model captured");
            Check(!capture.findingsCaptured, L"native capture does not project historical findings");
            Check(capture.findings.empty(), L"native capture historical finding list empty");
            CheckEqual(capture.processes.front().severity, Severity::None, L"native capture does not retain historical process severity");
            Check(capture.processes.front().indicators.empty(), L"native capture does not retain historical process indicators");
            Check(capture.processes.front().contextNotes.empty(), L"native capture does not retain historical process context rows");
            Check(capture.selectedNativeSourceEvidence.has_value(), L"selected native evidence retained");
            if (capture.selectedNativeSourceEvidence.has_value())
            {
                const auto& records =
                    capture.selectedNativeSourceEvidence->records;
                CheckEqual(records.size(), std::size_t{ 2 }, L"native capture record count");
                Check(
                    ValidateNativeSourceEvidenceRecords(records).valid,
                    L"native compare capture preserves canonical source-evidence contract");
                if (records.size() == 2)
                {
                    CheckEqual(records[0].stableRuleId, std::string("rule.a"), L"native capture canonical record order");
                    CheckEqual(records[1].stableRuleId, std::string("rule.z"), L"native capture canonical record order tail");
                }
            }

            ProcessInfo changedLegacySeverity = process;
            changedLegacySeverity.severity = Severity::High;
            changedLegacySeverity.suspicious = true;
            SnapshotSourceEvidenceCaptureContext currentEvidenceContext =
                evidenceContext;
            const SnapshotCompareResult comparison = CompareSnapshots(
                capture,
                CaptureProcessSnapshotForCompare(
                    MakeSnapshot(changedLegacySeverity),
                    nullptr,
                    false,
                    L"native-current",
                    nullptr,
                    &currentEvidenceContext));
            Check(comparison.changedProcesses.empty(), L"native process comparison ignores historical legacy severity");
        }

        void TestNativeComparisonIgnoresPresentationAndInputOrder()
        {
            const ProcessInfo process = MakeProcess();
            NativeSourceEvidenceRecord first =
                MakeNativeEvidence("rule.alpha", "Baseline title A");
            first.limitations = { "Limitation A", "Limitation B" };
            NativeSourceEvidenceRecord second =
                MakeNativeEvidence("rule.beta", "Baseline title B");

            NativeSourceEvidenceRecord currentFirst = first;
            currentFirst.title = "Current renamed title";
            currentFirst.summary = "Current presentation summary";
            currentFirst.details = { "Reordered detail", "Different detail" };
            currentFirst.provenanceSummary = "Different presentation provenance";
            currentFirst.strength = ObservationStrength::Strong;
            currentFirst.confidence = ObservationConfidence::Low;
            currentFirst.suppressedDuplicate = true;
            currentFirst.limitations = { "Limitation B", "Limitation A" };
            NativeSourceEvidenceRecord currentSecond = second;
            currentSecond.title = "Another presentation title";

            const SnapshotCompareResult comparison = CompareSnapshots(
                MakeNativeCapture(process, { first, second }),
                MakeNativeCapture(process, { currentSecond, currentFirst }));
            Check(comparison.sourceEvidenceCompared, L"native model comparison available");
            Check(comparison.nativeSourceEvidenceCompared, L"selected native evidence compared");
            Check(comparison.selectedNativeEvidence.semanticCompared, L"native semantic compare flag");
            Check(comparison.selectedNativeEvidence.newRecords.empty(), L"presentation changes do not add native records");
            Check(comparison.selectedNativeEvidence.removedRecords.empty(), L"presentation changes do not remove native records");
            Check(comparison.selectedNativeEvidence.changedRecords.empty(), L"presentation changes do not change native semantics");
        }

        void TestNativeComparisonUsesContributionAndLimitations()
        {
            const ProcessInfo process = MakeProcess();
            NativeSourceEvidenceRecord baselineRecord =
                MakeNativeEvidence("rule.semantic");
            baselineRecord.limitations = { "Baseline limitation" };
            NativeSourceEvidenceRecord currentRecord = baselineRecord;
            currentRecord.domain = EvidenceDomain::Network;
            currentRecord.disposition = ObservationDisposition::Context;
            currentRecord.artifactFamily = "Network Connection";
            currentRecord.contributedToVerdict = true;
            currentRecord.limitations = {
                "Additional limitation",
                "Baseline limitation"
            };

            const SnapshotCompareResult comparison = CompareSnapshots(
                MakeNativeCapture(process, { baselineRecord }),
                MakeNativeCapture(process, { currentRecord }));
            CheckEqual(
                comparison.selectedNativeEvidence.changedRecords.size(),
                std::size_t{ 1 },
                L"native contribution and limitation change paired");
            Check(comparison.selectedNativeEvidence.newRecords.empty(), L"native semantic change is not reported new");
            Check(comparison.selectedNativeEvidence.removedRecords.empty(), L"native semantic change is not reported removed");
            if (!comparison.selectedNativeEvidence.changedRecords.empty())
            {
                const auto& change =
                    comparison.selectedNativeEvidence.changedRecords.front();
                Check(
                    FindField(change.fields, L"Evidence domain") != nullptr,
                    L"native domain field retained");
                Check(
                    FindField(change.fields, L"Disposition") != nullptr,
                    L"native disposition field retained");
                Check(
                    FindField(change.fields, L"Artifact family") != nullptr,
                    L"native artifact-family field retained");
                Check(
                    FindField(change.fields, L"Contributed to verdict") != nullptr,
                    L"native contribution field retained");
                Check(
                    FindField(change.fields, L"Limitations") != nullptr,
                    L"native limitations field retained");
            }
        }

        void TestNativeIdentityUsesStableFieldsNotTitle()
        {
            const ProcessInfo process = MakeProcess();
            NativeSourceEvidenceRecord baselineRecord =
                MakeNativeEvidence("rule.baseline", "Shared title");
            NativeSourceEvidenceRecord currentRecord = baselineRecord;
            currentRecord.stableRuleId = "rule.current";

            const SnapshotCompareResult comparison = CompareSnapshots(
                MakeNativeCapture(process, { baselineRecord }),
                MakeNativeCapture(process, { currentRecord }));
            CheckEqual(comparison.selectedNativeEvidence.newRecords.size(), std::size_t{ 1 }, L"different stable rule appears");
            CheckEqual(comparison.selectedNativeEvidence.removedRecords.size(), std::size_t{ 1 }, L"different stable rule removes old record");
            Check(comparison.selectedNativeEvidence.changedRecords.empty(), L"shared title does not pair different stable rules");
        }

        void TestNativeHistoricalModelMismatchDoesNotTitleMatch()
        {
            ProcessInfo process = MakeProcess();
            process.indicators = { L"Shared title" };
            const ProcessSnapshotCapture historical =
                CaptureProcessSnapshotForCompare(
                    MakeSnapshot(process),
                    nullptr,
                    false,
                    L"historical");
            const ProcessSnapshotCapture native = MakeNativeCapture(
                process,
                { MakeNativeEvidence("rule.native", "Shared title") });

            const SnapshotCompareResult comparison = CompareSnapshots(
                historical,
                native);
            Check(comparison.sourceEvidenceModelMismatch, L"native historical model mismatch explicit");
            Check(!comparison.sourceEvidenceCompared, L"mismatched evidence models not compared");
            Check(!comparison.findingsCompared, L"historical finding matcher not run across models");
            Check(!comparison.nativeSourceEvidenceCompared, L"native matcher not run across models");
            Check(comparison.newFindings.empty(), L"model mismatch does not title-match historical finding as new");
            Check(comparison.removedFindings.empty(), L"model mismatch does not title-match historical finding as removed");
            Check(comparison.selectedNativeEvidence.newRecords.empty(), L"model mismatch does not project native additions");
        }

        void TestNativeModelVersionMismatchIsNotCompared()
        {
            const ProcessInfo process = MakeProcess();
            const NativeSourceEvidenceRecord evidence =
                MakeNativeEvidence("rule.versioned");
            const SnapshotCompareResult comparison = CompareSnapshots(
                MakeNativeCapture(
                    process,
                    { evidence },
                    NativeSourceEvidenceModelVersion),
                MakeNativeCapture(
                    process,
                    { evidence },
                    NativeSourceEvidenceModelVersion + 1));
            Check(comparison.nativeSourceEvidenceModelVersionMismatch, L"native model version mismatch explicit");
            Check(!comparison.sourceEvidenceCompared, L"different native model versions not compared");
            Check(!comparison.nativeSourceEvidenceCompared, L"different native model versions not semantically compared");
        }

        void TestIdenticalSemanticTriageDoesNotCreateChange()
        {
            const ProcessInfo process = MakeProcess(0, 700);
            const ProcessSnapshot snapshot = MakeSnapshot(process);
            const TriageResult result = MakeTriageResult(
                TriageVerdict::Informational,
                {},
                {
                    { TriageRationaleSection::VerdictBasis,
                        "No review-relevant baseline evidence contributed." }
                },
                "Baseline triage completed.");
            PersistedTriageContext context = MakeContext(
                process,
                MakeBaselineSummary(result, 0));
            const ProcessSnapshotCapture baseline =
                CaptureProcessSnapshotForCompare(
                    snapshot, nullptr, false, L"baseline", &context);
            const ProcessSnapshotCapture current =
                CaptureProcessSnapshotForCompare(
                    snapshot, nullptr, false, L"current", &context);
            const SnapshotCompareResult comparison = CompareSnapshots(
                baseline,
                current);
            Check(comparison.triageCompared, L"PID zero semantic triage compared");
            CheckEqual(comparison.comparableTriageProcessCount, std::size_t{ 1 }, L"PID zero comparable triage count");
            Check(comparison.changedProcesses.empty(), L"identical PID zero semantic triage has no change");
        }

        void TestRationaleVectorOrderDoesNotCreateFalseDifference()
        {
            const ProcessInfo process = MakeProcess(43, 701);
            const ProcessSnapshot snapshot = MakeSnapshot(process);
            const TriageResult baselineResult = MakeTriageResult(
                TriageVerdict::MediumAttention,
                { EvidenceDomain::FilePath, EvidenceDomain::FileSignature },
                {
                    { TriageRationaleSection::VerdictBasis, "Path fact." },
                    { TriageRationaleSection::VerdictBasis, "Signature fact." },
                    { TriageRationaleSection::CompletedCorrelations,
                        "Typed file correlation." }
                },
                "Baseline triage completed.");
            const TriageResult currentResult = MakeTriageResult(
                TriageVerdict::MediumAttention,
                { EvidenceDomain::FilePath, EvidenceDomain::FileSignature },
                {
                    { TriageRationaleSection::CompletedCorrelations,
                        "Typed file correlation." },
                    { TriageRationaleSection::VerdictBasis, "Signature fact." },
                    { TriageRationaleSection::VerdictBasis, "Path fact." }
                },
                "Baseline triage completed.");

            PersistedTriageContext baselineContext = MakeContext(
                process,
                MakeBaselineSummary(baselineResult, 2));
            PersistedTriageContext currentContext = MakeContext(
                process,
                MakeBaselineSummary(currentResult, 2));
            const SnapshotCompareResult comparison = CompareSnapshots(
                CaptureProcessSnapshotForCompare(
                    snapshot, nullptr, false, L"baseline", &baselineContext),
                CaptureProcessSnapshotForCompare(
                    snapshot, nullptr, false, L"current", &currentContext));

            Check(comparison.triageCompared, L"reordered rationale semantic triage compared");
            Check(
                comparison.changedProcesses.empty(),
                L"rationale vector order does not create a false semantic difference");
        }

        void TestSelectedEntityChangeDoesNotContaminateProcessRows()
        {
            const ProcessInfo firstProcess = MakeProcess(44, 1000);
            ProcessInfo secondProcess = MakeProcess(45, 2000);
            secondProcess.name = L"second-generic-process.exe";
            secondProcess.executablePath =
                L"C:\\Generic\\second-generic-process.exe";

            ProcessSnapshot snapshot;
            snapshot.processes = { firstProcess, secondProcess };
            snapshot.indexByPid.emplace(firstProcess.pid, 0);
            snapshot.indexByPid.emplace(secondProcess.pid, 1);

            const TriageResult triage = MakeTriageResult(
                TriageVerdict::Informational,
                {},
                {
                    { TriageRationaleSection::VerdictBasis,
                        "No review-relevant baseline evidence contributed." }
                },
                "Baseline triage completed.");
            const PersistedTriageSummary summary =
                MakeBaselineSummary(triage, 0);
            const std::vector<PersistedProcessTriageRecord> records{
                { MakeProcessIdentityKey(firstProcess), summary },
                { MakeProcessIdentityKey(secondProcess), summary }
            };
            PersistedTriageContext baselineContext =
                MakePersistedTriageContext(
                    records,
                    PersistedProcessTriageRecord{
                        MakeProcessIdentityKey(firstProcess), summary });
            PersistedTriageContext currentContext =
                MakePersistedTriageContext(
                    records,
                    PersistedProcessTriageRecord{
                        MakeProcessIdentityKey(secondProcess), summary });

            const SnapshotCompareResult comparison = CompareSnapshots(
                CaptureProcessSnapshotForCompare(
                    snapshot, nullptr, false, L"baseline", &baselineContext),
                CaptureProcessSnapshotForCompare(
                    snapshot, nullptr, false, L"current", &currentContext));
            Check(comparison.changedProcesses.empty(), L"selection-only change does not alter process rows");
            Check(comparison.selectedTriage.baseline.has_value(), L"baseline selection retained separately");
            Check(comparison.selectedTriage.current.has_value(), L"current selection retained separately");
            Check(!comparison.selectedTriage.sameIdentity, L"different selected identities reported explicitly");
            Check(!comparison.selectedTriage.semanticCompared, L"different selections are not semantically compared");
        }

        void TestDuplicateProcessIdentityIsExcludedDeterministically()
        {
            const ProcessInfo process = MakeProcess();
            ProcessSnapshotCapture baseline =
                CaptureProcessSnapshotForCompare(
                    MakeSnapshot(process), nullptr, false, L"baseline");
            ProcessSnapshotCapture current =
                CaptureProcessSnapshotForCompare(
                    MakeSnapshot(process), nullptr, false, L"current");
            baseline.processes.push_back(baseline.processes.front());
            baseline.findingsCaptured = false;
            current.findingsCaptured = false;

            const SnapshotCompareResult first = CompareSnapshots(
                baseline,
                current);
            const SnapshotCompareResult second = CompareSnapshots(
                baseline,
                current);
            CheckEqual(first.baselineAmbiguousProcessIdentityCount, std::size_t{ 1 }, L"duplicate baseline process identity count");
            CheckEqual(first.currentAmbiguousProcessIdentityCount, std::size_t{ 0 }, L"duplicate current process identity count");
            Check(first.newProcesses.empty(), L"ambiguous process is not reported new");
            Check(first.exitedProcesses.empty(), L"ambiguous process is not reported exited");
            Check(first.changedProcesses.empty(), L"ambiguous process is not reported changed");
            CheckEqual(first.notes, second.notes, L"duplicate process diagnostics deterministic");
        }

        void TestDuplicateFindingIdentityIsExcludedDeterministically()
        {
            SnapshotFindingRecord finding;
            finding.processKey = { 46, true, 3000 };
            finding.pid = 46;
            finding.processName = L"generic-process.exe";
            finding.severity = FindingSeverity::Low;
            finding.title = L"Generic typed fact";
            finding.category = L"Generic";
            finding.evidenceSummary = L"First retained source record";

            ProcessSnapshotCapture baseline;
            baseline.captured = true;
            baseline.sourceEvidenceModelKind =
                SnapshotSourceEvidenceModelKind::HistoricalLegacy;
            baseline.findingsCaptured = true;
            baseline.findings = { finding, finding };
            baseline.findings.back().evidenceSummary =
                L"Second retained source record";
            ProcessSnapshotCapture current;
            current.captured = true;
            current.sourceEvidenceModelKind =
                SnapshotSourceEvidenceModelKind::HistoricalLegacy;
            current.findingsCaptured = true;
            current.findings = { finding };

            const SnapshotCompareResult first = CompareSnapshots(
                baseline,
                current);
            const SnapshotCompareResult second = CompareSnapshots(
                baseline,
                current);
            CheckEqual(first.ambiguousFindingIdentityCount, std::size_t{ 1 }, L"duplicate finding identity count");
            Check(first.newFindings.empty(), L"ambiguous finding is not reported new");
            Check(first.removedFindings.empty(), L"ambiguous finding is not reported removed");
            Check(first.changedFindings.empty(), L"ambiguous finding is not reported changed");
            CheckEqual(first.notes, second.notes, L"duplicate finding diagnostics deterministic");
        }

        void TestProcessSortUsesExactIdentityTieBreakers()
        {
            ProcessInfo later = MakeProcess(47, 5000);
            ProcessInfo earlier = later;
            earlier.creationTimeFileTime = 4000;
            ProcessSnapshot currentSnapshot;
            currentSnapshot.processes = { later, earlier };
            currentSnapshot.indexByPid.emplace(later.pid, 0);

            ProcessSnapshotCapture baseline;
            baseline.captured = true;
            ProcessSnapshotCapture current =
                CaptureProcessSnapshotForCompare(
                    currentSnapshot, nullptr, false, L"current");
            baseline.findingsCaptured = false;
            current.findingsCaptured = false;
            const SnapshotCompareResult comparison = CompareSnapshots(
                baseline,
                current);
            CheckEqual(comparison.newProcesses.size(), std::size_t{ 2 }, L"two exact identities reported new");
            if (comparison.newProcesses.size() == 2)
            {
                Check(
                    comparison.newProcesses[0].key.creationTimeFileTime <
                        comparison.newProcesses[1].key.creationTimeFileTime,
                    L"process identity tie-breaker is deterministic");
            }
        }

        void TestLegacyAndNotCapturedContextsRemainUnavailable()
        {
            const ProcessInfo process = MakeProcess();
            const ProcessSnapshot snapshot = MakeSnapshot(process);
            const ProcessSnapshotCapture legacy =
                CaptureProcessSnapshotForCompare(
                    snapshot, nullptr, false, L"legacy");
            PersistedTriageContext notCapturedContext = MakeContext(
                process,
                MakeNotCapturedPersistedTriageSummary());
            const ProcessSnapshotCapture semanticNotCaptured =
                CaptureProcessSnapshotForCompare(
                    snapshot,
                    nullptr,
                    false,
                    L"semantic-not-captured",
                    &notCapturedContext);

            const SnapshotCompareResult comparison = CompareSnapshots(
                legacy,
                semanticNotCaptured);
            Check(!comparison.triageCompared, L"legacy and semantic not-captured contexts remain unavailable");
            CheckEqual(comparison.comparableTriageProcessCount, std::size_t{ 0 }, L"mixed not-captured comparable count zero");
            CheckEqual(comparison.triageAvailabilityMismatchCount, std::size_t{ 0 }, L"mixed not-captured availability mismatch zero");
            Check(comparison.changedProcesses.empty(), L"mixed not-captured contexts do not create process changes");
        }

        void TestMixedSchemaSelectedTriageRemainsSeparate()
        {
            const ProcessInfo process = MakeProcess();
            const ProcessSnapshot snapshot = MakeSnapshot(process);
            const ProcessSnapshotCapture legacy =
                CaptureProcessSnapshotForCompare(
                    snapshot, nullptr, false, L"legacy");

            const TriageResult baselineResult = MakeTriageResult(
                TriageVerdict::Informational,
                {},
                {
                    { TriageRationaleSection::VerdictBasis,
                        "No review-relevant baseline evidence contributed." }
                },
                "Baseline triage completed.");
            const TriageResult enrichedResult = MakeTriageResult(
                TriageVerdict::LowAttention,
                { EvidenceDomain::CommandLine },
                {
                    { TriageRationaleSection::VerdictBasis,
                        "One weak command-line observation contributed." }
                },
                "Enriched triage completed.");
            PersistedTriageContext semanticContext = MakeContext(
                process,
                MakeBaselineSummary(baselineResult, 0),
                MakeEnrichedSummary(enrichedResult, baselineResult, 1));
            const ProcessSnapshotCapture semantic =
                CaptureProcessSnapshotForCompare(
                    snapshot,
                    nullptr,
                    false,
                    L"semantic",
                    &semanticContext);

            CheckEqual(
                semantic.processes.front().authoritativeTriage.analysisLevel,
                PersistedTriageAnalysisLevel::Baseline,
                L"mixed-schema process row retains baseline projection");
            Check(semantic.selectedAuthoritativeTriage.has_value(), L"mixed-schema selected projection retained separately");
            if (semantic.selectedAuthoritativeTriage.has_value())
            {
                CheckEqual(
                    semantic.selectedAuthoritativeTriage->summary.analysisLevel,
                    PersistedTriageAnalysisLevel::Enriched,
                    L"mixed-schema selected projection is enriched");
            }

            const SnapshotCompareResult comparison = CompareSnapshots(
                legacy,
                semantic);
            Check(comparison.triageCompared, L"legacy-to-baseline capture availability is compared");
            CheckEqual(comparison.triageAvailabilityMismatchCount, std::size_t{ 1 }, L"mixed-schema process triage availability mismatch");
            Check(comparison.selectedTriage.availabilityMismatch, L"mixed-schema selected record availability mismatch");
            Check(!comparison.selectedTriage.semanticCompared, L"one-sided selected record is not semantically compared");
            const SnapshotChangedField* selectedRecordField = FindField(
                comparison.selectedTriage.fields,
                L"Selected authoritative triage record");
            Check(selectedRecordField != nullptr, L"mixed-schema selected record field exists");
            if (selectedRecordField != nullptr)
            {
                CheckEqual(selectedRecordField->baselineValue, std::wstring(L"Not present"), L"legacy selected record is not present");
                CheckEqual(selectedRecordField->currentValue, std::wstring(L"Present"), L"semantic selected record is present");
            }
        }

        void TestSelectedNotCapturedRecordIsNotCalledCaptured()
        {
            const ProcessInfo process = MakeProcess();
            const ProcessSnapshot snapshot = MakeSnapshot(process);
            PersistedTriageContext currentContext = MakeContext(
                process,
                MakeNotCapturedPersistedTriageSummary(),
                MakeNotCapturedPersistedTriageSummary());

            const SnapshotCompareResult comparison = CompareSnapshots(
                CaptureProcessSnapshotForCompare(
                    snapshot, nullptr, false, L"legacy"),
                CaptureProcessSnapshotForCompare(
                    snapshot,
                    nullptr,
                    false,
                    L"semantic-not-captured",
                    &currentContext));
            Check(!comparison.triageCompared, L"selected not-captured record does not create process triage comparison");
            Check(comparison.selectedTriage.availabilityMismatch, L"selected record presence differs");
            const SnapshotChangedField* selectedRecordField = FindField(
                comparison.selectedTriage.fields,
                L"Selected authoritative triage record");
            Check(selectedRecordField != nullptr, L"selected not-captured presence field exists");
            if (selectedRecordField != nullptr)
            {
                CheckEqual(selectedRecordField->currentValue, std::wstring(L"Present"), L"not-captured summary is described as a present record");
                Check(selectedRecordField->currentValue != L"Captured", L"not-captured selected summary is not mislabeled captured");
            }
        }

        void TestLargeAuthoritativeTriageCompareIsDeterministicAndBounded()
        {
            constexpr std::size_t ProcessCount = 1000;
            constexpr std::size_t ChangedCount = ProcessCount / 10;
            constexpr int TimedIterations = 3;

            const TriageResult informationalResult = MakeTriageResult(
                TriageVerdict::Informational,
                {},
                {
                    { TriageRationaleSection::VerdictBasis,
                        "No review-relevant baseline evidence contributed." }
                },
                "Baseline triage completed.");
            const TriageResult lowResult = MakeTriageResult(
                TriageVerdict::LowAttention,
                { EvidenceDomain::FilePath },
                {
                    { TriageRationaleSection::VerdictBasis,
                        "One weak path observation contributed." }
                },
                "Baseline triage completed with review-relevant evidence.");
            const PersistedTriageSummary informationalSummary =
                MakeBaselineSummary(informationalResult, 0);
            const PersistedTriageSummary lowSummary =
                MakeBaselineSummary(lowResult, 1);

            ProcessSnapshot snapshot;
            snapshot.processes.reserve(ProcessCount);
            std::vector<PersistedProcessTriageRecord> baselineRecords;
            std::vector<PersistedProcessTriageRecord> currentRecords;
            baselineRecords.reserve(ProcessCount);
            currentRecords.reserve(ProcessCount);
            for (std::size_t index = 0; index < ProcessCount; ++index)
            {
                ProcessInfo process = MakeProcess(
                    static_cast<std::uint32_t>(1000 + index),
                    static_cast<std::uint64_t>(100000 + index));
                process.name = L"generic-baseline-process.exe";
                process.severity = Severity::None;
                process.suspicious = false;
                process.indicators.clear();
                process.contextNotes.clear();
                snapshot.indexByPid.emplace(
                    process.pid,
                    snapshot.processes.size());
                snapshot.processes.push_back(process);

                const ProcessIdentityKey identity =
                    MakeProcessIdentityKey(process);
                baselineRecords.push_back({ identity, informationalSummary });
                currentRecords.push_back({
                    identity,
                    index % 10 == 0 ? lowSummary : informationalSummary
                });
            }

            const PersistedProcessTriageRecord selectedRecord =
                baselineRecords.back();
            PersistedTriageContext baselineContext =
                MakePersistedTriageContext(
                    std::move(baselineRecords),
                    selectedRecord);
            PersistedTriageContext currentContext =
                MakePersistedTriageContext(
                    std::move(currentRecords),
                    selectedRecord);
            const ProcessSnapshotCapture baseline =
                CaptureProcessSnapshotForCompare(
                    snapshot,
                    nullptr,
                    false,
                    L"large-baseline",
                    &baselineContext);
            const ProcessSnapshotCapture current =
                CaptureProcessSnapshotForCompare(
                    snapshot,
                    nullptr,
                    false,
                    L"large-current",
                    &currentContext);

            const SnapshotCompareResult reference = CompareSnapshots(
                baseline,
                current);
            Check(reference.triageCompared, L"large compare includes authoritative triage");
            CheckEqual(reference.comparableTriageProcessCount, ProcessCount, L"large comparable triage process count");
            CheckEqual(reference.changedProcesses.size(), ChangedCount, L"large changed triage process count");
            Check(reference.selectedTriage.semanticCompared, L"large selected triage compared separately");
            Check(reference.selectedTriage.fields.empty(), L"large identical selected triage has no fields");

            const auto started = std::chrono::steady_clock::now();
            for (int iteration = 0; iteration < TimedIterations; ++iteration)
            {
                const SnapshotCompareResult repeated = CompareSnapshots(
                    baseline,
                    current);
                CheckEqual(repeated.comparableTriageProcessCount, reference.comparableTriageProcessCount, L"large repeated comparable count deterministic");
                CheckEqual(repeated.changedProcesses.size(), reference.changedProcesses.size(), L"large repeated changed count deterministic");
                CheckEqual(repeated.notes, reference.notes, L"large repeated notes deterministic");
                if (repeated.changedProcesses.size() ==
                    reference.changedProcesses.size())
                {
                    for (std::size_t index = 0;
                        index < repeated.changedProcesses.size();
                        ++index)
                    {
                        CheckEqual(
                            repeated.changedProcesses[index].current.key.creationTimeFileTime,
                            reference.changedProcesses[index].current.key.creationTimeFileTime,
                            L"large changed-process ordering deterministic");
                        Check(
                            SameFields(
                                repeated.changedProcesses[index].fields,
                                reference.changedProcesses[index].fields),
                            L"large changed-field ordering deterministic");
                    }
                }
            }
            const auto elapsed = std::chrono::duration_cast<
                std::chrono::microseconds>(
                    std::chrono::steady_clock::now() - started).count();
            const auto average = elapsed / TimedIterations;
            std::wcout
                << L"Snapshot Compare authoritative triage fixture: processes="
                << ProcessCount
                << L", changed="
                << ChangedCount
                << L", average-us="
                << average
                << L".\n";
            Check(elapsed < 30'000'000, L"large authoritative triage compare remains bounded");
        }
    }

    int RunSnapshotCompareTriageTests()
    {
        failureCount = 0;
        TestCaptureUsesExactProcessIdentity();
        TestMixedCapturedAndNotCapturedComparison();
        TestSemanticTriageFieldsAndStableOrder();
        TestValidNotCapturedContextsAreNotCompared();
        TestValidNotCapturedToCapturedIsAvailabilityMismatch();
        TestPidOnlyIdentityDoesNotCompareSemanticTriage();
        TestFallbackSemanticsRemainExplicit();
        TestInvalidContextIsNotAttached();
        TestHistoricalLegacySourceSeverityComparisonPreservedAndRelabeled();
        TestNativeCaptureKeepsHistoricalFindingsSeparate();
        TestNativeComparisonIgnoresPresentationAndInputOrder();
        TestNativeComparisonUsesContributionAndLimitations();
        TestNativeIdentityUsesStableFieldsNotTitle();
        TestNativeHistoricalModelMismatchDoesNotTitleMatch();
        TestNativeModelVersionMismatchIsNotCompared();
        TestIdenticalSemanticTriageDoesNotCreateChange();
        TestRationaleVectorOrderDoesNotCreateFalseDifference();
        TestSelectedEntityChangeDoesNotContaminateProcessRows();
        TestDuplicateProcessIdentityIsExcludedDeterministically();
        TestDuplicateFindingIdentityIsExcludedDeterministically();
        TestProcessSortUsesExactIdentityTieBreakers();
        TestLegacyAndNotCapturedContextsRemainUnavailable();
        TestMixedSchemaSelectedTriageRemainsSeparate();
        TestSelectedNotCapturedRecordIsNotCalledCaptured();
        TestLargeAuthoritativeTriageCompareIsDeterministicAndBounded();

        if (failureCount == 0)
        {
            std::wcout << L"Snapshot Compare triage tests passed.\n";
        }
        return failureCount;
    }
}
