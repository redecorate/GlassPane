#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "Core/ServiceInfo.h"
#include "Export/MarkdownReportExporter.h"
#include "Export/SavedSnapshot.h"

#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace GlassPane::Tests
{
    namespace
    {
        using namespace Core;
        using namespace Export;

        constexpr std::uint32_t SelectedPid = 4242;
        int failureCount = 0;

        void Check(bool condition, const wchar_t* testName)
        {
            if (!condition)
            {
                std::wcerr << L"FAILED: " << testName << L'\n';
                ++failureCount;
            }
        }

        std::size_t CountOccurrences(std::string_view text, std::string_view needle)
        {
            if (needle.empty())
            {
                return 0;
            }

            std::size_t count = 0;
            std::size_t position = 0;
            while ((position = text.find(needle, position)) != std::string_view::npos)
            {
                ++count;
                position += needle.size();
            }
            return count;
        }

        class OwnedTempDirectory
        {
        public:
            OwnedTempDirectory()
            {
                std::error_code error;
                const std::filesystem::path root = std::filesystem::temp_directory_path(error);
                if (error)
                {
                    return;
                }

                const std::wstring prefix =
                    L"GlassPane-Markdown-Service-Tests-" +
                    std::to_wstring(GetCurrentProcessId()) + L"-" +
                    std::to_wstring(GetTickCount64()) + L"-";
                for (int attempt = 0; attempt < 16; ++attempt)
                {
                    const std::filesystem::path candidate =
                        root / (prefix + std::to_wstring(attempt));
                    error.clear();
                    if (std::filesystem::create_directory(candidate, error))
                    {
                        path_ = candidate;
                        ready_ = true;
                        return;
                    }
                    if (error)
                    {
                        return;
                    }
                }
            }

            ~OwnedTempDirectory()
            {
                if (ready_)
                {
                    std::error_code ignored;
                    std::filesystem::remove_all(path_, ignored);
                }
            }

            bool Ready() const noexcept
            {
                return ready_;
            }

            std::filesystem::path File(const wchar_t* name) const
            {
                return path_ / name;
            }

            const std::filesystem::path& Path() const noexcept
            {
                return path_;
            }

        private:
            std::filesystem::path path_;
            bool ready_ = false;
        };

        std::string ReadTextFile(const std::filesystem::path& path)
        {
            std::ifstream input(path, std::ios::binary);
            return std::string(
                std::istreambuf_iterator<char>(input),
                std::istreambuf_iterator<char>());
        }

        bool PersistedTriageSummariesEqual(
            const PersistedTriageSummary& left,
            const PersistedTriageSummary& right)
        {
            return left.captured == right.captured &&
                left.evaluationSucceeded == right.evaluationSucceeded &&
                left.usingFallback == right.usingFallback &&
                left.analysisLevel == right.analysisLevel &&
                left.authoritativeVerdict == right.authoritativeVerdict &&
                left.baselineVerdictAvailable == right.baselineVerdictAvailable &&
                left.baselineVerdict == right.baselineVerdict &&
                left.enrichedChangedVerdict == right.enrichedChangedVerdict &&
                left.triageModelVersion == right.triageModelVersion &&
                left.sourceEvidenceCount == right.sourceEvidenceCount &&
                left.contributingDomains == right.contributingDomains &&
                left.verdictBasis == right.verdictBasis &&
                left.completedCorrelations == right.completedCorrelations &&
                left.supportingContext == right.supportingContext &&
                left.collectionLimitations == right.collectionLimitations &&
                left.evidenceIntegrityContext == right.evidenceIntegrityContext &&
                left.unresolvedCorrelations == right.unresolvedCorrelations &&
                left.fallbackReason == right.fallbackReason &&
                left.status == right.status;
        }

        ProcessSnapshot MakeSnapshot()
        {
            ProcessSnapshot snapshot;
            ProcessInfo process;
            process.pid = SelectedPid;
            process.name = L"service-host.exe";
            process.executablePath = L"C:\\Windows\\System32\\service-host.exe";
            process.commandLine = L"service-host.exe --run";
            process.commandLineAccessible = true;
            process.architecture = L"x64";
            snapshot.processes.push_back(std::move(process));
            snapshot.Reindex();
            return snapshot;
        }

        ServiceInfo MakeService(
            std::wstring name,
            std::uint32_t pid = SelectedPid,
            ServiceProcessModel processModel = ServiceProcessModel::OwnProcess)
        {
            ServiceInfo service;
            service.serviceName = std::move(name);
            service.displayName = L"Display " + service.serviceName;
            service.description = L"Description for " + service.serviceName;
            service.stateRaw = 0x00000004;
            service.startTypeRaw = 0x00000002;
            service.serviceTypeRaw = processModel == ServiceProcessModel::SharedProcess
                ? 0x00000020
                : 0x00000010;
            service.serviceAccount = L"LocalSystem";
            service.rawImagePath = L"\"C:\\Program Files\\Example\\service.exe\" --service";
            service.expandedImagePath = service.rawImagePath;
            service.executablePath = L"C:\\Program Files\\Example\\service.exe";
            service.pathParseStatus = ServicePathParseStatus::ParsedQuoted;
            service.pathConfidence = ServicePathConfidence::High;
            service.pathParseMessage = L"Quoted absolute executable path parsed.";
            service.scmProcessId = pid;
            service.pidReliableForState = pid != 0;
            service.processModel = processModel;
            service.configurationAvailable = true;
            service.descriptionAvailable = true;
            return service;
        }

        ServiceCollectionResult MakeCompleteCollection(std::vector<ServiceInfo> services)
        {
            ServiceCollectionResult result;
            result.attempted = true;
            result.success = true;
            result.services = std::move(services);
            result.totalEnumerated = result.services.size();
            result.ReindexCorrelations();
            return result;
        }

        bool RenderReport(
            const std::filesystem::path& path,
            const ProcessSnapshot& snapshot,
            const ServiceCollectionResult& serviceContext,
            const PersistedTriageSummary& authoritativeTriage,
            std::string& text,
            const std::vector<NativeSourceEvidenceRecord>& nativeEvidence = {},
            const std::vector<Finding>& historicalEvidence = {},
            const HandleCollectionResult* handles = nullptr)
        {
            SelectedProcessMarkdownReportContext context;
            context.snapshot = &snapshot;
            context.serviceContext = &serviceContext;
            context.pid = SelectedPid;
            context.appVersion = L"V0.8.0-Debug";
            context.buildConfiguration = L"Debug";
            context.authoritativeTriage = authoritativeTriage;
            context.nativeSourceEvidence = nativeEvidence;
            context.historicalLegacyEvidence = historicalEvidence;
            context.handlesLoaded = handles != nullptr;
            context.handles = handles;

            std::wstring error;
            if (!ExportSelectedProcessMarkdownReport(context, path.wstring(), &error))
            {
                return false;
            }
            text = ReadTextFile(path);
            return true;
        }

        bool RenderReport(
            const std::filesystem::path& path,
            const ProcessSnapshot& snapshot,
            const ServiceCollectionResult& serviceContext,
            std::string& text)
        {
            return RenderReport(
                path,
                snapshot,
                serviceContext,
                PersistedTriageSummary{},
                text);
        }

        void TestCollectionStates(const OwnedTempDirectory& temporary)
        {
            const ProcessSnapshot snapshot = MakeSnapshot();
            std::string report;

            ServiceCollectionResult notCaptured;
            Check(
                RenderReport(temporary.File(L"not-captured.md"), snapshot, notCaptured, report),
                L"not-captured report exports");
            Check(
                report.find("- Collection status: Not captured") != std::string::npos,
                L"not-captured status renders");
            Check(
                report.find("Service context was not captured in this snapshot.") != std::string::npos,
                L"legacy snapshot wording renders");
            const std::size_t identityPosition = report.find("## Process Identity");
            const std::size_t servicePosition = report.find("## Service Context");
            const std::size_t chainPosition = report.find("## Parent Chain");
            Check(
                identityPosition < servicePosition && servicePosition < chainPosition,
                L"service section follows process identity");

            ServiceCollectionResult failed;
            failed.attempted = true;
            failed.statusMessage = L"Access <denied> & retry\nnot available";
            Check(
                RenderReport(temporary.File(L"failed.md"), snapshot, failed, report),
                L"failed collection report exports");
            Check(
                report.find("- Collection status: Unavailable") != std::string::npos &&
                    report.find("Service context could not be collected.") != std::string::npos,
                L"failed collection wording renders");
            Check(
                report.find("&lt;denied\\> &amp; retry<br>not available") != std::string::npos,
                L"failed status detail is Markdown-safe");

            ServiceCollectionResult emptySuccess;
            emptySuccess.attempted = true;
            emptySuccess.success = true;
            Check(
                RenderReport(temporary.File(L"empty-success.md"), snapshot, emptySuccess, report),
                L"empty success report exports");
            Check(
                report.find("- Collection status: Complete") != std::string::npos &&
                    report.find(
                        "No active Windows services were correlated to this process by SCM-reported PID.") !=
                        std::string::npos,
                L"empty success reports no correlation conservatively");

            ServiceCollectionResult partial = MakeCompleteCollection({ MakeService(L"OtherPid", 9191) });
            partial.success = false;
            partial.partial = true;
            partial.truncated = true;
            partial.totalEnumerated = 5;
            partial.configurationUnavailableCount = 1;
            partial.descriptionUnavailableCount = 1;
            partial.statusMessage = L"Bounded partial metadata.";
            Check(
                RenderReport(temporary.File(L"partial.md"), snapshot, partial, report),
                L"partial collection report exports");
            Check(
                report.find("- Collection status: Partial") != std::string::npos &&
                    report.find(
                        "Service context is partial. Some configuration details may be unavailable.") !=
                        std::string::npos,
                L"partial collection note renders");
            Check(
                report.find("4 active service records were omitted from the collected context.") !=
                    std::string::npos,
                L"endpoint truncation omitted count renders");
            Check(
                report.find("Configuration records unavailable: 1") != std::string::npos &&
                    report.find("Description records unavailable: 1") != std::string::npos,
                L"partial availability counters render");
        }

        void TestPartialHandleCollectionPresentation(
            const OwnedTempDirectory& temporary)
        {
            const ProcessSnapshot snapshot = MakeSnapshot();
            const ServiceCollectionResult services;
            HandleCollectionResult handles;
            handles.pid = SelectedPid;
            handles.state = HandleCollectionState::Partial;
            handles.success = true;
            handles.statusMessage =
                L"Additional handle metadata was not evaluated because a safety limit was reached.";
            handles.selectedProcessHandlesMatched = 3;
            handles.selectedProcessHandlesOmitted = 2;
            handles.namesSkipped = 1;
            handles.retentionCapReached = true;
            handles.nameResolutionCapReached = true;

            HandleInfo handle;
            handle.owningPid = SelectedPid;
            handle.handleValue = 0x88;
            handle.objectTypeIndex = 8;
            handle.objectType = L"Thread";
            handle.grantedAccessRaw = 0x10;
            handle.grantedAccess = L"0x00000010";
            handle.targetThreadId = 9001;
            handles.handles.push_back(std::move(handle));

            std::string report;
            Check(
                RenderReport(
                    temporary.File(L"partial-handles.md"),
                    snapshot,
                    services,
                    MakeNotCapturedPersistedTriageSummary(),
                    report,
                    {},
                    {},
                    &handles),
                L"partial handle Markdown report exports");
            Check(
                report.find("- Collection status: Partial") !=
                    std::string::npos &&
                    report.find("- Retained handles: 1") !=
                        std::string::npos &&
                    report.find("- Selected-process handles omitted: 2") !=
                        std::string::npos,
                L"partial handle counts render honestly");
            Check(
                report.find("Collection limitation: Additional handle metadata was not evaluated") !=
                    std::string::npos,
                L"partial handle limitation renders");
            Check(
                report.find("TID 9001") != std::string::npos &&
                    report.find("0x00000010") != std::string::npos,
                L"partial handle raw row remains visible without an object name");
            Check(
                report.find("Handles unavailable:") == std::string::npos,
                L"partial handle rows are not presented as unavailable");
        }

        void TestServiceFieldsAndMarkdownSafety(const OwnedTempDirectory& temporary)
        {
            const ProcessSnapshot snapshot = MakeSnapshot();

            ServiceInfo own = MakeService(L"svc#*_[x]<tag>&\nnext");
            own.displayName = L"\u670D\u52A1 display | name";
            own.description = L"First line\n## injected <tag> & value";
            own.rawImagePath =
                L"\"C:\\Program Files\\Example\\svc```name.exe\"\n--arg #value";
            own.expandedImagePath =
                L"\"C:\\Program Files\\Expanded\\svc```name.exe\"\n--arg #value";
            own.executablePath = L"C:\\Program Files\\Expanded\\svc```name.exe";
            own.rawImagePathTruncated = true;
            own.pathParseMessageTruncated = true;
            own.statusMessage = L"Observed [bounded] status.";

            ServiceInfo shared = MakeService(
                L"SharedOne",
                SelectedPid,
                ServiceProcessModel::SharedProcess);
            shared.stateRaw = 0xDEADBEEF;
            shared.startTypeRaw = 0xCAFEBABE;
            shared.serviceTypeRaw = 0x80000020;
            shared.svchostGroup = L"netsvcs";
            shared.rawImagePath = L"C:\\Windows\\System32\\svchost.exe -k netsvcs";
            shared.expandedImagePath = shared.rawImagePath;
            shared.executablePath = L"C:\\Windows\\System32\\svchost.exe";
            shared.pathParseStatus = ServicePathParseStatus::ParsedUnquoted;

            ServiceInfo unavailable = MakeService(
                L"SharedUnavailable",
                SelectedPid,
                ServiceProcessModel::SharedProcess);
            unavailable.configurationAvailable = false;
            unavailable.descriptionAvailable = false;
            unavailable.rawImagePath.clear();
            unavailable.expandedImagePath.clear();
            unavailable.executablePath.clear();
            unavailable.pathParseStatus = ServicePathParseStatus::NotAttempted;
            unavailable.pathConfidence = ServicePathConfidence::None;

            const ServiceCollectionResult collection = MakeCompleteCollection({
                std::move(own),
                std::move(shared),
                std::move(unavailable)
            });
            std::string report;
            Check(
                RenderReport(temporary.File(L"service-fields.md"), snapshot, collection, report),
                L"service field report exports");
            Check(
                report.find("- Correlated service count: 3") != std::string::npos &&
                    CountOccurrences(report, "### Associated service ") == 3,
                L"multiple associated services render");
            Check(
                report.find("Own process") != std::string::npos &&
                    CountOccurrences(report, "Shared process") >= 2,
                L"own and multiple shared process models render");
            Check(
                report.find("svchost group: netsvcs") != std::string::npos,
                L"svchost group renders");
            Check(
                report.find("0xDEADBEEF") != std::string::npos &&
                    report.find("0xCAFEBABE") != std::string::npos &&
                    report.find("0x80000000") != std::string::npos,
                L"unknown raw values remain visible");
            Check(
                report.find("Configured context: Unavailable") != std::string::npos &&
                    report.find("Description metadata: Unavailable") != std::string::npos,
                L"configuration and description unavailability render");
            Check(
                report.find(u8"\u670D\u52A1 display") != std::string::npos,
                L"Unicode service fields render as UTF-8");
            Check(
                report.find("<br>\\#\\# injected &lt;tag\\> &amp; value") != std::string::npos &&
                    report.find("\n## injected") == std::string::npos,
                L"Markdown metacharacters and newlines cannot inject headings");
            Check(
                report.find(
                    "\"C:\\Program Files\\Example\\svc```name.exe\"\n--arg #value") !=
                    std::string::npos,
                L"raw ImagePath is preserved inside a safe code fence");
            Check(
                report.find("Expanded ImagePath:") != std::string::npos &&
                    report.find("Parsed executable path:") != std::string::npos,
                L"expanded and parsed paths remain distinct");
            Check(
                report.find("Truncated fields: raw ImagePath, path parse message") !=
                    std::string::npos,
                L"field truncation notes render");

            ServiceInfo ambiguous = MakeService(L"AmbiguousPath");
            ambiguous.rawImagePath = L"C:\\Program Files\\Example\\service.exe --service";
            ambiguous.expandedImagePath = ambiguous.rawImagePath;
            ambiguous.executablePath.clear();
            ambiguous.pathParseStatus = ServicePathParseStatus::AmbiguousUnquoted;
            ambiguous.pathConfidence = ServicePathConfidence::None;
            ambiguous.pathParseMessage = L"Unquoted executable boundary is ambiguous.";
            const ServiceCollectionResult ambiguousCollection =
                MakeCompleteCollection({ std::move(ambiguous) });
            Check(
                RenderReport(temporary.File(L"ambiguous.md"), snapshot, ambiguousCollection, report),
                L"ambiguous path report exports");
            Check(
                report.find("Ambiguous unquoted path") != std::string::npos &&
                    report.find("C:\\Program Files\\Example\\service.exe --service") !=
                        std::string::npos,
                L"ambiguous raw ImagePath remains visible");
            Check(
                report.find("Parsed executable path:") == std::string::npos,
                L"ambiguous ImagePath does not fabricate an executable path");
        }

        void TestRenderingCapAndStaleIndexes(const OwnedTempDirectory& temporary)
        {
            const ProcessSnapshot snapshot = MakeSnapshot();
            std::vector<ServiceInfo> services;
            for (std::size_t index = 0; index < 40; ++index)
            {
                services.push_back(MakeService(L"valid-service-" + std::to_wstring(index)));
            }
            services.push_back(MakeService(L"wrong-pid-index", 9001));
            ServiceInfo unreliable = MakeService(L"unreliable-index");
            unreliable.pidReliableForState = false;
            services.push_back(std::move(unreliable));

            ServiceCollectionResult collection = MakeCompleteCollection(std::move(services));
            auto& indexes = collection.serviceIndexesByPid[SelectedPid];
            indexes.insert(indexes.begin(), { 999999, 40, 41, 0 });

            std::string report;
            Check(
                RenderReport(temporary.File(L"render-cap.md"), snapshot, collection, report),
                L"render-cap report exports");
            Check(
                report.find("- Correlated service count: 40") != std::string::npos,
                L"stale indexes are excluded from correlated count");
            Check(
                CountOccurrences(report, "### Associated service ") == 32,
                L"service report renders at most 32 cards");
            Check(
                report.find("8 additional correlated services were omitted from this report.") !=
                    std::string::npos,
                L"service report states valid omitted count");
            Check(
                report.find("wrong-pid-index") == std::string::npos &&
                    report.find("unreliable-index") == std::string::npos &&
                    report.find("valid-service-32") == std::string::npos,
                L"stale entries and rows beyond the cap are not rendered");
        }

        void TestAuthoritativeTriagePresentation(const OwnedTempDirectory& temporary)
        {
            const ProcessSnapshot snapshot = MakeSnapshot();
            const ServiceCollectionResult serviceContext;
            PersistedTriageSummary enriched;
            enriched.captured = true;
            enriched.evaluationSucceeded = true;
            enriched.analysisLevel = PersistedTriageAnalysisLevel::Enriched;
            enriched.authoritativeVerdict = TriageVerdict::MediumAttention;
            enriched.baselineVerdictAvailable = true;
            enriched.baselineVerdict = TriageVerdict::Informational;
            enriched.enrichedChangedVerdict = true;
            enriched.triageModelVersion = PersistedTriageModelVersion;
            enriched.sourceEvidenceCount = 1;
            enriched.contributingDomains = { EvidenceDomain::FilePath };
            enriched.verdictBasis = {
                "A typed local evidence fact contributed to this verdict."
            };
            enriched.supportingContext = {
                "Static memory-region metadata was retained as context."
            };

            NativeSourceEvidenceRecord sourceEvidence;
            sourceEvidence.stableRuleId = "native.test.local-evidence";
            sourceEvidence.title = "Typed local evidence";
            sourceEvidence.summary = "Retained native source evidence.";
            sourceEvidence.domain = EvidenceDomain::FilePath;
            sourceEvidence.disposition = ObservationDisposition::ReviewRelevant;
            sourceEvidence.strength = ObservationStrength::Moderate;
            sourceEvidence.confidence = ObservationConfidence::High;
            sourceEvidence.artifactFamily = "File";
            sourceEvidence.provenanceSummary = "Locally collected typed evidence";
            sourceEvidence.contributedToVerdict = true;

            std::string report;
            Check(
                RenderReport(
                    temporary.File(L"authoritative-triage.md"),
                    snapshot,
                    serviceContext,
                    enriched,
                    report,
                    { sourceEvidence }),
                L"authoritative triage report exports");
            Check(
                report.find("- Triage verdict: Medium Attention") != std::string::npos &&
                    report.find("- Analysis level: Enriched") != std::string::npos &&
                    report.find("- Baseline verdict: Informational") != std::string::npos &&
                    report.find("- Enriched evidence changed verdict: Yes") !=
                        std::string::npos,
                L"authoritative report renders enriched and baseline verdicts");
            Check(
                report.find("## Process Identity") < report.find("## Triage Summary") &&
                    report.find("## Triage Summary") < report.find("## Source Evidence"),
                L"authoritative report orders process, triage, and source evidence sections");
            Check(
                report.find("## Triage Summary") != std::string::npos &&
                    report.find("A typed local evidence fact contributed") != std::string::npos &&
                    report.find("Static memory") != std::string::npos &&
                    report.find("retained as context") != std::string::npos,
                L"authoritative report renders Core-projected rationale");
            Check(
                report.find("- TriageEngine result available: Yes") != std::string::npos &&
                    report.find("- Triage model: 1") != std::string::npos,
                L"authoritative report renders engine availability and triage model");
            Check(
                report.find("## Source Evidence") != std::string::npos &&
                    report.find("## Findings") == std::string::npos &&
                    report.find("Typed local evidence") != std::string::npos,
                L"native observations are rendered as source evidence");
            Check(
                report.find("ObservationEngine result unavailable; legacy triage is being shown.") ==
                    std::string::npos,
                L"successful authority does not disclose fallback");
            Check(
                report.find("legacy_suspicious") == std::string::npos &&
                    report.find("observation-id") == std::string::npos &&
                    report.find("correlation-id") == std::string::npos,
                L"normal Markdown contains no internal authority identifiers");

            PersistedTriageSummary fallback;
            fallback.captured = true;
            fallback.usingFallback = true;
            fallback.analysisLevel = PersistedTriageAnalysisLevel::LegacyFallback;
            fallback.authoritativeVerdict = TriageVerdict::HighAttention;
            fallback.triageModelVersion = PersistedTriageModelVersion;
            fallback.sourceEvidenceCount = 1;
            fallback.fallbackReason = "Current ObservationEngine result was unavailable.";
            Check(
                RenderReport(
                    temporary.File(L"authoritative-fallback.md"),
                    snapshot,
                    serviceContext,
                    fallback,
                    report,
                    { sourceEvidence }),
                L"authoritative fallback report exports");
            Check(
                report.find("schema-4 capture retained a historical legacy-fallback state") !=
                    std::string::npos,
                L"historical schema4 fallback is disclosed as captured metadata");
            Check(
                report.find("- Fallback reason: Current ObservationEngine result was unavailable.") !=
                    std::string::npos,
                L"fallback report preserves the bounded captured fallback reason");

            Check(
                RenderReport(
                    temporary.File(L"triage-not-captured.md"),
                    snapshot,
                    serviceContext,
                    PersistedTriageSummary{},
                    report),
                L"not-captured triage report exports");
            Check(
                report.find("Authoritative TriageEngine results were not captured for this process.") !=
                    std::string::npos &&
                    report.find("- Triage verdict: Not captured") != std::string::npos,
                L"legacy snapshot report states authoritative triage was not captured");

            Finding historicalRow;
            historicalRow.title = L"Imported historical indicator";
            historicalRow.category = L"Historical Source Evidence";
            historicalRow.description =
                L"Imported wording retained without row-level severity.";
            historicalRow.severityCaptured = false;
            Check(
                RenderReport(
                    temporary.File(L"historical-row-severity.md"),
                    snapshot,
                    serviceContext,
                    PersistedTriageSummary{},
                    report,
                    {},
                    { historicalRow }),
                L"historical source row report exports");
            Check(
                report.find("### Not captured: Imported historical indicator") !=
                    std::string::npos &&
                    report.find("- Historical source severity: Not captured") !=
                        std::string::npos &&
                    report.find("### Info: Imported historical indicator") ==
                        std::string::npos,
                L"Markdown does not fabricate Info severity for an uncaptured historical row");
        }

        void TestPersistedContextAndPackageManifest(const OwnedTempDirectory& temporary)
        {
            const ProcessSnapshot snapshot = MakeSnapshot();
            const ServiceCollectionResult serviceContext =
                MakeCompleteCollection({ MakeService(L"PersistedService") });

            PersistedTriageSummary baselineTriage;
            baselineTriage.captured = true;
            baselineTriage.evaluationSucceeded = true;
            baselineTriage.analysisLevel = PersistedTriageAnalysisLevel::Baseline;
            baselineTriage.authoritativeVerdict = TriageVerdict::Informational;
            baselineTriage.baselineVerdictAvailable = true;
            baselineTriage.baselineVerdict = TriageVerdict::Informational;
            baselineTriage.triageModelVersion = PersistedTriageModelVersion;
            baselineTriage.sourceEvidenceCount = 2;
            baselineTriage.verdictBasis = {
                "No review-relevant baseline evidence contributed."
            };
            baselineTriage.status = "Baseline capture completed.";

            constexpr std::string_view AuthorityMarker =
                "Package authority fixture: typed evidence changed the selected verdict.";
            PersistedTriageSummary selectedTriage;
            selectedTriage.captured = true;
            selectedTriage.evaluationSucceeded = true;
            selectedTriage.analysisLevel = PersistedTriageAnalysisLevel::Enriched;
            selectedTriage.authoritativeVerdict = TriageVerdict::MediumAttention;
            selectedTriage.baselineVerdictAvailable = true;
            selectedTriage.baselineVerdict = TriageVerdict::Informational;
            selectedTriage.enrichedChangedVerdict = true;
            selectedTriage.triageModelVersion = PersistedTriageModelVersion;
            selectedTriage.sourceEvidenceCount = 3;
            selectedTriage.contributingDomains = {
                EvidenceDomain::FilePath,
                EvidenceDomain::FileSignature
            };
            selectedTriage.verdictBasis = { std::string(AuthorityMarker) };
            selectedTriage.completedCorrelations = {
                "A typed file identity correlation completed."
            };
            selectedTriage.supportingContext = {
                "Static memory-region metadata remained non-contributing context."
            };
            selectedTriage.collectionLimitations = {
                "Deep module evidence was not evaluated for the baseline result."
            };
            selectedTriage.status = "Enriched capture completed.";

            PersistedProcessTriageRecord baselineRecord;
            baselineRecord.identity = MakeProcessIdentityKey(snapshot.processes.front());
            baselineRecord.summary = baselineTriage;
            PersistedProcessTriageRecord selectedRecord;
            selectedRecord.identity = baselineRecord.identity;
            selectedRecord.summary = selectedTriage;
            const PersistedTriageContext triageContext = MakePersistedTriageContext(
                { baselineRecord },
                selectedRecord);
            Check(
                ValidatePersistedTriageContext(triageContext).valid,
                L"package authority fixture triage context validates");

            SavedSnapshotExportContext snapshotContext;
            snapshotContext.snapshot = &snapshot;
            snapshotContext.serviceContext = &serviceContext;
            snapshotContext.glassPaneVersion = L"V0.8.0-Debug";
            snapshotContext.capturedAt = L"2026-07-11 12:00:00";
            snapshotContext.hostname = L"TEST-HOST";
            snapshotContext.currentUser = L"TEST\\User";
            snapshotContext.osBuild = L"Windows Test Build";
            snapshotContext.evidenceMode = L"default";
            snapshotContext.selectedPid = SelectedPid;
            snapshotContext.triageContext = &triageContext;

            const std::filesystem::path snapshotPath =
                temporary.File(L"snapshot.glasspane-snapshot.json");
            std::wstring error;
            const ULONGLONG snapshotStarted = GetTickCount64();
            Check(
                SaveGlassPaneSnapshot(snapshotContext, snapshotPath.wstring(), &error),
                L"schema4 package snapshot saves");
            const ULONGLONG snapshotMs = GetTickCount64() - snapshotStarted;

            const std::string snapshotJson = ReadTextFile(snapshotPath);
            Check(
                snapshotJson.find("\"schema_version\": 5") != std::string::npos &&
                    snapshotJson.find("\"triage_context\": {") != std::string::npos &&
                    snapshotJson.find("\"analysis_level\": \"enriched\"") !=
                        std::string::npos &&
                    snapshotJson.find("\"authoritative_verdict\": \"medium_attention\"") !=
                        std::string::npos,
                L"schema5 package snapshot contains selected authority fields");
            Check(
                CountOccurrences(snapshotJson, AuthorityMarker) == 1,
                L"schema4 package snapshot contains one selected authority value");

            SavedSnapshotDocument loaded;
            const bool loadedSuccessfully =
                LoadGlassPaneSnapshot(snapshotPath.wstring(), loaded, &error);
            Check(loadedSuccessfully, L"schema4 package snapshot loads");
            if (!loadedSuccessfully)
            {
                return;
            }
            Check(
                loaded.metadata.schemaVersion == GlassPaneSnapshotSchemaVersion,
                L"package snapshot loads as current schema");
            Check(
                loaded.triageContext.selectedRecord.has_value() &&
                    PersistedTriageSummariesEqual(
                        loaded.triageContext.selectedRecord->summary,
                        selectedTriage),
                L"schema4 package snapshot preserves exact selected authority value");

            std::string report;
            const std::filesystem::path reportPath =
                temporary.File(L"selected-process-report.md");
            const ULONGLONG markdownStarted = GetTickCount64();
            Check(
                RenderReport(
                    reportPath,
                    loaded.snapshot,
                    loaded.serviceContext,
                    selectedTriage,
                    report),
                L"loaded schema4 selected report exports");
            const ULONGLONG markdownMs = GetTickCount64() - markdownStarted;
            Check(
                report.find("## Service Context") != std::string::npos &&
                    report.find("PersistedService") != std::string::npos &&
                    report.find("Service context was not captured in this snapshot") ==
                        std::string::npos,
                L"loaded schema4 report uses persisted service context");
            Check(
                report.find("- Triage verdict: Medium Attention") != std::string::npos &&
                    report.find("- Analysis level: Enriched") != std::string::npos &&
                    report.find("- Baseline verdict: Informational") != std::string::npos &&
                    CountOccurrences(report, AuthorityMarker) == 1,
                L"package report renders the same selected authority value");

            std::string snapshotHash;
            std::string reportHash;
            Check(
                ComputeFileSha256Hex(snapshotPath.wstring(), snapshotHash, &error),
                L"package snapshot hash computes");
            Check(
                ComputeFileSha256Hex(reportPath.wstring(), reportHash, &error),
                L"selected report hash computes");

            const std::filesystem::path readmePath = temporary.File(L"README.txt");
            Check(
                WriteEvidencePackageReadme(
                    readmePath.wstring(),
                    snapshotContext.capturedAt,
                    snapshotContext.glassPaneVersion,
                    false,
                    {
                        snapshotPath.filename().wstring(),
                        reportPath.filename().wstring()
                    },
                    &error),
                L"package-style README writes");
            std::string readmeHash;
            Check(
                ComputeFileSha256Hex(readmePath.wstring(), readmeHash, &error),
                L"package README hash computes");

            const ULONGLONG manifestStarted = GetTickCount64();
            Check(
                WriteSha256Manifest(
                    temporary.Path().wstring(),
                    {
                        readmePath.filename().wstring(),
                        snapshotPath.filename().wstring(),
                        reportPath.filename().wstring()
                    },
                    L"hashes.sha256",
                    &error),
                L"package-style hash manifest writes");
            const ULONGLONG manifestMs = GetTickCount64() - manifestStarted;
            const std::string manifest = ReadTextFile(temporary.File(L"hashes.sha256"));
            Check(
                manifest.find(readmeHash + "  README.txt\n") != std::string::npos &&
                    manifest.find(
                        snapshotHash + "  snapshot.glasspane-snapshot.json\n") !=
                        std::string::npos &&
                    manifest.find(reportHash + "  selected-process-report.md\n") !=
                        std::string::npos,
                L"package manifest contains matching authority artifact hashes");
            Check(
                CountOccurrences(manifest, "\n") == 3,
                L"package manifest contains exactly the requested artifacts");
            Check(
                !std::filesystem::exists(temporary.File(L"services.json")),
                L"package does not create a separate service artifact");

            std::wcout << L"Markdown/package authority fixture timing: snapshot="
                << snapshotMs << L" ms, Markdown=" << markdownMs
                << L" ms, manifest=" << manifestMs << L" ms.\n";

            const ServiceCollectionResult legacyServiceContext;
            Check(
                RenderReport(
                    temporary.File(L"schema1-legacy-report.md"),
                    snapshot,
                    legacyServiceContext,
                    report),
                L"schema1-style legacy report exports");
            Check(
                report.find("Service context was not captured in this snapshot.") !=
                    std::string::npos,
                L"schema1-style report states service context not captured");
            Check(
                RenderReport(
                    temporary.File(L"schema2-legacy-report.md"),
                    snapshot,
                    legacyServiceContext,
                    report),
                L"schema2-style legacy report exports");
            Check(
                report.find("Service context was not captured in this snapshot.") !=
                    std::string::npos,
                L"schema2-style report states service context not captured");
        }
    }

    int RunMarkdownServiceReportTests()
    {
        failureCount = 0;
        OwnedTempDirectory temporary;
        Check(temporary.Ready(), L"Markdown service report temporary directory created");
        if (!temporary.Ready())
        {
            return failureCount;
        }

        TestCollectionStates(temporary);
        TestPartialHandleCollectionPresentation(temporary);
        TestServiceFieldsAndMarkdownSafety(temporary);
        TestRenderingCapAndStaleIndexes(temporary);
        TestAuthoritativeTriagePresentation(temporary);
        TestPersistedContextAndPackageManifest(temporary);
        return failureCount;
    }
}
