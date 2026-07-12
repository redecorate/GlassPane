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
            std::string& text)
        {
            SelectedProcessMarkdownReportContext context;
            context.snapshot = &snapshot;
            context.serviceContext = &serviceContext;
            context.pid = SelectedPid;
            context.appVersion = L"V0.7.0-Debug";
            context.buildConfiguration = L"Debug";

            std::wstring error;
            if (!ExportSelectedProcessMarkdownReport(context, path.wstring(), &error))
            {
                return false;
            }
            text = ReadTextFile(path);
            return true;
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

        void TestPersistedContextAndPackageManifest(const OwnedTempDirectory& temporary)
        {
            const ProcessSnapshot snapshot = MakeSnapshot();
            const ServiceCollectionResult serviceContext =
                MakeCompleteCollection({ MakeService(L"PersistedService") });

            SavedSnapshotExportContext snapshotContext;
            snapshotContext.snapshot = &snapshot;
            snapshotContext.serviceContext = &serviceContext;
            snapshotContext.glassPaneVersion = L"V0.7.0-Debug";
            snapshotContext.capturedAt = L"2026-07-11 12:00:00";
            snapshotContext.hostname = L"TEST-HOST";
            snapshotContext.currentUser = L"TEST\\User";
            snapshotContext.osBuild = L"Windows Test Build";
            snapshotContext.evidenceMode = L"default";
            snapshotContext.selectedPid = SelectedPid;

            const std::filesystem::path snapshotPath =
                temporary.File(L"snapshot.glasspane-snapshot.json");
            std::wstring error;
            Check(
                SaveGlassPaneSnapshot(snapshotContext, snapshotPath.wstring(), &error),
                L"schema3 package snapshot saves");

            SavedSnapshotDocument loaded;
            const bool loadedSuccessfully =
                LoadGlassPaneSnapshot(snapshotPath.wstring(), loaded, &error);
            Check(loadedSuccessfully, L"schema3 package snapshot loads");
            if (!loadedSuccessfully)
            {
                return;
            }

            std::string report;
            const std::filesystem::path reportPath =
                temporary.File(L"selected-process-report.md");
            Check(
                RenderReport(reportPath, loaded.snapshot, loaded.serviceContext, report),
                L"loaded schema3 selected report exports");
            Check(
                report.find("## Service Context") != std::string::npos &&
                    report.find("PersistedService") != std::string::npos &&
                    report.find("not captured in this snapshot") == std::string::npos,
                L"loaded schema3 report uses persisted service context");

            std::string reportHash;
            Check(
                ComputeFileSha256Hex(reportPath.wstring(), reportHash, &error),
                L"selected report hash computes");
            Check(
                WriteSha256Manifest(
                    temporary.Path().wstring(),
                    {
                        snapshotPath.filename().wstring(),
                        reportPath.filename().wstring()
                    },
                    L"hashes.sha256",
                    &error),
                L"package-style hash manifest writes");
            const std::string manifest = ReadTextFile(temporary.File(L"hashes.sha256"));
            Check(
                manifest.find(reportHash + "  selected-process-report.md\n") !=
                    std::string::npos,
                L"package manifest contains matching selected report hash");
            Check(
                !std::filesystem::exists(temporary.File(L"services.json")),
                L"package does not create a separate service artifact");

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
        TestServiceFieldsAndMarkdownSafety(temporary);
        TestRenderingCapAndStaleIndexes(temporary);
        TestPersistedContextAndPackageManifest(temporary);
        return failureCount;
    }
}
