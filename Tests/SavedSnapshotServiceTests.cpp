#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "Export/SavedSnapshot.h"

#include <Windows.h>

#include <algorithm>
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
        void CheckEqual(const Value& actual, const Value& expected, const wchar_t* testName)
        {
            Check(actual == expected, testName);
        }

        class OwnedTempDirectory
        {
        public:
            OwnedTempDirectory()
            {
                std::error_code error;
                const std::filesystem::path root =
                    std::filesystem::temp_directory_path(error);
                if (error)
                {
                    return;
                }

                const std::wstring prefix =
                    L"GlassPane-Snapshot-Service-Tests-" +
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
                if (ready_ && !path_.empty())
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

        bool WriteTextFile(const std::filesystem::path& path, const std::string& text)
        {
            std::ofstream output(path, std::ios::binary | std::ios::trunc);
            output.write(text.data(), static_cast<std::streamsize>(text.size()));
            return static_cast<bool>(output);
        }

        std::string ReadTextFile(const std::filesystem::path& path)
        {
            std::ifstream input(path, std::ios::binary);
            return std::string(
                std::istreambuf_iterator<char>(input),
                std::istreambuf_iterator<char>());
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

        bool ReplaceOnce(std::string& text, const std::string& from, const std::string& to)
        {
            const std::size_t position = text.find(from);
            if (position == std::string::npos)
            {
                return false;
            }
            text.replace(position, from.size(), to);
            return true;
        }

        bool EraseLineContaining(std::string& text, const std::string& token)
        {
            const std::size_t tokenPosition = text.find(token);
            if (tokenPosition == std::string::npos)
            {
                return false;
            }
            const std::size_t lineStart = text.rfind('\n', tokenPosition);
            const std::size_t eraseStart = lineStart == std::string::npos ? 0 : lineStart + 1;
            const std::size_t lineEnd = text.find('\n', tokenPosition);
            const std::size_t eraseEnd = lineEnd == std::string::npos ? text.size() : lineEnd + 1;
            text.erase(eraseStart, eraseEnd - eraseStart);
            return true;
        }

        ServiceInfo MakeService(
            std::wstring name,
            std::uint32_t pid,
            std::uint32_t stateRaw,
            std::uint32_t serviceTypeRaw)
        {
            ServiceInfo service;
            service.serviceName = std::move(name);
            service.displayName = L"Display " + service.serviceName;
            service.description = L"Description for " + service.serviceName;
            service.stateRaw = stateRaw;
            service.startTypeRaw = 0x00000002;
            service.serviceTypeRaw = serviceTypeRaw;
            service.serviceFlagsRaw = 0;
            service.serviceAccount = L"LocalSystem";
            service.rawImagePath = L"\"C:\\Program Files\\GlassPane Test\\Service.exe\" --service";
            service.expandedImagePath = service.rawImagePath;
            service.executablePath = L"C:\\Program Files\\GlassPane Test\\Service.exe";
            service.pathParseStatus = ServicePathParseStatus::ParsedQuoted;
            service.pathConfidence = ServicePathConfidence::High;
            service.pathParseMessage = L"Parsed a quoted absolute executable path.";
            service.scmProcessId = pid;
            service.pidReliableForState =
                pid != 0 && (stateRaw == 0x00000004 || stateRaw == 0x00000007);
            service.processModel = ServiceProcessModelFromType(serviceTypeRaw);
            service.svchostGroup = L"netsvcs";
            service.configurationAvailable = true;
            service.descriptionAvailable = true;
            service.statusMessage = L"Metadata available.";
            return service;
        }

        ServiceCollectionResult MakeCompleteServiceContext()
        {
            ServiceCollectionResult result;
            result.attempted = true;
            result.success = true;
            result.statusMessage = L"Collected persisted service context.";

            ServiceInfo first = MakeService(L"Svc Alpha", 4242, 0x00000004, 0x00000020);
            first.displayName = L"Unicode 服务 Alpha";
            first.description = L"Quoted ImagePath evidence: \"C:\\Program Files\\App\\Service.exe\" --run";
            first.serviceAccount = L"NT AUTHORITY\\Локальная служба";

            ServiceInfo second = MakeService(L"Svc Beta", 4242, 0x00000007, 0x00000020);
            second.svchostGroup = L"Local Service Network Restricted";

            ServiceInfo pidZero = MakeService(L"Svc Pid Zero", 0, 0xDEADBEEF, 0x80000010);
            pidZero.startTypeRaw = 0xCAFEBABE;
            pidZero.serviceFlagsRaw = 0xF0000001;

            ServiceInfo unreliable = MakeService(L"Svc Pending", 7777, 0x00000003, 0x00000010);

            result.services = {
                std::move(first),
                std::move(second),
                std::move(pidZero),
                std::move(unreliable)
            };
            result.totalEnumerated = result.services.size();
            result.ReindexCorrelations();
            return result;
        }

        SavedSnapshotExportContext MakeExportContext(
            const ProcessSnapshot& snapshot,
            const ServiceCollectionResult& serviceContext,
            const NetworkCollectionResult* network = nullptr)
        {
            SavedSnapshotExportContext context;
            context.snapshot = &snapshot;
            context.serviceContext = &serviceContext;
            context.networkLoaded = network != nullptr;
            context.network = network;
            context.glassPaneVersion = L"V0.8.0-Debug";
            context.capturedAt = L"2026-07-10 12:00:00";
            context.hostname = L"TEST-HOST";
            context.currentUser = L"TEST\\User";
            context.osBuild = L"Windows Test Build";
            context.evidenceMode = L"default";
            return context;
        }

        bool SaveAndLoad(
            const std::filesystem::path& path,
            const ProcessSnapshot& snapshot,
            const ServiceCollectionResult& serviceContext,
            SavedSnapshotDocument& loaded,
            std::wstring& error)
        {
            const SavedSnapshotExportContext context =
                MakeExportContext(snapshot, serviceContext);
            if (!SaveGlassPaneSnapshot(context, path.wstring(), &error))
            {
                return false;
            }
            return LoadGlassPaneSnapshot(path.wstring(), loaded, &error);
        }

        bool ServiceInfoEquals(const ServiceInfo& left, const ServiceInfo& right)
        {
            return left.serviceName == right.serviceName &&
                   left.displayName == right.displayName &&
                   left.description == right.description &&
                   left.stateRaw == right.stateRaw &&
                   left.startTypeRaw == right.startTypeRaw &&
                   left.serviceTypeRaw == right.serviceTypeRaw &&
                   left.serviceFlagsRaw == right.serviceFlagsRaw &&
                   left.serviceAccount == right.serviceAccount &&
                   left.rawImagePath == right.rawImagePath &&
                   left.expandedImagePath == right.expandedImagePath &&
                   left.executablePath == right.executablePath &&
                   left.pathParseStatus == right.pathParseStatus &&
                   left.pathConfidence == right.pathConfidence &&
                   left.pathParseMessage == right.pathParseMessage &&
                   left.scmProcessId == right.scmProcessId &&
                   left.pidReliableForState == right.pidReliableForState &&
                   left.processModel == right.processModel &&
                   left.svchostGroup == right.svchostGroup &&
                   left.configurationAvailable == right.configurationAvailable &&
                   left.descriptionAvailable == right.descriptionAvailable &&
                   left.serviceNameTruncated == right.serviceNameTruncated &&
                   left.displayNameTruncated == right.displayNameTruncated &&
                   left.descriptionTruncated == right.descriptionTruncated &&
                   left.serviceAccountTruncated == right.serviceAccountTruncated &&
                   left.rawImagePathTruncated == right.rawImagePathTruncated &&
                   left.expandedImagePathTruncated == right.expandedImagePathTruncated &&
                   left.svchostGroupTruncated == right.svchostGroupTruncated &&
                   left.pathParseMessageTruncated == right.pathParseMessageTruncated &&
                   left.statusMessageTruncated == right.statusMessageTruncated &&
                   left.statusMessage == right.statusMessage;
        }

        bool ServiceContextEquals(
            const ServiceCollectionResult& left,
            const ServiceCollectionResult& right)
        {
            if (left.attempted != right.attempted ||
                left.success != right.success ||
                left.partial != right.partial ||
                left.truncated != right.truncated ||
                left.totalEnumerated != right.totalEnumerated ||
                left.configurationUnavailableCount != right.configurationUnavailableCount ||
                left.descriptionUnavailableCount != right.descriptionUnavailableCount ||
                left.statusMessage != right.statusMessage ||
                left.services.size() != right.services.size())
            {
                return false;
            }
            for (std::size_t index = 0; index < left.services.size(); ++index)
            {
                if (!ServiceInfoEquals(left.services[index], right.services[index]))
                {
                    return false;
                }
            }
            return true;
        }

        std::string MinimalLegacySnapshot(int schemaVersion)
        {
            return
                "{\n"
                "  \"format\": \"glasspane_snapshot\",\n"
                "  \"schema_version\": " + std::to_string(schemaVersion) + ",\n"
                "  \"processes\": []\n"
                "}\n";
        }

        std::string MinimalSchema3Snapshot(const std::string& serviceContext)
        {
            return
                "{\n"
                "  \"format\": \"glasspane_snapshot\",\n"
                "  \"schema_version\": 3,\n"
                "  \"service_context\": " + serviceContext + ",\n"
                "  \"processes\": []\n"
                "}\n";
        }

        std::string ServiceContextWithServicesLiteral(
            const std::string& servicesLiteral);

        SavedSnapshotDocument MakeSentinelDocument()
        {
            SavedSnapshotDocument sentinel;
            sentinel.metadata.schemaVersion = 77;
            sentinel.metadata.format = L"sentinel";
            sentinel.metadata.selectedPid = 9090;
            ProcessInfo process;
            process.pid = 9090;
            process.name = L"sentinel-process";
            sentinel.snapshot.processes.push_back(std::move(process));
            sentinel.networkLoaded = true;
            sentinel.network.statusMessage = L"sentinel-network";
            sentinel.serviceContext.attempted = true;
            sentinel.serviceContext.success = true;
            sentinel.serviceContext.statusMessage = L"sentinel-services";
            sentinel.serviceContext.services.push_back(
                MakeService(L"sentinel-service", 9191, 4, 0x10));
            sentinel.serviceContext.totalEnumerated = 1;
            sentinel.serviceContext.ReindexCorrelations();
            return sentinel;
        }

        void CheckSentinelUnchanged(
            const SavedSnapshotDocument& document,
            const wchar_t* testName)
        {
            CheckEqual(document.metadata.schemaVersion, 77, testName);
            CheckEqual(document.metadata.format, std::wstring(L"sentinel"), testName);
            CheckEqual(document.metadata.selectedPid, std::uint32_t(9090), testName);
            CheckEqual(document.snapshot.processes.size(), std::size_t(1), testName);
            if (!document.snapshot.processes.empty())
            {
                CheckEqual(document.snapshot.processes[0].pid, std::uint32_t(9090), testName);
                CheckEqual(
                    document.snapshot.processes[0].name,
                    std::wstring(L"sentinel-process"),
                    testName);
            }
            Check(document.networkLoaded, testName);
            CheckEqual(
                document.network.statusMessage,
                std::wstring(L"sentinel-network"),
                testName);
            Check(document.serviceContext.attempted, testName);
            Check(document.serviceContext.success, testName);
            CheckEqual(
                document.serviceContext.statusMessage,
                std::wstring(L"sentinel-services"),
                testName);
            CheckEqual(document.serviceContext.services.size(), std::size_t(1), testName);
            if (!document.serviceContext.services.empty())
            {
                CheckEqual(
                    document.serviceContext.services[0].serviceName,
                    std::wstring(L"sentinel-service"),
                    testName);
            }
            const auto sentinelPid =
                document.serviceContext.serviceIndexesByPid.find(9191);
            Check(
                sentinelPid != document.serviceContext.serviceIndexesByPid.end(),
                testName);
            if (sentinelPid != document.serviceContext.serviceIndexesByPid.end())
            {
                CheckEqual(sentinelPid->second.size(), std::size_t(1), testName);
                CheckEqual(sentinelPid->second[0], std::size_t(0), testName);
            }
        }

        void TestLegacyCompatibilityAndResave(const OwnedTempDirectory& temporary)
        {
            for (const int schemaVersion : { 1, 2 })
            {
                const std::filesystem::path path = temporary.File(
                    schemaVersion == 1 ? L"schema1.json" : L"schema2.json");
                Check(
                    WriteTextFile(path, MinimalLegacySnapshot(schemaVersion)),
                    L"legacy fixture write");

                SavedSnapshotDocument loaded;
                std::wstring error;
                const bool legacyLoaded =
                    LoadGlassPaneSnapshot(path.wstring(), loaded, &error);
                Check(legacyLoaded, L"legacy snapshot loads");
                if (!legacyLoaded)
                {
                    continue;
                }
                CheckEqual(
                    loaded.metadata.schemaVersion,
                    schemaVersion,
                    L"legacy schema version preserved");
                Check(!loaded.serviceContext.attempted, L"legacy service context not attempted");
                Check(!loaded.serviceContext.success, L"legacy service context not successful");
                Check(loaded.serviceContext.services.empty(), L"legacy service rows empty");
                Check(
                    loaded.serviceContext.serviceIndexesByPid.empty(),
                    L"legacy service correlation index empty");
                Check(
                    loaded.triageContext.processRecords.empty() &&
                        !loaded.triageContext.selectedRecord.has_value(),
                    L"legacy snapshot has no captured authoritative triage");

                const std::filesystem::path upgradedPath = temporary.File(
                    schemaVersion == 1
                        ? L"schema1-upgraded.json"
                        : L"schema2-upgraded.json");
                SavedSnapshotExportContext context =
                    MakeExportContext(loaded.snapshot, loaded.serviceContext, &loaded.network);
                context.networkLoaded = loaded.networkLoaded;
                context.networkIndicatorMatches = &loaded.networkIndicatorMatches;
                context.processEvidence = &loaded.processEvidence;
                const bool upgradedSaved =
                    SaveGlassPaneSnapshot(context, upgradedPath.wstring(), &error);
                Check(upgradedSaved, L"legacy snapshot resaves as current schema");
                if (!upgradedSaved)
                {
                    continue;
                }

                SavedSnapshotDocument upgraded;
                const bool upgradedLoaded =
                    LoadGlassPaneSnapshot(upgradedPath.wstring(), upgraded, &error);
                Check(upgradedLoaded, L"upgraded legacy snapshot loads");
                if (!upgradedLoaded)
                {
                    continue;
                }
                CheckEqual(
                    upgraded.metadata.schemaVersion,
                    GlassPaneSnapshotSchemaVersion,
                    L"legacy resave writes current schema");
                Check(!upgraded.serviceContext.attempted, L"legacy resave does not fabricate attempt");
                Check(upgraded.serviceContext.services.empty(), L"legacy resave does not fabricate rows");
                CheckEqual(
                    upgraded.triageContext.processRecords.size(),
                    upgraded.snapshot.processes.size(),
                    L"legacy resave writes one explicit triage record per process");
                Check(
                    std::all_of(
                        upgraded.triageContext.processRecords.begin(),
                        upgraded.triageContext.processRecords.end(),
                        [](const PersistedProcessTriageRecord& record)
                        {
                            return !record.summary.captured &&
                                record.summary.analysisLevel ==
                                    PersistedTriageAnalysisLevel::NotCaptured;
                        }),
                    L"legacy resave does not fabricate authoritative verdicts");
            }

            const std::filesystem::path schema3Path =
                temporary.File(L"schema3-compatibility.json");
            Check(
                WriteTextFile(
                    schema3Path,
                    MinimalSchema3Snapshot(
                        ServiceContextWithServicesLiteral("[]"))),
                L"schema3 compatibility fixture write");
            SavedSnapshotDocument schema3;
            std::wstring schema3Error;
            Check(
                LoadGlassPaneSnapshot(
                    schema3Path.wstring(),
                    schema3,
                    &schema3Error),
                L"schema3 compatibility snapshot loads");
            CheckEqual(
                schema3.metadata.schemaVersion,
                3,
                L"schema3 compatibility version preserved");
            Check(
                schema3.triageContext.processRecords.empty() &&
                    !schema3.triageContext.selectedRecord.has_value(),
                L"schema3 does not fabricate authoritative triage");
        }

        void TestSchema3RoundTripAndManifest(const OwnedTempDirectory& temporary)
        {
            ProcessSnapshot snapshot;
            ServiceCollectionResult source = MakeCompleteServiceContext();
            source.serviceIndexesByPid[999999] = { 0 };

            const std::filesystem::path path = temporary.File(L"schema3-roundtrip.json");
            SavedSnapshotDocument loaded;
            std::wstring error;
            const bool roundTripSucceeded =
                SaveAndLoad(path, snapshot, source, loaded, error);
            Check(roundTripSucceeded, L"schema3 service context round-trip");
            CheckEqual(
                loaded.serviceContext.services.size(),
                source.services.size(),
                L"schema3 retained service row count round-trip");
            if (!roundTripSucceeded || loaded.serviceContext.services.size() < 4)
            {
                return;
            }
            CheckEqual(
                loaded.metadata.schemaVersion,
                GlassPaneSnapshotSchemaVersion,
                L"schema3 metadata version");
            Check(
                ServiceContextEquals(source, loaded.serviceContext),
                L"schema3 all persisted service fields round-trip");

            const auto sharedPid = loaded.serviceContext.serviceIndexesByPid.find(4242);
            Check(
                sharedPid != loaded.serviceContext.serviceIndexesByPid.end(),
                L"schema3 shared service PID indexed");
            if (sharedPid != loaded.serviceContext.serviceIndexesByPid.end())
            {
                CheckEqual(sharedPid->second.size(), std::size_t(2), L"schema3 many services per PID");
                CheckEqual(sharedPid->second[0], std::size_t(0), L"schema3 shared PID first row");
                CheckEqual(sharedPid->second[1], std::size_t(1), L"schema3 shared PID second row");
            }
            Check(
                loaded.serviceContext.serviceIndexesByPid.find(0) ==
                    loaded.serviceContext.serviceIndexesByPid.end(),
                L"schema3 PID0 excluded after reindex");
            Check(
                loaded.serviceContext.serviceIndexesByPid.find(7777) ==
                    loaded.serviceContext.serviceIndexesByPid.end(),
                L"schema3 unreliable PID excluded after reindex");
            Check(
                loaded.serviceContext.serviceIndexesByPid.find(999999) ==
                    loaded.serviceContext.serviceIndexesByPid.end(),
                L"schema3 stale derived index not persisted");

            CheckEqual(
                loaded.serviceContext.services[2].stateRaw,
                std::uint32_t(0xDEADBEEF),
                L"schema3 unknown raw state preserved");
            CheckEqual(
                loaded.serviceContext.services[2].startTypeRaw,
                std::uint32_t(0xCAFEBABE),
                L"schema3 unknown raw start type preserved");
            CheckEqual(
                loaded.serviceContext.services[2].serviceTypeRaw,
                std::uint32_t(0x80000010),
                L"schema3 unknown raw service type bits preserved");
            CheckEqual(
                loaded.serviceContext.services[2].serviceFlagsRaw,
                std::uint32_t(0xF0000001),
                L"schema3 unknown raw service flags preserved");
            CheckEqual(
                loaded.serviceContext.services[0].rawImagePath,
                source.services[0].rawImagePath,
                L"schema3 quoted raw ImagePath preserved");
            CheckEqual(
                loaded.serviceContext.services[0].displayName,
                source.services[0].displayName,
                L"schema3 Unicode field preserved");

            const std::string json = ReadTextFile(path);
            CheckEqual(
                CountOccurrences(json, "\"service_context\""),
                std::size_t(1),
                L"schema3 has one root service_context");
            Check(
                json.find("serviceIndexesByPid") == std::string::npos &&
                    json.find("service_indexes_by_pid") == std::string::npos,
                L"schema3 omits derived PID maps");

            std::string snapshotHash;
            Check(
                ComputeFileSha256Hex(path.wstring(), snapshotHash, &error),
                L"schema3 snapshot SHA256 computes");
            CheckEqual(snapshotHash.size(), std::size_t(64), L"schema3 SHA256 length");
            Check(
                WriteSha256Manifest(
                    temporary.Path().wstring(),
                    { path.filename().wstring() },
                    L"hashes.sha256",
                    &error),
                L"schema3 snapshot manifest writes");
            const std::string manifest = ReadTextFile(temporary.File(L"hashes.sha256"));
            Check(
                manifest.find(snapshotHash) != std::string::npos,
                L"schema3 manifest contains matching snapshot hash");
            Check(
                manifest.find("schema3-roundtrip.json") != std::string::npos,
                L"schema3 manifest names existing snapshot artifact");
        }

        void CheckCollectionVariantRoundTrip(
            const OwnedTempDirectory& temporary,
            const wchar_t* fileName,
            const ServiceCollectionResult& source,
            const wchar_t* testName)
        {
            ProcessSnapshot snapshot;
            SavedSnapshotDocument loaded;
            std::wstring error;
            Check(
                SaveAndLoad(temporary.File(fileName), snapshot, source, loaded, error),
                testName);
            Check(ServiceContextEquals(source, loaded.serviceContext), testName);
        }

        void TestCollectionResultVariants(const OwnedTempDirectory& temporary)
        {
            ServiceCollectionResult emptySuccess;
            emptySuccess.attempted = true;
            emptySuccess.success = true;
            emptySuccess.statusMessage = L"No active service rows were visible.";
            CheckCollectionVariantRoundTrip(
                temporary,
                L"empty-success.json",
                emptySuccess,
                L"empty successful service collection round-trip");

            ServiceCollectionResult partial;
            partial.attempted = true;
            partial.success = true;
            partial.partial = true;
            partial.services.push_back(MakeService(L"Partial Service", 5000, 4, 0x20));
            partial.services[0].configurationAvailable = false;
            partial.services[0].descriptionAvailable = false;
            partial.services[0].description.clear();
            partial.services[0].serviceAccount.clear();
            partial.services[0].rawImagePath.clear();
            partial.services[0].expandedImagePath.clear();
            partial.services[0].executablePath.clear();
            partial.services[0].pathParseStatus = ServicePathParseStatus::NotAttempted;
            partial.services[0].pathConfidence = ServicePathConfidence::None;
            partial.services[0].pathParseMessage.clear();
            partial.services[0].svchostGroup.clear();
            partial.services[0].statusMessage.assign(ServiceMessageMaxCharacters, L'B');
            partial.services[0].serviceNameTruncated = true;
            partial.services[0].displayNameTruncated = true;
            partial.services[0].descriptionTruncated = true;
            partial.services[0].serviceAccountTruncated = true;
            partial.services[0].rawImagePathTruncated = true;
            partial.services[0].expandedImagePathTruncated = true;
            partial.services[0].svchostGroupTruncated = true;
            partial.services[0].pathParseMessageTruncated = true;
            partial.services[0].statusMessageTruncated = true;
            partial.totalEnumerated = 1;
            partial.configurationUnavailableCount = 1;
            partial.descriptionUnavailableCount = 1;
            partial.statusMessage = L"Partial service metadata persisted.";
            partial.ReindexCorrelations();
            CheckCollectionVariantRoundTrip(
                temporary,
                L"partial.json",
                partial,
                L"partial service collection round-trip");

            ServiceCollectionResult failed;
            failed.attempted = true;
            failed.statusMessage = L"SCM open failed.";
            CheckCollectionVariantRoundTrip(
                temporary,
                L"failed.json",
                failed,
                L"failed service collection round-trip");

            ServiceCollectionResult failedWithRows;
            failedWithRows.attempted = true;
            failedWithRows.partial = true;
            failedWithRows.services.push_back(MakeService(L"Retained Before Failure", 6000, 4, 0x10));
            failedWithRows.totalEnumerated = 1;
            failedWithRows.statusMessage = L"Enumeration stopped after one retained row.";
            failedWithRows.ReindexCorrelations();
            CheckCollectionVariantRoundTrip(
                temporary,
                L"failed-with-row.json",
                failedWithRows,
                L"failed collection with retained rows round-trip");

            ServiceCollectionResult truncated;
            truncated.attempted = true;
            truncated.success = true;
            truncated.partial = true;
            truncated.truncated = true;
            truncated.services.push_back(MakeService(L"Retained Service", 7000, 4, 0x10));
            truncated.totalEnumerated = 2;
            truncated.statusMessage = L"One service row omitted by the service cap.";
            truncated.ReindexCorrelations();
            CheckCollectionVariantRoundTrip(
                temporary,
                L"truncated.json",
                truncated,
                L"truncated service collection round-trip");

            ServiceCollectionResult notCaptured;
            CheckCollectionVariantRoundTrip(
                temporary,
                L"not-captured.json",
                notCaptured,
                L"explicit not-captured schema3 context round-trip");
        }

        void TestCapsAndSaveValidation(const OwnedTempDirectory& temporary)
        {
            ProcessSnapshot snapshot;
            ServiceCollectionResult exactCaps;
            exactCaps.attempted = true;
            exactCaps.success = true;
            ServiceInfo capped = MakeService(
                std::wstring(ServiceNameMaxCharacters, L'N'),
                8100,
                4,
                0x10);
            capped.displayName.assign(ServiceDisplayNameMaxCharacters, L'D');
            capped.description.assign(ServiceDescriptionMaxCharacters, L'X');
            capped.serviceAccount.assign(ServiceAccountMaxCharacters, L'A');
            capped.rawImagePath.assign(ServiceImagePathMaxCharacters, L'R');
            capped.expandedImagePath.assign(ServiceImagePathMaxCharacters, L'E');
            capped.executablePath.assign(ServiceImagePathMaxCharacters, L'P');
            capped.pathParseMessage.assign(ServiceMessageMaxCharacters, L'M');
            capped.svchostGroup.assign(ServiceSvchostGroupMaxCharacters, L'G');
            capped.statusMessage.assign(ServiceMessageMaxCharacters, L'S');
            exactCaps.services.push_back(std::move(capped));
            exactCaps.totalEnumerated = 1;
            exactCaps.statusMessage.assign(ServiceMessageMaxCharacters, L'C');
            exactCaps.ReindexCorrelations();

            SavedSnapshotDocument exactLoaded;
            std::wstring error;
            const bool exactCapsLoaded =
                SaveAndLoad(
                    temporary.File(L"exact-string-caps.json"),
                    snapshot,
                    exactCaps,
                    exactLoaded,
                    error);
            Check(exactCapsLoaded, L"exact service string caps accepted");
            CheckEqual(
                exactLoaded.serviceContext.services.size(),
                std::size_t(1),
                L"exact-cap service row retained");
            if (exactCapsLoaded && !exactLoaded.serviceContext.services.empty())
            {
                CheckEqual(
                    exactLoaded.serviceContext.services[0].serviceName.size(),
                    ServiceNameMaxCharacters,
                    L"exact service-name cap preserved");
                CheckEqual(
                    exactLoaded.serviceContext.services[0].description.size(),
                    ServiceDescriptionMaxCharacters,
                    L"exact description cap preserved");
                CheckEqual(
                    exactLoaded.serviceContext.services[0].pathParseMessage.size(),
                    ServiceMessageMaxCharacters,
                    L"exact service-message cap preserved");
                Check(
                    ServiceInfoEquals(
                        exactCaps.services[0],
                        exactLoaded.serviceContext.services[0]),
                    L"all exact service string caps round-trip");
            }

            ServiceCollectionResult maximumRows;
            maximumRows.attempted = true;
            maximumRows.success = true;
            ServiceInfo minimal = MakeService(L"Cap Service", 0, 1, 0x10);
            minimal.displayName.clear();
            minimal.description.clear();
            minimal.serviceAccount.clear();
            minimal.rawImagePath.clear();
            minimal.expandedImagePath.clear();
            minimal.executablePath.clear();
            minimal.pathParseStatus = ServicePathParseStatus::NotAttempted;
            minimal.pathConfidence = ServicePathConfidence::None;
            minimal.pathParseMessage.clear();
            minimal.svchostGroup.clear();
            minimal.statusMessage.clear();
            maximumRows.services.assign(ServiceMaxRecords, minimal);
            maximumRows.totalEnumerated = maximumRows.services.size();
            maximumRows.ReindexCorrelations();

            SavedSnapshotDocument maximumLoaded;
            Check(
                SaveAndLoad(
                    temporary.File(L"maximum-service-array.json"),
                    snapshot,
                    maximumRows,
                    maximumLoaded,
                    error),
                L"maximum retained service array accepted");
            CheckEqual(
                maximumLoaded.serviceContext.services.size(),
                ServiceMaxRecords,
                L"maximum retained service array preserved");

            ServiceCollectionResult tooManyRows = maximumRows;
            tooManyRows.services.push_back(minimal);
            tooManyRows.totalEnumerated = tooManyRows.services.size();
            const SavedSnapshotExportContext tooManyContext =
                MakeExportContext(snapshot, tooManyRows);
            Check(
                !SaveGlassPaneSnapshot(
                    tooManyContext,
                    temporary.File(L"too-many-services.json").wstring(),
                    &error),
                L"oversized service array rejected on save");

            const auto CheckOversizedStringRejected =
                [&](const wchar_t* fileName, const wchar_t* testName, const auto& mutate) {
                    ServiceCollectionResult oversized;
                    oversized.attempted = true;
                    oversized.success = true;
                    oversized.services.push_back(MakeService(L"Oversized Field", 8200, 4, 0x10));
                    oversized.totalEnumerated = 1;
                    mutate(oversized);
                    const SavedSnapshotExportContext context =
                        MakeExportContext(snapshot, oversized);
                    Check(
                        !SaveGlassPaneSnapshot(
                            context,
                            temporary.File(fileName).wstring(),
                            &error),
                        testName);
                };

            CheckOversizedStringRejected(
                L"oversized-service-name.json",
                L"oversized service name rejected on save",
                [](ServiceCollectionResult& value) {
                    value.services[0].serviceName.assign(ServiceNameMaxCharacters + 1, L'N');
                });
            CheckOversizedStringRejected(
                L"oversized-display-name.json",
                L"oversized service display name rejected on save",
                [](ServiceCollectionResult& value) {
                    value.services[0].displayName.assign(ServiceDisplayNameMaxCharacters + 1, L'D');
                });
            CheckOversizedStringRejected(
                L"oversized-description.json",
                L"oversized service description rejected on save",
                [](ServiceCollectionResult& value) {
                    value.services[0].description.assign(ServiceDescriptionMaxCharacters + 1, L'X');
                });
            CheckOversizedStringRejected(
                L"oversized-account.json",
                L"oversized service account rejected on save",
                [](ServiceCollectionResult& value) {
                    value.services[0].serviceAccount.assign(ServiceAccountMaxCharacters + 1, L'A');
                });
            CheckOversizedStringRejected(
                L"oversized-raw-image-path.json",
                L"oversized raw ImagePath rejected on save",
                [](ServiceCollectionResult& value) {
                    value.services[0].rawImagePath.assign(ServiceImagePathMaxCharacters + 1, L'R');
                });
            CheckOversizedStringRejected(
                L"oversized-expanded-image-path.json",
                L"oversized expanded ImagePath rejected on save",
                [](ServiceCollectionResult& value) {
                    value.services[0].expandedImagePath.assign(ServiceImagePathMaxCharacters + 1, L'E');
                });
            CheckOversizedStringRejected(
                L"oversized-executable-path.json",
                L"oversized executable path rejected on save",
                [](ServiceCollectionResult& value) {
                    value.services[0].executablePath.assign(ServiceImagePathMaxCharacters + 1, L'P');
                });
            CheckOversizedStringRejected(
                L"oversized-parse-message.json",
                L"oversized path parse message rejected on save",
                [](ServiceCollectionResult& value) {
                    value.services[0].pathParseMessage.assign(ServiceMessageMaxCharacters + 1, L'M');
                });
            CheckOversizedStringRejected(
                L"oversized-svchost-group.json",
                L"oversized svchost group rejected on save",
                [](ServiceCollectionResult& value) {
                    value.services[0].svchostGroup.assign(ServiceSvchostGroupMaxCharacters + 1, L'G');
                });
            CheckOversizedStringRejected(
                L"oversized-service-status.json",
                L"oversized service status message rejected on save",
                [](ServiceCollectionResult& value) {
                    value.services[0].statusMessage.assign(ServiceMessageMaxCharacters + 1, L'S');
                });
            CheckOversizedStringRejected(
                L"oversized-aggregate-status.json",
                L"oversized aggregate service status rejected on save",
                [](ServiceCollectionResult& value) {
                    value.statusMessage.assign(ServiceMessageMaxCharacters + 1, L'C');
                });

            ServiceCollectionResult oversizedString;
            oversizedString.attempted = true;
            oversizedString.success = true;
            oversizedString.services.push_back(
                MakeService(std::wstring(ServiceNameMaxCharacters + 1, L'Z'), 8200, 4, 0x10));
            oversizedString.totalEnumerated = 1;
            const SavedSnapshotExportContext oversizedContext =
                MakeExportContext(snapshot, oversizedString);

            const std::filesystem::path preservedPath = temporary.File(L"prevalidation-preserves-file.json");
            Check(WriteTextFile(preservedPath, "preserve-me"), L"prevalidation sentinel write");
            Check(
                !SaveGlassPaneSnapshot(oversizedContext, preservedPath.wstring(), &error),
                L"invalid service context fails before write");
            CheckEqual(
                ReadTextFile(preservedPath),
                std::string("preserve-me"),
                L"invalid service context does not truncate destination");

            SavedSnapshotExportContext missingContext =
                MakeExportContext(snapshot, exactCaps);
            missingContext.serviceContext = nullptr;
            Check(
                !SaveGlassPaneSnapshot(
                    missingContext,
                    temporary.File(L"missing-service-context-pointer.json").wstring(),
                    &error),
                L"schema3 save requires explicit service context");
        }

        std::string ServiceContextWithServicesLiteral(const std::string& servicesLiteral)
        {
            return
                "{\n"
                "    \"attempted\": true,\n"
                "    \"success\": true,\n"
                "    \"partial\": false,\n"
                "    \"truncated\": false,\n"
                "    \"total_enumerated\": 0,\n"
                "    \"configuration_unavailable_count\": 0,\n"
                "    \"description_unavailable_count\": 0,\n"
                "    \"status_message\": \"\",\n"
                "    \"services\": " + servicesLiteral + "\n"
                "  }";
        }

        void ExpectLoadFailureWithoutAssignment(
            const OwnedTempDirectory& temporary,
            const wchar_t* fileName,
            const std::string& json,
            const wchar_t* testName,
            bool expectUnexpectedEnd = false)
        {
            const std::filesystem::path path = temporary.File(fileName);
            Check(WriteTextFile(path, json), testName);
            SavedSnapshotDocument document = MakeSentinelDocument();
            std::wstring error;
            Check(!LoadGlassPaneSnapshot(path.wstring(), document, &error), testName);
            Check(!error.empty(), testName);
            if (expectUnexpectedEnd)
            {
                Check(
                    error.find(L"Unexpected end of file") != std::wstring::npos,
                    L"truncated schema3 reports unexpected end of file");
            }
            CheckSentinelUnchanged(document, testName);
        }

        void TestMalformedSchema3IsTransactional(const OwnedTempDirectory& temporary)
        {
            ProcessSnapshot snapshot;
            ServiceCollectionResult source = MakeCompleteServiceContext();
            SavedSnapshotDocument ignored;
            std::wstring error;
            const std::filesystem::path validPath = temporary.File(L"valid-for-mutation.json");
            Check(
                SaveAndLoad(validPath, snapshot, source, ignored, error),
                L"valid mutation source saves");
            const std::string valid = ReadTextFile(validPath);

            std::string missingField = valid;
            Check(
                EraseLineContaining(missingField, "\"display_name\""),
                L"missing required service field mutation");
            ExpectLoadFailureWithoutAssignment(
                temporary,
                L"missing-service-field.json",
                missingField,
                L"missing required service field rejected");

            std::string wrongCollectionType = valid;
            Check(
                ReplaceOnce(
                    wrongCollectionType,
                    "\"attempted\": true",
                    "\"attempted\": \"true\""),
                L"wrong collection field type mutation");
            ExpectLoadFailureWithoutAssignment(
                temporary,
                L"wrong-collection-type.json",
                wrongCollectionType,
                L"wrong service collection field type rejected");

            std::string wrongServiceType = valid;
            Check(
                ReplaceOnce(
                    wrongServiceType,
                    "\"scm_pid\": 4242",
                    "\"scm_pid\": \"4242\""),
                L"wrong service field type mutation");
            ExpectLoadFailureWithoutAssignment(
                temporary,
                L"wrong-service-type.json",
                wrongServiceType,
                L"wrong service row field type rejected");

            std::string invalidEnum = valid;
            Check(
                ReplaceOnce(
                    invalidEnum,
                    "\"path_parse_status\": 2",
                    "\"path_parse_status\": 99"),
                L"invalid service enum mutation");
            ExpectLoadFailureWithoutAssignment(
                temporary,
                L"invalid-service-enum.json",
                invalidEnum,
                L"invalid modeled service enum rejected");

            std::string contradictoryModel = valid;
            Check(
                ReplaceOnce(
                    contradictoryModel,
                    "\"process_model\": 2",
                    "\"process_model\": 1"),
                L"contradictory process model mutation");
            ExpectLoadFailureWithoutAssignment(
                temporary,
                L"contradictory-process-model.json",
                contradictoryModel,
                L"service process model contradiction rejected");

            std::string contradictoryReliability = valid;
            Check(
                ReplaceOnce(
                    contradictoryReliability,
                    "\"pid_reliable_for_state\": true",
                    "\"pid_reliable_for_state\": false"),
                L"contradictory PID reliability mutation");
            ExpectLoadFailureWithoutAssignment(
                temporary,
                L"contradictory-pid-reliability.json",
                contradictoryReliability,
                L"service PID reliability contradiction rejected");

            std::string oversizedString = valid;
            Check(
                ReplaceOnce(
                    oversizedString,
                    "\"service_name\": \"Svc Alpha\"",
                    "\"service_name\": \"" +
                        std::string(ServiceNameMaxCharacters + 1, 'Z') + "\""),
                L"oversized service string mutation");
            ExpectLoadFailureWithoutAssignment(
                temporary,
                L"oversized-service-string-load.json",
                oversizedString,
                L"oversized service string rejected on load");

            std::string contradictoryCounts = valid;
            Check(
                ReplaceOnce(
                    contradictoryCounts,
                    "\"configuration_unavailable_count\": 0",
                    "\"configuration_unavailable_count\": 1"),
                L"contradictory service count mutation");
            ExpectLoadFailureWithoutAssignment(
                temporary,
                L"contradictory-service-count.json",
                contradictoryCounts,
                L"contradictory unavailable count rejected");

            std::string retainedCountMismatch = valid;
            Check(
                ReplaceOnce(
                    retainedCountMismatch,
                    "\"total_enumerated\": 4",
                    "\"total_enumerated\": 3"),
                L"retained service count mutation");
            ExpectLoadFailureWithoutAssignment(
                temporary,
                L"retained-service-count-mismatch.json",
                retainedCountMismatch,
                L"total enumerated below retained count rejected");

            std::string contradictoryPartial = valid;
            Check(
                ReplaceOnce(
                    contradictoryPartial,
                    "\"partial\": false",
                    "\"partial\": true"),
                L"contradictory partial flag mutation");
            ExpectLoadFailureWithoutAssignment(
                temporary,
                L"contradictory-partial.json",
                contradictoryPartial,
                L"contradictory partial flag rejected");

            std::string contradictoryTruncation = valid;
            Check(
                ReplaceOnce(
                    contradictoryTruncation,
                    "\"truncated\": false",
                    "\"truncated\": true"),
                L"contradictory truncated flag mutation");
            ExpectLoadFailureWithoutAssignment(
                temporary,
                L"contradictory-truncation.json",
                contradictoryTruncation,
                L"contradictory truncation flag rejected");

            std::string oversizedArray = "[";
            for (std::size_t index = 0; index < ServiceMaxRecords + 1; ++index)
            {
                if (index != 0)
                {
                    oversizedArray += ',';
                }
                oversizedArray += "{}";
            }
            oversizedArray += ']';
            ExpectLoadFailureWithoutAssignment(
                temporary,
                L"oversized-service-array-load.json",
                MinimalSchema3Snapshot(ServiceContextWithServicesLiteral(oversizedArray)),
                L"oversized service array rejected on load");

            ExpectLoadFailureWithoutAssignment(
                temporary,
                L"wrong-services-container.json",
                MinimalSchema3Snapshot(ServiceContextWithServicesLiteral("{}")),
                L"wrong services container type rejected");

            ExpectLoadFailureWithoutAssignment(
                temporary,
                L"missing-service-context.json",
                "{\"format\":\"glasspane_snapshot\",\"schema_version\":3,\"processes\":[]}",
                L"schema3 missing service_context rejected");

            ExpectLoadFailureWithoutAssignment(
                temporary,
                L"fractional-schema-version.json",
                "{\"format\":\"glasspane_snapshot\",\"schema_version\":3.9,\"processes\":[]}",
                L"fractional schema version rejected");

            const std::string truncated = valid.substr(0, valid.size() / 2);
            ExpectLoadFailureWithoutAssignment(
                temporary,
                L"truncated-schema3.json",
                truncated,
                L"truncated schema3 rejected transactionally",
                true);
        }
    }

    int RunSavedSnapshotServiceTests()
    {
        OwnedTempDirectory temporary;
        Check(temporary.Ready(), L"snapshot service test temp directory created");
        if (!temporary.Ready())
        {
            return failureCount;
        }

        TestLegacyCompatibilityAndResave(temporary);
        TestSchema3RoundTripAndManifest(temporary);
        TestCollectionResultVariants(temporary);
        TestCapsAndSaveValidation(temporary);
        TestMalformedSchema3IsTransactional(temporary);
        return failureCount;
    }
}
