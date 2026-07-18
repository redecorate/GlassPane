#include "Export/JsonExporter.h"

#include "Core/ProcessTree.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <utility>
#include <vector>

namespace GlassPane::Tests
{
    namespace
    {
        int failures = 0;

        void Check(bool condition, const wchar_t* message)
        {
            if (!condition)
            {
                ++failures;
                std::wcerr << L"FAIL: " << message << L'\n';
            }
        }

        void TestOfflineExportUsesOnlyCapturedEvidence()
        {
            Core::ProcessSnapshot snapshot;
            Core::ProcessInfo process;
            process.pid = 4120;
            process.parentPid = 4;
            process.name = L"offline-fixture";
            process.executablePath =
                L"Z:\\path-that-must-not-be-read\\offline-fixture.exe";
            process.hasCreationTime = true;
            process.creationTimeFileTime = 412099;
            snapshot.processes.push_back(process);
            Core::BuildProcessTree(snapshot);

            Core::ModuleCollectionResult modules;
            modules.pid = process.pid;
            modules.success = true;
            Core::ModuleInfo module;
            module.moduleName = L"offline-module.dll";
            module.modulePath =
                L"Z:\\path-that-must-not-be-read\\offline-module.dll";
            modules.modules.push_back(module);

            Export::SelectedProcessJsonEvidenceContext evidence;
            evidence.identityCaptured = true;
            evidence.identity = Core::MakeProcessIdentityKey(process);
            evidence.tokenCaptured = true;
            evidence.token.success = true;
            evidence.token.userSid = L"S-1-5-21-offline-fixture";

            const std::vector<Core::NetworkConnection> network;
            const std::vector<Core::NativeSourceEvidenceRecord> nativeEvidence;
            Core::Finding importedHistorical;
            importedHistorical.title = L"Imported historical indicator";
            importedHistorical.category = L"Historical Source Evidence";
            importedHistorical.severityCaptured = false;
            const std::vector<Core::Finding> historicalEvidence = {
                importedHistorical
            };

            Core::HandleCollectionResult handles;
            handles.pid = process.pid;
            handles.state = Core::HandleCollectionState::Partial;
            handles.success = true;
            handles.statusMessage =
                L"Retained core handle rows; optional metadata is partial.";
            handles.systemHandleCount = 180000;
            handles.systemEntriesScanned = 180000;
            handles.selectedProcessHandlesMatched = 3;
            handles.selectedProcessHandlesOmitted = 2;
            handles.namesAttempted = 1;
            handles.namesFailed = 1;
            handles.retentionCapReached = true;
            handles.nameResolutionCapReached = true;
            handles.typeOrTargetResolutionPartial = true;
            Core::HandleInfo handle;
            handle.owningPid = process.pid;
            handle.handleValue = 0x64;
            handle.objectTypeIndex = 8;
            handle.objectType = L"Thread";
            handle.grantedAccessRaw = 0x10;
            handle.grantedAccess = L"0x00000010";
            handle.targetThreadId = 5200;
            handles.handles.push_back(std::move(handle));

            const std::filesystem::path outputPath =
                std::filesystem::temp_directory_path() /
                L"glasspane-selected-offline-export-test.json";
            std::wstring error;
            const bool exported = Export::ExportSelectedProcessDetailsToJson(
                snapshot,
                process.pid,
                modules,
                network,
                &handles,
                nullptr,
                nullptr,
                evidence,
                Core::MakeNotCapturedPersistedTriageSummary(),
                &nativeEvidence,
                &historicalEvidence,
                outputPath.wstring(),
                &error);
            Check(exported, L"offline selected-process JSON export succeeds");

            std::ifstream input(outputPath, std::ios::binary);
            const std::string json(
                (std::istreambuf_iterator<char>(input)),
                std::istreambuf_iterator<char>());
            Check(
                json.find("\"fileIdentityCaptured\": false") !=
                    std::string::npos,
                L"uncaptured file identities are explicitly marked absent");
            Check(
                json.find("\"fileIdentity\": null") != std::string::npos,
                L"offline export does not fabricate file identity data");
            Check(
                json.find("\"tokenInspectionCaptured\": true") !=
                    std::string::npos,
                L"persisted token evidence is identified as captured");
            Check(
                json.find("S-1-5-21-offline-fixture") != std::string::npos,
                L"persisted token evidence is serialized by value");
            Check(
                json.find("\"legacy_source_severity_captured\": false") !=
                    std::string::npos &&
                    json.find("\"legacy_source_severity\": null") !=
                        std::string::npos,
                L"uncaptured historical row severity remains explicit and is not fabricated as Info");
            Check(
                json.find("\"collectionState\": \"partial\"") !=
                    std::string::npos &&
                    json.find("\"queryFailureKind\": \"none\"") !=
                        std::string::npos &&
                    json.find("\"selectedProcessHandlesOmitted\": 2") !=
                        std::string::npos,
                L"partial handle collection state is explicit in selected-process JSON");
            Check(
                json.find("\"objectTypeIndex\": 8") != std::string::npos &&
                    json.find("\"targetThreadId\": 5200") !=
                        std::string::npos,
                L"retained handle typed identity is preserved in selected-process JSON");

            evidence.identity.pid += 1;
            error.clear();
            Check(
                !Export::ExportSelectedProcessDetailsToJson(
                    snapshot,
                    process.pid,
                    modules,
                    network,
                    nullptr,
                    nullptr,
                    nullptr,
                    evidence,
                    Core::MakeNotCapturedPersistedTriageSummary(),
                    &nativeEvidence,
                    nullptr,
                    outputPath.wstring(),
                    &error),
                L"stale captured evidence identity is rejected");

            evidence = {};
            error.clear();
            Check(
                !Export::ExportSelectedProcessDetailsToJson(
                    snapshot,
                    process.pid,
                    modules,
                    network,
                    nullptr,
                    nullptr,
                    nullptr,
                    evidence,
                    Core::MakeNotCapturedPersistedTriageSummary(),
                    &nativeEvidence,
                    nullptr,
                    outputPath.wstring(),
                    &error),
                L"typed source evidence requires exact process identity");

            std::error_code ignored;
            std::filesystem::remove(outputPath, ignored);
        }
    }

    int RunJsonExporterOfflineTests()
    {
        failures = 0;
        TestOfflineExportUsesOnlyCapturedEvidence();
        if (failures == 0)
        {
            std::wcout << L"Offline selected-process JSON export tests passed.\n";
        }
        return failures;
    }
}
