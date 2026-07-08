#include "AppActions.h"

// This implementation file is included from ImGuiApp.cpp inside the private ImGuiApp class definition.
// Export and file-dialog state remain owned by ImGuiApp.

        void ExportSnapshot()
        {
            wchar_t fileName[MAX_PATH] = L"glasspane-snapshot.json";
            if (!PromptForJsonPath(fileName))
            {
                return;
            }

            std::wstring error;
            const ULONGLONG started = GetTickCount64();
            if (!Export::ExportSnapshotToJson(snapshot_, fileName, &error))
            {
                timings_.jsonExportMs = ElapsedMs(started);
                AddLog(LogLevel::High, "Snapshot export failed: " + WideToUtf8(error));
                MessageBoxW(hwnd_, error.c_str(), L"Export failed", MB_ICONERROR | MB_OK);
                return;
            }
            timings_.jsonExportMs = ElapsedMs(started);

            AddLog(LogLevel::Info, "Snapshot exported: " + WideToUtf8(fileName) +
                " (" + std::to_string(timings_.jsonExportMs) + " ms).");
        }

        void ExportSelectedDetails()
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                AddLog(LogLevel::Warning, "No selected process to export.");
                return;
            }

            if (!ModulesLoadedForProcess(*process))
            {
                RefreshModules();
            }

            if (!networkLoaded_)
            {
                RefreshNetwork(true);
            }
            const std::vector<Core::NetworkConnection> selectedNetworkConnections = SelectedNetworkConnectionsForExport();

            wchar_t fileName[MAX_PATH] = L"glasspane-selected-process.json";
            if (!PromptForJsonPath(fileName))
            {
                return;
            }

            std::wstring error;
            const Core::HandleCollectionResult* handlesForExport =
                HandlesLoadedForProcess(*process) ? &selectedHandles_ : nullptr;
            const Core::RuntimeInfo* runtimeForExport =
                RuntimeLoadedForProcess(*process) ? &selectedRuntime_ : nullptr;
            const Core::MemoryCollectionResult* memoryForExport =
                MemoryLoadedForProcess(*process) ? &selectedMemory_ : nullptr;
            const ULONGLONG started = GetTickCount64();
            if (!Export::ExportSelectedProcessDetailsToJson(
                snapshot_,
                selectedPid_,
                selectedModules_,
                selectedNetworkConnections,
                handlesForExport,
                runtimeForExport,
                memoryForExport,
                fileName,
                &error))
            {
                timings_.jsonExportMs = ElapsedMs(started);
                AddLog(LogLevel::High, "Selected process export failed: " + WideToUtf8(error));
                MessageBoxW(hwnd_, error.c_str(), L"Export selected failed", MB_ICONERROR | MB_OK);
                return;
            }
            timings_.jsonExportMs = ElapsedMs(started);

            AddLog(LogLevel::Info, "Selected process exported: " + WideToUtf8(fileName) +
                " (" + std::to_string(timings_.jsonExportMs) + " ms).");
        }

        void ExportSelectedMarkdownReport()
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                AddLog(LogLevel::Warning, "No selected process for report export.");
                return;
            }

            const std::wstring defaultFileName =
                L"glasspane-report-" +
                SanitizedFileNamePart(process->name) +
                L"-" +
                std::to_wstring(process->pid) +
                L"-" +
                FileTimestamp() +
                L".md";

            wchar_t fileName[MAX_PATH] = {};
            wcsncpy_s(fileName, defaultFileName.c_str(), _TRUNCATE);
            if (!PromptForMarkdownPath(fileName))
            {
                return;
            }

            const Core::ChainAnalysisResult chain = Core::AnalyzeChain(snapshot_, process->pid);
            const Core::FileIdentity& fileIdentity = CachedFileIdentity(process->executablePath);
            const std::vector<Core::FileIdentityIndicator> fileIdentityIndicators =
                Core::BuildFileIdentityIndicators(fileIdentity, process->name, true);
            const std::vector<Core::Finding> findings =
                FindingsForSelectedProcess(*process, chain, fileIdentity);
            const std::vector<Core::NetworkConnection> selectedNetworkConnections =
                networkLoaded_
                    ? SelectedNetworkConnectionsForExport()
                    : std::vector<Core::NetworkConnection>{};
            const std::vector<Core::NetworkIndicatorMatch> selectedNetworkIndicatorMatches =
                SelectedNetworkIndicatorMatchesForProcess(process->pid);
            const std::string appVersion = GlassPaneVersion();

            Export::SelectedProcessMarkdownReportContext reportContext;
            reportContext.snapshot = &snapshot_;
            reportContext.pid = selectedPid_;
            reportContext.appVersion = Utf8ToWide(appVersion.c_str());
            reportContext.buildConfiguration = Utf8ToWide(BuildConfiguration());
            reportContext.findings = findings;
            reportContext.fileIdentity = &fileIdentity;
            reportContext.fileIdentityIndicators = fileIdentityIndicators;
            reportContext.modulesLoaded = ModulesLoadedForProcess(*process);
            reportContext.modules = reportContext.modulesLoaded ? &selectedModules_ : nullptr;
            reportContext.networkLoaded = networkLoaded_;
            reportContext.networkSuccess = networkSnapshot_.success;
            reportContext.networkStatusMessage = networkSnapshot_.statusMessage;
            reportContext.networkConnections = reportContext.networkLoaded ? &selectedNetworkConnections : nullptr;
            reportContext.networkIntelFeedLoaded = networkIndicatorFeed_.loaded;
            reportContext.networkIntelStatusMessage = NetworkIntelStatusText();
            reportContext.networkIndicatorFeed = networkIndicatorFeed_.loaded ? &networkIndicatorFeed_ : nullptr;
            reportContext.networkIndicatorMatches =
                networkIndicatorFeed_.loaded ? &selectedNetworkIndicatorMatches : nullptr;
            reportContext.tokenLoaded = TokenLoadedForProcess(*process);
            reportContext.token = reportContext.tokenLoaded ? &selectedToken_ : nullptr;
            reportContext.runtimeLoaded = RuntimeLoadedForProcess(*process);
            reportContext.runtime = reportContext.runtimeLoaded ? &selectedRuntime_ : nullptr;
            reportContext.memoryLoaded = MemoryLoadedForProcess(*process);
            reportContext.memory = reportContext.memoryLoaded ? &selectedMemory_ : nullptr;
            reportContext.handlesLoaded = HandlesLoadedForProcess(*process);
            reportContext.handles = reportContext.handlesLoaded ? &selectedHandles_ : nullptr;

            AddLog(
                LogLevel::Info,
                "Markdown report export started for " + DisplayName(process->name) +
                    " (PID " + std::to_string(process->pid) + ").");

            std::wstring error;
            const ULONGLONG started = GetTickCount64();
            if (!Export::ExportSelectedProcessMarkdownReport(reportContext, fileName, &error))
            {
                timings_.markdownReportMs = ElapsedMs(started);
                AddLog(LogLevel::High, "Markdown report export failed: " + WideToUtf8(error));
                MessageBoxW(hwnd_, error.c_str(), L"Export report failed", MB_ICONERROR | MB_OK);
                return;
            }
            timings_.markdownReportMs = ElapsedMs(started);

            AddLog(LogLevel::Info, "Markdown report exported: " + WideToUtf8(fileName) +
                " (" + std::to_string(timings_.markdownReportMs) + " ms).");
        }

        bool PromptForJsonPath(wchar_t (&fileName)[MAX_PATH]) const
        {
            OPENFILENAMEW dialog = {};
            dialog.lStructSize = sizeof(dialog);
            dialog.hwndOwner = hwnd_;
            dialog.lpstrFilter = L"JSON Files (*.json)\0*.json\0All Files (*.*)\0*.*\0";
            dialog.lpstrFile = fileName;
            dialog.nMaxFile = MAX_PATH;
            dialog.lpstrDefExt = L"json";
            dialog.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
            return GetSaveFileNameW(&dialog) != FALSE;
        }

        bool PromptForMarkdownPath(wchar_t (&fileName)[MAX_PATH]) const
        {
            OPENFILENAMEW dialog = {};
            dialog.lStructSize = sizeof(dialog);
            dialog.hwndOwner = hwnd_;
            dialog.lpstrFilter = L"Markdown Files (*.md)\0*.md\0All Files (*.*)\0*.*\0";
            dialog.lpstrFile = fileName;
            dialog.nMaxFile = MAX_PATH;
            dialog.lpstrDefExt = L"md";
            dialog.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
            return GetSaveFileNameW(&dialog) != FALSE;
        }


