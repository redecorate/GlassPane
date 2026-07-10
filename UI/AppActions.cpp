#include "AppActions.h"

// This implementation file is included from ImGuiApp.cpp inside the private ImGuiApp class definition.
// Export and file-dialog state remain owned by ImGuiApp.

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
            const Core::FileIdentity& fileIdentity = CachedFileIdentity(*process);
            const std::vector<Core::FileIdentityIndicator> fileIdentityIndicators =
                BuildProcessFileIdentityIndicators(*process, fileIdentity);
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

        std::wstring HostnameText() const
        {
            wchar_t buffer[MAX_COMPUTERNAME_LENGTH + 1] = {};
            DWORD size = static_cast<DWORD>(_countof(buffer));
            return GetComputerNameW(buffer, &size) != FALSE ? std::wstring(buffer, size) : std::wstring{};
        }

        std::wstring CurrentUserText() const
        {
            wchar_t buffer[256] = {};
            DWORD size = static_cast<DWORD>(_countof(buffer));
            return GetUserNameW(buffer, &size) != FALSE && size > 0 ? std::wstring(buffer, size - 1) : std::wstring{};
        }

        std::wstring OsBuildText() const
        {
            OSVERSIONINFOEXW version = {};
            version.dwOSVersionInfoSize = sizeof(version);
            using RtlGetVersionFn = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);
            HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
            const auto rtlGetVersion = ntdll != nullptr
                ? reinterpret_cast<RtlGetVersionFn>(GetProcAddress(ntdll, "RtlGetVersion"))
                : nullptr;
            if (rtlGetVersion != nullptr &&
                rtlGetVersion(reinterpret_cast<PRTL_OSVERSIONINFOW>(&version)) == 0)
            {
                return L"Windows " +
                    std::to_wstring(version.dwMajorVersion) +
                    L"." +
                    std::to_wstring(version.dwMinorVersion) +
                    L" build " +
                    std::to_wstring(version.dwBuildNumber);
            }
            return L"Windows";
        }

        Export::NetworkIntelligenceSnapshotMetadata BuildNetworkIntelSnapshotMetadata() const
        {
            if (loadedSnapshotActive_)
            {
                return loadedSnapshotNetworkIntel_;
            }

            Export::NetworkIntelligenceSnapshotMetadata metadata;
            metadata.loaded = networkIndicatorFeed_.loaded;
            metadata.feedName = networkIndicatorFeed_.metadata.feedName;
            metadata.schemaVersion = networkIndicatorFeed_.metadata.schemaVersion;
            metadata.generatedAt = networkIndicatorFeed_.metadata.generatedAt;
            metadata.expiresAt = networkIndicatorFeed_.metadata.expiresAt;
            metadata.indicatorCount = networkIndicatorFeed_.indicators.size();
            metadata.source = networkIndicatorUsedFallback_ ? L"development fallback" : L"portable Indicators folder";
            metadata.status = NetworkIntelStatusText();

            const std::filesystem::path feedPath = networkIndicatorFeed_.metadata.sourcePath.empty()
                ? PortableNetworkIndicatorFeedPath()
                : std::filesystem::path(networkIndicatorFeed_.metadata.sourcePath);
            std::string hash;
            std::wstring hashError;
            if (networkIndicatorFeed_.loaded &&
                FileExists(feedPath) &&
                Export::ComputeFileSha256Hex(feedPath.wstring(), hash, &hashError))
            {
                metadata.localFeedSha256 = Utf8ToWide(hash.c_str());
            }
            return metadata;
        }

        static std::wstring LowercaseCopy(std::wstring value)
        {
            std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) {
                return static_cast<wchar_t>(std::towlower(ch));
            });
            return value;
        }

        static bool ContainsText(const std::wstring& value, const wchar_t* needle)
        {
            return LowercaseCopy(value).find(needle) != std::wstring::npos;
        }

        static std::wstring EvidenceFailureStatusFromMessage(const std::wstring& message)
        {
            if (ContainsText(message, L"access denied") ||
                ContainsText(message, L"denied") ||
                ContainsText(message, L"protected"))
            {
                return L"access_denied";
            }
            if (ContainsText(message, L"exited") ||
                ContainsText(message, L"no longer") ||
                ContainsText(message, L"not found"))
            {
                return L"process_exited";
            }
            if (ContainsText(message, L"unavailable") ||
                ContainsText(message, L"not available"))
            {
                return L"unavailable";
            }
            return L"failed";
        }

        template <typename T>
        static std::size_t TrimSnapshotVector(std::vector<T>& values, std::size_t limit)
        {
            const std::size_t originalCount = values.size();
            if (values.size() > limit)
            {
                values.resize(limit);
            }
            return originalCount;
        }

        static void ApplyCollectionStatus(
            Export::EvidenceCollectionStatus& status,
            bool success,
            const std::wstring& message,
            std::size_t originalCount,
            std::size_t savedCount)
        {
            status.status = success ? L"ok" : EvidenceFailureStatusFromMessage(message);
            status.message = message;
            status.originalCount = originalCount;
            status.savedCount = savedCount;

            if (originalCount > savedCount)
            {
                status.status = L"partial";
                status.truncated = true;
                const std::wstring truncationMessage = L"Truncated by snapshot limit.";
                status.message = status.message.empty()
                    ? truncationMessage
                    : status.message + L" " + truncationMessage;
            }
            else if (!success && savedCount > 0)
            {
                status.status = L"partial";
            }
        }

        static void SetNotAttemptedStatus(
            Export::EvidenceCollectionStatus& status,
            const std::wstring& message)
        {
            status.status = L"not_attempted";
            status.message = message;
            status.truncated = false;
            status.originalCount = 0;
            status.savedCount = 0;
        }

        static const wchar_t* EvidenceModeText(Export::SavedSnapshotEvidenceMode mode)
        {
            return mode == Export::SavedSnapshotEvidenceMode::Deep ? L"deep" : L"default";
        }

        static const char* EvidenceModeLogText(Export::SavedSnapshotEvidenceMode mode)
        {
            return mode == Export::SavedSnapshotEvidenceMode::Deep ? "deep" : "default bounded";
        }

        static bool ModuleHasSnapshotIndicator(const Core::ModuleInfo& module)
        {
            return !module.indicators.empty();
        }

        static bool EvidenceStatusCountsAsCollected(const Export::EvidenceCollectionStatus& status)
        {
            return status.status == L"ok" || status.status == L"partial";
        }

        static void CountEvidenceStatus(
            const Export::EvidenceCollectionStatus& status,
            std::size_t& okCount,
            std::size_t& failedCount,
            std::size_t& truncatedCount)
        {
            if (EvidenceStatusCountsAsCollected(status))
            {
                ++okCount;
            }
            else
            {
                ++failedCount;
            }
            if (status.truncated)
            {
                ++truncatedCount;
            }
        }

        static Export::FullEvidenceCollectionSummary CollectProcessEvidenceForSnapshot(
            const Core::ProcessSnapshot& snapshot,
            Export::SavedSnapshotEvidenceMode mode,
            std::vector<Export::ProcessEvidenceSnapshot>& processEvidence,
            const std::function<void(const std::string&, float)>& progress)
        {
            processEvidence.clear();
            processEvidence.reserve(snapshot.processes.size());

            const bool deepMode = mode == Export::SavedSnapshotEvidenceMode::Deep;
            std::size_t totalHandlesSaved = 0;
            std::size_t totalMemoryRegionsSaved = 0;

            Export::FullEvidenceCollectionSummary summary;
            summary.processCount = snapshot.processes.size();

            for (std::size_t processIndex = 0; processIndex < snapshot.processes.size(); ++processIndex)
            {
                const Core::ProcessInfo& process = snapshot.processes[processIndex];
                if (processIndex == 0 || processIndex % 10 == 0)
                {
                    const float fraction = snapshot.processes.empty()
                        ? 0.1f
                        : 0.1f + (static_cast<float>(processIndex) / static_cast<float>(snapshot.processes.size())) * 0.62f;
                    progress(
                        "Collecting process metadata " +
                            std::to_string(processIndex + 1) +
                            "/" +
                            std::to_string(snapshot.processes.size()) +
                            "...",
                        fraction);
                }

                Export::ProcessEvidenceSnapshot evidence;
                evidence.pid = process.pid;
                evidence.processName = process.name;

                evidence.runtime = Core::CollectProcessRuntimeInfo(process);
                std::size_t originalCount = TrimSnapshotVector(
                    evidence.runtime.threads,
                    deepMode ? Export::SnapshotDeepMaxThreadsPerProcess : 0);
                ApplyCollectionStatus(
                    evidence.runtimeStatus,
                    evidence.runtime.success,
                    evidence.runtime.errorMessage,
                    originalCount,
                    evidence.runtime.threads.size());
                if (!deepMode && originalCount > 0)
                {
                    evidence.runtimeStatus.status = L"partial";
                    evidence.runtimeStatus.message = L"Runtime summary saved; thread list omitted by default snapshot mode.";
                    evidence.runtimeStatus.truncated = true;
                }
                CountEvidenceStatus(
                    evidence.runtimeStatus,
                    summary.runtimeOk,
                    summary.runtimeFailed,
                    summary.truncatedCollections);

                evidence.token = Core::CollectProcessTokenInfo(process);
                originalCount = TrimSnapshotVector(
                    evidence.token.privileges,
                    deepMode ? Export::SnapshotDeepMaxPrivilegesPerProcess : 0);
                ApplyCollectionStatus(
                    evidence.tokenStatus,
                    evidence.token.success,
                    evidence.token.errorMessage,
                    originalCount,
                    evidence.token.privileges.size());
                if (!deepMode && originalCount > 0)
                {
                    evidence.tokenStatus.status = L"partial";
                    evidence.tokenStatus.message = L"Token summary saved; privilege list omitted by default snapshot mode.";
                    evidence.tokenStatus.truncated = true;
                }
                CountEvidenceStatus(
                    evidence.tokenStatus,
                    summary.tokenOk,
                    summary.tokenFailed,
                    summary.truncatedCollections);

                evidence.modules = Core::CollectProcessModules(process);
                originalCount = evidence.modules.modules.size();
                if (deepMode)
                {
                    TrimSnapshotVector(evidence.modules.modules, Export::SnapshotDeepMaxModulesPerProcess);
                }
                else
                {
                    auto& modules = evidence.modules.modules;
                    modules.erase(
                        std::remove_if(
                            modules.begin(),
                            modules.end(),
                            [](const Core::ModuleInfo& module) {
                                return !ModuleHasSnapshotIndicator(module);
                            }),
                        modules.end());
                    TrimSnapshotVector(modules, Export::SnapshotDefaultMaxIndicatorModulesPerProcess);
                }
                ApplyCollectionStatus(
                    evidence.modulesStatus,
                    evidence.modules.success,
                    evidence.modules.statusMessage,
                    originalCount,
                    evidence.modules.modules.size());
                if (!deepMode && originalCount > evidence.modules.modules.size())
                {
                    evidence.modulesStatus.status = L"partial";
                    evidence.modulesStatus.message =
                        L"Module summary saved; only module rows with indicators are included in default snapshot mode.";
                    evidence.modulesStatus.truncated = true;
                }
                CountEvidenceStatus(
                    evidence.modulesStatus,
                    summary.modulesOk,
                    summary.modulesFailed,
                    summary.truncatedCollections);

                if (deepMode)
                {
                    if (totalHandlesSaved >= Export::SnapshotDeepMaxTotalHandles)
                    {
                        evidence.handles.pid = process.pid;
                        evidence.handles.statusMessage = L"Skipped because the deep snapshot total handle cap was reached.";
                        evidence.handlesStatus.status = L"partial";
                        evidence.handlesStatus.message = evidence.handles.statusMessage;
                        evidence.handlesStatus.truncated = true;
                        ++summary.truncatedCollections;
                    }
                    else
                    {
                        evidence.handles = Core::CollectProcessHandles(process, &snapshot);
                        originalCount = evidence.handles.handles.size();
                        const std::size_t remainingTotal = Export::SnapshotDeepMaxTotalHandles - totalHandlesSaved;
                        const std::size_t handleLimit = std::min(Export::SnapshotDeepMaxHandlesPerProcess, remainingTotal);
                        TrimSnapshotVector(evidence.handles.handles, handleLimit);
                        totalHandlesSaved += evidence.handles.handles.size();
                        ApplyCollectionStatus(
                            evidence.handlesStatus,
                            evidence.handles.success,
                            evidence.handles.statusMessage,
                            originalCount,
                            evidence.handles.handles.size());
                        CountEvidenceStatus(
                            evidence.handlesStatus,
                            summary.handlesOk,
                            summary.handlesFailed,
                            summary.truncatedCollections);
                    }

                    if (totalMemoryRegionsSaved >= Export::SnapshotDeepMaxTotalMemoryRegions)
                    {
                        evidence.memory.pid = process.pid;
                        evidence.memory.statusMessage = L"Skipped because the deep snapshot total memory-region cap was reached.";
                        evidence.memoryStatus.status = L"partial";
                        evidence.memoryStatus.message = evidence.memory.statusMessage;
                        evidence.memoryStatus.truncated = true;
                        ++summary.truncatedCollections;
                    }
                    else
                    {
                        evidence.memory = Core::CollectMemoryRegionsForPid(process.pid);
                        originalCount = evidence.memory.regions.size();
                        const std::size_t remainingTotal =
                            Export::SnapshotDeepMaxTotalMemoryRegions - totalMemoryRegionsSaved;
                        const std::size_t memoryLimit = std::min(
                            Export::SnapshotDeepMaxMemoryRegionsPerProcess,
                            remainingTotal);
                        TrimSnapshotVector(evidence.memory.regions, memoryLimit);
                        totalMemoryRegionsSaved += evidence.memory.regions.size();
                        ApplyCollectionStatus(
                            evidence.memoryStatus,
                            evidence.memory.success,
                            evidence.memory.statusMessage,
                            originalCount,
                            evidence.memory.regions.size());
                        CountEvidenceStatus(
                            evidence.memoryStatus,
                            summary.memoryOk,
                            summary.memoryFailed,
                            summary.truncatedCollections);
                    }
                }
                else
                {
                    evidence.handles.pid = process.pid;
                    SetNotAttemptedStatus(
                        evidence.handlesStatus,
                        L"Handle list omitted by default snapshot mode. Use Save Deep Evidence Snapshot for capped handle rows.");
                    evidence.memory.pid = process.pid;
                    SetNotAttemptedStatus(
                        evidence.memoryStatus,
                        L"Memory region list omitted by default snapshot mode. Use Save Deep Evidence Snapshot for capped memory-region rows.");
                }

                processEvidence.push_back(std::move(evidence));
            }

            return summary;
        }

        static std::string EvidenceSummaryLog(
            Export::SavedSnapshotEvidenceMode mode,
            const Export::FullEvidenceCollectionSummary& summary)
        {
            return std::string("Evidence snapshot collected (") +
                EvidenceModeLogText(mode) +
                "): runtime " +
                std::to_string(summary.runtimeOk) + " ok/" +
                std::to_string(summary.runtimeFailed) + " failed, token " +
                std::to_string(summary.tokenOk) + " ok/" +
                std::to_string(summary.tokenFailed) + " failed, modules " +
                std::to_string(summary.modulesOk) + " ok/" +
                std::to_string(summary.modulesFailed) + " failed, handles " +
                std::to_string(summary.handlesOk) + " ok/" +
                std::to_string(summary.handlesFailed) + " failed, memory " +
                std::to_string(summary.memoryOk) + " ok/" +
                std::to_string(summary.memoryFailed) + " failed, " +
                std::to_string(summary.truncatedCollections) + " truncated collection(s).";
        }

        Export::SavedSnapshotExportContext BuildSavedSnapshotExportContext(
            const std::wstring& capturedAt,
            Export::SavedSnapshotEvidenceMode mode,
            const std::vector<Export::ProcessEvidenceSnapshot>* processEvidence) const
        {
            Export::SavedSnapshotExportContext context;
            context.snapshot = &snapshot_;
            context.networkLoaded = networkLoaded_;
            context.network = &networkSnapshot_;
            context.networkIndicatorMatches = loadedSnapshotActive_
                ? &loadedSnapshotNetworkIndicatorMatches_
                : &networkIndicatorMatches_;
            context.networkIntel = BuildNetworkIntelSnapshotMetadata();
            context.glassPaneVersion = Utf8ToWide(GlassPaneVersion().c_str());
            context.capturedAt =
                loadedSnapshotActive_ && !loadedSnapshotMetadata_.capturedAt.empty()
                    ? loadedSnapshotMetadata_.capturedAt
                    : capturedAt;
            context.hostname =
                loadedSnapshotActive_ && !loadedSnapshotMetadata_.hostname.empty()
                    ? loadedSnapshotMetadata_.hostname
                    : HostnameText();
            context.currentUser =
                loadedSnapshotActive_ && !loadedSnapshotMetadata_.currentUser.empty()
                    ? loadedSnapshotMetadata_.currentUser
                    : CurrentUserText();
            context.osBuild =
                loadedSnapshotActive_ && !loadedSnapshotMetadata_.osBuild.empty()
                    ? loadedSnapshotMetadata_.osBuild
                    : OsBuildText();
            context.evidenceMode =
                loadedSnapshotActive_ && !loadedSnapshotMetadata_.evidenceMode.empty()
                    ? loadedSnapshotMetadata_.evidenceMode
                    : EvidenceModeText(mode);
            context.selectedPid = selectedPid_;
            context.processEvidence = processEvidence;
            return context;
        }

        void SaveSnapshotFile(Export::SavedSnapshotEvidenceMode mode = Export::SavedSnapshotEvidenceMode::Default)
        {
            if (IsLongOperationActive())
            {
                AddLog(LogLevel::Warning, "Snapshot save ignored because another operation is running.");
                return;
            }

            const std::wstring defaultFileName =
                (mode == Export::SavedSnapshotEvidenceMode::Deep
                    ? std::wstring(L"GlassPane-DeepSnapshot-")
                    : std::wstring(L"GlassPane-Snapshot-")) +
                FileTimestamp() +
                L".json";
            wchar_t fileName[MAX_PATH] = {};
            wcsncpy_s(fileName, defaultFileName.c_str(), _TRUNCATE);
            if (!PromptForSnapshotSavePath(
                    fileName,
                    mode == Export::SavedSnapshotEvidenceMode::Deep
                        ? L"Save GlassPane Deep Evidence Snapshot"
                        : L"Save GlassPane Snapshot"))
            {
                return;
            }

            Core::ProcessSnapshot snapshotCopy = snapshot_;
            const bool loadedSnapshotActive = loadedSnapshotActive_;
            const bool networkLoaded = networkLoaded_;
            Core::NetworkCollectionResult networkCopy = networkSnapshot_;
            const std::vector<Core::NetworkIndicatorMatch> networkMatchesCopy =
                loadedSnapshotActive ? loadedSnapshotNetworkIndicatorMatches_ : networkIndicatorMatches_;
            std::vector<Export::ProcessEvidenceSnapshot> loadedEvidenceCopy =
                loadedSnapshotActive ? loadedSnapshotEvidence_ : std::vector<Export::ProcessEvidenceSnapshot>{};
            Export::NetworkIntelligenceSnapshotMetadata networkIntel = BuildNetworkIntelSnapshotMetadata();
            const std::wstring glassPaneVersion = Utf8ToWide(GlassPaneVersion().c_str());
            const std::wstring capturedAt =
                loadedSnapshotActive && !loadedSnapshotMetadata_.capturedAt.empty()
                    ? loadedSnapshotMetadata_.capturedAt
                    : LocalTimestamp();
            const std::wstring hostname =
                loadedSnapshotActive && !loadedSnapshotMetadata_.hostname.empty()
                    ? loadedSnapshotMetadata_.hostname
                    : HostnameText();
            const std::wstring currentUser =
                loadedSnapshotActive && !loadedSnapshotMetadata_.currentUser.empty()
                    ? loadedSnapshotMetadata_.currentUser
                    : CurrentUserText();
            const std::wstring osBuild =
                loadedSnapshotActive && !loadedSnapshotMetadata_.osBuild.empty()
                    ? loadedSnapshotMetadata_.osBuild
                    : OsBuildText();
            const std::wstring evidenceMode =
                loadedSnapshotActive && !loadedSnapshotMetadata_.evidenceMode.empty()
                    ? loadedSnapshotMetadata_.evidenceMode
                    : EvidenceModeText(mode);
            const std::uint32_t selectedPid = selectedPid_;
            const std::wstring outputPath = fileName;
            const LongRunningOperationKind kind = mode == Export::SavedSnapshotEvidenceMode::Deep
                ? LongRunningOperationKind::SaveDeepSnapshot
                : LongRunningOperationKind::SaveSnapshot;

            AddLog(
                LogLevel::Info,
                std::string(mode == Export::SavedSnapshotEvidenceMode::Deep ? "Deep evidence" : "Snapshot") +
                    " save started: " + WideToUtf8(fileName));

            StartLongOperation(
                kind,
                "Preparing snapshot...",
                [snapshotCopy = std::move(snapshotCopy),
                 networkCopy = std::move(networkCopy),
                 networkMatchesCopy = std::move(networkMatchesCopy),
                 loadedEvidenceCopy = std::move(loadedEvidenceCopy),
                 outputPath,
                 mode,
                 networkLoaded,
                 loadedSnapshotActive,
                 networkIntel,
                 glassPaneVersion,
                 capturedAt,
                 hostname,
                 currentUser,
                 osBuild,
                 evidenceMode,
                 selectedPid](
                    std::function<void(const std::string&, float)> progress) mutable {
                    LongOperationResult result;
                    result.outputPath = outputPath;
                    const ULONGLONG started = GetTickCount64();
                    progress("Collecting process metadata...", 0.08f);

                    std::vector<Export::ProcessEvidenceSnapshot> evidence;
                    if (loadedSnapshotActive)
                    {
                        evidence = std::move(loadedEvidenceCopy);
                        progress("Writing loaded snapshot evidence...", 0.65f);
                    }
                    else
                    {
                        const Export::FullEvidenceCollectionSummary summary =
                            CollectProcessEvidenceForSnapshot(snapshotCopy, mode, evidence, progress);
                        result.logs.push_back({ LogLevel::Info, EvidenceSummaryLog(mode, summary) });
                    }

                    progress("Writing snapshot...", 0.78f);
                    Export::SavedSnapshotExportContext context;
                    context.snapshot = &snapshotCopy;
                    context.networkLoaded = networkLoaded;
                    context.network = &networkCopy;
                    context.networkIndicatorMatches = &networkMatchesCopy;
                    context.networkIntel = networkIntel;
                    context.glassPaneVersion = glassPaneVersion;
                    context.capturedAt = capturedAt;
                    context.hostname = hostname;
                    context.currentUser = currentUser;
                    context.osBuild = osBuild;
                    context.evidenceMode = evidenceMode;
                    context.selectedPid = selectedPid;
                    context.processEvidence = &evidence;

                    std::wstring error;
                    result.success = Export::SaveGlassPaneSnapshot(context, outputPath, &error);
                    result.elapsedMs = ElapsedMs(started);
                    if (result.success)
                    {
                        result.status =
                            std::string(mode == Export::SavedSnapshotEvidenceMode::Deep
                                ? "Deep evidence snapshot saved: "
                                : "Snapshot saved: ") +
                            WideToUtf8(outputPath);
                        result.logs.push_back({
                            LogLevel::Info,
                            result.status + " (" + std::to_string(result.elapsedMs) + " ms)."
                        });
                    }
                    else
                    {
                        result.status = "Snapshot failed: " + WideToUtf8(error);
                        result.logs.push_back({ LogLevel::High, result.status });
                    }

                    evidence.clear();
                    evidence.shrink_to_fit();
                    progress("Finalizing...", 0.98f);
                    return result;
                });
        }

        void SaveDeepEvidenceSnapshotFile()
        {
            SaveSnapshotFile(Export::SavedSnapshotEvidenceMode::Deep);
        }

        void RequestDeepEvidenceSnapshotSave()
        {
            if (IsLongOperationActive())
            {
                AddLog(LogLevel::Warning, "Deep evidence snapshot save ignored because another operation is running.");
                return;
            }

            deepEvidenceSnapshotPopupRequested_ = true;
        }

        void CancelDeepEvidenceSnapshotSave()
        {
            AddLog(LogLevel::Info, "Deep evidence snapshot save cancelled.");
        }

        void PreserveLiveStateBeforeLoad()
        {
            if (loadedSnapshotActive_ || liveSnapshotPreserved_)
            {
                return;
            }

            liveSnapshotBeforeLoad_ = snapshot_;
            liveNetworkSnapshotBeforeLoad_ = networkSnapshot_;
            liveNetworkLoadedBeforeLoad_ = networkLoaded_;
            liveSelectedPidBeforeLoad_ = selectedPid_;
            liveLastRefreshTimeBeforeLoad_ = lastRefreshTime_;
            liveLastNetworkRefreshTimeBeforeLoad_ = lastNetworkRefreshTime_;
            liveSuspiciousCountBeforeLoad_ = suspiciousCount_;
            liveSnapshotPreserved_ = true;
        }

        void ApplyLoadedSnapshot(const Export::SavedSnapshotDocument& document, const std::wstring& sourcePath)
        {
            PreserveLiveStateBeforeLoad();
            loadedSnapshotActive_ = true;
            loadedSnapshotMetadata_ = document.metadata;
            loadedSnapshotMetadata_.sourcePath = sourcePath;
            loadedSnapshotNetworkIntel_ = document.networkIntel;
            loadedSnapshotEvidence_ = document.processEvidence;
            loadedSnapshotNetworkIndicatorMatches_ = document.networkIndicatorMatches;
            loadedSnapshotEvidenceByPid_.clear();
            for (std::size_t index = 0; index < loadedSnapshotEvidence_.size(); ++index)
            {
                loadedSnapshotEvidenceByPid_[loadedSnapshotEvidence_[index].pid] = index;
            }
            loadedSnapshotStatus_ = L"Viewing saved snapshot captured " +
                (document.metadata.capturedAt.empty() ? std::wstring(L"(unknown time)") : document.metadata.capturedAt);

            snapshot_ = document.snapshot;
            networkLoaded_ = document.networkLoaded;
            networkSnapshot_ = document.network;
            lastRefreshTime_ = document.metadata.capturedAt.empty() ? L"(saved snapshot)" : document.metadata.capturedAt;
            lastNetworkRefreshTime_ = networkLoaded_ ? lastRefreshTime_ : L"(not loaded in saved snapshot)";
            selectedPid_ = Core::FindProcessByPid(snapshot_, document.metadata.selectedPid) != nullptr
                ? document.metadata.selectedPid
                : (snapshot_.processes.empty() ? InvalidPid : snapshot_.processes.front().pid);

            ClearSelectedProcessEvidence();
            if (const Core::ProcessInfo* selectedProcess = Core::FindProcessByPid(snapshot_, selectedPid_);
                selectedProcess != nullptr)
            {
                RestoreLoadedSnapshotEvidenceForProcess(*selectedProcess);
            }
            fileIdentityCache_.clear();
            InvalidateFindingsCache();
            MarkAllTablesNeedAutoSize();
            MarkSnapshotDependentCachesDirty();
            suspiciousCount_ = CountSuspiciousProcesses();
            RefreshNetworkIntelMatches(false);
            RebuildFocusedGraph("loaded-snapshot");
            RequestGraphFit();
            RebuildVisibleProcessRowsIfNeeded();
            RebuildGraphWorldLayoutIfNeeded();
            AddLog(
                LogLevel::Info,
                "Loaded saved snapshot: " +
                    std::to_string(snapshot_.processes.size()) +
                    " process(es) from " +
                    WideToUtf8(sourcePath) +
                    ".");
        }

        void LoadSnapshotFile()
        {
            if (IsLongOperationActive())
            {
                AddLog(LogLevel::Warning, "Snapshot load ignored because another operation is running.");
                return;
            }

            wchar_t fileName[MAX_PATH] = {};
            if (!PromptForSnapshotOpenPath(fileName))
            {
                return;
            }

            AddLog(LogLevel::Info, "Snapshot load started: " + WideToUtf8(fileName));
            const std::wstring inputPath = fileName;
            StartLongOperation(
                LongRunningOperationKind::LoadSnapshot,
                "Reading saved snapshot...",
                [inputPath](std::function<void(const std::string&, float)> progress) mutable {
                    LongOperationResult result;
                    result.inputPath = inputPath;
                    const ULONGLONG started = GetTickCount64();
                    progress("Parsing snapshot JSON...", 0.35f);
                    std::wstring error;
                    result.hasLoadedSnapshot =
                        Export::LoadGlassPaneSnapshot(inputPath, result.loadedSnapshot, &error);
                    result.success = result.hasLoadedSnapshot;
                    result.elapsedMs = ElapsedMs(started);
                    if (result.success)
                    {
                        result.status =
                            "Snapshot loaded: " +
                            std::to_string(result.loadedSnapshot.snapshot.processes.size()) +
                            " process(es).";
                        result.logs.push_back({
                            LogLevel::Info,
                            "Snapshot loaded successfully from " +
                                WideToUtf8(inputPath) +
                                " (" +
                                std::to_string(result.elapsedMs) +
                                " ms)."
                        });
                    }
                    else
                    {
                        result.status = "Snapshot load failed: " + WideToUtf8(error);
                        result.logs.push_back({ LogLevel::High, result.status });
                    }
                    progress("Finalizing...", 0.95f);
                    return result;
                });
        }

        void ReturnToLiveView(bool refreshAfterRestore)
        {
            if (!loadedSnapshotActive_)
            {
                if (refreshAfterRestore)
                {
                    RefreshSnapshot(true);
                }
                return;
            }

            loadedSnapshotActive_ = false;
            loadedSnapshotMetadata_ = {};
            loadedSnapshotNetworkIntel_ = {};
            loadedSnapshotEvidence_.clear();
            loadedSnapshotEvidenceByPid_.clear();
            loadedSnapshotNetworkIndicatorMatches_.clear();
            loadedSnapshotStatus_.clear();

            if (liveSnapshotPreserved_)
            {
                snapshot_ = liveSnapshotBeforeLoad_;
                networkSnapshot_ = liveNetworkSnapshotBeforeLoad_;
                networkLoaded_ = liveNetworkLoadedBeforeLoad_;
                selectedPid_ = liveSelectedPidBeforeLoad_;
                lastRefreshTime_ = liveLastRefreshTimeBeforeLoad_;
                lastNetworkRefreshTime_ = liveLastNetworkRefreshTimeBeforeLoad_;
                suspiciousCount_ = liveSuspiciousCountBeforeLoad_;
            }

            liveSnapshotBeforeLoad_ = {};
            liveNetworkSnapshotBeforeLoad_ = {};
            liveNetworkLoadedBeforeLoad_ = false;
            liveSelectedPidBeforeLoad_ = InvalidPid;
            liveLastRefreshTimeBeforeLoad_.clear();
            liveLastNetworkRefreshTimeBeforeLoad_.clear();
            liveSuspiciousCountBeforeLoad_ = 0;
            liveSnapshotPreserved_ = false;

            ClearSelectedProcessEvidence();
            fileIdentityCache_.clear();
            InvalidateFindingsCache();
            MarkAllTablesNeedAutoSize();
            MarkSnapshotDependentCachesDirty();
            RefreshNetworkIntelMatches(false);
            RebuildFocusedGraph("return-live");
            RequestGraphFit();
            RebuildVisibleProcessRowsIfNeeded();
            RebuildGraphWorldLayoutIfNeeded();
            AddLog(LogLevel::Info, "Returned to live endpoint view.");

            if (refreshAfterRestore)
            {
                RefreshSnapshot(true);
            }
        }

        void UseLoadedSnapshotAsBaseline()
        {
            if (!loadedSnapshotActive_)
            {
                return;
            }

            baselineCompareSnapshot_ = CaptureSnapshotForCompare();
            baselineCompareSnapshot_.captureTimeLocal = loadedSnapshotMetadata_.capturedAt;
            compareResult_ = {};
            compareResultValid_ = false;
            compareChangedProcessRows_.clear();
            AddLog(
                LogLevel::Info,
                "Loaded snapshot set as compare baseline: " +
                    std::to_string(baselineCompareSnapshot_.processes.size()) +
                    " process(es).");
            if (currentCompareSnapshot_.captured)
            {
                ComputeSnapshotCompare();
            }
        }

        bool WriteSelectedMarkdownReportToPath(const std::wstring& filePath)
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                return false;
            }

            const Core::ChainAnalysisResult chain = Core::AnalyzeChain(snapshot_, process->pid);
            Core::FileIdentity loadedSnapshotFileIdentity;
            const Core::FileIdentity& fileIdentity = loadedSnapshotActive_
                ? loadedSnapshotFileIdentity
                : CachedFileIdentity(*process);
            const std::vector<Core::FileIdentityIndicator> fileIdentityIndicators =
                loadedSnapshotActive_
                    ? std::vector<Core::FileIdentityIndicator>{}
                    : BuildProcessFileIdentityIndicators(*process, fileIdentity);
            const std::vector<Core::Finding> findings =
                loadedSnapshotActive_
                    ? std::vector<Core::Finding>{}
                    : FindingsForSelectedProcess(*process, chain, fileIdentity);
            const std::vector<Core::NetworkConnection> selectedNetworkConnections =
                networkLoaded_
                    ? SelectedNetworkConnectionsForExport()
                    : std::vector<Core::NetworkConnection>{};
            const std::vector<Core::NetworkIndicatorMatch> selectedNetworkIndicatorMatches =
                SelectedNetworkIndicatorMatchesForProcess(process->pid);

            Export::SelectedProcessMarkdownReportContext reportContext;
            reportContext.snapshot = &snapshot_;
            reportContext.pid = selectedPid_;
            reportContext.appVersion = Utf8ToWide(GlassPaneVersion().c_str());
            reportContext.buildConfiguration = Utf8ToWide(BuildConfiguration());
            reportContext.findings = findings;
            reportContext.fileIdentity = loadedSnapshotActive_ ? nullptr : &fileIdentity;
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

            std::wstring error;
            if (!Export::ExportSelectedProcessMarkdownReport(reportContext, filePath, &error))
            {
                AddLog(LogLevel::Warning, "Selected report package export failed: " + WideToUtf8(error));
                return false;
            }
            return true;
        }

        struct SelectedMarkdownPackageData
        {
            bool available = false;
            Core::ProcessSnapshot snapshot;
            std::uint32_t pid = 0;
            std::wstring appVersion;
            std::wstring buildConfiguration;
            std::vector<Core::Finding> findings;

            bool hasFileIdentity = false;
            Core::FileIdentity fileIdentity;
            std::vector<Core::FileIdentityIndicator> fileIdentityIndicators;

            bool modulesLoaded = false;
            Core::ModuleCollectionResult modules;

            bool networkLoaded = false;
            bool networkSuccess = false;
            std::wstring networkStatusMessage;
            std::vector<Core::NetworkConnection> networkConnections;
            bool networkIntelFeedLoaded = false;
            std::wstring networkIntelStatusMessage;
            Core::NetworkIndicatorFeed networkIndicatorFeed;
            std::vector<Core::NetworkIndicatorMatch> networkIndicatorMatches;

            bool tokenLoaded = false;
            Core::TokenInfo token;

            bool runtimeLoaded = false;
            Core::RuntimeInfo runtime;

            bool memoryLoaded = false;
            Core::MemoryCollectionResult memory;

            bool handlesLoaded = false;
            Core::HandleCollectionResult handles;
        };

        SelectedMarkdownPackageData BuildSelectedMarkdownPackageData()
        {
            SelectedMarkdownPackageData data;
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                return data;
            }

            data.available = true;
            data.snapshot = snapshot_;
            data.pid = selectedPid_;
            data.appVersion = Utf8ToWide(GlassPaneVersion().c_str());
            data.buildConfiguration = Utf8ToWide(BuildConfiguration());

            const Core::ChainAnalysisResult chain = Core::AnalyzeChain(snapshot_, process->pid);
            if (!loadedSnapshotActive_)
            {
                data.fileIdentity = CachedFileIdentity(*process);
                data.hasFileIdentity = true;
                data.fileIdentityIndicators =
                    BuildProcessFileIdentityIndicators(*process, data.fileIdentity);
                data.findings = FindingsForSelectedProcess(*process, chain, data.fileIdentity);
            }

            data.modulesLoaded = ModulesLoadedForProcess(*process);
            if (data.modulesLoaded)
            {
                data.modules = selectedModules_;
            }

            data.networkLoaded = networkLoaded_;
            data.networkSuccess = networkSnapshot_.success;
            data.networkStatusMessage = networkSnapshot_.statusMessage;
            if (data.networkLoaded)
            {
                data.networkConnections = SelectedNetworkConnectionsForExport();
            }
            data.networkIntelFeedLoaded = networkIndicatorFeed_.loaded;
            data.networkIntelStatusMessage = NetworkIntelStatusText();
            if (networkIndicatorFeed_.loaded)
            {
                data.networkIndicatorFeed = networkIndicatorFeed_;
                data.networkIndicatorMatches =
                    SelectedNetworkIndicatorMatchesForProcess(process->pid);
            }

            data.tokenLoaded = TokenLoadedForProcess(*process);
            if (data.tokenLoaded)
            {
                data.token = selectedToken_;
            }
            data.runtimeLoaded = RuntimeLoadedForProcess(*process);
            if (data.runtimeLoaded)
            {
                data.runtime = selectedRuntime_;
            }
            data.memoryLoaded = MemoryLoadedForProcess(*process);
            if (data.memoryLoaded)
            {
                data.memory = selectedMemory_;
            }
            data.handlesLoaded = HandlesLoadedForProcess(*process);
            if (data.handlesLoaded)
            {
                data.handles = selectedHandles_;
            }

            return data;
        }

        static bool WriteSelectedMarkdownReportPackage(
            const SelectedMarkdownPackageData& data,
            const std::wstring& filePath,
            std::wstring* error)
        {
            if (!data.available)
            {
                if (error != nullptr)
                {
                    *error = L"No selected process report data is available.";
                }
                return false;
            }

            Export::SelectedProcessMarkdownReportContext reportContext;
            reportContext.snapshot = &data.snapshot;
            reportContext.pid = data.pid;
            reportContext.appVersion = data.appVersion;
            reportContext.buildConfiguration = data.buildConfiguration;
            reportContext.findings = data.findings;
            reportContext.fileIdentity = data.hasFileIdentity ? &data.fileIdentity : nullptr;
            reportContext.fileIdentityIndicators = data.fileIdentityIndicators;
            reportContext.modulesLoaded = data.modulesLoaded;
            reportContext.modules = data.modulesLoaded ? &data.modules : nullptr;
            reportContext.networkLoaded = data.networkLoaded;
            reportContext.networkSuccess = data.networkSuccess;
            reportContext.networkStatusMessage = data.networkStatusMessage;
            reportContext.networkConnections = data.networkLoaded ? &data.networkConnections : nullptr;
            reportContext.networkIntelFeedLoaded = data.networkIntelFeedLoaded;
            reportContext.networkIntelStatusMessage = data.networkIntelStatusMessage;
            reportContext.networkIndicatorFeed =
                data.networkIntelFeedLoaded ? &data.networkIndicatorFeed : nullptr;
            reportContext.networkIndicatorMatches =
                data.networkIntelFeedLoaded ? &data.networkIndicatorMatches : nullptr;
            reportContext.tokenLoaded = data.tokenLoaded;
            reportContext.token = data.tokenLoaded ? &data.token : nullptr;
            reportContext.runtimeLoaded = data.runtimeLoaded;
            reportContext.runtime = data.runtimeLoaded ? &data.runtime : nullptr;
            reportContext.memoryLoaded = data.memoryLoaded;
            reportContext.memory = data.memoryLoaded ? &data.memory : nullptr;
            reportContext.handlesLoaded = data.handlesLoaded;
            reportContext.handles = data.handlesLoaded ? &data.handles : nullptr;

            return Export::ExportSelectedProcessMarkdownReport(reportContext, filePath, error);
        }

        struct CompareMarkdownPackageData
        {
            bool available = false;
            Core::ProcessSnapshotCapture baseline;
            Core::ProcessSnapshotCapture current;
            Core::SnapshotCompareResult result;
            std::wstring appVersion;
            std::wstring buildConfiguration;
        };

        CompareMarkdownPackageData BuildCompareMarkdownPackageData() const
        {
            CompareMarkdownPackageData data;
            if (!baselineCompareSnapshot_.captured || !currentCompareSnapshot_.captured || !compareResultValid_)
            {
                return data;
            }

            data.available = true;
            data.baseline = baselineCompareSnapshot_;
            data.current = currentCompareSnapshot_;
            data.result = compareResult_;
            data.appVersion = Utf8ToWide(GlassPaneVersion().c_str());
            data.buildConfiguration = Utf8ToWide(BuildConfiguration());
            return data;
        }

        static bool WriteCompareReportPackage(
            const CompareMarkdownPackageData& data,
            const std::wstring& filePath,
            std::wstring* error)
        {
            if (!data.available)
            {
                if (error != nullptr)
                {
                    *error = L"No snapshot compare report data is available.";
                }
                return false;
            }

            Export::SnapshotCompareMarkdownReportContext context;
            context.baseline = &data.baseline;
            context.current = &data.current;
            context.result = &data.result;
            context.appVersion = data.appVersion;
            context.buildConfiguration = data.buildConfiguration;

            return Export::ExportSnapshotCompareMarkdownReport(context, filePath, error);
        }

        void ExportEvidencePackage()
        {
            if (IsLongOperationActive())
            {
                AddLog(LogLevel::Warning, "Evidence package export ignored because another operation is running.");
                return;
            }

            std::wstring parentFolder;
            AddLog(LogLevel::Info, "Select destination folder for evidence package.");
            if (!PromptForEvidencePackageParentFolder(parentFolder))
            {
                AddLog(LogLevel::Info, "Evidence package export cancelled.");
                return;
            }

            const std::wstring generatedAt = LocalTimestamp();
            const std::filesystem::path packagePath =
                std::filesystem::path(parentFolder) / (L"GlassPane-Evidence-" + FileTimestamp());

            const bool loadedSnapshotActive = loadedSnapshotActive_;
            Core::ProcessSnapshot snapshotCopy = snapshot_;
            const bool networkLoaded = networkLoaded_;
            Core::NetworkCollectionResult networkCopy = networkSnapshot_;
            const std::vector<Core::NetworkIndicatorMatch> networkMatchesCopy =
                loadedSnapshotActive ? loadedSnapshotNetworkIndicatorMatches_ : networkIndicatorMatches_;
            std::vector<Export::ProcessEvidenceSnapshot> loadedEvidenceCopy =
                loadedSnapshotActive ? loadedSnapshotEvidence_ : std::vector<Export::ProcessEvidenceSnapshot>{};
            const Export::NetworkIntelligenceSnapshotMetadata networkIntelMetadata =
                BuildNetworkIntelSnapshotMetadata();
            const std::wstring glassPaneVersion = Utf8ToWide(GlassPaneVersion().c_str());
            const std::wstring capturedAt =
                loadedSnapshotActive && !loadedSnapshotMetadata_.capturedAt.empty()
                    ? loadedSnapshotMetadata_.capturedAt
                    : generatedAt;
            const std::wstring hostname =
                loadedSnapshotActive && !loadedSnapshotMetadata_.hostname.empty()
                    ? loadedSnapshotMetadata_.hostname
                    : HostnameText();
            const std::wstring currentUser =
                loadedSnapshotActive && !loadedSnapshotMetadata_.currentUser.empty()
                    ? loadedSnapshotMetadata_.currentUser
                    : CurrentUserText();
            const std::wstring osBuild =
                loadedSnapshotActive && !loadedSnapshotMetadata_.osBuild.empty()
                    ? loadedSnapshotMetadata_.osBuild
                    : OsBuildText();
            const std::wstring evidenceMode =
                loadedSnapshotActive && !loadedSnapshotMetadata_.evidenceMode.empty()
                    ? loadedSnapshotMetadata_.evidenceMode
                    : EvidenceModeText(Export::SavedSnapshotEvidenceMode::Default);
            const std::uint32_t selectedPid = selectedPid_;
            SelectedMarkdownPackageData selectedReportData = BuildSelectedMarkdownPackageData();
            CompareMarkdownPackageData compareReportData = BuildCompareMarkdownPackageData();
            const std::string appVersionText = GlassPaneVersion();
            const std::string buildConfigurationText = BuildConfiguration();

            AddLog(LogLevel::Info, "Evidence package export started: " + WideToUtf8(packagePath.wstring()));

            StartLongOperation(
                LongRunningOperationKind::ExportEvidencePackage,
                "Preparing package...",
                [packagePath,
                 generatedAt,
                 snapshotCopy = std::move(snapshotCopy),
                 networkCopy = std::move(networkCopy),
                 networkMatchesCopy = std::move(networkMatchesCopy),
                 loadedEvidenceCopy = std::move(loadedEvidenceCopy),
                 selectedReportData = std::move(selectedReportData),
                 compareReportData = std::move(compareReportData),
                 networkIntelMetadata,
                 glassPaneVersion,
                 capturedAt,
                 hostname,
                 currentUser,
                 osBuild,
                 evidenceMode,
                 selectedPid,
                 networkLoaded,
                 loadedSnapshotActive,
                 appVersionText,
                 buildConfigurationText](
                    std::function<void(const std::string&, float)> progress) mutable {
                    LongOperationResult result;
                    result.outputPath = packagePath.wstring();
                    const ULONGLONG started = GetTickCount64();

                    std::error_code fsError;
                    if (std::filesystem::exists(packagePath, fsError))
                    {
                        result.status = "Evidence package failed: destination already exists.";
                        result.logs.push_back({ LogLevel::High, result.status });
                        return result;
                    }

                    progress("Creating package folder...", 0.05f);
                    std::filesystem::create_directories(packagePath, fsError);
                    if (fsError)
                    {
                        result.status = "Evidence package failed: could not create destination folder.";
                        result.logs.push_back({ LogLevel::High, result.status });
                        return result;
                    }

                    std::vector<std::wstring> files;
                    std::wstring error;
                    std::vector<Export::ProcessEvidenceSnapshot> evidence;
                    if (loadedSnapshotActive)
                    {
                        evidence = std::move(loadedEvidenceCopy);
                        progress("Writing loaded snapshot evidence...", 0.52f);
                    }
                    else
                    {
                        const Export::FullEvidenceCollectionSummary summary =
                            CollectProcessEvidenceForSnapshot(
                                snapshotCopy,
                                Export::SavedSnapshotEvidenceMode::Default,
                                evidence,
                                progress);
                        result.logs.push_back({
                            LogLevel::Info,
                            EvidenceSummaryLog(Export::SavedSnapshotEvidenceMode::Default, summary)
                        });
                    }

                    const std::wstring snapshotFile = L"snapshot.glasspane-snapshot.json";
                    progress("Writing snapshot...", 0.72f);
                    Export::SavedSnapshotExportContext snapshotContext;
                    snapshotContext.snapshot = &snapshotCopy;
                    snapshotContext.networkLoaded = networkLoaded;
                    snapshotContext.network = &networkCopy;
                    snapshotContext.networkIndicatorMatches = &networkMatchesCopy;
                    snapshotContext.networkIntel = networkIntelMetadata;
                    snapshotContext.glassPaneVersion = glassPaneVersion;
                    snapshotContext.capturedAt = capturedAt;
                    snapshotContext.hostname = hostname;
                    snapshotContext.currentUser = currentUser;
                    snapshotContext.osBuild = osBuild;
                    snapshotContext.evidenceMode = evidenceMode;
                    snapshotContext.selectedPid = selectedPid;
                    snapshotContext.processEvidence = &evidence;
                    if (!Export::SaveGlassPaneSnapshot(
                            snapshotContext,
                            (packagePath / snapshotFile).wstring(),
                            &error))
                    {
                        result.status = "Evidence package failed: " + WideToUtf8(error);
                        result.logs.push_back({ LogLevel::High, result.status });
                        return result;
                    }
                    files.push_back(snapshotFile);
                    evidence.clear();
                    evidence.shrink_to_fit();

                    progress("Writing reports...", 0.82f);
                    if (selectedReportData.available)
                    {
                        if (WriteSelectedMarkdownReportPackage(
                                selectedReportData,
                                (packagePath / L"selected-process-report.md").wstring(),
                                &error))
                        {
                            files.push_back(L"selected-process-report.md");
                        }
                        else
                        {
                            result.logs.push_back({
                                LogLevel::Warning,
                                "Selected report package export failed: " + WideToUtf8(error)
                            });
                        }
                    }

                    if (compareReportData.available)
                    {
                        if (WriteCompareReportPackage(
                                compareReportData,
                                (packagePath / L"compare-report.md").wstring(),
                                &error))
                        {
                            files.push_back(L"compare-report.md");
                        }
                        else
                        {
                            result.logs.push_back({
                                LogLevel::Warning,
                                "Compare report package export failed: " + WideToUtf8(error)
                            });
                        }
                    }

                    if (networkIntelMetadata.loaded)
                    {
                        if (Export::ExportNetworkIntelligenceMetadataJson(
                                networkIntelMetadata,
                                (packagePath / L"network-intelligence-metadata.json").wstring(),
                                &error))
                        {
                            files.push_back(L"network-intelligence-metadata.json");
                        }
                        else
                        {
                            result.logs.push_back({
                                LogLevel::Warning,
                                "Network intelligence metadata package export failed: " + WideToUtf8(error)
                            });
                        }
                    }

                    const std::wstring versionFile = L"glasspane-version.txt";
                    {
                        std::ofstream versionOutput(
                            packagePath / versionFile,
                            std::ios::binary | std::ios::trunc);
                        versionOutput << appVersionText << "\n";
                        versionOutput << "Build: " << buildConfigurationText << "\n";
                        if (!versionOutput)
                        {
                            result.status = "Evidence package failed: could not write version metadata.";
                            result.logs.push_back({ LogLevel::High, result.status });
                            return result;
                        }
                    }
                    files.push_back(versionFile);

                    const std::wstring readmeFile = L"README.txt";
                    if (!Export::WriteEvidencePackageReadme(
                            (packagePath / readmeFile).wstring(),
                            generatedAt,
                            glassPaneVersion,
                            loadedSnapshotActive,
                            files,
                            &error))
                    {
                        result.status = "Evidence package failed: " + WideToUtf8(error);
                        result.logs.push_back({ LogLevel::High, result.status });
                        return result;
                    }
                    files.insert(files.begin(), readmeFile);

                    progress("Generating hash manifest...", 0.92f);
                    if (!Export::WriteSha256Manifest(packagePath.wstring(), files, L"hashes.sha256", &error))
                    {
                        result.status = "Evidence package failed: " + WideToUtf8(error);
                        result.logs.push_back({ LogLevel::High, result.status });
                        return result;
                    }
                    files.push_back(L"hashes.sha256");

                    result.success = true;
                    result.elapsedMs = ElapsedMs(started);
                    result.status =
                        "Evidence package exported: " +
                        WideToUtf8(packagePath.wstring()) +
                        " (" +
                        std::to_string(files.size()) +
                        " file(s)).";
                    result.logs.push_back({
                        LogLevel::Info,
                        result.status + " (" + std::to_string(result.elapsedMs) + " ms)."
                    });
                    progress("Finalizing...", 0.98f);
                    return result;
                });
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

        std::wstring EvidenceDefaultRootPath() const
        {
            PWSTR documentsPath = nullptr;
            if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Documents, KF_FLAG_DEFAULT, nullptr, &documentsPath)) &&
                documentsPath != nullptr)
            {
                std::wstring result = documentsPath;
                CoTaskMemFree(documentsPath);
                return result;
            }

            if (documentsPath != nullptr)
            {
                CoTaskMemFree(documentsPath);
            }
            return {};
        }

        bool PromptForSnapshotSavePath(wchar_t (&fileName)[MAX_PATH], const wchar_t* title) const
        {
            const std::wstring initialDir = EvidenceDefaultRootPath();
            OPENFILENAMEW dialog = {};
            dialog.lStructSize = sizeof(dialog);
            dialog.hwndOwner = hwnd_;
            dialog.lpstrTitle = title;
            dialog.lpstrFilter = L"GlassPane Snapshot (*.json)\0*.json\0All Files (*.*)\0*.*\0";
            dialog.lpstrFile = fileName;
            dialog.nMaxFile = MAX_PATH;
            dialog.lpstrDefExt = L"json";
            if (!initialDir.empty())
            {
                dialog.lpstrInitialDir = initialDir.c_str();
            }
            dialog.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
            return GetSaveFileNameW(&dialog) != FALSE;
        }

        bool PromptForSnapshotOpenPath(wchar_t (&fileName)[MAX_PATH]) const
        {
            const std::wstring initialDir = EvidenceDefaultRootPath();
            OPENFILENAMEW dialog = {};
            dialog.lStructSize = sizeof(dialog);
            dialog.hwndOwner = hwnd_;
            dialog.lpstrTitle = L"Load GlassPane Snapshot";
            dialog.lpstrFilter = L"GlassPane Snapshots (*.glasspane-snapshot.json;*.json)\0*.glasspane-snapshot.json;*.json\0All Files (*.*)\0*.*\0";
            dialog.lpstrFile = fileName;
            dialog.nMaxFile = MAX_PATH;
            dialog.lpstrDefExt = L"json";
            if (!initialDir.empty())
            {
                dialog.lpstrInitialDir = initialDir.c_str();
            }
            dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
            return GetOpenFileNameW(&dialog) != FALSE;
        }

        bool PromptForEvidencePackageParentFolder(std::wstring& folderPath) const
        {
            const std::wstring initialDir = EvidenceDefaultRootPath();
            Microsoft::WRL::ComPtr<IFileOpenDialog> dialog;
            if (SUCCEEDED(CoCreateInstance(
                    CLSID_FileOpenDialog,
                    nullptr,
                    CLSCTX_INPROC_SERVER,
                    IID_PPV_ARGS(&dialog))) &&
                dialog)
            {
                DWORD options = 0;
                if (SUCCEEDED(dialog->GetOptions(&options)))
                {
                    dialog->SetOptions(options | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST);
                }
                dialog->SetTitle(L"Export GlassPane Evidence Package");
                Microsoft::WRL::ComPtr<IFileDialogCustomize> customize;
                if (SUCCEEDED(dialog.As(&customize)) && customize)
                {
                    customize->AddText(
                        1001,
                        L"Select a destination folder for the GlassPane evidence package.");
                }
                if (!initialDir.empty())
                {
                    Microsoft::WRL::ComPtr<IShellItem> defaultFolder;
                    if (SUCCEEDED(SHCreateItemFromParsingName(
                            initialDir.c_str(),
                            nullptr,
                            IID_PPV_ARGS(&defaultFolder))) &&
                        defaultFolder)
                    {
                        dialog->SetDefaultFolder(defaultFolder.Get());
                    }
                }
                if (SUCCEEDED(dialog->Show(hwnd_)))
                {
                    Microsoft::WRL::ComPtr<IShellItem> result;
                    if (SUCCEEDED(dialog->GetResult(&result)) && result)
                    {
                        PWSTR path = nullptr;
                        if (SUCCEEDED(result->GetDisplayName(SIGDN_FILESYSPATH, &path)) && path != nullptr)
                        {
                            folderPath = path;
                            CoTaskMemFree(path);
                            return true;
                        }
                        if (path != nullptr)
                        {
                            CoTaskMemFree(path);
                        }
                    }
                    return false;
                }
                return false;
            }

            BROWSEINFOW browse = {};
            browse.hwndOwner = hwnd_;
            browse.lpszTitle =
                L"Export GlassPane Evidence Package\n\n"
                L"Select a destination folder for the GlassPane evidence package.";
            browse.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;

            PIDLIST_ABSOLUTE item = SHBrowseForFolderW(&browse);
            if (item == nullptr)
            {
                return false;
            }

            wchar_t path[MAX_PATH] = {};
            const BOOL ok = SHGetPathFromIDListW(item, path);
            CoTaskMemFree(item);
            if (!ok)
            {
                return false;
            }

            folderPath = path;
            return true;
        }


