#include "EvidenceCacheActions.h"

// This implementation file is included from ImGuiApp.cpp inside the private ImGuiApp class definition.
// Selected-process evidence state, caches, timings, and logs remain owned by ImGuiApp.

        static std::wstring EvidenceCacheKey(const Core::ProcessInfo& process)
        {
            return std::to_wstring(process.pid) + L"|" +
                (process.hasCreationTime
                    ? std::to_wstring(process.creationTimeFileTime)
                    : std::wstring(L"pid-only"));
        }

        static bool CacheMatchesProcess(
            std::uint32_t cachedPid,
            std::uint64_t cachedCreationTime,
            const Core::ProcessInfo& process)
        {
            if (cachedPid != process.pid)
            {
                return false;
            }

            if (process.hasCreationTime)
            {
                return cachedCreationTime == process.creationTimeFileTime;
            }

            return cachedCreationTime == 0;
        }

        bool ModulesLoadedForProcess(const Core::ProcessInfo& process) const
        {
            return selectedModulesLoaded_ &&
                CacheMatchesProcess(selectedModulesPid_, selectedModulesCreationTime_, process);
        }

        bool TokenLoadedForProcess(const Core::ProcessInfo& process) const
        {
            return selectedTokenLoaded_ &&
                CacheMatchesProcess(selectedTokenPid_, selectedTokenCreationTime_, process);
        }

        bool RuntimeLoadedForProcess(const Core::ProcessInfo& process) const
        {
            return selectedRuntimeLoaded_ &&
                CacheMatchesProcess(selectedRuntimePid_, selectedRuntimeCreationTime_, process);
        }

        bool MemoryLoadedForProcess(const Core::ProcessInfo& process) const
        {
            return selectedMemoryLoaded_ &&
                CacheMatchesProcess(selectedMemoryPid_, selectedMemoryCreationTime_, process);
        }

        bool HandlesLoadedForProcess(const Core::ProcessInfo& process) const
        {
            return selectedHandlesLoaded_ &&
                CacheMatchesProcess(selectedHandlesPid_, selectedHandlesCreationTime_, process);
        }

        bool RestoreModulesFromCache(const Core::ProcessInfo& process)
        {
            const auto cached = moduleEvidenceCache_.find(EvidenceCacheKey(process));
            if (cached == moduleEvidenceCache_.end())
            {
                return false;
            }

            selectedModules_ = cached->second;
            selectedModulesLoaded_ = true;
            selectedModulesPid_ = process.pid;
            selectedModulesCreationTime_ = ProcessCacheStamp(process);
            selectedModulePid_ = InvalidPid;
            selectedModuleIndex_ = 0;
            modulesTableNeedsAutoSize_ = true;
            return true;
        }

        bool RestoreTokenFromCache(const Core::ProcessInfo& process)
        {
            const auto cached = tokenEvidenceCache_.find(EvidenceCacheKey(process));
            if (cached == tokenEvidenceCache_.end())
            {
                return false;
            }

            selectedToken_ = cached->second;
            selectedTokenLoaded_ = true;
            selectedTokenPid_ = process.pid;
            selectedTokenCreationTime_ = ProcessCacheStamp(process);
            tokenTableNeedsAutoSize_ = true;
            return true;
        }

        bool RestoreRuntimeFromCache(const Core::ProcessInfo& process)
        {
            const auto cached = runtimeEvidenceCache_.find(EvidenceCacheKey(process));
            if (cached == runtimeEvidenceCache_.end())
            {
                return false;
            }

            selectedRuntime_ = cached->second;
            selectedRuntimeLoaded_ = true;
            selectedRuntimePid_ = process.pid;
            selectedRuntimeCreationTime_ = ProcessCacheStamp(process);
            runtimeTableNeedsAutoSize_ = true;
            return true;
        }

        bool RestoreMemoryFromCache(const Core::ProcessInfo& process)
        {
            const auto cached = memoryEvidenceCache_.find(EvidenceCacheKey(process));
            if (cached == memoryEvidenceCache_.end())
            {
                return false;
            }

            selectedMemory_ = cached->second;
            selectedMemoryLoaded_ = true;
            selectedMemoryPid_ = process.pid;
            selectedMemoryCreationTime_ = ProcessCacheStamp(process);
            memoryTableNeedsAutoSize_ = true;
            visibleMemoryRegionsDirty_ = true;
            return true;
        }

        bool RestoreHandlesFromCache(const Core::ProcessInfo& process)
        {
            const auto cached = handleEvidenceCache_.find(EvidenceCacheKey(process));
            if (cached == handleEvidenceCache_.end())
            {
                return false;
            }

            selectedHandles_ = cached->second;
            selectedHandlesLoaded_ = true;
            selectedHandlesPid_ = process.pid;
            selectedHandlesCreationTime_ = ProcessCacheStamp(process);
            handlesTableNeedsAutoSize_ = true;
            visibleHandlesDirty_ = true;
            return true;
        }

        void ClearSelectedProcessEvidence()
        {
            selectedModules_ = {};
            selectedModulesLoaded_ = false;
            selectedModulesPid_ = InvalidPid;
            selectedModulesCreationTime_ = 0;
            selectedModulePid_ = InvalidPid;
            selectedModuleIndex_ = 0;

            selectedToken_ = {};
            selectedTokenLoaded_ = false;
            selectedTokenPid_ = InvalidPid;
            selectedTokenCreationTime_ = 0;

            selectedRuntime_ = {};
            selectedRuntimeLoaded_ = false;
            selectedRuntimePid_ = InvalidPid;
            selectedRuntimeCreationTime_ = 0;

            selectedMemory_ = {};
            selectedMemoryLoaded_ = false;
            selectedMemoryPid_ = InvalidPid;
            selectedMemoryCreationTime_ = 0;
            visibleMemoryRegionsDirty_ = true;
            visibleMemoryRegionIndexes_.clear();
            visibleMemoryPid_ = InvalidPid;
            visibleMemoryCreationTime_ = 0;
            visibleMemorySourceSize_ = 0;
            visibleMemorySearchText_.clear();

            selectedHandles_ = {};
            selectedHandlesLoaded_ = false;
            selectedHandlesPid_ = InvalidPid;
            selectedHandlesCreationTime_ = 0;
            visibleHandlesDirty_ = true;
            visibleHandleIndexes_.clear();
            visibleHandlesPid_ = InvalidPid;
            visibleHandlesCreationTime_ = 0;
            visibleHandlesSourceSize_ = 0;
            visibleHandlesWithIndicatorsCount_ = 0;
            visibleHandlesNameStatusCount_ = 0;
            visibleHandlesSearchText_.clear();

            InvalidateFindingsCache();
        }

        void MarkSelectedEvidenceTablesNeedAutoSize()
        {
            modulesTableNeedsAutoSize_ = true;
            networkTableNeedsAutoSize_ = true;
            tokenTableNeedsAutoSize_ = true;
            runtimeTableNeedsAutoSize_ = true;
            memoryTableNeedsAutoSize_ = true;
            handlesTableNeedsAutoSize_ = true;
        }

        void RefreshHandlesForSelectionChange(const Core::ProcessInfo& process)
        {
            if (HandlesLoadedForProcess(process))
            {
                return;
            }

            const ULONGLONG started = GetTickCount64();
            RefreshHandles(false);
            const ULONGLONG elapsedMs = GetTickCount64() - started;

            std::string message =
                "Handles refreshed for selected PID " + std::to_string(process.pid) +
                ": " + std::to_string(selectedHandles_.handles.size()) +
                " handle(s), " + std::to_string(selectedHandles_.sensitiveCount) +
                " sensitive, " + std::to_string(elapsedMs) + " ms.";
            if (!selectedHandles_.success && !selectedHandles_.statusMessage.empty())
            {
                message += " " + WideToUtf8(selectedHandles_.statusMessage);
            }

            AddLog(selectedHandles_.success ? LogLevel::Info : LogLevel::Warning, message);
        }

        void RefreshRuntimeForSelectionChange(const Core::ProcessInfo& process)
        {
            if (RuntimeLoadedForProcess(process))
            {
                return;
            }

            const ULONGLONG started = GetTickCount64();
            RefreshRuntime(false);
            const ULONGLONG elapsedMs = GetTickCount64() - started;

            std::string message =
                "Runtime refreshed for selected PID " + std::to_string(process.pid) +
                ": " + std::to_string(selectedRuntime_.threadCount) +
                " thread(s), " + std::to_string(selectedRuntime_.handleCount) +
                " handle(s), " + std::to_string(elapsedMs) + " ms.";
            if (!selectedRuntime_.success && !selectedRuntime_.errorMessage.empty())
            {
                message += " " + WideToUtf8(selectedRuntime_.errorMessage);
            }

            AddLog(selectedRuntime_.success ? LogLevel::Info : LogLevel::Warning, message);
        }

        void EnsureSelectedProcessEvidenceLoaded(const Core::ProcessInfo& process)
        {
            std::vector<std::string> refreshed;
            bool hasFailure = false;

            if (!ModulesLoadedForProcess(process) && !RestoreModulesFromCache(process))
            {
                RefreshModules(false);
                refreshed.push_back("modules");
                hasFailure = hasFailure || !selectedModules_.success;
            }

            if (!TokenLoadedForProcess(process) && !RestoreTokenFromCache(process))
            {
                RefreshToken(false);
                refreshed.push_back("token");
                hasFailure = hasFailure || !selectedToken_.success;
            }

            if (!RuntimeLoadedForProcess(process) && !RestoreRuntimeFromCache(process))
            {
                RefreshRuntime(false);
                refreshed.push_back("runtime");
                hasFailure = hasFailure || !selectedRuntime_.success;
            }

            if (!MemoryLoadedForProcess(process) && !RestoreMemoryFromCache(process))
            {
                RefreshMemory(false);
                refreshed.push_back("memory");
                hasFailure = hasFailure || !selectedMemory_.success;
            }

            if (!HandlesLoadedForProcess(process) && !RestoreHandlesFromCache(process))
            {
                RefreshHandles(false);
                refreshed.push_back("handles");
                hasFailure = hasFailure || !selectedHandles_.success;
            }

            if (!networkLoaded_)
            {
                RefreshNetwork(false);
                refreshed.push_back("network");
                hasFailure = hasFailure || !networkSnapshot_.success;
            }

            if (refreshed.empty())
            {
                return;
            }

            std::string summary;
            for (std::size_t index = 0; index < refreshed.size(); ++index)
            {
                if (index > 0)
                {
                    summary += ", ";
                }
                summary += refreshed[index];
            }

            AddLog(
                hasFailure ? LogLevel::Warning : LogLevel::Info,
                "Selected-process evidence refreshed for PID " + std::to_string(process.pid) +
                    ": " + summary + ".");
        }

        void RefreshModules(bool logActivity = true)
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                if (logActivity)
                {
                    AddLog(LogLevel::Warning, "No selected process for module refresh.");
                }
                selectedModules_ = {};
                selectedModulesLoaded_ = false;
                selectedModulesPid_ = InvalidPid;
                selectedModulesCreationTime_ = 0;
                return;
            }

            const ULONGLONG started = GetTickCount64();
            selectedModules_ = Core::CollectProcessModules(*process);
            timings_.modulesMs = ElapsedMs(started);
            selectedModulesLoaded_ = true;
            modulesTableNeedsAutoSize_ = true;
            selectedModulesPid_ = process->pid;
            selectedModulesCreationTime_ = ProcessCacheStamp(*process);
            selectedModulePid_ = InvalidPid;
            selectedModuleIndex_ = 0;
            moduleEvidenceCache_[EvidenceCacheKey(*process)] = selectedModules_;
            TrimEvidenceCache(moduleEvidenceCache_);
            InvalidateFindingsCache();
            if (logActivity)
            {
                AddLog(
                    selectedModules_.success ? LogLevel::Info : LogLevel::Warning,
                    "Module refresh for PID " + std::to_string(process->pid) + ": " +
                        WideToUtf8(selectedModules_.statusMessage) +
                        " (" + std::to_string(timings_.modulesMs) + " ms).");
            }
        }

        void RefreshToken(bool logActivity = true)
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                selectedToken_ = {};
                selectedTokenLoaded_ = false;
                selectedTokenPid_ = InvalidPid;
                selectedTokenCreationTime_ = 0;
                InvalidateFindingsCache();
                if (logActivity)
                {
                    AddLog(LogLevel::Warning, "No selected process for token refresh.");
                }
                return;
            }

            const ULONGLONG started = GetTickCount64();
            selectedToken_ = Core::CollectProcessTokenInfo(*process);
            timings_.tokenMs = ElapsedMs(started);
            selectedTokenLoaded_ = true;
            tokenTableNeedsAutoSize_ = true;
            selectedTokenPid_ = process->pid;
            selectedTokenCreationTime_ = ProcessCacheStamp(*process);
            tokenEvidenceCache_[EvidenceCacheKey(*process)] = selectedToken_;
            TrimEvidenceCache(tokenEvidenceCache_);
            InvalidateFindingsCache();

            if (logActivity)
            {
                AddLog(
                    selectedToken_.success ? LogLevel::Info : LogLevel::Warning,
                    "Token refresh for PID " + std::to_string(process->pid) + ": " +
                        (selectedToken_.success ? "loaded token metadata" : WideToUtf8(selectedToken_.errorMessage)) +
                        " (" + std::to_string(timings_.tokenMs) + " ms).");
            }
        }

        void RefreshRuntime(bool logActivity = true)
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                selectedRuntime_ = {};
                selectedRuntimeLoaded_ = false;
                selectedRuntimePid_ = InvalidPid;
                selectedRuntimeCreationTime_ = 0;
                InvalidateFindingsCache();
                if (logActivity)
                {
                    AddLog(LogLevel::Warning, "No selected process for runtime refresh.");
                }
                return;
            }

            const ULONGLONG started = GetTickCount64();
            selectedRuntime_ = Core::CollectProcessRuntimeInfo(*process);
            timings_.runtimeMs = ElapsedMs(started);
            selectedRuntimeLoaded_ = true;
            runtimeTableNeedsAutoSize_ = true;
            selectedRuntimePid_ = process->pid;
            selectedRuntimeCreationTime_ = ProcessCacheStamp(*process);
            runtimeEvidenceCache_[EvidenceCacheKey(*process)] = selectedRuntime_;
            TrimEvidenceCache(runtimeEvidenceCache_);
            InvalidateFindingsCache();

            if (logActivity)
            {
                AddLog(
                    selectedRuntime_.success ? LogLevel::Info : LogLevel::Warning,
                    "Runtime refresh for PID " + std::to_string(process->pid) + ": " +
                        std::to_string(selectedRuntime_.threadCount) +
                        " thread(s), " +
                        std::to_string(selectedRuntime_.handleCount) +
                        " handle(s) in " + std::to_string(timings_.runtimeMs) + " ms.");
            }
        }

        void RefreshMemory(bool logActivity = true)
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                selectedMemory_ = {};
                selectedMemoryLoaded_ = false;
                selectedMemoryPid_ = InvalidPid;
                selectedMemoryCreationTime_ = 0;
                visibleMemoryRegionsDirty_ = true;
                visibleMemoryRegionIndexes_.clear();
                visibleMemoryPid_ = InvalidPid;
                visibleMemoryCreationTime_ = 0;
                visibleMemorySourceSize_ = 0;
                visibleMemorySearchText_.clear();
                InvalidateFindingsCache();
                if (logActivity)
                {
                    AddLog(LogLevel::Warning, "No selected process for memory refresh.");
                }
                return;
            }

            const ULONGLONG started = GetTickCount64();
            selectedMemory_ = Core::CollectMemoryRegionsForPid(process->pid);
            timings_.memoryMs = ElapsedMs(started);
            selectedMemoryLoaded_ = true;
            memoryTableNeedsAutoSize_ = true;
            selectedMemoryPid_ = process->pid;
            selectedMemoryCreationTime_ = ProcessCacheStamp(*process);
            visibleMemoryRegionsDirty_ = true;
            memoryEvidenceCache_[EvidenceCacheKey(*process)] = selectedMemory_;
            TrimEvidenceCache(memoryEvidenceCache_);
            InvalidateFindingsCache();

            if (logActivity)
            {
                AddLog(
                    selectedMemory_.success ? LogLevel::Info : LogLevel::Warning,
                    "Memory refresh for PID " + std::to_string(process->pid) + ": " +
                        std::to_string(selectedMemory_.regions.size()) +
                        " region(s), " +
                        std::to_string(selectedMemory_.suspiciousRegions) +
                        " suspicious in " + std::to_string(timings_.memoryMs) + " ms.");
            }
        }

        void RefreshHandles(bool logActivity = true)
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                selectedHandles_ = {};
                selectedHandlesLoaded_ = false;
                selectedHandlesPid_ = InvalidPid;
                selectedHandlesCreationTime_ = 0;
                visibleHandlesDirty_ = true;
                visibleHandleIndexes_.clear();
                visibleHandlesPid_ = InvalidPid;
                visibleHandlesCreationTime_ = 0;
                visibleHandlesSourceSize_ = 0;
                visibleHandlesWithIndicatorsCount_ = 0;
                visibleHandlesNameStatusCount_ = 0;
                visibleHandlesSearchText_.clear();
                InvalidateFindingsCache();
                if (logActivity)
                {
                    AddLog(LogLevel::Warning, "No selected process for handle refresh.");
                }
                return;
            }

            const ULONGLONG started = GetTickCount64();
            selectedHandles_ = Core::CollectProcessHandles(*process, &snapshot_);
            timings_.handlesMs = ElapsedMs(started);
            selectedHandlesLoaded_ = true;
            handlesTableNeedsAutoSize_ = true;
            selectedHandlesPid_ = process->pid;
            selectedHandlesCreationTime_ = ProcessCacheStamp(*process);
            visibleHandlesDirty_ = true;
            handleEvidenceCache_[EvidenceCacheKey(*process)] = selectedHandles_;
            TrimEvidenceCache(handleEvidenceCache_);
            InvalidateFindingsCache();

            if (logActivity)
            {
                AddLog(
                    selectedHandles_.success ? LogLevel::Info : LogLevel::Warning,
                    "Handle refresh for PID " + std::to_string(process->pid) + ": " +
                        std::to_string(selectedHandles_.handles.size()) +
                        " handle(s), " +
                        std::to_string(selectedHandles_.sensitiveCount) +
                        " sensitive in " + std::to_string(timings_.handlesMs) + " ms.");
            }
        }
