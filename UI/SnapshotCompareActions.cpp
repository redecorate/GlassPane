#include "SnapshotCompareActions.h"

// This implementation file is included from ImGuiApp.cpp inside the private ImGuiApp class definition.
// Snapshot Compare state, snapshot ownership, timings, and logs remain owned by ImGuiApp.
        Core::ProcessSnapshotCapture CaptureSnapshotForCompare() const
        {
            return Core::CaptureProcessSnapshotForCompare(
                snapshot_,
                networkLoaded_ ? &networkSnapshot_ : nullptr,
                networkLoaded_,
                LocalTimestamp());
        }

        void ComputeSnapshotCompare()
        {
            if (!baselineCompareSnapshot_.captured || !currentCompareSnapshot_.captured)
            {
                compareResult_ = {};
                compareResultValid_ = false;
                compareChangedProcessRows_.clear();
                return;
            }

            const ULONGLONG started = GetTickCount64();
            compareResult_ = Core::CompareSnapshots(baselineCompareSnapshot_, currentCompareSnapshot_);
            timings_.snapshotCompareMs = ElapsedMs(started);
            compareResultValid_ = true;
            RebuildCompareChangedProcessRows();
            AddLog(
                LogLevel::Info,
                "Snapshot compare computed: " +
                    std::to_string(compareResult_.newProcesses.size()) +
                    " new, " +
                    std::to_string(compareResult_.exitedProcesses.size()) +
                    " exited, " +
                    std::to_string(compareResult_.changedProcesses.size()) +
                    " changed (" + std::to_string(timings_.snapshotCompareMs) + " ms).");
        }

        void CaptureBaselineSnapshot()
        {
            RefreshSnapshot();
            baselineCompareSnapshot_ = CaptureSnapshotForCompare();
            compareResult_ = {};
            compareResultValid_ = false;
            compareChangedProcessRows_.clear();
            AddLog(
                LogLevel::Info,
                "Baseline snapshot captured after refresh: " +
                    std::to_string(baselineCompareSnapshot_.processes.size()) +
                    " process(es).");

            if (currentCompareSnapshot_.captured)
            {
                ComputeSnapshotCompare();
            }
        }

        void CaptureCurrentSnapshot()
        {
            RefreshSnapshot();
            currentCompareSnapshot_ = CaptureSnapshotForCompare();
            AddLog(
                LogLevel::Info,
                "Current snapshot captured after refresh: " +
                    std::to_string(currentCompareSnapshot_.processes.size()) +
                    " process(es).");

            if (baselineCompareSnapshot_.captured)
            {
                ComputeSnapshotCompare();
            }
            else
            {
                compareResult_ = {};
                compareResultValid_ = false;
                compareChangedProcessRows_.clear();
            }
        }

        void ClearSnapshotCompare()
        {
            baselineCompareSnapshot_ = {};
            currentCompareSnapshot_ = {};
            compareResult_ = {};
            compareResultValid_ = false;
            compareChangedProcessRows_.clear();
            AddLog(LogLevel::Info, "Snapshot compare cleared.");
        }

        bool CompareHasNoDifferences() const
        {
            return compareResultValid_ &&
                compareResult_.newProcesses.empty() &&
                compareResult_.exitedProcesses.empty() &&
                compareResult_.changedProcesses.empty() &&
                compareResult_.newNetworkConnections.empty() &&
                compareResult_.closedNetworkConnections.empty() &&
                compareResult_.newFindings.empty() &&
                compareResult_.removedFindings.empty() &&
                compareResult_.changedFindings.empty();
        }

        std::wstring CompareEndpointText(const Core::SnapshotNetworkEndpoint& endpoint, bool remote) const
        {
            const std::wstring& address = remote ? endpoint.remoteAddress : endpoint.localAddress;
            const std::uint16_t port = remote ? endpoint.remotePort : endpoint.localPort;
            if (remote && (endpoint.isListening || endpoint.protocol == L"UDP" || address.empty() || port == 0))
            {
                return L"-";
            }
            if (address.empty())
            {
                return L"(unknown)";
            }
            return address + L":" + std::to_wstring(port);
        }

        bool SnapshotKeyMatchesCurrentProcess(
            const Core::SnapshotProcessKey& key,
            const Core::ProcessInfo& currentProcess) const
        {
            if (key.pid != currentProcess.pid)
            {
                return false;
            }

            if (key.hasCreationTime && currentProcess.hasCreationTime)
            {
                return key.creationTimeFileTime == currentProcess.creationTimeFileTime;
            }

            return true;
        }

        bool SnapshotProcessExistsInCurrentSnapshot(const Core::SnapshotProcessRecord& process) const
        {
            const Core::ProcessInfo* currentProcess = Core::FindProcessByPid(snapshot_, process.pid);
            return currentProcess != nullptr && SnapshotKeyMatchesCurrentProcess(process.key, *currentProcess);
        }

        bool SnapshotEndpointOwnerExistsInCurrentSnapshot(const Core::SnapshotNetworkEndpoint& endpoint) const
        {
            const Core::ProcessInfo* currentProcess = Core::FindProcessByPid(snapshot_, endpoint.owningPid);
            return currentProcess != nullptr &&
                SnapshotKeyMatchesCurrentProcess(endpoint.owningProcessKey, *currentProcess);
        }

        void SelectCompareProcessIfCurrent(const Core::SnapshotProcessRecord& process)
        {
            if (!SnapshotProcessExistsInCurrentSnapshot(process))
            {
                return;
            }

            SelectProcess(process.pid, true);
            scrollSelectedProcessIntoView_ = true;
        }

        void SelectCompareEndpointOwnerIfCurrent(const Core::SnapshotNetworkEndpoint& endpoint)
        {
            if (!SnapshotEndpointOwnerExistsInCurrentSnapshot(endpoint))
            {
                return;
            }

            SelectProcess(endpoint.owningPid, true);
            scrollSelectedProcessIntoView_ = true;
        }

        std::wstring FormatCompareEndpointSummary(
            const Core::SnapshotNetworkEndpoint& endpoint,
            bool remote) const
        {
            return CompareEndpointText(endpoint, remote);
        }

        std::wstring FormatCompareSummaryForClipboard(
            const Core::ProcessSnapshotCapture& baseline,
            const Core::ProcessSnapshotCapture& current,
            const Core::SnapshotCompareResult& result,
            bool resultValid) const
        {
            constexpr std::size_t MaxNotableItemsPerSection = 10;

            std::wstringstream text;
            text << L"GlassPane Snapshot Compare\r\n";
            text << L"Baseline: " << (baseline.captured ? baseline.captureTimeLocal : L"(not captured)") << L"\r\n";
            text << L"Current: " << (current.captured ? current.captureTimeLocal : L"(not captured)") << L"\r\n\r\n";

            const bool hasValidCompare =
                baseline.captured &&
                current.captured &&
                resultValid &&
                result.hasBaseline &&
                result.hasCurrent;

            if (!hasValidCompare)
            {
                text << L"Summary:\r\n";
                text << L"- Capture both baseline and current snapshots before reviewing differences.\r\n\r\n";
                text << L"Notes:\r\n";
                text << L"Snapshot differences are evidence worth reviewing, not proof of malicious activity.\r\n";
                return text.str();
            }

            const std::size_t findingChanges =
                result.newFindings.size() +
                result.removedFindings.size() +
                result.changedFindings.size();

            text << L"Summary:\r\n";
            text << L"- Baseline processes: " << baseline.processes.size() << L"\r\n";
            text << L"- Current processes: " << current.processes.size() << L"\r\n";
            text << L"- New processes: " << result.newProcesses.size() << L"\r\n";
            text << L"- Exited processes: " << result.exitedProcesses.size() << L"\r\n";
            text << L"- Changed processes: " << result.changedProcesses.size() << L"\r\n";
            text << L"- New network connections: "
                << (result.networkCompared ? std::to_wstring(result.newNetworkConnections.size()) : L"Unavailable") << L"\r\n";
            text << L"- Closed network connections: "
                << (result.networkCompared ? std::to_wstring(result.closedNetworkConnections.size()) : L"Unavailable") << L"\r\n";
            text << L"- Finding changes: "
                << (result.findingsCompared ? std::to_wstring(findingChanges) : L"Unavailable") << L"\r\n\r\n";

            if (result.newProcesses.empty() &&
                result.exitedProcesses.empty() &&
                result.changedProcesses.empty() &&
                result.newNetworkConnections.empty() &&
                result.closedNetworkConnections.empty() &&
                result.newFindings.empty() &&
                result.removedFindings.empty() &&
                result.changedFindings.empty())
            {
                text << L"Notable changes:\r\n";
                text << L"- No meaningful differences found.\r\n\r\n";
            }
            else
            {
                text << L"Notable changes:\r\n";

                const auto appendTruncation = [&text](std::size_t total) {
                    if (total > MaxNotableItemsPerSection)
                    {
                        text << L"- Additional items omitted: " << (total - MaxNotableItemsPerSection) << L"\r\n";
                    }
                };

                const std::size_t newProcessCount = std::min(MaxNotableItemsPerSection, result.newProcesses.size());
                for (std::size_t index = 0; index < newProcessCount; ++index)
                {
                    const Core::SnapshotProcessRecord& process = result.newProcesses[index];
                    text << L"- New process observed: "
                        << (process.processName.empty() ? L"(unknown)" : process.processName)
                        << L" PID " << process.pid << L"\r\n";
                }
                appendTruncation(result.newProcesses.size());

                const std::size_t exitedProcessCount = std::min(MaxNotableItemsPerSection, result.exitedProcesses.size());
                for (std::size_t index = 0; index < exitedProcessCount; ++index)
                {
                    const Core::SnapshotProcessRecord& process = result.exitedProcesses[index];
                    text << L"- Process exited: "
                        << (process.processName.empty() ? L"(unknown)" : process.processName)
                        << L" PID " << process.pid << L"\r\n";
                }
                appendTruncation(result.exitedProcesses.size());

                const std::size_t changedProcessCount = std::min(MaxNotableItemsPerSection, result.changedProcesses.size());
                for (std::size_t index = 0; index < changedProcessCount; ++index)
                {
                    const Core::SnapshotProcessChange& change = result.changedProcesses[index];
                    text << L"- Process changed: "
                        << (change.current.processName.empty() ? L"(unknown)" : change.current.processName)
                        << L" PID " << change.current.pid
                        << L" (" << change.fields.size() << L" field(s))\r\n";
                }
                appendTruncation(result.changedProcesses.size());

                if (result.networkCompared)
                {
                    const std::size_t newNetworkCount = std::min(MaxNotableItemsPerSection, result.newNetworkConnections.size());
                    for (std::size_t index = 0; index < newNetworkCount; ++index)
                    {
                        const Core::SnapshotNetworkEndpoint& endpoint = result.newNetworkConnections[index];
                        text << L"- Network connection appeared: "
                            << (endpoint.processName.empty() ? L"(unknown)" : endpoint.processName)
                            << L" -> " << FormatCompareEndpointSummary(endpoint, true) << L"\r\n";
                    }
                    appendTruncation(result.newNetworkConnections.size());

                    const std::size_t closedNetworkCount = std::min(MaxNotableItemsPerSection, result.closedNetworkConnections.size());
                    for (std::size_t index = 0; index < closedNetworkCount; ++index)
                    {
                        const Core::SnapshotNetworkEndpoint& endpoint = result.closedNetworkConnections[index];
                        text << L"- Network connection closed: "
                            << (endpoint.processName.empty() ? L"(unknown)" : endpoint.processName)
                            << L" -> " << FormatCompareEndpointSummary(endpoint, true) << L"\r\n";
                    }
                    appendTruncation(result.closedNetworkConnections.size());
                }

                if (result.findingsCompared)
                {
                    const std::size_t newFindingCount = std::min(MaxNotableItemsPerSection, result.newFindings.size());
                    for (std::size_t index = 0; index < newFindingCount; ++index)
                    {
                        const Core::SnapshotFindingRecord& finding = result.newFindings[index];
                        text << L"- New finding: "
                            << Core::FindingSeverityToString(finding.severity)
                            << L" "
                            << (finding.title.empty() ? L"(untitled)" : finding.title)
                            << L" (PID " << finding.pid << L")\r\n";
                    }
                    appendTruncation(result.newFindings.size());
                }

                text << L"\r\n";
            }

            text << L"Notes:\r\n";
            if (!result.networkCompared)
            {
                text << L"- Network comparison unavailable because network data was not loaded for both snapshots.\r\n";
            }
            if (!result.findingsCompared)
            {
                text << L"- Finding comparison unavailable for one or both snapshots.\r\n";
            }
            text << L"Snapshot differences are evidence worth reviewing, not proof of malicious activity.\r\n";
            return text.str();
        }

