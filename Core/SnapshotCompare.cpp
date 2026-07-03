#include "SnapshotCompare.h"

#include <algorithm>
#include <sstream>
#include <unordered_map>

namespace GlassPane::Core
{
    namespace
    {
        std::wstring ValueOr(const std::wstring& value, const wchar_t* fallback)
        {
            return value.empty() ? std::wstring(fallback) : value;
        }

        std::wstring SessionText(const SnapshotProcessRecord& process)
        {
            return process.hasSessionId ? std::to_wstring(process.sessionId) : L"(unknown)";
        }

        FindingSeverity FindingSeverityFromProcessSeverity(Severity severity)
        {
            switch (severity)
            {
            case Severity::High:
                return FindingSeverity::High;
            case Severity::Medium:
                return FindingSeverity::Medium;
            case Severity::Low:
                return FindingSeverity::Low;
            case Severity::Info:
            case Severity::None:
            default:
                return FindingSeverity::Info;
            }
        }

        std::wstring ProcessMapKey(const SnapshotProcessRecord& process)
        {
            return SnapshotProcessKeyToString(process.key);
        }

        std::wstring NetworkMapKey(const SnapshotNetworkEndpoint& endpoint)
        {
            std::wstringstream stream;
            stream << SnapshotProcessKeyToString(endpoint.owningProcessKey)
                   << L"|"
                   << endpoint.protocol
                   << L"|"
                   << endpoint.localAddress
                   << L":"
                   << endpoint.localPort
                   << L"|"
                   << endpoint.remoteAddress
                   << L":"
                   << endpoint.remotePort
                   << L"|"
                   << endpoint.state
                   << L"|"
                   << endpoint.addressFamily;
            return stream.str();
        }

        std::wstring FindingIdentityKey(const SnapshotFindingRecord& finding)
        {
            std::wstringstream stream;
            stream << SnapshotProcessKeyToString(finding.processKey)
                   << L"|"
                   << finding.category
                   << L"|"
                   << finding.title;
            return stream.str();
        }

        std::wstring FindingFullKey(const SnapshotFindingRecord& finding)
        {
            std::wstringstream stream;
            stream << FindingIdentityKey(finding)
                   << L"|"
                   << FindingSeverityToString(finding.severity)
                   << L"|"
                   << finding.evidenceSummary;
            return stream.str();
        }

        void AddChangedField(
            SnapshotProcessChange& change,
            const std::wstring& field,
            const std::wstring& baselineValue,
            const std::wstring& currentValue)
        {
            if (baselineValue != currentValue)
            {
                change.fields.push_back({ field, baselineValue, currentValue });
            }
        }

        void SortProcessRecords(std::vector<SnapshotProcessRecord>& records)
        {
            std::sort(records.begin(), records.end(), [](const SnapshotProcessRecord& left, const SnapshotProcessRecord& right) {
                if (left.processName != right.processName)
                {
                    return left.processName < right.processName;
                }
                return left.pid < right.pid;
            });
        }

        void SortNetworkEndpoints(std::vector<SnapshotNetworkEndpoint>& endpoints)
        {
            std::sort(endpoints.begin(), endpoints.end(), [](const SnapshotNetworkEndpoint& left, const SnapshotNetworkEndpoint& right) {
                if (left.processName != right.processName)
                {
                    return left.processName < right.processName;
                }
                if (left.owningPid != right.owningPid)
                {
                    return left.owningPid < right.owningPid;
                }
                return NetworkMapKey(left) < NetworkMapKey(right);
            });
        }

        void SortFindings(std::vector<SnapshotFindingRecord>& findings)
        {
            std::sort(findings.begin(), findings.end(), [](const SnapshotFindingRecord& left, const SnapshotFindingRecord& right) {
                if (FindingSeverityRank(left.severity) != FindingSeverityRank(right.severity))
                {
                    return FindingSeverityRank(left.severity) > FindingSeverityRank(right.severity);
                }
                if (left.processName != right.processName)
                {
                    return left.processName < right.processName;
                }
                return left.title < right.title;
            });
        }

        void AddProcessFindingRecords(
            const ProcessInfo& process,
            std::vector<SnapshotFindingRecord>& findings)
        {
            const FindingSeverity processFindingSeverity = FindingSeverityFromProcessSeverity(process.severity);
            if (SeverityRank(process.severity) >= SeverityRank(Severity::Low))
            {
                findings.push_back({
                    { process.pid, process.hasCreationTime, process.creationTimeFileTime },
                    process.pid,
                    process.name,
                    processFindingSeverity,
                    L"Process severity: " + std::wstring(SeverityToString(process.severity)),
                    L"Process",
                    L"Process was scored " + std::wstring(SeverityToString(process.severity))
                });
            }

            for (const std::wstring& indicator : process.indicators)
            {
                findings.push_back({
                    { process.pid, process.hasCreationTime, process.creationTimeFileTime },
                    process.pid,
                    process.name,
                    processFindingSeverity,
                    indicator,
                    L"Indicator",
                    indicator
                });
            }

            for (const std::wstring& note : process.contextNotes)
            {
                findings.push_back({
                    { process.pid, process.hasCreationTime, process.creationTimeFileTime },
                    process.pid,
                    process.name,
                    FindingSeverity::Info,
                    note,
                    L"Context",
                    note
                });
            }
        }
    }

    std::wstring SnapshotProcessKeyToString(const SnapshotProcessKey& key)
    {
        std::wstringstream stream;
        stream << key.pid;
        if (key.hasCreationTime)
        {
            stream << L"|" << key.creationTimeFileTime;
        }
        else
        {
            stream << L"|pid-only";
        }
        return stream.str();
    }

    ProcessSnapshotCapture CaptureProcessSnapshotForCompare(
        const ProcessSnapshot& snapshot,
        const NetworkCollectionResult* networkSnapshot,
        bool includeNetwork,
        const std::wstring& captureTimeLocal)
    {
        ProcessSnapshotCapture capture;
        capture.captured = true;
        capture.captureTimeLocal = captureTimeLocal;
        capture.processes.reserve(snapshot.processes.size());

        for (const ProcessInfo& process : snapshot.processes)
        {
            SnapshotProcessRecord record;
            record.key = { process.pid, process.hasCreationTime, process.creationTimeFileTime };
            record.pid = process.pid;
            record.parentPid = process.parentPid;
            record.processName = process.name;
            record.executablePath = process.executablePath;
            record.commandLine = process.commandLine;
            record.architecture = process.architecture;
            record.creationTimeLocal = process.creationTimeLocal;
            record.suspicious = process.suspicious;
            record.severity = process.severity;
            record.indicators = process.indicators;
            record.contextNotes = process.contextNotes;

            if (process.sessionId.has_value())
            {
                record.hasSessionId = true;
                record.sessionId = process.sessionId.value();
            }

            const auto parentIt = snapshot.indexByPid.find(process.parentPid);
            if (parentIt != snapshot.indexByPid.end())
            {
                const ProcessInfo& parent = snapshot.processes[parentIt->second];
                record.parentHasCreationTime = parent.hasCreationTime;
                record.parentCreationTimeFileTime = parent.creationTimeFileTime;
            }

            if (!process.hasCreationTime)
            {
                capture.usedPidOnlyFallback = true;
            }

            capture.processes.push_back(std::move(record));
            AddProcessFindingRecords(process, capture.findings);
        }
        capture.findingsCaptured = true;

        if (includeNetwork)
        {
            capture.networkCaptured = true;
            if (networkSnapshot != nullptr)
            {
                capture.networkAvailable = networkSnapshot->success;
                capture.networkStatusMessage = networkSnapshot->statusMessage;
                capture.networkConnections.reserve(networkSnapshot->connections.size());
                for (const NetworkConnection& connection : networkSnapshot->connections)
                {
                    SnapshotNetworkEndpoint endpoint;
                    endpoint.owningPid = connection.owningPid;
                    endpoint.processName = connection.processName;
                    endpoint.protocol = connection.protocol;
                    endpoint.localAddress = connection.localAddress;
                    endpoint.localPort = connection.localPort;
                    endpoint.remoteAddress = connection.remoteAddress;
                    endpoint.remotePort = connection.remotePort;
                    endpoint.state = connection.state;
                    endpoint.addressFamily = connection.addressFamily;
                    endpoint.isListening = connection.isListening;
                    endpoint.isLoopback = connection.isLoopback;
                    endpoint.isLan = connection.isLan;
                    endpoint.isPublicRemote = connection.isPublicRemote;

                    const auto processIt = snapshot.indexByPid.find(connection.owningPid);
                    if (processIt != snapshot.indexByPid.end())
                    {
                        const ProcessInfo& owner = snapshot.processes[processIt->second];
                        endpoint.owningProcessKey = { owner.pid, owner.hasCreationTime, owner.creationTimeFileTime };
                        if (endpoint.processName.empty())
                        {
                            endpoint.processName = owner.name;
                        }
                    }
                    else
                    {
                        endpoint.owningProcessKey = { connection.owningPid, false, 0 };
                    }

                    capture.networkConnections.push_back(std::move(endpoint));
                }
            }
            else
            {
                capture.networkStatusMessage = L"Network table was not loaded when this snapshot was captured.";
            }
        }

        return capture;
    }

    SnapshotCompareResult CompareSnapshots(
        const ProcessSnapshotCapture& baseline,
        const ProcessSnapshotCapture& current)
    {
        SnapshotCompareResult result;
        result.hasBaseline = baseline.captured;
        result.hasCurrent = current.captured;
        if (!baseline.captured || !current.captured)
        {
            return result;
        }

        result.processCompared = true;
        if (baseline.usedPidOnlyFallback || current.usedPidOnlyFallback)
        {
            result.notes.push_back(L"Some processes lacked creation time metadata; PID-only matching was used for those records.");
        }

        std::unordered_map<std::wstring, std::size_t> baselineProcesses;
        std::unordered_map<std::wstring, std::size_t> currentProcesses;
        for (std::size_t index = 0; index < baseline.processes.size(); ++index)
        {
            baselineProcesses[ProcessMapKey(baseline.processes[index])] = index;
        }
        for (std::size_t index = 0; index < current.processes.size(); ++index)
        {
            currentProcesses[ProcessMapKey(current.processes[index])] = index;
        }

        for (const SnapshotProcessRecord& process : current.processes)
        {
            const std::wstring key = ProcessMapKey(process);
            const auto baselineIt = baselineProcesses.find(key);
            if (baselineIt == baselineProcesses.end())
            {
                result.newProcesses.push_back(process);
                continue;
            }

            const SnapshotProcessRecord& baselineProcess = baseline.processes[baselineIt->second];
            SnapshotProcessChange change;
            change.baseline = baselineProcess;
            change.current = process;
            AddChangedField(change, L"Parent PID", std::to_wstring(baselineProcess.parentPid), std::to_wstring(process.parentPid));
            AddChangedField(change, L"Executable path", ValueOr(baselineProcess.executablePath, L"(empty)"), ValueOr(process.executablePath, L"(empty)"));
            AddChangedField(change, L"Command line", ValueOr(baselineProcess.commandLine, L"(empty)"), ValueOr(process.commandLine, L"(empty)"));
            AddChangedField(change, L"Severity", SeverityToString(baselineProcess.severity), SeverityToString(process.severity));
            AddChangedField(change, L"Session", SessionText(baselineProcess), SessionText(process));
            AddChangedField(change, L"Architecture", ValueOr(baselineProcess.architecture, L"(unknown)"), ValueOr(process.architecture, L"(unknown)"));

            if (!change.fields.empty())
            {
                result.changedProcesses.push_back(std::move(change));
            }
        }

        for (const SnapshotProcessRecord& process : baseline.processes)
        {
            const std::wstring key = ProcessMapKey(process);
            if (currentProcesses.find(key) == currentProcesses.end())
            {
                result.exitedProcesses.push_back(process);
            }
        }

        SortProcessRecords(result.newProcesses);
        SortProcessRecords(result.exitedProcesses);
        std::sort(result.changedProcesses.begin(), result.changedProcesses.end(), [](const SnapshotProcessChange& left, const SnapshotProcessChange& right) {
            if (left.current.processName != right.current.processName)
            {
                return left.current.processName < right.current.processName;
            }
            return left.current.pid < right.current.pid;
        });

        if (baseline.networkCaptured && current.networkCaptured && baseline.networkAvailable && current.networkAvailable)
        {
            result.networkCompared = true;
            std::unordered_map<std::wstring, std::size_t> baselineConnections;
            std::unordered_map<std::wstring, std::size_t> currentConnections;
            for (std::size_t index = 0; index < baseline.networkConnections.size(); ++index)
            {
                baselineConnections[NetworkMapKey(baseline.networkConnections[index])] = index;
            }
            for (std::size_t index = 0; index < current.networkConnections.size(); ++index)
            {
                currentConnections[NetworkMapKey(current.networkConnections[index])] = index;
            }

            for (const SnapshotNetworkEndpoint& endpoint : current.networkConnections)
            {
                if (baselineConnections.find(NetworkMapKey(endpoint)) == baselineConnections.end())
                {
                    result.newNetworkConnections.push_back(endpoint);
                }
            }
            for (const SnapshotNetworkEndpoint& endpoint : baseline.networkConnections)
            {
                if (currentConnections.find(NetworkMapKey(endpoint)) == currentConnections.end())
                {
                    result.closedNetworkConnections.push_back(endpoint);
                }
            }

            SortNetworkEndpoints(result.newNetworkConnections);
            SortNetworkEndpoints(result.closedNetworkConnections);
        }
        else
        {
            result.notes.push_back(L"Network comparison unavailable because network data was not loaded or did not collect successfully for both snapshots.");
        }

        if (baseline.findingsCaptured && current.findingsCaptured)
        {
            result.findingsCompared = true;
            std::unordered_map<std::wstring, std::size_t> baselineFindings;
            std::unordered_map<std::wstring, std::size_t> currentFindings;
            for (std::size_t index = 0; index < baseline.findings.size(); ++index)
            {
                baselineFindings[FindingIdentityKey(baseline.findings[index])] = index;
            }
            for (std::size_t index = 0; index < current.findings.size(); ++index)
            {
                currentFindings[FindingIdentityKey(current.findings[index])] = index;
            }

            for (const SnapshotFindingRecord& finding : current.findings)
            {
                const auto baselineIt = baselineFindings.find(FindingIdentityKey(finding));
                if (baselineIt == baselineFindings.end())
                {
                    result.newFindings.push_back(finding);
                    continue;
                }

                const SnapshotFindingRecord& baselineFinding = baseline.findings[baselineIt->second];
                if (FindingFullKey(baselineFinding) != FindingFullKey(finding))
                {
                    result.changedFindings.push_back({ baselineFinding, finding, L"Finding changed" });
                }
            }

            for (const SnapshotFindingRecord& finding : baseline.findings)
            {
                if (currentFindings.find(FindingIdentityKey(finding)) == currentFindings.end())
                {
                    result.removedFindings.push_back(finding);
                }
            }

            SortFindings(result.newFindings);
            SortFindings(result.removedFindings);
            std::sort(result.changedFindings.begin(), result.changedFindings.end(), [](const SnapshotFindingChange& left, const SnapshotFindingChange& right) {
                if (FindingSeverityRank(left.current.severity) != FindingSeverityRank(right.current.severity))
                {
                    return FindingSeverityRank(left.current.severity) > FindingSeverityRank(right.current.severity);
                }
                return left.current.title < right.current.title;
            });
        }
        else
        {
            result.notes.push_back(L"Finding comparison unavailable because finding summaries were not captured for both snapshots.");
        }

        return result;
    }
}
