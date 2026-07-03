#pragma once

#include "Finding.h"
#include "NetworkConnection.h"
#include "ProcessInfo.h"

#include <cstdint>
#include <string>
#include <vector>

namespace GlassPane::Core
{
    struct SnapshotProcessKey
    {
        std::uint32_t pid = 0;
        bool hasCreationTime = false;
        std::uint64_t creationTimeFileTime = 0;
    };

    struct SnapshotProcessRecord
    {
        SnapshotProcessKey key;
        std::uint32_t pid = 0;
        std::uint32_t parentPid = 0;
        bool parentHasCreationTime = false;
        std::uint64_t parentCreationTimeFileTime = 0;
        bool hasSessionId = false;
        std::uint32_t sessionId = 0;
        std::wstring processName;
        std::wstring executablePath;
        std::wstring commandLine;
        std::wstring architecture;
        std::wstring creationTimeLocal;
        bool suspicious = false;
        Severity severity = Severity::None;
        std::vector<std::wstring> indicators;
        std::vector<std::wstring> contextNotes;
    };

    struct SnapshotNetworkEndpoint
    {
        SnapshotProcessKey owningProcessKey;
        std::uint32_t owningPid = 0;
        std::wstring processName;
        std::wstring protocol;
        std::wstring localAddress;
        std::uint16_t localPort = 0;
        std::wstring remoteAddress;
        std::uint16_t remotePort = 0;
        std::wstring state;
        std::wstring addressFamily;
        bool isListening = false;
        bool isLoopback = false;
        bool isLan = false;
        bool isPublicRemote = false;
    };

    struct SnapshotFindingRecord
    {
        SnapshotProcessKey processKey;
        std::uint32_t pid = 0;
        std::wstring processName;
        FindingSeverity severity = FindingSeverity::Info;
        std::wstring title;
        std::wstring category;
        std::wstring evidenceSummary;
    };

    struct ProcessSnapshotCapture
    {
        bool captured = false;
        std::wstring captureTimeLocal;
        std::vector<SnapshotProcessRecord> processes;

        bool usedPidOnlyFallback = false;
        bool networkCaptured = false;
        bool networkAvailable = false;
        std::wstring networkStatusMessage;
        std::vector<SnapshotNetworkEndpoint> networkConnections;

        bool findingsCaptured = false;
        std::vector<SnapshotFindingRecord> findings;
    };

    struct SnapshotChangedField
    {
        std::wstring field;
        std::wstring baselineValue;
        std::wstring currentValue;
    };

    struct SnapshotProcessChange
    {
        SnapshotProcessRecord baseline;
        SnapshotProcessRecord current;
        std::vector<SnapshotChangedField> fields;
    };

    struct SnapshotFindingChange
    {
        SnapshotFindingRecord baseline;
        SnapshotFindingRecord current;
        std::wstring changeType;
    };

    struct SnapshotCompareResult
    {
        bool hasBaseline = false;
        bool hasCurrent = false;
        bool processCompared = false;
        bool networkCompared = false;
        bool findingsCompared = false;

        std::vector<SnapshotProcessRecord> newProcesses;
        std::vector<SnapshotProcessRecord> exitedProcesses;
        std::vector<SnapshotProcessChange> changedProcesses;
        std::vector<SnapshotNetworkEndpoint> newNetworkConnections;
        std::vector<SnapshotNetworkEndpoint> closedNetworkConnections;
        std::vector<SnapshotFindingRecord> newFindings;
        std::vector<SnapshotFindingRecord> removedFindings;
        std::vector<SnapshotFindingChange> changedFindings;
        std::vector<std::wstring> notes;
    };

    ProcessSnapshotCapture CaptureProcessSnapshotForCompare(
        const ProcessSnapshot& snapshot,
        const NetworkCollectionResult* networkSnapshot,
        bool includeNetwork,
        const std::wstring& captureTimeLocal);

    SnapshotCompareResult CompareSnapshots(
        const ProcessSnapshotCapture& baseline,
        const ProcessSnapshotCapture& current);

    std::wstring SnapshotProcessKeyToString(const SnapshotProcessKey& key);
}
