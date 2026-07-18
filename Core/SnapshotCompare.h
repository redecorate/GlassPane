#pragma once

#include "Finding.h"
#include "NativeSourceEvidence.h"
#include "NetworkConnection.h"
#include "PersistedTriage.h"
#include "ProcessInfo.h"

#include <cstddef>
#include <cstdint>
#include <optional>
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
        // Historical-model compatibility metadata. Native captures leave
        // these neutral and use selectedNativeSourceEvidence instead.
        bool suspicious = false;
        Severity severity = Severity::None;
        bool historicalSuspiciousCaptured = false;
        bool historicalSeverityCaptured = false;
        // Value-owned, presentation-safe authoritative triage captured for
        // this exact process identity. A default summary represents legacy or
        // mixed-schema input where semantic triage was not captured.
        PersistedTriageSummary authoritativeTriage;
        // Historical-model compatibility rows; empty for native captures.
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
        // Old process snapshots did not retain severity per indicator/context
        // row. False means comparison/presentation must say Not captured.
        bool severityCaptured = true;
    };

    inline const wchar_t* SnapshotFindingSeverityText(
        const SnapshotFindingRecord& finding)
    {
        return finding.severityCaptured
            ? FindingSeverityToString(finding.severity)
            : L"Not captured";
    }

    enum class SnapshotSourceEvidenceModelKind : std::uint32_t
    {
        Unavailable = 0,
        Native = 1,
        HistoricalLegacy = 2
    };

    const wchar_t* SnapshotSourceEvidenceModelKindDisplayText(
        SnapshotSourceEvidenceModelKind kind);

    // Native source evidence is captured only for the selected process. The
    // exact process identity is kept with the records so a later selection
    // change cannot cause evidence from different entities to be compared.
    struct SnapshotSelectedNativeSourceEvidenceRecord
    {
        SnapshotProcessKey processKey;
        std::uint32_t pid = 0;
        std::wstring processName;
        std::vector<NativeSourceEvidenceRecord> records;
    };

    struct SnapshotSourceEvidenceCaptureContext
    {
        SnapshotSourceEvidenceModelKind modelKind =
            SnapshotSourceEvidenceModelKind::Unavailable;
        std::uint32_t nativeModelVersion =
            NativeSourceEvidenceModelVersion;
        std::optional<SnapshotSelectedNativeSourceEvidenceRecord>
            selectedNativeEvidence;
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

        SnapshotSourceEvidenceModelKind sourceEvidenceModelKind =
            SnapshotSourceEvidenceModelKind::Unavailable;
        std::uint32_t nativeSourceEvidenceModelVersion = 0;
        bool nativeSourceEvidenceCaptured = false;
        std::optional<SnapshotSelectedNativeSourceEvidenceRecord>
            selectedNativeSourceEvidence;
        std::wstring sourceEvidenceStatusMessage;

        // These summaries are historical compatibility evidence only. They
        // are never used to match current/schema-5 native evidence.
        bool findingsCaptured = false;
        std::vector<SnapshotFindingRecord> findings;

        bool triageContextCaptured = false;
        bool triageContextValid = false;
        std::size_t triageCapturedProcessCount = 0;
        std::size_t triageNotCapturedProcessCount = 0;
        std::wstring triageStatusMessage;
        // Selected-process enriched authority is capture metadata, not a
        // process-wide row projection. Keeping it separate prevents UI
        // selection changes from becoming endpoint process changes.
        std::optional<PersistedProcessTriageRecord>
            selectedAuthoritativeTriage;
    };

    struct SnapshotChangedField
    {
        std::wstring field;
        std::wstring baselineValue;
        std::wstring currentValue;
    };

    struct SnapshotSelectedTriageComparison
    {
        std::optional<PersistedProcessTriageRecord> baseline;
        std::optional<PersistedProcessTriageRecord> current;
        bool sameIdentity = false;
        bool safeIdentity = false;
        bool semanticCompared = false;
        bool availabilityMismatch = false;
        std::vector<SnapshotChangedField> fields;
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

    struct SnapshotNativeSourceEvidenceChange
    {
        NativeSourceEvidenceRecord baseline;
        NativeSourceEvidenceRecord current;
        std::vector<SnapshotChangedField> fields;
    };

    struct SnapshotSelectedNativeSourceEvidenceComparison
    {
        std::optional<SnapshotSelectedNativeSourceEvidenceRecord> baseline;
        std::optional<SnapshotSelectedNativeSourceEvidenceRecord> current;
        bool sameIdentity = false;
        bool safeIdentity = false;
        bool semanticCompared = false;
        bool availabilityMismatch = false;
        std::vector<NativeSourceEvidenceRecord> newRecords;
        std::vector<NativeSourceEvidenceRecord> removedRecords;
        std::vector<SnapshotNativeSourceEvidenceChange> changedRecords;
    };

    struct SnapshotCompareResult
    {
        bool hasBaseline = false;
        bool hasCurrent = false;
        bool processCompared = false;
        bool networkCompared = false;
        bool sourceEvidenceCompared = false;
        bool sourceEvidenceModelMismatch = false;
        bool nativeSourceEvidenceCompared = false;
        bool nativeSourceEvidenceModelVersionMismatch = false;
        // This legacy name is retained for existing callers. It is true only
        // for a historical-to-historical source-finding comparison.
        bool findingsCompared = false;
        bool triageCompared = false;

        SnapshotSourceEvidenceModelKind baselineSourceEvidenceModelKind =
            SnapshotSourceEvidenceModelKind::Unavailable;
        SnapshotSourceEvidenceModelKind currentSourceEvidenceModelKind =
            SnapshotSourceEvidenceModelKind::Unavailable;
        SnapshotSelectedNativeSourceEvidenceComparison selectedNativeEvidence;

        std::size_t baselineTriageCapturedProcessCount = 0;
        std::size_t currentTriageCapturedProcessCount = 0;
        std::size_t comparableTriageProcessCount = 0;
        std::size_t triageAvailabilityMismatchCount = 0;
        std::size_t triageIdentityUnavailableCount = 0;
        std::size_t baselineAmbiguousProcessIdentityCount = 0;
        std::size_t currentAmbiguousProcessIdentityCount = 0;
        std::size_t ambiguousFindingIdentityCount = 0;
        SnapshotSelectedTriageComparison selectedTriage;

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
        const std::wstring& captureTimeLocal,
        const PersistedTriageContext* triageContext = nullptr,
        const SnapshotSourceEvidenceCaptureContext* sourceEvidenceContext =
            nullptr);

    SnapshotCompareResult CompareSnapshots(
        const ProcessSnapshotCapture& baseline,
        const ProcessSnapshotCapture& current);

    std::wstring SnapshotProcessKeyToString(const SnapshotProcessKey& key);
}
