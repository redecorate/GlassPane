#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace GlassPane::Core
{
    // HistoricalCompatibility boundary
    //
    // These identities are retained only to read, display, copy, and compare
    // source records captured by schemas 1-4. Current live analysis, schema-5
    // capture, native source-evidence projection, and TriageEngine authority
    // must not construct or consume Finding values.
    enum class FindingSeverity
    {
        Info,
        Low,
        Medium,
        High
    };

    // Stable historical identities must remain numerically unchanged so older
    // snapshot records and compatibility tests remain readable.
    enum class ExistingFindingKind : std::uint32_t
    {
        Unknown = 0,
        RelationshipEncodedCommand = 1,
        LocalSignalWithPublicNetwork = 2,
        ExactNetworkIndicatorMatch = 3,
        UserPathAndMissingOrInvalidSignature = 4,
        InvalidSignature = 5,
        IdentitySignerMismatch = 6,
        TokenUnavailable = 7,
        UserPathAndHighIntegrity = 8,
        LocalSignalWithElevation = 9,
        LocalSignalWithDebugPrivilege = 10,
        LocalSignalWithImpersonationPrivilege = 11,
        SandboxedTokenContext = 12,
        LocalSignalWithSensitiveTargetHandle = 13,
        LocalSignalWithSensitiveProcessAccess = 14,
        TokenHandlePresence = 15,
        LocalSignalWithSensitiveHandle = 16,
        PublicNetworkActivity = 17,
        AggregatedProcessIndicators = 18,
        AggregatedRelationshipIndicators = 19,
        LocalSignalWithHighPriority = 20,
        SingleProcessorAffinity = 21,
        HighRuntimeObjectCount = 22,
        WritableExecutableMemory = 23,
        LocalSignalWithPrivateExecutableMemory = 24,
        PrivateExecutableMemory = 25,
        ExecutableUnbackedMemory = 26,
        GuardedMemory = 27,
        ModulesUnavailable = 28,
        AggregatedModuleIndicators = 29
    };

    struct Finding
    {
        FindingSeverity severity = FindingSeverity::Info;
        std::wstring title;
        std::wstring description;
        std::vector<std::wstring> evidence;
        std::wstring category;
        ExistingFindingKind observationKind = ExistingFindingKind::Unknown;
        // Schemas 1-4 captured process-level legacy severity, but did not
        // capture a severity for every indicator/context row. Compatibility
        // projections must keep that distinction explicit instead of
        // inventing an Info (or process-level) severity for an individual
        // row. Existing serialized Finding records default to captured.
        bool severityCaptured = true;
    };

    inline int FindingSeverityRank(FindingSeverity severity)
    {
        switch (severity)
        {
        case FindingSeverity::High:
            return 4;
        case FindingSeverity::Medium:
            return 3;
        case FindingSeverity::Low:
            return 2;
        case FindingSeverity::Info:
        default:
            return 1;
        }
    }

    inline const wchar_t* FindingSeverityToString(FindingSeverity severity)
    {
        switch (severity)
        {
        case FindingSeverity::High:
            return L"High";
        case FindingSeverity::Medium:
            return L"Medium";
        case FindingSeverity::Low:
            return L"Low";
        case FindingSeverity::Info:
        default:
            return L"Info";
        }
    }

    inline const wchar_t* HistoricalFindingSeverityText(
        const Finding& finding)
    {
        return finding.severityCaptured
            ? FindingSeverityToString(finding.severity)
            : L"Not captured";
    }

    // Historical display/test helper. Current authority never calls this and
    // never projects a TriageVerdict from FindingSeverity.
    inline FindingSeverity HighestFindingSeverity(
        const std::vector<Finding>& findings)
    {
        FindingSeverity highest = FindingSeverity::Info;
        for (const Finding& finding : findings)
        {
            if (finding.severityCaptured &&
                FindingSeverityRank(finding.severity) >
                FindingSeverityRank(highest))
            {
                highest = finding.severity;
            }
        }
        return highest;
    }
}
