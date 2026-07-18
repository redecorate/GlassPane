#pragma once

#include "ProcessTriageCache.h"
#include "NativeSourceEvidence.h"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <vector>

namespace GlassPane::Core
{
    // Version of the bounded, schema-independent persisted triage model. The
    // snapshot schema that contains this model is intentionally owned by the
    // Export layer and is not coupled to this value.
    constexpr std::uint32_t PersistedTriageModelVersion = 1;

    constexpr std::size_t PersistedTriageMaxProcessRecords =
        ProcessTriageCacheMaxEntries;
    constexpr std::size_t PersistedTriageMaxContributingDomains = 16;
    constexpr std::size_t PersistedTriageMaxVerdictBasisItems = 32;
    constexpr std::size_t PersistedTriageMaxCompletedCorrelationItems = 32;
    constexpr std::size_t PersistedTriageMaxSupportingContextItems = 64;
    constexpr std::size_t PersistedTriageMaxCollectionLimitationItems = 32;
    constexpr std::size_t PersistedTriageMaxEvidenceIntegrityItems = 32;
    constexpr std::size_t PersistedTriageMaxUnresolvedCorrelationItems = 32;
    constexpr std::size_t PersistedTriageMaxSourceEvidenceCount =
        NativeSourceEvidenceMaxRecords;
    constexpr std::size_t PersistedTriageLineMaxUtf8Bytes = 1024;
    constexpr std::size_t PersistedTriageFallbackReasonMaxUtf8Bytes = 512;
    constexpr std::size_t PersistedTriageStatusMaxUtf8Bytes = 512;
    constexpr std::size_t PersistedTriageValidationFieldMaxUtf8Bytes = 256;
    constexpr std::size_t PersistedTriageValidationMessageMaxUtf8Bytes = 512;
    constexpr std::size_t PersistedTriageNoRecordIndex =
        (std::numeric_limits<std::size_t>::max)();

    enum class PersistedTriageAnalysisLevel : std::uint32_t
    {
        NotCaptured = 0,
        Baseline = 1,
        Enriched = 2,
        LegacyFallback = 3
    };

    std::string PersistedTriageAnalysisLevelDisplayText(
        PersistedTriageAnalysisLevel level);
    bool IsKnownPersistedTriageAnalysisLevel(
        PersistedTriageAnalysisLevel level);

    // ID-free, capture-time authority projection. Observation IDs,
    // correlation IDs, artifact keys, source indexes, timing values, runtime
    // generations, and pointer-bearing authority views are deliberately not
    // part of this persistence contract.
    struct PersistedTriageSummary
    {
        bool captured = false;
        bool evaluationSucceeded = false;
        bool usingFallback = false;
        PersistedTriageAnalysisLevel analysisLevel =
            PersistedTriageAnalysisLevel::NotCaptured;
        TriageVerdict authoritativeVerdict = TriageVerdict::Informational;

        bool baselineVerdictAvailable = false;
        TriageVerdict baselineVerdict = TriageVerdict::Informational;
        bool enrichedChangedVerdict = false;

        // Zero is reserved for NotCaptured. Every captured record uses the
        // current known model version exactly.
        std::uint32_t triageModelVersion = 0;
        std::size_t sourceEvidenceCount = 0;

        // Canonical ascending unique order is required for contributingDomains.
        std::vector<EvidenceDomain> contributingDomains;
        std::vector<std::string> verdictBasis;
        std::vector<std::string> completedCorrelations;
        std::vector<std::string> supportingContext;
        std::vector<std::string> collectionLimitations;
        std::vector<std::string> evidenceIntegrityContext;
        std::vector<std::string> unresolvedCorrelations;

        std::string fallbackReason;
        std::string status;
    };

    struct PersistedProcessTriageRecord
    {
        ProcessIdentityKey identity;
        PersistedTriageSummary summary;
    };

    struct PersistedTriageContext
    {
        std::uint32_t modelVersion = PersistedTriageModelVersion;
        // Canonical strict ProcessIdentityKey order is required. Exact
        // duplicate identities are invalid, including PID zero identities.
        std::vector<PersistedProcessTriageRecord> processRecords;
        std::optional<PersistedProcessTriageRecord> selectedRecord;

        const PersistedProcessTriageRecord* FindProcess(
            const ProcessIdentityKey& identity) const;
    };

    enum class PersistedTriageValidationCode : std::uint32_t
    {
        Valid = 0,
        UnsupportedModelVersion = 1,
        InvalidProcessIdentity = 2,
        UnknownAnalysisLevel = 3,
        UnknownVerdict = 4,
        UnknownEvidenceDomain = 5,
        InvalidUtf8 = 6,
        StringLimitExceeded = 7,
        CollectionLimitExceeded = 8,
        SourceEvidenceLimitExceeded = 9,
        ContradictoryState = 10,
        NonCanonicalOrder = 11,
        DuplicateProcessIdentity = 12,
        SelectedProcessMissing = 13
    };

    std::string PersistedTriageValidationCodeDisplayText(
        PersistedTriageValidationCode code);

    struct PersistedTriageValidationResult
    {
        bool valid = false;
        PersistedTriageValidationCode code =
            PersistedTriageValidationCode::ContradictoryState;
        std::size_t processRecordIndex = PersistedTriageNoRecordIndex;
        std::string field;
        std::string message;

        explicit operator bool() const
        {
            return valid;
        }
    };

    // Strict validation uses UTF-8 byte caps (not code-point counts), rejects
    // malformed/overlong/surrogate UTF-8, unknown enums, contradictory state,
    // non-canonical order, and duplicate exact process identities.
    PersistedTriageValidationResult ValidatePersistedTriageSummary(
        const PersistedTriageSummary& summary);
    PersistedTriageValidationResult ValidatePersistedProcessTriageRecord(
        const PersistedProcessTriageRecord& record);
    PersistedTriageValidationResult ValidatePersistedTriageContext(
        const PersistedTriageContext& context);

    struct PersistedTriageProjectionResult
    {
        bool success = false;
        PersistedTriageSummary summary;
        PersistedTriageValidationResult validation;
    };

    // Projects only Core-authored, ID-free preview rationale. Completed
    // correlation entries are presentation summaries, never internal IDs.
    // Enriched projection requires a successful baseline result.
    PersistedTriageProjectionResult ProjectPersistedTriageSummary(
        const TriageResult& result,
        PersistedTriageAnalysisLevel analysisLevel,
        std::size_t sourceEvidenceCount,
        const TriageResult* baselineResult = nullptr);

    PersistedTriageSummary MakeNotCapturedPersistedTriageSummary();

    // Sorts process rows into canonical identity order without deleting exact
    // duplicates. Validation remains responsible for rejecting duplicates and
    // any selected record whose identity is not present in processRecords.
    PersistedTriageContext MakePersistedTriageContext(
        std::vector<PersistedProcessTriageRecord> processRecords,
        std::optional<PersistedProcessTriageRecord> selectedRecord =
            std::nullopt);
}
