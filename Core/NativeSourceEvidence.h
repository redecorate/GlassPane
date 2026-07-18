#pragma once

#include "Observation.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace GlassPane::Core
{
    struct ObservationRefinementResult;
    struct TriageResult;

    constexpr std::uint32_t NativeSourceEvidenceModelVersion = 1;

    constexpr std::size_t NativeSourceEvidenceMaxRecords = 4096;
    constexpr std::size_t NativeSourceEvidenceMaxDetailItems =
        ObservationMaxEvidenceItems;
    constexpr std::size_t NativeSourceEvidenceMaxLimitationItems =
        ObservationMaxLimitationItems * 2;
    constexpr std::size_t NativeSourceEvidenceStableRuleIdMaxUtf8Bytes =
        ObservationRuleIdMaxCharacters;
    constexpr std::size_t NativeSourceEvidenceTitleMaxUtf8Bytes =
        ObservationTitleMaxCharacters;
    constexpr std::size_t NativeSourceEvidenceSummaryMaxUtf8Bytes =
        ObservationSummaryMaxCharacters;
    constexpr std::size_t NativeSourceEvidenceDetailMaxUtf8Bytes =
        ObservationEvidenceItemMaxCharacters;
    constexpr std::size_t NativeSourceEvidenceLimitationMaxUtf8Bytes =
        ObservationLimitationItemMaxCharacters;
    constexpr std::size_t NativeSourceEvidenceArtifactFamilyMaxUtf8Bytes = 64;
    constexpr std::size_t NativeSourceEvidenceProvenanceSummaryMaxUtf8Bytes =
        1024;
    constexpr std::size_t NativeSourceEvidenceDiagnosticMaxUtf8Bytes = 512;

    // Value-owned, presentation-safe source evidence. Stable rule identity is
    // retained for semantic comparison; ephemeral observation IDs, artifact
    // keys, adapter metadata, raw indexes, and legacy severity are deliberately
    // absent from this contract.
    struct NativeSourceEvidenceRecord
    {
        std::string stableRuleId;
        std::string title;
        std::string summary;
        std::vector<std::string> details;
        std::vector<std::string> limitations;

        EvidenceDomain domain = EvidenceDomain::Unknown;
        ObservationDisposition disposition =
            ObservationDisposition::Informational;
        ObservationStrength strength = ObservationStrength::None;
        ObservationConfidence confidence = ObservationConfidence::Unknown;

        // A bounded generic artifact class such as File, Memory Region, or
        // Handle. It never contains the artifact identity key.
        std::string artifactFamily;
        std::string provenanceSummary;

        bool contributedToVerdict = false;
        bool suppressedDuplicate = false;
        bool collectionLimitation = false;
    };

    enum class NativeSourceEvidenceValidationCode : std::uint32_t
    {
        Valid = 0,
        UnknownEnum = 1,
        MissingStableRuleId = 2,
        InvalidUtf8 = 3,
        StringLimitExceeded = 4,
        CollectionLimitExceeded = 5,
        NonCanonicalOrder = 6,
        ContradictoryState = 7
    };

    struct NativeSourceEvidenceValidationResult
    {
        bool valid = false;
        NativeSourceEvidenceValidationCode code =
            NativeSourceEvidenceValidationCode::UnknownEnum;
        std::size_t recordIndex = NativeSourceEvidenceMaxRecords;
        std::string field;
        std::string diagnostic;

        explicit operator bool() const
        {
            return valid;
        }
    };

    NativeSourceEvidenceValidationResult ValidateNativeSourceEvidenceRecord(
        const NativeSourceEvidenceRecord& record);
    NativeSourceEvidenceValidationResult ValidateNativeSourceEvidenceRecords(
        const std::vector<NativeSourceEvidenceRecord>& records);

    enum class NativeSourceEvidenceProjectionStatus : std::uint32_t
    {
        NotAttempted = 0,
        Success = 1,
        RefinementUnavailable = 2,
        TriageUnavailable = 3,
        InputLimitExceeded = 4,
        InvalidSourceObservation = 5,
        InvalidProjectedRecord = 6
    };

    struct NativeSourceEvidenceProjectionResult
    {
        bool attempted = false;
        bool success = false;
        NativeSourceEvidenceProjectionStatus status =
            NativeSourceEvidenceProjectionStatus::NotAttempted;
        // False means the evidence was projected without an authoritative
        // TriageResult. Records remain auditable, and no record is represented
        // as having contributed.
        bool contributionEvaluationAvailable = false;
        std::vector<NativeSourceEvidenceRecord> records;
        std::size_t contributingRecordCount = 0;
        std::size_t contextRecordCount = 0;
        std::size_t collectionLimitationCount = 0;
        std::size_t evidenceIntegrityRecordCount = 0;
        std::size_t suppressedDuplicateCount = 0;
        std::string diagnostic;
    };

    // Projects immutable refined observations into a deterministic, bounded,
    // ID-free presentation contract. A null triage pointer intentionally
    // projects evidence without contribution claims. A non-null triage input
    // must be a successful result; invalid inputs fail atomically.
    NativeSourceEvidenceProjectionResult ProjectNativeSourceEvidence(
        const ObservationRefinementResult& refinement,
        const TriageResult* triage = nullptr);
}
