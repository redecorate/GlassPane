#include "NativeSourceEvidence.h"

#include "ObservationPolicy.h"
#include "ObservationRefinement.h"
#include "TriageEngine.h"

#include <algorithm>
#include <set>
#include <string_view>
#include <tuple>
#include <utility>

namespace GlassPane::Core
{
    namespace
    {
        bool IsValidUtf8(std::string_view value)
        {
            std::size_t index = 0;
            while (index < value.size())
            {
                const unsigned char lead =
                    static_cast<unsigned char>(value[index]);
                std::size_t length = 0;
                std::uint32_t codePoint = 0;
                if (lead <= 0x7f)
                {
                    length = 1;
                    codePoint = lead;
                }
                else if (lead >= 0xc2 && lead <= 0xdf)
                {
                    length = 2;
                    codePoint = lead & 0x1fU;
                }
                else if (lead >= 0xe0 && lead <= 0xef)
                {
                    length = 3;
                    codePoint = lead & 0x0fU;
                }
                else if (lead >= 0xf0 && lead <= 0xf4)
                {
                    length = 4;
                    codePoint = lead & 0x07U;
                }
                else
                {
                    return false;
                }

                if (index + length > value.size())
                {
                    return false;
                }
                for (std::size_t offset = 1; offset < length; ++offset)
                {
                    const unsigned char continuation =
                        static_cast<unsigned char>(value[index + offset]);
                    if ((continuation & 0xc0U) != 0x80U)
                    {
                        return false;
                    }
                    codePoint = (codePoint << 6U) |
                        static_cast<std::uint32_t>(continuation & 0x3fU);
                }

                if ((length == 2 && codePoint < 0x80U) ||
                    (length == 3 && codePoint < 0x800U) ||
                    (length == 4 && codePoint < 0x10000U) ||
                    codePoint > 0x10ffffU ||
                    (codePoint >= 0xd800U && codePoint <= 0xdfffU))
                {
                    return false;
                }
                index += length;
            }
            return true;
        }

        bool IsKnownDomain(EvidenceDomain domain)
        {
            return domain >= EvidenceDomain::ProcessIdentity &&
                domain <= EvidenceDomain::ImportedEvidence;
        }

        bool IsKnownDisposition(ObservationDisposition disposition)
        {
            return disposition >= ObservationDisposition::Informational &&
                disposition <= ObservationDisposition::SuppressedExpected;
        }

        bool IsKnownStrength(ObservationStrength strength)
        {
            return strength >= ObservationStrength::None &&
                strength <= ObservationStrength::Strong;
        }

        bool IsKnownConfidence(ObservationConfidence confidence)
        {
            return confidence >= ObservationConfidence::Unknown &&
                confidence <= ObservationConfidence::High;
        }

        NativeSourceEvidenceValidationResult Valid()
        {
            NativeSourceEvidenceValidationResult result;
            result.valid = true;
            result.code = NativeSourceEvidenceValidationCode::Valid;
            result.recordIndex = NativeSourceEvidenceMaxRecords;
            return result;
        }

        NativeSourceEvidenceValidationResult Invalid(
            NativeSourceEvidenceValidationCode code,
            std::string field,
            std::string diagnostic)
        {
            NativeSourceEvidenceValidationResult result;
            result.code = code;
            result.field = std::move(field);
            result.diagnostic = std::move(diagnostic);
            return result;
        }

        NativeSourceEvidenceValidationResult ValidateText(
            const std::string& value,
            std::size_t maximumBytes,
            const char* field)
        {
            if (!IsValidUtf8(value))
            {
                return Invalid(
                    NativeSourceEvidenceValidationCode::InvalidUtf8,
                    field,
                    std::string(field) + " is not valid UTF-8.");
            }
            if (value.size() > maximumBytes)
            {
                return Invalid(
                    NativeSourceEvidenceValidationCode::StringLimitExceeded,
                    field,
                    std::string(field) + " exceeds its UTF-8 byte cap.");
            }
            return Valid();
        }

        NativeSourceEvidenceValidationResult ValidateTextItems(
            const std::vector<std::string>& values,
            std::size_t maximumItems,
            std::size_t maximumBytes,
            const char* field)
        {
            if (values.size() > maximumItems)
            {
                return Invalid(
                    NativeSourceEvidenceValidationCode::CollectionLimitExceeded,
                    field,
                    std::string(field) + " exceeds its item cap.");
            }
            if (!std::is_sorted(values.begin(), values.end()) ||
                std::adjacent_find(values.begin(), values.end()) != values.end())
            {
                return Invalid(
                    NativeSourceEvidenceValidationCode::NonCanonicalOrder,
                    field,
                    std::string(field) +
                        " must be in canonical ascending unique order.");
            }
            for (const std::string& value : values)
            {
                const NativeSourceEvidenceValidationResult validation =
                    ValidateText(value, maximumBytes, field);
                if (!validation)
                {
                    return validation;
                }
            }
            return Valid();
        }

        void Canonicalize(std::vector<std::string>& values)
        {
            std::sort(values.begin(), values.end());
            values.erase(std::unique(values.begin(), values.end()), values.end());
        }

        std::string ArtifactFamily(const Observation& observation)
        {
            return ObservationArtifactKindDisplayText(
                observation.artifactIdentity.kind);
        }

        std::string ProvenanceSummary(const Observation& observation)
        {
            const ObservationSourceKind kind = observation.provenance.sourceKind;
            if (kind == ObservationSourceKind::Imported &&
                !observation.provenance.sourceIdentifier.empty())
            {
                return "Imported evidence from " +
                    observation.provenance.sourceIdentifier;
            }
            if (!observation.provenance.sourceAvailable ||
                kind == ObservationSourceKind::Unavailable)
            {
                return "Source unavailable";
            }
            return ObservationSourceKindDisplayText(kind) + " evidence";
        }

        NativeSourceEvidenceRecord ProjectRecord(
            const Observation& observation,
            bool contributed,
            bool suppressedDuplicate)
        {
            NativeSourceEvidenceRecord record;
            record.stableRuleId = observation.ruleId;
            record.title = observation.title;
            record.summary = observation.summary;
            record.details = observation.evidence;
            record.limitations = observation.limitations;
            record.limitations.insert(
                record.limitations.end(),
                observation.provenance.limitations.begin(),
                observation.provenance.limitations.end());
            Canonicalize(record.details);
            Canonicalize(record.limitations);
            record.domain = observation.domain;
            record.disposition = observation.disposition;
            record.strength = observation.strength;
            record.confidence = observation.confidence;
            record.artifactFamily = ArtifactFamily(observation);
            record.provenanceSummary = ProvenanceSummary(observation);
            record.contributedToVerdict = contributed;
            record.suppressedDuplicate = suppressedDuplicate;
            record.collectionLimitation =
                observation.disposition == ObservationDisposition::CollectionNote;
            return record;
        }

        bool RecordLess(
            const NativeSourceEvidenceRecord& left,
            const NativeSourceEvidenceRecord& right)
        {
            return std::tie(
                    left.domain,
                    left.disposition,
                    left.stableRuleId,
                    left.artifactFamily,
                    left.title,
                    left.summary,
                    left.provenanceSummary,
                    left.contributedToVerdict,
                    left.suppressedDuplicate,
                    left.collectionLimitation,
                    left.strength,
                    left.confidence,
                    left.details,
                    left.limitations) <
                std::tie(
                    right.domain,
                    right.disposition,
                    right.stableRuleId,
                    right.artifactFamily,
                    right.title,
                    right.summary,
                    right.provenanceSummary,
                    right.contributedToVerdict,
                    right.suppressedDuplicate,
                    right.collectionLimitation,
                    right.strength,
                    right.confidence,
                    right.details,
                    right.limitations);
        }

        bool IsContributing(
            const std::set<std::string>& contributingIds,
            const Observation& observation)
        {
            return !observation.id.empty() &&
                contributingIds.find(observation.id) != contributingIds.end();
        }
    }

    NativeSourceEvidenceValidationResult ValidateNativeSourceEvidenceRecord(
        const NativeSourceEvidenceRecord& record)
    {
        if (record.stableRuleId.empty())
        {
            return Invalid(
                NativeSourceEvidenceValidationCode::MissingStableRuleId,
                "stableRuleId",
                "stableRuleId is required.");
        }
        if (!IsKnownDomain(record.domain) ||
            !IsKnownDisposition(record.disposition) ||
            !IsKnownStrength(record.strength) ||
            !IsKnownConfidence(record.confidence))
        {
            return Invalid(
                NativeSourceEvidenceValidationCode::UnknownEnum,
                "enum",
                "Native source evidence contains an unknown enum value.");
        }

        const std::pair<const std::string*, std::pair<std::size_t, const char*>>
            strings[] = {
                { &record.stableRuleId,
                    { NativeSourceEvidenceStableRuleIdMaxUtf8Bytes, "stableRuleId" } },
                { &record.title,
                    { NativeSourceEvidenceTitleMaxUtf8Bytes, "title" } },
                { &record.summary,
                    { NativeSourceEvidenceSummaryMaxUtf8Bytes, "summary" } },
                { &record.artifactFamily,
                    { NativeSourceEvidenceArtifactFamilyMaxUtf8Bytes, "artifactFamily" } },
                { &record.provenanceSummary,
                    { NativeSourceEvidenceProvenanceSummaryMaxUtf8Bytes, "provenanceSummary" } }
            };
        for (const auto& entry : strings)
        {
            const NativeSourceEvidenceValidationResult validation =
                ValidateText(*entry.first, entry.second.first, entry.second.second);
            if (!validation)
            {
                return validation;
            }
        }

        NativeSourceEvidenceValidationResult validation = ValidateTextItems(
            record.details,
            NativeSourceEvidenceMaxDetailItems,
            NativeSourceEvidenceDetailMaxUtf8Bytes,
            "details");
        if (!validation)
        {
            return validation;
        }
        validation = ValidateTextItems(
            record.limitations,
            NativeSourceEvidenceMaxLimitationItems,
            NativeSourceEvidenceLimitationMaxUtf8Bytes,
            "limitations");
        if (!validation)
        {
            return validation;
        }

        const bool isCollectionNote =
            record.disposition == ObservationDisposition::CollectionNote;
        if (record.collectionLimitation != isCollectionNote)
        {
            return Invalid(
                NativeSourceEvidenceValidationCode::ContradictoryState,
                "collectionLimitation",
                "CollectionNote disposition and collectionLimitation must agree.");
        }
        if (record.collectionLimitation && record.contributedToVerdict)
        {
            return Invalid(
                NativeSourceEvidenceValidationCode::ContradictoryState,
                "contributedToVerdict",
                "A collection limitation cannot contribute to the verdict.");
        }
        if (record.suppressedDuplicate && record.contributedToVerdict)
        {
            return Invalid(
                NativeSourceEvidenceValidationCode::ContradictoryState,
                "contributedToVerdict",
                "A suppressed duplicate cannot contribute to the verdict.");
        }
        if (record.contributedToVerdict &&
            record.disposition != ObservationDisposition::ReviewRelevant &&
            record.disposition != ObservationDisposition::CorrelatedOnly)
        {
            return Invalid(
                NativeSourceEvidenceValidationCode::ContradictoryState,
                "contributedToVerdict",
                "Only ReviewRelevant or CorrelatedOnly evidence can contribute to the verdict.");
        }
        if (record.contributedToVerdict &&
            (record.domain == EvidenceDomain::CollectionQuality ||
                record.domain == EvidenceDomain::EvidenceIntegrity))
        {
            return Invalid(
                NativeSourceEvidenceValidationCode::ContradictoryState,
                "domain",
                "Collection-quality and evidence-integrity domains cannot contribute to the verdict.");
        }
        if (record.contributedToVerdict &&
            record.disposition == ObservationDisposition::ReviewRelevant &&
            record.strength == ObservationStrength::None)
        {
            return Invalid(
                NativeSourceEvidenceValidationCode::ContradictoryState,
                "strength",
                "ReviewRelevant evidence requires Weak-or-higher strength to contribute to the verdict.");
        }
        return Valid();
    }

    NativeSourceEvidenceValidationResult ValidateNativeSourceEvidenceRecords(
        const std::vector<NativeSourceEvidenceRecord>& records)
    {
        if (records.size() > NativeSourceEvidenceMaxRecords)
        {
            return Invalid(
                NativeSourceEvidenceValidationCode::CollectionLimitExceeded,
                "records",
                "Native source evidence exceeds its record cap.");
        }
        if (!std::is_sorted(records.begin(), records.end(), RecordLess))
        {
            return Invalid(
                NativeSourceEvidenceValidationCode::NonCanonicalOrder,
                "records",
                "Native source evidence records are not canonically ordered.");
        }
        for (std::size_t index = 0; index < records.size(); ++index)
        {
            NativeSourceEvidenceValidationResult validation =
                ValidateNativeSourceEvidenceRecord(records[index]);
            if (!validation)
            {
                validation.recordIndex = index;
                return validation;
            }
        }
        return Valid();
    }

    NativeSourceEvidenceProjectionResult ProjectNativeSourceEvidence(
        const ObservationRefinementResult& refinement,
        const TriageResult* triage)
    {
        NativeSourceEvidenceProjectionResult result;
        result.attempted = true;
        if (!refinement.Succeeded())
        {
            result.status =
                NativeSourceEvidenceProjectionStatus::RefinementUnavailable;
            result.diagnostic = "Refined native observations are unavailable.";
            return result;
        }
        if (triage != nullptr && !triage->Succeeded())
        {
            result.status = NativeSourceEvidenceProjectionStatus::TriageUnavailable;
            result.diagnostic =
                "The supplied triage result is not a successful result.";
            return result;
        }

        std::size_t memberCount = 0;
        for (const RefinedObservationGroup& group : refinement.groups)
        {
            memberCount += group.members.size();
        }
        if (memberCount + refinement.collectionNotes.size() +
                refinement.evidenceIntegrityNotes.size() >
            NativeSourceEvidenceMaxRecords)
        {
            result.status = NativeSourceEvidenceProjectionStatus::InputLimitExceeded;
            result.diagnostic = "Refined native evidence exceeds its record cap.";
            return result;
        }
        result.contributionEvaluationAvailable = triage != nullptr;
        std::set<std::string> contributingIds;
        if (triage != nullptr)
        {
            contributingIds.insert(
                triage->contributingObservationIds.begin(),
                triage->contributingObservationIds.end());
        }

        std::vector<NativeSourceEvidenceRecord> projected;
        projected.reserve(
            memberCount + refinement.collectionNotes.size() +
            refinement.evidenceIntegrityNotes.size());

        const auto appendObservation = [&projected, &contributingIds, triage](
            const Observation& observation,
            bool suppressedDuplicate) -> bool
        {
            if (!ValidateObservation(observation).valid)
            {
                return false;
            }
            projected.push_back(ProjectRecord(
                observation,
                triage != nullptr && IsContributing(contributingIds, observation),
                suppressedDuplicate));
            return true;
        };

        for (const RefinedObservationGroup& group : refinement.groups)
        {
            for (const RefinedObservationMember& member : group.members)
            {
                const Observation effective = EffectiveObservation(member);
                if (!appendObservation(
                        effective,
                        member.role == RefinedObservationRole::Duplicate))
                {
                    result.status =
                        NativeSourceEvidenceProjectionStatus::InvalidSourceObservation;
                    result.diagnostic =
                        "Refinement contained an invalid source observation.";
                    return result;
                }
            }
        }
        for (const ObservationRecord& note : refinement.collectionNotes)
        {
            if (!appendObservation(note.observation, false))
            {
                result.status =
                    NativeSourceEvidenceProjectionStatus::InvalidSourceObservation;
                result.diagnostic =
                    "Refinement contained an invalid collection note.";
                return result;
            }
        }
        for (const ObservationRecord& note :
             refinement.evidenceIntegrityNotes)
        {
            if (!appendObservation(note.observation, false))
            {
                result.status =
                    NativeSourceEvidenceProjectionStatus::InvalidSourceObservation;
                result.diagnostic =
                    "Refinement contained an invalid evidence-integrity note.";
                return result;
            }
        }

        std::sort(projected.begin(), projected.end(), RecordLess);
        const NativeSourceEvidenceValidationResult validation =
            ValidateNativeSourceEvidenceRecords(projected);
        if (!validation)
        {
            result.status =
                NativeSourceEvidenceProjectionStatus::InvalidProjectedRecord;
            result.diagnostic = validation.diagnostic;
            return result;
        }

        for (const NativeSourceEvidenceRecord& record : projected)
        {
            result.contributingRecordCount += record.contributedToVerdict ? 1 : 0;
            result.collectionLimitationCount += record.collectionLimitation ? 1 : 0;
            result.evidenceIntegrityRecordCount +=
                record.disposition == ObservationDisposition::EvidenceIntegrityNote
                    ? 1
                    : 0;
            result.suppressedDuplicateCount += record.suppressedDuplicate ? 1 : 0;
            result.contextRecordCount +=
                !record.contributedToVerdict &&
                    !record.collectionLimitation &&
                    record.disposition !=
                        ObservationDisposition::EvidenceIntegrityNote
                    ? 1
                    : 0;
        }
        result.records = std::move(projected);
        result.success = true;
        result.status = NativeSourceEvidenceProjectionStatus::Success;
        result.diagnostic =
            "Native source evidence projected from refined observations.";
        return result;
    }
}
