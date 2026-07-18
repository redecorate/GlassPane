#include "TriageEngine.h"

#include <algorithm>
#include <chrono>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>
#include <string_view>
#include <utility>

namespace GlassPane::Core
{
    namespace
    {
        using TriageClock = std::chrono::steady_clock;

        struct EffectiveRecord
        {
            const RefinedObservationMember* member = nullptr;
            Observation observation;
        };

        std::uint64_t ElapsedMicroseconds(TriageClock::time_point started)
        {
            const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                TriageClock::now() - started).count();
            return elapsed > 0 ? static_cast<std::uint64_t>(elapsed) : 0;
        }

        std::string UnknownEnumText(const char* label, std::uint32_t value)
        {
            std::ostringstream stream;
            stream << "Unknown " << label << " (0x"
                   << std::uppercase
                   << std::hex
                   << std::setw(8)
                   << std::setfill('0')
                   << value
                   << ')';
            return stream.str();
        }

        bool IsContinuationByte(unsigned char value)
        {
            return (value & 0xC0U) == 0x80U;
        }

        std::string BoundedUtf8(std::string value, std::size_t maximumCharacters)
        {
            std::size_t retained = std::min(value.size(), maximumCharacters);
            while (retained > 0 &&
                retained < value.size() &&
                IsContinuationByte(static_cast<unsigned char>(value[retained])))
            {
                --retained;
            }

            // CompactBoundedText can reach the byte cap after copying only the
            // leading byte of a valid UTF-8 sequence. Detect that incomplete
            // final sequence even when the temporary string is exactly at the
            // cap, then retain only complete evidence text.
            if (retained > 0)
            {
                std::size_t sequenceStart = retained - 1;
                while (sequenceStart > 0 &&
                    IsContinuationByte(
                        static_cast<unsigned char>(value[sequenceStart])))
                {
                    --sequenceStart;
                }

                const unsigned char lead =
                    static_cast<unsigned char>(value[sequenceStart]);
                std::size_t sequenceLength = 1;
                if (lead >= 0xC2U && lead <= 0xDFU)
                {
                    sequenceLength = 2;
                }
                else if (lead >= 0xE0U && lead <= 0xEFU)
                {
                    sequenceLength = 3;
                }
                else if (lead >= 0xF0U && lead <= 0xF4U)
                {
                    sequenceLength = 4;
                }
                if (sequenceLength > 1 &&
                    sequenceStart + sequenceLength > retained)
                {
                    retained = sequenceStart;
                }
            }
            value.resize(retained);
            return value;
        }

        std::string CompactBoundedText(
            std::string_view value,
            std::size_t maximumCharacters)
        {
            std::string result;
            result.reserve(std::min(value.size(), maximumCharacters));
            bool pendingSpace = false;
            for (char character : value)
            {
                switch (character)
                {
                case '\r':
                case '\n':
                case '\t':
                case '\f':
                case '\v':
                    pendingSpace = !result.empty();
                    continue;
                default:
                    break;
                }

                if (pendingSpace && result.size() < maximumCharacters)
                {
                    result.push_back(' ');
                }
                pendingSpace = false;
                if (result.size() >= maximumCharacters)
                {
                    break;
                }
                result.push_back(character);
            }
            return BoundedUtf8(std::move(result), maximumCharacters);
        }

        bool HasNonWhitespace(std::string_view value)
        {
            return std::any_of(
                value.begin(),
                value.end(),
                [](char character)
                {
                    switch (character)
                    {
                    case ' ':
                    case '\t':
                    case '\r':
                    case '\n':
                    case '\f':
                    case '\v':
                        return false;
                    default:
                        return true;
                    }
                });
        }

        bool IsKnownDomain(EvidenceDomain domain)
        {
            switch (domain)
            {
            case EvidenceDomain::Unknown:
            case EvidenceDomain::ProcessIdentity:
            case EvidenceDomain::FilePath:
            case EvidenceDomain::FileSignature:
            case EvidenceDomain::CommandLine:
            case EvidenceDomain::ProcessRelationship:
            case EvidenceDomain::Network:
            case EvidenceDomain::Service:
            case EvidenceDomain::Module:
            case EvidenceDomain::Handle:
            case EvidenceDomain::Runtime:
            case EvidenceDomain::MemoryMetadata:
            case EvidenceDomain::Token:
            case EvidenceDomain::Persistence:
            case EvidenceDomain::CollectionQuality:
            case EvidenceDomain::EvidenceIntegrity:
            case EvidenceDomain::ImportedEvidence:
                return true;
            default:
                return false;
            }
        }

        bool IsBehaviorDomain(EvidenceDomain domain)
        {
            return IsKnownDomain(domain) &&
                domain != EvidenceDomain::Unknown &&
                domain != EvidenceDomain::CollectionQuality &&
                domain != EvidenceDomain::EvidenceIntegrity;
        }

        bool IsKnownStrength(ObservationStrength strength)
        {
            switch (strength)
            {
            case ObservationStrength::None:
            case ObservationStrength::Weak:
            case ObservationStrength::Moderate:
            case ObservationStrength::Strong:
                return true;
            default:
                return false;
            }
        }

        bool IsKnownConfidence(ObservationConfidence confidence)
        {
            switch (confidence)
            {
            case ObservationConfidence::Unknown:
            case ObservationConfidence::Low:
            case ObservationConfidence::Medium:
            case ObservationConfidence::High:
                return true;
            default:
                return false;
            }
        }

        bool IsKnownSourceKind(ObservationSourceKind sourceKind)
        {
            switch (sourceKind)
            {
            case ObservationSourceKind::Direct:
            case ObservationSourceKind::Corroborated:
            case ObservationSourceKind::Derived:
            case ObservationSourceKind::Imported:
            case ObservationSourceKind::UserDefined:
            case ObservationSourceKind::Unverified:
            case ObservationSourceKind::Unavailable:
                return true;
            default:
                return false;
            }
        }

        bool IsKnownCorrelationSignificance(CorrelationSignificance significance)
        {
            switch (significance)
            {
            case CorrelationSignificance::Informational:
            case CorrelationSignificance::Weak:
            case CorrelationSignificance::Moderate:
            case CorrelationSignificance::Strong:
                return true;
            default:
                return false;
            }
        }

        bool IsModerateOrStrong(ObservationStrength strength)
        {
            return strength == ObservationStrength::Moderate ||
                strength == ObservationStrength::Strong;
        }

        bool IsModerateOrStrong(CorrelationSignificance significance)
        {
            return significance == CorrelationSignificance::Moderate ||
                significance == CorrelationSignificance::Strong;
        }

        bool IsMediumOrHighConfidence(ObservationConfidence confidence)
        {
            return confidence == ObservationConfidence::Medium ||
                confidence == ObservationConfidence::High;
        }

        template <typename Value>
        bool AddUniqueBounded(
            std::vector<Value>& destination,
            const Value& value,
            std::size_t maximumItems)
        {
            if (std::find(destination.begin(), destination.end(), value) !=
                destination.end())
            {
                return true;
            }
            if (destination.size() >= maximumItems)
            {
                return false;
            }
            destination.push_back(value);
            return true;
        }

        void AddBoundedTextItem(
            std::vector<std::string>& destination,
            std::set<std::string>& seen,
            std::string value,
            std::size_t maximumItems,
            std::size_t maximumCharacters,
            bool& truncated)
        {
            value = CompactBoundedText(value, maximumCharacters);
            if (value.empty() || !seen.insert(value).second)
            {
                return;
            }
            if (destination.size() >= maximumItems)
            {
                truncated = true;
                return;
            }
            destination.push_back(std::move(value));
        }

        void AddBoundedRationaleItem(
            std::vector<std::string>& destination,
            std::vector<TriageRationaleEntry>& entries,
            std::set<std::string>& seen,
            TriageRationaleSection section,
            std::string value,
            bool& truncated)
        {
            value = CompactBoundedText(
                value,
                TriageRationaleItemMaxCharacters);
            if (value.empty() || !seen.insert(value).second)
            {
                return;
            }
            if (destination.size() >= TriageMaxRationaleItems)
            {
                truncated = true;
                return;
            }

            destination.push_back(value);
            entries.push_back({ section, std::move(value) });
        }

        void AddBoundedPreviewRationaleItem(
            std::vector<TriageRationaleEntry>& entries,
            std::set<std::string>& seen,
            TriageRationaleSection section,
            std::string value,
            bool& truncated)
        {
            value = CompactBoundedText(
                value,
                TriageRationaleItemMaxCharacters);
            if (value.empty() || !seen.insert(value).second)
            {
                return;
            }
            if (entries.size() >= TriageMaxRationaleEntries)
            {
                truncated = true;
                return;
            }
            entries.push_back({ section, std::move(value) });
        }

        void FinalizeBoundedTextList(
            std::vector<std::string>& destination,
            std::set<std::string>& seen,
            bool truncated,
            std::size_t maximumItems,
            const char* omissionText)
        {
            if (!truncated || maximumItems == 0)
            {
                return;
            }

            const std::string omission = omissionText;
            if (seen.find(omission) != seen.end())
            {
                return;
            }
            if (destination.size() >= maximumItems)
            {
                destination.back() = omission;
            }
            else
            {
                destination.push_back(omission);
            }
        }

        TriageResult FailureResult(
            TriageEngineStatus status,
            std::string message,
            TriageClock::time_point started)
        {
            TriageResult result;
            result.attempted = true;
            result.success = false;
            result.status = status;
            result.verdict = TriageVerdict::Informational;
            result.statusMessage = BoundedUtf8(
                std::move(message),
                TriageStatusMessageMaxCharacters);
            result.triageDurationMicroseconds = ElapsedMicroseconds(started);
            return result;
        }

        bool IsStaticMemoryRegionMetadata(const Observation& observation)
        {
            return observation.domain == EvidenceDomain::MemoryMetadata &&
                observation.artifactIdentity.kind ==
                    ObservationArtifactKind::MemoryRegion;
        }

        bool IsDirectReviewContribution(
            const RefinedObservationMember& member,
            const Observation& observation)
        {
            // Current MemoryRegion artifacts contain point-in-time region
            // properties only. They do not establish a protection transition,
            // a remote write, a thread start, executable-content provenance,
            // or another behavioral event. A future behavioral-memory source
            // requires an explicit typed semantic contract before it can use a
            // verdict-contributing path.
            return member.role != RefinedObservationRole::Duplicate &&
                !IsStaticMemoryRegionMetadata(observation) &&
                observation.disposition == ObservationDisposition::ReviewRelevant &&
                IsBehaviorDomain(observation.domain) &&
                CanContributeToVerdict(observation);
        }

        bool IsCorrelationDomainParticipant(
            const RefinedObservationMember& member,
            const Observation& observation)
        {
            if (member.role == RefinedObservationRole::Duplicate ||
                member.role == RefinedObservationRole::ArtifactAttribute)
            {
                return false;
            }
            if (IsDirectReviewContribution(member, observation))
            {
                return true;
            }
            return observation.disposition ==
                    ObservationDisposition::CorrelatedOnly &&
                IsBehaviorDomain(observation.domain);
        }

        bool IsQualifiedStrongObservation(const EffectiveRecord& record)
        {
            const Observation& observation = record.observation;
            if (observation.strength != ObservationStrength::Strong ||
                observation.confidence != ObservationConfidence::High ||
                !observation.provenance.sourceAvailable ||
                !HasNonWhitespace(
                    record.member->sourceRecord.source.assessmentRationale))
            {
                return false;
            }

            return observation.provenance.sourceKind == ObservationSourceKind::Direct ||
                observation.provenance.sourceKind ==
                    ObservationSourceKind::Corroborated;
        }

        bool IsContextDisposition(ObservationDisposition disposition)
        {
            return disposition == ObservationDisposition::Informational ||
                disposition == ObservationDisposition::Context ||
                disposition == ObservationDisposition::SuppressedExpected;
        }

        std::string ObservationLabel(const Observation& observation)
        {
            if (HasNonWhitespace(observation.title))
            {
                return CompactBoundedText(
                    observation.title,
                    ObservationTitleMaxCharacters);
            }
            return observation.id;
        }

        std::string PreviewObservationLabel(const Observation& observation)
        {
            if (HasNonWhitespace(observation.title))
            {
                return CompactBoundedText(
                    observation.title,
                    ObservationTitleMaxCharacters);
            }
            return EvidenceDomainDisplayText(observation.domain) +
                " observation";
        }

        bool ArtifactAttributeHasValue(
            const RefinedObservationGroup& group,
            const char* key,
            std::string_view value)
        {
            for (const RefinedObservationMember& member : group.members)
            {
                for (const ObservationArtifactAttribute& attribute :
                     member.sourceRecord.observation.artifactAttributes)
                {
                    if (attribute.key == key && attribute.value == value)
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        bool ArtifactAttributeIsTrue(
            const RefinedObservationGroup& group,
            const char* key)
        {
            return ArtifactAttributeHasValue(
                group,
                key,
                ObservationArtifactAttributeBooleanTrue);
        }

        std::string CorrelationLabel(const ObservationCorrelation& correlation)
        {
            if (HasNonWhitespace(correlation.title))
            {
                return CompactBoundedText(
                    correlation.title,
                    ObservationTitleMaxCharacters);
            }
            return correlation.id;
        }

        void AddObservationLimitations(
            const Observation& observation,
            std::vector<std::string>& limitations,
            std::set<std::string>& seen,
            bool& truncated)
        {
            for (const std::string& limitation : observation.limitations)
            {
                AddBoundedTextItem(
                    limitations,
                    seen,
                    limitation,
                    TriageMaxLimitationItems,
                    TriageLimitationItemMaxCharacters,
                    truncated);
            }
            for (const std::string& limitation : observation.provenance.limitations)
            {
                AddBoundedTextItem(
                    limitations,
                    seen,
                    limitation,
                    TriageMaxLimitationItems,
                    TriageLimitationItemMaxCharacters,
                    truncated);
            }
        }

        std::string DomainSummaryText(const std::set<EvidenceDomain>& domains)
        {
            std::string text = "Independent contributing domains: ";
            bool first = true;
            for (EvidenceDomain domain : domains)
            {
                if (!first)
                {
                    text += ", ";
                }
                first = false;
                text += EvidenceDomainDisplayText(domain);
            }
            text += '.';
            return text;
        }


        bool ValidateCorrelationStrings(const ObservationCorrelation& correlation)
        {
            if (correlation.id.empty() ||
                correlation.id.size() > ObservationIdMaxCharacters ||
                correlation.ruleId.size() > ObservationRuleIdMaxCharacters ||
                correlation.entityScope.size() > ObservationEntityScopeMaxCharacters ||
                correlation.correlationKey.size() >
                    ObservationCorrelationKeyMaxCharacters ||
                correlation.title.size() > ObservationTitleMaxCharacters ||
                correlation.rationale.size() >
                    ObservationCorrelationRationaleMaxCharacters)
            {
                return false;
            }
            return std::all_of(
                correlation.limitations.begin(),
                correlation.limitations.end(),
                [](const std::string& limitation)
                {
                    return limitation.size() <= ObservationLimitationItemMaxCharacters;
                });
        }
    }

    std::string TriageVerdictDisplayText(TriageVerdict verdict)
    {
        switch (verdict)
        {
        case TriageVerdict::Informational:
            return "Informational";
        case TriageVerdict::LowAttention:
            return "Low Attention";
        case TriageVerdict::MediumAttention:
            return "Medium Attention";
        case TriageVerdict::HighAttention:
            return "High Attention";
        default:
            return UnknownEnumText(
                "triage verdict",
                static_cast<std::uint32_t>(verdict));
        }
    }

    std::string TriageEngineStatusDisplayText(TriageEngineStatus status)
    {
        switch (status)
        {
        case TriageEngineStatus::NotAttempted:
            return "Not attempted";
        case TriageEngineStatus::Success:
            return "Success";
        case TriageEngineStatus::RefinementUnavailable:
            return "Refinement unavailable";
        case TriageEngineStatus::CorrelationUnavailable:
            return "Correlation unavailable";
        case TriageEngineStatus::InputLimitExceeded:
            return "Input limit exceeded";
        case TriageEngineStatus::InvalidInput:
            return "Invalid input";
        case TriageEngineStatus::OutputLimitExceeded:
            return "Output limit exceeded";
        case TriageEngineStatus::InternalPolicyFailure:
            return "Internal policy failure";
        default:
            return UnknownEnumText(
                "triage engine status",
                static_cast<std::uint32_t>(status));
        }
    }

    std::string TriageRationaleSectionDisplayText(
        TriageRationaleSection section)
    {
        switch (section)
        {
        case TriageRationaleSection::VerdictBasis:
            return "Verdict basis";
        case TriageRationaleSection::CompletedCorrelations:
            return "Completed correlations";
        case TriageRationaleSection::SupportingContext:
            return "Supporting context";
        case TriageRationaleSection::CollectionLimitations:
            return "Collection limitations";
        case TriageRationaleSection::EvidenceIntegrityContext:
            return "Evidence-integrity context";
        case TriageRationaleSection::UnresolvedCorrelations:
            return "Unresolved correlations";
        case TriageRationaleSection::PresentationNotes:
            return "Presentation notes";
        default:
            return UnknownEnumText(
                "triage rationale section",
                static_cast<std::uint32_t>(section));
        }
    }

    bool TriageResult::Succeeded() const
    {
        return attempted && success && status == TriageEngineStatus::Success;
    }

    TriageResult BuildTriageResult(
        const ObservationRefinementResult& refinement,
        const ObservationCorrelationResult& correlations)
    {
        const TriageClock::time_point started = TriageClock::now();

        try
        {
            if (!refinement.attempted || !refinement.success ||
                refinement.status != ObservationRefinementStatus::Success)
            {
                return FailureResult(
                    TriageEngineStatus::RefinementUnavailable,
                    "TriageEngine result was not built because refined observations were unavailable.",
                    started);
            }
            if (!correlations.attempted || !correlations.success ||
                correlations.status != ObservationCorrelationStatus::Success)
            {
                return FailureResult(
                    TriageEngineStatus::CorrelationUnavailable,
                    "TriageEngine result was not built because structured correlation results were unavailable.",
                    started);
            }
            if (refinement.groups.size() > ObservationRefinementMaxGroups ||
                refinement.collectionNotes.size() >
                    TriageMaxObservationReferences ||
                refinement.evidenceIntegrityNotes.size() >
                    TriageMaxObservationReferences ||
                correlations.correlations.size() >
                    TriageMaxCorrelationReferences ||
                correlations.unresolvedPreparations.size() >
                    TriageMaxUnresolvedCorrelationKeys)
            {
                return FailureResult(
                    TriageEngineStatus::InputLimitExceeded,
                    "TriageEngine input exceeded a bounded collection cap; no partial result was returned.",
                    started);
            }

            std::vector<EffectiveRecord> records;
            records.reserve(std::min(
                refinement.summary.behavioralContextObservationCount,
                TriageMaxObservationReferences));
            std::size_t memberCount = 0;
            std::string entityScope;
            bool entityScopeInitialized = false;

            for (const RefinedObservationGroup& group : refinement.groups)
            {
                if (group.members.size() >
                        TriageMaxObservationReferences - memberCount ||
                    group.entityScope.size() > ObservationEntityScopeMaxCharacters)
                {
                    return FailureResult(
                        TriageEngineStatus::InputLimitExceeded,
                        "TriageEngine observation input exceeded its cap; no partial result was returned.",
                        started);
                }
                memberCount += group.members.size();

                if (!entityScopeInitialized)
                {
                    entityScope = group.entityScope;
                    entityScopeInitialized = true;
                }
                else if (group.entityScope != entityScope)
                {
                    return FailureResult(
                        TriageEngineStatus::InvalidInput,
                        "TriageEngine requires one entity scope; cross-entity reinforcement was rejected.",
                        started);
                }

                for (const RefinedObservationMember& member : group.members)
                {
                    Observation observation = EffectiveObservation(member);
                    if (observation.id.empty() ||
                        !ValidateObservation(observation).IsValid() ||
                        !IsKnownDomain(observation.domain) ||
                        !IsKnownStrength(observation.strength) ||
                        !IsKnownConfidence(observation.confidence) ||
                        !IsKnownSourceKind(observation.provenance.sourceKind))
                    {
                        return FailureResult(
                            TriageEngineStatus::InvalidInput,
                            "TriageEngine rejected an invalid refined observation; no partial result was returned.",
                            started);
                    }
                    records.push_back({ &member, std::move(observation) });
                }
            }

            std::map<std::string, const EffectiveRecord*> recordsById;
            for (const EffectiveRecord& record : records)
            {
                // Duplicate IDs remain auditable in refinement. The primary or
                // first retained record is the stable correlation lookup target.
                const auto existing = recordsById.find(record.observation.id);
                if (existing == recordsById.end() ||
                    (existing->second->member->role ==
                            RefinedObservationRole::Duplicate &&
                        record.member->role != RefinedObservationRole::Duplicate))
                {
                    recordsById[record.observation.id] = &record;
                }
            }

            TriageResult result;
            result.attempted = true;
            result.status = TriageEngineStatus::Success;

            std::set<std::string> rationaleSeen;
            std::vector<TriageRationaleEntry> pendingRationaleEntries;
            std::set<std::string> limitationSeen;
            std::set<EvidenceDomain> weakDirectDomains;
            bool hasModerateOrStrongDirect = false;
            bool hasQualifiedStrongDirect = false;
            bool hasWeakDirect = false;
            bool outputLimitExceeded = false;

            for (const EffectiveRecord& record : records)
            {
                const Observation& observation = record.observation;
                const bool directlyContributes =
                    IsDirectReviewContribution(*record.member, observation);

                if (directlyContributes)
                {
                    outputLimitExceeded = !AddUniqueBounded(
                        result.contributingObservationIds,
                        observation.id,
                        TriageMaxObservationReferences) || outputLimitExceeded;
                    result.contributingDomains.insert(observation.domain);

                    if (observation.strength == ObservationStrength::Weak)
                    {
                        hasWeakDirect = true;
                        weakDirectDomains.insert(observation.domain);
                    }
                    else if (IsModerateOrStrong(observation.strength))
                    {
                        hasModerateOrStrongDirect = true;
                    }
                    hasQualifiedStrongDirect =
                        IsQualifiedStrongObservation(record) ||
                        hasQualifiedStrongDirect;

                    std::string line = "Verdict basis - source observation '" +
                        observation.id + "' reports: " +
                        ObservationLabel(observation) + " (" +
                        ObservationStrengthDisplayText(observation.strength) +
                        ", " + EvidenceDomainDisplayText(observation.domain) + ").";
                    AddBoundedRationaleItem(
                        result.rationale,
                        pendingRationaleEntries,
                        rationaleSeen,
                        TriageRationaleSection::VerdictBasis,
                        std::move(line),
                        result.rationaleTruncated);

                    if (IsQualifiedStrongObservation(record))
                    {
                        AddBoundedRationaleItem(
                            result.rationale,
                            pendingRationaleEntries,
                            rationaleSeen,
                            TriageRationaleSection::VerdictBasis,
                            "Attributed source assessment for '" +
                                observation.id + "': " +
                                record.member->sourceRecord.source.
                                    assessmentRationale,
                            result.rationaleTruncated);
                    }
                }
                else if (record.member->role != RefinedObservationRole::Duplicate &&
                    record.member->role !=
                        RefinedObservationRole::ArtifactAttribute &&
                    (IsStaticMemoryRegionMetadata(observation) ||
                        IsContextDisposition(observation.disposition) ||
                        (observation.disposition ==
                            ObservationDisposition::ReviewRelevant &&
                            !CanContributeToVerdict(observation))))
                {
                    outputLimitExceeded = !AddUniqueBounded(
                        result.contextObservationIds,
                        observation.id,
                        TriageMaxObservationReferences) || outputLimitExceeded;
                }

                if (record.member->role != RefinedObservationRole::Duplicate)
                {
                    AddObservationLimitations(
                        observation,
                        result.limitations,
                        limitationSeen,
                        result.limitationsTruncated);
                }
            }

            bool hasWeakCorrelation = false;
            bool hasModerateCorrelation = false;
            bool hasStrongCorrelation = false;
            bool hasCoherentModerateMultiDomainCorrelation = false;
            std::vector<std::string> sameDomainCeilingCorrelationIds;
            std::set<std::pair<std::string, std::string>> activatedKeys;
            std::set<std::string> correlationIds;

            for (const ObservationCorrelation& correlation :
                 correlations.correlations)
            {
                if (!ValidateCorrelationStrings(correlation) ||
                    !IsKnownCorrelationSignificance(correlation.significance) ||
                    !IsKnownConfidence(correlation.confidence) ||
                    !correlationIds.insert(correlation.id).second ||
                    correlation.participatingObservationIds.empty() ||
                    correlation.participatingObservationIds.size() >
                        ObservationCorrelationMaxParticipantsPerResult ||
                    correlation.supportingObservationIds.size() >
                        ObservationCorrelationMaxSupportingPerResult)
                {
                    return FailureResult(
                        TriageEngineStatus::InvalidInput,
                        "TriageEngine rejected an invalid structured correlation; no partial result was returned.",
                        started);
                }
                if (entityScopeInitialized && correlation.entityScope != entityScope)
                {
                    return FailureResult(
                        TriageEngineStatus::InvalidInput,
                        "TriageEngine rejected a cross-entity correlation.",
                        started);
                }

                bool hasUnverifiedParticipant = false;
                bool participantsEligibleForHigh = true;
                std::set<EvidenceDomain> actualParticipantDomains;
                std::set<EvidenceDomain> directParticipantDomains;
                std::set<EvidenceDomain> moderateDirectParticipantDomains;
                std::set<EvidenceDomain> verdictParticipantDomains;
                std::set<std::string> participantIds;
                for (const std::string& participantId :
                     correlation.participatingObservationIds)
                {
                    if (participantId.empty() ||
                        participantId.size() > ObservationIdMaxCharacters ||
                        !participantIds.insert(participantId).second)
                    {
                        return FailureResult(
                            TriageEngineStatus::InvalidInput,
                            "TriageEngine rejected an invalid correlation participant identity.",
                            started);
                    }
                    const auto participant = recordsById.find(participantId);
                    if (participant == recordsById.end() ||
                        participant->second->member->role ==
                            RefinedObservationRole::Duplicate ||
                        participant->second->member->role ==
                            RefinedObservationRole::ArtifactAttribute)
                    {
                        return FailureResult(
                            TriageEngineStatus::InvalidInput,
                            "TriageEngine rejected a correlation with a missing or duplicate-only participant.",
                            started);
                    }
                    const ObservationSourceKind sourceKind =
                        participant->second->observation.provenance.sourceKind;
                    const Observation& participantObservation =
                        participant->second->observation;
                    actualParticipantDomains.insert(
                        participant->second->observation.domain);
                    if (IsDirectReviewContribution(
                            *participant->second->member,
                            participant->second->observation))
                    {
                        directParticipantDomains.insert(
                            participant->second->observation.domain);
                        if (IsModerateOrStrong(
                                participant->second->observation.strength))
                        {
                            moderateDirectParticipantDomains.insert(
                                participant->second->observation.domain);
                        }
                    }
                    if (IsCorrelationDomainParticipant(
                            *participant->second->member,
                            participant->second->observation))
                    {
                        verdictParticipantDomains.insert(
                            participant->second->observation.domain);
                    }
                    hasUnverifiedParticipant =
                        sourceKind == ObservationSourceKind::Unverified ||
                        sourceKind == ObservationSourceKind::Unavailable ||
                        hasUnverifiedParticipant;
                    participantsEligibleForHigh =
                        participantObservation.provenance.sourceAvailable &&
                        sourceKind != ObservationSourceKind::Unverified &&
                        sourceKind != ObservationSourceKind::Unavailable &&
                        IsMediumOrHighConfidence(
                            participantObservation.confidence) &&
                        participantsEligibleForHigh;
                }
                if (actualParticipantDomains != correlation.participatingDomains)
                {
                    return FailureResult(
                        TriageEngineStatus::InvalidInput,
                        "TriageEngine rejected a correlation whose declared domains did not match its typed participants.",
                        started);
                }
                for (EvidenceDomain domain : correlation.participatingDomains)
                {
                    if (!IsBehaviorDomain(domain))
                    {
                        return FailureResult(
                            TriageEngineStatus::InvalidInput,
                            "TriageEngine rejected a correlation with a non-behavioral participating domain.",
                            started);
                    }
                }

                if (correlation.contributesToVerdict &&
                    (correlation.significance ==
                            CorrelationSignificance::Informational ||
                        correlation.participatingDomains.empty()))
                {
                    return FailureResult(
                        TriageEngineStatus::InvalidInput,
                        "TriageEngine rejected a contributing correlation without evidentiary significance and domains.",
                        started);
                }

                if (correlation.significance == CorrelationSignificance::Strong &&
                    (hasUnverifiedParticipant ||
                        correlation.confidence == ObservationConfidence::Unknown ||
                        correlation.confidence == ObservationConfidence::Low))
                {
                    return FailureResult(
                        TriageEngineStatus::InvalidInput,
                        "TriageEngine rejected a Strong correlation without sufficient participant provenance and confidence.",
                        started);
                }

                activatedKeys.insert({
                    correlation.entityScope,
                    correlation.correlationKey
                });

                for (const std::string& limitation : correlation.limitations)
                {
                    AddBoundedTextItem(
                        result.limitations,
                        limitationSeen,
                        limitation,
                        TriageMaxLimitationItems,
                        TriageLimitationItemMaxCharacters,
                        result.limitationsTruncated);
                }

                std::set<std::string> supportingIds;
                for (const std::string& supportingId :
                     correlation.supportingObservationIds)
                {
                    if (supportingId.empty() ||
                        supportingId.size() > ObservationIdMaxCharacters ||
                        !supportingIds.insert(supportingId).second)
                    {
                        return FailureResult(
                            TriageEngineStatus::InvalidInput,
                            "TriageEngine rejected an invalid correlation support identity.",
                            started);
                    }
                    const auto supporting = recordsById.find(supportingId);
                    if (supporting == recordsById.end() ||
                        supporting->second->member->role ==
                            RefinedObservationRole::Duplicate ||
                        supporting->second->member->role ==
                            RefinedObservationRole::ArtifactAttribute)
                    {
                        return FailureResult(
                            TriageEngineStatus::InvalidInput,
                            "TriageEngine rejected a correlation with missing or duplicate-only support.",
                            started);
                    }
                    if (!CanContributeToVerdict(supporting->second->observation))
                    {
                        outputLimitExceeded = !AddUniqueBounded(
                            result.contextObservationIds,
                            supportingId,
                            TriageMaxObservationReferences) ||
                            outputLimitExceeded;
                    }
                }

                // Context participants remain auditable support but cannot
                // make a correlation verdict-contributing by themselves.
                if (!correlation.contributesToVerdict ||
                    verdictParticipantDomains.empty())
                {
                    continue;
                }

                outputLimitExceeded = !AddUniqueBounded(
                    result.contributingCorrelationIds,
                    correlation.id,
                    TriageMaxCorrelationReferences) || outputLimitExceeded;
                for (const std::string& participantId :
                     correlation.participatingObservationIds)
                {
                    const auto participant = recordsById.find(participantId);
                    if (participant != recordsById.end() &&
                        IsCorrelationDomainParticipant(
                            *participant->second->member,
                            participant->second->observation))
                    {
                        outputLimitExceeded = !AddUniqueBounded(
                            result.contributingObservationIds,
                            participantId,
                            TriageMaxObservationReferences) ||
                            outputLimitExceeded;
                    }
                }
                result.contributingDomains.insert(
                    verdictParticipantDomains.begin(),
                    verdictParticipantDomains.end());
                result.maximumContributingCorrelationDomainCount = std::max(
                    result.maximumContributingCorrelationDomainCount,
                    verdictParticipantDomains.size());
                if (verdictParticipantDomains.size() == 1)
                {
                    ++result.sameDomainContributingCorrelationCount;
                }

                switch (correlation.significance)
                {
                case CorrelationSignificance::Weak:
                    hasWeakCorrelation = true;
                    break;
                case CorrelationSignificance::Moderate:
                    hasModerateCorrelation = true;
                    break;
                case CorrelationSignificance::Strong:
                    hasStrongCorrelation = true;
                    break;
                case CorrelationSignificance::Informational:
                default:
                    break;
                }
                if (IsModerateOrStrong(correlation.significance) &&
                    verdictParticipantDomains.size() == 1)
                {
                    result.sameDomainVerdictCeilingApplied = true;
                    sameDomainCeilingCorrelationIds.push_back(correlation.id);
                }
                if (IsModerateOrStrong(correlation.significance) &&
                    verdictParticipantDomains.size() >= 2 &&
                    directParticipantDomains.size() >= 2 &&
                    moderateDirectParticipantDomains.size() >= 2 &&
                    IsMediumOrHighConfidence(correlation.confidence) &&
                    participantsEligibleForHigh)
                {
                    hasCoherentModerateMultiDomainCorrelation = true;
                }

                std::string line = "Verdict basis - completed correlation '" +
                    correlation.id + "' (" +
                    CorrelationSignificanceDisplayText(correlation.significance) +
                    "): " + CorrelationLabel(correlation);
                if (HasNonWhitespace(correlation.rationale))
                {
                    line += ". " + CompactBoundedText(
                        correlation.rationale,
                        ObservationCorrelationRationaleMaxCharacters);
                }
                AddBoundedRationaleItem(
                    result.rationale,
                    pendingRationaleEntries,
                    rationaleSeen,
                    TriageRationaleSection::CompletedCorrelations,
                    std::move(line),
                    result.rationaleTruncated);
            }

            for (const ObservationRecord& note : refinement.collectionNotes)
            {
                if (note.observation.id.empty() ||
                    !ValidateObservation(note.observation).IsValid())
                {
                    return FailureResult(
                        TriageEngineStatus::InvalidInput,
                        "TriageEngine rejected an invalid collection note.",
                        started);
                }
                outputLimitExceeded = !AddUniqueBounded(
                    result.collectionNoteIds,
                    note.observation.id,
                    TriageMaxObservationReferences) || outputLimitExceeded;
                AddObservationLimitations(
                    note.observation,
                    result.limitations,
                    limitationSeen,
                    result.limitationsTruncated);
            }
            for (const ObservationRecord& note :
                 refinement.evidenceIntegrityNotes)
            {
                if (note.observation.id.empty() ||
                    !ValidateObservation(note.observation).IsValid())
                {
                    return FailureResult(
                        TriageEngineStatus::InvalidInput,
                        "TriageEngine rejected an invalid evidence-integrity note.",
                        started);
                }
                outputLimitExceeded = !AddUniqueBounded(
                    result.evidenceIntegrityNoteIds,
                    note.observation.id,
                    TriageMaxObservationReferences) || outputLimitExceeded;
                AddObservationLimitations(
                    note.observation,
                    result.limitations,
                    limitationSeen,
                    result.limitationsTruncated);
            }

            for (const ObservationCorrelationPreparation& preparation :
                 correlations.unresolvedPreparations)
            {
                if (preparation.correlationKey.empty() ||
                    preparation.correlationKey.size() >
                        ObservationCorrelationKeyMaxCharacters ||
                    preparation.entityScope.size() >
                        ObservationEntityScopeMaxCharacters)
                {
                    return FailureResult(
                        TriageEngineStatus::InvalidInput,
                        "TriageEngine rejected invalid unresolved-correlation metadata.",
                        started);
                }
                if (activatedKeys.find({
                        preparation.entityScope,
                        preparation.correlationKey
                    }) != activatedKeys.end())
                {
                    continue;
                }
                outputLimitExceeded = !AddUniqueBounded(
                    result.unresolvedCorrelationKeys,
                    preparation.correlationKey,
                    TriageMaxUnresolvedCorrelationKeys) || outputLimitExceeded;
            }

            if (outputLimitExceeded)
            {
                return FailureResult(
                    TriageEngineStatus::OutputLimitExceeded,
                    "TriageEngine output exceeded a reference cap; no partial result was returned.",
                    started);
            }

            result.qualifiedStandaloneStrongHighGateSatisfied =
                hasQualifiedStrongDirect;
            result.coherentMultiDomainHighGateSatisfied =
                hasCoherentModerateMultiDomainCorrelation;

            // Explicit, non-numeric policy. Correlation significance is not a
            // verdict shortcut: every same-domain correlation has a Medium
            // ceiling, including a Strong multi-signal correlation. High is
            // reserved for either a strictly qualified standalone Strong source
            // assessment or a completed typed correlation that coherently joins
            // at least two eligible Moderate-or-Strong direct ReviewRelevant
            // domains.
            if (hasQualifiedStrongDirect ||
                hasCoherentModerateMultiDomainCorrelation)
            {
                result.verdict = TriageVerdict::HighAttention;
            }
            else if (hasModerateOrStrongDirect || hasModerateCorrelation ||
                hasStrongCorrelation || weakDirectDomains.size() >= 2)
            {
                result.verdict = TriageVerdict::MediumAttention;
            }
            else if (hasWeakDirect || hasWeakCorrelation)
            {
                result.verdict = TriageVerdict::LowAttention;
            }
            else
            {
                result.verdict = TriageVerdict::Informational;
            }

            const TriageClock::time_point rationaleAggregationStarted =
                TriageClock::now();
            std::vector<std::string> orderedRationale;
            std::vector<TriageRationaleEntry> orderedRationaleEntries;
            std::set<std::string> orderedSeen;
            bool orderedTruncated = false;
            AddBoundedRationaleItem(
                orderedRationale,
                orderedRationaleEntries,
                orderedSeen,
                TriageRationaleSection::VerdictBasis,
                "TriageEngine result: " + TriageVerdictDisplayText(result.verdict) + ".",
                orderedTruncated);
            for (const std::string& correlationId :
                 sameDomainCeilingCorrelationIds)
            {
                AddBoundedRationaleItem(
                    orderedRationale,
                    orderedRationaleEntries,
                    orderedSeen,
                    TriageRationaleSection::VerdictBasis,
                    "Same-domain verdict ceiling - completed correlation '" +
                        correlationId +
                        "' is confined to one evidence domain. Its observations are insufficient by themselves for High Attention.",
                    orderedTruncated);
            }
            if (result.contributingObservationIds.empty() &&
                result.contributingCorrelationIds.empty())
            {
                AddBoundedRationaleItem(
                    orderedRationale,
                    orderedRationaleEntries,
                    orderedSeen,
                    TriageRationaleSection::VerdictBasis,
                    "Verdict basis: no ReviewRelevant observation or completed correlation contributes to the triage verdict.",
                    orderedTruncated);
            }
            for (const TriageRationaleEntry& entry : pendingRationaleEntries)
            {
                AddBoundedRationaleItem(
                    orderedRationale,
                    orderedRationaleEntries,
                    orderedSeen,
                    entry.section,
                    entry.text,
                    orderedTruncated);
            }
            if (!result.contributingDomains.empty())
            {
                AddBoundedRationaleItem(
                    orderedRationale,
                    orderedRationaleEntries,
                    orderedSeen,
                    TriageRationaleSection::VerdictBasis,
                    DomainSummaryText(result.contributingDomains),
                    orderedTruncated);
            }

            for (const std::string& contextId : result.contextObservationIds)
            {
                const auto record = recordsById.find(contextId);
                if (record != recordsById.end())
                {
                    AddBoundedRationaleItem(
                        orderedRationale,
                        orderedRationaleEntries,
                        orderedSeen,
                        TriageRationaleSection::SupportingContext,
                        "Supporting context - source observation '" +
                            contextId + "' reports: " +
                            ObservationLabel(record->second->observation) + ".",
                        orderedTruncated);
                }
            }
            for (const ObservationRecord& note : refinement.collectionNotes)
            {
                AddBoundedRationaleItem(
                    orderedRationale,
                    orderedRationaleEntries,
                    orderedSeen,
                    TriageRationaleSection::CollectionLimitations,
                    "Collection limitation - source observation '" +
                        note.observation.id + "' reports: " +
                        ObservationLabel(note.observation) + ".",
                    orderedTruncated);
            }
            for (const ObservationRecord& note :
                 refinement.evidenceIntegrityNotes)
            {
                AddBoundedRationaleItem(
                    orderedRationale,
                    orderedRationaleEntries,
                    orderedSeen,
                    TriageRationaleSection::EvidenceIntegrityContext,
                    "Evidence-integrity context - source observation '" +
                        note.observation.id + "' reports: " +
                        ObservationLabel(note.observation) + ".",
                    orderedTruncated);
            }
            for (const std::string& key : result.unresolvedCorrelationKeys)
            {
                AddBoundedRationaleItem(
                    orderedRationale,
                    orderedRationaleEntries,
                    orderedSeen,
                    TriageRationaleSection::UnresolvedCorrelations,
                    "Unresolved correlation: '" + key + "'.",
                    orderedTruncated);
            }

            result.rationaleTruncated =
                result.rationaleTruncated || orderedTruncated;
            FinalizeBoundedTextList(
                orderedRationale,
                orderedSeen,
                result.rationaleTruncated,
                TriageMaxRationaleItems,
                "Additional rationale items were omitted by the bounded triage policy.");
            if (orderedRationaleEntries.size() < orderedRationale.size())
            {
                orderedRationaleEntries.push_back({
                    TriageRationaleSection::PresentationNotes,
                    orderedRationale.back()
                });
            }
            for (std::size_t index = 0;
                 index < orderedRationaleEntries.size();
                 ++index)
            {
                if (orderedRationaleEntries[index].text != orderedRationale[index])
                {
                    orderedRationaleEntries[index].section =
                        TriageRationaleSection::PresentationNotes;
                    orderedRationaleEntries[index].text = orderedRationale[index];
                }
            }
            result.rationale = std::move(orderedRationale);
            result.rationaleEntries = std::move(orderedRationaleEntries);
            FinalizeBoundedTextList(
                result.limitations,
                limitationSeen,
                result.limitationsTruncated,
                TriageMaxLimitationItems,
                "Additional limitations were omitted by the bounded triage policy.");

            // Build a separate compact, ID-free view for the Debug comparison
            // summary. Detailed rationale above deliberately retains stable
            // source/correlation identities for expanded audit diagnostics.
            std::set<std::string> previewSeen;
            AddBoundedPreviewRationaleItem(
                result.previewRationaleEntries,
                previewSeen,
                TriageRationaleSection::VerdictBasis,
                "TriageEngine result: " +
                    TriageVerdictDisplayText(result.verdict) + ".",
                result.previewRationaleTruncated);

            std::size_t memoryArtifactCount = 0;
            std::size_t writableExecutableArtifactCount = 0;
            std::size_t privateExecutableArtifactCount = 0;
            std::size_t unbackedExecutableArtifactCount = 0;
            std::size_t guardedArtifactCount = 0;
            for (const RefinedObservationGroup& group : refinement.groups)
            {
                if (group.domain != EvidenceDomain::MemoryMetadata ||
                    group.artifactIdentity.kind !=
                        ObservationArtifactKind::MemoryRegion ||
                    !HasCompleteObservationArtifactIdentity(
                        group.artifactIdentity))
                {
                    continue;
                }
                ++memoryArtifactCount;
                const bool writable = ArtifactAttributeIsTrue(
                    group,
                    ObservationArtifactAttributeMemoryWritable);
                const bool executable = ArtifactAttributeIsTrue(
                    group,
                    ObservationArtifactAttributeMemoryExecutable);
                const bool privateAllocation = ArtifactAttributeIsTrue(
                    group,
                    ObservationArtifactAttributeMemoryPrivate);
                const bool imageBacked = ArtifactAttributeIsTrue(
                    group,
                    ObservationArtifactAttributeMemoryImageBacked);
                const bool explicitlyNotImageBacked =
                    ArtifactAttributeHasValue(
                        group,
                        ObservationArtifactAttributeMemoryImageBacked,
                        "false");
                const bool mappedFileBacked = ArtifactAttributeIsTrue(
                    group,
                    ObservationArtifactAttributeMemoryMappedFileBacked);
                const bool explicitlyNotMappedFileBacked =
                    ArtifactAttributeHasValue(
                        group,
                        ObservationArtifactAttributeMemoryMappedFileBacked,
                        "false");
                const bool guarded = ArtifactAttributeIsTrue(
                    group,
                    ObservationArtifactAttributeMemoryGuarded);

                writableExecutableArtifactCount += writable && executable
                    ? 1U
                    : 0U;
                privateExecutableArtifactCount +=
                    privateAllocation && executable ? 1U : 0U;
                unbackedExecutableArtifactCount +=
                    executable && explicitlyNotImageBacked &&
                        explicitlyNotMappedFileBacked && !imageBacked &&
                        !mappedFileBacked
                    ? 1U
                    : 0U;
                guardedArtifactCount += guarded ? 1U : 0U;
            }

            if (memoryArtifactCount > 0)
            {
                const auto regionCountText = [](std::size_t count)
                {
                    return std::to_string(count) +
                        (count == 1 ? " region." : " regions.");
                };
                AddBoundedPreviewRationaleItem(
                    result.previewRationaleEntries,
                    previewSeen,
                    TriageRationaleSection::SupportingContext,
                    "Static memory-region metadata was observed across " +
                        std::to_string(memoryArtifactCount) +
                        (memoryArtifactCount == 1
                            ? " memory-region artifact."
                            : " memory-region artifacts."),
                    result.previewRationaleTruncated);
                if (writableExecutableArtifactCount > 0)
                {
                    AddBoundedPreviewRationaleItem(
                        result.previewRationaleEntries,
                        previewSeen,
                        TriageRationaleSection::SupportingContext,
                        "Writable and executable memory was observed on " +
                            regionCountText(writableExecutableArtifactCount),
                        result.previewRationaleTruncated);
                }
                if (privateExecutableArtifactCount > 0)
                {
                    AddBoundedPreviewRationaleItem(
                        result.previewRationaleEntries,
                        previewSeen,
                        TriageRationaleSection::SupportingContext,
                        "Private executable memory was observed on " +
                            regionCountText(privateExecutableArtifactCount),
                        result.previewRationaleTruncated);
                }
                if (unbackedExecutableArtifactCount > 0)
                {
                    AddBoundedPreviewRationaleItem(
                        result.previewRationaleEntries,
                        previewSeen,
                        TriageRationaleSection::SupportingContext,
                        "Executable memory without image or mapped-file backing was observed on " +
                            regionCountText(unbackedExecutableArtifactCount),
                        result.previewRationaleTruncated);
                }
                if (guardedArtifactCount > 0)
                {
                    AddBoundedPreviewRationaleItem(
                        result.previewRationaleEntries,
                        previewSeen,
                        TriageRationaleSection::SupportingContext,
                        "Guard-page protection was observed on " +
                            regionCountText(guardedArtifactCount),
                        result.previewRationaleTruncated);
                }
                AddBoundedPreviewRationaleItem(
                    result.previewRationaleEntries,
                    previewSeen,
                    TriageRationaleSection::SupportingContext,
                    "These are static point-in-time region properties and do not establish injection, payload execution, or malicious activity.",
                    result.previewRationaleTruncated);
            }

            for (const EffectiveRecord& record : records)
            {
                if (!IsDirectReviewContribution(
                        *record.member,
                        record.observation) ||
                    record.observation.artifactIdentity.kind ==
                        ObservationArtifactKind::MemoryRegion)
                {
                    continue;
                }
                AddBoundedPreviewRationaleItem(
                    result.previewRationaleEntries,
                    previewSeen,
                    TriageRationaleSection::VerdictBasis,
                    PreviewObservationLabel(record.observation) + " (" +
                        ObservationStrengthDisplayText(
                            record.observation.strength) + ", " +
                        EvidenceDomainDisplayText(record.observation.domain) +
                        ").",
                    result.previewRationaleTruncated);
            }
            for (const ObservationCorrelation& correlation :
                 correlations.correlations)
            {
                if (!correlation.contributesToVerdict)
                {
                    continue;
                }
                std::string line = "Completed correlation: " +
                    (HasNonWhitespace(correlation.title)
                        ? CompactBoundedText(
                            correlation.title,
                            ObservationTitleMaxCharacters)
                        : std::string("typed evidence relationship")) + ".";
                if (HasNonWhitespace(correlation.rationale))
                {
                    line += " " + CompactBoundedText(
                        correlation.rationale,
                        ObservationCorrelationRationaleMaxCharacters);
                }
                AddBoundedPreviewRationaleItem(
                    result.previewRationaleEntries,
                    previewSeen,
                    TriageRationaleSection::CompletedCorrelations,
                    std::move(line),
                    result.previewRationaleTruncated);
            }

            if (result.contributingObservationIds.empty() &&
                result.contributingCorrelationIds.empty())
            {
                AddBoundedPreviewRationaleItem(
                    result.previewRationaleEntries,
                    previewSeen,
                    TriageRationaleSection::VerdictBasis,
                    "No ReviewRelevant observation or completed correlation contributes to the triage verdict.",
                    result.previewRationaleTruncated);
            }
            if (!result.contributingDomains.empty())
            {
                AddBoundedPreviewRationaleItem(
                    result.previewRationaleEntries,
                    previewSeen,
                    TriageRationaleSection::VerdictBasis,
                    DomainSummaryText(result.contributingDomains),
                    result.previewRationaleTruncated);
            }
            if (result.sameDomainVerdictCeilingApplied)
            {
                AddBoundedPreviewRationaleItem(
                    result.previewRationaleEntries,
                    previewSeen,
                    TriageRationaleSection::VerdictBasis,
                    "A same-domain verdict ceiling was applied; repeated facts from one evidence domain cannot independently satisfy High Attention.",
                    result.previewRationaleTruncated);
            }
            if (result.verdict != TriageVerdict::HighAttention)
            {
                AddBoundedPreviewRationaleItem(
                    result.previewRationaleEntries,
                    previewSeen,
                    TriageRationaleSection::VerdictBasis,
                    "High Attention requirements were not satisfied.",
                    result.previewRationaleTruncated);
            }

            for (const std::string& contextId : result.contextObservationIds)
            {
                const auto record = recordsById.find(contextId);
                if (record == recordsById.end() ||
                    record->second->observation.artifactIdentity.kind ==
                        ObservationArtifactKind::MemoryRegion)
                {
                    continue;
                }
                AddBoundedPreviewRationaleItem(
                    result.previewRationaleEntries,
                    previewSeen,
                    TriageRationaleSection::SupportingContext,
                    PreviewObservationLabel(record->second->observation) + ".",
                    result.previewRationaleTruncated);
            }
            for (const ObservationRecord& note : refinement.collectionNotes)
            {
                AddBoundedPreviewRationaleItem(
                    result.previewRationaleEntries,
                    previewSeen,
                    TriageRationaleSection::CollectionLimitations,
                    PreviewObservationLabel(note.observation) + ".",
                    result.previewRationaleTruncated);
            }
            for (const ObservationRecord& note :
                 refinement.evidenceIntegrityNotes)
            {
                AddBoundedPreviewRationaleItem(
                    result.previewRationaleEntries,
                    previewSeen,
                    TriageRationaleSection::EvidenceIntegrityContext,
                    PreviewObservationLabel(note.observation) + ".",
                    result.previewRationaleTruncated);
            }
            if (!result.unresolvedCorrelationKeys.empty())
            {
                AddBoundedPreviewRationaleItem(
                    result.previewRationaleEntries,
                    previewSeen,
                    TriageRationaleSection::UnresolvedCorrelations,
                    std::to_string(result.unresolvedCorrelationKeys.size()) +
                        " typed correlation candidate(s) remain unresolved.",
                    result.previewRationaleTruncated);
            }

            result.rationaleAggregationDurationMicroseconds =
                ElapsedMicroseconds(rationaleAggregationStarted);
            result.success = true;
            result.statusMessage = BoundedUtf8(
                "TriageEngine result completed: " +
                    TriageVerdictDisplayText(result.verdict) + "; " +
                    std::to_string(result.contributingObservationIds.size()) +
                    " contributing observation(s), " +
                    std::to_string(result.contributingCorrelationIds.size()) +
                    " completed correlation(s), " +
                    std::to_string(result.contributingDomains.size()) +
                    " independent domain(s).",
                TriageStatusMessageMaxCharacters);
            result.triageDurationMicroseconds = ElapsedMicroseconds(started);
            return result;
        }
        catch (...)
        {
            return FailureResult(
                TriageEngineStatus::InternalPolicyFailure,
                "TriageEngine evaluation failed internally; refined native observations remain available for audit and authority is unavailable for this evaluation.",
                started);
        }
    }
}
