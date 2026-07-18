#include "ObservationPolicy.h"

#include <algorithm>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>
#include <utility>

namespace GlassPane::Core
{
    namespace
    {
        void LimitString(std::string& value, std::size_t maximumCharacters)
        {
            if (value.size() > maximumCharacters)
            {
                value.resize(maximumCharacters);
            }
        }

        void LimitStringItems(
            std::vector<std::string>& values,
            std::size_t maximumItems,
            std::size_t maximumCharactersPerItem)
        {
            if (values.size() > maximumItems)
            {
                values.resize(maximumItems);
            }

            for (std::string& value : values)
            {
                LimitString(value, maximumCharactersPerItem);
            }
        }

        bool AnyStringTooLong(
            const std::vector<std::string>& values,
            std::size_t maximumCharacters)
        {
            return std::any_of(
                values.begin(),
                values.end(),
                [maximumCharacters](const std::string& value)
                {
                    return value.size() > maximumCharacters;
                });
        }

        void AddValidationIssue(
            ObservationValidationResult& result,
            ObservationValidationIssue issue)
        {
            result.valid = false;
            if (!result.HasIssue(issue))
            {
                result.issues.push_back(issue);
            }
        }

        bool IsKnownEvidenceDomain(EvidenceDomain domain)
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

        bool IsKnownArtifactKind(ObservationArtifactKind kind)
        {
            switch (kind)
            {
            case ObservationArtifactKind::None:
            case ObservationArtifactKind::Process:
            case ObservationArtifactKind::File:
            case ObservationArtifactKind::MemoryRegion:
            case ObservationArtifactKind::NetworkConnection:
            case ObservationArtifactKind::Service:
            case ObservationArtifactKind::Handle:
            case ObservationArtifactKind::Module:
            case ObservationArtifactKind::Token:
            case ObservationArtifactKind::RuntimeObject:
                return true;
            default:
                return false;
            }
        }

        bool ArtifactAttributesWithinCaps(
            const std::vector<ObservationArtifactAttribute>& attributes)
        {
            if (attributes.size() > ObservationMaxArtifactAttributes)
            {
                return false;
            }
            std::set<std::string> keys;
            for (const ObservationArtifactAttribute& attribute : attributes)
            {
                if (attribute.key.empty() ||
                    attribute.key.size() >
                        ObservationArtifactAttributeKeyMaxCharacters ||
                    attribute.value.size() >
                        ObservationArtifactAttributeValueMaxCharacters ||
                    !keys.insert(attribute.key).second)
                {
                    return false;
                }
            }
            return true;
        }

        bool ArtifactContractIsValid(const Observation& observation)
        {
            const ObservationArtifactIdentity& identity =
                observation.artifactIdentity;
            if (!IsKnownArtifactKind(identity.kind))
            {
                return false;
            }
            if (identity.kind == ObservationArtifactKind::None)
            {
                return identity.entityScope.empty() &&
                    identity.artifactKey.empty() &&
                    observation.artifactAttributes.empty();
            }
            return HasCompleteObservationArtifactIdentity(identity) &&
                identity.entityScope == observation.entityScope &&
                ArtifactAttributesWithinCaps(observation.artifactAttributes);
        }

        void AddArtifactNormalizationLimitation(Observation& observation)
        {
            constexpr const char* Message =
                "Artifact identity metadata was invalid or exceeded its bounded Core contract and was cleared to prevent accidental artifact merging.";
            if (std::find(
                    observation.limitations.begin(),
                    observation.limitations.end(),
                    Message) != observation.limitations.end())
            {
                return;
            }
            if (observation.limitations.size() < ObservationMaxLimitationItems)
            {
                observation.limitations.emplace_back(Message);
            }
        }

        bool IsContributingStrength(ObservationStrength strength)
        {
            switch (strength)
            {
            case ObservationStrength::Weak:
            case ObservationStrength::Moderate:
            case ObservationStrength::Strong:
                return true;
            case ObservationStrength::None:
            default:
                return false;
            }
        }

        bool IsExcludedContributionDomain(EvidenceDomain domain)
        {
            return domain == EvidenceDomain::CollectionQuality ||
                domain == EvidenceDomain::EvidenceIntegrity;
        }

        bool HasNonWhitespace(const std::string& value)
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
                    case '\n':
                    case '\r':
                    case '\f':
                    case '\v':
                        return false;
                    default:
                        return true;
                    }
                });
        }

        std::string UnknownValidationIssueDisplayText(std::uint32_t value)
        {
            std::ostringstream stream;
            stream << "Unknown validation issue (0x"
                   << std::uppercase
                   << std::hex
                   << std::setw(8)
                   << std::setfill('0')
                   << value
                   << ')';
            return stream.str();
        }
    }

    std::string ObservationValidationIssueDisplayText(ObservationValidationIssue issue)
    {
        switch (issue)
        {
        case ObservationValidationIssue::None:
            return "None";
        case ObservationValidationIssue::IdTooLong:
            return "Observation ID exceeds its cap";
        case ObservationValidationIssue::RuleIdTooLong:
            return "Rule ID exceeds its cap";
        case ObservationValidationIssue::TitleTooLong:
            return "Title exceeds its cap";
        case ObservationValidationIssue::SummaryTooLong:
            return "Summary exceeds its cap";
        case ObservationValidationIssue::GroupingKeyTooLong:
            return "Grouping key exceeds its cap";
        case ObservationValidationIssue::CorrelationKeyTooLong:
            return "Correlation key exceeds its cap";
        case ObservationValidationIssue::SuppressionReasonTooLong:
            return "Suppression reason exceeds its cap";
        case ObservationValidationIssue::RawValueTooLong:
            return "Raw value exceeds its cap";
        case ObservationValidationIssue::NormalizedValueTooLong:
            return "Normalized value exceeds its cap";
        case ObservationValidationIssue::TooManyEvidenceItems:
            return "Evidence item count exceeds its cap";
        case ObservationValidationIssue::EvidenceItemTooLong:
            return "An evidence item exceeds its cap";
        case ObservationValidationIssue::TooManyLimitationItems:
            return "Limitation item count exceeds its cap";
        case ObservationValidationIssue::LimitationItemTooLong:
            return "A limitation item exceeds its cap";
        case ObservationValidationIssue::ProvenanceSourceIdentifierTooLong:
            return "Provenance source identifier exceeds its cap";
        case ObservationValidationIssue::ProvenanceCollectionMethodTooLong:
            return "Provenance collection method exceeds its cap";
        case ObservationValidationIssue::ProvenanceCollectionTimestampTooLong:
            return "Provenance collection timestamp exceeds its cap";
        case ObservationValidationIssue::ProvenanceRequiredPrivilegeTooLong:
            return "Provenance required privilege exceeds its cap";
        case ObservationValidationIssue::TooManyProvenanceLimitationItems:
            return "Provenance limitation item count exceeds its cap";
        case ObservationValidationIssue::ProvenanceLimitationItemTooLong:
            return "A provenance limitation item exceeds its cap";
        case ObservationValidationIssue::ProvenanceRawSourceReferenceTooLong:
            return "Provenance raw source reference exceeds its cap";
        case ObservationValidationIssue::SourceKindMismatch:
            return "Observation and provenance source kinds differ";
        case ObservationValidationIssue::VerdictContributionIncompatibleDisposition:
            return "Disposition cannot independently contribute to a verdict";
        case ObservationValidationIssue::VerdictContributionRequiresStrength:
            return "Verdict contribution requires explicit evidence strength";
        case ObservationValidationIssue::VerdictContributionRequiresKnownDomain:
            return "Verdict contribution requires a known evidence domain";
        case ObservationValidationIssue::VerdictContributionExcludedDomain:
            return "Evidence domain is excluded from suspicious-domain contribution";
        case ObservationValidationIssue::SuppressionReasonRequired:
            return "Suppressed observations require a reason";
        case ObservationValidationIssue::EntityScopeTooLong:
            return "Entity scope exceeds its cap";
        case ObservationValidationIssue::SuppressorIdTooLong:
            return "Suppressor ID exceeds its cap";
        case ObservationValidationIssue::ArtifactKindUnknown:
            return "Artifact kind is unknown";
        case ObservationValidationIssue::ArtifactIdentityIncomplete:
            return "Artifact identity is incomplete";
        case ObservationValidationIssue::ArtifactEntityScopeTooLong:
            return "Artifact entity scope exceeds its cap";
        case ObservationValidationIssue::ArtifactKeyTooLong:
            return "Artifact key exceeds its cap";
        case ObservationValidationIssue::ArtifactEntityScopeMismatch:
            return "Artifact entity scope differs from the observation scope";
        case ObservationValidationIssue::TooManyArtifactAttributes:
            return "Artifact attribute count exceeds its cap";
        case ObservationValidationIssue::ArtifactAttributeKeyRequired:
            return "Artifact attribute key is required";
        case ObservationValidationIssue::ArtifactAttributeKeyTooLong:
            return "An artifact attribute key exceeds its cap";
        case ObservationValidationIssue::ArtifactAttributeValueTooLong:
            return "An artifact attribute value exceeds its cap";
        case ObservationValidationIssue::ArtifactAttributeKeyDuplicate:
            return "Artifact attribute keys must be unique";
        case ObservationValidationIssue::ArtifactAttributesRequireIdentity:
            return "Artifact attributes require a complete artifact identity";
        default:
            return UnknownValidationIssueDisplayText(static_cast<std::uint32_t>(issue));
        }
    }

    bool ObservationValidationResult::IsValid() const
    {
        return valid;
    }

    bool ObservationValidationResult::HasIssue(ObservationValidationIssue issue) const
    {
        return std::find(issues.begin(), issues.end(), issue) != issues.end();
    }

    Observation NormalizeObservationPolicy(Observation observation)
    {
        const bool artifactContractValid = ArtifactContractIsValid(observation);
        if (!artifactContractValid)
        {
            observation.artifactIdentity = {};
            observation.artifactAttributes.clear();
            AddArtifactNormalizationLimitation(observation);
        }

        LimitString(observation.id, ObservationIdMaxCharacters);
        LimitString(observation.ruleId, ObservationRuleIdMaxCharacters);
        LimitString(observation.title, ObservationTitleMaxCharacters);
        LimitString(observation.summary, ObservationSummaryMaxCharacters);
        LimitString(observation.entityScope, ObservationEntityScopeMaxCharacters);
        LimitString(observation.groupingKey, ObservationGroupingKeyMaxCharacters);
        LimitString(observation.correlationKey, ObservationCorrelationKeyMaxCharacters);
        LimitString(observation.suppressorId, ObservationSuppressorIdMaxCharacters);
        LimitString(observation.suppressionReason, ObservationSuppressionReasonMaxCharacters);
        LimitString(observation.rawValue, ObservationRawValueMaxCharacters);
        LimitString(observation.normalizedValue, ObservationNormalizedValueMaxCharacters);

        LimitStringItems(
            observation.evidence,
            ObservationMaxEvidenceItems,
            ObservationEvidenceItemMaxCharacters);
        LimitStringItems(
            observation.limitations,
            ObservationMaxLimitationItems,
            ObservationLimitationItemMaxCharacters);

        LimitString(
            observation.provenance.sourceIdentifier,
            ObservationProvenanceSourceIdentifierMaxCharacters);
        LimitString(
            observation.provenance.collectionMethod,
            ObservationProvenanceCollectionMethodMaxCharacters);
        LimitString(
            observation.provenance.collectionTimestamp,
            ObservationProvenanceCollectionTimestampMaxCharacters);
        LimitString(
            observation.provenance.requiredPrivilege,
            ObservationProvenanceRequiredPrivilegeMaxCharacters);
        LimitStringItems(
            observation.provenance.limitations,
            ObservationMaxLimitationItems,
            ObservationLimitationItemMaxCharacters);
        LimitString(
            observation.provenance.rawSourceReference,
            ObservationProvenanceRawSourceReferenceMaxCharacters);

        if (!CanContributeToVerdict(observation))
        {
            observation.contributesToVerdict = false;
        }

        return observation;
    }

    ObservationValidationResult ValidateObservation(const Observation& observation)
    {
        ObservationValidationResult result;

        if (observation.id.size() > ObservationIdMaxCharacters)
        {
            AddValidationIssue(result, ObservationValidationIssue::IdTooLong);
        }
        if (observation.ruleId.size() > ObservationRuleIdMaxCharacters)
        {
            AddValidationIssue(result, ObservationValidationIssue::RuleIdTooLong);
        }
        if (observation.title.size() > ObservationTitleMaxCharacters)
        {
            AddValidationIssue(result, ObservationValidationIssue::TitleTooLong);
        }
        if (observation.summary.size() > ObservationSummaryMaxCharacters)
        {
            AddValidationIssue(result, ObservationValidationIssue::SummaryTooLong);
        }
        if (observation.entityScope.size() > ObservationEntityScopeMaxCharacters)
        {
            AddValidationIssue(result, ObservationValidationIssue::EntityScopeTooLong);
        }
        if (observation.groupingKey.size() > ObservationGroupingKeyMaxCharacters)
        {
            AddValidationIssue(result, ObservationValidationIssue::GroupingKeyTooLong);
        }
        if (observation.correlationKey.size() > ObservationCorrelationKeyMaxCharacters)
        {
            AddValidationIssue(result, ObservationValidationIssue::CorrelationKeyTooLong);
        }
        if (observation.suppressorId.size() > ObservationSuppressorIdMaxCharacters)
        {
            AddValidationIssue(result, ObservationValidationIssue::SuppressorIdTooLong);
        }
        if (observation.suppressionReason.size() > ObservationSuppressionReasonMaxCharacters)
        {
            AddValidationIssue(result, ObservationValidationIssue::SuppressionReasonTooLong);
        }
        if (observation.rawValue.size() > ObservationRawValueMaxCharacters)
        {
            AddValidationIssue(result, ObservationValidationIssue::RawValueTooLong);
        }
        if (observation.normalizedValue.size() > ObservationNormalizedValueMaxCharacters)
        {
            AddValidationIssue(result, ObservationValidationIssue::NormalizedValueTooLong);
        }

        const ObservationArtifactIdentity& artifact = observation.artifactIdentity;
        if (!IsKnownArtifactKind(artifact.kind))
        {
            AddValidationIssue(result, ObservationValidationIssue::ArtifactKindUnknown);
        }
        if (artifact.entityScope.size() >
            ObservationArtifactEntityScopeMaxCharacters)
        {
            AddValidationIssue(
                result,
                ObservationValidationIssue::ArtifactEntityScopeTooLong);
        }
        if (artifact.artifactKey.size() > ObservationArtifactKeyMaxCharacters)
        {
            AddValidationIssue(result, ObservationValidationIssue::ArtifactKeyTooLong);
        }
        if (artifact.kind == ObservationArtifactKind::None)
        {
            if (!artifact.entityScope.empty() || !artifact.artifactKey.empty())
            {
                AddValidationIssue(
                    result,
                    ObservationValidationIssue::ArtifactIdentityIncomplete);
            }
            if (!observation.artifactAttributes.empty())
            {
                AddValidationIssue(
                    result,
                    ObservationValidationIssue::ArtifactAttributesRequireIdentity);
            }
        }
        else
        {
            if (!HasCompleteObservationArtifactIdentity(artifact))
            {
                AddValidationIssue(
                    result,
                    ObservationValidationIssue::ArtifactIdentityIncomplete);
            }
            if (artifact.entityScope != observation.entityScope)
            {
                AddValidationIssue(
                    result,
                    ObservationValidationIssue::ArtifactEntityScopeMismatch);
            }
        }
        if (observation.artifactAttributes.size() >
            ObservationMaxArtifactAttributes)
        {
            AddValidationIssue(
                result,
                ObservationValidationIssue::TooManyArtifactAttributes);
        }
        std::set<std::string> artifactAttributeKeys;
        for (const ObservationArtifactAttribute& attribute :
             observation.artifactAttributes)
        {
            if (attribute.key.empty())
            {
                AddValidationIssue(
                    result,
                    ObservationValidationIssue::ArtifactAttributeKeyRequired);
            }
            if (attribute.key.size() >
                ObservationArtifactAttributeKeyMaxCharacters)
            {
                AddValidationIssue(
                    result,
                    ObservationValidationIssue::ArtifactAttributeKeyTooLong);
            }
            if (attribute.value.size() >
                ObservationArtifactAttributeValueMaxCharacters)
            {
                AddValidationIssue(
                    result,
                    ObservationValidationIssue::ArtifactAttributeValueTooLong);
            }
            if (!attribute.key.empty() &&
                !artifactAttributeKeys.insert(attribute.key).second)
            {
                AddValidationIssue(
                    result,
                    ObservationValidationIssue::ArtifactAttributeKeyDuplicate);
            }
        }

        if (observation.evidence.size() > ObservationMaxEvidenceItems)
        {
            AddValidationIssue(result, ObservationValidationIssue::TooManyEvidenceItems);
        }
        if (AnyStringTooLong(observation.evidence, ObservationEvidenceItemMaxCharacters))
        {
            AddValidationIssue(result, ObservationValidationIssue::EvidenceItemTooLong);
        }
        if (observation.limitations.size() > ObservationMaxLimitationItems)
        {
            AddValidationIssue(result, ObservationValidationIssue::TooManyLimitationItems);
        }
        if (AnyStringTooLong(observation.limitations, ObservationLimitationItemMaxCharacters))
        {
            AddValidationIssue(result, ObservationValidationIssue::LimitationItemTooLong);
        }

        if (observation.provenance.sourceIdentifier.size() >
            ObservationProvenanceSourceIdentifierMaxCharacters)
        {
            AddValidationIssue(
                result,
                ObservationValidationIssue::ProvenanceSourceIdentifierTooLong);
        }
        if (observation.provenance.collectionMethod.size() >
            ObservationProvenanceCollectionMethodMaxCharacters)
        {
            AddValidationIssue(
                result,
                ObservationValidationIssue::ProvenanceCollectionMethodTooLong);
        }
        if (observation.provenance.collectionTimestamp.size() >
            ObservationProvenanceCollectionTimestampMaxCharacters)
        {
            AddValidationIssue(
                result,
                ObservationValidationIssue::ProvenanceCollectionTimestampTooLong);
        }
        if (observation.provenance.requiredPrivilege.size() >
            ObservationProvenanceRequiredPrivilegeMaxCharacters)
        {
            AddValidationIssue(
                result,
                ObservationValidationIssue::ProvenanceRequiredPrivilegeTooLong);
        }
        if (observation.provenance.limitations.size() > ObservationMaxLimitationItems)
        {
            AddValidationIssue(
                result,
                ObservationValidationIssue::TooManyProvenanceLimitationItems);
        }
        if (AnyStringTooLong(
                observation.provenance.limitations,
                ObservationLimitationItemMaxCharacters))
        {
            AddValidationIssue(
                result,
                ObservationValidationIssue::ProvenanceLimitationItemTooLong);
        }
        if (observation.provenance.rawSourceReference.size() >
            ObservationProvenanceRawSourceReferenceMaxCharacters)
        {
            AddValidationIssue(
                result,
                ObservationValidationIssue::ProvenanceRawSourceReferenceTooLong);
        }

        if (observation.sourceKind != observation.provenance.sourceKind)
        {
            AddValidationIssue(result, ObservationValidationIssue::SourceKindMismatch);
        }

        if (observation.disposition == ObservationDisposition::SuppressedExpected &&
            !HasNonWhitespace(observation.suppressionReason))
        {
            AddValidationIssue(result, ObservationValidationIssue::SuppressionReasonRequired);
        }

        if (observation.contributesToVerdict)
        {
            if (observation.disposition != ObservationDisposition::ReviewRelevant)
            {
                AddValidationIssue(
                    result,
                    ObservationValidationIssue::VerdictContributionIncompatibleDisposition);
            }
            if (!IsContributingStrength(observation.strength))
            {
                AddValidationIssue(
                    result,
                    ObservationValidationIssue::VerdictContributionRequiresStrength);
            }
            if (!IsKnownEvidenceDomain(observation.domain) ||
                observation.domain == EvidenceDomain::Unknown)
            {
                AddValidationIssue(
                    result,
                    ObservationValidationIssue::VerdictContributionRequiresKnownDomain);
            }
            else if (IsExcludedContributionDomain(observation.domain))
            {
                AddValidationIssue(
                    result,
                    ObservationValidationIssue::VerdictContributionExcludedDomain);
            }
        }

        return result;
    }

    bool CanContributeToVerdict(const Observation& observation)
    {
        return observation.contributesToVerdict &&
            observation.disposition == ObservationDisposition::ReviewRelevant &&
            IsContributingStrength(observation.strength) &&
            IsKnownEvidenceDomain(observation.domain) &&
            observation.domain != EvidenceDomain::Unknown &&
            !IsExcludedContributionDomain(observation.domain);
    }

    ObservationDomainSummary SummarizeObservationDomains(
        const std::vector<Observation>& observations)
    {
        ObservationDomainSummary summary;
        for (const Observation& observation : observations)
        {
            if (observation.domain == EvidenceDomain::CollectionQuality)
            {
                ++summary.collectionQualityObservationCount;
            }
            else if (observation.domain == EvidenceDomain::EvidenceIntegrity)
            {
                ++summary.evidenceIntegrityObservationCount;
            }

            if (CanContributeToVerdict(observation))
            {
                summary.contributingDomains.insert(observation.domain);
            }
        }
        return summary;
    }

    std::set<EvidenceDomain> CollectContributingDomains(
        const std::vector<Observation>& observations)
    {
        return SummarizeObservationDomains(observations).contributingDomains;
    }

    bool ObservationGroupingResult::HasDuplicateIds() const
    {
        return !duplicateIds.empty();
    }

    bool ObservationGroupingResult::Succeeded() const
    {
        return status == ObservationGroupingStatus::Success;
    }

    ObservationGroupingResult GroupObservations(
        const std::vector<Observation>& observations)
    {
        ObservationGroupingResult result;
        if (observations.size() > ObservationGroupingMaxSourceObservations)
        {
            result.status = ObservationGroupingStatus::InputLimitExceeded;
            return result;
        }

        const bool identityFieldLimitExceeded = std::any_of(
            observations.begin(),
            observations.end(),
            [](const Observation& observation)
            {
                return observation.id.size() > ObservationIdMaxCharacters ||
                    observation.entityScope.size() > ObservationEntityScopeMaxCharacters ||
                    observation.groupingKey.size() > ObservationGroupingKeyMaxCharacters;
            });
        if (identityFieldLimitExceeded)
        {
            result.status = ObservationGroupingStatus::IdentityFieldLimitExceeded;
            return result;
        }

        using ScopedGroupingKey = std::pair<std::string, std::string>;
        std::map<ScopedGroupingKey, std::size_t> groupIndexByKey;
        std::set<std::string> observedIds;
        std::set<std::string> duplicateIds;

        result.groups.reserve(observations.size());
        for (const Observation& sourceObservation : observations)
        {
            Observation observation = NormalizeObservationPolicy(sourceObservation);

            if (!observation.id.empty())
            {
                const bool firstOccurrence = observedIds.insert(observation.id).second;
                if (!firstOccurrence)
                {
                    duplicateIds.insert(observation.id);
                }
            }

            if (observation.entityScope.empty() || observation.groupingKey.empty())
            {
                ObservationGroup group;
                group.entityScope = observation.entityScope;
                group.groupingKey = observation.groupingKey;
                group.sourceObservations.push_back(std::move(observation));
                result.groups.push_back(std::move(group));
                continue;
            }

            const ScopedGroupingKey scopedGroupingKey{
                observation.entityScope,
                observation.groupingKey
            };
            const auto existingGroup = groupIndexByKey.find(scopedGroupingKey);
            if (existingGroup != groupIndexByKey.end())
            {
                result.groups[existingGroup->second].sourceObservations.push_back(
                    std::move(observation));
                continue;
            }

            ObservationGroup group;
            group.entityScope = observation.entityScope;
            group.groupingKey = observation.groupingKey;
            group.sourceObservations.push_back(std::move(observation));
            const std::size_t groupIndex = result.groups.size();
            result.groups.push_back(std::move(group));
            groupIndexByKey.emplace(scopedGroupingKey, groupIndex);
        }

        result.duplicateIds.assign(duplicateIds.begin(), duplicateIds.end());
        return result;
    }

    ObservationSuppression NormalizeObservationSuppression(
        ObservationSuppression suppression)
    {
        LimitString(suppression.suppressorId, ObservationSuppressorIdMaxCharacters);
        LimitString(suppression.reason, ObservationSuppressionReasonMaxCharacters);
        return suppression;
    }

    bool IsValidObservationSuppression(const ObservationSuppression& suppression)
    {
        return suppression.suppressorId.size() <= ObservationSuppressorIdMaxCharacters &&
            suppression.reason.size() <= ObservationSuppressionReasonMaxCharacters &&
            HasNonWhitespace(suppression.reason) &&
            suppression.resultingDisposition == ObservationDisposition::SuppressedExpected;
    }

    Observation ApplySuppression(
        Observation observation,
        const ObservationSuppression& suppression)
    {
        if (!IsValidObservationSuppression(suppression))
        {
            return observation;
        }

        observation.disposition = suppression.resultingDisposition;
        observation.contributesToVerdict = false;
        observation.suppressorId = suppression.suppressorId;
        observation.suppressionReason = suppression.reason;
        return observation;
    }
}
