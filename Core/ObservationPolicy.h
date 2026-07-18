#pragma once

#include "Observation.h"

#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace GlassPane::Core
{
    enum class ObservationValidationIssue : std::uint32_t
    {
        None = 0,
        IdTooLong = 1,
        RuleIdTooLong = 2,
        TitleTooLong = 3,
        SummaryTooLong = 4,
        GroupingKeyTooLong = 5,
        CorrelationKeyTooLong = 6,
        SuppressionReasonTooLong = 7,
        RawValueTooLong = 8,
        NormalizedValueTooLong = 9,
        TooManyEvidenceItems = 10,
        EvidenceItemTooLong = 11,
        TooManyLimitationItems = 12,
        LimitationItemTooLong = 13,
        ProvenanceSourceIdentifierTooLong = 14,
        ProvenanceCollectionMethodTooLong = 15,
        ProvenanceCollectionTimestampTooLong = 16,
        ProvenanceRequiredPrivilegeTooLong = 17,
        TooManyProvenanceLimitationItems = 18,
        ProvenanceLimitationItemTooLong = 19,
        ProvenanceRawSourceReferenceTooLong = 20,
        SourceKindMismatch = 21,
        VerdictContributionIncompatibleDisposition = 22,
        VerdictContributionRequiresStrength = 23,
        VerdictContributionRequiresKnownDomain = 24,
        VerdictContributionExcludedDomain = 25,
        SuppressionReasonRequired = 26,
        EntityScopeTooLong = 27,
        SuppressorIdTooLong = 28,
        ArtifactKindUnknown = 29,
        ArtifactIdentityIncomplete = 30,
        ArtifactEntityScopeTooLong = 31,
        ArtifactKeyTooLong = 32,
        ArtifactEntityScopeMismatch = 33,
        TooManyArtifactAttributes = 34,
        ArtifactAttributeKeyRequired = 35,
        ArtifactAttributeKeyTooLong = 36,
        ArtifactAttributeValueTooLong = 37,
        ArtifactAttributeKeyDuplicate = 38,
        ArtifactAttributesRequireIdentity = 39
    };

    std::string ObservationValidationIssueDisplayText(ObservationValidationIssue issue);

    struct ObservationValidationResult
    {
        bool valid = true;
        std::vector<ObservationValidationIssue> issues;

        bool IsValid() const;
        bool HasIssue(ObservationValidationIssue issue) const;
    };

    // Applies only bounded representation and explicit contribution invariants.
    // It does not infer confidence, strength, source trust, or a final verdict.
    Observation NormalizeObservationPolicy(Observation observation);
    ObservationValidationResult ValidateObservation(const Observation& observation);
    bool CanContributeToVerdict(const Observation& observation);

    struct ObservationDomainSummary
    {
        std::set<EvidenceDomain> contributingDomains;
        std::size_t collectionQualityObservationCount = 0;
        std::size_t evidenceIntegrityObservationCount = 0;
    };

    ObservationDomainSummary SummarizeObservationDomains(
        const std::vector<Observation>& observations);

    // Repeated observations in one domain produce one set entry. Collection
    // quality and evidence integrity are excluded from this set.
    std::set<EvidenceDomain> CollectContributingDomains(
        const std::vector<Observation>& observations);

    struct ObservationGroup
    {
        std::string entityScope;
        std::string groupingKey;
        std::vector<Observation> sourceObservations;
    };

    constexpr std::size_t ObservationGroupingMaxSourceObservations = 4096;

    enum class ObservationGroupingStatus : std::uint32_t
    {
        Success = 0,
        InputLimitExceeded = 1,
        IdentityFieldLimitExceeded = 2
    };

    struct ObservationGroupingResult
    {
        ObservationGroupingStatus status = ObservationGroupingStatus::Success;
        std::vector<ObservationGroup> groups;
        std::vector<std::string> duplicateIds;

        bool Succeeded() const;
        bool HasDuplicateIds() const;
    };

    // Each source observation is retained as a bounded, normalized value copy.
    // Only observations with the same nonempty entity scope and grouping key can
    // combine. Missing either value produces a separate group. Group order follows
    // first input occurrence. Over-cap input or identity fields are rejected
    // without a partial result, preventing truncation from merging distinct IDs,
    // scopes, or keys. No aggregate strength is calculated, and grouping has no
    // cross-call or global state.
    ObservationGroupingResult GroupObservations(
        const std::vector<Observation>& observations);

    struct ObservationSuppression
    {
        std::string suppressorId;
        std::string reason;
        ObservationDisposition resultingDisposition =
            ObservationDisposition::SuppressedExpected;
    };

    ObservationSuppression NormalizeObservationSuppression(
        ObservationSuppression suppression);
    bool IsValidObservationSuppression(const ObservationSuppression& suppression);

    // Invalid or over-cap suppression contracts leave the observation unchanged.
    // A valid suppression changes only disposition, contribution, suppressorId,
    // and suppressionReason.
    Observation ApplySuppression(
        Observation observation,
        const ObservationSuppression& suppression);
}
