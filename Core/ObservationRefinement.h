#pragma once

#include "ObservationInventory.h"
#include "ObservationPolicy.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace GlassPane::Core
{
    constexpr std::size_t ObservationRefinementMaxSourceObservations =
        ObservationInventoryMaxObservations;
    constexpr std::size_t ObservationRefinementMaxGroups =
        ObservationInventoryMaxObservations;
    constexpr std::size_t ObservationRefinementMaxCorrelations =
        ObservationInventoryMaxObservations;
    constexpr std::size_t ObservationRefinementMaxCorrelationSourceIds =
        ObservationInventoryMaxObservations;
    constexpr std::size_t ObservationRefinementMaxWarnings = 128;
    constexpr std::size_t ObservationRefinementWarningMaxCharacters = 1024;
    constexpr std::size_t ObservationSemanticFingerprintMaxCharacters = 128;

    enum class ObservationRefinementStatus : std::uint32_t
    {
        NotAttempted = 0,
        Success = 1,
        RawInventoryUnavailable = 2,
        SourceLimitExceeded = 3,
        InvalidSourceObservation = 4,
        GroupLimitExceeded = 5,
        CorrelationLimitExceeded = 6,
        CorrelationReferenceLimitExceeded = 7,
        InternalPolicyFailure = 8
    };

    std::string ObservationRefinementStatusDisplayText(
        ObservationRefinementStatus status);

    enum class RefinedObservationRole : std::uint32_t
    {
        Primary = 0,
        Supporting = 1,
        ArtifactAttribute = 2,
        Duplicate = 3
    };

    struct RefinedObservationMember
    {
        // The original native record remains unchanged and fully auditable.
        // Suppression is stored as a reversible policy delta.
        ObservationRecord sourceRecord;
        RefinedObservationRole role = RefinedObservationRole::Primary;
        std::string semanticFingerprint;
        std::string primaryObservationId;
        bool suppressed = false;
        ObservationSuppression suppression;
    };

    struct RefinedObservationGroup
    {
        std::string entityScope;
        std::string groupingKey;
        std::string semanticFamily;
        EvidenceDomain domain = EvidenceDomain::Unknown;
        ObservationArtifactIdentity artifactIdentity;
        std::size_t artifactAttributeCount = 0;
        std::vector<RefinedObservationMember> members;
    };

    struct ObservationDomainArtifactCount
    {
        EvidenceDomain domain = EvidenceDomain::Unknown;
        std::size_t distinctArtifactCount = 0;
    };

    enum class CorrelationDomainRequirementMode : std::uint32_t
    {
        AllOf = 0,
        AnyOf = 1
    };

    struct CorrelationDomainRequirement
    {
        CorrelationDomainRequirementMode mode =
            CorrelationDomainRequirementMode::AllOf;
        std::vector<EvidenceDomain> domains;
    };

    struct ObservationCorrelationPreparation
    {
        std::string entityScope;
        std::string correlationKey;
        bool requirementsKnown = false;
        std::vector<CorrelationDomainRequirement> requirements;
        std::vector<EvidenceDomain> availableSupportingDomains;
        bool containsCorrelatedOnly = false;
        bool incomplete = true;

        // Stable identities are retained instead of internal vector indexes.
        std::vector<std::string> sourceObservationIds;
    };

    struct ObservationRefinementSummary
    {
        // Native source-fact accounting remains distinct from observation and
        // artifact counts so producer omissions and duplicate reconciliation
        // remain auditable without legacy Finding coverage metadata.
        std::size_t typedSourceFactCount = 0;
        std::size_t declaredSourceFactCount = 0;
        std::size_t typedSourceFactDuplicateCount = 0;
        std::size_t rawObservationCount = 0;
        std::size_t behavioralContextObservationCount = 0;
        std::size_t collectionNoteCount = 0;
        std::size_t evidenceIntegrityNoteCount = 0;
        std::size_t groupCount = 0;
        std::size_t artifactGroupCount = 0;
        std::size_t distinctArtifactCount = 0;
        std::size_t artifactAttributeCount = 0;
        std::vector<ObservationDomainArtifactCount>
            distinctArtifactCountsByDomain;
        std::size_t duplicateCount = 0;
        std::size_t suppressedCount = 0;
        std::size_t unresolvedCorrelatedOnlyCount = 0;
        std::size_t contributingDomainCountBefore = 0;
        std::size_t contributingDomainCountAfter = 0;
        std::size_t refinementWarningCount = 0;
        std::uint64_t refinementDurationMicroseconds = 0;
    };

    struct ObservationRefinementResult
    {
        bool attempted = false;
        bool success = false;
        ObservationRefinementStatus status =
            ObservationRefinementStatus::NotAttempted;

        std::vector<RefinedObservationGroup> groups;
        std::vector<ObservationRecord> collectionNotes;
        std::vector<ObservationRecord> evidenceIntegrityNotes;
        std::vector<ObservationCorrelationPreparation> correlations;

        ObservationRefinementSummary summary;
        bool warningsTruncated = false;
        std::vector<std::string> warnings;

        bool Succeeded() const;
    };

    // Returns the original observation or a suppressed value copy. The source
    // record and its provenance are never modified.
    Observation EffectiveObservation(const RefinedObservationMember& member);

    // Pure, deterministic shadow refinement. Any invalid input or output-cap
    // violation fails atomically without returning partial groups or note sets.
    ObservationRefinementResult RefineObservationInventory(
        const ObservationInventory& inventory);
}
