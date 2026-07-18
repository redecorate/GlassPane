#pragma once

#include "ObservationRefinement.h"

#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace GlassPane::Core
{
    constexpr std::size_t ObservationCorrelationMaxResults = 1024;
    constexpr std::size_t ObservationCorrelationMaxParticipantsPerResult = 64;
    constexpr std::size_t ObservationCorrelationMaxSupportingPerResult = 64;
    constexpr std::size_t ObservationCorrelationMaxParticipantReferences = 4096;
    constexpr std::size_t ObservationCorrelationMaxSupportingReferences = 4096;
    constexpr std::size_t ObservationCorrelationMaxRequirementsPerPreparation = 2;
    constexpr std::size_t ObservationCorrelationMaxDomainsPerRequirement = 17;
    constexpr std::size_t ObservationCorrelationMaxLimitations =
        ObservationMaxLimitationItems;
    constexpr std::size_t ObservationCorrelationMaxUnresolvedPreparations =
        ObservationRefinementMaxCorrelations;
    constexpr std::size_t ObservationCorrelationMaxWarnings = 128;
    constexpr std::size_t ObservationCorrelationWarningMaxCharacters = 1024;
    constexpr std::size_t ObservationCorrelationRationaleMaxCharacters = 1024;

    enum class CorrelationSignificance : std::uint32_t
    {
        Informational = 0,
        Weak = 1,
        Moderate = 2,
        Strong = 3
    };

    // Significance describes the density and quality of the typed correlation,
    // not its final triage verdict. TriageEngine applies separate domain-
    // independence, provenance, and confidence gates; a Strong same-domain
    // correlation therefore need not produce High Attention.

    std::string CorrelationSignificanceDisplayText(
        CorrelationSignificance significance);

    enum class ObservationCorrelationStatus : std::uint32_t
    {
        NotAttempted = 0,
        Success = 1,
        RefinementUnavailable = 2,
        InvalidRefinement = 3,
        ResultLimitExceeded = 4,
        ParticipantLimitExceeded = 5,
        SupportingLimitExceeded = 6,
        UnresolvedLimitExceeded = 7,
        InternalPolicyFailure = 8
    };

    std::string ObservationCorrelationStatusDisplayText(
        ObservationCorrelationStatus status);

    struct ObservationCorrelation
    {
        std::string id;
        std::string ruleId;
        std::string entityScope;
        std::string correlationKey;
        std::string title;
        std::string rationale;

        CorrelationSignificance significance =
            CorrelationSignificance::Informational;
        ObservationConfidence confidence = ObservationConfidence::Unknown;

        std::vector<std::string> participatingObservationIds;
        std::set<EvidenceDomain> participatingDomains;
        std::vector<std::string> supportingObservationIds;
        std::vector<std::string> limitations;

        bool contributesToVerdict = false;
    };

    struct ObservationCorrelationSummary
    {
        std::size_t preparedCorrelationCount = 0;
        std::size_t activatedCorrelationCount = 0;
        std::size_t contributingCorrelationCount = 0;
        std::size_t unresolvedCorrelationCount = 0;
        std::size_t duplicateCorrelationCount = 0;
        std::uint64_t correlationDurationMicroseconds = 0;
    };

    struct ObservationCorrelationResult
    {
        bool attempted = false;
        bool success = false;
        ObservationCorrelationStatus status =
            ObservationCorrelationStatus::NotAttempted;

        std::vector<ObservationCorrelation> correlations;
        std::vector<ObservationCorrelationPreparation> unresolvedPreparations;

        ObservationCorrelationSummary summary;
        bool warningsTruncated = false;
        std::vector<std::string> warnings;

        bool Succeeded() const;
    };

    // Activates only complete, typed preparation contracts emitted by native producers.
    // The refined observations are read-only inputs; CorrelatedOnly records are
    // referenced by activated correlations but are never mutated or promoted.
    ObservationCorrelationResult ActivateObservationCorrelations(
        const ObservationRefinementResult& refinement);
}
