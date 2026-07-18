#pragma once

#include "ObservationCorrelation.h"

#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace GlassPane::Core
{
    constexpr std::size_t TriageMaxObservationReferences =
        ObservationRefinementMaxSourceObservations;
    constexpr std::size_t TriageMaxCorrelationReferences =
        ObservationCorrelationMaxResults;
    constexpr std::size_t TriageMaxUnresolvedCorrelationKeys =
        ObservationCorrelationMaxUnresolvedPreparations;
    constexpr std::size_t TriageMaxRationaleItems = 512;
    constexpr std::size_t TriageMaxRationaleEntries =
        TriageMaxRationaleItems;
    constexpr std::size_t TriageMaxLimitationItems = 512;
    constexpr std::size_t TriageRationaleItemMaxCharacters = 1024;
    constexpr std::size_t TriageLimitationItemMaxCharacters = 1024;
    constexpr std::size_t TriageStatusMessageMaxCharacters = 1024;

    enum class TriageVerdict : std::uint32_t
    {
        Informational = 0,
        LowAttention = 1,
        MediumAttention = 2,
        HighAttention = 3
    };

    std::string TriageVerdictDisplayText(TriageVerdict verdict);

    enum class TriageEngineStatus : std::uint32_t
    {
        NotAttempted = 0,
        Success = 1,
        RefinementUnavailable = 2,
        CorrelationUnavailable = 3,
        InputLimitExceeded = 4,
        InvalidInput = 5,
        OutputLimitExceeded = 6,
        InternalPolicyFailure = 7
    };

    std::string TriageEngineStatusDisplayText(TriageEngineStatus status);

    // Presentation metadata for Core-generated rationale. The flattened
    // rationale list remains available for compatibility; this typed view lets
    // callers present the same lines without parsing display text or
    // reconstructing verdict reasoning.
    enum class TriageRationaleSection : std::uint32_t
    {
        VerdictBasis = 0,
        CompletedCorrelations = 1,
        SupportingContext = 2,
        CollectionLimitations = 3,
        EvidenceIntegrityContext = 4,
        UnresolvedCorrelations = 5,
        // Bounded rendering/omission notices. These are presentation metadata,
        // never evidence supporting the triage verdict.
        PresentationNotes = 6
    };

    std::string TriageRationaleSectionDisplayText(
        TriageRationaleSection section);

    struct TriageRationaleEntry
    {
        TriageRationaleSection section =
            TriageRationaleSection::VerdictBasis;
        std::string text;
    };

    struct TriageResult
    {
        bool attempted = false;
        bool success = false;
        TriageEngineStatus status = TriageEngineStatus::NotAttempted;
        TriageVerdict verdict = TriageVerdict::Informational;

        std::vector<std::string> contributingObservationIds;
        std::vector<std::string> contributingCorrelationIds;
        std::set<EvidenceDomain> contributingDomains;

        std::vector<std::string> contextObservationIds;
        std::vector<std::string> collectionNoteIds;
        std::vector<std::string> evidenceIntegrityNoteIds;
        std::vector<std::string> unresolvedCorrelationKeys;

        // Explicit policy diagnostics. Correlation significance describes the
        // typed relationship itself; these fields record the separate verdict
        // gates applied by TriageEngine.
        std::size_t maximumContributingCorrelationDomainCount = 0;
        std::size_t sameDomainContributingCorrelationCount = 0;
        bool sameDomainVerdictCeilingApplied = false;
        bool qualifiedStandaloneStrongHighGateSatisfied = false;
        bool coherentMultiDomainHighGateSatisfied = false;

        // Deterministic, bounded lines. They describe the source basis and do
        // not expose vector indexes, raw values, or a numerical score.
        std::vector<std::string> rationale;
        // One-to-one typed presentation view of rationale. Entry text and
        // ordering are identical to the flattened compatibility list.
        std::vector<TriageRationaleEntry> rationaleEntries;
        // Compact, ID-free Core rationale for normal presentation and copy.
        // Deep diagnostics continue to use rationaleEntries above.
        std::vector<TriageRationaleEntry> previewRationaleEntries;
        std::vector<std::string> limitations;
        bool rationaleTruncated = false;
        bool previewRationaleTruncated = false;
        bool limitationsTruncated = false;

        std::string statusMessage;
        // Subset of triageDurationMicroseconds spent assembling bounded
        // detailed and compact rationale presentation data.
        std::uint64_t rationaleAggregationDurationMicroseconds = 0;
        std::uint64_t triageDurationMicroseconds = 0;

        bool Succeeded() const;
    };

    // Builds the authoritative typed verdict from immutable refined observations and
    // completed typed correlations. Legacy FindingSeverity is intentionally not
    // an input. Context, collection notes, integrity notes, duplicates,
    // suppressions, and unresolved CorrelatedOnly records cannot elevate it.
    //
    // A standalone Strong observation reaches High Attention only when it has
    // High confidence, Direct/Corroborated provenance, and an explicit producer
    // assessment rationale. Coherent multi-domain High Attention requires a
    // completed Moderate-or-Strong typed correlation whose participants include
    // at least two independent Moderate-or-Strong direct ReviewRelevant domains
    // and meet availability, confidence, and provenance gates. Participants
    // that are merely Weak, Context, or CorrelatedOnly do not satisfy that
    // gate. A Strong
    // correlation confined to one domain retains its Strong label but has a
    // Medium Attention verdict ceiling.
    TriageResult BuildTriageResult(
        const ObservationRefinementResult& refinement,
        const ObservationCorrelationResult& correlations);
}
