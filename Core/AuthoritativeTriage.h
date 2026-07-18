#pragma once

#include "ObservationShadow.h"
#include "PersistedTriage.h"
#include "ProcessTriageCache.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace GlassPane::Core
{
    constexpr std::size_t AuthoritativeTriageUnavailableReasonMaxCharacters = 512;
    constexpr std::size_t AuthoritativeTriageSummaryMaxCharacters = 32768;

    // Canonical availability categories are shared by process-wide baseline,
    // selected-process enriched, and persisted-authority selectors.
    enum class TriageAvailabilityCategory : std::uint32_t
    {
        None = 0,
        EntityUnavailable = 1,
        EngineNotAttempted = 2,
        EntityOrGenerationMismatch = 3,
        ScopeMismatch = 4,
        ResultMissing = 5,
        EvaluationFailed = 6,
        InputTruncated = 7,
        SourceMismatch = 8,
        MaterialEvidenceIncomplete = 9,
        InvalidResult = 10,
        NotCaptured = 11,
        CapturedLegacyFallback = 12
    };

    enum class TriageAvailabilityDisclosure : std::uint32_t
    {
        None = 0,
        NoCurrentEntity = 1,
        LegacyTriageShown = 2,
        TriageNotCaptured = 3,
        TriageUnavailable = 4
    };

    enum class TriageAvailabilityDisposition : std::uint32_t
    {
        None = 0,
        Avoidable = 1,
        Expected = 2,
        HistoricalCompatibilityOnly = 3
    };

    std::string TriageAvailabilityCategoryDisplayText(
        TriageAvailabilityCategory category);
    std::string TriageAvailabilityDisclosureText(
        TriageAvailabilityDisclosure disclosure);
    TriageAvailabilityDisposition ClassifyTriageAvailability(
        TriageAvailabilityCategory category);
    std::string TriageAvailabilityDispositionDisplayText(
        TriageAvailabilityDisposition disposition);

    struct TriageAvailabilityDescriptor
    {
        TriageAvailabilityCategory category = TriageAvailabilityCategory::None;
        TriageAvailabilityDisclosure disclosure = TriageAvailabilityDisclosure::None;
        std::string diagnostic;

        bool Active() const;
    };

    // Produces concise normal-presentation wording from the typed category.
    // The bounded technical diagnostic remains available to Debug views.
    std::string TriageAvailabilityUserMessage(
        const TriageAvailabilityDescriptor& availability);

    enum class ProcessTriageUnavailableKind : std::uint32_t
    {
        None = 0,
        CacheNotAttempted = 1,
        CacheGenerationMismatch = 2,
        BaselineEntryMissing = 3,
        ProcessIdentityMismatch = 4,
        BaselineEvaluationUnavailable = 5,
        BaselineInputTruncated = 6,
        InvalidVerdict = 7
    };

    std::string ProcessTriageUnavailableKindDisplayText(
        ProcessTriageUnavailableKind kind);
    TriageAvailabilityCategory CanonicalTriageUnavailableCategory(
        ProcessTriageUnavailableKind kind);

    // One value is shared by list filtering/counting, header metrics, graph
    // styling, and timeline classification. Informational is deliberately
    // neutral rather than the legacy informational-severity presentation.
    struct TriageSurfaceClassification
    {
        Severity severity = Severity::None;
        bool suspicious = false;
    };

    TriageSurfaceClassification ClassifyTriageVerdictForSurfaces(
        TriageVerdict verdict);

    // A non-owning view over one exact current cache entry. A failed or stale
    // native baseline is explicitly unavailable; legacy severity is never read.
    struct ProcessTriageAuthority
    {
        TriageVerdict verdict = TriageVerdict::Informational;
        bool unavailable = true;
        bool baselineAvailable = false;
        ProcessTriageUnavailableKind unavailableKind =
            ProcessTriageUnavailableKind::CacheNotAttempted;
        std::string unavailableReason;
        TriageAvailabilityDescriptor unavailability;
        const CachedBaselineTriage* baseline = nullptr;

        bool UsesBaselineTriage() const;
    };

    ProcessTriageAuthority SelectNativeProcessTriageAuthority(
        const ProcessTriageCache& cache,
        const ProcessInfo& process,
        const ProcessTriageCacheSourceStamp& expectedSourceStamp);

    enum class AuthoritativeTriageUnavailableKind : std::uint32_t
    {
        None = 0,
        NoCurrentEntity = 1,
        EngineNotAttempted = 2,
        EntityOrGenerationMismatch = 3,
        EntityScopeMismatch = 4,
        NativeObservationBuildUnavailable = 5,
        RefinementUnavailable = 6,
        CorrelationUnavailable = 7,
        TriageUnavailable = 8,
        SourceEvidenceMismatch = 9,
        MaterialEvidenceIncomplete = 10,
        InvalidVerdict = 11
    };

    std::string AuthoritativeTriageUnavailableKindDisplayText(
        AuthoritativeTriageUnavailableKind kind);
    TriageAvailabilityCategory CanonicalTriageUnavailableCategory(
        AuthoritativeTriageUnavailableKind kind);

    // A non-owning view over caller-owned current state. The selector never
    // evaluates observations and never mutates either source. Pointers are
    // exposed only after exact current-entity/generation validation.
    struct AuthoritativeTriageView
    {
        TriageVerdict verdict = TriageVerdict::Informational;
        bool unavailable = true;
        AuthoritativeTriageUnavailableKind unavailableKind =
            AuthoritativeTriageUnavailableKind::EngineNotAttempted;
        std::string unavailableReason;
        TriageAvailabilityDescriptor unavailability;
        std::size_t sourceEvidenceCount = 0;

        const TriageResult* triageResult = nullptr;

        bool UsesTriageEngine() const;
    };

    enum class SelectedTriageAnalysisLevel : std::uint32_t
    {
        NotCaptured = 0,
        LegacyFallback = 1,
        Baseline = 2,
        Enriched = 3,
        Unavailable = 4
    };

    std::string SelectedTriageAnalysisLevelDisplayText(
        SelectedTriageAnalysisLevel level);

    // Historical compatibility view. Current live analysis uses the native
    // selector below and never reaches this legacy-fallback path.
    struct SelectedProcessTriageAuthority
    {
        TriageVerdict verdict = TriageVerdict::Informational;
        TriageVerdict baselineVerdict = TriageVerdict::Informational;
        SelectedTriageAnalysisLevel analysisLevel =
            SelectedTriageAnalysisLevel::Unavailable;
        bool historicalFallbackCaptured = false;
        bool baselineAvailable = false;
        bool enrichedAvailable = false;
        std::size_t sourceEvidenceCount = 0;
        std::string availabilityReason;
        TriageAvailabilityDescriptor availability;
        const TriageResult* triageResult = nullptr;
        const TriageResult* baselineTriageResult = nullptr;
        const CachedBaselineTriage* baseline = nullptr;
        const PersistedTriageSummary* persistedSummary = nullptr;
        bool notCaptured = false;
        bool unavailable = false;

        bool UsesEnrichedTriage() const;
        bool UsesBaselineTriage() const;
    };

    Severity TriageVerdictToSeverity(TriageVerdict verdict);
    bool IsSuspiciousTriageVerdict(TriageVerdict verdict);

    // Selects TriageEngine only when all stages describe the exact current
    // entity/evidence generation and verdict-material source coverage is
    // sufficient. Audit-only bounded detail never makes authority unavailable.

    // Current native analysis never consults Finding or legacy severity. A
    // failed native result is returned as explicitly unavailable so callers
    // can keep the entity neutral without silently treating it as clean.
    AuthoritativeTriageView SelectNativeAuthoritativeTriage(
        const ObservationShadowState& shadow,
        bool hasEntity,
        std::uint32_t selectedPid,
        std::uint64_t entityCreationTime,
        std::uint64_t sourceGeneration,
        const std::string& expectedEntityScope);


    // Current selected-process precedence: enriched native result, baseline
    // native result, then an explicit unavailable state. There is no legacy
    // verdict fallback in this selector.
    SelectedProcessTriageAuthority SelectNativeSelectedProcessTriageAuthority(
        const ObservationShadowState& shadow,
        bool hasEntity,
        const ProcessInfo& selectedProcess,
        std::uint64_t sourceGeneration,
        const std::string& expectedEntityScope,
        const ProcessTriageCache& baselineCache,
        const ProcessTriageCacheSourceStamp& expectedBaselineSourceStamp);

    // Saved-snapshot authority is selected only from the value-owned captured
    // schema-4/schema-5 contract. Missing records (schemas 1-3) remain
    // explicitly not captured and are never recomputed with current policy.

    // Selects only value-owned captured authority. Missing older-schema data
    // remains NotCaptured; invalid current data is explicitly Unavailable.
    // Historical Finding metadata is never consulted by this selector.
    SelectedProcessTriageAuthority SelectCapturedSelectedProcessTriageAuthority(
        const PersistedTriageContext& context,
        bool hasEntity,
        const ProcessInfo& selectedProcess);

    // Pure, bounded normal-presentation text used by Copy Triage Summary.
    // It consumes only ID-free Core preview rationale and never emits internal
    // observation/correlation IDs, artifact keys, or raw evidence values.

    std::string FormatSelectedProcessTriageSummary(
        const SelectedProcessTriageAuthority& authority,
        const std::string& processName,
        std::uint32_t pid);
}
