#include "AuthoritativeTriage.h"

#include <algorithm>
#include <sstream>
#include <utility>

namespace GlassPane::Core
{
    namespace
    {
        std::string BoundedUtf8(std::string value, std::size_t maximumCharacters)
        {
            if (value.size() <= maximumCharacters)
            {
                return value;
            }

            std::size_t retained = maximumCharacters;
            while (retained > 0 && retained < value.size() &&
                (static_cast<unsigned char>(value[retained]) & 0xC0U) == 0x80U)
            {
                --retained;
            }
            value.resize(retained);
            return value;
        }

        TriageAvailabilityDescriptor MakeAvailabilityDescriptor(
            TriageAvailabilityCategory category,
            TriageAvailabilityDisclosure disclosure,
            std::string diagnostic)
        {
            TriageAvailabilityDescriptor result;
            result.category = category;
            result.disclosure = disclosure;
            result.diagnostic = BoundedUtf8(
                std::move(diagnostic),
                AuthoritativeTriageUnavailableReasonMaxCharacters);
            return result;
        }


        int AvailabilityCategoryPriority(TriageAvailabilityCategory category)
        {
            switch (category)
            {
            case TriageAvailabilityCategory::InvalidResult:
                return 12;
            case TriageAvailabilityCategory::MaterialEvidenceIncomplete:
                return 11;
            case TriageAvailabilityCategory::InputTruncated:
                return 10;
            case TriageAvailabilityCategory::SourceMismatch:
                return 9;
            case TriageAvailabilityCategory::ScopeMismatch:
                return 8;
            case TriageAvailabilityCategory::EntityOrGenerationMismatch:
                return 7;
            case TriageAvailabilityCategory::EvaluationFailed:
                return 6;
            case TriageAvailabilityCategory::ResultMissing:
                return 5;
            case TriageAvailabilityCategory::EngineNotAttempted:
                return 4;
            case TriageAvailabilityCategory::NotCaptured:
                return 3;
            case TriageAvailabilityCategory::CapturedLegacyFallback:
                return 2;
            case TriageAvailabilityCategory::EntityUnavailable:
                return 1;
            case TriageAvailabilityCategory::None:
            default:
                return 0;
            }
        }

        TriageAvailabilityCategory MoreMaterialUnavailableCategory(
            TriageAvailabilityCategory left,
            TriageAvailabilityCategory right)
        {
            return AvailabilityCategoryPriority(left) >=
                AvailabilityCategoryPriority(right)
                ? left
                : right;
        }

        bool IsKnownVerdict(TriageVerdict verdict)
        {
            switch (verdict)
            {
            case TriageVerdict::Informational:
            case TriageVerdict::LowAttention:
            case TriageVerdict::MediumAttention:
            case TriageVerdict::HighAttention:
                return true;
            default:
                return false;
            }
        }

        ProcessTriageAuthority MakeProcessUnavailable(
            const ProcessInfo& /*process*/,
            ProcessTriageUnavailableKind kind,
            std::string reason,
            const CachedBaselineTriage* baseline = nullptr)
        {
            ProcessTriageAuthority authority;
            // Native baseline failure is an unavailable state, not permission
            // to resurrect the retired finding-derived process severity.
            authority.verdict = TriageVerdict::Informational;
            authority.unavailable = true;
            authority.baselineAvailable = false;
            authority.unavailableKind = kind;
            authority.unavailability = MakeAvailabilityDescriptor(
                CanonicalTriageUnavailableCategory(kind),
                TriageAvailabilityDisclosure::TriageUnavailable,
                std::move(reason));
            authority.unavailableReason = authority.unavailability.diagnostic;
            authority.baseline = baseline;
            return authority;
        }

        bool CacheContainsPidWithDifferentIdentity(
            const ProcessTriageCache& cache,
            const ProcessIdentityKey& expectedIdentity)
        {
            const ProcessIdentityKey firstForPid{
                expectedIdentity.pid,
                false,
                0
            };
            const auto found = std::lower_bound(
                cache.entries.begin(),
                cache.entries.end(),
                firstForPid,
                [](const CachedBaselineTriage& entry,
                    const ProcessIdentityKey& identity)
                {
                    return entry.identity < identity;
                });
            return found != cache.entries.end() &&
                found->identity.pid == expectedIdentity.pid &&
                found->identity != expectedIdentity;
        }


        AuthoritativeTriageView MakeNativeUnavailable(
            AuthoritativeTriageUnavailableKind kind,
            std::string reason)
        {
            AuthoritativeTriageView view;
            view.verdict = TriageVerdict::Informational;
            view.unavailable = true;
            view.unavailableKind = kind;
            view.unavailability = MakeAvailabilityDescriptor(
                CanonicalTriageUnavailableCategory(kind),
                kind == AuthoritativeTriageUnavailableKind::NoCurrentEntity
                    ? TriageAvailabilityDisclosure::NoCurrentEntity
                    : TriageAvailabilityDisclosure::TriageUnavailable,
                std::move(reason));
            view.unavailableReason = view.unavailability.diagnostic;
            return view;
        }

        const char* SectionHeading(TriageRationaleSection section)
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
            default:
                return "";
            }
        }

        void AppendRationaleSection(
            std::ostringstream& text,
            const TriageResult& triage,
            TriageRationaleSection section)
        {
            text << "\r\n" << SectionHeading(section) << ":\r\n";
            bool appended = false;
            for (const TriageRationaleEntry& entry : triage.previewRationaleEntries)
            {
                if (entry.section != section || entry.text.empty())
                {
                    continue;
                }
                text << "- " << entry.text << "\r\n";
                appended = true;
            }
            if (!appended)
            {
                text << "- None observed.\r\n";
            }
        }

        const std::vector<std::string>& PersistedRationaleSection(
            const PersistedTriageSummary& summary,
            TriageRationaleSection section)
        {
            switch (section)
            {
            case TriageRationaleSection::VerdictBasis:
                return summary.verdictBasis;
            case TriageRationaleSection::CompletedCorrelations:
                return summary.completedCorrelations;
            case TriageRationaleSection::SupportingContext:
                return summary.supportingContext;
            case TriageRationaleSection::CollectionLimitations:
                return summary.collectionLimitations;
            case TriageRationaleSection::EvidenceIntegrityContext:
                return summary.evidenceIntegrityContext;
            case TriageRationaleSection::UnresolvedCorrelations:
                return summary.unresolvedCorrelations;
            case TriageRationaleSection::PresentationNotes:
            default:
                return summary.verdictBasis;
            }
        }

        void AppendPersistedRationaleSection(
            std::ostringstream& text,
            const PersistedTriageSummary& summary,
            TriageRationaleSection section)
        {
            text << "\r\n" << SectionHeading(section) << ":\r\n";
            const std::vector<std::string>& lines =
                PersistedRationaleSection(summary, section);
            if (lines.empty())
            {
                text << "- None observed.\r\n";
                return;
            }
            for (const std::string& line : lines)
            {
                text << "- " << line << "\r\n";
            }
        }
    }

    bool TriageAvailabilityDescriptor::Active() const
    {
        return category != TriageAvailabilityCategory::None;
    }

    std::string TriageAvailabilityCategoryDisplayText(
        TriageAvailabilityCategory category)
    {
        switch (category)
        {
        case TriageAvailabilityCategory::None:
            return "None";
        case TriageAvailabilityCategory::EntityUnavailable:
            return "Current entity unavailable";
        case TriageAvailabilityCategory::EngineNotAttempted:
            return "Engine not attempted";
        case TriageAvailabilityCategory::EntityOrGenerationMismatch:
            return "Entity or generation mismatch";
        case TriageAvailabilityCategory::ScopeMismatch:
            return "Live or snapshot scope mismatch";
        case TriageAvailabilityCategory::ResultMissing:
            return "Current result missing";
        case TriageAvailabilityCategory::EvaluationFailed:
            return "Evaluation failed";
        case TriageAvailabilityCategory::InputTruncated:
            return "Verdict-material input truncated";
        case TriageAvailabilityCategory::SourceMismatch:
            return "Source generation mismatch";
        case TriageAvailabilityCategory::MaterialEvidenceIncomplete:
            return "Verdict-material evidence incomplete";
        case TriageAvailabilityCategory::InvalidResult:
            return "Invalid engine result";
        case TriageAvailabilityCategory::NotCaptured:
            return "Triage result not captured";
        case TriageAvailabilityCategory::CapturedLegacyFallback:
            return "Captured legacy fallback";
        default:
            return "Unknown availability category";
        }
    }

    std::string TriageAvailabilityDisclosureText(
        TriageAvailabilityDisclosure disclosure)
    {
        switch (disclosure)
        {
        case TriageAvailabilityDisclosure::None:
            return {};
        case TriageAvailabilityDisclosure::NoCurrentEntity:
            return "No current process entity is available for triage.";
        case TriageAvailabilityDisclosure::LegacyTriageShown:
            return "ObservationEngine result unavailable; legacy triage is being shown.";
        case TriageAvailabilityDisclosure::TriageNotCaptured:
            return "Authoritative TriageEngine results were not captured in this older snapshot.";
        case TriageAvailabilityDisclosure::TriageUnavailable:
            return "TriageEngine result is unavailable for this process; no authoritative attention level is shown.";
        default:
            return "Triage authority is unavailable.";
        }
    }

    TriageAvailabilityDisposition ClassifyTriageAvailability(
        TriageAvailabilityCategory category)
    {
        switch (category)
        {
        case TriageAvailabilityCategory::None:
            return TriageAvailabilityDisposition::None;
        case TriageAvailabilityCategory::EntityUnavailable:
            return TriageAvailabilityDisposition::Expected;
        case TriageAvailabilityCategory::NotCaptured:
        case TriageAvailabilityCategory::CapturedLegacyFallback:
            return TriageAvailabilityDisposition::HistoricalCompatibilityOnly;
        case TriageAvailabilityCategory::EngineNotAttempted:
        case TriageAvailabilityCategory::EntityOrGenerationMismatch:
        case TriageAvailabilityCategory::ScopeMismatch:
        case TriageAvailabilityCategory::ResultMissing:
        case TriageAvailabilityCategory::EvaluationFailed:
        case TriageAvailabilityCategory::InputTruncated:
        case TriageAvailabilityCategory::SourceMismatch:
        case TriageAvailabilityCategory::MaterialEvidenceIncomplete:
        case TriageAvailabilityCategory::InvalidResult:
        default:
            return TriageAvailabilityDisposition::Avoidable;
        }
    }

    std::string TriageAvailabilityDispositionDisplayText(
        TriageAvailabilityDisposition disposition)
    {
        switch (disposition)
        {
        case TriageAvailabilityDisposition::None:
            return "None";
        case TriageAvailabilityDisposition::Avoidable:
            return "Avoidable current-state failure";
        case TriageAvailabilityDisposition::Expected:
            return "Expected unavailable state";
        case TriageAvailabilityDisposition::HistoricalCompatibilityOnly:
            return "Historical compatibility only";
        default:
            return "Unknown availability disposition";
        }
    }

    std::string TriageAvailabilityUserMessage(
        const TriageAvailabilityDescriptor& fallback)
    {
        if (!fallback.Active())
        {
            return {};
        }
        if (fallback.category ==
            TriageAvailabilityCategory::MaterialEvidenceIncomplete)
        {
            return "TriageEngine result unavailable due to incomplete material evidence; no authoritative attention level is shown.";
        }
        return TriageAvailabilityDisclosureText(fallback.disclosure);
    }

    std::string AuthoritativeTriageUnavailableKindDisplayText(
        AuthoritativeTriageUnavailableKind kind)
    {
        switch (kind)
        {
        case AuthoritativeTriageUnavailableKind::None:
            return "None";
        case AuthoritativeTriageUnavailableKind::NoCurrentEntity:
            return "No current process entity";
        case AuthoritativeTriageUnavailableKind::EngineNotAttempted:
            return "Native TriageEngine result not available";
        case AuthoritativeTriageUnavailableKind::EntityOrGenerationMismatch:
            return "Entity or evidence generation mismatch";
        case AuthoritativeTriageUnavailableKind::EntityScopeMismatch:
            return "Live/offline entity scope mismatch";
        case AuthoritativeTriageUnavailableKind::NativeObservationBuildUnavailable:
            return "Native observation build unavailable";
        case AuthoritativeTriageUnavailableKind::RefinementUnavailable:
            return "Observation refinement unavailable";
        case AuthoritativeTriageUnavailableKind::CorrelationUnavailable:
            return "Observation correlation unavailable";
        case AuthoritativeTriageUnavailableKind::TriageUnavailable:
            return "TriageEngine result unavailable";
        case AuthoritativeTriageUnavailableKind::SourceEvidenceMismatch:
            return "Source-evidence generation mismatch";
        case AuthoritativeTriageUnavailableKind::MaterialEvidenceIncomplete:
            return "Verdict-material native evidence incomplete";
        case AuthoritativeTriageUnavailableKind::InvalidVerdict:
            return "TriageEngine returned an invalid verdict";
        default:
            return "Unknown unavailable condition";
        }
    }

    TriageAvailabilityCategory CanonicalTriageUnavailableCategory(
        AuthoritativeTriageUnavailableKind kind)
    {
        switch (kind)
        {
        case AuthoritativeTriageUnavailableKind::None:
            return TriageAvailabilityCategory::None;
        case AuthoritativeTriageUnavailableKind::NoCurrentEntity:
            return TriageAvailabilityCategory::EntityUnavailable;
        case AuthoritativeTriageUnavailableKind::EngineNotAttempted:
            return TriageAvailabilityCategory::EngineNotAttempted;
        case AuthoritativeTriageUnavailableKind::EntityOrGenerationMismatch:
            return TriageAvailabilityCategory::EntityOrGenerationMismatch;
        case AuthoritativeTriageUnavailableKind::EntityScopeMismatch:
            return TriageAvailabilityCategory::ScopeMismatch;
        case AuthoritativeTriageUnavailableKind::NativeObservationBuildUnavailable:
        case AuthoritativeTriageUnavailableKind::RefinementUnavailable:
        case AuthoritativeTriageUnavailableKind::CorrelationUnavailable:
        case AuthoritativeTriageUnavailableKind::TriageUnavailable:
            return TriageAvailabilityCategory::EvaluationFailed;
        case AuthoritativeTriageUnavailableKind::SourceEvidenceMismatch:
            return TriageAvailabilityCategory::SourceMismatch;
        case AuthoritativeTriageUnavailableKind::MaterialEvidenceIncomplete:
            return TriageAvailabilityCategory::MaterialEvidenceIncomplete;
        case AuthoritativeTriageUnavailableKind::InvalidVerdict:
            return TriageAvailabilityCategory::InvalidResult;
        default:
            return TriageAvailabilityCategory::InvalidResult;
        }
    }

    std::string ProcessTriageUnavailableKindDisplayText(
        ProcessTriageUnavailableKind kind)
    {
        switch (kind)
        {
        case ProcessTriageUnavailableKind::None:
            return "None";
        case ProcessTriageUnavailableKind::CacheNotAttempted:
            return "Baseline cache unavailable";
        case ProcessTriageUnavailableKind::CacheGenerationMismatch:
            return "Baseline cache generation mismatch";
        case ProcessTriageUnavailableKind::BaselineEntryMissing:
            return "Baseline result missing";
        case ProcessTriageUnavailableKind::ProcessIdentityMismatch:
            return "Process identity mismatch";
        case ProcessTriageUnavailableKind::BaselineEvaluationUnavailable:
            return "Baseline evaluation unavailable";
        case ProcessTriageUnavailableKind::BaselineInputTruncated:
            return "Baseline evidence truncated";
        case ProcessTriageUnavailableKind::InvalidVerdict:
            return "Baseline verdict invalid";
        default:
            return "Unknown unavailable condition";
        }
    }

    TriageAvailabilityCategory CanonicalTriageUnavailableCategory(
        ProcessTriageUnavailableKind kind)
    {
        switch (kind)
        {
        case ProcessTriageUnavailableKind::None:
            return TriageAvailabilityCategory::None;
        case ProcessTriageUnavailableKind::CacheNotAttempted:
            return TriageAvailabilityCategory::EngineNotAttempted;
        case ProcessTriageUnavailableKind::CacheGenerationMismatch:
        case ProcessTriageUnavailableKind::ProcessIdentityMismatch:
            return TriageAvailabilityCategory::EntityOrGenerationMismatch;
        case ProcessTriageUnavailableKind::BaselineEntryMissing:
            return TriageAvailabilityCategory::ResultMissing;
        case ProcessTriageUnavailableKind::BaselineEvaluationUnavailable:
            return TriageAvailabilityCategory::EvaluationFailed;
        case ProcessTriageUnavailableKind::BaselineInputTruncated:
            return TriageAvailabilityCategory::InputTruncated;
        case ProcessTriageUnavailableKind::InvalidVerdict:
            return TriageAvailabilityCategory::InvalidResult;
        default:
            return TriageAvailabilityCategory::InvalidResult;
        }
    }

    TriageSurfaceClassification ClassifyTriageVerdictForSurfaces(
        TriageVerdict verdict)
    {
        TriageSurfaceClassification classification;
        switch (verdict)
        {
        case TriageVerdict::HighAttention:
            classification.severity = Severity::High;
            classification.suspicious = true;
            break;
        case TriageVerdict::MediumAttention:
            classification.severity = Severity::Medium;
            classification.suspicious = true;
            break;
        case TriageVerdict::LowAttention:
            classification.severity = Severity::Low;
            classification.suspicious = true;
            break;
        case TriageVerdict::Informational:
        default:
            classification.severity = Severity::None;
            classification.suspicious = false;
            break;
        }
        return classification;
    }

    bool ProcessTriageAuthority::UsesBaselineTriage() const
    {
        return !unavailable && baselineAvailable &&
            unavailableKind == ProcessTriageUnavailableKind::None &&
            !unavailability.Active() &&
            baseline != nullptr && baseline->triage.Succeeded();
    }

    ProcessTriageAuthority SelectNativeProcessTriageAuthority(
        const ProcessTriageCache& cache,
        const ProcessInfo& process,
        const ProcessTriageCacheSourceStamp& expectedSourceStamp)
    {
        if (!cache.attempted)
        {
            return MakeProcessUnavailable(
                process,
                ProcessTriageUnavailableKind::CacheNotAttempted,
                "The process-wide TriageEngine cache has not been built.");
        }
        if (!cache.Succeeded())
        {
            return MakeProcessUnavailable(
                process,
                ProcessTriageUnavailableKind::BaselineEvaluationUnavailable,
                "Process-wide TriageEngine cache construction did not complete successfully.");
        }
        if (!cache.MatchesStamp(expectedSourceStamp))
        {
            return MakeProcessUnavailable(
                process,
                ProcessTriageUnavailableKind::CacheGenerationMismatch,
                "The process-wide TriageEngine cache does not match the current evidence generation.");
        }

        const ProcessIdentityKey identity = MakeProcessIdentityKey(process);
        const CachedBaselineTriage* baseline = cache.Find(identity);
        if (baseline == nullptr)
        {
            if (CacheContainsPidWithDifferentIdentity(cache, identity))
            {
                return MakeProcessUnavailable(
                    process,
                    ProcessTriageUnavailableKind::ProcessIdentityMismatch,
                    "The cached baseline result belongs to a different creation-time identity for this PID.");
            }
            if (cache.summary.omittedProcessCount != 0)
            {
                return MakeProcessUnavailable(
                    process,
                    ProcessTriageUnavailableKind::BaselineInputTruncated,
                    "The process-wide cache limit omitted this process identity from baseline evaluation.");
            }
            return MakeProcessUnavailable(
                process,
                ProcessTriageUnavailableKind::BaselineEntryMissing,
                "No current baseline TriageEngine result exists for this process identity.");
        }
        if (baseline->identity != identity)
        {
            return MakeProcessUnavailable(
                process,
                ProcessTriageUnavailableKind::ProcessIdentityMismatch,
                "The retained baseline entry does not match the current process identity.",
                baseline);
        }
        if (baseline->sourceStamp != expectedSourceStamp)
        {
            return MakeProcessUnavailable(
                process,
                ProcessTriageUnavailableKind::CacheGenerationMismatch,
                "The retained baseline entry does not match the current evidence generation.",
                baseline);
        }
        if (!baseline->attempted || !baseline->success ||
            !baseline->baseline.Succeeded() ||
            !baseline->refinement.Succeeded() ||
            !baseline->correlations.Succeeded() ||
            !baseline->triage.Succeeded())
        {
            return MakeProcessUnavailable(
                process,
                ProcessTriageUnavailableKind::BaselineEvaluationUnavailable,
                "Baseline TriageEngine evaluation did not complete successfully for this process identity.",
                baseline);
        }
        if (baseline->baseline.omittedFactCount != 0)
        {
            return MakeProcessUnavailable(
                process,
                ProcessTriageUnavailableKind::BaselineInputTruncated,
                "Baseline evidence exceeded a bounded input cap, so the partial verdict is not authoritative.",
                baseline);
        }
        if (!IsKnownVerdict(baseline->triage.verdict))
        {
            return MakeProcessUnavailable(
                process,
                ProcessTriageUnavailableKind::InvalidVerdict,
                "The baseline TriageEngine returned an invalid attention verdict.",
                baseline);
        }

        ProcessTriageAuthority authority;
        authority.verdict = baseline->triage.verdict;
        authority.unavailable = false;
        authority.baselineAvailable = true;
        authority.unavailableKind = ProcessTriageUnavailableKind::None;
        authority.unavailability = {};
        authority.baseline = baseline;
        return authority;
    }

    bool AuthoritativeTriageView::UsesTriageEngine() const
    {
        return !unavailable && unavailableKind ==
            AuthoritativeTriageUnavailableKind::None &&
            !unavailability.Active() &&
            triageResult != nullptr && triageResult->Succeeded();
    }


    Severity TriageVerdictToSeverity(TriageVerdict verdict)
    {
        return ClassifyTriageVerdictForSurfaces(verdict).severity;
    }

    bool IsSuspiciousTriageVerdict(TriageVerdict verdict)
    {
        return ClassifyTriageVerdictForSurfaces(verdict).suspicious;
    }

    std::string SelectedTriageAnalysisLevelDisplayText(
        SelectedTriageAnalysisLevel level)
    {
        switch (level)
        {
        case SelectedTriageAnalysisLevel::NotCaptured:
            return "Not captured";
        case SelectedTriageAnalysisLevel::Enriched:
            return "Enriched";
        case SelectedTriageAnalysisLevel::Baseline:
            return "Baseline";
        case SelectedTriageAnalysisLevel::LegacyFallback:
            return "Legacy fallback";
        case SelectedTriageAnalysisLevel::Unavailable:
            return "Unavailable";
        default:
            return "Unknown";
        }
    }

    bool SelectedProcessTriageAuthority::UsesEnrichedTriage() const
    {
        return !historicalFallbackCaptured && !unavailable &&
            enrichedAvailable &&
            analysisLevel == SelectedTriageAnalysisLevel::Enriched &&
            !availability.Active() &&
            ((triageResult != nullptr && triageResult->Succeeded()) ||
             (persistedSummary != nullptr &&
              persistedSummary->evaluationSucceeded));
    }

    bool SelectedProcessTriageAuthority::UsesBaselineTriage() const
    {
        return !historicalFallbackCaptured && !unavailable &&
            baselineAvailable &&
            analysisLevel == SelectedTriageAnalysisLevel::Baseline &&
            !availability.Active() &&
            ((triageResult != nullptr && triageResult->Succeeded() &&
              baseline != nullptr) ||
             (persistedSummary != nullptr &&
              persistedSummary->evaluationSucceeded));
    }


    AuthoritativeTriageView SelectNativeAuthoritativeTriage(
        const ObservationShadowState& shadow,
        bool hasEntity,
        std::uint32_t selectedPid,
        std::uint64_t entityCreationTime,
        std::uint64_t sourceGeneration,
        const std::string& expectedEntityScope)
    {
        if (!hasEntity)
        {
            return MakeNativeUnavailable(
                AuthoritativeTriageUnavailableKind::NoCurrentEntity,
                "No current process entity is available for native TriageEngine evaluation.");
        }
        if (!shadow.attempted)
        {
            return MakeNativeUnavailable(
                AuthoritativeTriageUnavailableKind::EngineNotAttempted,
                "The native TriageEngine pipeline has not produced a result for the current evidence generation.");
        }
        if (!ObservationShadowMatches(
                shadow,
                true,
                selectedPid,
                entityCreationTime,
                sourceGeneration))
        {
            return MakeNativeUnavailable(
                AuthoritativeTriageUnavailableKind::EntityOrGenerationMismatch,
                "The retained native TriageEngine result does not match the current process identity and evidence generation.");
        }
        if (shadow.entityScope != expectedEntityScope)
        {
            return MakeNativeUnavailable(
                AuthoritativeTriageUnavailableKind::EntityScopeMismatch,
                "The retained native TriageEngine result does not match the current live or snapshot scope.");
        }
        if (!shadow.success || !shadow.inventory.Succeeded() ||
            !shadow.nativeObservations.attempted ||
            !shadow.nativeObservations.Succeeded())
        {
            return MakeNativeUnavailable(
                AuthoritativeTriageUnavailableKind::NativeObservationBuildUnavailable,
                "Native observation production did not complete successfully for the current process generation.");
        }
        // Bounded previews, optional names, and context-only rows may be
        // truncated without changing the verdict. Authority is blocked only
        // when the native builder reports omitted verdict-material facts.
        if (shadow.decisionSummary.nativeMaterialEvidenceTruncated)
        {
            return MakeNativeUnavailable(
                AuthoritativeTriageUnavailableKind::MaterialEvidenceIncomplete,
                "Verdict-material native evidence exceeded a bounded input cap.");
        }
        if (!shadow.refinement.Succeeded())
        {
            return MakeNativeUnavailable(
                AuthoritativeTriageUnavailableKind::RefinementUnavailable,
                "Native observation refinement did not complete successfully.");
        }
        if (!shadow.correlation.Succeeded())
        {
            return MakeNativeUnavailable(
                AuthoritativeTriageUnavailableKind::CorrelationUnavailable,
                "Native correlation activation did not complete successfully.");
        }
        if (!shadow.triage.Succeeded())
        {
            return MakeNativeUnavailable(
                AuthoritativeTriageUnavailableKind::TriageUnavailable,
                "TriageEngine did not produce a valid native result.");
        }
        if (!IsKnownVerdict(shadow.triage.verdict))
        {
            return MakeNativeUnavailable(
                AuthoritativeTriageUnavailableKind::InvalidVerdict,
                "TriageEngine returned an invalid attention verdict.");
        }

        AuthoritativeTriageView view;
        view.verdict = shadow.triage.verdict;
        view.unavailable = false;
        view.unavailableKind = AuthoritativeTriageUnavailableKind::None;
        view.sourceEvidenceCount = shadow.inventory.records.size();
        view.triageResult = &shadow.triage;
        return view;
    }


    SelectedProcessTriageAuthority SelectNativeSelectedProcessTriageAuthority(
        const ObservationShadowState& shadow,
        bool hasEntity,
        const ProcessInfo& selectedProcess,
        std::uint64_t sourceGeneration,
        const std::string& expectedEntityScope,
        const ProcessTriageCache& baselineCache,
        const ProcessTriageCacheSourceStamp& expectedBaselineSourceStamp)
    {
        SelectedProcessTriageAuthority selected;
        selected.verdict = TriageVerdict::Informational;
        selected.analysisLevel = SelectedTriageAnalysisLevel::Unavailable;
        selected.unavailable = true;

        if (!hasEntity)
        {
            selected.availability = MakeAvailabilityDescriptor(
                TriageAvailabilityCategory::EntityUnavailable,
                TriageAvailabilityDisclosure::NoCurrentEntity,
                "No current process entity is available for native TriageEngine authority.");
            selected.availabilityReason = selected.availability.diagnostic;
            return selected;
        }

        const AuthoritativeTriageView enriched =
            SelectNativeAuthoritativeTriage(
                shadow,
                true,
                selectedProcess.pid,
                selectedProcess.hasCreationTime
                    ? selectedProcess.creationTimeFileTime
                    : 0,
                sourceGeneration,
                expectedEntityScope);
        const ProcessTriageAuthority baseline = SelectNativeProcessTriageAuthority(
            baselineCache,
            selectedProcess,
            expectedBaselineSourceStamp);

        selected.baselineAvailable = baseline.UsesBaselineTriage();
        selected.baseline = baseline.baseline;
        if (selected.baselineAvailable)
        {
            selected.baselineVerdict = baseline.verdict;
            selected.baselineTriageResult = &baseline.baseline->triage;
        }

        if (enriched.UsesTriageEngine())
        {
            selected.verdict = enriched.verdict;
            selected.analysisLevel = SelectedTriageAnalysisLevel::Enriched;
            selected.unavailable = false;
            selected.enrichedAvailable = true;
            selected.availability = {};
            selected.triageResult = enriched.triageResult;
            selected.sourceEvidenceCount =
                shadow.inventory.records.size();
            return selected;
        }
        if (baseline.UsesBaselineTriage())
        {
            selected.verdict = baseline.verdict;
            selected.analysisLevel = SelectedTriageAnalysisLevel::Baseline;
            selected.unavailable = false;
            selected.availability = {};
            selected.triageResult = &baseline.baseline->triage;
            selected.sourceEvidenceCount =
                baseline.baseline->baseline.inventory.records.size();
            return selected;
        }

        selected.availability = MakeAvailabilityDescriptor(
            MoreMaterialUnavailableCategory(
                enriched.unavailability.category,
                baseline.unavailability.category),
            TriageAvailabilityDisclosure::TriageUnavailable,
            "Enriched native evaluation unavailable: " +
                enriched.unavailableReason +
                " Baseline native evaluation unavailable: " +
                baseline.unavailableReason);
        selected.availabilityReason = selected.availability.diagnostic;
        return selected;
    }


    SelectedProcessTriageAuthority SelectCapturedSelectedProcessTriageAuthority(
        const PersistedTriageContext& context,
        bool hasEntity,
        const ProcessInfo& selectedProcess)
    {
        SelectedProcessTriageAuthority selected;
        selected.verdict = TriageVerdict::Informational;
        selected.analysisLevel = SelectedTriageAnalysisLevel::NotCaptured;

        if (!hasEntity)
        {
            selected.notCaptured = true;
            selected.availability = MakeAvailabilityDescriptor(
                TriageAvailabilityCategory::EntityUnavailable,
                TriageAvailabilityDisclosure::NoCurrentEntity,
                "No selected saved-snapshot process entity is available.");
            selected.availabilityReason = selected.availability.diagnostic;
            return selected;
        }

        const ProcessIdentityKey identity = MakeProcessIdentityKey(selectedProcess);
        const PersistedProcessTriageRecord* record = nullptr;
        if (context.selectedRecord.has_value() &&
            context.selectedRecord->identity == identity)
        {
            record = &context.selectedRecord.value();
        }
        else
        {
            record = context.FindProcess(identity);
        }
        if (record == nullptr || !record->summary.captured ||
            record->summary.analysisLevel ==
                PersistedTriageAnalysisLevel::NotCaptured)
        {
            selected.notCaptured = true;
            selected.availability = MakeAvailabilityDescriptor(
                TriageAvailabilityCategory::NotCaptured,
                TriageAvailabilityDisclosure::TriageNotCaptured,
                "Authoritative TriageEngine results were not captured in this older snapshot.");
            selected.availabilityReason = selected.availability.diagnostic;
            return selected;
        }

        const PersistedTriageValidationResult validation =
            ValidatePersistedTriageSummary(record->summary);
        if (!validation.valid)
        {
            selected.analysisLevel = SelectedTriageAnalysisLevel::Unavailable;
            selected.unavailable = true;
            selected.availability = MakeAvailabilityDescriptor(
                TriageAvailabilityCategory::InvalidResult,
                TriageAvailabilityDisclosure::TriageUnavailable,
                "The captured authoritative triage record is invalid.");
            selected.availabilityReason = selected.availability.diagnostic;
            return selected;
        }

        const PersistedTriageSummary& summary = record->summary;
        selected.persistedSummary = &summary;
        selected.verdict = summary.authoritativeVerdict;
        selected.sourceEvidenceCount = summary.sourceEvidenceCount;
        selected.baselineAvailable = summary.baselineVerdictAvailable;
        selected.baselineVerdict = summary.baselineVerdict;
        switch (summary.analysisLevel)
        {
        case PersistedTriageAnalysisLevel::Enriched:
            selected.analysisLevel = SelectedTriageAnalysisLevel::Enriched;
            selected.enrichedAvailable = true;
            break;
        case PersistedTriageAnalysisLevel::Baseline:
            selected.analysisLevel = SelectedTriageAnalysisLevel::Baseline;
            selected.baselineAvailable = true;
            break;
        case PersistedTriageAnalysisLevel::LegacyFallback:
            // Schema-4 compatibility: preserve the historical captured state
            // as metadata without invoking or reconstructing legacy policy.
            selected.analysisLevel = SelectedTriageAnalysisLevel::LegacyFallback;
            selected.historicalFallbackCaptured = true;
            selected.availability = MakeAvailabilityDescriptor(
                TriageAvailabilityCategory::CapturedLegacyFallback,
                TriageAvailabilityDisclosure::LegacyTriageShown,
                summary.fallbackReason);
            selected.availabilityReason = selected.availability.diagnostic;
            break;
        case PersistedTriageAnalysisLevel::NotCaptured:
        default:
            selected.persistedSummary = nullptr;
            selected.notCaptured = true;
            selected.analysisLevel = SelectedTriageAnalysisLevel::NotCaptured;
            selected.verdict = TriageVerdict::Informational;
            break;
        }
        return selected;
    }


    std::string FormatSelectedProcessTriageSummary(
        const SelectedProcessTriageAuthority& authority,
        const std::string& processName,
        std::uint32_t pid)
    {
        std::ostringstream text;
        text << "GlassPane Triage Summary\r\n\r\n";
        text << "Verdict: ";
        if (authority.notCaptured)
        {
            text << "Not captured\r\n";
        }
        else
        {
            text << TriageVerdictDisplayText(authority.verdict) << "\r\n";
        }
        text << "Analysis level: "
             << SelectedTriageAnalysisLevelDisplayText(authority.analysisLevel)
             << "\r\n";
        if (authority.analysisLevel == SelectedTriageAnalysisLevel::Enriched &&
            authority.baselineAvailable)
        {
            text << "Baseline verdict: "
                 << TriageVerdictDisplayText(authority.baselineVerdict)
                 << "\r\n";
        }
        text << "Process: " << (processName.empty() ? "(unknown)" : processName)
             << " (PID " << pid << ")\r\n";

        if (authority.notCaptured)
        {
            const std::string disclosure =
                TriageAvailabilityUserMessage(authority.availability);
            text << "\r\n"
                 << (disclosure.empty()
                        ? "Authoritative TriageEngine results were not captured in this older snapshot."
                        : disclosure)
                 << "\r\n";
        }
        else if (authority.historicalFallbackCaptured || authority.unavailable)
        {
            const std::string disclosure =
                TriageAvailabilityUserMessage(authority.availability);
            if (!disclosure.empty())
            {
                text << "\r\n" << disclosure << "\r\n";
            }
        }
        else if (authority.triageResult != nullptr)
        {
            AppendRationaleSection(
                text,
                *authority.triageResult,
                TriageRationaleSection::VerdictBasis);
            AppendRationaleSection(
                text,
                *authority.triageResult,
                TriageRationaleSection::CompletedCorrelations);
            AppendRationaleSection(
                text,
                *authority.triageResult,
                TriageRationaleSection::SupportingContext);
            AppendRationaleSection(
                text,
                *authority.triageResult,
                TriageRationaleSection::CollectionLimitations);
            AppendRationaleSection(
                text,
                *authority.triageResult,
                TriageRationaleSection::EvidenceIntegrityContext);
            AppendRationaleSection(
                text,
                *authority.triageResult,
                TriageRationaleSection::UnresolvedCorrelations);
        }
        else if (authority.persistedSummary != nullptr)
        {
            AppendPersistedRationaleSection(
                text,
                *authority.persistedSummary,
                TriageRationaleSection::VerdictBasis);
            AppendPersistedRationaleSection(
                text,
                *authority.persistedSummary,
                TriageRationaleSection::CompletedCorrelations);
            AppendPersistedRationaleSection(
                text,
                *authority.persistedSummary,
                TriageRationaleSection::SupportingContext);
            AppendPersistedRationaleSection(
                text,
                *authority.persistedSummary,
                TriageRationaleSection::CollectionLimitations);
            AppendPersistedRationaleSection(
                text,
                *authority.persistedSummary,
                TriageRationaleSection::EvidenceIntegrityContext);
            AppendPersistedRationaleSection(
                text,
                *authority.persistedSummary,
                TriageRationaleSection::UnresolvedCorrelations);
        }

        text << "\r\nSource evidence:\r\n- " << authority.sourceEvidenceCount
             << (authority.sourceEvidenceCount == 1
                    ? " source-evidence record retained for audit.\r\n"
                    : " source-evidence records retained for audit.\r\n");

        return BoundedUtf8(
            text.str(),
            AuthoritativeTriageSummaryMaxCharacters);
    }
}
