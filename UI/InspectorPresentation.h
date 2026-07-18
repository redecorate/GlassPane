#pragma once

#include "../Core/HandleInfo.h"
#include "../Core/SelectedProcessEnrichedLifecycle.h"

#include <cstddef>

namespace GlassPane::UI
{
    inline constexpr const char* AnalysisLevelBaselineText =
        "Analysis level: Baseline";
    inline constexpr const char* AnalysisLevelEnrichedText =
        "Analysis level: Enriched";
    inline constexpr const char* AnalysisLevelUnavailableText =
        "Analysis level: Unavailable";
    inline constexpr const char* BaselineTriagePrefix =
        "Baseline triage: ";
    inline constexpr const char* EnrichedAnalysisPendingMessage =
        "Enriched analysis is in progress.";
    inline constexpr const char* EnrichedAnalysisRefreshingMessage =
        "Enriched analysis is being refreshed.";
    inline constexpr const char* EnrichedAnalysisFailedMessage =
        "Enriched analysis could not be completed. Baseline triage remains available.";
    inline constexpr const char* AuthoritativeTriageUnavailableMessage =
        "No current authoritative TriageEngine result is available.";

    enum class EnrichedAnalysisPresentationState
    {
        None = 0,
        Pending = 1,
        Refreshing = 2,
        Enriched = 3,
        Failed = 4
    };

    struct EnrichedAnalysisPresentationPlan
    {
        EnrichedAnalysisPresentationState state =
            EnrichedAnalysisPresentationState::None;
        const char* message = "";
    };

    [[nodiscard]] constexpr EnrichedAnalysisPresentationPlan
    PlanEnrichedAnalysisPresentation(
        bool enriched,
        bool pending,
        bool failed,
        bool explicitRefresh) noexcept
    {
        if (enriched)
        {
            return {
                EnrichedAnalysisPresentationState::Enriched,
                ""
            };
        }
        if (pending)
        {
            return explicitRefresh
                ? EnrichedAnalysisPresentationPlan{
                    EnrichedAnalysisPresentationState::Refreshing,
                    EnrichedAnalysisRefreshingMessage }
                : EnrichedAnalysisPresentationPlan{
                    EnrichedAnalysisPresentationState::Pending,
                    EnrichedAnalysisPendingMessage };
        }
        if (failed)
        {
            return {
                EnrichedAnalysisPresentationState::Failed,
                EnrichedAnalysisFailedMessage
            };
        }
        return {};
    }

    [[nodiscard]] constexpr bool IsExplicitEvidenceRefreshReason(
        Core::SelectedProcessEnrichedRebuildReason reason) noexcept
    {
        return reason ==
                Core::SelectedProcessEnrichedRebuildReason::FileIdentityChanged ||
            reason == Core::SelectedProcessEnrichedRebuildReason::ChainChanged ||
            reason == Core::SelectedProcessEnrichedRebuildReason::ModulesChanged ||
            reason == Core::SelectedProcessEnrichedRebuildReason::MemoryChanged ||
            reason == Core::SelectedProcessEnrichedRebuildReason::HandlesChanged ||
            reason == Core::SelectedProcessEnrichedRebuildReason::TokenChanged ||
            reason == Core::SelectedProcessEnrichedRebuildReason::RuntimeChanged ||
            reason == Core::SelectedProcessEnrichedRebuildReason::NetworkChanged ||
            reason == Core::SelectedProcessEnrichedRebuildReason::
                AllSelectedEvidenceChanged;
    }

    // Pure presentation plan for the current native source-evidence section.
    // Keeping this independent of ImGui makes the zero/nonzero layout contract
    // deterministic and testable without introducing additional UI state.
    struct NativeSourceEvidenceSectionPlan
    {
        std::size_t sectionCount = 1;
        bool showFilters = false;
        bool showRecordCards = false;
        bool showEmptyState = true;
        bool copyEnabled = false;
    };

    [[nodiscard]] constexpr NativeSourceEvidenceSectionPlan
    PlanNativeSourceEvidenceSection(std::size_t recordCount) noexcept
    {
        const bool hasRecords = recordCount != 0;
        return NativeSourceEvidenceSectionPlan{
            1,
            hasRecords,
            hasRecords,
            !hasRecords,
            hasRecords
        };
    }

    struct HandleCollectionSectionPlan
    {
        bool showRows = false;
        bool showFilters = false;
        bool showEmptyState = false;
        bool showUnavailableState = false;
        bool showLimitationBanner = false;
    };

    [[nodiscard]] constexpr HandleCollectionSectionPlan
    PlanHandleCollectionSection(
        Core::HandleCollectionState state,
        std::size_t retainedRowCount) noexcept
    {
        const bool hasRows = retainedRowCount != 0;
        const bool completed = state == Core::HandleCollectionState::Success ||
            state == Core::HandleCollectionState::Partial;
        const bool partial = state == Core::HandleCollectionState::Partial;
        return HandleCollectionSectionPlan{
            hasRows,
            hasRows,
            !hasRows && completed,
            !hasRows && !completed,
            partial || (hasRows && state != Core::HandleCollectionState::Success)
        };
    }

    [[nodiscard]] constexpr const wchar_t* HandleCollectionStateDisplayText(
        Core::HandleCollectionState state) noexcept
    {
        switch (state)
        {
        case Core::HandleCollectionState::Success:
            return L"Success";
        case Core::HandleCollectionState::Partial:
            return L"Partial";
        case Core::HandleCollectionState::Unavailable:
            return L"Unavailable";
        case Core::HandleCollectionState::Failed:
            return L"Failed";
        case Core::HandleCollectionState::NotAttempted:
        default:
            return L"Not attempted";
        }
    }
}
