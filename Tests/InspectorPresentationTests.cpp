#include "UI/InspectorPresentation.h"

#include <iostream>
#include <string_view>

namespace GlassPane::Tests
{
    namespace
    {
        int failures = 0;

        void Check(bool condition, const wchar_t* message)
        {
            if (!condition)
            {
                ++failures;
                std::wcerr << L"FAIL: " << message << L'\n';
            }
        }

        void TestSuccessfulRowsRenderNormally()
        {
            constexpr UI::HandleCollectionSectionPlan plan =
                UI::PlanHandleCollectionSection(
                    Core::HandleCollectionState::Success,
                    5);
            static_assert(plan.showRows && plan.showFilters);
            static_assert(!plan.showEmptyState && !plan.showUnavailableState);
            static_assert(!plan.showLimitationBanner);
            Check(plan.showRows && plan.showFilters,
                L"successful retained handles render rows and filters");
            Check(!plan.showLimitationBanner,
                L"successful retained handles do not show a limitation banner");
        }

        void TestPartialRowsRemainVisible()
        {
            constexpr UI::HandleCollectionSectionPlan plan =
                UI::PlanHandleCollectionSection(
                    Core::HandleCollectionState::Partial,
                    3);
            static_assert(plan.showRows && plan.showFilters);
            static_assert(plan.showLimitationBanner);
            static_assert(!plan.showUnavailableState);
            Check(plan.showRows && plan.showLimitationBanner,
                L"partial retained handles render with one limitation banner");
            Check(!plan.showUnavailableState,
                L"partial retained handles are not replaced by unavailable state");
        }

        void TestTerminalStateOnlyReplacesEmptyTable()
        {
            constexpr UI::HandleCollectionSectionPlan failedWithRows =
                UI::PlanHandleCollectionSection(
                    Core::HandleCollectionState::Failed,
                    2);
            constexpr UI::HandleCollectionSectionPlan unavailableWithoutRows =
                UI::PlanHandleCollectionSection(
                    Core::HandleCollectionState::Unavailable,
                    0);
            Check(failedWithRows.showRows &&
                    failedWithRows.showLimitationBanner &&
                    !failedWithRows.showUnavailableState,
                L"failed collection preserves any retained core rows");
            Check(unavailableWithoutRows.showUnavailableState &&
                    !unavailableWithoutRows.showRows,
                L"unavailable collection replaces the table only without rows");
        }

        void TestSuccessfulZeroRowsIsHonestEmptyState()
        {
            constexpr UI::HandleCollectionSectionPlan plan =
                UI::PlanHandleCollectionSection(
                    Core::HandleCollectionState::Success,
                    0);
            Check(plan.showEmptyState &&
                    !plan.showUnavailableState &&
                    !plan.showFilters,
                L"successful zero-row collection renders an honest empty state");
        }

        void TestOptionalMetadataDoesNotControlRowVisibility()
        {
            Core::HandleCollectionResult collection;
            collection.state = Core::HandleCollectionState::Partial;
            collection.success = true;
            collection.namesSkipped = 4;
            collection.namesFailed = 2;
            collection.handles.resize(6);
            const UI::HandleCollectionSectionPlan plan =
                UI::PlanHandleCollectionSection(
                    collection.state,
                    collection.handles.size());
            Check(plan.showRows && plan.showLimitationBanner,
                L"optional name omissions preserve raw handle rows");
        }

        void TestEnrichedLifecycleWording()
        {
            const UI::EnrichedAnalysisPresentationPlan pending =
                UI::PlanEnrichedAnalysisPresentation(false, true, false, false);
            const UI::EnrichedAnalysisPresentationPlan refreshing =
                UI::PlanEnrichedAnalysisPresentation(false, true, false, true);
            const UI::EnrichedAnalysisPresentationPlan enriched =
                UI::PlanEnrichedAnalysisPresentation(true, false, false, false);
            const UI::EnrichedAnalysisPresentationPlan failed =
                UI::PlanEnrichedAnalysisPresentation(false, false, true, false);

            Check(pending.state ==
                    UI::EnrichedAnalysisPresentationState::Pending &&
                    std::string_view(pending.message) ==
                        UI::EnrichedAnalysisPendingMessage,
                L"pending wording is distinct and exact");
            Check(refreshing.state ==
                    UI::EnrichedAnalysisPresentationState::Refreshing &&
                    std::string_view(refreshing.message) ==
                        UI::EnrichedAnalysisRefreshingMessage,
                L"explicit refresh wording is distinct and exact");
            Check(enriched.state ==
                    UI::EnrichedAnalysisPresentationState::Enriched &&
                    std::string_view(UI::AnalysisLevelEnrichedText) ==
                        "Analysis level: Enriched" &&
                    std::string_view(UI::BaselineTriagePrefix) ==
                        "Baseline triage: ",
                L"enriched wording identifies baseline triage separately");
            Check(failed.state ==
                    UI::EnrichedAnalysisPresentationState::Failed &&
                    std::string_view(failed.message) ==
                        UI::EnrichedAnalysisFailedMessage,
                L"genuine failure wording preserves baseline authority");
            Check(std::string_view(UI::AnalysisLevelUnavailableText) ==
                    "Analysis level: Unavailable" &&
                    std::string_view(UI::AuthoritativeTriageUnavailableMessage) ==
                        "No current authoritative TriageEngine result is available.",
                L"unavailable wording is explicit and exact");
        }
    }

    int RunInspectorPresentationTests()
    {
        failures = 0;
        TestSuccessfulRowsRenderNormally();
        TestPartialRowsRemainVisible();
        TestTerminalStateOnlyReplacesEmptyTable();
        TestSuccessfulZeroRowsIsHonestEmptyState();
        TestOptionalMetadataDoesNotControlRowVisibility();
        TestEnrichedLifecycleWording();
        if (failures == 0)
        {
            std::wcout << L"Inspector presentation tests passed.\n";
        }
        return failures;
    }
}
