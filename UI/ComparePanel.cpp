#include "ComparePanel.h"
#include "UiHelpers.h"

#include <algorithm>

namespace GlassPane::UI
{
    void PushGlassButtonStyle();
    void PopGlassButtonStyle();
    void RenderGlassSectionHeader(const char* label, ImFont* font, const ImVec4& accent);

    namespace
    {
        bool PushFontIfAvailable(ImFont* font)
        {
            if (font == nullptr)
            {
                return false;
            }

            ImGui::PushFont(font);
            return true;
        }

        void PopFontIfPushed(bool pushed)
        {
            if (pushed)
            {
                ImGui::PopFont();
            }
        }

        void WrappedTextDisabled(const char* text)
        {
            ImGui::PushTextWrapPos(0.0f);
            ImGui::TextDisabled("%s", text);
            ImGui::PopTextWrapPos();
        }

        float StandardButtonWidth(const char* label)
        {
            const ImGuiStyle& style = ImGui::GetStyle();
            return ImGui::CalcTextSize(label).x + style.FramePadding.x * 2.0f + 2.0f;
        }

        void SameLineIfFits(float nextItemWidth, float spacing = 4.0f)
        {
            const float contentRight = ImGui::GetCursorScreenPos().x + ImGui::GetContentRegionAvail().x;
            const float nextItemRight = ImGui::GetItemRectMax().x + spacing + nextItemWidth;
            if (nextItemRight <= contentRight)
            {
                ImGui::SameLine(0.0f, spacing);
            }
        }

        bool ActionButton(const char* label, bool enabled = true, const char* disabledReason = nullptr)
        {
            PushGlassButtonStyle();
            if (!enabled)
            {
                ImGui::BeginDisabled();
            }
            const bool clicked = ImGui::Button(label);
            if (!enabled)
            {
                ImGui::EndDisabled();
                RenderDisabledReasonTooltip(disabledReason);
            }
            PopGlassButtonStyle();
            return enabled && clicked;
        }
    }

    void RenderComparePanel(
        const ComparePanelState& state,
        const ComparePanelCallbacks& callbacks,
        ImFont* titleFont,
        const ImVec4& accentColor)
    {
        RenderGlassSectionHeader("Snapshot Compare", titleFont, accentColor);
        WrappedTextDisabled("Compare local in-memory snapshots. Changes are evidence worth reviewing, not proof of malicious activity.");
        WrappedTextDisabled("Capture Baseline and Capture Current refresh the process snapshot first. Capture Current replaces the previous current snapshot and compares it to the baseline.");
        WrappedTextDisabled("Current and schema-5 selected-process source evidence is compared by stable native semantics. Imported historical legacy records remain a separate compatibility comparison and are never title-matched to native records.");
        ImGui::Spacing();

        if (ActionButton("Capture Baseline##Compare") && callbacks.captureBaseline)
        {
            callbacks.captureBaseline();
        }
        SameLineIfFits(StandardButtonWidth("Capture Current"), 8.0f);
        if (ActionButton("Capture Current##Compare") && callbacks.captureCurrent)
        {
            callbacks.captureCurrent();
        }
        SameLineIfFits(StandardButtonWidth("Clear Compare"), 8.0f);
        const bool hasCompareState = state.baselineCaptured || state.currentCaptured || state.resultValid;
        if (ActionButton(
                "Clear Compare##Compare",
                hasCompareState,
                "There is no captured comparison to clear.") && callbacks.clearCompare)
        {
            callbacks.clearCompare();
        }
        SameLineIfFits(StandardButtonWidth("Copy Compare Summary"), 8.0f);
        if (ActionButton("Copy Compare Summary##Compare") && callbacks.copySummary)
        {
            callbacks.copySummary();
        }

        ImGui::Spacing();
        if (callbacks.renderSummary)
        {
            callbacks.renderSummary();
        }
        ImGui::Separator();

        if (!state.baselineCaptured && !state.currentCaptured)
        {
            RenderEmptyState("Capture a baseline and current snapshot to review differences.");
            return;
        }
        if (state.baselineCaptured && !state.currentCaptured)
        {
            RenderEmptyState("Baseline captured.", "Capture a current snapshot to review differences.");
            return;
        }
        if (!state.baselineCaptured && state.currentCaptured)
        {
            RenderEmptyState("Current snapshot captured.", "Capture a baseline snapshot to review differences.");
            return;
        }
        if (!state.resultValid)
        {
            RenderEmptyState("The comparison is not available.", "Capture both snapshots to compute it.");
            return;
        }

        if (state.noDifferences)
        {
            WrappedTextDisabled("No meaningful differences found between snapshots.");
        }

        if (state.hasNotes && callbacks.renderNotes)
        {
            ImGui::SeparatorText("Notes");
            callbacks.renderNotes();
        }

        ImGui::SeparatorText("New Processes");
        if (state.newProcessesEmpty)
        {
            WrappedTextDisabled("No new processes were observed.");
        }
        else if (callbacks.renderNewProcesses)
        {
            callbacks.renderNewProcesses();
        }

        ImGui::SeparatorText("Exited Processes");
        if (state.exitedProcessesEmpty)
        {
            WrappedTextDisabled("No exited processes were observed.");
        }
        else if (callbacks.renderExitedProcesses)
        {
            callbacks.renderExitedProcesses();
        }

        ImGui::SeparatorText("Changed Processes");
        if (state.changedProcessesEmpty)
        {
            WrappedTextDisabled("No important process attribute changes were observed.");
        }
        else if (callbacks.renderChangedProcesses)
        {
            callbacks.renderChangedProcesses();
        }

        ImGui::SeparatorText("Network Changes");
        if (!state.networkCompared)
        {
            WrappedTextDisabled("Network comparison unavailable. Refresh Network before capturing both snapshots to include socket ownership changes.");
        }
        else if (state.newNetworkEmpty && state.closedNetworkEmpty)
        {
            WrappedTextDisabled("No network connection changes were observed.");
        }
        else if (callbacks.renderNetworkChanges)
        {
            callbacks.renderNetworkChanges();
        }

        ImGui::SeparatorText("Historical Legacy Source Evidence Changes");
        if (!state.findingsCompared)
        {
            WrappedTextDisabled("Historical legacy source evidence was not compared. Native selected-process changes and evidence-model mismatches are summarized under Notes and in compare exports.");
        }
        else if (state.newFindingsEmpty && state.removedFindingsEmpty && state.changedFindingsEmpty)
        {
            WrappedTextDisabled("No historical legacy source-finding or process-indicator changes were observed.");
        }
        else if (callbacks.renderFindingChanges)
        {
            callbacks.renderFindingChanges();
        }
    }
}
