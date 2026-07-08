#include "ComparePanel.h"

#include <algorithm>

namespace GlassPane::UI
{
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
    }

    void RenderComparePanel(
        const ComparePanelState& state,
        const ComparePanelCallbacks& callbacks,
        ImFont* titleFont,
        const ImVec4& accentColor)
    {
        const bool pushedTitleFont = PushFontIfAvailable(titleFont);
        ImGui::TextColored(accentColor, "Snapshot Compare");
        PopFontIfPushed(pushedTitleFont);
        WrappedTextDisabled("Compare local in-memory snapshots. Changes are evidence worth reviewing, not proof of malicious activity.");
        WrappedTextDisabled("Capture Baseline and Capture Current refresh the process snapshot first. Capture Current replaces the previous current snapshot and compares it to the baseline.");
        ImGui::Spacing();

        if (ImGui::Button("Capture Baseline##Compare") && callbacks.captureBaseline)
        {
            callbacks.captureBaseline();
        }
        SameLineIfFits(StandardButtonWidth("Capture Current"), 8.0f);
        if (ImGui::Button("Capture Current##Compare") && callbacks.captureCurrent)
        {
            callbacks.captureCurrent();
        }
        SameLineIfFits(StandardButtonWidth("Clear Compare"), 8.0f);
        if (ImGui::Button("Clear Compare##Compare") && callbacks.clearCompare)
        {
            callbacks.clearCompare();
        }
        SameLineIfFits(StandardButtonWidth("Copy Compare Summary"), 8.0f);
        if (ImGui::Button("Copy Compare Summary##Compare") && callbacks.copySummary)
        {
            callbacks.copySummary();
        }
        SameLineIfFits(StandardButtonWidth("Export Compare Report"), 8.0f);
        if (ImGui::Button("Export Compare Report##Compare") && callbacks.exportReport)
        {
            callbacks.exportReport();
        }

        ImGui::Spacing();
        if (callbacks.renderSummary)
        {
            callbacks.renderSummary();
        }
        ImGui::Separator();

        if (!state.baselineCaptured && !state.currentCaptured)
        {
            WrappedTextDisabled("Capture a baseline snapshot, then capture a current snapshot to compare changes.");
            return;
        }
        if (state.baselineCaptured && !state.currentCaptured)
        {
            WrappedTextDisabled("Baseline captured. Capture a current snapshot to compare changes.");
            return;
        }
        if (!state.baselineCaptured && state.currentCaptured)
        {
            WrappedTextDisabled("Current snapshot captured. Capture a baseline snapshot to compare changes.");
            return;
        }
        if (!state.resultValid)
        {
            WrappedTextDisabled("Capture both snapshots to compute a comparison.");
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

        ImGui::SeparatorText("Finding Changes");
        if (!state.findingsCompared)
        {
            WrappedTextDisabled("Finding comparison unavailable.");
        }
        else if (state.newFindingsEmpty && state.removedFindingsEmpty && state.changedFindingsEmpty)
        {
            WrappedTextDisabled("No finding or process indicator changes were observed.");
        }
        else if (callbacks.renderFindingChanges)
        {
            callbacks.renderFindingChanges();
        }
    }
}
