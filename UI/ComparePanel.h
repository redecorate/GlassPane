#pragma once

#include "imgui.h"

#include <functional>

namespace GlassPane::UI
{
    struct ComparePanelState
    {
        bool baselineCaptured = false;
        bool currentCaptured = false;
        bool resultValid = false;
        bool noDifferences = false;
        bool hasNotes = false;
        bool newProcessesEmpty = true;
        bool exitedProcessesEmpty = true;
        bool changedProcessesEmpty = true;
        bool networkCompared = false;
        bool newNetworkEmpty = true;
        bool closedNetworkEmpty = true;
        bool findingsCompared = false;
        bool newFindingsEmpty = true;
        bool removedFindingsEmpty = true;
        bool changedFindingsEmpty = true;
    };

    struct ComparePanelCallbacks
    {
        std::function<void()> captureBaseline;
        std::function<void()> captureCurrent;
        std::function<void()> clearCompare;
        std::function<void()> copySummary;
        std::function<void()> renderSummary;
        std::function<void()> renderNotes;
        std::function<void()> renderNewProcesses;
        std::function<void()> renderExitedProcesses;
        std::function<void()> renderChangedProcesses;
        std::function<void()> renderNetworkChanges;
        std::function<void()> renderFindingChanges;
    };

    void RenderComparePanel(
        const ComparePanelState& state,
        const ComparePanelCallbacks& callbacks,
        ImFont* titleFont,
        const ImVec4& accentColor);
}
