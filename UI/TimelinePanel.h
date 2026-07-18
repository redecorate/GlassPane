#pragma once

#include "../Core/TimelineModel.h"

#include "imgui.h"

#include <cstdint>
#include <functional>
#include <vector>

namespace GlassPane::UI
{
    struct TimelinePanelContext
    {
        const Core::ProcessSnapshot* snapshot = nullptr;
        const std::vector<Core::TimelineRow>* rows = nullptr;
        std::uint32_t selectedPid = 0;
        Core::TimelineFilter activeFilter = Core::TimelineFilter::All;

        bool* timelineTableNeedsAutoSize = nullptr;

        ImFont* monospaceFont = nullptr;
        ImVec4 selectedRowColor = ImVec4(0.075f, 0.155f, 0.235f, 1.0f);

        std::function<ImTextureID(const Core::ProcessInfo&)> resolveProcessIcon;
        std::function<void(Core::TimelineFilter)> onFilterChanged;
        std::function<void(std::uint32_t)> onSelectProcess;
    };

    void RenderTimelinePanelContent(const TimelinePanelContext& context);
}
