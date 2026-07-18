#pragma once

#include "../Core/ProcessInfo.h"

#include "imgui.h"

#include <cstdint>
#include <functional>
#include <vector>

namespace GlassPane::UI
{
    enum class ProcessFilterMode
    {
        All,
        Suspicious,
        Low,
        Medium,
        High
    };

    struct VisibleProcessRow
    {
        std::size_t processIndex = 0;
        std::size_t depth = 0;
        Core::Severity authoritySeverity = Core::Severity::None;
        bool triageUnavailable = false;
    };

    struct ProcessPanelContext
    {
        const Core::ProcessSnapshot* snapshot = nullptr;
        const std::vector<VisibleProcessRow>* visibleRows = nullptr;

        std::uint32_t selectedPid = 0;
        std::size_t suspiciousCount = 0;
        std::size_t unavailableCount = 0;
        ProcessFilterMode activeFilter = ProcessFilterMode::All;
        bool searchActive = false;

        bool* processTableNeedsAutoSize = nullptr;
        bool* scrollSelectedProcessIntoView = nullptr;

        ImFont* boldFont = nullptr;
        ImFont* smallUiFont = nullptr;
        ImFont* monospaceFont = nullptr;

        ImVec4 accentColor = ImVec4(0.36f, 0.62f, 0.88f, 1.0f);
        ImVec4 mutedTextColor = ImVec4(0.48f, 0.56f, 0.66f, 1.0f);
        ImVec4 selectedRowColor = ImVec4(0.075f, 0.155f, 0.235f, 1.0f);

        // All process surfaces receive textures from the ImGuiApp-owned
        // canonical resolver. Panels never extract or choose fallbacks.
        std::function<ImTextureID(const Core::ProcessInfo&)> resolveProcessIcon;
        std::function<void(ProcessFilterMode)> onFilterModeChanged;
        std::function<void(std::uint32_t)> onSelectProcess;
    };

    void RenderProcessPanelContent(const ProcessPanelContext& context);
}
