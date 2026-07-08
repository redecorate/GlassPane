#pragma once

#include "imgui.h"

#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace GlassPane::UI
{
    enum class LogsPanelLevel
    {
        Info,
        Warning,
        High
    };

    struct LogPanelEntryView
    {
        LogsPanelLevel level = LogsPanelLevel::Info;
        std::string_view message;
    };

    struct LogsPanelContext
    {
        std::vector<LogPanelEntryView> entries;
        ImFont* monospaceFont = nullptr;
        ImVec4 accentColor = ImVec4(0.55f, 0.72f, 0.92f, 1.0f);
        ImVec4 mutedTextColor = ImVec4(0.65f, 0.70f, 0.78f, 1.0f);
        ImVec4 consoleBgColor = ImVec4(0.025f, 0.035f, 0.048f, 1.0f);
        ImVec4 panelBorderColor = ImVec4(0.16f, 0.22f, 0.30f, 1.0f);
        std::function<void()> onClear;
        std::function<void()> onSave;
    };

    struct IndicatorItemView
    {
        std::wstring text;
        bool hasSeverity = false;
        std::string severityLabel;
        ImVec4 severityColor = ImVec4(0.65f, 0.70f, 0.78f, 1.0f);
    };

    struct IndicatorsPanelContext
    {
        bool hasSelectedProcess = false;
        std::vector<IndicatorItemView> processIndicators;
        std::vector<std::wstring> chainIndicators;
        std::vector<std::wstring> moduleIndicators;
        std::string compareSummary;
    };

    struct LogsAndIndicatorsPanelContext
    {
        LogsPanelContext logs;
        IndicatorsPanelContext indicators;
    };

    void RenderLogsPanelContent(const LogsPanelContext& context);
    void RenderIndicatorsPanelContent(const IndicatorsPanelContext& context);
    void RenderLogsAndIndicatorsPanel(const LogsAndIndicatorsPanelContext& context);
}
