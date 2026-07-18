#pragma once

#include "imgui.h"

#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace GlassPane::UI
{
    inline constexpr float AppStatusBarHeight = 28.0f;

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

    struct SourceEvidenceItemView
    {
        std::wstring title;
        std::wstring summary;
        std::string metadata;
        std::string role;
    };

    struct SourceEvidencePanelContext
    {
        bool hasSelectedProcess = false;
        bool historical = false;
        std::vector<SourceEvidenceItemView> records;
        std::string compareSummary;
    };

    struct LogsAndEvidencePanelContext
    {
        LogsPanelContext logs;
        SourceEvidencePanelContext evidence;
    };

    struct AppStatusBarContext
    {
        std::string statusText = "Ready";
        std::string osBuild;
        std::string architecture;
        ImVec4 indicatorColor = ImVec4(0.32f, 0.74f, 0.46f, 1.0f);
        ImVec4 textColor = ImVec4(0.86f, 0.90f, 0.95f, 1.0f);
        ImVec4 mutedTextColor = ImVec4(0.58f, 0.66f, 0.76f, 1.0f);
        ImVec4 backgroundColor = ImVec4(0.025f, 0.035f, 0.048f, 1.0f);
        ImVec4 borderColor = ImVec4(0.16f, 0.22f, 0.30f, 1.0f);
    };

    void RenderLogsPanelContent(const LogsPanelContext& context);
    void RenderSourceEvidencePanelContent(const SourceEvidencePanelContext& context);
    void RenderLogsAndEvidencePanel(const LogsAndEvidencePanelContext& context);
    void RenderAppStatusBar(const AppStatusBarContext& context);
}
