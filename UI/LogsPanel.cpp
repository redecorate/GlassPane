#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "LogsPanel.h"
#include "UiHelpers.h"

#include <Windows.h>

#include <algorithm>

namespace GlassPane::UI
{
    namespace
    {
        std::string WideToUtf8(const std::wstring& value)
        {
            if (value.empty())
            {
                return {};
            }

            const int required = WideCharToMultiByte(
                CP_UTF8,
                0,
                value.data(),
                static_cast<int>(value.size()),
                nullptr,
                0,
                nullptr,
                nullptr);
            if (required <= 0)
            {
                return {};
            }

            std::string result(static_cast<std::size_t>(required), '\0');
            WideCharToMultiByte(
                CP_UTF8,
                0,
                value.data(),
                static_cast<int>(value.size()),
                result.data(),
                required,
                nullptr,
                nullptr);
            return result;
        }

        bool PushLogsFontIfAvailable(ImFont* font)
        {
            if (font == nullptr)
            {
                return false;
            }

            ImGui::PushFont(font);
            return true;
        }

        void PopLogsFontIfPushed(bool pushed)
        {
            if (pushed)
            {
                ImGui::PopFont();
            }
        }

        void RenderWrappedLogWide(const std::wstring& value)
        {
            const std::string text = WideToUtf8(value);
            ImGui::PushTextWrapPos(0.0f);
            ImGui::TextUnformatted(text.c_str());
            ImGui::PopTextWrapPos();
        }

        void RenderWrappedLogDisabled(const std::string& value)
        {
            ImGui::PushTextWrapPos(0.0f);
            ImGui::TextDisabled("%s", value.c_str());
            ImGui::PopTextWrapPos();
        }

        ImVec4 LogColor(LogsPanelLevel level)
        {
            switch (level)
            {
            case LogsPanelLevel::High:
                return ImVec4(0.96f, 0.24f, 0.22f, 1.0f);
            case LogsPanelLevel::Warning:
                return ImVec4(0.96f, 0.52f, 0.20f, 1.0f);
            case LogsPanelLevel::Info:
            default:
                return ImVec4(0.55f, 0.72f, 0.92f, 1.0f);
            }
        }

        const char* LogLevelLabel(LogsPanelLevel level)
        {
            switch (level)
            {
            case LogsPanelLevel::High:
                return "HIGH";
            case LogsPanelLevel::Warning:
                return "WARN";
            case LogsPanelLevel::Info:
            default:
                return "INFO";
            }
        }

    }

    void RenderLogsPanelContent(const LogsPanelContext& context)
    {
        const ImVec2 headerStart = ImGui::GetCursorScreenPos();
        const float contentRight = headerStart.x + ImGui::GetContentRegionAvail().x;
        PushGlassButtonStyle();
        const float clearWidth = ImGui::CalcTextSize("Clear").x + ImGui::GetStyle().FramePadding.x * 2.0f;
        const float saveWidth = ImGui::CalcTextSize("Save").x + ImGui::GetStyle().FramePadding.x * 2.0f;
        const float buttonSpacing = ImGui::GetStyle().ItemSpacing.x;
        const float buttonsWidth = clearWidth + saveWidth + buttonSpacing;
        const float titleWidth =
            ImGui::CalcTextSize("Console").x +
            ImGui::CalcTextSize("000 entries").x +
            8.0f;
        const bool actionsFitHeader = ImGui::GetContentRegionAvail().x >= titleWidth + buttonsWidth + 18.0f;
        const bool hasEntries = !context.entries.empty();

        ImGui::AlignTextToFramePadding();
        ImGui::TextColored(context.accentColor, "Console");
        ImGui::SameLine(0.0f, 8.0f);
        ImGui::TextColored(context.mutedTextColor, "%zu entries", context.entries.size());

        const float actionY = actionsFitHeader ? headerStart.y : ImGui::GetCursorScreenPos().y;
        ImGui::SetCursorScreenPos(ImVec2(std::max(headerStart.x, contentRight - buttonsWidth), actionY));
        if (!hasEntries)
        {
            ImGui::BeginDisabled();
        }
        if (ImGui::Button("Clear", ImVec2(clearWidth, 0.0f)) && context.onClear)
        {
            context.onClear();
        }
        if (!hasEntries)
        {
            ImGui::EndDisabled();
            RenderDisabledReasonTooltip("There are no log entries to clear.");
        }
        ImGui::SameLine(0.0f, buttonSpacing);
        if (!hasEntries)
        {
            ImGui::BeginDisabled();
        }
        if (ImGui::Button("Save", ImVec2(saveWidth, 0.0f)) && context.onSave)
        {
            context.onSave();
        }
        if (!hasEntries)
        {
            ImGui::EndDisabled();
            RenderDisabledReasonTooltip("There are no log entries to save.");
        }
        PopGlassButtonStyle();

        const ImVec2 separatorStart = ImGui::GetCursorScreenPos();
        ImGui::GetWindowDrawList()->AddLine(
            separatorStart,
            ImVec2(separatorStart.x + ImGui::GetContentRegionAvail().x, separatorStart.y),
            ImGui::ColorConvertFloat4ToU32(ImVec4(
                context.panelBorderColor.x,
                context.panelBorderColor.y,
                context.panelBorderColor.z,
                0.62f)),
            1.0f);
        ImGui::Dummy(ImVec2(0.0f, 5.0f));

        ImGui::PushStyleColor(ImGuiCol_ChildBg, context.consoleBgColor);
        ImGui::PushStyleColor(ImGuiCol_Border, context.panelBorderColor);
        ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 6.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(9.0f, 7.0f));
        ImGui::BeginChild("log_console", ImVec2(0.0f, 0.0f), ImGuiChildFlags_Borders | ImGuiChildFlags_AlwaysUseWindowPadding);
        const bool pushedLogFont = PushLogsFontIfAvailable(context.monospaceFont);
        if (context.entries.empty())
        {
            RenderEmptyState(
                "No log entries are available.",
                "Application actions and collection results will appear here.");
        }
        else
        {
            const ImGuiTableFlags tableFlags =
                ImGuiTableFlags_SizingFixedFit |
                ImGuiTableFlags_NoSavedSettings |
                ImGuiTableFlags_NoPadOuterX;
            ImGui::PushStyleVar(ImGuiStyleVar_CellPadding, ImVec2(5.0f, 2.0f));
            if (ImGui::BeginTable("log_rows", 3, tableFlags))
            {
                const float timestampWidth = ImGui::CalcTextSize("0000-00-00 00:00:00").x + 8.0f;
                const float levelWidth = ImGui::CalcTextSize("[HIGH]").x + 8.0f;
                ImGui::TableSetupColumn("Timestamp", ImGuiTableColumnFlags_WidthFixed, timestampWidth);
                ImGui::TableSetupColumn("Level", ImGuiTableColumnFlags_WidthFixed, levelWidth);
                ImGui::TableSetupColumn("Message", ImGuiTableColumnFlags_WidthStretch);

                for (const LogPanelEntryView& entry : context.entries)
                {
                    std::string timestamp;
                    std::string message(entry.message);
                    if (entry.message.size() > 21 && entry.message[4] == '-' && entry.message[13] == ':')
                    {
                        timestamp = std::string(entry.message.substr(0, 19));
                        message = std::string(entry.message.substr(21));
                    }

                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    ImGui::TextColored(context.mutedTextColor, "%s", timestamp.empty() ? "-" : timestamp.c_str());
                    ImGui::TableSetColumnIndex(1);
                    ImGui::TextColored(LogColor(entry.level), "[%s]", LogLevelLabel(entry.level));
                    ImGui::TableSetColumnIndex(2);
                    ImGui::PushTextWrapPos(0.0f);
                    ImGui::TextUnformatted(message.c_str());
                    ImGui::PopTextWrapPos();
                }

                ImGui::EndTable();
            }
            ImGui::PopStyleVar();
        }
        PopLogsFontIfPushed(pushedLogFont);
        ImGui::EndChild();
        ImGui::PopStyleVar(3);
        ImGui::PopStyleColor(2);
    }

    void RenderSourceEvidencePanelContent(const SourceEvidencePanelContext& context)
    {
        if (!context.hasSelectedProcess)
        {
            RenderEmptyState("No process is selected.", "Select a process to review source evidence.");
            return;
        }

        ImGui::TextDisabled(
            context.historical ? "Historical Source Evidence" : "Native Source Evidence");
        if (context.records.empty())
        {
            RenderEmptyState(
                context.historical
                    ? "No historical source records are available."
                    : "No native source-evidence records are available.");
        }
        else
        {
            for (const SourceEvidenceItemView& record : context.records)
            {
                ImGui::Bullet();
                ImGui::SameLine();
                RenderWrappedLogWide(record.title);
                if (!record.metadata.empty() || !record.role.empty())
                {
                    ImGui::Indent();
                    if (!record.metadata.empty())
                    {
                        RenderWrappedLogDisabled(record.metadata);
                    }
                    if (!record.role.empty())
                    {
                        RenderWrappedLogDisabled(record.role);
                    }
                    ImGui::Unindent();
                }
                if (!record.summary.empty() && record.summary != record.title)
                {
                    ImGui::Indent();
                    RenderWrappedLogWide(record.summary);
                    ImGui::Unindent();
                }
            }
        }

        if (!context.compareSummary.empty())
        {
            ImGui::Separator();
            ImGui::TextDisabled("Snapshot Compare");
            RenderWrappedLogDisabled(context.compareSummary);
        }
    }

    void RenderLogsAndEvidencePanel(const LogsAndEvidencePanelContext& context)
    {
        if (ImGui::BeginTabBar(
                "bottom_tabs",
                ImGuiTabBarFlags_DrawSelectedOverline |
                    ImGuiTabBarFlags_FittingPolicyShrink |
                    ImGuiTabBarFlags_NoTabListScrollingButtons))
        {
            if (ImGui::BeginTabItem("Logs"))
            {
                RenderLogsPanelContent(context.logs);
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Source Evidence"))
            {
                RenderSourceEvidencePanelContent(context.evidence);
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }
    }

    void RenderAppStatusBar(const AppStatusBarContext& context)
    {
        const ImGuiViewport* viewport = ImGui::GetMainViewport();
        const ImVec2 barPosition(
            viewport->WorkPos.x,
            viewport->WorkPos.y + viewport->WorkSize.y - AppStatusBarHeight);
        const ImVec2 barSize(viewport->WorkSize.x, AppStatusBarHeight);

        ImGui::SetNextWindowPos(barPosition, ImGuiCond_Always);
        ImGui::SetNextWindowSize(barSize, ImGuiCond_Always);
        ImGui::SetNextWindowViewport(viewport->ID);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(12.0f, 5.0f));
        ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
        ImGui::PushStyleColor(ImGuiCol_WindowBg, context.backgroundColor);
        ImGui::Begin(
            "Status##GlassPaneStatusBar",
            nullptr,
            ImGuiWindowFlags_NoTitleBar |
                ImGuiWindowFlags_NoCollapse |
                ImGuiWindowFlags_NoResize |
                ImGuiWindowFlags_NoMove |
                ImGuiWindowFlags_NoSavedSettings |
                ImGuiWindowFlags_NoDocking |
                ImGuiWindowFlags_NoNav |
                ImGuiWindowFlags_NoFocusOnAppearing);

        ImDrawList* drawList = ImGui::GetWindowDrawList();
        drawList->AddLine(
            barPosition,
            ImVec2(barPosition.x + barSize.x, barPosition.y),
            ImGui::ColorConvertFloat4ToU32(context.borderColor),
            1.0f);

        std::string rightText = context.osBuild;
        if (!context.architecture.empty())
        {
            if (!rightText.empty())
            {
                rightText += "  |  ";
            }
            rightText += context.architecture;
        }

        const ImVec2 rowStart = ImGui::GetCursorScreenPos();
        const float textHeight = ImGui::GetTextLineHeight();
        constexpr float DotRadius = 3.5f;
        drawList->AddCircleFilled(
            ImVec2(rowStart.x + DotRadius, rowStart.y + textHeight * 0.5f),
            DotRadius,
            ImGui::ColorConvertFloat4ToU32(context.indicatorColor));
        ImGui::Dummy(ImVec2(DotRadius * 2.0f, textHeight));
        ImGui::SameLine(0.0f, 6.0f);
        const float statusStartX = ImGui::GetCursorScreenPos().x;
        const float contentRight = barPosition.x + barSize.x - ImGui::GetStyle().WindowPadding.x;
        float rightWidth = ImGui::CalcTextSize(rightText.c_str()).x;
        float rightX = contentRight - rightWidth;
        constexpr float MinimumStatusWidth = 120.0f;
        if (!rightText.empty() && rightX < statusStartX + MinimumStatusWidth + 18.0f && !context.architecture.empty())
        {
            rightText = context.architecture;
            rightWidth = ImGui::CalcTextSize(rightText.c_str()).x;
            rightX = contentRight - rightWidth;
        }
        if (!rightText.empty() && rightX < statusStartX + MinimumStatusWidth + 18.0f)
        {
            rightText.clear();
            rightWidth = 0.0f;
            rightX = contentRight;
        }

        const float statusRight = rightText.empty() ? contentRight : rightX - 18.0f;
        const float statusWidth = std::max(40.0f, statusRight - statusStartX);
        const std::string clippedStatus = EllipsizeToWidth(context.statusText, statusWidth);
        ImGui::PushStyleColor(ImGuiCol_Text, context.textColor);
        ImGui::TextUnformatted(clippedStatus.c_str());
        ImGui::PopStyleColor();
        if (ImGui::IsItemHovered())
        {
            std::string tooltip;
            if (clippedStatus != context.statusText)
            {
                tooltip = context.statusText + "\n\n";
            }
            if (context.statusText == "Ready")
            {
                tooltip += "Ready means GlassPane is idle; it does not describe endpoint health.";
            }
            else if (context.statusText.rfind("Working:", 0) == 0)
            {
                tooltip += "A user-requested operation is currently running.";
            }
            else if (context.statusText.rfind("Failed:", 0) == 0)
            {
                tooltip += "The last operation failed. Review Operation Status and the logs for details.";
            }
            else
            {
                tooltip += "The last operation completed. Acknowledge its result to return to Ready.";
            }
            RenderWrappedTooltip(tooltip, 420.0f);
        }

        if (!rightText.empty())
        {
            ImGui::SetCursorScreenPos(ImVec2(rightX, rowStart.y));
            ImGui::TextColored(context.mutedTextColor, "%s", rightText.c_str());
        }

        ImGui::End();
        ImGui::PopStyleColor();
        ImGui::PopStyleVar(3);
    }
}
