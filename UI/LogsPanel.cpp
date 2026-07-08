#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "LogsPanel.h"

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

        void WrappedTextWide(const std::wstring& value)
        {
            const std::string text = WideToUtf8(value);
            ImGui::PushTextWrapPos(0.0f);
            ImGui::TextUnformatted(text.c_str());
            ImGui::PopTextWrapPos();
        }

        void WrappedTextDisabled(const std::string& value)
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

        void RenderIndicatorList(const std::vector<std::wstring>& indicators)
        {
            if (indicators.empty())
            {
                ImGui::TextUnformatted("None");
                return;
            }

            for (const std::wstring& indicator : indicators)
            {
                ImGui::Bullet();
                ImGui::SameLine();
                WrappedTextWide(indicator);
            }
        }
    }

    void RenderLogsPanelContent(const LogsPanelContext& context)
    {
        ImGui::TextColored(context.accentColor, "Console");
        ImGui::SameLine();
        ImGui::TextColored(context.mutedTextColor, "%zu entries", context.entries.size());
        const float buttonsWidth = ImGui::CalcTextSize("Clear").x + ImGui::CalcTextSize("Save").x + 54.0f;
        ImGui::SameLine(ImGui::GetCursorPosX() + std::max(0.0f, ImGui::GetContentRegionAvail().x - buttonsWidth));
        if (ImGui::Button("Clear") && context.onClear)
        {
            context.onClear();
        }
        ImGui::SameLine();
        if (ImGui::Button("Save") && context.onSave)
        {
            context.onSave();
        }

        ImGui::PushStyleColor(ImGuiCol_ChildBg, context.consoleBgColor);
        ImGui::PushStyleColor(ImGuiCol_Border, context.panelBorderColor);
        ImGui::BeginChild("log_console", ImVec2(0.0f, 0.0f), ImGuiChildFlags_Borders | ImGuiChildFlags_AlwaysUseWindowPadding);
        const bool pushedLogFont = PushFontIfAvailable(context.monospaceFont);
        for (const LogPanelEntryView& entry : context.entries)
        {
            std::string timestamp;
            std::string message(entry.message);
            if (entry.message.size() > 21 && entry.message[4] == '-' && entry.message[13] == ':')
            {
                timestamp = std::string(entry.message.substr(0, 19));
                message = std::string(entry.message.substr(21));
            }

            if (!timestamp.empty())
            {
                ImGui::TextDisabled("%s", timestamp.c_str());
                ImGui::SameLine(176.0f);
            }
            ImGui::TextColored(LogColor(entry.level), "[%s]", LogLevelLabel(entry.level));
            ImGui::SameLine();
            ImGui::TextWrapped("%s", message.c_str());
        }
        PopFontIfPushed(pushedLogFont);
        ImGui::EndChild();
        ImGui::PopStyleColor(2);
    }

    void RenderIndicatorsPanelContent(const IndicatorsPanelContext& context)
    {
        if (!context.hasSelectedProcess)
        {
            ImGui::TextUnformatted("No process selected.");
            return;
        }

        ImGui::TextDisabled("Process Indicators");
        if (context.processIndicators.empty())
        {
            ImGui::TextUnformatted("None");
        }
        else
        {
            for (const IndicatorItemView& indicator : context.processIndicators)
            {
                ImGui::Bullet();
                ImGui::SameLine();
                if (indicator.hasSeverity)
                {
                    ImGui::TextColored(indicator.severityColor, "%s", indicator.severityLabel.c_str());
                    ImGui::SameLine();
                }
                WrappedTextWide(indicator.text);
            }
        }

        ImGui::Separator();
        ImGui::TextDisabled("Chain Indicators");
        RenderIndicatorList(context.chainIndicators);

        if (!context.moduleIndicators.empty())
        {
            ImGui::Separator();
            ImGui::TextDisabled("Module Indicators");
            RenderIndicatorList(context.moduleIndicators);
        }

        if (!context.compareSummary.empty())
        {
            ImGui::Separator();
            ImGui::TextDisabled("Snapshot Compare");
            WrappedTextDisabled(context.compareSummary);
        }
    }

    void RenderLogsAndIndicatorsPanel(const LogsAndIndicatorsPanelContext& context)
    {
        if (ImGui::BeginTabBar("bottom_tabs"))
        {
            if (ImGui::BeginTabItem("Logs"))
            {
                RenderLogsPanelContent(context.logs);
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Indicators"))
            {
                RenderIndicatorsPanelContent(context.indicators);
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }
    }
}
