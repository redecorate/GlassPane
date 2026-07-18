#include "TimelinePanel.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <exception>
#include <string>

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

        std::string WideToUtf8(const std::wstring& value)
        {
            try
            {
                if (value.empty())
                {
                    return {};
                }

                constexpr std::size_t MaxDisplayCharacters = 4096;
                const std::size_t inputLength = std::min(value.size(), MaxDisplayCharacters);
                if (inputLength == 0)
                {
                    return {};
                }

                const int required = WideCharToMultiByte(
                    CP_UTF8,
                    0,
                    value.data(),
                    static_cast<int>(inputLength),
                    nullptr,
                    0,
                    nullptr,
                    nullptr);
                if (required <= 0)
                {
                    return "(invalid)";
                }

                std::string result(static_cast<std::size_t>(required), '\0');
                const int written = WideCharToMultiByte(
                    CP_UTF8,
                    0,
                    value.data(),
                    static_cast<int>(inputLength),
                    result.data(),
                    required,
                    nullptr,
                    nullptr);
                if (written <= 0)
                {
                    return "(invalid)";
                }

                return result;
            }
            catch (const std::exception&)
            {
                return "(invalid)";
            }
            catch (...)
            {
                return "(invalid)";
            }
        }

        ImVec4 SeverityColor(Core::Severity severity)
        {
            switch (severity)
            {
            case Core::Severity::High:
                return ImVec4(0.96f, 0.24f, 0.22f, 1.0f);
            case Core::Severity::Medium:
                return ImVec4(0.96f, 0.52f, 0.20f, 1.0f);
            case Core::Severity::Low:
                return ImVec4(0.82f, 0.70f, 0.36f, 1.0f);
            case Core::Severity::Info:
                return ImVec4(0.45f, 0.67f, 0.95f, 1.0f);
            case Core::Severity::None:
            default:
                return ImVec4(0.66f, 0.72f, 0.80f, 1.0f);
            }
        }

        ImU32 ColorU32(const ImVec4& color)
        {
            return ImGui::ColorConvertFloat4ToU32(color);
        }

        void TextWide(const std::wstring& value)
        {
            const std::string text = WideToUtf8(value);
            ImGui::TextUnformatted(text.c_str());
        }

        void SeverityText(Core::Severity severity)
        {
            ImGui::TextColored(SeverityColor(severity), "%s", WideToUtf8(Core::SeverityToString(severity)).c_str());
        }

        void AcknowledgeTableAutoSizeRequest(bool* needsAutoSize)
        {
            if (needsAutoSize != nullptr)
            {
                *needsAutoSize = false;
            }
        }
    }

    void RenderTimelinePanelContent(const TimelinePanelContext& context)
    {
        Core::TimelineFilter activeFilter = context.activeFilter;
        ImGui::TextUnformatted("Filter:");
        ImGui::SameLine();
        if (ImGui::RadioButton("All", activeFilter == Core::TimelineFilter::All) &&
            context.onFilterChanged)
        {
            context.onFilterChanged(Core::TimelineFilter::All);
            activeFilter = Core::TimelineFilter::All;
        }
        ImGui::SameLine();
        if (ImGui::RadioButton("Suspicious only", activeFilter == Core::TimelineFilter::SuspiciousOnly) &&
            context.onFilterChanged)
        {
            context.onFilterChanged(Core::TimelineFilter::SuspiciousOnly);
            activeFilter = Core::TimelineFilter::SuspiciousOnly;
        }
        ImGui::SameLine();
        if (ImGui::RadioButton("High severity only", activeFilter == Core::TimelineFilter::HighSeverityOnly) &&
            context.onFilterChanged)
        {
            context.onFilterChanged(Core::TimelineFilter::HighSeverityOnly);
            activeFilter = Core::TimelineFilter::HighSeverityOnly;
        }

        if (context.rows == nullptr)
        {
            ImGui::Spacing();
            ImGui::TextDisabled("No timeline data available.");
            return;
        }

        const std::vector<Core::TimelineRow>& visibleTimelineRows = *context.rows;
        const ImGuiTableFlags flags =
            ImGuiTableFlags_BordersInnerV |
            ImGuiTableFlags_RowBg |
            ImGuiTableFlags_Resizable |
            ImGuiTableFlags_ScrollY |
            ImGuiTableFlags_SizingStretchProp |
            ImGuiTableFlags_NoSavedSettings;
        if (visibleTimelineRows.empty())
        {
            ImGui::Spacing();
            ImGui::TextDisabled("No matching timeline rows.");
            return;
        }

        AcknowledgeTableAutoSizeRequest(context.timelineTableNeedsAutoSize);
        if (ImGui::BeginTable("TimelineTable##TimelinePanel", 5, flags))
        {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("Timestamp", ImGuiTableColumnFlags_WidthFixed, 150.0f);
            ImGui::TableSetupColumn("Process", ImGuiTableColumnFlags_WidthFixed, 190.0f);
            ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 70.0f);
            ImGui::TableSetupColumn("Parent", ImGuiTableColumnFlags_WidthFixed, 210.0f);
            ImGui::TableSetupColumn("Triage", ImGuiTableColumnFlags_WidthFixed, 110.0f);
            ImGui::TableHeadersRow();

            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(visibleTimelineRows.size()));
            while (clipper.Step())
            {
                for (int rowIndex = clipper.DisplayStart; rowIndex < clipper.DisplayEnd; ++rowIndex)
                {
                    const Core::TimelineRow& row = visibleTimelineRows[static_cast<std::size_t>(rowIndex)];

                    ImGui::TableNextRow();
                    if (row.pid == context.selectedPid)
                    {
                        const ImU32 selectedRow = ColorU32(context.selectedRowColor);
                        ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, selectedRow);
                        ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1, selectedRow);
                    }
                    ImGui::PushID(static_cast<int>(row.pid));

                    ImGui::TableSetColumnIndex(0);
                    const bool pushedTimelineTimeFont = PushFontIfAvailable(context.monospaceFont);
                    if (ImGui::Selectable(
                            WideToUtf8(row.hasCreationTime ? row.creationTimeLocal : L"(unavailable)").c_str(),
                            row.pid == context.selectedPid,
                            ImGuiSelectableFlags_SpanAllColumns,
                            ImVec2(0.0f, 24.0f)) &&
                        context.onSelectProcess)
                    {
                        context.onSelectProcess(row.pid);
                    }
                    PopFontIfPushed(pushedTimelineTimeFont);

                    ImGui::TableSetColumnIndex(1);
                    if (context.snapshot != nullptr &&
                        row.sourceProcessIndex < context.snapshot->processes.size() &&
                        context.resolveProcessIcon)
                    {
                        const Core::ProcessInfo& process =
                            context.snapshot->processes[row.sourceProcessIndex];
                        const ImTextureID processIcon = context.resolveProcessIcon(process);
                        if (processIcon != ImTextureID{})
                        {
                            ImGui::Image(processIcon, ImVec2(16.0f, 16.0f));
                            ImGui::SameLine(0.0f, 6.0f);
                        }
                    }
                    TextWide(row.processName.empty() ? L"(unknown)" : row.processName);
                    ImGui::TableSetColumnIndex(2);
                    const bool pushedTimelinePidFont = PushFontIfAvailable(context.monospaceFont);
                    ImGui::Text("%u", row.pid);
                    PopFontIfPushed(pushedTimelinePidFont);
                    ImGui::TableSetColumnIndex(3);
                    std::wstring parentText;
                    if (row.parentPid != 0)
                    {
                        parentText = std::to_wstring(row.parentPid);
                        if (!row.parentName.empty())
                        {
                            parentText += L" ";
                            parentText += row.parentName;
                        }
                    }
                    TextWide(parentText);
                    ImGui::TableSetColumnIndex(4);
                    if (row.authorityAvailable)
                    {
                        if (row.severity == Core::Severity::None)
                        {
                            ImGui::TextDisabled("Informational");
                        }
                        else
                        {
                            SeverityText(row.severity);
                        }
                    }
                    else
                    {
                        ImGui::TextDisabled("Unavailable");
                    }

                    ImGui::PopID();
                }
            }
            ImGui::EndTable();
        }
    }
}
