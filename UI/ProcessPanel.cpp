#include "ProcessPanel.h"

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

        std::string DisplayName(const std::wstring& value)
        {
            try
            {
                if (value.empty())
                {
                    return "(unknown)";
                }

                constexpr std::size_t MaxDisplayCharacters = 256;
                const std::string displayName = WideToUtf8(value.substr(0, MaxDisplayCharacters));
                if (displayName.empty())
                {
                    return "(unknown)";
                }

                return displayName;
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

        ImVec4 CardBg()
        {
            return ImVec4(0.040f, 0.054f, 0.076f, 1.0f);
        }

        ImVec4 PanelHover()
        {
            return ImVec4(0.060f, 0.082f, 0.118f, 1.0f);
        }

        ImVec4 PanelBorder()
        {
            return ImVec4(0.105f, 0.140f, 0.195f, 1.0f);
        }

        void SeverityText(Core::Severity severity)
        {
            ImGui::TextColored(SeverityColor(severity), "%s", WideToUtf8(Core::SeverityToString(severity)).c_str());
        }

        bool ChipButton(const char* label, bool active, const ImVec4& accent)
        {
            const ImVec4 inactive = CardBg();
            ImGui::PushStyleColor(ImGuiCol_Button, active ? ImVec4(accent.x * 0.30f, accent.y * 0.30f, accent.z * 0.30f, 1.0f) : inactive);
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, active ? ImVec4(accent.x * 0.40f, accent.y * 0.40f, accent.z * 0.40f, 1.0f) : PanelHover());
            ImGui::PushStyleColor(ImGuiCol_ButtonActive, active ? ImVec4(accent.x * 0.50f, accent.y * 0.50f, accent.z * 0.50f, 1.0f) : ImVec4(0.105f, 0.155f, 0.220f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_Border, active ? ImVec4(accent.x, accent.y, accent.z, 0.65f) : PanelBorder());
            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(10.0f, 5.0f));
            const bool clicked = ImGui::Button(label, ImVec2(0.0f, 29.0f));
            ImGui::PopStyleVar();
            ImGui::PopStyleColor();
            if (active)
            {
                const ImVec2 min = ImGui::GetItemRectMin();
                const ImVec2 max = ImGui::GetItemRectMax();
                ImGui::GetWindowDrawList()->AddRect(min, max, ColorU32(ImVec4(accent.x, accent.y, accent.z, 0.70f)), 6.0f, 0, 1.3f);
                ImGui::GetWindowDrawList()->AddRectFilled(
                    ImVec2(min.x + 8.0f, max.y - 3.0f),
                    ImVec2(max.x - 8.0f, max.y - 1.0f),
                    ColorU32(ImVec4(accent.x, accent.y, accent.z, 0.85f)),
                    2.0f);
            }
            ImGui::PopStyleColor(3);
            return clicked;
        }

        float ChipButtonWidth(const char* label)
        {
            return ImGui::CalcTextSize(label).x + 20.0f;
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

        void SameLineIfChipFits(const char* nextLabel, float spacing = 4.0f)
        {
            SameLineIfFits(ChipButtonWidth(nextLabel), spacing);
        }

        void AcknowledgeTableAutoSizeRequest(bool* needsAutoSize)
        {
            if (needsAutoSize != nullptr)
            {
                *needsAutoSize = false;
            }
        }

        const char* ActiveChipLabel(ProcessFilterMode mode)
        {
            switch (mode)
            {
            case ProcessFilterMode::All:
                return "All";
            case ProcessFilterMode::Suspicious:
                return "Suspicious";
            case ProcessFilterMode::Low:
                return "Low";
            case ProcessFilterMode::Medium:
                return "Medium";
            case ProcessFilterMode::High:
                return "High";
            default:
                return "All";
            }
        }
    }

    void RenderProcessPanelContent(const ProcessPanelContext& context)
    {
        if (context.snapshot == nullptr || context.visibleRows == nullptr)
        {
            ImGui::TextDisabled("No process snapshot available.");
            return;
        }

        const Core::ProcessSnapshot& snapshot = *context.snapshot;
        const std::vector<VisibleProcessRow>& visibleRows = *context.visibleRows;
        ProcessFilterMode activeFilter = context.activeFilter;

        const bool pushedProcessesFont = PushFontIfAvailable(context.boldFont);
        ImGui::TextColored(context.accentColor, "Processes");
        PopFontIfPushed(pushedProcessesFont);
        ImGui::SameLine();
        ImGui::TextDisabled("%zu total", snapshot.processes.size());
        const bool pushedProcessHelperFont = PushFontIfAvailable(context.smallUiFont);
        ImGui::TextColored(context.mutedTextColor, "Search combines with the active preset");
        if (context.searchActive)
        {
            ImGui::SameLine();
            ImGui::TextColored(context.accentColor, "search active");
        }
        PopFontIfPushed(pushedProcessHelperFont);

        ImGui::PushID("process_filter_chips");
        if (ChipButton("All##ProcessFilter", activeFilter == ProcessFilterMode::All, context.accentColor) &&
            context.onFilterModeChanged)
        {
            context.onFilterModeChanged(ProcessFilterMode::All);
            activeFilter = ProcessFilterMode::All;
        }
        SameLineIfChipFits("Suspicious");
        if (ChipButton("Suspicious##ProcessFilter", activeFilter == ProcessFilterMode::Suspicious, SeverityColor(Core::Severity::High)) &&
            context.onFilterModeChanged)
        {
            context.onFilterModeChanged(ProcessFilterMode::Suspicious);
            activeFilter = ProcessFilterMode::Suspicious;
        }
        SameLineIfChipFits("Low");
        if (ChipButton("Low##ProcessFilter", activeFilter == ProcessFilterMode::Low, SeverityColor(Core::Severity::Low)) &&
            context.onFilterModeChanged)
        {
            context.onFilterModeChanged(ProcessFilterMode::Low);
            activeFilter = ProcessFilterMode::Low;
        }
        SameLineIfChipFits("Medium");
        if (ChipButton("Medium##ProcessFilter", activeFilter == ProcessFilterMode::Medium, SeverityColor(Core::Severity::Medium)) &&
            context.onFilterModeChanged)
        {
            context.onFilterModeChanged(ProcessFilterMode::Medium);
            activeFilter = ProcessFilterMode::Medium;
        }
        SameLineIfChipFits("High");
        if (ChipButton("High##ProcessFilter", activeFilter == ProcessFilterMode::High, SeverityColor(Core::Severity::High)) &&
            context.onFilterModeChanged)
        {
            context.onFilterModeChanged(ProcessFilterMode::High);
            activeFilter = ProcessFilterMode::High;
        }
        ImGui::PopID();
        ImGui::TextDisabled("Active: %s", ActiveChipLabel(activeFilter));
        ImGui::Dummy(ImVec2(0.0f, 2.0f));

        const ImGuiTableFlags flags =
            ImGuiTableFlags_RowBg |
            ImGuiTableFlags_Resizable |
            ImGuiTableFlags_ScrollY |
            ImGuiTableFlags_SizingStretchProp |
            ImGuiTableFlags_NoSavedSettings;

        const float footerHeight = ImGui::GetFrameHeightWithSpacing() + 12.0f;
        if (visibleRows.empty())
        {
            ImGui::BeginChild(
                "process_empty_state",
                ImVec2(0.0f, -footerHeight),
                ImGuiChildFlags_None,
                ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
            ImGui::TextDisabled("No matching processes.");
            ImGui::EndChild();
        }
        else
        {
            AcknowledgeTableAutoSizeRequest(context.processTableNeedsAutoSize);
            if (ImGui::BeginTable("ProcessesTable##ProcessPanel", 4, flags, ImVec2(0.0f, -footerHeight)))
            {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn("Process", ImGuiTableColumnFlags_WidthStretch, 0.0f, 0);
                ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 58.0f, 1);
                ImGui::TableSetupColumn("PPID", ImGuiTableColumnFlags_WidthFixed, 58.0f, 2);
                ImGui::TableSetupColumn("Severity", ImGuiTableColumnFlags_WidthFixed, 86.0f, 3);
                ImGui::TableHeadersRow();

                ImGuiListClipper clipper;
                clipper.Begin(static_cast<int>(visibleRows.size()));
                while (clipper.Step())
                {
                    for (int rowIndex = clipper.DisplayStart; rowIndex < clipper.DisplayEnd; ++rowIndex)
                    {
                        const VisibleProcessRow& row = visibleRows[static_cast<std::size_t>(rowIndex)];
                        if (row.processIndex >= snapshot.processes.size())
                        {
                            continue;
                        }

                        const Core::ProcessInfo& process = snapshot.processes[row.processIndex];
                        const bool selected = context.selectedPid == process.pid;
                        ImGui::TableNextRow();
                        if (selected)
                        {
                            const ImU32 selectedRow = ColorU32(context.selectedRowColor);
                            ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, selectedRow);
                            ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1, selectedRow);
                        }
                        ImGui::PushID(static_cast<int>(process.pid));

                        ImGui::TableSetColumnIndex(0);
                        ImGui::Indent(static_cast<float>(row.depth) * 16.0f);
                        const std::string name = DisplayName(process.name);
                        if (ImGui::Selectable(name.c_str(), selected, ImGuiSelectableFlags_SpanAllColumns, ImVec2(0.0f, 32.0f)) &&
                            context.onSelectProcess)
                        {
                            context.onSelectProcess(process.pid);
                        }
                        if (selected)
                        {
                            const ImVec2 min = ImGui::GetItemRectMin();
                            const ImVec2 max = ImGui::GetItemRectMax();
                            ImGui::GetWindowDrawList()->AddRectFilled(
                                min,
                                ImVec2(min.x + 3.0f, max.y),
                                ColorU32(context.accentColor),
                                2.0f);
                            if (context.scrollSelectedProcessIntoView != nullptr && *context.scrollSelectedProcessIntoView)
                            {
                                ImGui::SetScrollHereY(0.5f);
                                *context.scrollSelectedProcessIntoView = false;
                            }
                        }
                        ImGui::Unindent(static_cast<float>(row.depth) * 16.0f);

                        const bool pushedPidFont = PushFontIfAvailable(context.monospaceFont);
                        ImGui::TableSetColumnIndex(1);
                        ImGui::Text("%u", process.pid);
                        ImGui::TableSetColumnIndex(2);
                        ImGui::Text("%u", process.parentPid);
                        PopFontIfPushed(pushedPidFont);
                        ImGui::TableSetColumnIndex(3);
                        SeverityText(row.filterSeverity);

                        ImGui::PopID();
                    }
                }

                ImGui::EndTable();
            }
        }
        ImGui::TextDisabled("%zu processes", snapshot.processes.size());
        ImGui::SameLine();
        ImGui::TextDisabled("|");
        ImGui::SameLine();
        ImGui::TextColored(SeverityColor(Core::Severity::High), "%zu suspicious", context.suspiciousCount);
        ImGui::SameLine();
        ImGui::TextDisabled("| %zu visible", visibleRows.size());
    }
}
