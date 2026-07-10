#include "ProcessPanel.h"

#include "imgui_internal.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <shellapi.h>

#include <algorithm>
#include <cstring>
#include <cwctype>
#include <exception>
#include <memory>
#include <string>
#include <unordered_map>

namespace GlassPane::UI
{
    void PushGlassChipStyle(bool active, const ImVec4& accent);
    void PopGlassChipStyle();
    ImVec4 GlassSelectedRowColor(const ImVec4& accent);
    std::string EllipsizeToWidth(const std::string& value, float maxWidth);

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

        ImVec4 RowTint(Core::Severity severity)
        {
            if (Core::SeverityRank(severity) >= Core::SeverityRank(Core::Severity::High))
            {
                return ImVec4(0.36f, 0.08f, 0.08f, 0.18f);
            }
            if (Core::SeverityRank(severity) >= Core::SeverityRank(Core::Severity::Medium))
            {
                return ImVec4(0.32f, 0.16f, 0.05f, 0.13f);
            }
            if (Core::SeverityRank(severity) >= Core::SeverityRank(Core::Severity::Low))
            {
                return ImVec4(0.25f, 0.22f, 0.10f, 0.10f);
            }
            return ImVec4(0.0f, 0.0f, 0.0f, 0.0f);
        }

        ImVec4 SelectedProcessRowColor(const ImVec4& accent)
        {
            return GlassSelectedRowColor(accent);
        }

        std::wstring NormalizeIconCacheKey(const std::wstring& path)
        {
            std::wstring key = path;
            std::transform(key.begin(), key.end(), key.begin(), [](wchar_t character) {
                return static_cast<wchar_t>(std::towlower(character));
            });
            return key;
        }

        bool RasterizeIcon(HICON icon, ImTextureData& texture)
        {
            if (icon == nullptr)
            {
                return false;
            }

            constexpr int TextureSize = 16;
            BITMAPINFO bitmapInfo = {};
            bitmapInfo.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
            bitmapInfo.bmiHeader.biWidth = TextureSize;
            bitmapInfo.bmiHeader.biHeight = -TextureSize;
            bitmapInfo.bmiHeader.biPlanes = 1;
            bitmapInfo.bmiHeader.biBitCount = 32;
            bitmapInfo.bmiHeader.biCompression = BI_RGB;

            HDC screenDc = GetDC(nullptr);
            if (screenDc == nullptr)
            {
                return false;
            }

            void* bitmapBits = nullptr;
            HBITMAP bitmap = CreateDIBSection(screenDc, &bitmapInfo, DIB_RGB_COLORS, &bitmapBits, nullptr, 0);
            if (bitmap == nullptr || bitmapBits == nullptr)
            {
                if (bitmap != nullptr)
                {
                    DeleteObject(bitmap);
                }
                ReleaseDC(nullptr, screenDc);
                return false;
            }

            HDC memoryDc = CreateCompatibleDC(screenDc);
            if (memoryDc == nullptr)
            {
                DeleteObject(bitmap);
                ReleaseDC(nullptr, screenDc);
                return false;
            }

            HGDIOBJ previousBitmap = SelectObject(memoryDc, bitmap);
            if (previousBitmap == nullptr || previousBitmap == HGDI_ERROR)
            {
                DeleteDC(memoryDc);
                DeleteObject(bitmap);
                ReleaseDC(nullptr, screenDc);
                return false;
            }

            constexpr std::size_t PixelBytes = static_cast<std::size_t>(TextureSize * TextureSize * 4);
            std::memset(bitmapBits, 0, PixelBytes);
            const bool drawn = DrawIconEx(
                memoryDc,
                0,
                0,
                icon,
                TextureSize,
                TextureSize,
                0,
                nullptr,
                DI_NORMAL) != FALSE;
            SelectObject(memoryDc, previousBitmap);

            if (drawn)
            {
                texture.Create(ImTextureFormat_RGBA32, TextureSize, TextureSize);
                const auto* source = static_cast<const unsigned char*>(bitmapBits);
                auto* destination = static_cast<unsigned char*>(texture.GetPixels());
                bool hasAlpha = false;
                for (std::size_t offset = 3; offset < PixelBytes; offset += 4)
                {
                    hasAlpha = hasAlpha || source[offset] != 0;
                }

                for (std::size_t offset = 0; offset < PixelBytes; offset += 4)
                {
                    destination[offset + 0] = source[offset + 2];
                    destination[offset + 1] = source[offset + 1];
                    destination[offset + 2] = source[offset + 0];
                    destination[offset + 3] = hasAlpha
                        ? source[offset + 3]
                        : ((source[offset + 0] | source[offset + 1] | source[offset + 2]) != 0 ? 255 : 0);
                }
                texture.UseColors = true;
            }

            DeleteDC(memoryDc);
            DeleteObject(bitmap);
            ReleaseDC(nullptr, screenDc);
            return drawn;
        }

        ImTextureData* GetCachedProcessIcon(const Core::ProcessInfo& process)
        {
            if (process.pid == 0 || process.executablePath.empty() ||
                (ImGui::GetIO().BackendFlags & ImGuiBackendFlags_RendererHasTextures) == 0)
            {
                return nullptr;
            }

            static std::unordered_map<std::wstring, std::unique_ptr<ImTextureData>> iconCache;
            const std::wstring cacheKey = NormalizeIconCacheKey(process.executablePath);
            const auto [cached, inserted] = iconCache.try_emplace(cacheKey);
            if (!inserted)
            {
                return cached->second.get();
            }

            SHFILEINFOW shellInfo = {};
            if (SHGetFileInfoW(
                    process.executablePath.c_str(),
                    0,
                    &shellInfo,
                    sizeof(shellInfo),
                    SHGFI_ICON | SHGFI_SMALLICON) == 0 ||
                shellInfo.hIcon == nullptr)
            {
                return nullptr;
            }

            auto texture = std::make_unique<ImTextureData>();
            const bool rasterized = RasterizeIcon(shellInfo.hIcon, *texture);
            DestroyIcon(shellInfo.hIcon);
            if (!rasterized)
            {
                return nullptr;
            }

            ImGui::RegisterUserTexture(texture.get());
            cached->second = std::move(texture);
            return cached->second.get();
        }

        void DrawProcessIconGlyph(
            ImDrawList* drawList,
            const ImVec2& min,
            float size,
            Core::Severity severity,
            const ImVec4& accent,
            bool selected,
            bool systemEntry)
        {
            const ImVec4 glyphAccent = Core::SeverityRank(severity) >= Core::SeverityRank(Core::Severity::Low)
                ? SeverityColor(severity)
                : (systemEntry ? ImVec4(0.58f, 0.66f, 0.76f, 1.0f) : accent);
            const ImVec4 fill = selected
                ? ImVec4(accent.x * 0.18f, accent.y * 0.27f, accent.z * 0.36f, 1.0f)
                : ImVec4(0.045f, 0.058f, 0.078f, 1.0f);
            const ImVec2 max(min.x + size, min.y + size);
            drawList->AddRectFilled(min, max, ColorU32(fill), 3.0f);
            drawList->AddRectFilled(
                ImVec2(min.x + 2.0f, min.y + 2.0f),
                ImVec2(max.x - 2.0f, min.y + 5.0f),
                ColorU32(ImVec4(glyphAccent.x, glyphAccent.y, glyphAccent.z, 0.72f)),
                1.5f);
            drawList->AddRect(
                ImVec2(min.x + 3.0f, min.y + 6.5f),
                ImVec2(max.x - 3.0f, max.y - 3.0f),
                ColorU32(ImVec4(glyphAccent.x, glyphAccent.y, glyphAccent.z, 0.38f)),
                1.5f,
                0,
                1.0f);
            drawList->AddRect(
                min,
                max,
                ColorU32(ImVec4(glyphAccent.x, glyphAccent.y, glyphAccent.z, 0.62f)),
                3.0f,
                0,
                1.0f);
        }

        bool ChipButton(const char* label, bool active, const ImVec4& accent)
        {
            PushGlassChipStyle(active, accent);
            const bool clicked = ImGui::Button(label, ImVec2(0.0f, 31.0f));
            PopGlassChipStyle();
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
            return clicked;
        }

        float ChipButtonWidth(const char* label)
        {
            return ImGui::CalcTextSize(label).x + 22.0f;
        }

        void SameLineIfFits(float nextItemWidth, float spacing = 6.0f)
        {
            const float contentRight = ImGui::GetCursorScreenPos().x + ImGui::GetContentRegionAvail().x;
            const float nextItemRight = ImGui::GetItemRectMax().x + spacing + nextItemWidth;
            if (nextItemRight <= contentRight)
            {
                ImGui::SameLine(0.0f, spacing);
            }
        }

        void SameLineIfChipFits(const char* nextLabel, float spacing = 6.0f)
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
        ImGui::SameLine(0.0f, 8.0f);
        ImGui::TextDisabled("%zu total", snapshot.processes.size());
        ImGui::Spacing();
        const bool pushedProcessHelperFont = PushFontIfAvailable(context.smallUiFont);
        ImGui::TextColored(context.mutedTextColor, "Search combines with the active preset");
        if (context.searchActive)
        {
            ImGui::SameLine(0.0f, 8.0f);
            ImGui::TextColored(context.accentColor, "search active");
        }
        PopFontIfPushed(pushedProcessHelperFont);
        ImGui::Dummy(ImVec2(0.0f, 4.0f));

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
        ImGui::Dummy(ImVec2(0.0f, 2.0f));
        ImGui::TextDisabled("Active: %s", ActiveChipLabel(activeFilter));
        ImGui::Dummy(ImVec2(0.0f, 6.0f));

        const ImGuiTableFlags flags =
            ImGuiTableFlags_RowBg |
            ImGuiTableFlags_Resizable |
            ImGuiTableFlags_ScrollY |
            ImGuiTableFlags_SizingStretchProp |
            ImGuiTableFlags_BordersInnerV |
            ImGuiTableFlags_NoSavedSettings;

        const float footerHeight = ImGui::GetFrameHeightWithSpacing() + 18.0f;
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
            constexpr float RowHeight = 28.0f;
            constexpr float IconSize = 16.0f;
            constexpr float SelectedRailWidth = 3.0f;
            constexpr float RailToContentGap = 4.0f;
            constexpr float IconNameGap = 6.0f;
            constexpr float DepthIndent = 6.0f;
            constexpr float MaxDepthIndent = 30.0f;
            constexpr float CellPaddingX = SelectedRailWidth + RailToContentGap;
            ImGui::PushStyleVar(ImGuiStyleVar_CellPadding, ImVec2(CellPaddingX, 3.0f));
            if (ImGui::BeginTable("ProcessesTable##ProcessPanel", 4, flags, ImVec2(0.0f, -footerHeight)))
            {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn("Process", ImGuiTableColumnFlags_WidthStretch, 0.0f, 0);
                ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 58.0f, 1);
                ImGui::TableSetupColumn("PPID", ImGuiTableColumnFlags_WidthFixed, 58.0f, 2);
                ImGui::TableSetupColumn("Severity", ImGuiTableColumnFlags_WidthFixed, 86.0f, 3);
                ImGui::TableHeadersRow();

                // Keep body rows at an exact height. The hidden Selectable below owns
                // row hit testing; all visible content is drawn from its screen rect.
                ImGui::PushStyleVar(ImGuiStyleVar_CellPadding, ImVec2(CellPaddingX, 0.0f));
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
                        ImGui::TableNextRow(ImGuiTableRowFlags_None, RowHeight);
                        ImGui::PushID(static_cast<int>(process.pid));

                        ImGui::TableSetColumnIndex(0);
                        const std::string name = DisplayName(process.name);
                        const ImVec2 processCellCursor = ImGui::GetCursorScreenPos();
                        const float processColumnRight = processCellCursor.x + ImGui::GetContentRegionAvail().x;
                        const ImVec4 nameColor = selected
                            ? ImVec4(0.92f, 0.96f, 1.0f, 1.0f)
                            : (Core::SeverityRank(row.filterSeverity) >= Core::SeverityRank(Core::Severity::Low)
                                ? SeverityColor(row.filterSeverity)
                                : ImGui::GetStyleColorVec4(ImGuiCol_Text));

                        const ImVec2 itemSpacing = ImGui::GetStyle().ItemSpacing;
                        ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(itemSpacing.x, 0.0f));
                        ImGui::PushStyleColor(ImGuiCol_Header, ImVec4(0.0f, 0.0f, 0.0f, 0.0f));
                        ImGui::PushStyleColor(ImGuiCol_HeaderHovered, ImVec4(0.0f, 0.0f, 0.0f, 0.0f));
                        ImGui::PushStyleColor(ImGuiCol_HeaderActive, ImVec4(0.0f, 0.0f, 0.0f, 0.0f));
                        const bool rowClicked = ImGui::Selectable(
                            "##ProcessRow",
                            false,
                            ImGuiSelectableFlags_SpanAllColumns,
                            ImVec2(0.0f, RowHeight));
                        const bool rowHovered = ImGui::IsItemHovered();
                        const ImVec2 itemMin = ImGui::GetItemRectMin();
                        const ImVec2 itemMax = ImGui::GetItemRectMax();
                        ImGui::PopStyleColor(3);
                        ImGui::PopStyleVar();

                        if (rowClicked && context.onSelectProcess)
                        {
                            context.onSelectProcess(process.pid);
                        }

                        const float rowTop = itemMin.y;
                        const float rowBottom = itemMax.y;
                        const float rowCenterY = (rowTop + rowBottom) * 0.5f;
                        const float textY = rowCenterY - (ImGui::GetTextLineHeight() * 0.5f);

                        ImVec4 rowColor;
                        bool hasRowColor = false;
                        if (selected)
                        {
                            rowColor = SelectedProcessRowColor(context.accentColor);
                            hasRowColor = true;
                        }
                        else if (rowHovered)
                        {
                            rowColor = ImGui::GetStyleColorVec4(ImGuiCol_HeaderHovered);
                            hasRowColor = true;
                        }
                        else
                        {
                            rowColor = RowTint(row.filterSeverity);
                            hasRowColor = rowColor.w > 0.0f;
                        }
                        if (hasRowColor)
                        {
                            const ImU32 rowBackground = ColorU32(rowColor);
                            ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, rowBackground);
                            ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1, rowBackground);
                        }

                        ImDrawList* drawList = ImGui::GetWindowDrawList();
                        if (selected)
                        {
                            drawList->AddRectFilled(
                                ImVec2(itemMin.x, rowTop + 2.0f),
                                ImVec2(itemMin.x + SelectedRailWidth, rowBottom - 2.0f),
                                ColorU32(context.accentColor),
                                1.5f);
                            if (context.scrollSelectedProcessIntoView != nullptr && *context.scrollSelectedProcessIntoView)
                            {
                                ImGui::SetScrollHereY(0.5f);
                                *context.scrollSelectedProcessIntoView = false;
                            }
                        }
                        const float depthOffset = std::min(static_cast<float>(row.depth) * DepthIndent, MaxDepthIndent);
                        const float contentStartX = itemMin.x + SelectedRailWidth + RailToContentGap;
                        const ImVec2 iconMin(
                            contentStartX + depthOffset,
                            rowCenterY - (IconSize * 0.5f));
                        const ImVec2 iconMax(iconMin.x + IconSize, iconMin.y + IconSize);
                        const float textX = iconMin.x + IconSize + IconNameGap;
                        const float textWidth = std::max(24.0f, processColumnRight - textX - 5.0f);
                        const std::string clippedName = EllipsizeToWidth(name, textWidth);
                        drawList->PushClipRect(
                            ImVec2(processCellCursor.x, rowTop),
                            ImVec2(processColumnRight, rowBottom),
                            true);
                        ImTextureData* processIcon = GetCachedProcessIcon(process);
                        if (processIcon != nullptr)
                        {
                            drawList->AddImage(processIcon->GetTexRef(), iconMin, iconMax);
                        }
                        else
                        {
                            DrawProcessIconGlyph(
                                drawList,
                                iconMin,
                                IconSize,
                                row.filterSeverity,
                                context.accentColor,
                                selected,
                                process.pid == 0);
                        }
                        drawList->AddText(ImVec2(textX, textY), ColorU32(nameColor), clippedName.c_str());
                        drawList->PopClipRect();
                        if (clippedName != name && rowHovered)
                        {
                            ImGui::SetTooltip("%s", name.c_str());
                        }

                        const auto drawCellText = [&](int columnIndex, const std::string& value, const ImVec4& color)
                        {
                            if (!ImGui::TableSetColumnIndex(columnIndex))
                            {
                                return;
                            }

                            const ImVec2 cellCursor = ImGui::GetCursorScreenPos();
                            const float cellRight = cellCursor.x + ImGui::GetContentRegionAvail().x;
                            drawList->PushClipRect(
                                ImVec2(cellCursor.x, rowTop),
                                ImVec2(cellRight, rowBottom),
                                true);
                            drawList->AddText(ImVec2(cellCursor.x, textY), ColorU32(color), value.c_str());
                            drawList->PopClipRect();
                        };

                        const ImVec4 normalTextColor = ImGui::GetStyleColorVec4(ImGuiCol_Text);
                        drawCellText(1, std::to_string(process.pid), normalTextColor);
                        drawCellText(2, std::to_string(process.parentPid), normalTextColor);
                        drawCellText(
                            3,
                            WideToUtf8(Core::SeverityToString(row.filterSeverity)),
                            SeverityColor(row.filterSeverity));

                        ImGui::PopID();
                    }
                }
                ImGui::PopStyleVar();

                ImGui::EndTable();
            }
            ImGui::PopStyleVar();
        }
        ImGui::Separator();
        ImGui::Dummy(ImVec2(0.0f, 2.0f));
        ImGui::TextDisabled("%zu processes", snapshot.processes.size());
        ImGui::SameLine(0.0f, 8.0f);
        ImGui::TextDisabled("|");
        ImGui::SameLine(0.0f, 8.0f);
        ImGui::TextColored(SeverityColor(Core::Severity::High), "%zu suspicious", context.suspiciousCount);
        ImGui::SameLine(0.0f, 8.0f);
        ImGui::TextDisabled("| %zu visible", visibleRows.size());
    }
}
