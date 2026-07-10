#include "HeaderPanel.h"

#include <algorithm>

namespace GlassPane::UI
{
    void PushGlassButtonStyle();
    void PopGlassButtonStyle();
    ImVec4 GlassCardBackground();
    ImVec4 GlassMutedTextColor();
    ImU32 ColorU32(const ImVec4& color);

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

        std::string Shorten(const std::string& value, std::size_t maxLength)
        {
            if (value.size() <= maxLength)
            {
                return value;
            }
            if (maxLength <= 3)
            {
                return value.substr(0, maxLength);
            }
            return value.substr(0, maxLength - 3) + "...";
        }

        void StatCard(
            const char* label,
            const std::string& value,
            const ImVec4& accent,
            float width,
            ImFont* labelFont,
            ImFont* valueFont,
            const ImVec4& cardBg,
            const ImVec4& borderColor)
        {
            constexpr float cardHeight = 60.0f;
            ImGui::PushStyleColor(ImGuiCol_ChildBg, cardBg);
            ImGui::PushStyleColor(ImGuiCol_Border, borderColor);
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(12.0f, 9.0f));
            ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(6.0f, 2.0f));
            ImGui::BeginChild(
                label,
                ImVec2(width, cardHeight),
                ImGuiChildFlags_Borders | ImGuiChildFlags_AlwaysUseWindowPadding,
                ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
            const ImVec2 cardMin = ImGui::GetWindowPos();
            const ImVec2 cardMax(cardMin.x + ImGui::GetWindowSize().x, cardMin.y + ImGui::GetWindowSize().y);
            ImGui::GetWindowDrawList()->AddRectFilled(
                ImVec2(cardMin.x + 9.0f, cardMin.y),
                ImVec2(cardMax.x - 9.0f, cardMin.y + 2.0f),
                ColorU32(ImVec4(accent.x, accent.y, accent.z, 0.68f)),
                2.0f);
            const float textBlockHeight = ImGui::GetTextLineHeight() * 2.0f + 4.0f;
            ImGui::SetCursorPosY(std::max(ImGui::GetCursorPosY(), (cardHeight - textBlockHeight) * 0.5f));
            const bool pushedLabelFont = PushFontIfAvailable(labelFont);
            ImGui::TextColored(GlassMutedTextColor(), "%s", label);
            PopFontIfPushed(pushedLabelFont);
            const bool pushedValueFont = PushFontIfAvailable(valueFont);
            ImGui::TextColored(accent, "%s", Shorten(value, 28).c_str());
            PopFontIfPushed(pushedValueFont);
            ImGui::EndChild();
            ImGui::PopStyleVar(2);
            ImGui::PopStyleColor(2);
        }

        ImVec4 CardBg()
        {
            return GlassCardBackground();
        }

        bool ToolbarButton(const char* label, const char* tooltip, bool disabled = false, const char* disabledTooltip = nullptr)
        {
            if (disabled)
            {
                ImGui::BeginDisabled();
            }
            PushGlassButtonStyle();
            const bool clicked = ImGui::Button(label, ImVec2(0.0f, 34.0f));
            PopGlassButtonStyle();
            if (disabled)
            {
                ImGui::EndDisabled();
            }

            if (disabled && disabledTooltip != nullptr && ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
            {
                ImGui::SetTooltip("%s", disabledTooltip);
            }
            else if (!disabled && tooltip != nullptr && ImGui::IsItemHovered())
            {
                ImGui::SetTooltip("%s", tooltip);
            }
            return !disabled && clicked;
        }
    }

    void RenderHeaderPanel(const HeaderPanelContext& context)
    {
        const ImGuiViewport* viewport = ImGui::GetMainViewport();
        const float headerWindowWidth = std::max(viewport->WorkSize.x - 16.0f, 980.0f);
        ImGui::SetNextWindowPos(
            ImVec2(viewport->WorkPos.x + 8.0f, viewport->WorkPos.y + 8.0f),
            ImGuiCond_Always);
        ImGui::SetNextWindowSize(
            ImVec2(headerWindowWidth, 104.0f),
            ImGuiCond_Always);

        ImGui::PushStyleColor(ImGuiCol_WindowBg, context.headerBgColor);
        ImGui::PushStyleColor(ImGuiCol_Border, context.panelBorderColor);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(18.0f, 13.0f));
        ImGuiWindowFlags headerFlags =
            ImGuiWindowFlags_NoTitleBar |
            ImGuiWindowFlags_NoCollapse |
            ImGuiWindowFlags_NoResize |
            ImGuiWindowFlags_NoMove |
            ImGuiWindowFlags_NoScrollbar;
#ifdef IMGUI_HAS_DOCK
        headerFlags |= ImGuiWindowFlags_NoDocking;
#endif
        ImGui::Begin(
            "GlassPane Header",
            nullptr,
            headerFlags);

        const bool narrowHeader = headerWindowWidth < 1180.0f;
        const bool compactHeader = headerWindowWidth < 1320.0f;
        const float statsWidth = narrowHeader ? 396.0f : (compactHeader ? 474.0f : 534.0f);
        const float brandWidth = narrowHeader ? 374.0f : (compactHeader ? 454.0f : 514.0f);
        const float processCardWidth = narrowHeader ? 98.0f : (compactHeader ? 118.0f : 134.0f);
        const float suspiciousCardWidth = narrowHeader ? 106.0f : (compactHeader ? 120.0f : 134.0f);
        const float refreshCardWidth = narrowHeader ? 176.0f : (compactHeader ? 218.0f : 238.0f);
        constexpr float rowHeight = 72.0f;
        const float contentTop = ImGui::GetCursorPosY();
        const float centeredRowY = contentTop + std::max(0.0f, (ImGui::GetContentRegionAvail().y - rowHeight) * 0.5f);

        if (ImGui::BeginTable("HeaderLayoutTable##TopToolbar", 3, ImGuiTableFlags_SizingStretchProp))
        {
            ImGui::TableSetupColumn("brand", ImGuiTableColumnFlags_WidthFixed, brandWidth);
            ImGui::TableSetupColumn("controls", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("stats", ImGuiTableColumnFlags_WidthFixed, statsWidth);
            ImGui::TableNextRow();

            ImGui::TableSetColumnIndex(0);
            constexpr float logoSize = 30.0f;
            bool pushedTitleFont = PushFontIfAvailable(context.titleFont);
            const ImVec2 titleSize = ImGui::CalcTextSize("GlassPane");
            PopFontIfPushed(pushedTitleFont);

            const bool hasLogo = context.logoTexture != nullptr;
            constexpr float identityGap = 7.0f;
            const float identityHeight = std::max(hasLogo ? logoSize : 0.0f, titleSize.y);
            const float identityTopY = centeredRowY + 2.0f;
            const ImVec2 windowPos = ImGui::GetWindowPos();

            ImGui::SetCursorPosY(identityTopY);
            const float identityStartX = ImGui::GetCursorScreenPos().x;
            const float identityCenterY = windowPos.y + identityTopY + identityHeight * 0.5f;
            const float titleX = identityStartX + (hasLogo ? logoSize + identityGap : 0.0f);
            const ImVec2 brandMin(identityStartX, windowPos.y + identityTopY);
            if (context.logoTexture != nullptr)
            {
                ImGui::SetCursorScreenPos(ImVec2(identityStartX, identityCenterY - logoSize * 0.5f));
                ImGui::Image(reinterpret_cast<ImTextureID>(context.logoTexture), ImVec2(logoSize, logoSize));
            }
            const ImVec2 titlePosition(titleX, identityCenterY - titleSize.y * 0.5f);
            const ImVec2 brandMax(
                titlePosition.x + titleSize.x,
                brandMin.y + identityHeight);
            const bool titleHovered = ImGui::IsMouseHoveringRect(brandMin, brandMax);
            if (titleHovered)
            {
                ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
                ImGui::SetTooltip("About GlassPane");
            }
            if (titleHovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left) && context.onAbout)
            {
                context.onAbout();
            }
            ImGui::SetCursorScreenPos(titlePosition);
            pushedTitleFont = PushFontIfAvailable(context.titleFont);
            ImGui::TextColored(
                titleHovered ? ImVec4(0.56f, 0.76f, 0.98f, 1.0f) : context.accentColor,
                "GlassPane");
            PopFontIfPushed(pushedTitleFont);
            ImGui::SetCursorPosY(centeredRowY + 36.0f);
            ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(compactHeader ? 5.0f : 7.0f, 5.0f));
            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(compactHeader ? 8.0f : 10.0f, 5.0f));
            constexpr const char* LoadedSnapshotDisabledTooltip =
                "Unavailable while viewing a saved snapshot. Return to Live View to refresh live endpoint data.";
            constexpr const char* LongOperationDisabledTooltip =
                "Unavailable while an operation is running.";
            const char* liveActionDisabledTooltip =
                context.longOperationActive ? LongOperationDisabledTooltip : LoadedSnapshotDisabledTooltip;
            const bool liveActionDisabled = context.loadedSnapshotActive || context.longOperationActive;
            if (ToolbarButton(
                    "Refresh##HeaderRefresh",
                    "Refresh live process snapshot",
                    liveActionDisabled,
                    liveActionDisabledTooltip) && context.onRefresh)
            {
                context.onRefresh();
            }
            ImGui::SameLine();
            if (ToolbarButton(
                    "Pick##HeaderPickWindow",
                    "Pick Window",
                    liveActionDisabled,
                    liveActionDisabledTooltip) && context.onPickWindow)
            {
                context.onPickWindow();
            }
            ImGui::SameLine();
            if (ToolbarButton(
                    "Evidence##HeaderEvidence",
                    "Snapshot and evidence package actions",
                    context.longOperationActive,
                    LongOperationDisabledTooltip))
            {
                ImGui::OpenPopup("EvidenceMenu##Header");
            }
            if (ImGui::BeginPopup("EvidenceMenu##Header"))
            {
                if (ImGui::MenuItem("Save Snapshot") && context.onSaveSnapshot)
                {
                    ImGui::CloseCurrentPopup();
                    context.onSaveSnapshot();
                }
                if (ImGui::MenuItem("Save Deep Evidence Snapshot") && context.onSaveDeepSnapshot)
                {
                    ImGui::CloseCurrentPopup();
                    context.onSaveDeepSnapshot();
                }
                if (ImGui::MenuItem("Load Snapshot") && context.onLoadSnapshot)
                {
                    ImGui::CloseCurrentPopup();
                    context.onLoadSnapshot();
                }
                ImGui::Separator();
                if (ImGui::MenuItem("Export Evidence Package") && context.onExportEvidencePackage)
                {
                    ImGui::CloseCurrentPopup();
                    context.onExportEvidencePackage();
                }
                ImGui::EndPopup();
            }
            ImGui::SameLine();
            if (ToolbarButton(
                    "Modules##HeaderRefreshModules",
                    "Refresh Modules",
                    liveActionDisabled,
                    liveActionDisabledTooltip) && context.onRefreshModules)
            {
                context.onRefreshModules();
            }
#ifdef IMGUI_HAS_DOCK
            ImGui::SameLine();
            if (ToolbarButton(
                    "Layout##HeaderResetLayout",
                    "Reset Layout",
                    context.longOperationActive,
                    LongOperationDisabledTooltip) && context.onResetLayout)
            {
                context.onResetLayout();
            }
#endif
            ImGui::PopStyleVar(2);

            ImGui::TableSetColumnIndex(1);
            ImGui::SetCursorPosY(centeredRowY + 24.0f);
            const float controlsAvail = ImGui::GetContentRegionAvail().x;
            const float minSearchWidth = narrowHeader ? 160.0f : (compactHeader ? 220.0f : 260.0f);
            const float maxSearchWidth = narrowHeader ? 240.0f : (compactHeader ? 360.0f : 460.0f);
            const float searchWidth = std::clamp(controlsAvail - 72.0f, minSearchWidth, maxSearchWidth);
            const float controlsWidth =
                ImGui::CalcTextSize("Search").x +
                searchWidth +
                16.0f;
            const float centeredControlsX = ImGui::GetCursorPosX() + std::max(0.0f, (controlsAvail - controlsWidth) * 0.5f);
            ImGui::SetCursorPosX(centeredControlsX);
            ImGui::BeginGroup();
            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(11.0f, 6.0f));
            ImGui::AlignTextToFramePadding();
            ImGui::TextColored(context.mutedTextColor, "Search");
            ImGui::SameLine();
            ImGui::SetNextItemWidth(searchWidth);
            if (context.searchBuffer != nullptr &&
                context.searchBufferSize > 0 &&
                ImGui::InputTextWithHint(
                    "##ProcessPanelSearch",
                    "name, path, command line, PID, indicator",
                    context.searchBuffer,
                    context.searchBufferSize))
            {
                if (context.onSearchChanged)
                {
                    context.onSearchChanged(context.searchBuffer);
                }
            }
            ImGui::PopStyleVar();
            ImGui::EndGroup();

            if (context.pickWindowActive)
            {
                ImGui::SetCursorPosX(centeredControlsX);
                ImGui::SetCursorPosY(centeredRowY + 58.0f);
                const bool pushedPickerFont = PushFontIfAvailable(context.smallUiFont);
                ImGui::TextColored(
                    ImVec4(context.accentColor.x, context.accentColor.y, context.accentColor.z, 0.95f),
                    "Pick mode: click a window. Esc cancels.");
                PopFontIfPushed(pushedPickerFont);
            }

            ImGui::TableSetColumnIndex(2);
            ImGui::SetCursorPosY(centeredRowY + 4.0f);
            StatCard(
                "Processes",
                std::to_string(context.processCount),
                context.accentColor,
                processCardWidth,
                context.smallUiFont,
                context.boldFont,
                CardBg(),
                ImVec4(context.accentColor.x, context.accentColor.y, context.accentColor.z, 0.20f));
            ImGui::SameLine(0.0f, 8.0f);
            StatCard(
                "Suspicious",
                std::to_string(context.suspiciousCount),
                context.highSeverityColor,
                suspiciousCardWidth,
                context.smallUiFont,
                context.boldFont,
                CardBg(),
                ImVec4(context.highSeverityColor.x, context.highSeverityColor.y, context.highSeverityColor.z, 0.20f));
            ImGui::SameLine(0.0f, 8.0f);
            StatCard(
                "Last refresh",
                context.lastRefreshText,
                context.primaryTextColor,
                refreshCardWidth,
                context.smallUiFont,
                context.monospaceFont,
                CardBg(),
                ImVec4(context.primaryTextColor.x, context.primaryTextColor.y, context.primaryTextColor.z, 0.20f));

            ImGui::EndTable();
        }
        ImGui::End();
        ImGui::PopStyleVar();
        ImGui::PopStyleColor(2);
    }
}
