#include "HeaderPanel.h"

#include <algorithm>

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
            constexpr float cardHeight = 54.0f;
            ImGui::PushStyleColor(ImGuiCol_ChildBg, cardBg);
            ImGui::PushStyleColor(ImGuiCol_Border, borderColor);
            ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(6.0f, 2.0f));
            ImGui::BeginChild(
                label,
                ImVec2(width, cardHeight),
                ImGuiChildFlags_Borders | ImGuiChildFlags_AlwaysUseWindowPadding,
                ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
            const float textBlockHeight = ImGui::GetTextLineHeight() * 2.0f + 4.0f;
            ImGui::SetCursorPosY(std::max(ImGui::GetCursorPosY(), (cardHeight - textBlockHeight) * 0.5f));
            const bool pushedLabelFont = PushFontIfAvailable(labelFont);
            ImGui::TextDisabled("%s", label);
            PopFontIfPushed(pushedLabelFont);
            const bool pushedValueFont = PushFontIfAvailable(valueFont);
            ImGui::TextColored(accent, "%s", Shorten(value, 24).c_str());
            PopFontIfPushed(pushedValueFont);
            ImGui::EndChild();
            ImGui::PopStyleVar();
            ImGui::PopStyleColor(2);
        }

        ImVec4 CardBg()
        {
            return ImVec4(0.040f, 0.058f, 0.078f, 1.0f);
        }
    }

    void RenderHeaderPanel(const HeaderPanelContext& context)
    {
        const ImGuiViewport* viewport = ImGui::GetMainViewport();
        const float headerWindowWidth = std::max(viewport->WorkSize.x - 16.0f, 960.0f);
        ImGui::SetNextWindowPos(
            ImVec2(viewport->WorkPos.x + 8.0f, viewport->WorkPos.y + 8.0f),
            ImGuiCond_Always);
        ImGui::SetNextWindowSize(
            ImVec2(headerWindowWidth, 96.0f),
            ImGuiCond_Always);

        ImGui::PushStyleColor(ImGuiCol_WindowBg, context.headerBgColor);
        ImGui::PushStyleColor(ImGuiCol_Border, context.panelBorderColor);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(16.0f, 11.0f));
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
        const float statsWidth = narrowHeader ? 376.0f : (compactHeader ? 456.0f : 516.0f);
        const float brandWidth = narrowHeader ? 360.0f : (compactHeader ? 440.0f : 500.0f);
        const float processCardWidth = narrowHeader ? 92.0f : (compactHeader ? 112.0f : 128.0f);
        const float suspiciousCardWidth = narrowHeader ? 98.0f : (compactHeader ? 112.0f : 128.0f);
        const float refreshCardWidth = narrowHeader ? 166.0f : (compactHeader ? 208.0f : 228.0f);
        constexpr float rowHeight = 64.0f;
        const float contentTop = ImGui::GetCursorPosY();
        const float centeredRowY = contentTop + std::max(0.0f, (ImGui::GetContentRegionAvail().y - rowHeight) * 0.5f);

        if (ImGui::BeginTable("HeaderLayoutTable##TopToolbar", 3, ImGuiTableFlags_SizingStretchProp))
        {
            ImGui::TableSetupColumn("brand", ImGuiTableColumnFlags_WidthFixed, brandWidth);
            ImGui::TableSetupColumn("controls", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("stats", ImGuiTableColumnFlags_WidthFixed, statsWidth);
            ImGui::TableNextRow();

            ImGui::TableSetColumnIndex(0);
            ImGui::SetCursorPosY(centeredRowY + 2.0f);
            const ImVec2 brandMin = ImGui::GetCursorScreenPos();
            constexpr float logoSize = 28.0f;
            if (context.logoTexture != nullptr)
            {
                ImGui::Image(reinterpret_cast<ImTextureID>(context.logoTexture), ImVec2(logoSize, logoSize));
                ImGui::SameLine(0.0f, 8.0f);
            }
            const ImVec2 titlePosition = ImGui::GetCursorScreenPos();
            bool pushedTitleFont = PushFontIfAvailable(context.titleFont);
            const ImVec2 titleSize = ImGui::CalcTextSize("GlassPane");
            PopFontIfPushed(pushedTitleFont);
            const ImVec2 brandMax(
                titlePosition.x + titleSize.x,
                brandMin.y + std::max(context.logoTexture != nullptr ? logoSize : 0.0f, titleSize.y));
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
            if (ImGui::Button("Refresh") && context.onRefresh)
            {
                context.onRefresh();
            }
            ImGui::SameLine();
            if (ImGui::Button("Pick Window") && context.onPickWindow)
            {
                context.onPickWindow();
            }
            ImGui::SameLine();
            if (ImGui::Button("Export JSON") && context.onExportJson)
            {
                context.onExportJson();
            }
            ImGui::SameLine();
            if (ImGui::Button("Refresh Modules") && context.onRefreshModules)
            {
                context.onRefreshModules();
            }
#ifdef IMGUI_HAS_DOCK
            ImGui::SameLine();
            if (ImGui::Button("Reset Layout") && context.onResetLayout)
            {
                context.onResetLayout();
            }
#endif

            ImGui::TableSetColumnIndex(1);
            ImGui::SetCursorPosY(centeredRowY + 21.0f);
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
            ImGui::EndGroup();

            if (context.pickWindowActive)
            {
                ImGui::SetCursorPosX(centeredControlsX);
                ImGui::SetCursorPosY(centeredRowY + 52.0f);
                const bool pushedPickerFont = PushFontIfAvailable(context.smallUiFont);
                ImGui::TextColored(
                    ImVec4(context.accentColor.x, context.accentColor.y, context.accentColor.z, 0.95f),
                    "Pick mode: click a window. Esc cancels.");
                PopFontIfPushed(pushedPickerFont);
            }

            ImGui::TableSetColumnIndex(2);
            ImGui::SetCursorPosY(centeredRowY + 5.0f);
            StatCard(
                "Processes",
                std::to_string(context.processCount),
                context.accentColor,
                processCardWidth,
                context.smallUiFont,
                context.boldFont,
                CardBg(),
                ImVec4(context.accentColor.x, context.accentColor.y, context.accentColor.z, 0.20f));
            ImGui::SameLine();
            StatCard(
                "Suspicious",
                std::to_string(context.suspiciousCount),
                context.highSeverityColor,
                suspiciousCardWidth,
                context.smallUiFont,
                context.boldFont,
                CardBg(),
                ImVec4(context.highSeverityColor.x, context.highSeverityColor.y, context.highSeverityColor.z, 0.20f));
            ImGui::SameLine();
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
