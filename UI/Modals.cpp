#include "Modals.h"

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

        void WrappedText(const char* text)
        {
            ImGui::PushTextWrapPos(0.0f);
            ImGui::TextUnformatted(text);
            ImGui::PopTextWrapPos();
        }

        void LabelValue(const char* label, const char* value)
        {
            ImGui::TextDisabled("%s", label);
            ImGui::SameLine(145.0f);
            ImGui::TextUnformatted(value != nullptr && value[0] != '\0' ? value : "(unknown)");
        }

        ImU32 ColorU32(const ImVec4& color)
        {
            return ImGui::ColorConvertFloat4ToU32(color);
        }

        void RenderModalCloseHint(const ImVec4& mutedTextColor)
        {
            const char* hint = "Click anywhere to close";
            const ImGuiViewport* viewport = ImGui::GetMainViewport();
            const ImVec2 textSize = ImGui::CalcTextSize(hint);
            const ImVec2 position(
                viewport->WorkPos.x + (viewport->WorkSize.x - textSize.x) * 0.5f,
                viewport->WorkPos.y + viewport->WorkSize.y - textSize.y - 28.0f);
            ImGui::GetForegroundDrawList()->AddText(position, ColorU32(mutedTextColor), hint);
        }

        bool BeginGlassPaneModal(
            const char* title,
            int openedFrame,
            const ImVec2& size,
            const ImVec4& mutedTextColor,
            bool* closeRequested)
        {
            if (closeRequested != nullptr)
            {
                *closeRequested = false;
            }

            ImGui::SetNextWindowSize(size, ImGuiCond_Appearing);
            ImGui::PushStyleColor(ImGuiCol_ModalWindowDimBg, ImVec4(0.0f, 0.0f, 0.0f, 0.58f));
            ImGuiWindowFlags flags =
                ImGuiWindowFlags_AlwaysAutoResize |
                ImGuiWindowFlags_NoSavedSettings |
                ImGuiWindowFlags_NoCollapse;
#ifdef IMGUI_HAS_DOCK
            flags |= ImGuiWindowFlags_NoDocking;
#endif
            const bool visible = ImGui::BeginPopupModal(title, nullptr, flags);
            ImGui::PopStyleColor();
            if (!visible)
            {
                return false;
            }

            const ImVec2 popupMin = ImGui::GetWindowPos();
            const ImVec2 popupMax(
                popupMin.x + ImGui::GetWindowSize().x,
                popupMin.y + ImGui::GetWindowSize().y);
            const bool mouseInsidePopup = ImGui::IsMouseHoveringRect(popupMin, popupMax, false);
            const bool canCloseFromOutsideClick = ImGui::GetFrameCount() > openedFrame;
            if (closeRequested != nullptr &&
                ((canCloseFromOutsideClick && ImGui::IsMouseClicked(ImGuiMouseButton_Left) && !mouseInsidePopup) ||
                    ImGui::IsKeyPressed(ImGuiKey_Escape)))
            {
                *closeRequested = true;
            }
            RenderModalCloseHint(mutedTextColor);
            return true;
        }

        void EndGlassPaneModal(bool closeRequested)
        {
            if (closeRequested)
            {
                ImGui::CloseCurrentPopup();
            }
            ImGui::EndPopup();
        }
    }

    void RenderAboutPanel(const AboutPanelContext& context)
    {
        if (context.popupRequested != nullptr && *context.popupRequested)
        {
            ImGui::OpenPopup("About GlassPane");
            if (context.openedFrame != nullptr)
            {
                *context.openedFrame = ImGui::GetFrameCount();
            }
            *context.popupRequested = false;
        }

        const int openedFrame = context.openedFrame != nullptr ? *context.openedFrame : -1;
        bool closeRequested = false;
        if (BeginGlassPaneModal(
                "About GlassPane",
                openedFrame,
                ImVec2(540.0f, 0.0f),
                context.mutedTextColor,
                &closeRequested))
        {
            if (context.logoTexture != nullptr)
            {
                ImGui::Image(reinterpret_cast<ImTextureID>(context.logoTexture), ImVec2(56.0f, 56.0f));
                ImGui::SameLine(0.0f, 14.0f);
            }
            ImGui::BeginGroup();
            const bool pushedTitleFont = PushFontIfAvailable(context.titleFont);
            ImGui::TextColored(context.accentColor, "GlassPane");
            PopFontIfPushed(pushedTitleFont);
            ImGui::TextDisabled("Version: %s", context.appVersion != nullptr ? context.appVersion : "(unknown)");
            ImGui::EndGroup();
            ImGui::Spacing();
            WrappedText("Read-only Windows process and forensic context analysis dashboard.");

            ImGui::SeparatorText("Build");
            LabelValue("Architecture", context.buildArchitecture);
            LabelValue("Configuration", context.buildConfiguration);

            ImGui::SeparatorText("Links");
            ImGui::TextDisabled("GitHub");
            ImGui::SameLine(120.0f);
            ImGui::TextColored(context.accentColor, "%s", context.githubUrl != nullptr ? context.githubUrl : "");

            ImGui::SeparatorText("Disclaimer");
            WrappedText("GlassPane is a read-only local analysis tool. Findings are evidence worth investigating, not proof of malicious activity.");

            ImGui::Spacing();
            if (ImGui::Button("Copy GitHub URL"))
            {
                if (context.githubUrl != nullptr)
                {
                    ImGui::SetClipboardText(context.githubUrl);
                }
                if (context.onCopyGithubUrl)
                {
                    context.onCopyGithubUrl();
                }
            }
            ImGui::SameLine();
            if (ImGui::Button("Close"))
            {
                closeRequested = true;
            }

            EndGlassPaneModal(closeRequested);
        }
    }

    void RenderResetLayoutModal(const ResetLayoutModalContext& context)
    {
        if (context.popupRequested != nullptr && *context.popupRequested)
        {
            ImGui::OpenPopup("Reset Layout?");
            if (context.openedFrame != nullptr)
            {
                *context.openedFrame = ImGui::GetFrameCount();
            }
            *context.popupRequested = false;
        }

        const int openedFrame = context.openedFrame != nullptr ? *context.openedFrame : -1;
        bool closeRequested = false;
        if (BeginGlassPaneModal(
                "Reset Layout?",
                openedFrame,
                ImVec2(560.0f, 0.0f),
                context.mutedTextColor,
                &closeRequested))
        {
            const bool pushedTitleFont = PushFontIfAvailable(context.titleFont);
            ImGui::TextColored(context.accentColor, "Reset Layout?");
            PopFontIfPushed(pushedTitleFont);
            ImGui::Spacing();
            WrappedText("This will restore the default GlassPane workspace layout.");
            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();

            if (ImGui::Button("Reset Layout"))
            {
                if (context.onResetLayout)
                {
                    context.onResetLayout();
                }
                closeRequested = true;
            }
            ImGui::SameLine();
            if (ImGui::Button("Cancel"))
            {
                closeRequested = true;
            }

            EndGlassPaneModal(closeRequested);
        }
    }

    void RenderNetworkIntelUpdateModal(const NetworkIntelUpdateModalContext& context)
    {
        if (context.popupRequested != nullptr && *context.popupRequested)
        {
            ImGui::OpenPopup("Update Network Intelligence Feed?");
            if (context.openedFrame != nullptr)
            {
                *context.openedFrame = ImGui::GetFrameCount();
            }
            *context.popupRequested = false;
        }

        const int openedFrame = context.openedFrame != nullptr ? *context.openedFrame : -1;
        bool closeRequested = false;
        if (BeginGlassPaneModal(
                "Update Network Intelligence Feed?",
                openedFrame,
                ImVec2(620.0f, 0.0f),
                context.mutedTextColor,
                &closeRequested))
        {
            const bool pushedTitleFont = PushFontIfAvailable(context.titleFont);
            ImGui::TextColored(context.accentColor, "Update Network Intelligence Feed?");
            PopFontIfPushed(pushedTitleFont);
            ImGui::Spacing();

            WrappedText("GlassPane will connect to GitHub to download the official Network Intelligence feed and checksum file.");
            ImGui::Spacing();
            ImGui::TextDisabled("Only these files are downloaded:");
            ImGui::BulletText("network-indicators.json");
            ImGui::BulletText("network-indicators.sha256");
            ImGui::Spacing();
            WrappedText("Downloads only the official GlassPane feed files from GitHub.");
            WrappedText("No endpoint, process, network, or telemetry data is uploaded.");
            WrappedText("SHA256 verification and JSON validation are required before replacement. Existing local feed is kept if update fails.");
            ImGui::Spacing();
            WrappedText("The downloaded feed will only replace the local feed after SHA256 verification and JSON validation pass.");
            ImGui::Spacing();

            bool localDoNotShowAgain = context.doNotShowAgain != nullptr && *context.doNotShowAgain;
            if (ImGui::Checkbox("Do not show again this session", &localDoNotShowAgain) &&
                context.doNotShowAgain != nullptr)
            {
                *context.doNotShowAgain = localDoNotShowAgain;
            }

            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();

            bool confirmUpdate = false;
            bool cancelUpdate = false;
            if (ImGui::Button("Update Feed"))
            {
                confirmUpdate = true;
                closeRequested = true;
            }
            ImGui::SameLine();
            if (ImGui::Button("Cancel"))
            {
                cancelUpdate = true;
                closeRequested = true;
            }

            if (closeRequested && !confirmUpdate && !cancelUpdate)
            {
                cancelUpdate = true;
            }

            EndGlassPaneModal(closeRequested);

            if (confirmUpdate && context.onConfirmUpdate)
            {
                context.onConfirmUpdate();
            }
            else if (cancelUpdate && context.onCancel)
            {
                context.onCancel();
            }
        }
    }
}
