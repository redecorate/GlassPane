#pragma once

#include "imgui.h"

#include <functional>

struct ID3D11ShaderResourceView;

namespace GlassPane::UI
{
    struct AboutPanelContext
    {
        bool* popupRequested = nullptr;
        int* openedFrame = nullptr;
        ImFont* titleFont = nullptr;
        ID3D11ShaderResourceView* logoTexture = nullptr;
        const char* appVersion = "";
        const char* githubUrl = "";
        const char* buildArchitecture = "";
        const char* buildConfiguration = "";
        ImVec4 accentColor = ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
        ImVec4 mutedTextColor = ImVec4(0.65f, 0.70f, 0.78f, 1.0f);
        std::function<void()> onCopyGithubUrl;
    };

    struct ResetLayoutModalContext
    {
        bool* popupRequested = nullptr;
        int* openedFrame = nullptr;
        ImFont* titleFont = nullptr;
        ImVec4 accentColor = ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
        ImVec4 mutedTextColor = ImVec4(0.65f, 0.70f, 0.78f, 1.0f);
        std::function<void()> onResetLayout;
    };

    struct NetworkIntelUpdateModalContext
    {
        bool* popupRequested = nullptr;
        int* openedFrame = nullptr;
        bool* doNotShowAgain = nullptr;
        ImFont* titleFont = nullptr;
        ImVec4 accentColor = ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
        ImVec4 mutedTextColor = ImVec4(0.65f, 0.70f, 0.78f, 1.0f);
        std::function<void()> onConfirmUpdate;
        std::function<void()> onCancel;
    };

    void RenderAboutPanel(const AboutPanelContext& context);
    void RenderResetLayoutModal(const ResetLayoutModalContext& context);
    void RenderNetworkIntelUpdateModal(const NetworkIntelUpdateModalContext& context);
}
