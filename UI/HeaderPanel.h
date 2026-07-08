#pragma once

#include "imgui.h"

#include <cstddef>
#include <functional>
#include <string>

struct ID3D11ShaderResourceView;

namespace GlassPane::UI
{
    struct HeaderPanelContext
    {
        ID3D11ShaderResourceView* logoTexture = nullptr;
        char* searchBuffer = nullptr;
        std::size_t searchBufferSize = 0;
        bool pickWindowActive = false;
        std::size_t processCount = 0;
        std::size_t suspiciousCount = 0;
        std::string lastRefreshText;

        ImFont* titleFont = nullptr;
        ImFont* smallUiFont = nullptr;
        ImFont* boldFont = nullptr;
        ImFont* monospaceFont = nullptr;

        ImVec4 headerBgColor = ImVec4(0.04f, 0.06f, 0.08f, 1.0f);
        ImVec4 panelBorderColor = ImVec4(0.16f, 0.22f, 0.30f, 1.0f);
        ImVec4 accentColor = ImVec4(0.55f, 0.72f, 0.92f, 1.0f);
        ImVec4 mutedTextColor = ImVec4(0.65f, 0.70f, 0.78f, 1.0f);
        ImVec4 primaryTextColor = ImVec4(0.86f, 0.90f, 0.96f, 1.0f);
        ImVec4 highSeverityColor = ImVec4(0.96f, 0.24f, 0.22f, 1.0f);

        std::function<void()> onAbout;
        std::function<void()> onRefresh;
        std::function<void()> onPickWindow;
        std::function<void()> onExportJson;
        std::function<void()> onRefreshModules;
        std::function<void()> onResetLayout;
        std::function<void(const char*)> onSearchChanged;
    };

    void RenderHeaderPanel(const HeaderPanelContext& context);
}
