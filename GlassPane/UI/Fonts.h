#pragma once

struct ImFont;

namespace GlassPane::UI
{
    struct FontSet
    {
        ImFont* ui = nullptr;
        ImFont* smallUi = nullptr;
        ImFont* bold = nullptr;
        ImFont* title = nullptr;
        ImFont* monospace = nullptr;

        void Load();
    };
}
