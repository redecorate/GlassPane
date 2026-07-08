#include "Fonts.h"

#include "imgui.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

namespace GlassPane::UI
{
    namespace
    {
        bool FontFileExists(const wchar_t* path)
        {
            const DWORD attributes = GetFileAttributesW(path);
            return attributes != INVALID_FILE_ATTRIBUTES &&
                (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
        }

        ImFont* AddFontIfAvailable(const wchar_t* testPath, const char* imguiPath, float sizePixels)
        {
            if (!FontFileExists(testPath))
            {
                return nullptr;
            }

            ImFontConfig config = {};
            config.OversampleH = 3;
            config.OversampleV = 2;
            config.PixelSnapH = false;
            return ImGui::GetIO().Fonts->AddFontFromFileTTF(imguiPath, sizePixels, &config);
        }
    }

    void FontSet::Load()
    {
        ImGuiIO& io = ImGui::GetIO();
        io.Fonts->Clear();

        ui = AddFontIfAvailable(
            L"C:\\Windows\\Fonts\\segoeui.ttf",
            "C:\\Windows\\Fonts\\segoeui.ttf",
            16.5f);
        if (ui == nullptr)
        {
            ui = io.Fonts->AddFontDefault();
        }

        smallUi = AddFontIfAvailable(
            L"C:\\Windows\\Fonts\\segoeui.ttf",
            "C:\\Windows\\Fonts\\segoeui.ttf",
            13.8f);
        if (smallUi == nullptr)
        {
            smallUi = ui;
        }

        bold = AddFontIfAvailable(
            L"C:\\Windows\\Fonts\\segoeuib.ttf",
            "C:\\Windows\\Fonts\\segoeuib.ttf",
            17.2f);
        if (bold == nullptr)
        {
            bold = ui;
        }

        title = AddFontIfAvailable(
            L"C:\\Windows\\Fonts\\segoeuib.ttf",
            "C:\\Windows\\Fonts\\segoeuib.ttf",
            22.0f);
        if (title == nullptr)
        {
            title = bold != nullptr ? bold : ui;
        }

        monospace = AddFontIfAvailable(
            L"C:\\Windows\\Fonts\\CascadiaMono.ttf",
            "C:\\Windows\\Fonts\\CascadiaMono.ttf",
            14.2f);
        if (monospace == nullptr)
        {
            monospace = AddFontIfAvailable(
                L"C:\\Windows\\Fonts\\consola.ttf",
                "C:\\Windows\\Fonts\\consola.ttf",
                14.2f);
        }
        if (monospace == nullptr)
        {
            monospace = ui;
        }

        io.FontDefault = ui;
    }
}
