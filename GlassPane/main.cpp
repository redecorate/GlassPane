#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "UI/MainWindow.h"

#include <Windows.h>

#ifndef GLASSPANE_ENABLE_IMGUI
int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int showCommand)
{
    return GlassPane::UI::RunApp(instance, showCommand);
}
#endif
