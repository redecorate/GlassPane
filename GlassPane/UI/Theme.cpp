#include "Theme.h"

#ifdef GLASSPANE_ENABLE_IMGUI
#include "imgui.h"
#endif

namespace GlassPane::UI
{
    void ApplyGlassPaneTheme()
    {
#ifdef GLASSPANE_ENABLE_IMGUI
        ImGuiIO& io = ImGui::GetIO();
        io.FontGlobalScale = 1.00f;

        ImGuiStyle& style = ImGui::GetStyle();
        style.WindowRounding = 8.0f;
        style.ChildRounding = 8.0f;
        style.FrameRounding = 6.0f;
        style.PopupRounding = 6.0f;
        style.ScrollbarRounding = 6.0f;
        style.ScrollbarSize = 7.0f;
        style.GrabRounding = 4.0f;
        style.TabRounding = 6.0f;
        style.WindowBorderSize = 1.0f;
        style.ChildBorderSize = 1.0f;
        style.FrameBorderSize = 1.0f;
        style.CellPadding = ImVec2(11.0f, 8.0f);
        style.ItemSpacing = ImVec2(10.0f, 9.0f);
        style.ItemInnerSpacing = ImVec2(8.0f, 6.0f);
        style.FramePadding = ImVec2(11.0f, 7.0f);
        style.WindowPadding = ImVec2(14.0f, 13.0f);
        style.IndentSpacing = 20.0f;

        ImVec4* colors = style.Colors;
        colors[ImGuiCol_Text] = ImVec4(0.89f, 0.93f, 0.97f, 1.00f);
        colors[ImGuiCol_TextDisabled] = ImVec4(0.48f, 0.56f, 0.66f, 1.00f);
        colors[ImGuiCol_WindowBg] = ImVec4(0.017f, 0.023f, 0.032f, 1.00f);
        colors[ImGuiCol_ChildBg] = ImVec4(0.031f, 0.041f, 0.058f, 1.00f);
        colors[ImGuiCol_PopupBg] = ImVec4(0.040f, 0.054f, 0.076f, 1.00f);
        colors[ImGuiCol_Border] = ImVec4(0.105f, 0.140f, 0.195f, 1.00f);
        colors[ImGuiCol_BorderShadow] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
        colors[ImGuiCol_FrameBg] = ImVec4(0.046f, 0.061f, 0.084f, 1.00f);
        colors[ImGuiCol_FrameBgHovered] = ImVec4(0.060f, 0.082f, 0.118f, 1.00f);
        colors[ImGuiCol_FrameBgActive] = ImVec4(0.090f, 0.135f, 0.195f, 1.00f);
        colors[ImGuiCol_TitleBg] = ImVec4(0.026f, 0.034f, 0.047f, 1.00f);
        colors[ImGuiCol_TitleBgActive] = ImVec4(0.031f, 0.041f, 0.058f, 1.00f);
        colors[ImGuiCol_MenuBarBg] = ImVec4(0.031f, 0.041f, 0.058f, 1.00f);
        colors[ImGuiCol_ScrollbarBg] = ImVec4(0.025f, 0.032f, 0.044f, 0.08f);
        colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.18f, 0.24f, 0.32f, 0.28f);
        colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.34f, 0.48f, 0.66f, 0.62f);
        colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.40f, 0.58f, 0.80f, 0.78f);
        colors[ImGuiCol_CheckMark] = ImVec4(0.38f, 0.62f, 0.88f, 1.00f);
        colors[ImGuiCol_SliderGrab] = ImVec4(0.38f, 0.62f, 0.88f, 1.00f);
        colors[ImGuiCol_Button] = ImVec4(0.040f, 0.054f, 0.076f, 1.00f);
        colors[ImGuiCol_ButtonHovered] = ImVec4(0.060f, 0.082f, 0.118f, 1.00f);
        colors[ImGuiCol_ButtonActive] = ImVec4(0.105f, 0.155f, 0.220f, 1.00f);
        colors[ImGuiCol_Header] = ImVec4(0.060f, 0.082f, 0.118f, 1.00f);
        colors[ImGuiCol_HeaderHovered] = ImVec4(0.090f, 0.135f, 0.195f, 1.00f);
        colors[ImGuiCol_HeaderActive] = ImVec4(0.120f, 0.185f, 0.270f, 1.00f);
        colors[ImGuiCol_Separator] = ImVec4(0.105f, 0.140f, 0.195f, 1.00f);
        colors[ImGuiCol_ResizeGrip] = ImVec4(0.15f, 0.23f, 0.32f, 0.00f);
        colors[ImGuiCol_ResizeGripHovered] = ImVec4(0.22f, 0.36f, 0.52f, 0.18f);
        colors[ImGuiCol_ResizeGripActive] = ImVec4(0.35f, 0.56f, 0.78f, 0.30f);
        colors[ImGuiCol_Tab] = ImVec4(0.040f, 0.054f, 0.076f, 1.00f);
        colors[ImGuiCol_TabHovered] = ImVec4(0.090f, 0.135f, 0.195f, 1.00f);
#if IMGUI_VERSION_NUM >= 19090
        colors[ImGuiCol_TabSelected] = ImVec4(0.075f, 0.120f, 0.180f, 1.00f);
#else
        colors[ImGuiCol_TabActive] = ImVec4(0.075f, 0.120f, 0.180f, 1.00f);
#endif
#ifdef IMGUI_HAS_DOCK
        colors[ImGuiCol_DockingPreview] = ImVec4(0.38f, 0.62f, 0.88f, 0.45f);
#endif
        colors[ImGuiCol_TableHeaderBg] = ImVec4(0.040f, 0.054f, 0.076f, 1.00f);
        colors[ImGuiCol_TableBorderStrong] = ImVec4(0.110f, 0.150f, 0.205f, 1.00f);
        colors[ImGuiCol_TableBorderLight] = ImVec4(0.070f, 0.095f, 0.135f, 1.00f);
        colors[ImGuiCol_TableRowBg] = ImVec4(0.024f, 0.032f, 0.046f, 1.00f);
        colors[ImGuiCol_TableRowBgAlt] = ImVec4(0.031f, 0.041f, 0.058f, 1.00f);
        colors[ImGuiCol_TextSelectedBg] = ImVec4(0.18f, 0.31f, 0.46f, 0.50f);
#endif
    }
}
