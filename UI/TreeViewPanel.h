#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "../Core/GraphModel.h"

#include <Windows.h>

#include <cstdint>
#include <vector>

namespace GlassPane::UI
{
    class TreeViewPanel
    {
    public:
        static constexpr UINT SelectionChangedMessage = WM_APP + 101;

        bool Create(HWND parent, HINSTANCE instance, int controlId);
        HWND Window() const;

        void SetSnapshot(const Core::ProcessSnapshot* snapshot);
        void SetSelectedPid(std::uint32_t pid);
        void FocusProcess(std::uint32_t pid);

    private:
        struct LayoutNode
        {
            std::uint32_t pid = 0;
            RECT rect = {};
        };

        static LRESULT CALLBACK WindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
        LRESULT HandleMessage(UINT message, WPARAM wParam, LPARAM lParam);

        void RebuildGraph(bool centerOnFocus);
        void RebuildLayout();
        void UpdateScrollbars();
        void ScrollTo(int x, int y);
        void ScrollBy(int dx, int dy);
        void CenterOnPid(std::uint32_t pid);
        void Paint(HDC targetDc);
        std::uint32_t HitTest(int x, int y) const;
        const Core::FocusedGraphNode* FindGraphNode(std::uint32_t pid) const;
        RECT ClientRect() const;

        HWND hwnd_ = nullptr;
        HWND parent_ = nullptr;
        HINSTANCE instance_ = nullptr;
        HFONT font_ = nullptr;

        const Core::ProcessSnapshot* snapshot_ = nullptr;
        Core::FocusedGraph graph_;
        std::uint32_t focusPid_ = 0;
        std::uint32_t selectedPid_ = 0;

        std::vector<LayoutNode> layout_;
        int contentWidth_ = 0;
        int contentHeight_ = 0;
        int scrollX_ = 0;
        int scrollY_ = 0;
    };
}
