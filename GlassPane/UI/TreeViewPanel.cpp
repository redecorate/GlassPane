#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "TreeViewPanel.h"

#include <Windowsx.h>

#include <algorithm>
#include <sstream>
#include <string>

namespace GlassPane::UI
{
    namespace
    {
        constexpr wchar_t ClassName[] = L"GlassPaneTreeViewPanel";
        constexpr int NodeWidth = 168;
        constexpr int NodeHeight = 66;
        constexpr int HorizontalSpacing = 52;
        constexpr int VerticalSpacing = 18;
        constexpr int Margin = 18;

        int RectWidth(const RECT& rect)
        {
            return static_cast<int>(std::max<LONG>(0, rect.right - rect.left));
        }

        int RectHeight(const RECT& rect)
        {
            return static_cast<int>(std::max<LONG>(0, rect.bottom - rect.top));
        }

        bool Intersects(const RECT& left, const RECT& right)
        {
            RECT intersection = {};
            return IntersectRect(&intersection, &left, &right) != FALSE;
        }

        std::wstring NodeName(const Core::FocusedGraphNode& node)
        {
            return node.name.empty() ? L"(unknown)" : node.name;
        }

        void DrawEllipsizedText(HDC dc, const std::wstring& text, RECT rect, COLORREF color, UINT format)
        {
            SetTextColor(dc, color);
            DrawTextW(dc, text.c_str(), static_cast<int>(text.size()), &rect, format | DT_END_ELLIPSIS | DT_NOPREFIX);
        }

        COLORREF SeverityColor(Core::Severity severity, bool selected)
        {
            if (selected)
            {
                return RGB(30, 90, 180);
            }

            switch (severity)
            {
            case Core::Severity::High:
                return RGB(190, 40, 40);
            case Core::Severity::Medium:
                return RGB(185, 105, 25);
            case Core::Severity::Low:
                return RGB(55, 110, 175);
            case Core::Severity::Info:
                return RGB(90, 90, 90);
            case Core::Severity::None:
            default:
                return RGB(120, 120, 120);
            }
        }

        COLORREF SeverityTextColor(Core::Severity severity)
        {
            switch (severity)
            {
            case Core::Severity::High:
                return RGB(165, 30, 30);
            case Core::Severity::Medium:
                return RGB(150, 80, 15);
            case Core::Severity::Low:
                return RGB(45, 95, 155);
            case Core::Severity::Info:
                return RGB(70, 70, 70);
            case Core::Severity::None:
            default:
                return RGB(70, 70, 70);
            }
        }
    }

    bool TreeViewPanel::Create(HWND parent, HINSTANCE instance, int controlId)
    {
        parent_ = parent;
        instance_ = instance;
        font_ = reinterpret_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));

        WNDCLASSEXW windowClass = {};
        windowClass.cbSize = sizeof(windowClass);
        windowClass.lpfnWndProc = TreeViewPanel::WindowProc;
        windowClass.hInstance = instance_;
        windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        windowClass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
        windowClass.lpszClassName = ClassName;

        if (RegisterClassExW(&windowClass) == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
        {
            return false;
        }

        hwnd_ = CreateWindowExW(
            WS_EX_CLIENTEDGE,
            ClassName,
            L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL,
            0,
            0,
            0,
            0,
            parent_,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(controlId)),
            instance_,
            this);

        return hwnd_ != nullptr;
    }

    HWND TreeViewPanel::Window() const
    {
        return hwnd_;
    }

    void TreeViewPanel::SetSnapshot(const Core::ProcessSnapshot* snapshot)
    {
        snapshot_ = snapshot;
        RebuildGraph(false);
    }

    void TreeViewPanel::SetSelectedPid(std::uint32_t pid)
    {
        selectedPid_ = pid;
        InvalidateRect(hwnd_, nullptr, TRUE);
    }

    void TreeViewPanel::FocusProcess(std::uint32_t pid)
    {
        focusPid_ = pid;
        RebuildGraph(true);
    }

    LRESULT CALLBACK TreeViewPanel::WindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
    {
        TreeViewPanel* panel = nullptr;
        if (message == WM_NCCREATE)
        {
            auto* createStruct = reinterpret_cast<CREATESTRUCTW*>(lParam);
            panel = reinterpret_cast<TreeViewPanel*>(createStruct->lpCreateParams);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(panel));
            panel->hwnd_ = hwnd;
        }
        else
        {
            panel = reinterpret_cast<TreeViewPanel*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        }

        if (panel != nullptr)
        {
            return panel->HandleMessage(message, wParam, lParam);
        }

        return DefWindowProcW(hwnd, message, wParam, lParam);
    }

    LRESULT TreeViewPanel::HandleMessage(UINT message, WPARAM wParam, LPARAM lParam)
    {
        switch (message)
        {
        case WM_SETFONT:
            font_ = reinterpret_cast<HFONT>(wParam);
            InvalidateRect(hwnd_, nullptr, TRUE);
            return 0;

        case WM_SIZE:
            RebuildLayout();
            return 0;

        case WM_PAINT:
        {
            PAINTSTRUCT paint = {};
            HDC dc = BeginPaint(hwnd_, &paint);
            Paint(dc);
            EndPaint(hwnd_, &paint);
            return 0;
        }

        case WM_LBUTTONDOWN:
        {
            SetFocus(hwnd_);
            const std::uint32_t pid = HitTest(GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam));
            if (pid != 0)
            {
                SendMessageW(parent_, SelectionChangedMessage, static_cast<WPARAM>(pid), 0);
            }
            return 0;
        }

        case WM_MOUSEWHEEL:
        {
            const int delta = GET_WHEEL_DELTA_WPARAM(wParam);
            ScrollBy(0, -(delta / WHEEL_DELTA) * 48);
            return 0;
        }

        case WM_VSCROLL:
        {
            SCROLLINFO scroll = {};
            scroll.cbSize = sizeof(scroll);
            scroll.fMask = SIF_ALL;
            GetScrollInfo(hwnd_, SB_VERT, &scroll);

            int next = scrollY_;
            switch (LOWORD(wParam))
            {
            case SB_LINEUP:
                next -= 32;
                break;
            case SB_LINEDOWN:
                next += 32;
                break;
            case SB_PAGEUP:
                next -= static_cast<int>(scroll.nPage);
                break;
            case SB_PAGEDOWN:
                next += static_cast<int>(scroll.nPage);
                break;
            case SB_THUMBTRACK:
            case SB_THUMBPOSITION:
                next = scroll.nTrackPos;
                break;
            default:
                break;
            }

            ScrollTo(scrollX_, next);
            return 0;
        }

        case WM_HSCROLL:
        {
            SCROLLINFO scroll = {};
            scroll.cbSize = sizeof(scroll);
            scroll.fMask = SIF_ALL;
            GetScrollInfo(hwnd_, SB_HORZ, &scroll);

            int next = scrollX_;
            switch (LOWORD(wParam))
            {
            case SB_LINELEFT:
                next -= 32;
                break;
            case SB_LINERIGHT:
                next += 32;
                break;
            case SB_PAGELEFT:
                next -= static_cast<int>(scroll.nPage);
                break;
            case SB_PAGERIGHT:
                next += static_cast<int>(scroll.nPage);
                break;
            case SB_THUMBTRACK:
            case SB_THUMBPOSITION:
                next = scroll.nTrackPos;
                break;
            default:
                break;
            }

            ScrollTo(next, scrollY_);
            return 0;
        }

        default:
            return DefWindowProcW(hwnd_, message, wParam, lParam);
        }
    }

    void TreeViewPanel::RebuildGraph(bool centerOnFocus)
    {
        if (snapshot_ == nullptr || focusPid_ == 0)
        {
            graph_ = {};
            layout_.clear();
            scrollX_ = 0;
            scrollY_ = 0;
            contentWidth_ = 0;
            contentHeight_ = 0;
            UpdateScrollbars();
            InvalidateRect(hwnd_, nullptr, TRUE);
            return;
        }

        graph_ = Core::BuildFocusedTree(*snapshot_, focusPid_, 2);
        RebuildLayout();
        if (centerOnFocus)
        {
            CenterOnPid(focusPid_);
        }
        InvalidateRect(hwnd_, nullptr, TRUE);
    }

    void TreeViewPanel::RebuildLayout()
    {
        layout_.clear();
        contentWidth_ = Margin;
        contentHeight_ = Margin;

        int row = 0;
        for (const Core::FocusedGraphNode& node : graph_.nodes)
        {
            const int x = Margin + static_cast<int>(node.depth) * (NodeWidth + HorizontalSpacing);
            const int y = Margin + row * (NodeHeight + VerticalSpacing);
            RECT rect = { x, y, x + NodeWidth, y + NodeHeight };
            layout_.push_back({ node.pid, rect });
            contentWidth_ = std::max(contentWidth_, static_cast<int>(rect.right) + Margin);
            contentHeight_ = std::max(contentHeight_, static_cast<int>(rect.bottom) + Margin);
            ++row;
        }

        UpdateScrollbars();
    }

    void TreeViewPanel::UpdateScrollbars()
    {
        if (hwnd_ == nullptr)
        {
            return;
        }

        const RECT client = ClientRect();
        const int pageWidth = std::max(1, RectWidth(client));
        const int pageHeight = std::max(1, RectHeight(client));
        const int maxX = std::max(0, contentWidth_ - pageWidth);
        const int maxY = std::max(0, contentHeight_ - pageHeight);

        scrollX_ = std::max(0, std::min(scrollX_, maxX));
        scrollY_ = std::max(0, std::min(scrollY_, maxY));

        SCROLLINFO horizontal = {};
        horizontal.cbSize = sizeof(horizontal);
        horizontal.fMask = SIF_RANGE | SIF_PAGE | SIF_POS;
        horizontal.nMin = 0;
        horizontal.nMax = std::max(0, contentWidth_ - 1);
        horizontal.nPage = static_cast<UINT>(pageWidth);
        horizontal.nPos = scrollX_;
        SetScrollInfo(hwnd_, SB_HORZ, &horizontal, TRUE);

        SCROLLINFO vertical = {};
        vertical.cbSize = sizeof(vertical);
        vertical.fMask = SIF_RANGE | SIF_PAGE | SIF_POS;
        vertical.nMin = 0;
        vertical.nMax = std::max(0, contentHeight_ - 1);
        vertical.nPage = static_cast<UINT>(pageHeight);
        vertical.nPos = scrollY_;
        SetScrollInfo(hwnd_, SB_VERT, &vertical, TRUE);
    }

    void TreeViewPanel::ScrollTo(int x, int y)
    {
        const RECT client = ClientRect();
        const int maxX = std::max(0, contentWidth_ - RectWidth(client));
        const int maxY = std::max(0, contentHeight_ - RectHeight(client));
        const int nextX = std::max(0, std::min(x, maxX));
        const int nextY = std::max(0, std::min(y, maxY));

        if (nextX == scrollX_ && nextY == scrollY_)
        {
            return;
        }

        scrollX_ = nextX;
        scrollY_ = nextY;
        UpdateScrollbars();
        InvalidateRect(hwnd_, nullptr, TRUE);
    }

    void TreeViewPanel::ScrollBy(int dx, int dy)
    {
        ScrollTo(scrollX_ + dx, scrollY_ + dy);
    }

    void TreeViewPanel::CenterOnPid(std::uint32_t pid)
    {
        for (const LayoutNode& node : layout_)
        {
            if (node.pid != pid)
            {
                continue;
            }

            const RECT client = ClientRect();
            const int targetX = ((node.rect.left + node.rect.right) / 2) - (RectWidth(client) / 2);
            const int targetY = ((node.rect.top + node.rect.bottom) / 2) - (RectHeight(client) / 2);
            ScrollTo(targetX, targetY);
            return;
        }
    }

    void TreeViewPanel::Paint(HDC targetDc)
    {
        const RECT client = ClientRect();
        const int width = RectWidth(client);
        const int height = RectHeight(client);
        if (width <= 0 || height <= 0)
        {
            return;
        }

        HDC memoryDc = CreateCompatibleDC(targetDc);
        HBITMAP bitmap = CreateCompatibleBitmap(targetDc, width, height);
        HGDIOBJ oldBitmap = SelectObject(memoryDc, bitmap);
        HGDIOBJ oldFont = SelectObject(memoryDc, font_);

        HBRUSH background = CreateSolidBrush(RGB(255, 255, 255));
        FillRect(memoryDc, &client, background);
        DeleteObject(background);

        SetBkMode(memoryDc, TRANSPARENT);

        if (graph_.nodes.empty())
        {
            RECT textRect = client;
            InflateRect(&textRect, -16, -16);
            DrawEllipsizedText(
                memoryDc,
                L"No process selected for graph view.",
                textRect,
                RGB(96, 96, 96),
                DT_LEFT | DT_TOP | DT_SINGLELINE);
            BitBlt(targetDc, 0, 0, width, height, memoryDc, 0, 0, SRCCOPY);
            SelectObject(memoryDc, oldFont);
            SelectObject(memoryDc, oldBitmap);
            DeleteObject(bitmap);
            DeleteDC(memoryDc);
            return;
        }

        HPEN edgePen = CreatePen(PS_SOLID, 1, RGB(150, 150, 150));
        HPEN chainEdgePen = CreatePen(PS_SOLID, 3, RGB(35, 95, 175));
        HGDIOBJ oldPen = SelectObject(memoryDc, edgePen);

        for (const Core::FocusedGraphEdge& edge : graph_.edges)
        {
            RECT parentRect = {};
            RECT childRect = {};
            bool foundParent = false;
            bool foundChild = false;

            for (const LayoutNode& node : layout_)
            {
                if (node.pid == edge.parentPid)
                {
                    parentRect = node.rect;
                    foundParent = true;
                }
                if (node.pid == edge.childPid)
                {
                    childRect = node.rect;
                    foundChild = true;
                }
            }

            if (!foundParent || !foundChild)
            {
                continue;
            }

            SelectObject(memoryDc, edge.inSelectedChain ? chainEdgePen : edgePen);

            OffsetRect(&parentRect, -scrollX_, -scrollY_);
            OffsetRect(&childRect, -scrollX_, -scrollY_);

            RECT edgeBounds = parentRect;
            UnionRect(&edgeBounds, &edgeBounds, &childRect);
            if (!Intersects(edgeBounds, client))
            {
                continue;
            }

            const int parentY = (parentRect.top + parentRect.bottom) / 2;
            const int childY = (childRect.top + childRect.bottom) / 2;
            const int midX = (parentRect.right + childRect.left) / 2;

            MoveToEx(memoryDc, parentRect.right, parentY, nullptr);
            LineTo(memoryDc, midX, parentY);
            LineTo(memoryDc, midX, childY);
            LineTo(memoryDc, childRect.left, childY);
        }

        SelectObject(memoryDc, oldPen);
        DeleteObject(chainEdgePen);
        DeleteObject(edgePen);

        for (const LayoutNode& layoutNode : layout_)
        {
            const Core::FocusedGraphNode* graphNode = FindGraphNode(layoutNode.pid);
            if (graphNode == nullptr)
            {
                continue;
            }

            RECT rect = layoutNode.rect;
            OffsetRect(&rect, -scrollX_, -scrollY_);
            if (!Intersects(rect, client))
            {
                continue;
            }

            const bool selected = graphNode->pid == selectedPid_;
            COLORREF borderColor = SeverityColor(graphNode->severity, selected);
            if (!selected && graphNode->inSelectedChain && !graphNode->suspicious)
            {
                borderColor = RGB(35, 95, 175);
            }
            const COLORREF fillColor = selected
                ? RGB(230, 240, 255)
                : (graphNode->inSelectedChain ? RGB(245, 249, 255) : RGB(250, 250, 250));

            HBRUSH fillBrush = CreateSolidBrush(fillColor);
            HPEN borderPen = CreatePen(
                PS_SOLID,
                selected || graphNode->suspicious || graphNode->inSelectedChain ? 2 : 1,
                borderColor);
            HGDIOBJ oldNodeBrush = SelectObject(memoryDc, fillBrush);
            HGDIOBJ oldNodePen = SelectObject(memoryDc, borderPen);
            RoundRect(memoryDc, rect.left, rect.top, rect.right, rect.bottom, 8, 8);
            SelectObject(memoryDc, oldNodePen);
            SelectObject(memoryDc, oldNodeBrush);
            DeleteObject(borderPen);
            DeleteObject(fillBrush);

            RECT nameRect = rect;
            nameRect.left += 8;
            nameRect.right -= 8;
            nameRect.top += 6;
            nameRect.bottom = nameRect.top + 18;
            DrawEllipsizedText(
                memoryDc,
                NodeName(*graphNode),
                nameRect,
                graphNode->suspicious ? SeverityTextColor(graphNode->severity) : RGB(24, 24, 24),
                DT_LEFT | DT_SINGLELINE);

            RECT pidRect = rect;
            pidRect.left += 8;
            pidRect.right -= 8;
            pidRect.top += 26;
            pidRect.bottom = pidRect.top + 16;
            std::wstringstream pidText;
            pidText << L"PID " << graphNode->pid;
            DrawEllipsizedText(memoryDc, pidText.str(), pidRect, RGB(70, 70, 70), DT_LEFT | DT_SINGLELINE);

            RECT stateRect = rect;
            stateRect.left += 8;
            stateRect.right -= 8;
            stateRect.top += 44;
            stateRect.bottom = stateRect.top + 16;
            DrawEllipsizedText(
                memoryDc,
                Core::SeverityToString(graphNode->severity),
                stateRect,
                SeverityTextColor(graphNode->severity),
                DT_LEFT | DT_SINGLELINE);
        }

        BitBlt(targetDc, 0, 0, width, height, memoryDc, 0, 0, SRCCOPY);

        SelectObject(memoryDc, oldFont);
        SelectObject(memoryDc, oldBitmap);
        DeleteObject(bitmap);
        DeleteDC(memoryDc);
    }

    std::uint32_t TreeViewPanel::HitTest(int x, int y) const
    {
        const int logicalX = x + scrollX_;
        const int logicalY = y + scrollY_;

        for (auto it = layout_.rbegin(); it != layout_.rend(); ++it)
        {
            const RECT& rect = it->rect;
            if (logicalX >= rect.left && logicalX <= rect.right &&
                logicalY >= rect.top && logicalY <= rect.bottom)
            {
                return it->pid;
            }
        }

        return 0;
    }

    const Core::FocusedGraphNode* TreeViewPanel::FindGraphNode(std::uint32_t pid) const
    {
        for (const Core::FocusedGraphNode& node : graph_.nodes)
        {
            if (node.pid == pid)
            {
                return &node;
            }
        }
        return nullptr;
    }

    RECT TreeViewPanel::ClientRect() const
    {
        RECT rect = {};
        if (hwnd_ != nullptr)
        {
            GetClientRect(hwnd_, &rect);
        }
        return rect;
    }
}
