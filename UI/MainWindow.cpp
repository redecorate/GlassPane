#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "MainWindow.h"

#include "../Core/ChainAnalysis.h"
#include "../Core/FileIdentity.h"
#include "../Core/ModuleCollector.h"
#include "../Core/ProcessCollector.h"
#include "../Core/ProcessTree.h"
#include "../Export/JsonExporter.h"
#include "../resource.h"

#include <CommCtrl.h>
#include <commdlg.h>

#include <algorithm>
#include <cwctype>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "Comctl32.lib")
#pragma comment(lib, "Comdlg32.lib")

namespace GlassPane::UI
{
    namespace
    {
        constexpr int IdRefreshButton = 1001;
        constexpr int IdExportButton = 1002;
        constexpr int IdSearchEdit = 1003;
        constexpr int IdSuspiciousOnlyCheck = 1004;
        constexpr int IdProcessList = 1005;
        constexpr int IdDetailsEdit = 1006;
        constexpr int IdFocusGraphButton = 1007;
        constexpr int IdTreeViewPanel = 1008;
        constexpr int IdLowSeverityCheck = 1009;
        constexpr int IdMediumSeverityCheck = 1010;
        constexpr int IdHighSeverityCheck = 1011;
        constexpr int IdCopyChainButton = 1012;
        constexpr int IdBottomTab = 1013;
        constexpr int IdTimelineList = 1014;
        constexpr int IdTimelineAllRadio = 1015;
        constexpr int IdTimelineSuspiciousRadio = 1016;
        constexpr int IdTimelineHighRadio = 1017;
        constexpr int IdRefreshModulesButton = 1018;
        constexpr int IdExportSelectedButton = 1019;

        std::wstring ToLower(std::wstring value)
        {
            std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) {
                return static_cast<wchar_t>(std::towlower(ch));
            });
            return value;
        }

        std::wstring FormatOptionalNumber(const std::optional<std::uint32_t>& value)
        {
            if (!value.has_value())
            {
                return L"";
            }
            return std::to_wstring(value.value());
        }

        std::wstring FileSizeText(std::uint64_t bytes)
        {
            std::wstringstream stream;
            stream << bytes << L" bytes";
            return stream.str();
        }

        std::wstring SignatureStatusText(const Core::FileIdentity& identity)
        {
            if (!identity.exists)
            {
                return L"(unavailable)";
            }
            if (identity.signatureValid)
            {
                return L"Valid Authenticode signature";
            }
            if (identity.signaturePresent)
            {
                return L"Signature present but invalid";
            }
            return L"Unsigned";
        }

        std::wstring LocalTimestamp()
        {
            SYSTEMTIME local = {};
            GetLocalTime(&local);

            wchar_t buffer[64] = {};
            swprintf_s(
                buffer,
                L"%04u-%02u-%02u %02u:%02u:%02u",
                local.wYear,
                local.wMonth,
                local.wDay,
                local.wHour,
                local.wMinute,
                local.wSecond);
            return buffer;
        }

        void SetWindowFont(HWND hwnd, HFONT font)
        {
            SendMessageW(hwnd, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
        }

        void InsertColumn(HWND listView, int index, const wchar_t* text, int width)
        {
            LVCOLUMNW column = {};
            column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
            column.pszText = const_cast<wchar_t*>(text);
            column.cx = width;
            column.iSubItem = index;
            ListView_InsertColumn(listView, index, &column);
        }

        void SetListText(HWND listView, int row, int column, const std::wstring& text)
        {
            ListView_SetItemText(listView, row, column, const_cast<wchar_t*>(text.c_str()));
        }

        HICON LoadGlassPaneIcon(HINSTANCE instance, int width, int height)
        {
            HICON icon = reinterpret_cast<HICON>(LoadImageW(
                instance,
                MAKEINTRESOURCEW(IDI_GLASSPANE_ICON),
                IMAGE_ICON,
                width,
                height,
                LR_DEFAULTCOLOR | LR_SHARED));
            return icon != nullptr ? icon : LoadIconW(nullptr, IDI_APPLICATION);
        }
    }

    int RunApp(HINSTANCE instance, int showCommand)
    {
        MainWindow window;
        if (!window.Create(instance, showCommand))
        {
            return -1;
        }
        return window.MessageLoop();
    }

    bool MainWindow::Create(HINSTANCE instance, int showCommand)
    {
        instance_ = instance;

        INITCOMMONCONTROLSEX controls = {};
        controls.dwSize = sizeof(controls);
        controls.dwICC = ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES | ICC_TAB_CLASSES;
        InitCommonControlsEx(&controls);

        WNDCLASSEXW windowClass = {};
        windowClass.cbSize = sizeof(windowClass);
        windowClass.lpfnWndProc = MainWindow::WindowProc;
        windowClass.hInstance = instance_;
        windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        windowClass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
        windowClass.lpszClassName = L"GlassPaneMainWindow";
        windowClass.hIcon = LoadGlassPaneIcon(instance_, GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON));
        windowClass.hIconSm = LoadGlassPaneIcon(instance_, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON));

        if (RegisterClassExW(&windowClass) == 0)
        {
            return false;
        }

        hwnd_ = CreateWindowExW(
            0,
            windowClass.lpszClassName,
            L"GlassPane v0.1",
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            1180,
            720,
            nullptr,
            nullptr,
            instance_,
            this);

        if (hwnd_ == nullptr)
        {
            return false;
        }
        SendMessageW(hwnd_, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(windowClass.hIcon));
        SendMessageW(hwnd_, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(windowClass.hIconSm));

        ShowWindow(hwnd_, showCommand);
        UpdateWindow(hwnd_);
        return true;
    }

    int MainWindow::MessageLoop()
    {
        MSG message = {};
        while (GetMessageW(&message, nullptr, 0, 0) > 0)
        {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
        return static_cast<int>(message.wParam);
    }

    LRESULT CALLBACK MainWindow::WindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
    {
        MainWindow* window = nullptr;
        if (message == WM_NCCREATE)
        {
            auto* createStruct = reinterpret_cast<CREATESTRUCTW*>(lParam);
            window = reinterpret_cast<MainWindow*>(createStruct->lpCreateParams);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(window));
            window->hwnd_ = hwnd;
        }
        else
        {
            window = reinterpret_cast<MainWindow*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        }

        if (window != nullptr)
        {
            return window->HandleMessage(message, wParam, lParam);
        }

        return DefWindowProcW(hwnd, message, wParam, lParam);
    }

    LRESULT MainWindow::HandleMessage(UINT message, WPARAM wParam, LPARAM lParam)
    {
        switch (message)
        {
        case WM_CREATE:
            OnCreate();
            return 0;

        case WM_COMMAND:
            OnCommand(wParam, lParam);
            return 0;

        case WM_NOTIFY:
            OnNotify(lParam);
            return 0;

        case TreeViewPanel::SelectionChangedMessage:
            SelectProcess(static_cast<std::uint32_t>(wParam), true, true);
            return 0;

        case WM_SIZE:
            OnSize(LOWORD(lParam), HIWORD(lParam));
            return 0;

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;

        default:
            return DefWindowProcW(hwnd_, message, wParam, lParam);
        }
    }

    void MainWindow::OnCreate()
    {
        uiFont_ = reinterpret_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));

        refreshButton_ = CreateWindowExW(
            0,
            WC_BUTTONW,
            L"Refresh",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            0,
            0,
            0,
            0,
            hwnd_,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(IdRefreshButton)),
            instance_,
            nullptr);

        exportButton_ = CreateWindowExW(
            0,
            WC_BUTTONW,
            L"Export JSON",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            0,
            0,
            0,
            0,
            hwnd_,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(IdExportButton)),
            instance_,
            nullptr);

        searchLabel_ = CreateWindowExW(
            0,
            WC_STATICW,
            L"Search",
            WS_CHILD | WS_VISIBLE,
            0,
            0,
            0,
            0,
            hwnd_,
            nullptr,
            instance_,
            nullptr);

        focusGraphButton_ = CreateWindowExW(
            0,
            WC_BUTTONW,
            L"Focus selected",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            0,
            0,
            0,
            0,
            hwnd_,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(IdFocusGraphButton)),
            instance_,
            nullptr);

        bottomTab_ = CreateWindowExW(
            0,
            WC_TABCONTROLW,
            L"",
            WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
            0,
            0,
            0,
            0,
            hwnd_,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(IdBottomTab)),
            instance_,
            nullptr);

        TCITEMW graphTab = {};
        graphTab.mask = TCIF_TEXT;
        graphTab.pszText = const_cast<wchar_t*>(L"Graph View");
        TabCtrl_InsertItem(bottomTab_, 0, &graphTab);

        TCITEMW timelineTab = {};
        timelineTab.mask = TCIF_TEXT;
        timelineTab.pszText = const_cast<wchar_t*>(L"Timeline View");
        TabCtrl_InsertItem(bottomTab_, 1, &timelineTab);

        searchEdit_ = CreateWindowExW(
            WS_EX_CLIENTEDGE,
            WC_EDITW,
            L"",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            0,
            0,
            0,
            0,
            hwnd_,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(IdSearchEdit)),
            instance_,
            nullptr);

        suspiciousOnlyCheck_ = CreateWindowExW(
            0,
            WC_BUTTONW,
            L"Suspicious only",
            WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            0,
            0,
            0,
            0,
            hwnd_,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(IdSuspiciousOnlyCheck)),
            instance_,
            nullptr);

        lowSeverityCheck_ = CreateWindowExW(
            0,
            WC_BUTTONW,
            L"Low",
            WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            0,
            0,
            0,
            0,
            hwnd_,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(IdLowSeverityCheck)),
            instance_,
            nullptr);

        mediumSeverityCheck_ = CreateWindowExW(
            0,
            WC_BUTTONW,
            L"Medium",
            WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            0,
            0,
            0,
            0,
            hwnd_,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(IdMediumSeverityCheck)),
            instance_,
            nullptr);

        highSeverityCheck_ = CreateWindowExW(
            0,
            WC_BUTTONW,
            L"High",
            WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            0,
            0,
            0,
            0,
            hwnd_,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(IdHighSeverityCheck)),
            instance_,
            nullptr);

        SendMessageW(lowSeverityCheck_, BM_SETCHECK, BST_CHECKED, 0);
        SendMessageW(mediumSeverityCheck_, BM_SETCHECK, BST_CHECKED, 0);
        SendMessageW(highSeverityCheck_, BM_SETCHECK, BST_CHECKED, 0);

        statusText_ = CreateWindowExW(
            0,
            WC_STATICW,
            L"",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            0,
            0,
            0,
            0,
            hwnd_,
            nullptr,
            instance_,
            nullptr);

        listView_ = CreateWindowExW(
            WS_EX_CLIENTEDGE,
            WC_LISTVIEWW,
            L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
            0,
            0,
            0,
            0,
            hwnd_,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(IdProcessList)),
            instance_,
            nullptr);

        detailsEdit_ = CreateWindowExW(
            WS_EX_CLIENTEDGE,
            WC_EDITW,
            L"",
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | WS_VSCROLL | ES_AUTOVSCROLL,
            0,
            0,
            0,
            0,
            hwnd_,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(IdDetailsEdit)),
            instance_,
            nullptr);

        copyChainButton_ = CreateWindowExW(
            0,
            WC_BUTTONW,
            L"Copy Chain",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            0,
            0,
            0,
            0,
            hwnd_,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(IdCopyChainButton)),
            instance_,
            nullptr);

        refreshModulesButton_ = CreateWindowExW(
            0,
            WC_BUTTONW,
            L"Refresh Modules",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            0,
            0,
            0,
            0,
            hwnd_,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(IdRefreshModulesButton)),
            instance_,
            nullptr);

        exportSelectedButton_ = CreateWindowExW(
            0,
            WC_BUTTONW,
            L"Export Selected",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            0,
            0,
            0,
            0,
            hwnd_,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(IdExportSelectedButton)),
            instance_,
            nullptr);

        timelineAllRadio_ = CreateWindowExW(
            0,
            WC_BUTTONW,
            L"All",
            WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON | WS_GROUP,
            0,
            0,
            0,
            0,
            hwnd_,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(IdTimelineAllRadio)),
            instance_,
            nullptr);

        timelineSuspiciousRadio_ = CreateWindowExW(
            0,
            WC_BUTTONW,
            L"Suspicious only",
            WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON,
            0,
            0,
            0,
            0,
            hwnd_,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(IdTimelineSuspiciousRadio)),
            instance_,
            nullptr);

        timelineHighRadio_ = CreateWindowExW(
            0,
            WC_BUTTONW,
            L"High severity only",
            WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON,
            0,
            0,
            0,
            0,
            hwnd_,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(IdTimelineHighRadio)),
            instance_,
            nullptr);

        SendMessageW(timelineAllRadio_, BM_SETCHECK, BST_CHECKED, 0);

        timelineListView_ = CreateWindowExW(
            WS_EX_CLIENTEDGE,
            WC_LISTVIEWW,
            L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
            0,
            0,
            0,
            0,
            hwnd_,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(IdTimelineList)),
            instance_,
            nullptr);

        treeViewPanel_.Create(hwnd_, instance_, IdTreeViewPanel);

        SetWindowFont(refreshButton_, uiFont_);
        SetWindowFont(exportButton_, uiFont_);
        SetWindowFont(focusGraphButton_, uiFont_);
        SetWindowFont(searchLabel_, uiFont_);
        SetWindowFont(bottomTab_, uiFont_);
        SetWindowFont(searchEdit_, uiFont_);
        SetWindowFont(suspiciousOnlyCheck_, uiFont_);
        SetWindowFont(lowSeverityCheck_, uiFont_);
        SetWindowFont(mediumSeverityCheck_, uiFont_);
        SetWindowFont(highSeverityCheck_, uiFont_);
        SetWindowFont(timelineAllRadio_, uiFont_);
        SetWindowFont(timelineSuspiciousRadio_, uiFont_);
        SetWindowFont(timelineHighRadio_, uiFont_);
        SetWindowFont(timelineListView_, uiFont_);
        SetWindowFont(statusText_, uiFont_);
        SetWindowFont(listView_, uiFont_);
        SetWindowFont(detailsEdit_, uiFont_);
        SetWindowFont(copyChainButton_, uiFont_);
        SetWindowFont(refreshModulesButton_, uiFont_);
        SetWindowFont(exportSelectedButton_, uiFont_);
        SetWindowFont(treeViewPanel_.Window(), uiFont_);

        ListView_SetExtendedListViewStyle(
            listView_,
            LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);

        ListView_SetExtendedListViewStyle(
            timelineListView_,
            LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);

        InsertColumn(listView_, 0, L"Process", 300);
        InsertColumn(listView_, 1, L"PID", 78);
        InsertColumn(listView_, 2, L"PPID", 78);
        InsertColumn(listView_, 3, L"Start Time", 150);
        InsertColumn(listView_, 4, L"Session", 78);
        InsertColumn(listView_, 5, L"Arch", 82);
        InsertColumn(listView_, 6, L"Suspicious", 96);
        InsertColumn(listView_, 7, L"Severity", 82);
        InsertColumn(listView_, 8, L"Chain Severity", 112);

        InsertColumn(timelineListView_, 0, L"Start Time", 150);
        InsertColumn(timelineListView_, 1, L"Process", 180);
        InsertColumn(timelineListView_, 2, L"PID", 78);
        InsertColumn(timelineListView_, 3, L"Parent", 210);
        InsertColumn(timelineListView_, 4, L"Severity", 82);
        InsertColumn(timelineListView_, 5, L"Indicator", 360);

        RefreshSnapshot();
        UpdateBottomPanelVisibility();
    }

    void MainWindow::OnCommand(WPARAM wParam, LPARAM lParam)
    {
        const int id = LOWORD(wParam);
        const int notification = HIWORD(wParam);

        if (id == IdRefreshButton && notification == BN_CLICKED)
        {
            RefreshSnapshot();
            return;
        }

        if (id == IdExportButton && notification == BN_CLICKED)
        {
            ExportSnapshot();
            return;
        }

        if (id == IdCopyChainButton && notification == BN_CLICKED)
        {
            CopySelectedChainToClipboard();
            return;
        }

        if (id == IdRefreshModulesButton && notification == BN_CLICKED)
        {
            RefreshSelectedModules();
            return;
        }

        if (id == IdExportSelectedButton && notification == BN_CLICKED)
        {
            ExportSelectedDetails();
            return;
        }

        if (id == IdFocusGraphButton && notification == BN_CLICKED)
        {
            treeViewPanel_.SetSelectedPid(selectedPid_);
            treeViewPanel_.FocusProcess(selectedPid_);
            return;
        }

        if (id == IdSearchEdit && notification == EN_CHANGE)
        {
            RebuildProcessList();
            return;
        }

        if (id == IdSuspiciousOnlyCheck && notification == BN_CLICKED)
        {
            RebuildProcessList();
            return;
        }

        if ((id == IdLowSeverityCheck || id == IdMediumSeverityCheck || id == IdHighSeverityCheck) &&
            notification == BN_CLICKED)
        {
            RebuildProcessList();
            return;
        }

        if ((id == IdTimelineAllRadio || id == IdTimelineSuspiciousRadio || id == IdTimelineHighRadio) &&
            notification == BN_CLICKED)
        {
            RebuildTimelineList();
            return;
        }

        UNREFERENCED_PARAMETER(lParam);
    }

    void MainWindow::OnNotify(LPARAM lParam)
    {
        const auto* header = reinterpret_cast<NMHDR*>(lParam);

        if (header->idFrom == IdBottomTab && header->code == TCN_SELCHANGE)
        {
            UpdateBottomPanelVisibility();
            return;
        }

        if (header->idFrom == IdTimelineList && header->code == LVN_ITEMCHANGED)
        {
            if (suppressTimelineSelectionEvents_)
            {
                return;
            }

            const auto* change = reinterpret_cast<NMLISTVIEW*>(lParam);
            if ((change->uChanged & LVIF_STATE) == 0 ||
                (change->uNewState & LVIS_SELECTED) == 0 ||
                change->iItem < 0)
            {
                return;
            }

            LVITEMW item = {};
            item.mask = LVIF_PARAM;
            item.iItem = change->iItem;
            if (ListView_GetItem(timelineListView_, &item) != FALSE)
            {
                SelectProcess(static_cast<std::uint32_t>(item.lParam), true, true);
            }
            return;
        }

        if (suppressListSelectionEvents_)
        {
            return;
        }

        if (header->idFrom != IdProcessList || header->code != LVN_ITEMCHANGED)
        {
            return;
        }

        const auto* change = reinterpret_cast<NMLISTVIEW*>(lParam);
        if ((change->uChanged & LVIF_STATE) == 0 ||
            (change->uNewState & LVIS_SELECTED) == 0 ||
            change->iItem < 0)
        {
            return;
        }

        LVITEMW item = {};
        item.mask = LVIF_PARAM;
        item.iItem = change->iItem;
        if (ListView_GetItem(listView_, &item) != FALSE)
        {
            SelectProcess(static_cast<std::uint32_t>(item.lParam), false, true);
        }
    }

    void MainWindow::OnSize(int width, int height)
    {
        constexpr int margin = 8;
        constexpr int gap = 8;
        constexpr int toolbarHeight = 30;
        constexpr int tabHeaderHeight = 28;
        constexpr int bottomToolbarHeight = 30;
        constexpr int labelWidth = 48;
        constexpr int buttonWidth = 92;
        constexpr int exportWidth = 110;
        constexpr int checkboxWidth = 140;
        constexpr int lowSeverityWidth = 54;
        constexpr int mediumSeverityWidth = 76;
        constexpr int highSeverityWidth = 58;
        constexpr int focusButtonWidth = 118;
        constexpr int timelineAllWidth = 54;
        constexpr int timelineSuspiciousWidth = 122;
        constexpr int timelineHighWidth = 132;

        const int usableWidth = std::max(0, width - (margin * 2));
        int x = margin;
        const int y = margin;

        MoveWindow(refreshButton_, x, y, buttonWidth, toolbarHeight, TRUE);
        x += buttonWidth + gap;
        MoveWindow(exportButton_, x, y, exportWidth, toolbarHeight, TRUE);
        x += exportWidth + gap;

        if (searchLabel_ != nullptr)
        {
            MoveWindow(searchLabel_, x, y + 7, labelWidth, 20, TRUE);
        }
        x += labelWidth + 4;

        const int statusWidth = std::max(120, usableWidth / 4);
        const int fixedRight = checkboxWidth +
            gap + lowSeverityWidth +
            gap + mediumSeverityWidth +
            gap + highSeverityWidth +
            gap + statusWidth;
        const int searchWidth = std::max(120, usableWidth - (x - margin) - fixedRight - gap);
        MoveWindow(searchEdit_, x, y + 3, searchWidth, 24, TRUE);
        x += searchWidth + gap;

        MoveWindow(suspiciousOnlyCheck_, x, y + 4, checkboxWidth, 24, TRUE);
        x += checkboxWidth + gap;
        MoveWindow(lowSeverityCheck_, x, y + 4, lowSeverityWidth, 24, TRUE);
        x += lowSeverityWidth + gap;
        MoveWindow(mediumSeverityCheck_, x, y + 4, mediumSeverityWidth, 24, TRUE);
        x += mediumSeverityWidth + gap;
        MoveWindow(highSeverityCheck_, x, y + 4, highSeverityWidth, 24, TRUE);
        x += highSeverityWidth + gap;
        MoveWindow(statusText_, x, y + 7, std::max(0, width - x - margin), 20, TRUE);

        const int contentY = margin + toolbarHeight + gap;
        const int contentHeight = std::max(0, height - contentY - margin);
        const int contentWidth = std::max(0, width - (margin * 2));
        int graphTotalHeight = std::min(280, std::max(170, contentHeight / 3));
        if (contentHeight < 430)
        {
            graphTotalHeight = std::max(120, contentHeight / 3);
        }
        graphTotalHeight = std::min(graphTotalHeight, std::max(0, contentHeight - 160));
        const int topHeight = std::max(0, contentHeight - graphTotalHeight - gap);

        int leftWidth = (contentWidth * 56) / 100;
        if (contentWidth < 720)
        {
            leftWidth = contentWidth / 2;
        }
        if (contentWidth >= 560)
        {
            leftWidth = std::max(280, std::min(leftWidth, contentWidth - 260));
        }
        const int rightWidth = std::max(0, contentWidth - leftWidth - gap);

        MoveWindow(listView_, margin, contentY, leftWidth, topHeight, TRUE);
        const int detailsX = margin + leftWidth + gap;
        constexpr int detailsHeaderHeight = 30;
        MoveWindow(copyChainButton_, detailsX, contentY + 2, 100, 24, TRUE);
        MoveWindow(refreshModulesButton_, detailsX + 108, contentY + 2, 124, 24, TRUE);
        MoveWindow(exportSelectedButton_, detailsX + 240, contentY + 2, 124, 24, TRUE);
        MoveWindow(
            detailsEdit_,
            detailsX,
            contentY + detailsHeaderHeight,
            rightWidth,
            std::max(0, topHeight - detailsHeaderHeight),
            TRUE);

        const int bottomY = contentY + topHeight + gap;
        MoveWindow(bottomTab_, margin, bottomY, contentWidth, graphTotalHeight, TRUE);

        const int tabContentX = margin + 6;
        const int tabContentY = bottomY + tabHeaderHeight;
        const int tabContentWidth = std::max(0, contentWidth - 12);
        const int tabContentHeight = std::max(0, graphTotalHeight - tabHeaderHeight - 6);

        MoveWindow(focusGraphButton_, tabContentX, tabContentY + 2, focusButtonWidth, 24, TRUE);
        MoveWindow(
            treeViewPanel_.Window(),
            tabContentX,
            tabContentY + bottomToolbarHeight,
            tabContentWidth,
            std::max(0, tabContentHeight - bottomToolbarHeight),
            TRUE);

        MoveWindow(timelineAllRadio_, tabContentX, tabContentY + 4, timelineAllWidth, 22, TRUE);
        MoveWindow(
            timelineSuspiciousRadio_,
            tabContentX + timelineAllWidth + gap,
            tabContentY + 4,
            timelineSuspiciousWidth,
            22,
            TRUE);
        MoveWindow(
            timelineHighRadio_,
            tabContentX + timelineAllWidth + gap + timelineSuspiciousWidth + gap,
            tabContentY + 4,
            timelineHighWidth,
            22,
            TRUE);
        MoveWindow(
            timelineListView_,
            tabContentX,
            tabContentY + bottomToolbarHeight,
            tabContentWidth,
            std::max(0, tabContentHeight - bottomToolbarHeight),
            TRUE);

        const int fixedColumns = 78 + 78 + 150 + 78 + 82 + 96 + 82 + 112 + 22;
        ListView_SetColumnWidth(listView_, 0, std::max(180, leftWidth - fixedColumns));
        ListView_SetColumnWidth(listView_, 1, 78);
        ListView_SetColumnWidth(listView_, 2, 78);
        ListView_SetColumnWidth(listView_, 3, 150);
        ListView_SetColumnWidth(listView_, 4, 78);
        ListView_SetColumnWidth(listView_, 5, 82);
        ListView_SetColumnWidth(listView_, 6, 96);
        ListView_SetColumnWidth(listView_, 7, 82);
        ListView_SetColumnWidth(listView_, 8, 112);

        ListView_SetColumnWidth(timelineListView_, 0, 150);
        ListView_SetColumnWidth(timelineListView_, 1, 180);
        ListView_SetColumnWidth(timelineListView_, 2, 78);
        ListView_SetColumnWidth(timelineListView_, 3, 210);
        ListView_SetColumnWidth(timelineListView_, 4, 82);
        ListView_SetColumnWidth(
            timelineListView_,
            5,
            std::max(180, tabContentWidth - (150 + 180 + 78 + 210 + 82 + 22)));

        UpdateBottomPanelVisibility();
    }

    void MainWindow::RefreshSnapshot()
    {
        SetWindowTextW(statusText_, L"Refreshing...");
        snapshot_ = Core::CollectProcessSnapshot();
        selectedModules_ = {};
        selectedModulesPid_ = 0;
        selectedModulesLoaded_ = false;
        treeViewPanel_.SetSnapshot(&snapshot_);
        RebuildProcessList();
        RebuildTimelineList();

        std::wstringstream status;
        status << snapshot_.processes.size() << L" processes | refreshed " << LocalTimestamp();
        SetWindowTextW(statusText_, status.str().c_str());
    }

    void MainWindow::RebuildProcessList()
    {
        const std::wstring filter = ToLower(GetSearchText());
        const bool suspiciousOnly = SendMessageW(suspiciousOnlyCheck_, BM_GETCHECK, 0, 0) == BST_CHECKED;
        const std::vector<Core::TreeRow> rows = Core::BuildTreeRows(snapshot_);

        visibleProcesses_.clear();
        suppressListSelectionEvents_ = true;
        SendMessageW(listView_, WM_SETREDRAW, FALSE, 0);
        ListView_DeleteAllItems(listView_);

        int listIndex = 0;
        bool selectedPidVisible = false;

        for (const Core::TreeRow& row : rows)
        {
            if (row.processIndex >= snapshot_.processes.size())
            {
                continue;
            }

            const Core::ProcessInfo& process = snapshot_.processes[row.processIndex];
            const Core::ChainAnalysisResult chainAnalysis = Core::AnalyzeChain(snapshot_, process.pid);
            const Core::Severity filterSeverity =
                Core::SeverityRank(chainAnalysis.chainSeverity) > Core::SeverityRank(process.severity)
                    ? chainAnalysis.chainSeverity
                    : process.severity;
            if (suspiciousOnly && Core::SeverityRank(filterSeverity) < Core::SeverityRank(Core::Severity::Low))
            {
                continue;
            }

            if (suspiciousOnly && !SeverityAllowed(filterSeverity))
            {
                continue;
            }

            if (!filter.empty() && !MatchesCurrentFilter(process, filter))
            {
                continue;
            }

            visibleProcesses_.push_back({ row.processIndex, row.depth });

            std::wstring displayName(row.depth * 2, L' ');
            displayName += process.name.empty() ? L"(unknown)" : process.name;

            LVITEMW item = {};
            item.mask = LVIF_TEXT | LVIF_PARAM;
            item.iItem = listIndex;
            item.iSubItem = 0;
            item.pszText = const_cast<wchar_t*>(displayName.c_str());
            item.lParam = static_cast<LPARAM>(process.pid);
            ListView_InsertItem(listView_, &item);

            SetListText(listView_, listIndex, 1, std::to_wstring(process.pid));
            SetListText(listView_, listIndex, 2, std::to_wstring(process.parentPid));
            SetListText(listView_, listIndex, 3, process.hasCreationTime ? process.creationTimeLocal : L"");
            SetListText(listView_, listIndex, 4, FormatOptionalNumber(process.sessionId));
            SetListText(listView_, listIndex, 5, process.architecture);
            SetListText(listView_, listIndex, 6, process.IsSuspicious() ? L"Yes" : L"No");
            SetListText(listView_, listIndex, 7, Core::SeverityToString(process.severity));
            SetListText(listView_, listIndex, 8, Core::SeverityToString(chainAnalysis.chainSeverity));

            if (process.pid == selectedPid_)
            {
                ListView_SetItemState(listView_, listIndex, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
                selectedPidVisible = true;
            }

            ++listIndex;
        }

        if (!selectedPidVisible)
        {
            selectedPid_ = 0;
            if (listIndex > 0)
            {
                LVITEMW item = {};
                item.mask = LVIF_PARAM;
                item.iItem = 0;
                if (ListView_GetItem(listView_, &item) != FALSE)
                {
                    selectedPid_ = static_cast<std::uint32_t>(item.lParam);
                    ListView_SetItemState(listView_, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
                }
            }
        }

        SendMessageW(listView_, WM_SETREDRAW, TRUE, 0);
        suppressListSelectionEvents_ = false;
        InvalidateRect(listView_, nullptr, TRUE);
        UpdateDetails();
        UpdateGraphView(true);
    }

    void MainWindow::RebuildTimelineList()
    {
        const std::vector<Core::TimelineRow> rows =
            Core::BuildTimelineRows(snapshot_, CurrentTimelineFilter());

        suppressTimelineSelectionEvents_ = true;
        SendMessageW(timelineListView_, WM_SETREDRAW, FALSE, 0);
        ListView_DeleteAllItems(timelineListView_);

        int listIndex = 0;
        bool selectedPidVisible = false;
        for (const Core::TimelineRow& row : rows)
        {
            const std::wstring startTime = row.hasCreationTime ? row.creationTimeLocal : L"(unavailable)";
            LVITEMW item = {};
            item.mask = LVIF_TEXT | LVIF_PARAM;
            item.iItem = listIndex;
            item.iSubItem = 0;
            item.pszText = const_cast<wchar_t*>(startTime.c_str());
            item.lParam = static_cast<LPARAM>(row.pid);
            ListView_InsertItem(timelineListView_, &item);

            std::wstring parentText;
            if (row.parentPid != 0)
            {
                parentText = std::to_wstring(row.parentPid);
                if (!row.parentName.empty())
                {
                    parentText += L" ";
                    parentText += row.parentName;
                }
            }

            SetListText(timelineListView_, listIndex, 1, row.processName.empty() ? L"(unknown)" : row.processName);
            SetListText(timelineListView_, listIndex, 2, std::to_wstring(row.pid));
            SetListText(timelineListView_, listIndex, 3, parentText);
            SetListText(timelineListView_, listIndex, 4, Core::SeverityToString(row.severity));
            SetListText(timelineListView_, listIndex, 5, row.firstIndicator);

            if (row.pid == selectedPid_)
            {
                ListView_SetItemState(
                    timelineListView_,
                    listIndex,
                    LVIS_SELECTED | LVIS_FOCUSED,
                    LVIS_SELECTED | LVIS_FOCUSED);
                selectedPidVisible = true;
            }

            ++listIndex;
        }

        if (!selectedPidVisible)
        {
            ListView_SetItemState(timelineListView_, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
        }

        SendMessageW(timelineListView_, WM_SETREDRAW, TRUE, 0);
        suppressTimelineSelectionEvents_ = false;
        InvalidateRect(timelineListView_, nullptr, TRUE);
    }

    void MainWindow::UpdateDetails()
    {
        const Core::ProcessInfo* process = FindProcess(selectedPid_);
        if (process == nullptr)
        {
            SetWindowTextW(detailsEdit_, L"No process selected.");
            return;
        }

        const std::wstring details = BuildDetailsText(*process);
        SetWindowTextW(detailsEdit_, details.c_str());
    }

    void MainWindow::UpdateGraphView(bool focusSelected)
    {
        treeViewPanel_.SetSelectedPid(selectedPid_);
        if (focusSelected)
        {
            treeViewPanel_.FocusProcess(selectedPid_);
        }
    }

    void MainWindow::UpdateBottomPanelVisibility()
    {
        const int selectedTab = bottomTab_ == nullptr ? 0 : TabCtrl_GetCurSel(bottomTab_);
        const bool showTimeline = selectedTab == 1;

        ShowWindow(focusGraphButton_, showTimeline ? SW_HIDE : SW_SHOW);
        ShowWindow(treeViewPanel_.Window(), showTimeline ? SW_HIDE : SW_SHOW);

        ShowWindow(timelineAllRadio_, showTimeline ? SW_SHOW : SW_HIDE);
        ShowWindow(timelineSuspiciousRadio_, showTimeline ? SW_SHOW : SW_HIDE);
        ShowWindow(timelineHighRadio_, showTimeline ? SW_SHOW : SW_HIDE);
        ShowWindow(timelineListView_, showTimeline ? SW_SHOW : SW_HIDE);

        if (showTimeline)
        {
            RebuildTimelineList();
        }
    }

    void MainWindow::SelectProcess(std::uint32_t pid, bool selectInList, bool focusGraph)
    {
        if (FindProcess(pid) == nullptr)
        {
            return;
        }

        if (selectedPid_ != pid)
        {
            selectedModules_ = {};
            selectedModulesPid_ = 0;
            selectedModulesLoaded_ = false;
        }

        selectedPid_ = pid;
        if (selectInList)
        {
            SelectListItemByPid(pid);
        }
        SelectTimelineItemByPid(pid);

        UpdateDetails();
        UpdateGraphView(focusGraph);
    }

    bool MainWindow::SelectListItemByPid(std::uint32_t pid)
    {
        if (listView_ == nullptr)
        {
            return false;
        }

        suppressListSelectionEvents_ = true;
        ListView_SetItemState(listView_, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);

        const int itemCount = ListView_GetItemCount(listView_);
        for (int itemIndex = 0; itemIndex < itemCount; ++itemIndex)
        {
            LVITEMW item = {};
            item.mask = LVIF_PARAM;
            item.iItem = itemIndex;
            if (ListView_GetItem(listView_, &item) != FALSE &&
                static_cast<std::uint32_t>(item.lParam) == pid)
            {
                ListView_SetItemState(
                    listView_,
                    itemIndex,
                    LVIS_SELECTED | LVIS_FOCUSED,
                    LVIS_SELECTED | LVIS_FOCUSED);
                ListView_EnsureVisible(listView_, itemIndex, FALSE);
                suppressListSelectionEvents_ = false;
                return true;
            }
        }

        suppressListSelectionEvents_ = false;
        return false;
    }

    bool MainWindow::SelectTimelineItemByPid(std::uint32_t pid)
    {
        if (timelineListView_ == nullptr)
        {
            return false;
        }

        suppressTimelineSelectionEvents_ = true;
        ListView_SetItemState(timelineListView_, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);

        const int itemCount = ListView_GetItemCount(timelineListView_);
        for (int itemIndex = 0; itemIndex < itemCount; ++itemIndex)
        {
            LVITEMW item = {};
            item.mask = LVIF_PARAM;
            item.iItem = itemIndex;
            if (ListView_GetItem(timelineListView_, &item) != FALSE &&
                static_cast<std::uint32_t>(item.lParam) == pid)
            {
                ListView_SetItemState(
                    timelineListView_,
                    itemIndex,
                    LVIS_SELECTED | LVIS_FOCUSED,
                    LVIS_SELECTED | LVIS_FOCUSED);
                ListView_EnsureVisible(timelineListView_, itemIndex, FALSE);
                suppressTimelineSelectionEvents_ = false;
                return true;
            }
        }

        suppressTimelineSelectionEvents_ = false;
        return false;
    }

    void MainWindow::ExportSnapshot()
    {
        wchar_t fileName[MAX_PATH] = L"glasspane-snapshot.json";

        OPENFILENAMEW dialog = {};
        dialog.lStructSize = sizeof(dialog);
        dialog.hwndOwner = hwnd_;
        dialog.lpstrFilter = L"JSON Files (*.json)\0*.json\0All Files (*.*)\0*.*\0";
        dialog.lpstrFile = fileName;
        dialog.nMaxFile = MAX_PATH;
        dialog.lpstrDefExt = L"json";
        dialog.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;

        if (GetSaveFileNameW(&dialog) == FALSE)
        {
            return;
        }

        std::wstring error;
        if (!Export::ExportSnapshotToJson(snapshot_, fileName, &error))
        {
            MessageBoxW(hwnd_, error.c_str(), L"Export failed", MB_ICONERROR | MB_OK);
            return;
        }

        MessageBoxW(hwnd_, L"Snapshot exported.", L"GlassPane", MB_ICONINFORMATION | MB_OK);
    }

    void MainWindow::ExportSelectedDetails()
    {
        const Core::ProcessInfo* process = FindProcess(selectedPid_);
        if (process == nullptr)
        {
            MessageBoxW(hwnd_, L"No process is selected.", L"GlassPane", MB_ICONINFORMATION | MB_OK);
            return;
        }

        if (!selectedModulesLoaded_ || selectedModulesPid_ != selectedPid_)
        {
            selectedModules_ = Core::CollectProcessModules(*process);
            selectedModulesPid_ = selectedPid_;
            selectedModulesLoaded_ = true;
            UpdateDetails();
        }

        wchar_t fileName[MAX_PATH] = L"glasspane-selected-process.json";

        OPENFILENAMEW dialog = {};
        dialog.lStructSize = sizeof(dialog);
        dialog.hwndOwner = hwnd_;
        dialog.lpstrFilter = L"JSON Files (*.json)\0*.json\0All Files (*.*)\0*.*\0";
        dialog.lpstrFile = fileName;
        dialog.nMaxFile = MAX_PATH;
        dialog.lpstrDefExt = L"json";
        dialog.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;

        if (GetSaveFileNameW(&dialog) == FALSE)
        {
            return;
        }

        std::wstring error;
        if (!Export::ExportSelectedProcessDetailsToJson(
            snapshot_,
            selectedPid_,
            selectedModules_,
            fileName,
            &error))
        {
            MessageBoxW(hwnd_, error.c_str(), L"Export selected failed", MB_ICONERROR | MB_OK);
            return;
        }

        MessageBoxW(hwnd_, L"Selected process details exported.", L"GlassPane", MB_ICONINFORMATION | MB_OK);
    }

    void MainWindow::RefreshSelectedModules()
    {
        const Core::ProcessInfo* process = FindProcess(selectedPid_);
        if (process == nullptr)
        {
            MessageBoxW(hwnd_, L"No process is selected.", L"GlassPane", MB_ICONINFORMATION | MB_OK);
            return;
        }

        SetWindowTextW(statusText_, L"Refreshing selected process modules...");
        selectedModules_ = Core::CollectProcessModules(*process);
        selectedModulesPid_ = selectedPid_;
        selectedModulesLoaded_ = true;
        SetWindowTextW(statusText_, selectedModules_.statusMessage.c_str());
        UpdateDetails();
    }

    void MainWindow::CopySelectedChainToClipboard()
    {
        const std::wstring chain = Core::FormatParentChain(snapshot_, selectedPid_);
        if (chain.empty())
        {
            MessageBoxW(hwnd_, L"No parent chain is available to copy.", L"GlassPane", MB_ICONINFORMATION | MB_OK);
            return;
        }

        if (OpenClipboard(hwnd_) == FALSE)
        {
            MessageBoxW(hwnd_, L"Could not open the clipboard.", L"GlassPane", MB_ICONERROR | MB_OK);
            return;
        }

        EmptyClipboard();

        const SIZE_T byteCount = (chain.size() + 1) * sizeof(wchar_t);
        HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, byteCount);
        if (memory == nullptr)
        {
            CloseClipboard();
            MessageBoxW(hwnd_, L"Could not allocate clipboard memory.", L"GlassPane", MB_ICONERROR | MB_OK);
            return;
        }

        void* data = GlobalLock(memory);
        if (data == nullptr)
        {
            GlobalFree(memory);
            CloseClipboard();
            MessageBoxW(hwnd_, L"Could not lock clipboard memory.", L"GlassPane", MB_ICONERROR | MB_OK);
            return;
        }

        CopyMemory(data, chain.c_str(), byteCount);
        GlobalUnlock(memory);

        if (SetClipboardData(CF_UNICODETEXT, memory) == nullptr)
        {
            GlobalFree(memory);
            CloseClipboard();
            MessageBoxW(hwnd_, L"Could not set clipboard data.", L"GlassPane", MB_ICONERROR | MB_OK);
            return;
        }

        CloseClipboard();
        SetWindowTextW(statusText_, L"Copied parent chain to clipboard.");
    }

    std::wstring MainWindow::GetSearchText() const
    {
        const int length = GetWindowTextLengthW(searchEdit_);
        std::wstring text(static_cast<std::size_t>(length) + 1, L'\0');
        if (length > 0)
        {
            GetWindowTextW(searchEdit_, text.data(), length + 1);
        }
        text.resize(static_cast<std::size_t>(length));
        return text;
    }

    bool MainWindow::SeverityAllowed(Core::Severity severity) const
    {
        switch (severity)
        {
        case Core::Severity::Low:
            return SendMessageW(lowSeverityCheck_, BM_GETCHECK, 0, 0) == BST_CHECKED;
        case Core::Severity::Medium:
            return SendMessageW(mediumSeverityCheck_, BM_GETCHECK, 0, 0) == BST_CHECKED;
        case Core::Severity::High:
            return SendMessageW(highSeverityCheck_, BM_GETCHECK, 0, 0) == BST_CHECKED;
        case Core::Severity::None:
        case Core::Severity::Info:
        default:
            return false;
        }
    }

    Core::TimelineFilter MainWindow::CurrentTimelineFilter() const
    {
        if (SendMessageW(timelineHighRadio_, BM_GETCHECK, 0, 0) == BST_CHECKED)
        {
            return Core::TimelineFilter::HighSeverityOnly;
        }

        if (SendMessageW(timelineSuspiciousRadio_, BM_GETCHECK, 0, 0) == BST_CHECKED)
        {
            return Core::TimelineFilter::SuspiciousOnly;
        }

        return Core::TimelineFilter::All;
    }

    bool MainWindow::MatchesCurrentFilter(const Core::ProcessInfo& process, const std::wstring& filter) const
    {
        const Core::ChainAnalysisResult chainAnalysis = Core::AnalyzeChain(snapshot_, process.pid);

        if (ToLower(process.name).find(filter) != std::wstring::npos)
        {
            return true;
        }

        if (ToLower(process.executablePath).find(filter) != std::wstring::npos)
        {
            return true;
        }

        if (ToLower(process.commandLine).find(filter) != std::wstring::npos)
        {
            return true;
        }

        if (ToLower(process.creationTimeLocal).find(filter) != std::wstring::npos)
        {
            return true;
        }

        if (std::to_wstring(process.pid).find(filter) != std::wstring::npos)
        {
            return true;
        }

        if (std::to_wstring(process.parentPid).find(filter) != std::wstring::npos)
        {
            return true;
        }

        if (ToLower(Core::SeverityToString(process.severity)).find(filter) != std::wstring::npos)
        {
            return true;
        }

        if (ToLower(Core::SeverityToString(chainAnalysis.chainSeverity)).find(filter) != std::wstring::npos)
        {
            return true;
        }

        if (ToLower(chainAnalysis.formattedParentChain).find(filter) != std::wstring::npos)
        {
            return true;
        }

        for (const std::wstring& indicator : process.indicators)
        {
            if (ToLower(indicator).find(filter) != std::wstring::npos)
            {
                return true;
            }
        }

        for (const std::wstring& note : process.contextNotes)
        {
            if (ToLower(note).find(filter) != std::wstring::npos)
            {
                return true;
            }
        }

        for (const std::wstring& indicator : chainAnalysis.chainIndicators)
        {
            if (ToLower(indicator).find(filter) != std::wstring::npos)
            {
                return true;
            }
        }

        return false;
    }

    std::wstring MainWindow::BuildDetailsText(const Core::ProcessInfo& process) const
    {
        const Core::ChainAnalysisResult chainAnalysis = Core::AnalyzeChain(snapshot_, process.pid);
        const Core::FileIdentity fileIdentity = Core::CollectFileIdentity(process.executablePath);
        const std::vector<Core::FileIdentityIndicator> fileIdentityIndicators =
            Core::BuildFileIdentityIndicators(fileIdentity, process.name, true);
        std::wstringstream details;

        details << L"Process\r\n";
        details << L"Name: " << (process.name.empty() ? L"(unknown)" : process.name) << L"\r\n";
        details << L"PID: " << process.pid << L"\r\n";
        details << L"Parent PID: " << process.parentPid;

        const Core::ProcessInfo* parent = FindProcess(process.parentPid);
        if (parent != nullptr)
        {
            details << L" (" << parent->name << L")";
        }

        details << L"\r\n";
        details << L"Session ID: ";
        if (process.sessionId.has_value())
        {
            details << process.sessionId.value();
        }
        else
        {
            details << L"(unknown)";
        }
        details << L"\r\n";
        details << L"Architecture: " << process.architecture << L"\r\n\r\n";

        details << L"Start Time\r\n";
        details << (process.hasCreationTime ? process.creationTimeLocal : L"(not accessible)") << L"\r\n\r\n";

        details << L"Executable Path\r\n";
        details << (process.executablePath.empty() ? L"(not accessible)" : process.executablePath) << L"\r\n\r\n";

        details << L"File Identity\r\n";
        details << L"Exists: " << (fileIdentity.exists ? L"Yes" : L"No") << L"\r\n";
        details << L"Size: " << (fileIdentity.exists ? FileSizeText(fileIdentity.fileSize) : L"(unavailable)") << L"\r\n";
        details << L"SHA-256: " << (fileIdentity.sha256.empty() ? L"(unavailable)" : fileIdentity.sha256) << L"\r\n";
        details << L"Signature: " << SignatureStatusText(fileIdentity) << L"\r\n";
        details << L"Signer: " << (fileIdentity.signerName.empty() ? L"(none)" : fileIdentity.signerName) << L"\r\n";
        details << L"Company: " << (fileIdentity.companyName.empty() ? L"(none)" : fileIdentity.companyName) << L"\r\n";
        details << L"Product: " << (fileIdentity.productName.empty() ? L"(none)" : fileIdentity.productName) << L"\r\n";
        details << L"Description: " << (fileIdentity.fileDescription.empty() ? L"(none)" : fileIdentity.fileDescription) << L"\r\n";
        details << L"Original filename: " << (fileIdentity.originalFilename.empty() ? L"(none)" : fileIdentity.originalFilename) << L"\r\n";
        details << L"Version: " << (fileIdentity.versionString.empty() ? L"(none)" : fileIdentity.versionString) << L"\r\n";
        if (!fileIdentity.errorMessage.empty())
        {
            details << L"Identity notes: " << fileIdentity.errorMessage << L"\r\n";
        }
        if (!fileIdentityIndicators.empty())
        {
            details << L"Identity indicators\r\n";
            for (const Core::FileIdentityIndicator& indicator : fileIdentityIndicators)
            {
                details << L"- [" << Core::SeverityToString(indicator.severity) << L"] "
                    << indicator.message << L"\r\n";
            }
        }
        details << L"\r\n";

        details << L"Command Line\r\n";
        if (!process.commandLineAccessible)
        {
            details << L"(not accessible)";
        }
        else if (process.commandLine.empty())
        {
            details << L"(empty)";
        }
        else
        {
            details << process.commandLine;
        }
        details << L"\r\n\r\n";

        details << L"Suspicious\r\n";
        details << (process.IsSuspicious() ? L"Yes" : L"No") << L"\r\n";
        details << L"Severity: " << Core::SeverityToString(process.severity) << L"\r\n\r\n";

        details << L"Indicators\r\n";
        if (process.indicators.empty() && fileIdentityIndicators.empty())
        {
            details << L"(none)\r\n";
        }
        else
        {
            for (const std::wstring& indicator : process.indicators)
            {
                details << L"- " << indicator << L"\r\n";
            }
            for (const Core::FileIdentityIndicator& indicator : fileIdentityIndicators)
            {
                details << L"- [" << Core::SeverityToString(indicator.severity) << L"] "
                    << indicator.message << L"\r\n";
            }
        }

        details << L"\r\nContext Notes\r\n";
        if (process.contextNotes.empty())
        {
            details << L"(none)\r\n";
        }
        else
        {
            for (const std::wstring& note : process.contextNotes)
            {
                details << L"- " << note << L"\r\n";
            }
        }

        details << L"\r\nChain Summary\r\n";
        details << L"Parent chain: ";
        if (chainAnalysis.formattedParentChain.empty())
        {
            details << L"(unavailable)";
        }
        else
        {
            details << chainAnalysis.formattedParentChain;
        }
        details << L"\r\n";
        details << L"Chain severity: " << Core::SeverityToString(chainAnalysis.chainSeverity) << L"\r\n";
        details << L"Chain indicators\r\n";
        if (chainAnalysis.chainIndicators.empty())
        {
            details << L"(none)\r\n";
        }
        else
        {
            for (const std::wstring& indicator : chainAnalysis.chainIndicators)
            {
                details << L"- " << indicator << L"\r\n";
            }
        }

        details << L"\r\nModules\r\n";
        if (!selectedModulesLoaded_ || selectedModulesPid_ != process.pid)
        {
            details << L"Click Refresh Modules to inspect modules for this process.\r\n";
        }
        else
        {
            details << selectedModules_.statusMessage << L"\r\n";
            details << L"Module indicators\r\n";
            if (selectedModules_.indicators.empty())
            {
                details << L"(none)\r\n";
            }
            else
            {
                for (const std::wstring& indicator : selectedModules_.indicators)
                {
                    details << L"- " << indicator << L"\r\n";
                }
            }

            details << L"\r\nLoaded modules\r\n";
            if (selectedModules_.modules.empty())
            {
                details << L"(none)\r\n";
            }
            else
            {
                for (const Core::ModuleInfo& module : selectedModules_.modules)
                {
                    details << (module.moduleName.empty() ? L"(unknown)" : module.moduleName)
                        << L" | Base: " << (module.baseAddress.empty() ? L"(unknown)" : module.baseAddress)
                        << L" | Size: " << module.sizeBytes
                        << L" | " << (module.readable ? L"Readable" : L"Partial")
                        << L"\r\n";
                    details << L"  " << (module.modulePath.empty() ? L"(path unavailable)" : module.modulePath) << L"\r\n";
                    for (const std::wstring& indicator : module.indicators)
                    {
                        details << L"  - " << indicator << L"\r\n";
                    }
                }
            }
        }

        details << L"\r\nChildren\r\n";
        if (process.children.empty())
        {
            details << L"(none)\r\n";
        }
        else
        {
            for (const std::uint32_t childPid : process.children)
            {
                const Core::ProcessInfo* child = FindProcess(childPid);
                if (child != nullptr)
                {
                    details << child->pid << L"  " << child->name << L"\r\n";
                }
            }
        }

        return details.str();
    }

    const Core::ProcessInfo* MainWindow::FindProcess(std::uint32_t pid) const
    {
        const auto it = snapshot_.indexByPid.find(pid);
        if (it == snapshot_.indexByPid.end())
        {
            return nullptr;
        }
        return &snapshot_.processes[it->second];
    }
}
