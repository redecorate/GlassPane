#include "PickWindowActions.h"

// This implementation file is included from ImGuiApp.cpp inside the private ImGuiApp class definition.
// Pick Window state, overlay HWNDs, logs, and process selection remain owned by ImGuiApp.
        std::optional<LRESULT> HandlePickerWindowMessage(UINT message, WPARAM wParam, LPARAM lParam)
        {
            if (!pickWindowActive_)
            {
                return std::nullopt;
            }

            switch (message)
            {
            case WM_SETCURSOR:
                SetCursor(LoadCursorW(nullptr, IDC_CROSS));
                return TRUE;
            case WM_MOUSEMOVE:
                SetCursor(LoadCursorW(nullptr, IDC_CROSS));
                return std::nullopt;
            case WM_KEYDOWN:
            case WM_SYSKEYDOWN:
                if (wParam == VK_ESCAPE)
                {
                    CancelPickWindowMode("Pick Window picker cancelled.");
                    return 0;
                }
                break;
            case WM_ACTIVATEAPP:
                if (wParam == FALSE)
                {
                    CancelPickWindowMode("Pick Window picker cancelled because GlassPane lost focus.");
                    return std::nullopt;
                }
                break;
            case WM_CANCELMODE:
                CancelPickWindowMode("Pick Window picker cancelled.");
                return 0;
            case WM_LBUTTONDOWN:
            case WM_NCLBUTTONDOWN:
                PickWindowAtCursor();
                return 0;
            case WM_CAPTURECHANGED:
                if (reinterpret_cast<HWND>(lParam) != hwnd_ && reinterpret_cast<HWND>(lParam) != pickerOverlayHwnd_)
                {
                    pickWindowActive_ = false;
                    DestroyPickWindowOverlay();
                    AddLog(LogLevel::Warning, "Pick Window picker cancelled because mouse capture was lost.");
                }
                return std::nullopt;
            default:
                break;
            }

            return std::nullopt;
        }

        static LRESULT WINAPI PickerOverlayProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
        {
            ImGuiApp* app = reinterpret_cast<ImGuiApp*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
            if (message == WM_NCCREATE)
            {
                const CREATESTRUCTW* create = reinterpret_cast<const CREATESTRUCTW*>(lParam);
                app = static_cast<ImGuiApp*>(create->lpCreateParams);
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(app));
            }

            if (app != nullptr && app->pickWindowActive_)
            {
                switch (message)
                {
                case WM_SETCURSOR:
                case WM_MOUSEMOVE:
                    SetCursor(LoadCursorW(nullptr, IDC_CROSS));
                    return message == WM_SETCURSOR ? TRUE : 0;
                case WM_LBUTTONDOWN:
                case WM_NCLBUTTONDOWN:
                    app->PickWindowAtCursor();
                    return 0;
                case WM_KEYDOWN:
                case WM_SYSKEYDOWN:
                    if (wParam == VK_ESCAPE)
                    {
                        app->CancelPickWindowMode("Pick Window picker cancelled.");
                        return 0;
                    }
                    break;
                default:
                    break;
                }
            }

            return DefWindowProcW(hwnd, message, wParam, lParam);
        }

        void StartPickWindowMode()
        {
            if (pickWindowActive_)
            {
                return;
            }

            if (hwnd_ == nullptr)
            {
                AddLog(LogLevel::Warning, "Pick Window picker failed to start: application window is not available.");
                return;
            }

            pickWindowActive_ = true;
            if (!CreatePickWindowOverlay())
            {
                pickWindowActive_ = false;
                AddLog(LogLevel::Warning, "Pick Window picker failed to start: picker overlay could not be created.");
                return;
            }

            SetCapture(pickerOverlayHwnd_ != nullptr ? pickerOverlayHwnd_ : hwnd_);
            SetCursor(LoadCursorW(nullptr, IDC_CROSS));
            AddLog(LogLevel::Info, "Pick Window picker started.");
        }

        void CancelPickWindowMode(const std::string& message)
        {
            if (!pickWindowActive_)
            {
                return;
            }

            pickWindowActive_ = false;
            ReleasePickerCapture();
            DestroyPickWindowOverlay();
            SetCursor(LoadCursorW(nullptr, IDC_ARROW));
            AddLog(LogLevel::Info, message);
        }

        void UpdatePickWindowCursor()
        {
            if (!pickWindowActive_)
            {
                return;
            }

            if ((GetAsyncKeyState(VK_ESCAPE) & 0x0001) != 0)
            {
                CancelPickWindowMode("Pick Window picker cancelled.");
                return;
            }

            if (pickerOverlayHwnd_ == nullptr && !CreatePickWindowOverlay())
            {
                CancelPickWindowMode("Pick Window picker cancelled because the picker overlay is unavailable.");
                return;
            }

            if (GetCapture() != hwnd_ && GetCapture() != pickerOverlayHwnd_)
            {
                SetCapture(pickerOverlayHwnd_ != nullptr ? pickerOverlayHwnd_ : hwnd_);
            }

            if (pickerOverlayHwnd_ != nullptr)
            {
                SetWindowPos(
                    pickerOverlayHwnd_,
                    HWND_TOPMOST,
                    0,
                    0,
                    0,
                    0,
                    SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW);
            }

            SetCursor(LoadCursorW(nullptr, IDC_CROSS));
        }

        bool EnsurePickWindowOverlayClass()
        {
            if (pickerOverlayClassRegistered_)
            {
                return true;
            }

            WNDCLASSEXW overlayClass = {};
            overlayClass.cbSize = sizeof(overlayClass);
            overlayClass.style = CS_CLASSDC;
            overlayClass.lpfnWndProc = ImGuiApp::PickerOverlayProc;
            overlayClass.hInstance = instance_;
            overlayClass.hCursor = LoadCursorW(nullptr, IDC_CROSS);
            overlayClass.lpszClassName = L"GlassPanePickerOverlayWindow";

            if (RegisterClassExW(&overlayClass) == 0)
            {
                if (GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
                {
                    return false;
                }
            }

            pickerOverlayClassRegistered_ = true;
            return true;
        }

        bool CreatePickWindowOverlay()
        {
            if (pickerOverlayHwnd_ != nullptr)
            {
                return true;
            }

            if (!EnsurePickWindowOverlayClass())
            {
                return false;
            }

            const int virtualX = GetSystemMetrics(SM_XVIRTUALSCREEN);
            const int virtualY = GetSystemMetrics(SM_YVIRTUALSCREEN);
            const int virtualWidth = std::max(GetSystemMetrics(SM_CXVIRTUALSCREEN), 1);
            const int virtualHeight = std::max(GetSystemMetrics(SM_CYVIRTUALSCREEN), 1);

            pickerOverlayHwnd_ = CreateWindowExW(
                WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_LAYERED | WS_EX_NOACTIVATE,
                L"GlassPanePickerOverlayWindow",
                L"GlassPane Pick Window",
                WS_POPUP,
                virtualX,
                virtualY,
                virtualWidth,
                virtualHeight,
                hwnd_,
                nullptr,
                instance_,
                this);

            if (pickerOverlayHwnd_ == nullptr)
            {
                return false;
            }

            SetLayeredWindowAttributes(pickerOverlayHwnd_, 0, 1, LWA_ALPHA);
            ShowWindow(pickerOverlayHwnd_, SW_SHOWNOACTIVATE);
            UpdateWindow(pickerOverlayHwnd_);
            return true;
        }

        void ReleasePickerCapture() const
        {
            const HWND capturedWindow = GetCapture();
            if (capturedWindow == hwnd_ || capturedWindow == pickerOverlayHwnd_)
            {
                ReleaseCapture();
            }
        }

        void DestroyPickWindowOverlay()
        {
            if (pickerOverlayHwnd_ == nullptr)
            {
                return;
            }

            DestroyWindow(pickerOverlayHwnd_);
            pickerOverlayHwnd_ = nullptr;
        }

        static std::string FormatWindowHandle(HWND hwnd)
        {
            std::ostringstream stream;
            stream << "0x"
                << std::uppercase
                << std::hex
                << reinterpret_cast<std::uintptr_t>(hwnd);
            return stream.str();
        }

        void PickWindowAtCursor()
        {
            POINT cursorPosition = {};
            if (!GetCursorPos(&cursorPosition))
            {
                pickWindowActive_ = false;
                ReleasePickerCapture();
                DestroyPickWindowOverlay();
                SetCursor(LoadCursorW(nullptr, IDC_ARROW));
                AddLog(LogLevel::Warning, "Pick Window failed: could not read cursor position.");
                return;
            }

            if (pickerOverlayHwnd_ != nullptr)
            {
                ShowWindow(pickerOverlayHwnd_, SW_HIDE);
            }

            HWND pickedWindow = WindowFromPoint(cursorPosition);
            if (pickedWindow == nullptr)
            {
                pickWindowActive_ = false;
                ReleasePickerCapture();
                DestroyPickWindowOverlay();
                SetCursor(LoadCursorW(nullptr, IDC_ARROW));
                AddLog(LogLevel::Warning, "Pick Window failed: no window found under the cursor.");
                return;
            }

            HWND rootWindow = GetAncestor(pickedWindow, GA_ROOT);
            if (rootWindow != nullptr)
            {
                pickedWindow = rootWindow;
            }

            DWORD owningPid = 0;
            GetWindowThreadProcessId(pickedWindow, &owningPid);

            pickWindowActive_ = false;
            ReleasePickerCapture();
            DestroyPickWindowOverlay();
            SetCursor(LoadCursorW(nullptr, IDC_ARROW));

            if (owningPid == 0)
            {
                AddLog(
                    LogLevel::Warning,
                    "Pick Window failed: could not resolve an owning PID for HWND " +
                        FormatWindowHandle(pickedWindow) + ".");
                return;
            }

            const std::uint32_t pid = static_cast<std::uint32_t>(owningPid);
            const Core::ProcessInfo* selectedProcess = Core::FindProcessByPid(snapshot_, pid);
            if (selectedProcess == nullptr)
            {
                AddLog(
                    LogLevel::Warning,
                    "Picked window belongs to PID " + std::to_string(pid) +
                        ", not found in current snapshot. Refresh may be needed.");
                return;
            }

            SelectProcess(pid, true, false);
            AddLog(
                Core::SeverityRank(ProcessAuthoritySeverity(*selectedProcess)) >=
                    Core::SeverityRank(Core::Severity::High)
                    ? LogLevel::High
                    : LogLevel::Info,
                "Picked HWND " + FormatWindowHandle(pickedWindow) +
                    " owned by " + DisplayName(selectedProcess->name) +
                    " (PID " + std::to_string(selectedProcess->pid) + ").");
        }

