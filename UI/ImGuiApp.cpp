#include "ImGuiApp.h"

#include "Fonts.h"
#include "ComparePanel.h"
#include "HeaderPanel.h"
#include "LogsPanel.h"
#include "Modals.h"
#include "ProcessPanel.h"
#include "Theme.h"
#include "UiHelpers.h"
#include "TimelinePanel.h"

#include "../Core/ChainAnalysis.h"
#include "../Core/CorrelationEngine.h"
#include "../Core/FileIdentity.h"
#include "../Core/GraphModel.h"
#include "../Core/HandleCollector.h"
#include "../Core/MemoryCollector.h"
#include "../Core/ModuleCollector.h"
#include "../Core/NetworkCollector.h"
#include "../Core/NetworkIndicatorMatcher.h"
#include "../Core/NetworkIndicatorUpdater.h"
#include "../Core/ProcessCollector.h"
#include "../Core/ProcessTree.h"
#include "../Core/RuntimeCollector.h"
#include "../Core/ServiceCollector.h"
#include "../Core/SnapshotCompare.h"
#include "../Core/TimelineModel.h"
#include "../Core/TokenCollector.h"
#include "../Export/JsonExporter.h"
#include "../Export/MarkdownReportExporter.h"
#include "../Export/SavedSnapshot.h"
#include "../resource.h"

#include "imgui.h"
#ifdef IMGUI_HAS_DOCK
#include "imgui_internal.h"
#endif
#include "backends/imgui_impl_dx11.h"
#include "backends/imgui_impl_win32.h"

#include <Windows.h>
#include <commdlg.h>
#include <d3d11.h>
#include <dwmapi.h>
#include <knownfolders.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <shellapi.h>
#include <wincodec.h>
#include <wrl/client.h>

#include <algorithm>
#include <atomic>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <cwctype>
#include <exception>
#include <filesystem>
#include <functional>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "d3dcompiler.lib")
#pragma comment(lib, "Comdlg32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Windowscodecs.lib")
#pragma comment(lib, "Dwmapi.lib")

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);

namespace GlassPane::UI
{
    namespace
    {
        constexpr UINT WindowWidth = 1440;
        constexpr UINT WindowHeight = 900;
        constexpr std::uint32_t InvalidPid = 0;
        constexpr const char* GlassPaneBaseVersion = "V0.7.0";
#ifdef _DEBUG
        constexpr const char* GlassPaneBuildSuffix = "-Debug";
#else
        constexpr const char* GlassPaneBuildSuffix = "-Release";
#endif
        constexpr const char* GlassPaneGithubUrl = "https://github.com/redecorate/GlassPane";

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

#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
        constexpr DWORD DWMWA_USE_IMMERSIVE_DARK_MODE = 20;
#endif
#ifndef DWMWA_CAPTION_COLOR
        constexpr DWORD DWMWA_CAPTION_COLOR = 35;
#endif
#ifndef DWMWA_BORDER_COLOR
        constexpr DWORD DWMWA_BORDER_COLOR = 34;
#endif

        void ApplyDarkNativeTitleBar(HWND hwnd)
        {
            if (hwnd == nullptr)
            {
                return;
            }

            const BOOL useDarkMode = TRUE;
            if (FAILED(DwmSetWindowAttribute(
                    hwnd,
                    DWMWA_USE_IMMERSIVE_DARK_MODE,
                    &useDarkMode,
                    sizeof(useDarkMode))))
            {
                constexpr DWORD LegacyDarkModeAttribute = 19;
                DwmSetWindowAttribute(
                    hwnd,
                    LegacyDarkModeAttribute,
                    &useDarkMode,
                    sizeof(useDarkMode));
            }

            const COLORREF captionColor = RGB(6, 10, 16);
            DwmSetWindowAttribute(hwnd, DWMWA_CAPTION_COLOR, &captionColor, sizeof(captionColor));
            const COLORREF borderColor = RGB(28, 42, 60);
            DwmSetWindowAttribute(hwnd, DWMWA_BORDER_COLOR, &borderColor, sizeof(borderColor));
        }

        enum class LogLevel
        {
            Info,
            Warning,
            High
        };

        struct CollectorTimings
        {
            std::uint64_t processSnapshotMs = 0;
            std::uint64_t servicesMs = 0;
            std::uint64_t graphLayoutMs = 0;
            std::uint64_t processFilterMs = 0;
            std::uint64_t modulesMs = 0;
            std::uint64_t networkMs = 0;
            std::uint64_t tokenMs = 0;
            std::uint64_t handlesMs = 0;
            std::uint64_t runtimeMs = 0;
            std::uint64_t memoryMs = 0;
            std::uint64_t fileIdentityMs = 0;
            std::uint64_t findingsMs = 0;
            std::uint64_t jsonExportMs = 0;
            std::uint64_t markdownReportMs = 0;
            std::uint64_t snapshotCompareMs = 0;
        };

        enum class InspectorTab
        {
            Triage,
            Details,
            Chain,
            Services,
            Modules,
            Network,
            Runtime,
            Memory,
            Token,
            Handles
        };

        enum class MemoryFilter
        {
            All,
            Executable,
            Writable,
            Private,
            Image,
            Suspicious,
            Rwx
        };

        enum class TriageFilter
        {
            All,
            Info,
            Low,
            Medium,
            High
        };

        enum class HandleFilter
        {
            All,
            Sensitive,
            Process,
            Token,
            File,
            Registry,
            NamedObjects,
            WithIndicators
        };

        enum class LongRunningOperationKind
        {
            None,
            SaveSnapshot,
            SaveDeepSnapshot,
            ExportEvidencePackage,
            UpdateIntelFeed,
            LoadIntelFeed,
            LoadSnapshot
        };

        struct LongOperationLog
        {
            LogLevel level = LogLevel::Info;
            std::string message;
        };

        struct LongOperationResult
        {
            LongRunningOperationKind kind = LongRunningOperationKind::None;
            bool success = false;
            std::string status;
            std::wstring outputPath;
            std::wstring inputPath;
            std::uint64_t elapsedMs = 0;
            std::vector<LongOperationLog> logs;

            Core::NetworkIndicatorUpdateResult networkUpdateResult;
            Core::NetworkIndicatorLoadResult networkLoadResult;
            bool networkUsedFallback = false;

            Export::SavedSnapshotDocument loadedSnapshot;
            bool hasLoadedSnapshot = false;
        };

        struct InspectorTabSpec
        {
            const char* label;
            InspectorTab tab;
        };

        constexpr std::array<InspectorTabSpec, 10> InspectorTabs = {
            InspectorTabSpec{"Triage", InspectorTab::Triage},
            InspectorTabSpec{"Details", InspectorTab::Details},
            InspectorTabSpec{"Chain", InspectorTab::Chain},
            InspectorTabSpec{"Services", InspectorTab::Services},
            InspectorTabSpec{"Memory", InspectorTab::Memory},
            InspectorTabSpec{"Runtime", InspectorTab::Runtime},
            InspectorTabSpec{"Handles", InspectorTab::Handles},
            InspectorTabSpec{"Modules", InspectorTab::Modules},
            InspectorTabSpec{"Network", InspectorTab::Network},
            InspectorTabSpec{"Token", InspectorTab::Token},
        };

        std::size_t InspectorTabIndex(InspectorTab tab)
        {
            for (std::size_t index = 0; index < InspectorTabs.size(); ++index)
            {
                if (InspectorTabs[index].tab == tab)
                {
                    return index;
                }
            }
            return 0;
        }

        const char* InspectorTabLabel(InspectorTab tab)
        {
            for (const InspectorTabSpec& spec : InspectorTabs)
            {
                if (spec.tab == tab)
                {
                    return spec.label;
                }
            }
            return "Inspector";
        }

        const char* InspectorDockWindowTitle(InspectorTab tab)
        {
            switch (tab)
            {
            case InspectorTab::Triage:
                return "Triage##InspectorDockView";
            case InspectorTab::Details:
                return "Details##InspectorDockView";
            case InspectorTab::Chain:
                return "Chain##InspectorDockView";
            case InspectorTab::Services:
                return "Services##InspectorDockView";
            case InspectorTab::Memory:
                return "Memory##InspectorDockView";
            case InspectorTab::Runtime:
                return "Runtime##InspectorDockView";
            case InspectorTab::Handles:
                return "Handles##InspectorDockView";
            case InspectorTab::Modules:
                return "Modules##InspectorDockView";
            case InspectorTab::Network:
                return "Network##InspectorDockView";
            case InspectorTab::Token:
                return "Token##InspectorDockView";
            default:
                return "Inspector View##InspectorDockView";
            }
        }

        bool IsHeavyInspectorTab(InspectorTab tab)
        {
            return tab == InspectorTab::Memory ||
                tab == InspectorTab::Handles ||
                tab == InspectorTab::Modules ||
                tab == InspectorTab::Network ||
                tab == InspectorTab::Services;
        }

        ImVec2 InspectorDockDefaultSize(InspectorTab tab)
        {
            return IsHeavyInspectorTab(tab)
                ? ImVec2(720.0f, 520.0f)
                : ImVec2(640.0f, 460.0f);
        }

        enum class GraphLayoutMode
        {
            TopDown,
            LeftToRight
        };

        struct LogEntry
        {
            LogLevel level = LogLevel::Info;
            std::string message;
        };

        struct GraphLayoutNode
        {
            std::size_t nodeIndex = 0;
            ImVec2 worldCenter = ImVec2(0.0f, 0.0f);
        };

        struct NetworkSummary
        {
            std::size_t connectionCount = 0;
            std::size_t listeningCount = 0;
            std::size_t publicRemoteCount = 0;
            std::size_t intelMatchCount = 0;
        };

        struct CachedIconTexture
        {
            ID3D11ShaderResourceView* texture = nullptr;
            bool ownsTexture = false;
        };

        template <typename TValue>
        void TrimEvidenceCache(std::unordered_map<std::wstring, TValue>& cache)
        {
            constexpr std::size_t MaxEntries = 16;
            while (cache.size() > MaxEntries)
            {
                cache.erase(cache.begin());
            }
        }

        const char* BuildArchitecture()
        {
#if defined(_M_X64)
            return "x64";
#elif defined(_M_IX86)
            return "x86";
#elif defined(_M_ARM64)
            return "ARM64";
#else
            return "unknown";
#endif
        }

        const char* BuildConfiguration()
        {
#ifdef _DEBUG
            return "Debug";
#else
            return "Release";
#endif
        }

        std::string GlassPaneVersion()
        {
            return std::string(GlassPaneBaseVersion) + GlassPaneBuildSuffix;
        }

        ImVec4 AccentBlue()
        {
            return ImVec4(0.36f, 0.62f, 0.88f, 1.0f);
        }

        ImVec4 AppBg()
        {
            return ImVec4(0.017f, 0.023f, 0.032f, 1.0f);
        }

        ImVec4 HeaderBg()
        {
            return ImVec4(0.026f, 0.034f, 0.047f, 1.0f);
        }

        ImVec4 PanelBg()
        {
            return ImVec4(0.031f, 0.041f, 0.058f, 1.0f);
        }

        ImVec4 PanelBgRaised()
        {
            return ImVec4(0.046f, 0.061f, 0.084f, 1.0f);
        }

        ImVec4 PanelHover()
        {
            return ImVec4(0.060f, 0.082f, 0.118f, 1.0f);
        }

        ImVec4 PanelBorder()
        {
            return ImVec4(0.105f, 0.140f, 0.195f, 1.0f);
        }

        ImVec4 PrimaryText()
        {
            return ImVec4(0.89f, 0.93f, 0.97f, 1.0f);
        }

        ImVec4 MutedText()
        {
            return ImVec4(0.48f, 0.56f, 0.66f, 1.0f);
        }

        ImVec4 CardBg()
        {
            return ImVec4(0.040f, 0.054f, 0.076f, 1.0f);
        }

        ImVec4 GraphCanvasBg()
        {
            return ImVec4(0.015f, 0.020f, 0.030f, 1.0f);
        }

        ImVec4 GraphGridLine()
        {
            return ImVec4(0.125f, 0.165f, 0.220f, 0.24f);
        }

        ImVec4 TableSelectedRow()
        {
            return ImVec4(0.075f, 0.155f, 0.235f, 1.0f);
        }

        ImVec4 ConsoleBg()
        {
            return ImVec4(0.012f, 0.017f, 0.026f, 1.0f);
        }

        constexpr ImGuiWindowFlags PanelWindowFlags()
        {
#ifdef IMGUI_HAS_DOCK
            return ImGuiWindowFlags_NoCollapse;
#else
            return ImGuiWindowFlags_NoTitleBar |
                ImGuiWindowFlags_NoCollapse |
                ImGuiWindowFlags_NoResize |
                ImGuiWindowFlags_NoMove |
                ImGuiWindowFlags_NoSavedSettings;
#endif
        }

        void DrawActivePanelAccent()
        {
            const bool focused = ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows);
            const bool interacted =
                ImGui::IsWindowHovered(ImGuiHoveredFlags_RootAndChildWindows) &&
                (ImGui::IsMouseDown(ImGuiMouseButton_Left) ||
                    ImGui::IsMouseDown(ImGuiMouseButton_Right) ||
                    ImGui::IsMouseDown(ImGuiMouseButton_Middle));
            if (!focused && !interacted)
            {
                return;
            }

            const ImVec2 min = ImGui::GetWindowPos();
            const ImVec2 size = ImGui::GetWindowSize();
            const ImVec2 max(min.x + size.x, min.y + size.y);
            ImDrawList* drawList = ImGui::GetWindowDrawList();
            const ImVec4 accent = AccentBlue();
            const float alpha = focused ? 0.64f : 0.42f;
            const ImU32 border = ColorU32(ImVec4(accent.x, accent.y, accent.z, alpha));
            const ImU32 strip = ColorU32(ImVec4(accent.x, accent.y, accent.z, focused ? 0.82f : 0.55f));
            drawList->AddRect(min, max, border, 8.0f, 0, focused ? 1.6f : 1.2f);
            drawList->AddRectFilled(
                ImVec2(min.x + 12.0f, min.y),
                ImVec2(std::max(min.x + 12.0f, max.x - 12.0f), min.y + 2.0f),
                strip,
                2.0f);
        }

        bool BeginPanelWindow(const char* title)
        {
            ImGui::PushStyleColor(ImGuiCol_WindowBg, PanelBg());
            const bool visible = ImGui::Begin(title, nullptr, PanelWindowFlags());
            DrawActivePanelAccent();
            return visible;
        }

        bool BeginPanelWindow(const char* title, ImGuiWindowFlags extraFlags)
        {
            ImGui::PushStyleColor(ImGuiCol_WindowBg, PanelBg());
            const bool visible = ImGui::Begin(title, nullptr, PanelWindowFlags() | extraFlags);
            DrawActivePanelAccent();
            return visible;
        }

        bool BeginPanelWindow(const char* title, bool* open, ImGuiWindowFlags extraFlags)
        {
            ImGui::PushStyleColor(ImGuiCol_WindowBg, PanelBg());
            const bool visible = ImGui::Begin(title, open, PanelWindowFlags() | extraFlags);
            DrawActivePanelAccent();
            return visible;
        }

        void EndPanelWindow()
        {
            ImGui::End();
            ImGui::PopStyleColor();
        }

        void InspectorFieldRow(
            const char* id,
            const char* label,
            const std::wstring& value,
            float labelWidth = 118.0f,
            ImFont* valueFont = nullptr)
        {
            ImGui::PushID(id);
            const ImGuiTableFlags flags =
                ImGuiTableFlags_SizingStretchProp |
                ImGuiTableFlags_NoSavedSettings |
                ImGuiTableFlags_PadOuterX;
            if (ImGui::BeginTable("FieldRowTable##InspectorField", 2, flags))
            {
                ImGui::TableSetupColumn("Label", ImGuiTableColumnFlags_WidthFixed, labelWidth);
                ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::TextDisabled("%s", label);
                ImGui::TableSetColumnIndex(1);
                const bool pushedValueFont = PushFontIfAvailable(valueFont);
                ClippedTextWithTooltip(value.empty() ? L"(empty)" : value);
                PopFontIfPushed(pushedValueFont);
                ImGui::EndTable();
            }
            ImGui::PopID();
        }

        void TokenSummaryCell(const char* label, const std::wstring& value, const ImVec4& color, ImFont* valueFont)
        {
            ImGui::TextDisabled("%s", label);
            const bool pushedValueFont = PushFontIfAvailable(valueFont);
            ImGui::PushStyleColor(ImGuiCol_Text, color);
            ClippedTextWithTooltip(value.empty() ? L"(unavailable)" : value);
            ImGui::PopStyleColor();
            PopFontIfPushed(pushedValueFont);
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

        std::wstring YesNo(bool value)
        {
            return value ? L"Yes" : L"No";
        }

        std::wstring ParentRelationshipStatusText(Core::ParentRelationshipStatus status)
        {
            switch (status)
            {
            case Core::ParentRelationshipStatus::Verified:
                return L"Validated by creation time";
            case Core::ParentRelationshipStatus::Unverified:
                return L"Unverified; creation time unavailable";
            case Core::ParentRelationshipStatus::InvalidPidReuse:
                return L"Invalid; PID reuse suspected";
            case Core::ParentRelationshipStatus::MissingParent:
                return L"Parent PID not present in snapshot";
            case Core::ParentRelationshipStatus::NoParent:
            default:
                return L"(none)";
            }
        }

        std::wstring TokenUserText(const Core::TokenInfo& token)
        {
            if (token.userName.empty() && token.domainName.empty())
            {
                return L"(unavailable)";
            }
            if (token.domainName.empty())
            {
                return token.userName;
            }
            if (token.userName.empty())
            {
                return token.domainName;
            }
            return token.domainName + L"\\" + token.userName;
        }

        std::wstring PrivilegeStateText(const Core::PrivilegeInfo& privilege)
        {
            std::vector<std::wstring> states;
            if (privilege.removed)
            {
                states.push_back(L"Removed");
            }
            if (privilege.enabled)
            {
                states.push_back(L"Enabled");
            }
            if (privilege.enabledByDefault)
            {
                states.push_back(L"Default");
            }
            if (privilege.usedForAccess)
            {
                states.push_back(L"Used");
            }
            if (states.empty())
            {
                return L"Disabled";
            }

            std::wstring joined;
            for (std::size_t index = 0; index < states.size(); ++index)
            {
                if (index > 0)
                {
                    joined += L", ";
                }
                joined += states[index];
            }
            return joined;
        }

        std::wstring HandleValueText(std::uint64_t handleValue)
        {
            std::wstringstream stream;
            stream << L"0x" << std::uppercase << std::hex << handleValue;
            return stream.str();
        }

        std::wstring JoinWide(const std::vector<std::wstring>& values, const std::wstring& separator)
        {
            std::wstring joined;
            for (std::size_t index = 0; index < values.size(); ++index)
            {
                if (index > 0)
                {
                    joined += separator;
                }
                joined += values[index];
            }
            return joined;
        }

        bool StartsWith(const std::wstring& value, const std::wstring& prefix)
        {
            return value.size() >= prefix.size() &&
                std::equal(prefix.begin(), prefix.end(), value.begin());
        }

        bool IsRawObjectTypeIndex(const std::wstring& objectType)
        {
            if (!StartsWith(objectType, L"Type ") || objectType.size() <= 5)
            {
                return false;
            }

            return std::all_of(objectType.begin() + 5, objectType.end(), [](wchar_t ch) {
                return std::iswdigit(ch) != 0;
            });
        }

        std::wstring HandleObjectTypeText(const Core::HandleInfo& handle)
        {
            if (handle.objectType.empty())
            {
                return L"Unknown";
            }

            if (IsRawObjectTypeIndex(handle.objectType))
            {
                return L"Unknown (" + handle.objectType.substr(5) + L")";
            }

            return handle.objectType;
        }

        bool IsNamedObjectType(const std::wstring& objectType)
        {
            const std::wstring loweredType = ToLower(objectType);
            return loweredType == L"key" ||
                loweredType == L"section" ||
                loweredType == L"mutant" ||
                loweredType == L"event" ||
                loweredType == L"semaphore" ||
                loweredType == L"symboliclink" ||
                loweredType == L"directory";
        }

        bool IsHandleNameLookupSkipped(const Core::HandleInfo& handle)
        {
            if (!handle.objectName.empty() || handle.targetPid.has_value() || IsRawObjectTypeIndex(handle.objectType))
            {
                return false;
            }

            return !IsNamedObjectType(handle.objectType);
        }

        bool IsHandleNameUnavailable(const Core::HandleInfo& handle)
        {
            return handle.objectName.empty() &&
                !handle.targetPid.has_value() &&
                IsNamedObjectType(handle.objectType);
        }

        std::wstring NormalizeHandleIndicator(const std::wstring& indicator)
        {
            const std::wstring lowered = ToLower(indicator);
            if (lowered.find(L"lsass.exe") != std::wstring::npos ||
                lowered.find(L"winlogon.exe") != std::wstring::npos)
            {
                return L"Sensitive process handle";
            }
            if (lowered.find(L"vm write") != std::wstring::npos ||
                lowered.find(L"create-thread") != std::wstring::npos ||
                lowered.find(L"duplicate-handle") != std::wstring::npos)
            {
                return L"Suspicious access rights";
            }
            if (lowered.find(L"token handle") != std::wstring::npos)
            {
                return L"Token handle";
            }
            if (lowered.find(L"registry key") != std::wstring::npos)
            {
                return L"Sensitive registry key";
            }
            if (lowered.find(L"user-writable") != std::wstring::npos)
            {
                return L"User-writable file handle";
            }
            return indicator;
        }

        std::wstring HandleIndicatorText(const Core::HandleInfo& handle)
        {
            if (handle.indicators.empty())
            {
                return {};
            }

            std::vector<std::wstring> labels;
            for (const std::wstring& indicator : handle.indicators)
            {
                const std::wstring label = NormalizeHandleIndicator(indicator);
                if (std::find(labels.begin(), labels.end(), label) == labels.end())
                {
                    labels.push_back(label);
                }
            }
            return JoinWide(labels, L"; ");
        }

        std::wstring HandleStatusText(const Core::HandleInfo& handle)
        {
            if (!handle.objectName.empty() || handle.targetPid.has_value())
            {
                return {};
            }
            if (IsRawObjectTypeIndex(handle.objectType))
            {
                return L"Type unavailable";
            }
            if (IsHandleNameUnavailable(handle))
            {
                return L"Name unavailable";
            }
            if (IsHandleNameLookupSkipped(handle))
            {
                return L"Name skipped";
            }
            return handle.errorMessage.empty() ? L"" : L"Name unavailable";
        }

        std::wstring HandleTargetText(const Core::HandleInfo& handle)
        {
            if (handle.targetPid.has_value())
            {
                if (!handle.targetProcessName.empty())
                {
                    return handle.targetProcessName + L"  PID " + std::to_wstring(handle.targetPid.value());
                }
                return L"PID " + std::to_wstring(handle.targetPid.value());
            }

            if (!handle.objectName.empty())
            {
                return handle.objectName;
            }

            return L"(name unavailable)";
        }

        std::wstring HandleTargetTooltipText(const Core::HandleInfo& handle)
        {
            std::wstringstream text;
            text << L"Target / Name: " << HandleTargetText(handle) << L"\n";
            text << L"Type: " << HandleObjectTypeText(handle);
            if (IsRawObjectTypeIndex(handle.objectType))
            {
                text << L" (object type name unavailable; raw " << handle.objectType << L")";
            }
            text << L"\n";
            text << L"Access: " << (handle.grantedAccess.empty() ? L"(unknown)" : handle.grantedAccess);
            if (!handle.decodedAccess.empty())
            {
                text << L"\nDecoded access:\n" << JoinWide(handle.decodedAccess, L"\n");
            }
            if (!handle.errorMessage.empty())
            {
                text << L"\nMetadata note: " << handle.errorMessage;
            }
            return text.str();
        }

        std::wstring HandleAccessTooltipText(const Core::HandleInfo& handle)
        {
            std::wstring text = handle.grantedAccess.empty() ? L"(access unavailable)" : handle.grantedAccess;
            if (!handle.decodedAccess.empty())
            {
                text += L"\n";
                text += JoinWide(handle.decodedAccess, L"\n");
            }
            return text;
        }

        bool HandleMatchesFilter(const Core::HandleInfo& handle, HandleFilter filter)
        {
            const std::wstring loweredType = ToLower(handle.objectType);
            switch (filter)
            {
            case HandleFilter::Sensitive:
                return handle.isSensitive;
            case HandleFilter::Process:
                return loweredType == L"process";
            case HandleFilter::Token:
                return loweredType == L"token";
            case HandleFilter::File:
                return loweredType == L"file";
            case HandleFilter::Registry:
                return loweredType == L"key";
            case HandleFilter::NamedObjects:
                return !handle.objectName.empty() || IsNamedObjectType(handle.objectType);
            case HandleFilter::WithIndicators:
                return !handle.indicators.empty();
            case HandleFilter::All:
            default:
                return true;
            }
        }

        bool HandleMatchesSearch(const Core::HandleInfo& handle, const std::wstring& loweredSearch)
        {
            if (loweredSearch.empty())
            {
                return true;
            }

            std::wstring searchable;
            searchable.reserve(256);
            searchable += ToLower(HandleValueText(handle.handleValue));
            searchable += L" ";
            searchable += ToLower(handle.objectType);
            searchable += L" ";
            searchable += ToLower(HandleObjectTypeText(handle));
            searchable += L" ";
            searchable += ToLower(HandleTargetText(handle));
            searchable += L" ";
            searchable += ToLower(handle.objectName);
            searchable += L" ";
            searchable += ToLower(handle.grantedAccess);
            searchable += L" ";
            searchable += ToLower(HandleIndicatorText(handle));
            searchable += L" ";
            searchable += ToLower(HandleStatusText(handle));
            return searchable.find(loweredSearch) != std::wstring::npos;
        }

        std::wstring MemoryIndicatorText(const Core::MemoryRegionInfo& region)
        {
            if (region.indicators.empty())
            {
                return {};
            }
            return JoinWide(region.indicators, L"; ");
        }

        bool MemoryMatchesFilter(const Core::MemoryRegionInfo& region, MemoryFilter filter)
        {
            switch (filter)
            {
            case MemoryFilter::Executable:
                return region.isExecutable;
            case MemoryFilter::Writable:
                return region.isWritable;
            case MemoryFilter::Private:
                return region.isPrivate;
            case MemoryFilter::Image:
                return region.isImage;
            case MemoryFilter::Suspicious:
                return region.isSuspicious;
            case MemoryFilter::Rwx:
                return region.isExecutable && region.isWritable;
            case MemoryFilter::All:
            default:
                return true;
            }
        }

        bool MemoryMatchesSearch(const Core::MemoryRegionInfo& region, const std::wstring& loweredSearch)
        {
            if (loweredSearch.empty())
            {
                return true;
            }

            std::wstring searchable;
            searchable.reserve(512);
            searchable += ToLower(region.baseAddressString);
            searchable += L" ";
            searchable += ToLower(region.allocationBaseString);
            searchable += L" ";
            searchable += ToLower(region.regionSizeString);
            searchable += L" ";
            searchable += ToLower(region.stateName);
            searchable += L" ";
            searchable += ToLower(region.typeName);
            searchable += L" ";
            searchable += ToLower(region.protectName);
            searchable += L" ";
            searchable += ToLower(region.allocationProtectName);
            searchable += L" ";
            searchable += ToLower(region.mappedFilePath);
            searchable += L" ";
            searchable += ToLower(MemoryIndicatorText(region));
            return searchable.find(loweredSearch) != std::wstring::npos;
        }

        Core::Severity FindingSeverityAsCoreSeverity(Core::FindingSeverity severity)
        {
            switch (severity)
            {
            case Core::FindingSeverity::High:
                return Core::Severity::High;
            case Core::FindingSeverity::Medium:
                return Core::Severity::Medium;
            case Core::FindingSeverity::Low:
                return Core::Severity::Low;
            case Core::FindingSeverity::Info:
            default:
                return Core::Severity::Info;
            }
        }

        ImVec4 FindingSeverityColor(Core::FindingSeverity severity)
        {
            return SeverityColor(FindingSeverityAsCoreSeverity(severity));
        }

        ImVec4 FindingCardBg(Core::FindingSeverity severity)
        {
            switch (severity)
            {
            case Core::FindingSeverity::High:
                return ImVec4(0.090f, 0.041f, 0.049f, 1.0f);
            case Core::FindingSeverity::Medium:
                return ImVec4(0.090f, 0.061f, 0.035f, 1.0f);
            case Core::FindingSeverity::Low:
                return ImVec4(0.072f, 0.066f, 0.038f, 1.0f);
            case Core::FindingSeverity::Info:
            default:
                return ImVec4(0.044f, 0.055f, 0.073f, 1.0f);
            }
        }

        std::wstring TriageFilterLabel(TriageFilter filter)
        {
            switch (filter)
            {
            case TriageFilter::High:
                return L"High";
            case TriageFilter::Medium:
                return L"Medium";
            case TriageFilter::Low:
                return L"Low";
            case TriageFilter::Info:
                return L"Info";
            case TriageFilter::All:
            default:
                return L"All";
            }
        }

        bool FindingMatchesFilter(const Core::Finding& finding, TriageFilter filter)
        {
            switch (filter)
            {
            case TriageFilter::Info:
                return finding.severity == Core::FindingSeverity::Info;
            case TriageFilter::Low:
                return finding.severity == Core::FindingSeverity::Low;
            case TriageFilter::Medium:
                return finding.severity == Core::FindingSeverity::Medium;
            case TriageFilter::High:
                return finding.severity == Core::FindingSeverity::High;
            case TriageFilter::All:
            default:
                return true;
            }
        }

        std::wstring FormatFindingForClipboard(const Core::Finding& finding)
        {
            std::wstringstream text;
            text << L"[" << Core::FindingSeverityToString(finding.severity) << L"] "
                << (finding.title.empty() ? L"(untitled finding)" : finding.title) << L"\r\n";
            if (!finding.category.empty())
            {
                text << L"Category: " << finding.category << L"\r\n";
            }
            if (!finding.description.empty())
            {
                text << L"Description: " << finding.description << L"\r\n";
            }
            if (!finding.evidence.empty())
            {
                text << L"Evidence:\r\n";
                for (const std::wstring& evidence : finding.evidence)
                {
                    text << L"- " << evidence << L"\r\n";
                }
            }
            return text.str();
        }

        std::wstring FormatTriageSummaryForClipboard(
            const Core::ProcessInfo& process,
            const std::vector<Core::Finding>& findings)
        {
            std::wstringstream text;
            text << L"Triage: " << Core::TriageSummary(findings) << L"\r\n";
            text << L"Process: " << (process.name.empty() ? L"(unknown)" : process.name)
                << L" (PID " << process.pid << L")\r\n";
            text << L"Finding count: " << findings.size() << L"\r\n";
            text << L"Highest severity: "
                << (findings.empty()
                    ? L"None"
                    : Core::FindingSeverityToString(Core::HighestFindingSeverity(findings)))
                << L"\r\n";
            return text.str();
        }

        std::wstring FormatFindingsForClipboard(
            const Core::ProcessInfo& process,
            const std::vector<Core::Finding>& findings)
        {
            std::wstringstream text;
            text << FormatTriageSummaryForClipboard(process, findings);
            if (!findings.empty())
            {
                text << L"\r\nFindings\r\n";
                for (std::size_t index = 0; index < findings.size(); ++index)
                {
                    if (index > 0)
                    {
                        text << L"\r\n";
                    }
                    text << FormatFindingForClipboard(findings[index]);
                }
            }
            return text.str();
        }

        bool ChipButton(const char* label, bool active, const ImVec4& accent)
        {
            PushGlassChipStyle(active, accent);
            const bool clicked = ImGui::Button(label, ImVec2(0.0f, 29.0f));
            PopGlassChipStyle();
            if (active)
            {
                const ImVec2 min = ImGui::GetItemRectMin();
                const ImVec2 max = ImGui::GetItemRectMax();
                ImGui::GetWindowDrawList()->AddRect(min, max, ColorU32(ImVec4(accent.x, accent.y, accent.z, 0.70f)), 6.0f, 0, 1.3f);
                ImGui::GetWindowDrawList()->AddRectFilled(
                    ImVec2(min.x + 8.0f, max.y - 3.0f),
                    ImVec2(max.x - 8.0f, max.y - 1.0f),
                    ColorU32(ImVec4(accent.x, accent.y, accent.z, 0.85f)),
                    2.0f);
            }
            return clicked;
        }

        float ChipButtonWidth(const char* label)
        {
            return ImGui::CalcTextSize(label).x + 22.0f;
        }

        float StandardButtonWidth(const char* label)
        {
            const ImGuiStyle& style = ImGui::GetStyle();
            return ImGui::CalcTextSize(label).x + style.FramePadding.x * 2.0f + 2.0f;
        }

        void SameLineIfFits(float nextItemWidth, float spacing = 4.0f)
        {
            const float contentRight = ImGui::GetCursorScreenPos().x + ImGui::GetContentRegionAvail().x;
            const float nextItemRight = ImGui::GetItemRectMax().x + spacing + nextItemWidth;
            if (nextItemRight <= contentRight)
            {
                ImGui::SameLine(0.0f, spacing);
            }
        }

        void SameLineIfChipFits(const char* nextLabel, float spacing = 4.0f)
        {
            SameLineIfFits(ChipButtonWidth(nextLabel), spacing);
        }

        void AcknowledgeTableAutoSizeRequest(bool& needsAutoSize)
        {
            needsAutoSize = false;
        }

        void BeginInspectorCard(const char* id, const char* title, ImFont* headingFont)
        {
            PushGlassCardStyle();
            ImGui::BeginChild(
                id,
                ImVec2(0.0f, 0.0f),
                ImGuiChildFlags_Borders | ImGuiChildFlags_AlwaysUseWindowPadding | ImGuiChildFlags_AutoResizeY);
            RenderGlassSectionHeader(title, headingFont, AccentBlue());
        }

        void EndInspectorCard()
        {
            ImGui::EndChild();
            PopGlassCardStyle();
            ImGui::Spacing();
        }

        void CopyTextToClipboard(const std::wstring& value)
        {
            const std::string text = WideToUtf8(value);
            ImGui::SetClipboardText(text.c_str());
        }

        ImVec4 LogColor(LogLevel level)
        {
            switch (level)
            {
            case LogLevel::High:
                return ImVec4(0.96f, 0.24f, 0.22f, 1.0f);
            case LogLevel::Warning:
                return ImVec4(0.96f, 0.52f, 0.20f, 1.0f);
            case LogLevel::Info:
            default:
                return ImVec4(0.55f, 0.72f, 0.92f, 1.0f);
            }
        }

        const char* LogLevelLabel(LogLevel level)
        {
            switch (level)
            {
            case LogLevel::High:
                return "HIGH";
            case LogLevel::Warning:
                return "WARN";
            case LogLevel::Info:
            default:
                return "INFO";
            }
        }

        LogsPanelLevel ToLogsPanelLevel(LogLevel level)
        {
            switch (level)
            {
            case LogLevel::High:
                return LogsPanelLevel::High;
            case LogLevel::Warning:
                return LogsPanelLevel::Warning;
            case LogLevel::Info:
            default:
                return LogsPanelLevel::Info;
            }
        }
    }

    class ImGuiApp
    {
    public:
        explicit ImGuiApp(HINSTANCE instance)
            : instance_(instance)
        {
        }

        bool Create(int showCommand)
        {
            WNDCLASSEXW windowClass = {};
            windowClass.cbSize = sizeof(windowClass);
            windowClass.style = CS_CLASSDC;
            windowClass.lpfnWndProc = ImGuiApp::WindowProc;
            windowClass.hInstance = instance_;
            windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
            windowClass.lpszClassName = L"GlassPaneImGuiWindow";
            windowClass.hIcon = LoadGlassPaneIcon(instance_, GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON));
            windowClass.hIconSm = LoadGlassPaneIcon(instance_, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON));

            if (RegisterClassExW(&windowClass) == 0)
            {
                return false;
            }

            hwnd_ = CreateWindowW(
                windowClass.lpszClassName,
                L"GlassPane",
                WS_OVERLAPPEDWINDOW,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                WindowWidth,
                WindowHeight,
                nullptr,
                nullptr,
                instance_,
                this);
            if (hwnd_ == nullptr)
            {
                UnregisterClassW(windowClass.lpszClassName, instance_);
                return false;
            }
            ApplyDarkNativeTitleBar(hwnd_);
            SendMessageW(hwnd_, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(windowClass.hIcon));
            SendMessageW(hwnd_, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(windowClass.hIconSm));

            if (!CreateDeviceD3D())
            {
                CleanupDeviceD3D();
                DestroyWindow(hwnd_);
                hwnd_ = nullptr;
                UnregisterClassW(windowClass.lpszClassName, instance_);
                return false;
            }

            const HRESULT comInitResult = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
            comInitialized_ = SUCCEEDED(comInitResult);

            IMGUI_CHECKVERSION();
            ImGui::CreateContext();
            ImGuiIO& io = ImGui::GetIO();
            io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
#ifdef IMGUI_HAS_DOCK
            io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
#endif
            io.IniFilename = "GlassPaneImGui.ini";

            fonts_.Load();
            ApplyGlassPaneTheme();

            ImGui_ImplWin32_Init(hwnd_);
            ImGui_ImplDX11_Init(device_, deviceContext_);

            ShowWindow(hwnd_, showCommand);
            UpdateWindow(hwnd_);

            RefreshSnapshot();
            return true;
        }

        int Run()
        {
            MSG message = {};
            while (message.message != WM_QUIT)
            {
                while (PeekMessageW(&message, nullptr, 0U, 0U, PM_REMOVE))
                {
                    TranslateMessage(&message);
                    DispatchMessageW(&message);
                    if (message.message == WM_QUIT)
                    {
                        break;
                    }
                }

                if (message.message == WM_QUIT)
                {
                    break;
                }

                ImGui_ImplDX11_NewFrame();
                ImGui_ImplWin32_NewFrame();
                ImGui::NewFrame();

                RenderUi();
                UpdatePickWindowCursor();

                ImGui::Render();
                const float clearColor[4] = { 0.04f, 0.05f, 0.07f, 1.00f };
                deviceContext_->OMSetRenderTargets(1, &renderTargetView_, nullptr);
                deviceContext_->ClearRenderTargetView(renderTargetView_, clearColor);
                ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
                swapChain_->Present(1, 0);
            }

            Cleanup();
            return static_cast<int>(message.wParam);
        }

    private:
        static LRESULT WINAPI WindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
        {
            ImGuiApp* app = nullptr;
            if (message == WM_NCCREATE)
            {
                const CREATESTRUCTW* create = reinterpret_cast<const CREATESTRUCTW*>(lParam);
                app = static_cast<ImGuiApp*>(create->lpCreateParams);
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(app));
            }
            else
            {
                app = reinterpret_cast<ImGuiApp*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
            }

            if (app != nullptr)
            {
                const std::optional<LRESULT> pickerResult = app->HandlePickerWindowMessage(message, wParam, lParam);
                if (pickerResult.has_value())
                {
                    return pickerResult.value();
                }
            }

            if (ImGui_ImplWin32_WndProcHandler(hwnd, message, wParam, lParam))
            {
                return TRUE;
            }

            switch (message)
            {
            case WM_SIZE:
                if (app != nullptr && app->device_ != nullptr && wParam != SIZE_MINIMIZED)
                {
                    app->ResizeRenderTarget(static_cast<UINT>(LOWORD(lParam)), static_cast<UINT>(HIWORD(lParam)));
                }
                return 0;
            case WM_DESTROY:
                PostQuitMessage(0);
                return 0;
            default:
                break;
            }

            return DefWindowProcW(hwnd, message, wParam, lParam);
        }

        #include "PickWindowActions.cpp"

        #include "RenderDeviceActions.cpp"

        void Cleanup()
        {
            WaitForLongOperationBeforeShutdown();
            ReleasePickerCapture();
            DestroyPickWindowOverlay();
            pickWindowActive_ = false;

            ImGui_ImplDX11_Shutdown();
            ImGui_ImplWin32_Shutdown();
            ImGui::DestroyContext();

            ReleaseIconCache();
            if (comInitialized_)
            {
                CoUninitialize();
                comInitialized_ = false;
            }
            CleanupDeviceD3D();

            if (hwnd_ != nullptr)
            {
                DestroyWindow(hwnd_);
                hwnd_ = nullptr;
            }
            UnregisterClassW(L"GlassPaneImGuiWindow", instance_);
            if (pickerOverlayClassRegistered_)
            {
                UnregisterClassW(L"GlassPanePickerOverlayWindow", instance_);
                pickerOverlayClassRegistered_ = false;
            }
        }

        void AddLog(LogLevel level, const std::string& message)
        {
            logs_.push_back({ level, WideToUtf8(LocalTimestamp()) + "  " + message });
            constexpr std::size_t MaxLogEntries = 400;
            if (logs_.size() > MaxLogEntries)
            {
                logs_.erase(logs_.begin(), logs_.begin() + static_cast<std::vector<LogEntry>::difference_type>(logs_.size() - MaxLogEntries));
            }
        }

        bool IsLongOperationActive() const
        {
            return longOperationRunning_.load() && !longOperationCompleted_.load();
        }

        static const char* LongOperationTitle(LongRunningOperationKind kind)
        {
            switch (kind)
            {
            case LongRunningOperationKind::SaveSnapshot:
                return "Saving Snapshot...";
            case LongRunningOperationKind::SaveDeepSnapshot:
                return "Saving Deep Evidence Snapshot...";
            case LongRunningOperationKind::ExportEvidencePackage:
                return "Exporting Evidence Package...";
            case LongRunningOperationKind::UpdateIntelFeed:
                return "Updating Network Intelligence...";
            case LongRunningOperationKind::LoadIntelFeed:
                return "Loading Network Intelligence...";
            case LongRunningOperationKind::LoadSnapshot:
                return "Loading Snapshot...";
            default:
                return "Working...";
            }
        }

        static const char* LongOperationStatusLabel(LongRunningOperationKind kind)
        {
            switch (kind)
            {
            case LongRunningOperationKind::SaveSnapshot:
                return "Saving snapshot";
            case LongRunningOperationKind::SaveDeepSnapshot:
                return "Saving deep evidence snapshot";
            case LongRunningOperationKind::ExportEvidencePackage:
                return "Exporting evidence package";
            case LongRunningOperationKind::UpdateIntelFeed:
                return "Updating Network Intelligence";
            case LongRunningOperationKind::LoadIntelFeed:
                return "Loading Network Intelligence";
            case LongRunningOperationKind::LoadSnapshot:
                return "Loading snapshot";
            default:
                return "operation";
            }
        }

        void UpdateLongOperationProgress(const std::string& status, float progress)
        {
            std::lock_guard<std::mutex> lock(longOperationMutex_);
            longOperationStatus_ = status;
            longOperationProgress_ = std::clamp(progress, 0.0f, 1.0f);
        }

        bool StartLongOperation(
            LongRunningOperationKind kind,
            const std::string& initialStatus,
            std::function<LongOperationResult(std::function<void(const std::string&, float)>)> worker)
        {
            if (IsLongOperationActive())
            {
                AddLog(LogLevel::Warning, "Action ignored because another operation is already running.");
                return false;
            }

            if (longOperationWorker_.joinable())
            {
                longOperationWorker_.join();
            }

            {
                std::lock_guard<std::mutex> lock(longOperationMutex_);
                longOperationKind_ = kind;
                longOperationTitle_ = LongOperationTitle(kind);
                longOperationStatus_ = initialStatus;
                longOperationProgress_ = 0.0f;
                longOperationResult_ = {};
                longOperationResultVisible_ = false;
                longOperationResultVisibleFrame_ = -1;
                longOperationCloseClickArmed_ = false;
            }

            longOperationCompleted_.store(false);
            longOperationRunning_.store(true);
            longOperationWorker_ = std::thread([this, kind, worker = std::move(worker)]() mutable {
                auto progress = [this](const std::string& status, float value) {
                    UpdateLongOperationProgress(status, value);
                };

                LongOperationResult result;
                result.kind = kind;
                try
                {
                    result = worker(progress);
                    result.kind = kind;
                }
                catch (const std::exception& ex)
                {
                    result.kind = kind;
                    result.success = false;
                    result.status = std::string("Operation failed: ") + ex.what();
                }
                catch (...)
                {
                    result.kind = kind;
                    result.success = false;
                    result.status = "Operation failed unexpectedly.";
                }

                {
                    std::lock_guard<std::mutex> lock(longOperationMutex_);
                    longOperationResult_ = std::move(result);
                    longOperationStatus_ = longOperationResult_.status.empty()
                        ? (longOperationResult_.success ? "Operation complete." : "Operation failed.")
                        : longOperationResult_.status;
                    longOperationProgress_ = 1.0f;
                }
                longOperationCompleted_.store(true);
            });

            return true;
        }

        void ApplyLongOperationResult(const LongOperationResult& result)
        {
            for (const LongOperationLog& entry : result.logs)
            {
                AddLog(entry.level, entry.message);
            }

            switch (result.kind)
            {
            case LongRunningOperationKind::SaveSnapshot:
            case LongRunningOperationKind::SaveDeepSnapshot:
            case LongRunningOperationKind::ExportEvidencePackage:
                timings_.jsonExportMs = result.elapsedMs;
                break;
            case LongRunningOperationKind::UpdateIntelFeed:
                networkIndicatorUpdateInProgress_ = false;
                networkIndicatorUpdateAttempted_ = true;
                networkIndicatorUpdateResult_ = result.networkUpdateResult;
                if (result.networkUpdateResult.success)
                {
                    networkIndicatorLoadAttempted_ = true;
                    networkIndicatorUsedFallback_ = false;
                    networkIndicatorLoadResult_ = result.networkUpdateResult.loadResult;
                    networkIndicatorFeed_ = networkIndicatorLoadResult_.feed;
                    RefreshNetworkIntelMatches(true);
                    InvalidateFindingsCache();
                }
                break;
            case LongRunningOperationKind::LoadIntelFeed:
                networkIndicatorUpdateAttempted_ = false;
                networkIndicatorUpdateResult_ = {};
                networkIndicatorLoadAttempted_ = true;
                networkIndicatorUsedFallback_ = result.networkUsedFallback;
                networkIndicatorLoadResult_ = result.networkLoadResult;
                networkIndicatorFeed_ = networkIndicatorLoadResult_.success
                    ? networkIndicatorLoadResult_.feed
                    : Core::NetworkIndicatorFeed{};
                RefreshNetworkIntelMatches(false);
                InvalidateFindingsCache();
                break;
            case LongRunningOperationKind::LoadSnapshot:
                if (result.success && result.hasLoadedSnapshot)
                {
                    ApplyLoadedSnapshot(result.loadedSnapshot, result.inputPath);
                }
                break;
            default:
                break;
            }

            const bool statusAlreadyLogged =
                std::any_of(
                    result.logs.begin(),
                    result.logs.end(),
                    [&result](const LongOperationLog& entry) {
                        return entry.message == result.status ||
                            (!result.status.empty() &&
                                entry.message.rfind(result.status + " (", 0) == 0);
                    });

            if (!result.status.empty() && !statusAlreadyLogged)
            {
                AddLog(result.success ? LogLevel::Info : LogLevel::Warning, result.status);
            }
        }

        void PollLongOperationCompletion()
        {
            if (!longOperationCompleted_.load())
            {
                return;
            }

            if (longOperationWorker_.joinable())
            {
                longOperationWorker_.join();
            }

            LongOperationResult result;
            {
                std::lock_guard<std::mutex> lock(longOperationMutex_);
                result = std::move(longOperationResult_);
                longOperationResult_.success = result.success;
            }
            ApplyLongOperationResult(result);
            longOperationRunning_.store(false);
            longOperationCompleted_.store(false);
            longOperationResultVisible_ = true;
            longOperationResultVisibleFrame_ = ImGui::GetFrameCount();
            longOperationCloseClickArmed_ = false;
        }

        void WaitForLongOperationBeforeShutdown()
        {
            if (!longOperationRunning_.load() && !longOperationWorker_.joinable())
            {
                return;
            }

            {
                std::lock_guard<std::mutex> lock(longOperationMutex_);
                if (longOperationRunning_.load() && !longOperationCompleted_.load())
                {
                    longOperationStatus_ = "Finishing operation before shutdown...";
                }
            }
            if (longOperationWorker_.joinable())
            {
                longOperationWorker_.join();
            }
            if (longOperationCompleted_.load())
            {
                LongOperationResult result;
                {
                    std::lock_guard<std::mutex> lock(longOperationMutex_);
                    result = std::move(longOperationResult_);
                    longOperationResult_.success = result.success;
                }
                ApplyLongOperationResult(result);
            }
            longOperationRunning_.store(false);
            longOperationCompleted_.store(false);
        }

        void RenderLongOperationOverlay()
        {
            const bool active = IsLongOperationActive();
            if (!active && !longOperationResultVisible_)
            {
                return;
            }

            std::string title;
            std::string status;
            float progress = 0.0f;
            bool success = false;
            LongRunningOperationKind kind = LongRunningOperationKind::None;
            {
                std::lock_guard<std::mutex> lock(longOperationMutex_);
                title = longOperationTitle_.empty() ? "Working..." : longOperationTitle_;
                status = longOperationStatus_;
                progress = longOperationProgress_;
                success = longOperationResult_.success;
                kind = longOperationKind_;
            }
            const bool showFooter = !active && longOperationResultVisible_;

            constexpr const char* PopupId = "Operation Status##GlassPaneLongOperation";
            if (!ImGui::IsPopupOpen(PopupId))
            {
                ImGui::OpenPopup(PopupId);
            }

            std::string rawStatus;
            if (status.empty())
            {
                rawStatus = active ? "Working..." : "Operation complete.";
            }
            else if (!active && success)
            {
                switch (kind)
                {
                case LongRunningOperationKind::SaveSnapshot:
                    rawStatus = "Snapshot saved successfully.";
                    break;
                case LongRunningOperationKind::SaveDeepSnapshot:
                    rawStatus = "Deep evidence snapshot saved successfully.";
                    break;
                case LongRunningOperationKind::ExportEvidencePackage:
                    rawStatus = "Evidence package exported successfully.";
                    break;
                case LongRunningOperationKind::LoadSnapshot:
                    rawStatus = "Snapshot loaded successfully.";
                    break;
                default:
                    rawStatus = status;
                    break;
                }
            }
            else
            {
                rawStatus = status;
            }

            ImGuiViewport* viewport = ImGui::GetMainViewport();
            const ImGuiStyle& style = ImGui::GetStyle();
            constexpr float DesiredWidth = 500.0f;
            constexpr float MinWidth = 360.0f;
            constexpr float ViewportMargin = 48.0f;
            constexpr float ProgressHeight = 26.0f;
            constexpr float TitleToProgressSpacing = 12.0f;
            constexpr float ProgressToStatusSpacing = 12.0f;
            constexpr float StatusToFooterSpacing = 16.0f;
            constexpr float FooterBottomPadding = 14.0f;
            constexpr float LayoutSafetyPadding = 12.0f;
            const ImVec2 modalPadding(16.0f, 14.0f);
            const float maxModalWidth = std::max(260.0f, viewport->WorkSize.x - ViewportMargin);
            const float modalMinWidth = std::min(MinWidth, maxModalWidth);
            const float modalWidth = std::clamp(DesiredWidth, modalMinWidth, maxModalWidth);
            const float contentWidth = std::max(1.0f, modalWidth - modalPadding.x * 2.0f);

            auto fitTextToWidth = [](const std::string& value, float width) {
                if (value.empty() || ImGui::CalcTextSize(value.c_str()).x <= width)
                {
                    return value;
                }

                constexpr const char* Ellipsis = "...";
                const float ellipsisWidth = ImGui::CalcTextSize(Ellipsis).x;
                if (ellipsisWidth >= width)
                {
                    return std::string(Ellipsis);
                }

                std::size_t low = 0;
                std::size_t high = value.size();
                while (low < high)
                {
                    const std::size_t mid = (low + high + 1) / 2;
                    const std::string candidate = value.substr(0, mid) + Ellipsis;
                    if (ImGui::CalcTextSize(candidate.c_str()).x <= width)
                    {
                        low = mid;
                    }
                    else
                    {
                        high = mid - 1;
                    }
                }
                return value.substr(0, low) + Ellipsis;
            };

            const float spinnerWidth = active ? 28.0f : 0.0f;
            const std::string displayTitle = fitTextToWidth(title, contentWidth);
            const std::string displayStatus =
                fitTextToWidth(rawStatus, std::max(1.0f, contentWidth - spinnerWidth));
            const float titleHeight = std::max(
                ImGui::GetTextLineHeight(),
                ImGui::CalcTextSize(displayTitle.c_str()).y);
            const float statusLineHeight = std::max(
                ImGui::GetTextLineHeight(),
                ImGui::CalcTextSize(displayStatus.c_str()).y);
            const float statusAreaHeight =
                std::max(statusLineHeight * 2.0f + style.ItemSpacing.y * 0.25f, 30.0f);
            const float footerHeight = showFooter ? ImGui::GetFrameHeightWithSpacing() : 0.0f;
            const float footerSpacing = showFooter ? StatusToFooterSpacing : 0.0f;
            const float footerBottomPadding = showFooter ? FooterBottomPadding : 0.0f;
            const float popupTitleBarHeight = ImGui::GetFrameHeightWithSpacing();
            const float measuredHeight =
                popupTitleBarHeight +
                modalPadding.y * 2.0f +
                titleHeight +
                TitleToProgressSpacing +
                ProgressHeight +
                ProgressToStatusSpacing +
                statusAreaHeight +
                footerSpacing +
                footerHeight +
                footerBottomPadding +
                LayoutSafetyPadding;
            const float maxModalHeight = std::max(160.0f, viewport->WorkSize.y - ViewportMargin);
            const float modalHeight = std::min(measuredHeight, maxModalHeight);
            const bool needsScroll = modalHeight + 0.5f < measuredHeight;
            const ImVec2 modalSize(modalWidth, modalHeight);
            ImGui::SetNextWindowSize(modalSize, ImGuiCond_Always);
            ImGui::SetNextWindowSizeConstraints(modalSize, modalSize);
            ImGui::PushStyleColor(ImGuiCol_ModalWindowDimBg, ImVec4(0.0f, 0.0f, 0.0f, 0.58f));
            ImGui::PushStyleColor(ImGuiCol_PopupBg, PanelBgRaised());
            ImGui::PushStyleColor(ImGuiCol_Border, PanelBorder());
            ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 8.0f);
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, modalPadding);
            ImGuiWindowFlags flags =
                ImGuiWindowFlags_NoResize |
                ImGuiWindowFlags_NoSavedSettings |
                ImGuiWindowFlags_NoCollapse;
            if (!needsScroll)
            {
                flags |= ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse;
            }
#ifdef IMGUI_HAS_DOCK
            flags |= ImGuiWindowFlags_NoDocking;
#endif
            const bool modalVisible = ImGui::BeginPopupModal(
                PopupId,
                nullptr,
                flags);
            ImGui::PopStyleVar(2);
            ImGui::PopStyleColor(3);

            if (!modalVisible)
            {
                return;
            }

            const ImGuiViewport* overlayViewport = ImGui::GetMainViewport();
            const ImVec2 overlayMin = overlayViewport->Pos;
            const ImVec2 overlayMax(
                overlayMin.x + overlayViewport->Size.x,
                overlayMin.y + overlayViewport->Size.y);
            const ImVec2 popupMin = ImGui::GetWindowPos();
            const ImVec2 popupMax(
                popupMin.x + ImGui::GetWindowSize().x,
                popupMin.y + ImGui::GetWindowSize().y);
            auto pointInsideOverlay = [overlayMin, overlayMax](const ImVec2& point) {
                return point.x >= overlayMin.x &&
                    point.x <= overlayMax.x &&
                    point.y >= overlayMin.y &&
                    point.y <= overlayMax.y;
            };
            auto pointInsidePopup = [popupMin, popupMax](const ImVec2& point) {
                return point.x >= popupMin.x &&
                    point.x <= popupMax.x &&
                    point.y >= popupMin.y &&
                    point.y <= popupMax.y;
            };
            if (showFooter &&
                ImGui::GetFrameCount() > longOperationResultVisibleFrame_ &&
                !ImGui::IsMouseDown(ImGuiMouseButton_Left) &&
                !ImGui::IsMouseReleased(ImGuiMouseButton_Left))
            {
                longOperationCloseClickArmed_ = true;
            }

            bool closeResultRequested = false;
            const bool pushedTitle = PushFontIfAvailable(fonts_.bold);
            ImGui::TextColored(
                active || success ? AccentBlue() : SeverityColor(Core::Severity::High),
                "%s",
                displayTitle.c_str());
            PopFontIfPushed(pushedTitle);
            if (displayTitle != title && ImGui::IsItemHovered())
            {
                RenderWrappedTooltip(title, 520.0f);
            }
            ImGui::Dummy(ImVec2(0.0f, TitleToProgressSpacing));

            ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.035f, 0.049f, 0.070f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImVec4(0.035f, 0.049f, 0.070f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_FrameBgActive, ImVec4(0.035f, 0.049f, 0.070f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_PlotHistogram, AccentBlue());
            ImGui::PushStyleColor(ImGuiCol_PlotHistogramHovered, AccentBlue());
            ImGui::ProgressBar(progress, ImVec2(ImGui::GetContentRegionAvail().x, ProgressHeight));
            ImGui::PopStyleColor(5);

            ImGui::Dummy(ImVec2(0.0f, ProgressToStatusSpacing));
            const float statusStartY = ImGui::GetCursorPosY();
            if (active)
            {
                constexpr float radius = 7.0f;
                const ImVec2 cursor = ImGui::GetCursorScreenPos();
                const ImVec2 center(cursor.x + radius + 1.0f, cursor.y + radius + 2.0f);
                ImDrawList* drawList = ImGui::GetWindowDrawList();
                const float time = static_cast<float>(ImGui::GetTime());
                constexpr int segments = 18;
                for (int index = 0; index < segments; ++index)
                {
                    const float alpha = static_cast<float>(index + 1) / static_cast<float>(segments);
                    const float angle =
                        time * 7.5f +
                        (static_cast<float>(index) / static_cast<float>(segments)) * 6.2831853f;
                    const ImVec2 point(
                        center.x + std::cos(angle) * radius,
                        center.y + std::sin(angle) * radius);
                    const ImVec4 accent = AccentBlue();
                    drawList->AddCircleFilled(
                        point,
                        1.8f,
                        ImGui::ColorConvertFloat4ToU32(
                            ImVec4(accent.x, accent.y, accent.z, alpha * 0.92f)));
                }
                ImGui::Dummy(ImVec2(radius * 2.0f + 8.0f, radius * 2.0f + 6.0f));
                ImGui::SameLine();
                WrappedTextDisabled(displayStatus);
            }
            else
            {
                const ImVec4 resultColor = success
                    ? ImVec4(AccentBlue().x, AccentBlue().y, AccentBlue().z, 0.96f)
                    : SeverityColor(Core::Severity::High);
                WrappedTextColored(resultColor, displayStatus);
            }
            if (displayStatus != rawStatus && !status.empty() && ImGui::IsItemHovered())
            {
                RenderWrappedTooltip(status, 520.0f);
            }

            const float statusTargetY = statusStartY + statusAreaHeight;
            if (ImGui::GetCursorPosY() < statusTargetY)
            {
                ImGui::Dummy(ImVec2(0.0f, statusTargetY - ImGui::GetCursorPosY()));
            }

            if (showFooter)
            {
                ImGui::Dummy(ImVec2(0.0f, StatusToFooterSpacing));
                constexpr float buttonWidth = 92.0f;
                const float contentMinX = ImGui::GetCursorStartPos().x;
                const float contentWidthNow = ImGui::GetContentRegionAvail().x;
                ImGui::SetCursorPosX(contentMinX + std::max(0.0f, (contentWidthNow - buttonWidth) * 0.5f));
                if (ImGui::Button("Close##LongOperation", ImVec2(buttonWidth, 0.0f)))
                {
                    closeResultRequested = true;
                }
                ImGui::Dummy(ImVec2(0.0f, FooterBottomPadding));
            }

            if (showFooter)
            {
                constexpr const char* hint = "Click anywhere to close";
                const ImVec2 hintSize = ImGui::CalcTextSize(hint);
                const ImVec2 hintPosition(
                    overlayViewport->WorkPos.x + (overlayViewport->WorkSize.x - hintSize.x) * 0.5f,
                    overlayViewport->WorkPos.y + overlayViewport->WorkSize.y - hintSize.y - 28.0f);
                const ImVec4 muted = MutedText();
                ImGui::GetForegroundDrawList()->AddText(
                    hintPosition,
                    ImGui::ColorConvertFloat4ToU32(muted),
                    hint);
            }

            if (!closeResultRequested &&
                showFooter &&
                longOperationCloseClickArmed_)
            {
                const ImGuiIO& io = ImGui::GetIO();
                const bool clickStartedInsideOverlay = pointInsideOverlay(io.MouseClickedPos[ImGuiMouseButton_Left]);
                const bool clickReleasedInsideOverlay =
                    ImGui::IsMouseReleased(ImGuiMouseButton_Left) &&
                    pointInsideOverlay(io.MousePos);
                const bool clickStartedInsidePopup = pointInsidePopup(io.MouseClickedPos[ImGuiMouseButton_Left]);
                const bool clickReleasedInsidePopup = pointInsidePopup(io.MousePos);
                if (clickStartedInsideOverlay &&
                    clickReleasedInsideOverlay &&
                    !clickStartedInsidePopup &&
                    !clickReleasedInsidePopup)
                {
                    closeResultRequested = true;
                }
            }

            if (closeResultRequested)
            {
                longOperationResultVisible_ = false;
                longOperationResultVisibleFrame_ = -1;
                longOperationCloseClickArmed_ = false;
                ImGui::CloseCurrentPopup();
            }

            ImGui::EndPopup();
        }

        static std::uint64_t ElapsedMs(ULONGLONG started)
        {
            return static_cast<std::uint64_t>(GetTickCount64() - started);
        }

        static std::uint64_t ProcessCacheStamp(const Core::ProcessInfo& process)
        {
            return process.hasCreationTime ? process.creationTimeFileTime : 0;
        }

        #include "EvidenceCacheActions.cpp"













        void RefreshNetwork(bool logActivity = true)
        {
            if (loadedSnapshotActive_)
            {
                if (logActivity)
                {
                    AddLog(LogLevel::Warning, "Network refresh is unavailable while viewing a saved snapshot. Return to live view first.");
                }
                return;
            }

            const ULONGLONG started = GetTickCount64();
            networkSnapshot_ = Core::CollectNetworkConnectionSnapshot();
            timings_.networkMs = ElapsedMs(started);
            networkLoaded_ = true;
            networkTableNeedsAutoSize_ = true;
            lastNetworkRefreshTime_ = LocalTimestamp();

            for (Core::NetworkConnection& connection : networkSnapshot_.connections)
            {
                const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, connection.owningPid);
                if (process != nullptr)
                {
                    connection.processName = process->name;
                }
            }
            RefreshNetworkIntelMatches(logActivity);
            InvalidateFindingsCache();

            if (logActivity)
            {
                AddLog(
                    networkSnapshot_.success ? LogLevel::Info : LogLevel::Warning,
                    "Network owner table refreshed: " +
                        std::to_string(networkSnapshot_.connections.size()) +
                        " sockets cached in " + std::to_string(timings_.networkMs) + " ms.");
            }
        }

        std::filesystem::path ExecutableDirectory() const
        {
            wchar_t modulePath[MAX_PATH] = {};
            const DWORD length = GetModuleFileNameW(nullptr, modulePath, MAX_PATH);
            if (length == 0 || length >= MAX_PATH)
            {
                return std::filesystem::current_path();
            }
            return std::filesystem::path(modulePath).parent_path();
        }

        std::filesystem::path PortableNetworkIndicatorFeedPath() const
        {
            return PortableNetworkIndicatorDirectory() / L"network-indicators.json";
        }

        std::filesystem::path PortableNetworkIndicatorDirectory() const
        {
            return ExecutableDirectory() / L"Indicators";
        }

        std::filesystem::path DevelopmentNetworkIndicatorFeedPath() const
        {
            return std::filesystem::current_path() / L"Indicators" / L"network-indicators.json";
        }

        bool FileExists(const std::filesystem::path& path) const
        {
            std::error_code error;
            return std::filesystem::is_regular_file(path, error);
        }

        void LoadNetworkIntelFeed()
        {
            if (IsLongOperationActive())
            {
                AddLog(LogLevel::Warning, "Intel feed load ignored because another operation is running.");
                return;
            }

            const std::filesystem::path portablePath = PortableNetworkIndicatorFeedPath();
            std::filesystem::path loadPath = portablePath;
            bool usedFallback = false;

            if (!FileExists(loadPath))
            {
                const std::filesystem::path fallbackPath = DevelopmentNetworkIndicatorFeedPath();
                if (fallbackPath != portablePath && FileExists(fallbackPath))
                {
                    loadPath = fallbackPath;
                    usedFallback = true;
                }
            }

            AddLog(LogLevel::Info, "Intel feed load started.");
            const std::wstring loadPathText = loadPath.wstring();

            StartLongOperation(
                LongRunningOperationKind::LoadIntelFeed,
                "Reading local indicator feed...",
                [loadPathText, usedFallback](std::function<void(const std::string&, float)> progress) mutable {
                    LongOperationResult result;
                    const ULONGLONG started = GetTickCount64();
                    result.networkUsedFallback = usedFallback;
                    progress("Parsing local feed JSON...", 0.45f);
                    result.networkLoadResult =
                        Core::LoadNetworkIndicatorFeedFromFile(loadPathText);
                    result.success = result.networkLoadResult.success;
                    result.elapsedMs = ElapsedMs(started);

                    if (usedFallback)
                    {
                        result.logs.push_back({
                            LogLevel::Warning,
                            "Intel feed portable path missing; using development fallback: " +
                                WideToUtf8(loadPathText)
                        });
                    }

                    if (result.networkLoadResult.success)
                    {
                        result.status =
                            std::string("Intel feed loaded ") +
                            (usedFallback ? "from development fallback: " : "from portable Indicators folder: ") +
                            std::to_string(result.networkLoadResult.feed.indicators.size()) +
                            " indicator(s).";
                        result.logs.push_back({
                            LogLevel::Info,
                            result.status + " (" + std::to_string(result.elapsedMs) + " ms)."
                        });
                    }
                    else if (result.networkLoadResult.missing)
                    {
                        result.status =
                            "Intel feed missing: Indicators/network-indicators.json next to GlassPane.exe.";
                        result.logs.push_back({ LogLevel::Warning, result.status });
                    }
                    else
                    {
                        result.status =
                            "Intel feed error: " +
                            WideToUtf8(result.networkLoadResult.statusMessage);
                        result.logs.push_back({ LogLevel::Warning, result.status });
                    }

                    progress("Finalizing...", 0.95f);
                    return result;
                });
        }

        void UpdateNetworkIntelFeed()
        {
            if (networkIndicatorUpdateInProgress_ || IsLongOperationActive())
            {
                AddLog(LogLevel::Warning, "Network intelligence update ignored because another operation is running.");
                return;
            }

            networkIndicatorUpdateInProgress_ = true;
            networkIndicatorUpdateAttempted_ = true;
            networkIndicatorUpdateResult_ = {};
            AddLog(LogLevel::Info, "Network intelligence feed update started.");

            const std::wstring indicatorsDirectory = PortableNetworkIndicatorDirectory().wstring();
            if (!StartLongOperation(
                    LongRunningOperationKind::UpdateIntelFeed,
                    "Connecting to GitHub...",
                    [indicatorsDirectory](std::function<void(const std::string&, float)> progress) mutable {
                        LongOperationResult result;
                        const ULONGLONG started = GetTickCount64();
                        result.networkUpdateResult =
                            Core::UpdateNetworkIndicatorFeed(
                                indicatorsDirectory,
                                [&progress](const std::wstring& status, float value) {
                                    progress(WideToUtf8(status), value);
                                });
                        result.success = result.networkUpdateResult.success;
                        result.elapsedMs = ElapsedMs(started);

                        if (result.networkUpdateResult.jsonDownloaded)
                        {
                            result.logs.push_back({
                                LogLevel::Info,
                                "Network intelligence JSON downloaded: " +
                                    std::to_string(result.networkUpdateResult.downloadedJsonBytes) +
                                    " bytes."
                            });
                        }
                        if (result.networkUpdateResult.shaDownloaded)
                        {
                            result.logs.push_back({
                                LogLevel::Info,
                                "Network intelligence checksum downloaded: " +
                                    std::to_string(result.networkUpdateResult.downloadedShaBytes) +
                                    " bytes."
                            });
                        }
                        if (result.networkUpdateResult.checksumParsed)
                        {
                            result.logs.push_back({ LogLevel::Info, "Network intelligence checksum parsed." });
                        }
                        if (result.networkUpdateResult.shaVerified)
                        {
                            result.logs.push_back({ LogLevel::Info, "Network intelligence SHA256 verification passed." });
                        }
                        if (result.networkUpdateResult.jsonValidated)
                        {
                            result.logs.push_back({ LogLevel::Info, "Network intelligence feed JSON validation passed." });
                        }

                        if (!result.networkUpdateResult.success)
                        {
                            result.status = WideToUtf8(
                                result.networkUpdateResult.statusMessage.empty()
                                    ? std::wstring(L"Update failed: network intelligence feed update failed")
                                    : result.networkUpdateResult.statusMessage);
                            result.logs.push_back({ LogLevel::Warning, result.status });
                            if (!result.networkUpdateResult.detail.empty())
                            {
                                result.logs.push_back({
                                    LogLevel::Warning,
                                    WideToUtf8(result.networkUpdateResult.detail)
                                });
                            }
                        }
                        else
                        {
                            result.status =
                                WideToUtf8(result.networkUpdateResult.statusMessage.empty()
                                    ? std::wstring(L"Network Intelligence updated and verified.")
                                    : result.networkUpdateResult.statusMessage);
                            result.logs.push_back({
                                LogLevel::Info,
                                result.status + " (" + std::to_string(result.elapsedMs) + " ms)."
                            });
                            if (result.networkUpdateResult.cleanupWarning)
                            {
                                result.logs.push_back({
                                    LogLevel::Warning,
                                    "Intel feed update completed, but temporary cleanup was incomplete."
                                });
                            }
                        }
                        progress("Finalizing...", 0.98f);
                        return result;
                    }))
            {
                networkIndicatorUpdateInProgress_ = false;
            }
        }

        void RequestNetworkIntelFeedUpdate()
        {
            if (networkIndicatorUpdateInProgress_ || IsLongOperationActive())
            {
                AddLog(LogLevel::Warning, "Network intelligence update ignored because another operation is running.");
                return;
            }

            if (networkIntelUpdateConfirmationSuppressed_)
            {
                ConfirmNetworkIntelFeedUpdate();
                return;
            }

            networkIntelUpdateDoNotShowAgainChoice_ = false;
            networkIntelUpdatePopupRequested_ = true;
            AddLog(LogLevel::Info, "Network intelligence feed update confirmation opened.");
        }

        void ConfirmNetworkIntelFeedUpdate()
        {
            if (networkIndicatorUpdateInProgress_ || IsLongOperationActive())
            {
                AddLog(LogLevel::Warning, "Network intelligence update ignored because another operation is running.");
                return;
            }

            if (networkIntelUpdateDoNotShowAgainChoice_)
            {
                networkIntelUpdateConfirmationSuppressed_ = true;
            }
            networkIntelUpdatePopupRequested_ = false;
            AddLog(LogLevel::Info, "Network intelligence feed update confirmed.");
            UpdateNetworkIntelFeed();
        }

        void CancelNetworkIntelFeedUpdate()
        {
            networkIntelUpdatePopupRequested_ = false;
            AddLog(LogLevel::Info, "Network intelligence feed update cancelled.");
        }

        void RefreshNetworkIntelMatches(bool logActivity)
        {
            networkIndicatorMatches_.clear();
            networkIndicatorMatchIndexesByRemote_.clear();
            if (loadedSnapshotActive_)
            {
                networkIndicatorMatches_ = loadedSnapshotNetworkIndicatorMatches_;
                for (std::size_t index = 0; index < networkIndicatorMatches_.size(); ++index)
                {
                    const Core::NetworkIndicatorMatch& match = networkIndicatorMatches_[index];
                    const std::wstring normalizedRemote =
                        Core::NormalizeIpIndicatorValue(match.connection.remoteAddress);
                    if (!normalizedRemote.empty())
                    {
                        networkIndicatorMatchIndexesByRemote_[normalizedRemote].push_back(index);
                    }
                }
                return;
            }
            if (!networkLoaded_ || !networkIndicatorFeed_.loaded)
            {
                return;
            }

            networkIndicatorMatches_ =
                Core::MatchNetworkIndicators(networkSnapshot_.connections, networkIndicatorFeed_);
            for (std::size_t index = 0; index < networkIndicatorMatches_.size(); ++index)
            {
                const Core::NetworkIndicatorMatch& match = networkIndicatorMatches_[index];
                const std::wstring normalizedRemote =
                    Core::NormalizeIpIndicatorValue(match.connection.remoteAddress);
                if (!normalizedRemote.empty())
                {
                    networkIndicatorMatchIndexesByRemote_[normalizedRemote].push_back(index);
                }
            }

            if (logActivity && !networkIndicatorMatches_.empty())
            {
                AddLog(
                    LogLevel::Warning,
                    "Network intelligence matched " +
                        std::to_string(networkIndicatorMatches_.size()) +
                        " endpoint(s) against the loaded indicator feed.");
            }
        }

        std::wstring NetworkIntelStatusText() const
        {
            if (loadedSnapshotActive_)
            {
                if (!loadedSnapshotNetworkIntel_.loaded)
                {
                    return L"Intel feed: not loaded in saved snapshot";
                }
                std::wstring status = loadedSnapshotNetworkIntel_.status.empty()
                    ? std::wstring(L"Intel feed: saved snapshot metadata")
                    : loadedSnapshotNetworkIntel_.status;
                status += L"; offline saved snapshot";
                return status;
            }

            if (networkIndicatorUpdateAttempted_ && !networkIndicatorUpdateResult_.success)
            {
                std::wstring status =
                    networkIndicatorUpdateResult_.statusMessage.empty()
                        ? std::wstring(L"Intel feed update failed")
                        : networkIndicatorUpdateResult_.statusMessage;
                if (networkIndicatorFeed_.loaded)
                {
                    status += L"; existing loaded feed kept";
                }
                return status;
            }

            if (networkIndicatorLoadResult_.success && networkIndicatorFeed_.loaded)
            {
                std::wstring status =
                    networkIndicatorUpdateAttempted_ && networkIndicatorUpdateResult_.success
                        ? std::wstring(L"Intel feed: updated and verified, ")
                        : std::wstring(L"Intel feed: ");
                status += networkIndicatorFeed_.metadata.feedName.empty()
                    ? L"(unnamed feed)"
                    : networkIndicatorFeed_.metadata.feedName;
                status += L", " + std::to_wstring(networkIndicatorFeed_.indicators.size()) + L" indicator";
                status += networkIndicatorFeed_.indicators.size() == 1 ? L"" : L"s";
                status += networkIndicatorUsedFallback_ ? L", loaded from development fallback" : L", loaded from portable Indicators folder";
                if (!networkIndicatorFeed_.metadata.generatedAt.empty())
                {
                    status += L", generated " + networkIndicatorFeed_.metadata.generatedAt;
                }
                return status;
            }

            if (!networkIndicatorLoadAttempted_)
            {
                return L"Intel feed: not loaded";
            }
            if (networkIndicatorLoadResult_.missing)
            {
                return L"Intel feed: missing Indicators/network-indicators.json next to GlassPane.exe";
            }
            return L"Intel feed error: " +
                (networkIndicatorLoadResult_.statusMessage.empty()
                    ? std::wstring(L"malformed feed")
                    : networkIndicatorLoadResult_.statusMessage);
        }

        std::wstring CompactFeedTimestamp(std::wstring value) const
        {
            if (value.empty())
            {
                return value;
            }

            std::replace(value.begin(), value.end(), L'T', L' ');
            if (!value.empty() && value.back() == L'Z')
            {
                value.pop_back();
                value += L" UTC";
            }
            return value;
        }

        std::wstring FormatIndicatorCount(std::size_t count) const
        {
            std::wstring text = std::to_wstring(count);
            for (int insertAt = static_cast<int>(text.size()) - 3;
                insertAt > 0;
                insertAt -= 3)
            {
                text.insert(static_cast<std::size_t>(insertAt), L",");
            }
            return text;
        }

        std::wstring NetworkIntelPrimaryStatusText() const
        {
            if (loadedSnapshotActive_)
            {
                return loadedSnapshotNetworkIntel_.loaded
                    ? std::wstring(L"Intel feed: saved snapshot metadata")
                    : std::wstring(L"Intel feed: not loaded in saved snapshot");
            }

            if (networkIndicatorUpdateInProgress_)
            {
                return L"Intel feed: updating...";
            }
            if (networkIndicatorUpdateAttempted_ && !networkIndicatorUpdateResult_.success)
            {
                return L"Intel feed: update failed";
            }
            if (networkIndicatorLoadResult_.success && networkIndicatorFeed_.loaded)
            {
                return networkIndicatorUpdateAttempted_ && networkIndicatorUpdateResult_.success
                    ? std::wstring(L"Intel feed: updated and verified")
                    : std::wstring(L"Intel feed: loaded");
            }
            if (!networkIndicatorLoadAttempted_)
            {
                return L"Intel feed: not loaded";
            }
            if (networkIndicatorLoadResult_.missing)
            {
                return L"Intel feed: missing";
            }
            return L"Intel feed: error";
        }

        std::wstring NetworkIntelMetadataLine() const
        {
            if (loadedSnapshotActive_)
            {
                if (!loadedSnapshotNetworkIntel_.loaded)
                {
                    return L"Saved snapshot did not include Network Intelligence feed metadata.";
                }

                std::wstring line = loadedSnapshotNetworkIntel_.feedName.empty()
                    ? std::wstring(L"(unnamed feed)")
                    : loadedSnapshotNetworkIntel_.feedName;
                line += L" | " + FormatIndicatorCount(loadedSnapshotNetworkIntel_.indicatorCount) + L" indicator";
                line += loadedSnapshotNetworkIntel_.indicatorCount == 1 ? L"" : L"s";
                if (!loadedSnapshotNetworkIntel_.generatedAt.empty())
                {
                    line += L" | generated " + CompactFeedTimestamp(loadedSnapshotNetworkIntel_.generatedAt);
                }
                return line;
            }

            if (networkIndicatorUpdateAttempted_ && !networkIndicatorUpdateResult_.success)
            {
                const std::wstring reason = !networkIndicatorUpdateResult_.statusMessage.empty()
                    ? networkIndicatorUpdateResult_.statusMessage
                    : std::wstring(L"network intelligence feed update failed");
                return L"Reason: " + reason;
            }

            if (networkIndicatorLoadResult_.success && networkIndicatorFeed_.loaded)
            {
                std::wstring line = networkIndicatorFeed_.metadata.feedName.empty()
                    ? std::wstring(L"(unnamed feed)")
                    : networkIndicatorFeed_.metadata.feedName;
                line += L" | " + FormatIndicatorCount(networkIndicatorFeed_.indicators.size()) + L" indicator";
                line += networkIndicatorFeed_.indicators.size() == 1 ? L"" : L"s";
                if (!networkIndicatorFeed_.metadata.generatedAt.empty())
                {
                    line += L" | generated " + CompactFeedTimestamp(networkIndicatorFeed_.metadata.generatedAt);
                }
                return line;
            }

            if (!networkIndicatorLoadAttempted_)
            {
                return L"Load a local portable feed or update from GitHub after confirmation.";
            }
            if (networkIndicatorLoadResult_.missing)
            {
                return L"Place network-indicators.json next to GlassPane.exe in the Indicators folder.";
            }
            return L"Reason: " +
                (networkIndicatorLoadResult_.statusMessage.empty()
                    ? std::wstring(L"malformed feed")
                    : networkIndicatorLoadResult_.statusMessage);
        }

        std::wstring NetworkIntelSourceLine() const
        {
            if (loadedSnapshotActive_)
            {
                return loadedSnapshotNetworkIntel_.loaded
                    ? std::wstring(L"Source: saved snapshot") +
                        (loadedSnapshotNetworkIntel_.source.empty()
                            ? std::wstring{}
                            : std::wstring(L" (") + loadedSnapshotNetworkIntel_.source + L")")
                    : std::wstring{};
            }

            if (!(networkIndicatorLoadResult_.success && networkIndicatorFeed_.loaded))
            {
                return {};
            }

            if (networkIndicatorUsedFallback_)
            {
                return L"Source: development fallback";
            }

            return networkIndicatorUpdateAttempted_ && networkIndicatorUpdateResult_.success
                ? std::wstring(L"Source: portable Indicators folder (updated and verified)")
                : std::wstring(L"Source: portable Indicators folder");
        }

        std::wstring NetworkIntelDetailsText() const
        {
            std::wstringstream details;
            details << NetworkIntelPrimaryStatusText() << L"\n";

            const std::wstring metadata = NetworkIntelMetadataLine();
            if (!metadata.empty())
            {
                details << metadata << L"\n";
            }
            const std::wstring source = NetworkIntelSourceLine();
            if (!source.empty())
            {
                details << source << L"\n";
            }

            if (loadedSnapshotActive_ && loadedSnapshotNetworkIntel_.loaded)
            {
                details << L"Feed name: " <<
                    (loadedSnapshotNetworkIntel_.feedName.empty() ? L"(unnamed feed)" : loadedSnapshotNetworkIntel_.feedName) << L"\n";
                details << L"Schema version: " << loadedSnapshotNetworkIntel_.schemaVersion << L"\n";
                details << L"Generated: " <<
                    (loadedSnapshotNetworkIntel_.generatedAt.empty()
                        ? std::wstring(L"(unknown)")
                        : CompactFeedTimestamp(loadedSnapshotNetworkIntel_.generatedAt)) << L"\n";
                details << L"Expires: " <<
                    (loadedSnapshotNetworkIntel_.expiresAt.empty()
                        ? std::wstring(L"(unknown)")
                        : CompactFeedTimestamp(loadedSnapshotNetworkIntel_.expiresAt)) << L"\n";
                details << L"Indicators: " << FormatIndicatorCount(loadedSnapshotNetworkIntel_.indicatorCount) << L"\n";
                if (!loadedSnapshotNetworkIntel_.localFeedSha256.empty())
                {
                    details << L"Feed SHA256: " << loadedSnapshotNetworkIntel_.localFeedSha256 << L"\n";
                }
            }
            else if (networkIndicatorFeed_.loaded)
            {
                details << L"Feed name: " <<
                    (networkIndicatorFeed_.metadata.feedName.empty() ? L"(unnamed feed)" : networkIndicatorFeed_.metadata.feedName) << L"\n";
                details << L"Schema version: " << networkIndicatorFeed_.metadata.schemaVersion << L"\n";
                details << L"Generated: " <<
                    (networkIndicatorFeed_.metadata.generatedAt.empty()
                        ? std::wstring(L"(unknown)")
                        : CompactFeedTimestamp(networkIndicatorFeed_.metadata.generatedAt)) << L"\n";
                details << L"Expires: " <<
                    (networkIndicatorFeed_.metadata.expiresAt.empty()
                        ? std::wstring(L"(unknown)")
                        : CompactFeedTimestamp(networkIndicatorFeed_.metadata.expiresAt)) << L"\n";
                details << L"Indicators: " << FormatIndicatorCount(networkIndicatorFeed_.indicators.size()) << L"\n";
            }

            if (networkIndicatorUpdateAttempted_)
            {
                details << L"Last update: " <<
                    (networkIndicatorUpdateResult_.success ? L"verified and loaded" : L"failed") << L"\n";
                if (!networkIndicatorUpdateResult_.detail.empty())
                {
                    details << L"Detail: " << networkIndicatorUpdateResult_.detail << L"\n";
                }
                if (!networkIndicatorUpdateResult_.expectedSha256.empty())
                {
                    details << L"Expected SHA256: " << Utf8ToWide(networkIndicatorUpdateResult_.expectedSha256.c_str()) << L"\n";
                }
                if (!networkIndicatorUpdateResult_.computedSha256.empty())
                {
                    details << L"Computed SHA256: " << Utf8ToWide(networkIndicatorUpdateResult_.computedSha256.c_str()) << L"\n";
                }
            }

            return details.str();
        }

        void RenderNetworkIntelStatus()
        {
            const bool warningState =
                !loadedSnapshotActive_ &&
                ((networkIndicatorUpdateAttempted_ && !networkIndicatorUpdateResult_.success) ||
                    (networkIndicatorLoadAttempted_ && !networkIndicatorLoadResult_.success));
            const ImVec4 statusColor = warningState
                ? ImVec4(0.96f, 0.62f, 0.24f, 1.0f)
                : AccentBlue();

            ImGui::Spacing();
            ImGui::TextColored(statusColor, "%s", WideToUtf8(NetworkIntelPrimaryStatusText()).c_str());
            ImGui::SameLine();
            ImGui::TextDisabled("(Details)");
            if (ImGui::IsItemHovered())
            {
                RenderWrappedTooltip(NetworkIntelDetailsText(), 620.0f);
            }

            const std::wstring metadata = NetworkIntelMetadataLine();
            if (!metadata.empty())
            {
                WrappedTextDisabled(metadata);
            }

            const std::wstring source = NetworkIntelSourceLine();
            if (!source.empty())
            {
                WrappedTextDisabled(source);
            }
        }

        std::vector<const Core::NetworkIndicatorMatch*> NetworkIntelMatchesForConnection(
            const Core::NetworkConnection& connection) const
        {
            std::vector<const Core::NetworkIndicatorMatch*> matches;
            const std::wstring normalizedRemote =
                Core::NormalizeIpIndicatorValue(connection.remoteAddress);
            if (normalizedRemote.empty())
            {
                return matches;
            }

            const auto found = networkIndicatorMatchIndexesByRemote_.find(normalizedRemote);
            if (found == networkIndicatorMatchIndexesByRemote_.end())
            {
                return matches;
            }

            for (std::size_t index : found->second)
            {
                if (index < networkIndicatorMatches_.size() &&
                    networkIndicatorMatches_[index].connection.owningPid == connection.owningPid &&
                    networkIndicatorMatches_[index].connection.remotePort == connection.remotePort &&
                    networkIndicatorMatches_[index].connection.protocol == connection.protocol)
                {
                    matches.push_back(&networkIndicatorMatches_[index]);
                }
            }
            return matches;
        }

        std::vector<Core::NetworkIndicatorMatch> SelectedNetworkIndicatorMatchesForProcess(std::uint32_t pid) const
        {
            std::vector<Core::NetworkIndicatorMatch> matches;
            for (const Core::NetworkIndicatorMatch& match : networkIndicatorMatches_)
            {
                if (match.connection.owningPid == pid)
                {
                    matches.push_back(match);
                }
            }
            return matches;
        }

        Core::Severity NetworkIndicatorSeverityAsCoreSeverity(const std::wstring& severity) const
        {
            const std::wstring lowered = ToLower(severity);
            if (lowered == L"high")
            {
                return Core::Severity::High;
            }
            if (lowered == L"medium")
            {
                return Core::Severity::Medium;
            }
            if (lowered == L"low")
            {
                return Core::Severity::Low;
            }
            return Core::Severity::Info;
        }

        std::wstring NetworkIndicatorMatchLabel(const Core::NetworkIndicatorMatch& match) const
        {
            std::wstring label = match.indicator.severity.empty() ? L"match" : match.indicator.severity;
            if (!match.indicator.category.empty())
            {
                label += L" / " + match.indicator.category;
            }
            return label;
        }

        std::wstring NetworkIndicatorTooltipText(
            const std::vector<const Core::NetworkIndicatorMatch*>& matches) const
        {
            if (matches.empty())
            {
                return {};
            }

            const Core::NetworkIndicatorMatch& match = *matches.front();
            std::wstringstream text;
            text << L"Remote endpoint matched local feed indicator.\n";
            text << L"Indicator: " << (match.indicator.value.empty() ? L"(unknown)" : match.indicator.value) << L"\n";
            text << L"Category: " << (match.indicator.category.empty() ? L"(unspecified)" : match.indicator.category) << L"\n";
            text << L"Severity: " << (match.indicator.severity.empty() ? L"(unspecified)" : match.indicator.severity) << L"\n";
            text << L"Confidence: " << (match.indicator.confidence.empty() ? L"(unspecified)" : match.indicator.confidence) << L"\n";
            text << L"Source: " << (match.indicator.source.empty() ? L"(unspecified)" : match.indicator.source);
            if (!match.indicator.lastSeen.empty())
            {
                text << L"\nLast seen: " << match.indicator.lastSeen;
            }
            if (!match.indicator.description.empty())
            {
                text << L"\nDescription: " << match.indicator.description;
            }
            if (matches.size() > 1)
            {
                text << L"\nAdditional matches for this endpoint: " << (matches.size() - 1);
            }
            return text.str();
        }

        std::vector<const Core::NetworkConnection*> SelectedNetworkConnections() const
        {
            std::vector<const Core::NetworkConnection*> selectedConnections;
            if (!networkLoaded_)
            {
                return selectedConnections;
            }

            for (const Core::NetworkConnection& connection : networkSnapshot_.connections)
            {
                if (connection.owningPid == selectedPid_)
                {
                    selectedConnections.push_back(&connection);
                }
            }
            return selectedConnections;
        }

        std::vector<Core::NetworkConnection> SelectedNetworkConnectionsForExport() const
        {
            std::vector<Core::NetworkConnection> selectedConnections;
            if (!networkLoaded_)
            {
                return selectedConnections;
            }

            for (const Core::NetworkConnection& connection : networkSnapshot_.connections)
            {
                if (connection.owningPid == selectedPid_)
                {
                    selectedConnections.push_back(connection);
                }
            }
            return selectedConnections;
        }

        NetworkSummary GetNetworkSummary(std::uint32_t pid) const
        {
            NetworkSummary summary;
            if (!networkLoaded_)
            {
                return summary;
            }

            for (const Core::NetworkConnection& connection : networkSnapshot_.connections)
            {
                if (connection.owningPid != pid)
                {
                    continue;
                }

                ++summary.connectionCount;
                if (connection.isListening)
                {
                    ++summary.listeningCount;
                }
                if (connection.isPublicRemote)
                {
                    ++summary.publicRemoteCount;
                }
                const std::vector<const Core::NetworkIndicatorMatch*> intelMatches =
                    NetworkIntelMatchesForConnection(connection);
                summary.intelMatchCount += intelMatches.size();
            }
            return summary;
        }

        std::wstring NetworkEndpoint(const Core::NetworkConnection& connection, bool remote) const
        {
            const std::wstring& address = remote ? connection.remoteAddress : connection.localAddress;
            const std::uint16_t port = remote ? connection.remotePort : connection.localPort;
            if (remote && (connection.protocol == L"UDP" || connection.isListening || address.empty() || address == L"0.0.0.0" || port == 0))
            {
                return L"-";
            }
            if (address.empty())
            {
                return L"-";
            }
            return address + L":" + std::to_wstring(port);
        }

        std::wstring NetworkScopeText(const Core::NetworkConnection& connection) const
        {
            if (connection.isListening)
            {
                if (connection.localAddress == L"0.0.0.0")
                {
                    return L"Listening / all interfaces";
                }
                if (connection.isLoopback)
                {
                    return L"Listening / loopback";
                }
                if (connection.isLan)
                {
                    return L"Listening / LAN";
                }
                return L"Listening";
            }
            if (connection.isPublicRemote)
            {
                return L"Public remote";
            }
            if (connection.isLoopback)
            {
                return L"Loopback";
            }
            if (connection.isLan)
            {
                return L"LAN";
            }
            return L"Local/unspecified";
        }

        std::vector<std::wstring> BuildNetworkIndicators(
            const Core::ProcessInfo& process,
            const NetworkSummary& summary) const
        {
            std::vector<std::wstring> indicators;
            if (summary.listeningCount > 0)
            {
                indicators.push_back(L"Network: process has listening socket.");
            }
            if (summary.publicRemoteCount > 0)
            {
                indicators.push_back(L"Network: process has public remote connection.");
            }
            if (process.IsSuspicious() && summary.publicRemoteCount > 0)
            {
                indicators.push_back(L"Network: suspicious process has outbound public connection.");
            }
            if (summary.intelMatchCount > 0)
            {
                indicators.push_back(
                    L"Network intelligence: " +
                    std::to_wstring(summary.intelMatchCount) +
                    L" remote endpoint matched local indicator feed.");
            }
            return indicators;
        }

        std::vector<std::wstring> BuildNetworkContextNotes(
            const Core::ProcessInfo& process,
            const Core::ChainAnalysisResult& chain,
            const NetworkSummary& summary) const
        {
            std::vector<std::wstring> notes;
            const Core::Severity effectiveSeverity =
                Core::SeverityRank(chain.chainSeverity) > Core::SeverityRank(process.severity)
                    ? chain.chainSeverity
                    : process.severity;
            if (summary.publicRemoteCount > 0 &&
                Core::SeverityRank(effectiveSeverity) >= Core::SeverityRank(Core::Severity::Medium))
            {
                notes.push_back(L"Network context: elevated process or chain severity with public outbound connection. No severity escalation applied.");
            }
            return notes;
        }

        static bool IsSyntheticSystemProcessEntry(const Core::ProcessInfo& process)
        {
            return process.pid == 0 && process.executablePath.empty();
        }

        static const Core::FileIdentity& SyntheticSystemProcessFileIdentity()
        {
            static const Core::FileIdentity identity = [] {
                Core::FileIdentity result;
                result.path.clear();
                return result;
            }();
            return identity;
        }

        const Core::FileIdentity& CachedFileIdentity(const std::wstring& path)
        {
            const std::wstring key = ToLower(path);
            auto existing = fileIdentityCache_.find(key);
            if (existing != fileIdentityCache_.end())
            {
                return existing->second;
            }

            const ULONGLONG started = GetTickCount64();
            Core::FileIdentity identity = Core::CollectFileIdentity(path);
            timings_.fileIdentityMs = ElapsedMs(started);
            auto inserted = fileIdentityCache_.emplace(key, std::move(identity));
            const Core::FileIdentity& cached = inserted.first->second;
            if (!cached.errorMessage.empty())
            {
                AddLog(
                    LogLevel::Warning,
                    "File identity note for " + Shorten(WideToUtf8(path.empty() ? L"(empty path)" : path), 96) +
                        ": " + WideToUtf8(cached.errorMessage) +
                        " (" + std::to_string(timings_.fileIdentityMs) + " ms).");
            }
            return cached;
        }

        const Core::FileIdentity& CachedFileIdentity(const Core::ProcessInfo& process)
        {
            if (IsSyntheticSystemProcessEntry(process))
            {
                return SyntheticSystemProcessFileIdentity();
            }

            return CachedFileIdentity(process.executablePath);
        }

        std::vector<Core::FileIdentityIndicator> BuildProcessFileIdentityIndicators(
            const Core::ProcessInfo& process,
            const Core::FileIdentity& fileIdentity) const
        {
            if (IsSyntheticSystemProcessEntry(process))
            {
                return {};
            }

            return Core::BuildFileIdentityIndicators(fileIdentity, process.name, true);
        }

        void RenderFileIdentityFields(
            const char* id,
            const Core::FileIdentity& identity,
            const std::vector<Core::FileIdentityIndicator>& indicators,
            const char* logSubject)
        {
            ImGui::PushID(id);
            LabelValue("Exists", identity.exists ? "Yes" : "No");
            LabelValue("File Size", identity.exists ? FileSizeText(identity.fileSize) : L"(unavailable)");
            LabelValue("Signature", SignatureStatusText(identity));

            ImGui::TextDisabled("SHA-256");
            if (!identity.sha256.empty())
            {
                ImGui::SameLine();
                if (ImGui::SmallButton("Copy Hash"))
                {
                    CopyTextToClipboard(identity.sha256);
                    AddLog(LogLevel::Info, std::string("Copied ") + logSubject + " SHA-256 to clipboard.");
                }
            }
            const bool pushedHashFont = PushFontIfAvailable(fonts_.monospace);
            WrappedTextWide(identity.sha256.empty() ? L"(unavailable)" : identity.sha256);
            PopFontIfPushed(pushedHashFont);

            ImGui::TextDisabled("Signer");
            ImGui::SameLine(145.0f);
            WrappedTextWide(identity.signerName.empty() ? L"(none)" : identity.signerName);

            LabelValue("Company", identity.companyName.empty() ? L"(none)" : identity.companyName);
            LabelValue("Product", identity.productName.empty() ? L"(none)" : identity.productName);
            LabelValue("Description", identity.fileDescription.empty() ? L"(none)" : identity.fileDescription);
            LabelValue("Original Name", identity.originalFilename.empty() ? L"(none)" : identity.originalFilename);
            LabelValue("Version", identity.versionString.empty() ? L"(none)" : identity.versionString);

            if (!identity.errorMessage.empty())
            {
                ImGui::TextDisabled("Identity Notes");
                WrappedTextDisabled(identity.errorMessage);
            }

            if (!indicators.empty())
            {
                ImGui::SeparatorText("Identity Indicators");
                for (const Core::FileIdentityIndicator& indicator : indicators)
                {
                    ImGui::Bullet();
                    ImGui::SameLine();
                    SeverityText(indicator.severity);
                    ImGui::SameLine();
                    WrappedTextWide(indicator.message);
                }
            }
            ImGui::PopID();
        }

        std::vector<Core::Finding> BuildFindingsForSelectedProcess(
            const Core::ProcessInfo& process,
            const Core::ChainAnalysisResult& chain,
            const Core::FileIdentity& fileIdentity) const
        {
            const std::vector<Core::NetworkConnection> selectedNetworkConnections = SelectedNetworkConnectionsForExport();
            const std::vector<Core::NetworkIndicatorMatch> selectedNetworkIndicatorMatches =
                SelectedNetworkIndicatorMatchesForProcess(process.pid);
            const Core::ModuleCollectionResult* modules =
                ModulesLoadedForProcess(process)
                    ? &selectedModules_
                    : nullptr;
            const Core::TokenInfo* token =
                TokenLoadedForProcess(process)
                    ? &selectedToken_
                    : nullptr;
            const Core::RuntimeInfo* runtime =
                RuntimeLoadedForProcess(process)
                    ? &selectedRuntime_
                    : nullptr;
            const Core::MemoryCollectionResult* memory =
                MemoryLoadedForProcess(process)
                    ? &selectedMemory_
                    : nullptr;
            const Core::HandleCollectionResult* handles =
                HandlesLoadedForProcess(process)
                    ? &selectedHandles_
                    : nullptr;

            Core::CorrelationContext context;
            context.process = &process;
            context.chain = &chain;
            context.modules = modules;
            context.networkConnections = &selectedNetworkConnections;
            context.networkIndicatorMatches = &selectedNetworkIndicatorMatches;
            context.fileIdentity = IsSyntheticSystemProcessEntry(process) ? nullptr : &fileIdentity;
            context.token = token;
            context.runtime = runtime;
            context.memory = memory;
            context.handles = handles;
            return Core::CorrelateFindings(context);
        }

        void InvalidateFindingsCache()
        {
            findingsCacheValid_ = false;
            findingsCachePid_ = InvalidPid;
            findingsCacheCreationTime_ = 0;
            selectedFindingsCache_.clear();
            selectedHighTriageCacheValid_ = false;
            selectedHighTriagePid_ = InvalidPid;
            selectedHighTriageCreationTime_ = 0;
            selectedHighTriage_ = false;
        }

        void InvalidateChainCache()
        {
            selectedChainCacheValid_ = false;
            selectedChainCachePid_ = InvalidPid;
            selectedChainCacheCreationTime_ = 0;
            selectedChainCacheSnapshotGeneration_ = 0;
            selectedChainCache_ = {};
        }

        void MarkAllTablesNeedAutoSize()
        {
            processTableNeedsAutoSize_ = true;
            timelineTableNeedsAutoSize_ = true;
            modulesTableNeedsAutoSize_ = true;
            networkTableNeedsAutoSize_ = true;
            tokenTableNeedsAutoSize_ = true;
            runtimeTableNeedsAutoSize_ = true;
            memoryTableNeedsAutoSize_ = true;
            handlesTableNeedsAutoSize_ = true;
        }

        void MarkProcessRowsDirty()
        {
            visibleProcessRowsDirty_ = true;
            timelineRowsDirty_ = true;
            processTableNeedsAutoSize_ = true;
            timelineTableNeedsAutoSize_ = true;
        }

        void MarkSnapshotDependentCachesDirty()
        {
            ++snapshotGeneration_;
            visibleProcessRowsDirty_ = true;
            timelineRowsDirty_ = true;
            graphLayoutDirty_ = true;
            InvalidateChainCache();
        }

        bool SetProcessSearchText(std::wstring loweredSearchText)
        {
            if (searchText_ == loweredSearchText)
            {
                return false;
            }

            searchText_ = std::move(loweredSearchText);
            ++processQueryRevision_;
            MarkProcessRowsDirty();
            return true;
        }

        bool SetProcessFilterMode(ProcessFilterMode mode)
        {
            if (processFilterMode_ == mode)
            {
                return false;
            }

            processFilterMode_ = mode;
            ++processQueryRevision_;
            MarkProcessRowsDirty();
            return true;
        }

        bool SetTimelineFilter(Core::TimelineFilter filter)
        {
            if (timelineFilter_ == filter)
            {
                return false;
            }

            timelineFilter_ = filter;
            timelineRowsDirty_ = true;
            timelineTableNeedsAutoSize_ = true;
            return true;
        }


        const std::vector<Core::Finding>& FindingsForSelectedProcess(
            const Core::ProcessInfo& process,
            const Core::ChainAnalysisResult& chain,
            const Core::FileIdentity& fileIdentity)
        {
            if (findingsCacheValid_ &&
                CacheMatchesProcess(findingsCachePid_, findingsCacheCreationTime_, process))
            {
                return selectedFindingsCache_;
            }

            const ULONGLONG started = GetTickCount64();
            selectedFindingsCache_ = BuildFindingsForSelectedProcess(process, chain, fileIdentity);
            timings_.findingsMs = ElapsedMs(started);
            findingsCachePid_ = process.pid;
            findingsCacheCreationTime_ = ProcessCacheStamp(process);
            findingsCacheValid_ = true;

            if (!IsSyntheticSystemProcessEntry(process))
            {
                const std::string logMessage =
                    "Triage findings recomputed for PID " + std::to_string(process.pid) +
                    ": " + std::to_string(selectedFindingsCache_.size()) +
                    " finding(s) in " + std::to_string(timings_.findingsMs) + " ms.";
                const ULONGLONG now = GetTickCount64();
                constexpr ULONGLONG DuplicateTriageLogWindowMs = 100;
                const bool duplicateFromSameAction =
                    logMessage == lastTriageRecomputeLogMessage_ &&
                    now >= lastTriageRecomputeLogTick_ &&
                    now - lastTriageRecomputeLogTick_ <= DuplicateTriageLogWindowMs;
                if (!duplicateFromSameAction)
                {
                    AddLog(LogLevel::Info, logMessage);
                }
                lastTriageRecomputeLogMessage_ = logMessage;
                lastTriageRecomputeLogTick_ = now;
            }
            return selectedFindingsCache_;
        }

        const Core::ChainAnalysisResult& CachedChainAnalysis(const Core::ProcessInfo& process)
        {
            const std::uint64_t creationTime = ProcessCacheStamp(process);
            if (selectedChainCacheValid_ &&
                selectedChainCachePid_ == process.pid &&
                selectedChainCacheCreationTime_ == creationTime &&
                selectedChainCacheSnapshotGeneration_ == snapshotGeneration_)
            {
                return selectedChainCache_;
            }

            selectedChainCache_ = Core::AnalyzeChain(snapshot_, process.pid);
            selectedChainCachePid_ = process.pid;
            selectedChainCacheCreationTime_ = creationTime;
            selectedChainCacheSnapshotGeneration_ = snapshotGeneration_;
            selectedChainCacheValid_ = true;
            return selectedChainCache_;
        }

        bool SelectedProcessHasHighTriageFinding()
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                return false;
            }

            if (selectedHighTriageCacheValid_ &&
                CacheMatchesProcess(selectedHighTriagePid_, selectedHighTriageCreationTime_, *process))
            {
                return selectedHighTriage_;
            }

            const Core::ChainAnalysisResult& chain = CachedChainAnalysis(*process);
            const Core::FileIdentity& fileIdentity = CachedFileIdentity(*process);
            const std::vector<Core::Finding>& findings =
                FindingsForSelectedProcess(*process, chain, fileIdentity);
            selectedHighTriage_ = !findings.empty() &&
                Core::HighestFindingSeverity(findings) == Core::FindingSeverity::High;
            selectedHighTriagePid_ = process->pid;
            selectedHighTriageCreationTime_ = ProcessCacheStamp(*process);
            selectedHighTriageCacheValid_ = true;
            return selectedHighTriage_;
        }

        std::size_t CountSuspiciousProcesses() const
        {
            return static_cast<std::size_t>(std::count_if(
                snapshot_.processes.begin(),
                snapshot_.processes.end(),
                [](const Core::ProcessInfo& process) {
                    return Core::SeverityRank(process.severity) >= Core::SeverityRank(Core::Severity::Low);
                }));
        }

        std::size_t CountVisibleProcesses() const
        {
            return visibleProcessRows_.size();
        }

        void RebuildVisibleProcessRowsIfNeeded()
        {
            if (!visibleProcessRowsDirty_ &&
                visibleProcessRowsSnapshotGeneration_ == snapshotGeneration_ &&
                visibleProcessRowsQueryRevision_ == processQueryRevision_)
            {
                return;
            }

            const ULONGLONG started = GetTickCount64();
            const std::vector<Core::TreeRow> rows = Core::BuildTreeRows(snapshot_);
            visibleProcessRows_.clear();
            visibleProcessRows_.reserve(rows.size());
            for (const Core::TreeRow& row : rows)
            {
                if (row.processIndex >= snapshot_.processes.size())
                {
                    continue;
                }

                const Core::ProcessInfo& process = snapshot_.processes[row.processIndex];
                if (ProcessMatchesFilters(process))
                {
                    visibleProcessRows_.push_back({ row.processIndex, row.depth, process.severity });
                }
            }

            timings_.processFilterMs = ElapsedMs(started);
            visibleProcessRowsSnapshotGeneration_ = snapshotGeneration_;
            visibleProcessRowsQueryRevision_ = processQueryRevision_;
            visibleProcessRowsDirty_ = false;
        }

        const std::vector<Core::TimelineRow>& TimelineRowsForCurrentFilters()
        {
            if (!timelineRowsDirty_ &&
                timelineRowsSnapshotGeneration_ == snapshotGeneration_ &&
                timelineRowsQueryRevision_ == processQueryRevision_ &&
                timelineRowsFilter_ == timelineFilter_)
            {
                return cachedTimelineRows_;
            }

            cachedTimelineRows_.clear();
            const std::vector<Core::TimelineRow> rows = Core::BuildTimelineRows(snapshot_, timelineFilter_);
            cachedTimelineRows_.reserve(rows.size());
            for (const Core::TimelineRow& row : rows)
            {
                const Core::ProcessInfo* timelineProcess = Core::FindProcessByPid(snapshot_, row.pid);
                if (timelineProcess != nullptr && ProcessMatchesFilters(*timelineProcess))
                {
                    cachedTimelineRows_.push_back(row);
                }
            }

            timelineRowsSnapshotGeneration_ = snapshotGeneration_;
            timelineRowsQueryRevision_ = processQueryRevision_;
            timelineRowsFilter_ = timelineFilter_;
            timelineRowsDirty_ = false;
            return cachedTimelineRows_;
        }

        void RebuildVisibleHandlesIfNeeded(const Core::ProcessInfo& process)
        {
            const std::uint64_t creationTime = ProcessCacheStamp(process);
            if (!visibleHandlesDirty_ &&
                visibleHandlesPid_ == process.pid &&
                visibleHandlesCreationTime_ == creationTime &&
                visibleHandlesSourceSize_ == selectedHandles_.handles.size() &&
                visibleHandlesFilter_ == handleFilter_ &&
                visibleHandlesSearchText_ == handleSearchText_)
            {
                return;
            }

            visibleHandleIndexes_.clear();
            visibleHandleIndexes_.reserve(selectedHandles_.handles.size());
            visibleHandlesWithIndicatorsCount_ = 0;
            visibleHandlesNameStatusCount_ = 0;
            for (std::size_t index = 0; index < selectedHandles_.handles.size(); ++index)
            {
                const Core::HandleInfo& handle = selectedHandles_.handles[index];
                if (!handle.indicators.empty())
                {
                    ++visibleHandlesWithIndicatorsCount_;
                }
                if (!HandleStatusText(handle).empty())
                {
                    ++visibleHandlesNameStatusCount_;
                }
                if (HandleMatchesFilter(handle, handleFilter_) &&
                    HandleMatchesSearch(handle, handleSearchText_))
                {
                    visibleHandleIndexes_.push_back(index);
                }
            }

            visibleHandlesPid_ = process.pid;
            visibleHandlesCreationTime_ = creationTime;
            visibleHandlesSourceSize_ = selectedHandles_.handles.size();
            visibleHandlesFilter_ = handleFilter_;
            visibleHandlesSearchText_ = handleSearchText_;
            visibleHandlesDirty_ = false;
        }

        void RebuildVisibleMemoryRegionsIfNeeded(const Core::ProcessInfo& process)
        {
            const std::uint64_t creationTime = ProcessCacheStamp(process);
            if (!visibleMemoryRegionsDirty_ &&
                visibleMemoryPid_ == process.pid &&
                visibleMemoryCreationTime_ == creationTime &&
                visibleMemorySourceSize_ == selectedMemory_.regions.size() &&
                visibleMemoryFilter_ == memoryFilter_ &&
                visibleMemorySearchText_ == memorySearchText_)
            {
                return;
            }

            visibleMemoryRegionIndexes_.clear();
            visibleMemoryRegionIndexes_.reserve(selectedMemory_.regions.size());
            for (std::size_t index = 0; index < selectedMemory_.regions.size(); ++index)
            {
                const Core::MemoryRegionInfo& region = selectedMemory_.regions[index];
                if (MemoryMatchesFilter(region, memoryFilter_) &&
                    MemoryMatchesSearch(region, memorySearchText_))
                {
                    visibleMemoryRegionIndexes_.push_back(index);
                }
            }

            visibleMemoryPid_ = process.pid;
            visibleMemoryCreationTime_ = creationTime;
            visibleMemorySourceSize_ = selectedMemory_.regions.size();
            visibleMemoryFilter_ = memoryFilter_;
            visibleMemorySearchText_ = memorySearchText_;
            visibleMemoryRegionsDirty_ = false;
        }

        void LogServiceSnapshotRefresh()
        {
            const std::string status = WideToUtf8(serviceSnapshot_.statusMessage);
            const bool partialEnumeration =
                !serviceSnapshot_.success &&
                serviceSnapshot_.partial &&
                !serviceSnapshot_.services.empty();
            if (!serviceSnapshot_.success && !partialEnumeration)
            {
                std::string message =
                    "Service context could not be collected in " +
                    std::to_string(timings_.servicesMs) + " ms";
                if (!status.empty())
                {
                    message += ": " + status;
                }
                else
                {
                    message += ".";
                }
                AddLog(LogLevel::Warning, message);
                return;
            }

            std::size_t correlationCount = 0;
            for (const auto& entry : serviceSnapshot_.serviceIndexesByPid)
            {
                correlationCount += entry.second.size();
            }

            const std::size_t retainedCount = serviceSnapshot_.services.size();
            const std::size_t totalCount = (std::max)(
                retainedCount,
                serviceSnapshot_.totalEnumerated);
            const std::size_t omittedCount = totalCount - retainedCount;
            const bool partial =
                partialEnumeration ||
                serviceSnapshot_.partial ||
                serviceSnapshot_.truncated;
            std::string message = partialEnumeration
                ? "Service snapshot collection stopped with partial results: "
                : (partial
                    ? "Service snapshot loaded with partial metadata: "
                    : "Service snapshot loaded: ");

            if (omittedCount != 0)
            {
                message +=
                    std::to_string(retainedCount) + " of " +
                    std::to_string(totalCount) +
                    " active Win32 service record(s) visible to the current security context retained";
            }
            else
            {
                message +=
                    std::to_string(retainedCount) +
                    " active Win32 service record(s) visible to the current security context";
            }
            message +=
                ", " + std::to_string(correlationCount) +
                " SCM-reported service-to-PID correlation(s)";

            if (serviceSnapshot_.configurationUnavailableCount != 0)
            {
                message +=
                    ", " +
                    std::to_string(serviceSnapshot_.configurationUnavailableCount) +
                    " configuration record(s) unavailable";
            }
            if (serviceSnapshot_.descriptionUnavailableCount != 0)
            {
                message +=
                    ", " +
                    std::to_string(serviceSnapshot_.descriptionUnavailableCount) +
                    " description record(s) unavailable";
            }
            if (omittedCount != 0)
            {
                message +=
                    ", " + std::to_string(omittedCount) +
                    " record(s) omitted by the service cap";
            }
            else if (partial && !partialEnumeration &&
                serviceSnapshot_.configurationUnavailableCount == 0 &&
                serviceSnapshot_.descriptionUnavailableCount == 0)
            {
                message += ", one or more metadata fields bounded to collection limits";
            }

            message += " in " + std::to_string(timings_.servicesMs) + " ms.";
            if (partialEnumeration && !status.empty())
            {
                message += " " + status;
            }
            AddLog(partial ? LogLevel::Warning : LogLevel::Info, message);
        }

        void RefreshSnapshot(bool refreshSelectedEvidence = false)
        {
            if (loadedSnapshotActive_)
            {
                ReturnToLiveView(true);
                return;
            }

            AddLog(LogLevel::Info, "Refreshing process snapshot.");
            const std::uint32_t previousSelectedPid = selectedPid_;
            const Core::ProcessInfo* previousSelectedProcess = Core::FindProcessByPid(snapshot_, previousSelectedPid);
            const std::uint64_t previousSelectedCreationTime =
                previousSelectedProcess != nullptr ? ProcessCacheStamp(*previousSelectedProcess) : 0;
            fileIdentityCache_.clear();
            InvalidateFindingsCache();
            MarkAllTablesNeedAutoSize();
            const ULONGLONG started = GetTickCount64();
            snapshot_ = Core::CollectProcessSnapshot();
            timings_.processSnapshotMs = ElapsedMs(started);
            const ULONGLONG servicesStarted = GetTickCount64();
            serviceSnapshot_ = Core::CollectServiceSnapshot();
            timings_.servicesMs = ElapsedMs(servicesStarted);
            LogServiceSnapshotRefresh();
            MarkSnapshotDependentCachesDirty();
            ClearSelectedProcessEvidence();
            lastRefreshTime_ = LocalTimestamp();
            suspiciousCount_ = CountSuspiciousProcesses();
            RefreshNetwork(false);

            if (snapshot_.processes.empty())
            {
                selectedPid_ = InvalidPid;
            }
            else if (previousSelectedPid != InvalidPid &&
                Core::FindProcessByPid(snapshot_, previousSelectedPid) != nullptr)
            {
                selectedPid_ = previousSelectedPid;
                const Core::ProcessInfo* refreshedSelectedProcess =
                    Core::FindProcessByPid(snapshot_, previousSelectedPid);
                if (previousSelectedCreationTime != 0 &&
                    refreshedSelectedProcess != nullptr &&
                    refreshedSelectedProcess->hasCreationTime &&
                    refreshedSelectedProcess->creationTimeFileTime != previousSelectedCreationTime)
                {
                    AddLog(
                        LogLevel::Warning,
                        "Selected PID " + std::to_string(previousSelectedPid) +
                            " has a different creation time after refresh; PID reuse suspected. Evidence caches cleared.");
                }
            }
            else
            {
                selectedPid_ = snapshot_.processes.front().pid;
                if (previousSelectedPid != InvalidPid)
                {
                    AddLog(
                        LogLevel::Warning,
                        "Previously selected PID " + std::to_string(previousSelectedPid) +
                            " is no longer present; selected PID " + std::to_string(selectedPid_) + ".");
                }
            }

            RefreshToken(false);
            RefreshRuntime(false);
            if (refreshSelectedEvidence)
            {
                const Core::ProcessInfo* selectedProcess = Core::FindProcessByPid(snapshot_, selectedPid_);
                if (selectedProcess != nullptr)
                {
                    EnsureSelectedProcessEvidenceLoaded(*selectedProcess);
                }
            }
            RebuildFocusedGraph("snapshot-refresh");
            RequestGraphFit();
            RebuildVisibleProcessRowsIfNeeded();
            RebuildGraphWorldLayoutIfNeeded();
            InvalidateFindingsCache();
            AddLog(
                snapshot_.processes.empty() ? LogLevel::Warning : LogLevel::Info,
                "Snapshot loaded: " + std::to_string(snapshot_.processes.size()) +
                    " processes, " + std::to_string(suspiciousCount_) +
                    " suspicious in " + std::to_string(timings_.processSnapshotMs) +
                    " ms. Filter " + std::to_string(timings_.processFilterMs) +
                    " ms, graph layout " + std::to_string(timings_.graphLayoutMs) + " ms.");
        }




        void RequestNetworkTableAutoFit(std::uint32_t pid)
        {
            if (pid == InvalidPid || networkTableAutoFitPid_ == pid)
            {
                return;
            }

            networkTableAutoFitPid_ = pid;
            ++networkTableAutoFitGeneration_;
            networkTableNeedsAutoSize_ = true;
        }

        #include "GraphPanel.cpp"




        void SelectProcess(std::uint32_t pid, bool focusGraph, bool logSelection = true)
        {
            const Core::ProcessInfo* selectedProcess = Core::FindProcessByPid(snapshot_, pid);
            if (selectedProcess == nullptr)
            {
                AddLog(LogLevel::Warning, "Selection ignored because PID " + std::to_string(pid) + " is no longer present.");
                return;
            }

            const bool changed = selectedPid_ != pid;
            if (selectedPid_ != pid)
            {
                ClearSelectedProcessEvidence();
                MarkSelectedEvidenceTablesNeedAutoSize();
            }

            selectedPid_ = pid;
            EnsureSelectedProcessEvidenceLoaded(*selectedProcess);
            if (changed && inspectorTab_ == InspectorTab::Network)
            {
                RequestNetworkTableAutoFit(selectedPid_);
            }
            if (focusGraph)
            {
                RebuildFocusedGraph("selection");
                if (changed)
                {
                    RequestGraphFit();
                }
            }

            if (changed && logSelection)
            {
                AddLog(
                    Core::SeverityRank(selectedProcess->severity) >= Core::SeverityRank(Core::Severity::High)
                        ? LogLevel::High
                        : LogLevel::Info,
                    "Selected " + DisplayName(selectedProcess->name) + " (PID " + std::to_string(selectedProcess->pid) + ").");
            }
        }

        void SelectGraphNode(std::uint32_t pid)
        {
            const Core::ProcessInfo* selectedProcess = Core::FindProcessByPid(snapshot_, pid);
            if (selectedProcess == nullptr)
            {
                AddLog(LogLevel::Warning, "Graph node selection ignored because PID " + std::to_string(pid) + " is no longer present.");
                return;
            }

            const bool changed = selectedPid_ != pid;
            SelectProcess(pid, true, false);
            if (changed)
            {
                AddLog(
                    Core::SeverityRank(selectedProcess->severity) >= Core::SeverityRank(Core::Severity::High)
                        ? LogLevel::High
                        : LogLevel::Info,
                        "Selected graph node " + DisplayName(selectedProcess->name) +
                        " (PID " + std::to_string(selectedProcess->pid) + ").");
            }
        }

        #include "AppActions.cpp"









        void ShowSelectedProcessInFilters()
        {
            const Core::ProcessInfo* selectedProcess = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (selectedProcess == nullptr)
            {
                AddLog(LogLevel::Warning, "Show selected ignored because the selected process is no longer present.");
                return;
            }

            const std::uint32_t preservedSelectedPid = selectedPid_;
            SetProcessFilterMode(ProcessFilterMode::All);
            searchBuffer_.fill('\0');
            SetProcessSearchText({});
            selectedPid_ = preservedSelectedPid;
            RebuildFocusedGraph("show-selected");
            RequestGraphFit();
            scrollSelectedProcessIntoView_ = true;

            if (!ProcessMatchesFilters(*selectedProcess))
            {
                AddLog(
                    LogLevel::Warning,
                    "Show selected could not reveal PID " + std::to_string(selectedProcess->pid) +
                        "; filter state may be inconsistent.");
                return;
            }

            AddLog(
                LogLevel::Info,
                "Cleared filters to show selected process " + DisplayName(selectedProcess->name) +
                    " (PID " + std::to_string(selectedProcess->pid) + ").");
        }

        void RenderUi()
        {
            PollLongOperationCompletion();
            RenderToolbar();
            RenderAboutPopup();
            RenderResetLayoutPopup();
            RenderNetworkIntelUpdatePopup();
            RenderDeepEvidenceSnapshotPopup();
            RenderLoadedSnapshotBanner();

#ifdef IMGUI_HAS_DOCK
            RenderDockedWorkspace();
#else
            RenderFixedWorkspace();
#endif
            GlassPane::UI::RenderAppStatusBar(BuildAppStatusBarContext());
            RenderLongOperationOverlay();
        }

        float HeaderReservedHeight() const
        {
            return loadedSnapshotActive_ ? 198.0f : 108.0f;
        }

        bool LoadedSnapshotLiveActionButton(const char* label)
        {
            const bool operationActive = IsLongOperationActive();
            if (!loadedSnapshotActive_ && !operationActive)
            {
                return ImGui::Button(label);
            }

            ImGui::BeginDisabled();
            ImGui::Button(label);
            ImGui::EndDisabled();
            if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
            {
                ImGui::SetTooltip(
                    "%s",
                    operationActive
                        ? "Unavailable while an operation is running."
                        : "Live collection is disabled while viewing a saved snapshot.");
            }
            return false;
        }

        void SameLineIfButtonFits(const char* label)
        {
            const float buttonWidth =
                ImGui::CalcTextSize(label).x +
                ImGui::GetStyle().FramePadding.x * 2.0f;
            if (ImGui::GetContentRegionAvail().x > buttonWidth + ImGui::GetStyle().ItemSpacing.x)
            {
                ImGui::SameLine();
            }
        }

        void RenderLoadedSnapshotBanner()
        {
            if (!loadedSnapshotActive_)
            {
                return;
            }

            const ImGuiViewport* viewport = ImGui::GetMainViewport();
            constexpr float margin = 10.0f;
            constexpr float headerHeight = 108.0f;
            const ImVec2 bannerPos(viewport->WorkPos.x + margin, viewport->WorkPos.y + headerHeight + 4.0f);
            const ImVec2 bannerSize(std::max(640.0f, viewport->WorkSize.x - margin * 2.0f), 76.0f);

            ImGui::SetNextWindowPos(bannerPos, ImGuiCond_Always);
            ImGui::SetNextWindowSize(bannerSize, ImGuiCond_Always);
            ImGui::SetNextWindowViewport(viewport->ID);
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(12.0f, 8.0f));
            ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 6.0f);
            ImGui::PushStyleColor(ImGuiCol_WindowBg, PanelBgRaised());
            ImGui::PushStyleColor(ImGuiCol_Border, PanelBorder());
            ImGui::Begin(
                "Loaded Snapshot Banner##GlassPane",
                nullptr,
                ImGuiWindowFlags_NoTitleBar |
                    ImGuiWindowFlags_NoCollapse |
                    ImGuiWindowFlags_NoResize |
                    ImGuiWindowFlags_NoMove |
                    ImGuiWindowFlags_NoSavedSettings |
                    ImGuiWindowFlags_NoDocking);

            const std::wstring capturedAt = loadedSnapshotMetadata_.capturedAt.empty()
                ? std::wstring(L"(unknown time)")
                : loadedSnapshotMetadata_.capturedAt;
            const std::wstring host = loadedSnapshotMetadata_.hostname.empty()
                ? std::wstring(L"(unknown host)")
                : loadedSnapshotMetadata_.hostname;
            const std::wstring summary =
                L"Viewing saved snapshot | captured " +
                capturedAt +
                L" | " +
                host +
                L" | " +
                std::to_wstring(snapshot_.processes.size()) +
                L" processes";
            ImGui::TextColored(AccentBlue(), "Saved snapshot mode");
            ImGui::SameLine();
            WrappedTextDisabled(summary);

            ImGui::Spacing();
            const bool operationActive = IsLongOperationActive();
            if (operationActive)
            {
                ImGui::BeginDisabled();
            }
            if (ImGui::Button("Use as Baseline##LoadedSnapshot"))
            {
                UseLoadedSnapshotAsBaseline();
            }
            SameLineIfButtonFits("Return to Live View##LoadedSnapshot");
            if (ImGui::Button("Return to Live View##LoadedSnapshot"))
            {
                ReturnToLiveView(false);
            }
            SameLineIfButtonFits("Refresh Live##LoadedSnapshot");
            if (ImGui::Button("Refresh Live##LoadedSnapshot"))
            {
                ReturnToLiveView(true);
            }
            if (operationActive)
            {
                ImGui::EndDisabled();
                if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
                {
                    ImGui::SetTooltip("Unavailable while an operation is running.");
                }
            }

            ImGui::End();
            ImGui::PopStyleColor(2);
            ImGui::PopStyleVar(2);
        }

        void RenderFixedWorkspace()
        {
            const ImGuiViewport* viewport = ImGui::GetMainViewport();
            constexpr float margin = 10.0f;
            constexpr float gap = 10.0f;
            const float headerHeight = HeaderReservedHeight();
            const float bottomHeight = std::clamp(
                (viewport->WorkSize.y - AppStatusBarHeight) * 0.17f,
                138.0f,
                190.0f);
            const float bodyTop = headerHeight + gap;
            const float bodyHeight = std::max(
                280.0f,
                viewport->WorkSize.y - bodyTop - bottomHeight - AppStatusBarHeight - (margin * 2.0f));
            const float leftWidth = std::clamp(viewport->WorkSize.x * 0.24f, 330.0f, 365.0f);
            const float rightWidth = std::clamp(viewport->WorkSize.x * 0.23f, 330.0f, 430.0f);
            const float centerWidth = std::max(420.0f, viewport->WorkSize.x - leftWidth - rightWidth - (margin * 2.0f) - (gap * 2.0f));
            const float centerX = margin + leftWidth + gap;
            const float rightX = centerX + centerWidth + gap;
            const float bottomY = bodyTop + bodyHeight + gap;

            PlacePanel(leftDockId_, ImVec2(margin, bodyTop), ImVec2(leftWidth, bodyHeight));
            RenderProcessesPanel();

            PlacePanel(centerDockId_, ImVec2(centerX, bodyTop), ImVec2(centerWidth, bodyHeight));
            RenderCenterPanel();

            PlacePanel(rightDockId_, ImVec2(rightX, bodyTop), ImVec2(rightWidth, bodyHeight));
            RenderRightPanel();

            PlacePanel(bottomDockId_, ImVec2(margin, bottomY), ImVec2(viewport->WorkSize.x - margin * 2.0f, bottomHeight));
            RenderBottomPanel();
        }

#ifdef IMGUI_HAS_DOCK
        void RenderDockedWorkspace()
        {
            const ImGuiViewport* viewport = ImGui::GetMainViewport();
            constexpr float margin = 10.0f;
            constexpr float gap = 10.0f;
            const float headerHeight = HeaderReservedHeight();
            const float bodyTop = headerHeight + gap;
            const ImVec2 dockHostPos(
                viewport->WorkPos.x + margin,
                viewport->WorkPos.y + bodyTop);
            const ImVec2 dockHostSize(
                std::max(640.0f, viewport->WorkSize.x - (margin * 2.0f)),
                std::max(360.0f, viewport->WorkSize.y - bodyTop - margin - AppStatusBarHeight));

            ImGui::SetNextWindowPos(dockHostPos, ImGuiCond_Always);
            ImGui::SetNextWindowSize(dockHostSize, ImGuiCond_Always);
            ImGui::SetNextWindowViewport(viewport->ID);
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));
            ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
            ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.0f, 0.0f, 0.0f, 0.0f));

            ImGui::Begin(
                "GlassPane Dock Host",
                nullptr,
                ImGuiWindowFlags_NoTitleBar |
                    ImGuiWindowFlags_NoCollapse |
                    ImGuiWindowFlags_NoResize |
                    ImGuiWindowFlags_NoMove |
                    ImGuiWindowFlags_NoBringToFrontOnFocus |
                    ImGuiWindowFlags_NoNavFocus |
                    ImGuiWindowFlags_NoDocking |
                    ImGuiWindowFlags_NoSavedSettings);

            dockspaceId_ = ImGui::GetID("GlassPaneDockSpace-v0.5.0");
            const bool missingSavedDockspace = ImGui::DockBuilderGetNode(dockspaceId_) == nullptr;
            if (resetDockLayoutRequested_ || (!dockspaceBuilt_ && missingSavedDockspace))
            {
                BuildDefaultDockLayout(dockHostSize);
            }
            ImGui::DockSpace(dockspaceId_, ImVec2(0.0f, 0.0f), ImGuiDockNodeFlags_None);
            dockspaceBuilt_ = true;

            ImGui::End();
            ImGui::PopStyleColor();
            ImGui::PopStyleVar(2);

            RenderDockedPanels();
        }

        void BuildDefaultDockLayout(const ImVec2& dockHostSize)
        {
            if (dockspaceId_ == 0)
            {
                return;
            }

            ImGui::DockBuilderRemoveNode(dockspaceId_);
            ImGui::DockBuilderAddNode(dockspaceId_, ImGuiDockNodeFlags_DockSpace);
            ImGui::DockBuilderSetNodeSize(dockspaceId_, dockHostSize);

            ImGuiID dockMain = dockspaceId_;
            ImGuiID dockBottom = 0;
            ImGuiID dockLeft = 0;
            ImGuiID dockRight = 0;
            ImGuiID dockCenter = 0;

            const float bottomRatio = std::clamp(150.0f / std::max(dockHostSize.y, 1.0f), 0.16f, 0.22f);
            ImGui::DockBuilderSplitNode(dockMain, ImGuiDir_Down, bottomRatio, &dockBottom, &dockMain);
            const float processPanelWidth = std::clamp(dockHostSize.x * 0.24f, 330.0f, 365.0f);
            const float processPanelRatio = processPanelWidth / std::max(dockHostSize.x, 1.0f);
            ImGui::DockBuilderSplitNode(dockMain, ImGuiDir_Left, processPanelRatio, &dockLeft, &dockMain);
            ImGui::DockBuilderSplitNode(dockMain, ImGuiDir_Right, 0.205f, &dockRight, &dockCenter);

            leftDockId_ = dockLeft;
            centerDockId_ = dockCenter;
            rightDockId_ = dockRight;
            bottomDockId_ = dockBottom;

            ImGui::DockBuilderDockWindow("Processes", leftDockId_);

            ImGui::DockBuilderDockWindow("Graph", centerDockId_);
            ImGui::DockBuilderDockWindow("Timeline", centerDockId_);

            ImGui::DockBuilderDockWindow("Inspector", rightDockId_);
            ImGui::DockBuilderDockWindow("Compare", rightDockId_);

            ImGui::DockBuilderDockWindow("Indicators", bottomDockId_);
            ImGui::DockBuilderDockWindow("Logs", bottomDockId_);
            ApplyDockNodeChromeFlags(dockspaceId_);

            ImGui::DockBuilderFinish(dockspaceId_);
            dockspaceBuilt_ = true;
            resetDockLayoutRequested_ = false;
            dockLayoutFocusRequested_ = true;
            rightDockLayoutFocusRequested_ = true;
            AddLog(LogLevel::Info, "Dock layout reset to default dashboard.");
        }

        void ApplyDockNodeChromeFlags(ImGuiID dockNodeId)
        {
            ApplyDockNodeChromeFlags(ImGui::DockBuilderGetNode(dockNodeId));
        }

        void ApplyDockNodeChromeFlags(ImGuiDockNode* dockNode)
        {
            if (dockNode == nullptr)
            {
                return;
            }

            dockNode->SetLocalFlags(
                dockNode->LocalFlags |
                ImGuiDockNodeFlags_NoWindowMenuButton |
                ImGuiDockNodeFlags_NoCloseButton);

            if (dockNode->TabBar != nullptr)
            {
                dockNode->TabBar->Flags |=
                    ImGuiTabBarFlags_NoTabListScrollingButtons |
                    ImGuiTabBarFlags_FittingPolicyShrink;
                dockNode->TabBar->Flags &= ~ImGuiTabBarFlags_FittingPolicyScroll;
            }

            ApplyDockNodeChromeFlags(dockNode->ChildNodes[0]);
            ApplyDockNodeChromeFlags(dockNode->ChildNodes[1]);
        }

        template <typename RenderCallback>
        void RenderDockedContentPanel(const char* title, RenderCallback renderContent)
        {
            if (!BeginPanelWindow(title))
            {
                EndPanelWindow();
                return;
            }
            renderContent();
            EndPanelWindow();
        }

        void RenderDockedPanels()
        {
            ApplyDockNodeChromeFlags(dockspaceId_);

            RenderProcessesPanel();

            if (dockLayoutFocusRequested_)
            {
                ImGui::SetNextWindowFocus();
            }
            RenderDockedContentPanel("Graph", [this]() { RenderGraphView(); });
            dockLayoutFocusRequested_ = false;
            RenderDockedContentPanel("Timeline", [this]() { RenderTimelineView(); });
            RenderDockedContentPanel("Compare", [this]() { RenderCompareView(); });

            if (rightDockLayoutFocusRequested_)
            {
                ImGui::SetNextWindowFocus();
            }
            RenderRightPanel();
            rightDockLayoutFocusRequested_ = false;
            RenderInspectorDockViews();

            RenderDockedContentPanel("Indicators", [this]() { RenderSelectedIndicators(); });
            RenderDockedContentPanel("Logs", [this]() { RenderLogsPanelContent(); });

            ApplyDockNodeChromeFlags(dockspaceId_);
        }

#endif

        void RequestDockLayoutReset()
        {
            CloseInspectorDockViews();
            resetDockLayoutRequested_ = true;
            dockspaceBuilt_ = false;
        }
        void PlacePanel(ImGuiID dockId, const ImVec2& fallbackPosition, const ImVec2& fallbackSize) const
        {
            const ImGuiViewport* viewport = ImGui::GetMainViewport();
#ifdef IMGUI_HAS_DOCK
            if (dockId != 0)
            {
                ImGui::SetNextWindowDockID(dockId, ImGuiCond_FirstUseEver);
            }
#else
            ImGui::SetNextWindowPos(
                ImVec2(viewport->WorkPos.x + fallbackPosition.x, viewport->WorkPos.y + fallbackPosition.y),
                ImGuiCond_Always);
            ImGui::SetNextWindowSize(fallbackSize, ImGuiCond_Always);
#endif
            (void)viewport;
        }

        void RenderAboutPopup()
        {
            const std::string appVersion = GlassPaneVersion();
            AboutPanelContext context;
            context.popupRequested = &aboutPopupRequested_;
            context.openedFrame = &aboutPopupOpenedFrame_;
            context.titleFont = fonts_.title;
            context.logoTexture = GetAppLogoTexture();
            context.appVersion = appVersion.c_str();
            context.githubUrl = GlassPaneGithubUrl;
            context.buildArchitecture = BuildArchitecture();
            context.buildConfiguration = BuildConfiguration();
            context.accentColor = AccentBlue();
            context.mutedTextColor = MutedText();
            context.onCopyGithubUrl = [this]() {
                AddLog(LogLevel::Info, "Copied GlassPane GitHub URL to clipboard.");
            };
            RenderAboutPanel(context);
        }

        void RenderResetLayoutPopup()
        {
            ResetLayoutModalContext context;
            context.popupRequested = &resetLayoutPopupRequested_;
            context.openedFrame = &resetLayoutPopupOpenedFrame_;
            context.titleFont = fonts_.bold;
            context.accentColor = AccentBlue();
            context.mutedTextColor = MutedText();
            context.onResetLayout = [this]() {
                RequestDockLayoutReset();
            };
            RenderResetLayoutModal(context);
        }

        void RenderNetworkIntelUpdatePopup()
        {
            NetworkIntelUpdateModalContext context;
            context.popupRequested = &networkIntelUpdatePopupRequested_;
            context.openedFrame = &networkIntelUpdatePopupOpenedFrame_;
            context.doNotShowAgain = &networkIntelUpdateDoNotShowAgainChoice_;
            context.titleFont = fonts_.bold;
            context.accentColor = AccentBlue();
            context.mutedTextColor = MutedText();
            context.onConfirmUpdate = [this]() {
                ConfirmNetworkIntelFeedUpdate();
            };
            context.onCancel = [this]() {
                CancelNetworkIntelFeedUpdate();
            };
            RenderNetworkIntelUpdateModal(context);
        }

        void RenderDeepEvidenceSnapshotPopup()
        {
            DeepEvidenceSnapshotModalContext context;
            context.popupRequested = &deepEvidenceSnapshotPopupRequested_;
            context.openedFrame = &deepEvidenceSnapshotPopupOpenedFrame_;
            context.titleFont = fonts_.bold;
            context.accentColor = AccentBlue();
            context.mutedTextColor = MutedText();
            context.onContinue = [this]() {
                SaveDeepEvidenceSnapshotFile();
            };
            context.onCancel = [this]() {
                CancelDeepEvidenceSnapshotSave();
            };
            RenderDeepEvidenceSnapshotModal(context);
        }

        void RenderToolbar()
        {
            HeaderPanelContext context;
            context.logoTexture = GetAppLogoTexture();
            context.searchBuffer = searchBuffer_.data();
            context.searchBufferSize = searchBuffer_.size();
            context.pickWindowActive = pickWindowActive_;
            context.loadedSnapshotActive = loadedSnapshotActive_;
            context.longOperationActive = IsLongOperationActive();
            context.processCount = snapshot_.processes.size();
            context.suspiciousCount = suspiciousCount_;
            context.lastRefreshText = WideToUtf8(lastRefreshTime_);
            context.titleFont = fonts_.title;
            context.smallUiFont = fonts_.smallUi;
            context.boldFont = fonts_.bold;
            context.monospaceFont = fonts_.monospace;
            context.headerBgColor = HeaderBg();
            context.panelBorderColor = PanelBorder();
            context.accentColor = AccentBlue();
            context.mutedTextColor = MutedText();
            context.primaryTextColor = PrimaryText();
            context.highSeverityColor = SeverityColor(Core::Severity::High);
            context.onAbout = [this]() {
                aboutPopupRequested_ = true;
            };
            context.onRefresh = [this]() {
                RefreshSnapshot(true);
            };
            context.onPickWindow = [this]() {
                StartPickWindowMode();
            };
            context.onSaveSnapshot = [this]() {
                SaveSnapshotFile();
            };
            context.onSaveDeepSnapshot = [this]() {
                RequestDeepEvidenceSnapshotSave();
            };
            context.onLoadSnapshot = [this]() {
                LoadSnapshotFile();
            };
            context.onExportEvidencePackage = [this]() {
                ExportEvidencePackage();
            };
            context.onRefreshModules = [this]() {
                RefreshModules();
            };
            context.onResetLayout = [this]() {
                resetLayoutPopupRequested_ = true;
            };
            context.onSearchChanged = [this](const char* searchText) {
                SetProcessSearchText(ToLower(Utf8ToWide(searchText)));
            };
            RenderHeaderPanel(context);
        }

        void RenderProcessesPanel()
        {
            if (!BeginPanelWindow("Processes"))
            {
                EndPanelWindow();
                return;
            }

            RebuildVisibleProcessRowsIfNeeded();

            ProcessPanelContext context;
            context.snapshot = &snapshot_;
            context.visibleRows = &visibleProcessRows_;
            context.selectedPid = selectedPid_;
            context.suspiciousCount = suspiciousCount_;
            context.activeFilter = processFilterMode_;
            context.searchActive = !searchText_.empty();
            context.processTableNeedsAutoSize = &processTableNeedsAutoSize_;
            context.scrollSelectedProcessIntoView = &scrollSelectedProcessIntoView_;
            context.boldFont = fonts_.bold;
            context.smallUiFont = fonts_.smallUi;
            context.monospaceFont = fonts_.monospace;
            context.accentColor = AccentBlue();
            context.mutedTextColor = MutedText();
            context.selectedRowColor = TableSelectedRow();
            context.onFilterModeChanged = [this](ProcessFilterMode mode) {
                if (SetProcessFilterMode(mode))
                {
                    RebuildVisibleProcessRowsIfNeeded();
                }
            };
            context.onSelectProcess = [this](std::uint32_t pid) {
                SelectProcess(pid, true);
            };
            RenderProcessPanelContent(context);
            EndPanelWindow();
        }

        void RenderCenterPanel()
        {
            if (!BeginPanelWindow("Graph / Timeline"))
            {
                EndPanelWindow();
                return;
            }
            if (ImGui::BeginTabBar("center_tabs"))
            {
                if (ImGui::BeginTabItem("Graph View"))
                {
                    RenderGraphView();
                    ImGui::EndTabItem();
                }
                if (ImGui::BeginTabItem("Timeline View"))
                {
                    RenderTimelineView();
                    ImGui::EndTabItem();
                }
                if (ImGui::BeginTabItem("Compare"))
                {
                    RenderCompareView();
                    ImGui::EndTabItem();
                }
                ImGui::EndTabBar();
            }
            EndPanelWindow();
        }

        #include "SnapshotCompareActions.cpp"

        void RenderCompareSummary()
        {
            const std::size_t baselineCount = baselineCompareSnapshot_.captured ? baselineCompareSnapshot_.processes.size() : 0;
            const std::size_t currentCount = currentCompareSnapshot_.captured ? currentCompareSnapshot_.processes.size() : 0;
            if (ImGui::BeginTable("CompareSummaryTable##SnapshotCompare", 4, ImGuiTableFlags_SizingStretchProp))
            {
                ImGui::TableSetupColumn("Metric", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Count", ImGuiTableColumnFlags_WidthFixed, 80.0f);
                ImGui::TableSetupColumn("Metric2", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Count2", ImGuiTableColumnFlags_WidthFixed, 80.0f);
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::TextDisabled("Baseline processes");
                ImGui::TableSetColumnIndex(1);
                ImGui::Text("%zu", baselineCount);
                ImGui::TableSetColumnIndex(2);
                ImGui::TextDisabled("Current processes");
                ImGui::TableSetColumnIndex(3);
                ImGui::Text("%zu", currentCount);

                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::TextDisabled("New processes");
                ImGui::TableSetColumnIndex(1);
                ImGui::Text("%zu", compareResultValid_ ? compareResult_.newProcesses.size() : 0);
                ImGui::TableSetColumnIndex(2);
                ImGui::TextDisabled("Exited processes");
                ImGui::TableSetColumnIndex(3);
                ImGui::Text("%zu", compareResultValid_ ? compareResult_.exitedProcesses.size() : 0);

                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::TextDisabled("Changed processes");
                ImGui::TableSetColumnIndex(1);
                ImGui::Text("%zu", compareResultValid_ ? compareResult_.changedProcesses.size() : 0);
                ImGui::TableSetColumnIndex(2);
                ImGui::TextDisabled("New network connections");
                ImGui::TableSetColumnIndex(3);
                if (compareResultValid_ && compareResult_.networkCompared)
                {
                    ImGui::Text("%zu", compareResult_.newNetworkConnections.size());
                }
                else
                {
                    ImGui::TextDisabled("N/A");
                }
                ImGui::EndTable();
            }
        }

        void RebuildCompareChangedProcessRows()
        {
            compareChangedProcessRows_.clear();
            if (!compareResultValid_)
            {
                return;
            }

            std::size_t rowCount = 0;
            for (const Core::SnapshotProcessChange& change : compareResult_.changedProcesses)
            {
                rowCount += change.fields.size();
            }
            compareChangedProcessRows_.reserve(rowCount);

            for (std::size_t changeIndex = 0; changeIndex < compareResult_.changedProcesses.size(); ++changeIndex)
            {
                const Core::SnapshotProcessChange& change = compareResult_.changedProcesses[changeIndex];
                for (std::size_t fieldIndex = 0; fieldIndex < change.fields.size(); ++fieldIndex)
                {
                    compareChangedProcessRows_.push_back({ changeIndex, fieldIndex });
                }
            }
        }

        void RenderCompareProcessTable(
            const char* tableId,
            const std::vector<Core::SnapshotProcessRecord>& processes,
            bool selectableRows)
        {
            constexpr ImGuiTableFlags flags =
                ImGuiTableFlags_BordersInnerV |
                ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Resizable |
                ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_SizingStretchProp;
            const float tableHeight = std::min(260.0f, std::max(118.0f, ImGui::GetTextLineHeightWithSpacing() * (static_cast<float>(processes.size()) + 2.0f)));
            if (!ImGui::BeginTable(tableId, 5, flags, ImVec2(0.0f, tableHeight)))
            {
                return;
            }

            ImGui::TableSetupColumn("Process", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 72.0f);
            ImGui::TableSetupColumn("PPID", ImGuiTableColumnFlags_WidthFixed, 72.0f);
            ImGui::TableSetupColumn("Severity", ImGuiTableColumnFlags_WidthFixed, 92.0f);
            ImGui::TableSetupColumn("Path", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();

            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(processes.size()));
            while (clipper.Step())
            {
                for (int rowIndex = clipper.DisplayStart; rowIndex < clipper.DisplayEnd; ++rowIndex)
                {
                    const Core::SnapshotProcessRecord& process = processes[static_cast<std::size_t>(rowIndex)];
                    ImGui::PushID(rowIndex);
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    if (selectableRows)
                    {
                        const bool canSelect = SnapshotProcessExistsInCurrentSnapshot(process);
                        if (ImGui::Selectable(
                                DisplayName(process.processName).c_str(),
                                false,
                                ImGuiSelectableFlags_SpanAllColumns))
                        {
                            if (canSelect)
                            {
                                SelectCompareProcessIfCurrent(process);
                            }
                        }
                        if (!canSelect && ImGui::IsItemHovered())
                        {
                            ImGui::SetTooltip("Process is not present in the current snapshot.");
                        }
                    }
                    else
                    {
                        ImGui::TextUnformatted(DisplayName(process.processName).c_str());
                        if (ImGui::IsItemHovered())
                        {
                            ImGui::SetTooltip("Process exited; cannot select in current snapshot.");
                        }
                    }
                    ImGui::TableSetColumnIndex(1);
                    ImGui::Text("%u", process.pid);
                    ImGui::TableSetColumnIndex(2);
                    ImGui::Text("%u", process.parentPid);
                    ImGui::TableSetColumnIndex(3);
                    SeverityText(process.severity);
                    ImGui::TableSetColumnIndex(4);
                    ClippedTextWithTooltip(process.executablePath.empty() ? L"(path unavailable)" : process.executablePath);
                    ImGui::PopID();
                }
            }
            ImGui::EndTable();
        }

        void RenderCompareChangedProcessTable()
        {
            constexpr ImGuiTableFlags flags =
                ImGuiTableFlags_BordersInnerV |
                ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Resizable |
                ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_SizingStretchProp;
            const float tableHeight = std::min(300.0f, std::max(126.0f, ImGui::GetTextLineHeightWithSpacing() * 10.0f));
            if (!ImGui::BeginTable("CompareChangedProcessesTable##SnapshotCompare", 5, flags, ImVec2(0.0f, tableHeight)))
            {
                return;
            }

            ImGui::TableSetupColumn("Process", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 72.0f);
            ImGui::TableSetupColumn("Field", ImGuiTableColumnFlags_WidthFixed, 122.0f);
            ImGui::TableSetupColumn("Baseline", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Current", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();

            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(compareChangedProcessRows_.size()));
            while (clipper.Step())
            {
                for (int rowIndex = clipper.DisplayStart; rowIndex < clipper.DisplayEnd; ++rowIndex)
                {
                    const auto [changeIndex, fieldIndex] = compareChangedProcessRows_[static_cast<std::size_t>(rowIndex)];
                    const Core::SnapshotProcessChange& change = compareResult_.changedProcesses[changeIndex];
                    const Core::SnapshotChangedField& field = change.fields[fieldIndex];
                    ImGui::PushID(rowIndex);
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    if (ImGui::Selectable(
                            DisplayName(change.current.processName).c_str(),
                            false,
                            ImGuiSelectableFlags_SpanAllColumns))
                    {
                        SelectCompareProcessIfCurrent(change.current);
                    }
                    ImGui::TableSetColumnIndex(1);
                    ImGui::Text("%u", change.current.pid);
                    ImGui::TableSetColumnIndex(2);
                    ClippedTextWithTooltip(field.field);
                    ImGui::TableSetColumnIndex(3);
                    ClippedTextWithTooltip(field.baselineValue);
                    ImGui::TableSetColumnIndex(4);
                    ClippedTextWithTooltip(field.currentValue);
                    ImGui::PopID();
                }
            }
            ImGui::EndTable();
        }

        void RenderCompareNetworkTable()
        {
            const std::size_t totalRows =
                compareResult_.newNetworkConnections.size() +
                compareResult_.closedNetworkConnections.size();
            constexpr ImGuiTableFlags flags =
                ImGuiTableFlags_BordersInnerV |
                ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Resizable |
                ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_SizingStretchProp;
            const float tableHeight = std::min(300.0f, std::max(118.0f, ImGui::GetTextLineHeightWithSpacing() * (static_cast<float>(totalRows) + 2.0f)));
            if (!ImGui::BeginTable("CompareNetworkChangesTable##SnapshotCompare", 7, flags, ImVec2(0.0f, tableHeight)))
            {
                return;
            }

            ImGui::TableSetupColumn("Change", ImGuiTableColumnFlags_WidthFixed, 86.0f);
            ImGui::TableSetupColumn("Process", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 70.0f);
            ImGui::TableSetupColumn("Protocol", ImGuiTableColumnFlags_WidthFixed, 82.0f);
            ImGui::TableSetupColumn("Local", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Remote", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 92.0f);
            ImGui::TableHeadersRow();

            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(totalRows));
            while (clipper.Step())
            {
                for (int rowIndex = clipper.DisplayStart; rowIndex < clipper.DisplayEnd; ++rowIndex)
                {
                    const std::size_t index = static_cast<std::size_t>(rowIndex);
                    const bool isNew = index < compareResult_.newNetworkConnections.size();
                    const Core::SnapshotNetworkEndpoint& endpoint = isNew
                        ? compareResult_.newNetworkConnections[index]
                        : compareResult_.closedNetworkConnections[index - compareResult_.newNetworkConnections.size()];
                    const bool canSelect = SnapshotEndpointOwnerExistsInCurrentSnapshot(endpoint);
                    ImGui::PushID(rowIndex);
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    ImGui::PushStyleColor(ImGuiCol_Text, isNew ? AccentBlue() : MutedText());
                    if (ImGui::Selectable(
                            isNew ? "Appeared" : "Closed",
                            false,
                            ImGuiSelectableFlags_SpanAllColumns))
                    {
                        if (canSelect)
                        {
                            SelectCompareEndpointOwnerIfCurrent(endpoint);
                        }
                    }
                    ImGui::PopStyleColor();
                    if (!canSelect && ImGui::IsItemHovered())
                    {
                        ImGui::SetTooltip("Owning process is not present in the current snapshot.");
                    }
                    ImGui::TableSetColumnIndex(1);
                    ImGui::TextUnformatted(DisplayName(endpoint.processName).c_str());
                    ImGui::TableSetColumnIndex(2);
                    ImGui::Text("%u", endpoint.owningPid);
                    ImGui::TableSetColumnIndex(3);
                    ClippedTextWithTooltip(endpoint.protocol);
                    ImGui::TableSetColumnIndex(4);
                    ClippedTextWithTooltip(CompareEndpointText(endpoint, false));
                    ImGui::TableSetColumnIndex(5);
                    ClippedTextWithTooltip(CompareEndpointText(endpoint, true));
                    ImGui::TableSetColumnIndex(6);
                    ClippedTextWithTooltip(endpoint.state.empty() ? L"-" : endpoint.state);
                    ImGui::PopID();
                }
            }
            ImGui::EndTable();
        }

        void RenderCompareFindingTable()
        {
            const std::size_t totalRows =
                compareResult_.newFindings.size() +
                compareResult_.changedFindings.size() +
                compareResult_.removedFindings.size();
            constexpr ImGuiTableFlags flags =
                ImGuiTableFlags_BordersInnerV |
                ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Resizable |
                ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_SizingStretchProp;
            const float tableHeight = std::min(320.0f, std::max(118.0f, ImGui::GetTextLineHeightWithSpacing() * (static_cast<float>(totalRows) + 2.0f)));
            if (!ImGui::BeginTable("CompareFindingChangesTable##SnapshotCompare", 6, flags, ImVec2(0.0f, tableHeight)))
            {
                return;
            }

            ImGui::TableSetupColumn("Change", ImGuiTableColumnFlags_WidthFixed, 86.0f);
            ImGui::TableSetupColumn("Severity", ImGuiTableColumnFlags_WidthFixed, 86.0f);
            ImGui::TableSetupColumn("Process", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 70.0f);
            ImGui::TableSetupColumn("Finding", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Category", ImGuiTableColumnFlags_WidthFixed, 104.0f);
            ImGui::TableHeadersRow();

            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(totalRows));
            while (clipper.Step())
            {
                for (int rowIndex = clipper.DisplayStart; rowIndex < clipper.DisplayEnd; ++rowIndex)
                {
                    const std::size_t index = static_cast<std::size_t>(rowIndex);
                    const Core::SnapshotFindingRecord* finding = nullptr;
                    const char* changeLabel = "New";
                    if (index < compareResult_.newFindings.size())
                    {
                        finding = &compareResult_.newFindings[index];
                        changeLabel = "New";
                    }
                    else if (index < compareResult_.newFindings.size() + compareResult_.changedFindings.size())
                    {
                        const std::size_t changedIndex = index - compareResult_.newFindings.size();
                        finding = &compareResult_.changedFindings[changedIndex].current;
                        changeLabel = "Changed";
                    }
                    else
                    {
                        const std::size_t removedIndex =
                            index - compareResult_.newFindings.size() - compareResult_.changedFindings.size();
                        finding = &compareResult_.removedFindings[removedIndex];
                        changeLabel = "Removed";
                    }

                    if (finding == nullptr)
                    {
                        continue;
                    }

                    ImGui::PushID(rowIndex);
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    ImGui::TextUnformatted(changeLabel);
                    ImGui::TableSetColumnIndex(1);
                    SeverityText(FindingSeverityAsCoreSeverity(finding->severity));
                    ImGui::TableSetColumnIndex(2);
                    ImGui::TextUnformatted(DisplayName(finding->processName).c_str());
                    ImGui::TableSetColumnIndex(3);
                    ImGui::Text("%u", finding->pid);
                    ImGui::TableSetColumnIndex(4);
                    ClippedTextWithTooltip(finding->title.empty() ? L"(untitled)" : finding->title);
                    ImGui::TableSetColumnIndex(5);
                    ClippedTextWithTooltip(finding->category.empty() ? L"(none)" : finding->category);
                    ImGui::PopID();
                }
            }
            ImGui::EndTable();
        }


        void RenderCompareView()
        {
            ComparePanelState state;
            state.baselineCaptured = baselineCompareSnapshot_.captured;
            state.currentCaptured = currentCompareSnapshot_.captured;
            state.resultValid = compareResultValid_;
            state.noDifferences = CompareHasNoDifferences();
            state.hasNotes = !compareResult_.notes.empty();
            state.newProcessesEmpty = compareResult_.newProcesses.empty();
            state.exitedProcessesEmpty = compareResult_.exitedProcesses.empty();
            state.changedProcessesEmpty = compareResult_.changedProcesses.empty();
            state.networkCompared = compareResult_.networkCompared;
            state.newNetworkEmpty = compareResult_.newNetworkConnections.empty();
            state.closedNetworkEmpty = compareResult_.closedNetworkConnections.empty();
            state.findingsCompared = compareResult_.findingsCompared;
            state.newFindingsEmpty = compareResult_.newFindings.empty();
            state.removedFindingsEmpty = compareResult_.removedFindings.empty();
            state.changedFindingsEmpty = compareResult_.changedFindings.empty();

            ComparePanelCallbacks callbacks;
            callbacks.captureBaseline = [this]() { CaptureBaselineSnapshot(); };
            callbacks.captureCurrent = [this]() { CaptureCurrentSnapshot(); };
            callbacks.clearCompare = [this]() { ClearSnapshotCompare(); };
            callbacks.copySummary = [this]() {
                CopyTextToClipboard(FormatCompareSummaryForClipboard(
                    baselineCompareSnapshot_,
                    currentCompareSnapshot_,
                    compareResult_,
                    compareResultValid_));
                AddLog(LogLevel::Info, "Compare summary copied to clipboard.");
            };
            callbacks.renderSummary = [this]() { RenderCompareSummary(); };
            callbacks.renderNotes = [this]() {
                for (const std::wstring& note : compareResult_.notes)
                {
                    ImGui::Bullet();
                    ImGui::SameLine();
                    WrappedTextDisabled(note);
                }
            };
            callbacks.renderNewProcesses = [this]() {
                RenderCompareProcessTable(
                    "CompareNewProcessesTable##SnapshotCompare",
                    compareResult_.newProcesses,
                    true);
            };
            callbacks.renderExitedProcesses = [this]() {
                RenderCompareProcessTable(
                    "CompareExitedProcessesTable##SnapshotCompare",
                    compareResult_.exitedProcesses,
                    false);
            };
            callbacks.renderChangedProcesses = [this]() { RenderCompareChangedProcessTable(); };
            callbacks.renderNetworkChanges = [this]() { RenderCompareNetworkTable(); };
            callbacks.renderFindingChanges = [this]() { RenderCompareFindingTable(); };

            RenderComparePanel(state, callbacks, fonts_.bold, AccentBlue());
        }

        void SelectInspectorTab(InspectorTab tab)
        {
            const bool wasNetworkTab = inspectorTab_ == InspectorTab::Network;
            inspectorTab_ = tab;
            if (tab == InspectorTab::Network && !wasNetworkTab)
            {
                RequestNetworkTableAutoFit(selectedPid_);
            }
        }

        bool IsInspectorDockViewOpen(InspectorTab tab) const
        {
            return inspectorDockViewOpen_[InspectorTabIndex(tab)];
        }

        bool TryGetFirstAvailableInspectorTab(InspectorTab& tab) const
        {
            for (const InspectorTabSpec& spec : InspectorTabs)
            {
                if (!IsInspectorDockViewOpen(spec.tab))
                {
                    tab = spec.tab;
                    return true;
                }
            }
            return false;
        }

        bool EnsureVisibleInspectorTab()
        {
            if (!IsInspectorDockViewOpen(inspectorTab_))
            {
                return true;
            }

            InspectorTab fallback = InspectorTab::Triage;
            if (TryGetFirstAvailableInspectorTab(fallback))
            {
                inspectorTab_ = fallback;
                return true;
            }

            return false;
        }

        void ResetInspectorTabScroll()
        {
            inspectorTabScrollX_ = 0.0f;
            inspectorTabEdgeHoverDirection_ = 0;
            inspectorTabEdgeHoverStartedMs_ = 0;
            inspectorTabAutoScrollCooldownUntilMs_ = 0;
        }

        void RestoreAllInspectorDockViews(bool logActivity = true)
        {
            bool changed = false;
            for (bool& open : inspectorDockViewOpen_)
            {
                changed = changed || open;
                open = false;
            }

            inspectorTab_ = InspectorTab::Triage;
            ResetInspectorTabScroll();

            if (changed && logActivity)
            {
                AddLog(LogLevel::Info, "Restored all inspector views to the Inspector panel.");
            }
        }

        void SetInspectorDockViewOpen(InspectorTab tab, bool open, bool logActivity = true)
        {
            bool& state = inspectorDockViewOpen_[InspectorTabIndex(tab)];
            if (state == open)
            {
                return;
            }

            state = open;
            if (open && tab == InspectorTab::Network)
            {
                RequestNetworkTableAutoFit(selectedPid_);
            }
            if (open && inspectorTab_ == tab)
            {
                EnsureVisibleInspectorTab();
            }
            if (!open && IsInspectorDockViewOpen(inspectorTab_))
            {
                inspectorTab_ = tab;
            }
            if (logActivity)
            {
                AddLog(
                    LogLevel::Info,
                    std::string(open ? "Opened " : "Closed ") +
                        InspectorTabLabel(tab) +
                        " dockable inspector panel.");
            }
        }

        void CloseInspectorDockViews()
        {
            RestoreAllInspectorDockViews(false);
        }

        void RenderInspectorTabContextMenu(InspectorTab tab)
        {
            if (!ImGui::BeginPopupContextItem("InspectorTabContext"))
            {
                return;
            }

            if (IsInspectorDockViewOpen(tab))
            {
                if (ImGui::MenuItem("Close Dockable Panel"))
                {
                    SetInspectorDockViewOpen(tab, false);
                }
            }
            else
            {
                if (ImGui::MenuItem("Open as Dockable Panel"))
                {
                    SetInspectorDockViewOpen(tab, true);
                }
            }

            ImGui::EndPopup();
        }

        void RenderInspectorTabContent(InspectorTab tab)
        {
            switch (tab)
            {
            case InspectorTab::Triage:
                RenderTriagePanel();
                break;
            case InspectorTab::Details:
                RenderDetailsPanel();
                break;
            case InspectorTab::Chain:
                RenderChainPanel();
                break;
            case InspectorTab::Services:
                RenderServicesPanel();
                break;
            case InspectorTab::Modules:
                RenderModulesPanel();
                break;
            case InspectorTab::Network:
                RenderNetworkPanel();
                break;
            case InspectorTab::Runtime:
                RenderRuntimePanel();
                break;
            case InspectorTab::Memory:
                RenderMemoryPanel();
                break;
            case InspectorTab::Token:
                RenderTokenPanel();
                break;
            case InspectorTab::Handles:
                RenderHandlesPanel();
                break;
            default:
                RenderTriagePanel();
                break;
            }
        }

        void RenderInspectorTabStrip()
        {
            constexpr float spacing = 6.0f;
            constexpr float stripHeight = 38.0f;
            constexpr float wheelStep = 92.0f;
            constexpr float edgeWidth = 64.0f;
            constexpr float strictClickDeadzoneWidth = 30.0f;
            constexpr float edgeScrollSpeed = 160.0f;
            constexpr ULONGLONG edgeHoverDelayMs = 1200;
            constexpr ULONGLONG manualWheelCooldownMs = 800;

            const float visibleWidth = std::max(1.0f, ImGui::GetContentRegionAvail().x);
            float contentWidth = 0.0f;
            std::size_t visibleTabCount = 0;
            for (std::size_t index = 0; index < InspectorTabs.size(); ++index)
            {
                if (IsInspectorDockViewOpen(InspectorTabs[index].tab))
                {
                    continue;
                }
                contentWidth += ChipButtonWidth(InspectorTabs[index].label);
                if (visibleTabCount > 0)
                {
                    contentWidth += spacing;
                }
                ++visibleTabCount;
            }
            const float maxScroll = std::max(0.0f, contentWidth - visibleWidth);
            inspectorTabScrollX_ = std::clamp(inspectorTabScrollX_, 0.0f, maxScroll);

            ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(spacing, 4.0f));
            ImGui::BeginChild(
                "inspector_tab_strip",
                ImVec2(0.0f, stripHeight),
                ImGuiChildFlags_None,
                ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoNavInputs);

            if (visibleTabCount == 0)
            {
                ResetInspectorTabScroll();
                WrappedTextDisabled("All inspector views are open as dockable panels.");
                ImGui::EndChild();
                ImGui::PopStyleVar();
                return;
            }

            const ImVec2 stripMin = ImGui::GetWindowPos();
            const ImVec2 stripMax(stripMin.x + ImGui::GetWindowSize().x, stripMin.y + ImGui::GetWindowSize().y);
            const bool hovered = ImGui::IsWindowHovered(ImGuiHoveredFlags_AllowWhenBlockedByActiveItem);
            ImGuiIO& io = ImGui::GetIO();
            const bool canScrollLeft = inspectorTabScrollX_ > 0.5f;
            const bool canScrollRight = inspectorTabScrollX_ < maxScroll - 0.5f;
            const bool mouseInLeftGradient =
                canScrollLeft &&
                io.MousePos.x >= stripMin.x &&
                io.MousePos.x <= stripMin.x + edgeWidth &&
                io.MousePos.y >= stripMin.y &&
                io.MousePos.y <= stripMax.y;
            const bool mouseInRightGradient =
                canScrollRight &&
                io.MousePos.x >= stripMax.x - edgeWidth &&
                io.MousePos.x <= stripMax.x &&
                io.MousePos.y >= stripMin.y &&
                io.MousePos.y <= stripMax.y;
            const bool mouseInStrictLeftDeadzone =
                canScrollLeft &&
                io.MousePos.x >= stripMin.x &&
                io.MousePos.x <= stripMin.x + strictClickDeadzoneWidth &&
                io.MousePos.y >= stripMin.y &&
                io.MousePos.y <= stripMax.y;
            const bool mouseInStrictRightDeadzone =
                canScrollRight &&
                io.MousePos.x >= stripMax.x - strictClickDeadzoneWidth &&
                io.MousePos.x <= stripMax.x &&
                io.MousePos.y >= stripMin.y &&
                io.MousePos.y <= stripMax.y;
            const bool suppressTabClick = mouseInStrictLeftDeadzone || mouseInStrictRightDeadzone;

            if (hovered && maxScroll > 0.0f)
            {
                const ULONGLONG now = GetTickCount64();
                if (io.MouseWheel != 0.0f)
                {
                    inspectorTabScrollX_ = std::clamp(inspectorTabScrollX_ - io.MouseWheel * wheelStep, 0.0f, maxScroll);
                    inspectorTabAutoScrollCooldownUntilMs_ = now + manualWheelCooldownMs;
                    inspectorTabEdgeHoverDirection_ = 0;
                    inspectorTabEdgeHoverStartedMs_ = 0;
                    io.MouseWheel = 0.0f;
                    io.MouseWheelH = 0.0f;
                }

                int edgeDirection = 0;
                if (mouseInLeftGradient)
                {
                    edgeDirection = -1;
                }
                else if (mouseInRightGradient)
                {
                    edgeDirection = 1;
                }

                if (edgeDirection != 0)
                {
                    if (now < inspectorTabAutoScrollCooldownUntilMs_)
                    {
                        inspectorTabEdgeHoverDirection_ = 0;
                        inspectorTabEdgeHoverStartedMs_ = 0;
                    }
                    else if (inspectorTabEdgeHoverDirection_ != edgeDirection)
                    {
                        inspectorTabEdgeHoverDirection_ = edgeDirection;
                        inspectorTabEdgeHoverStartedMs_ = now;
                    }
                    else if (now - inspectorTabEdgeHoverStartedMs_ >= edgeHoverDelayMs)
                    {
                        inspectorTabScrollX_ = std::clamp(
                            inspectorTabScrollX_ + static_cast<float>(edgeDirection) * edgeScrollSpeed * io.DeltaTime,
                            0.0f,
                            maxScroll);
                    }
                }
                else
                {
                    inspectorTabEdgeHoverDirection_ = 0;
                    inspectorTabEdgeHoverStartedMs_ = 0;
                }
            }
            else
            {
                inspectorTabEdgeHoverDirection_ = 0;
                inspectorTabEdgeHoverStartedMs_ = 0;
            }

            ImGui::SetScrollX(inspectorTabScrollX_);
            ImGui::Dummy(ImVec2(0.0f, 2.0f));
            bool renderedAnyTab = false;
            for (std::size_t index = 0; index < InspectorTabs.size(); ++index)
            {
                const InspectorTabSpec& spec = InspectorTabs[index];
                if (IsInspectorDockViewOpen(spec.tab))
                {
                    continue;
                }
                if (renderedAnyTab)
                {
                    ImGui::SameLine(0.0f, spacing);
                }
                ImGui::PushID(spec.label);
                const std::string chipId = std::string(spec.label) + "##InspectorTab";
                if (ChipButton(chipId.c_str(), inspectorTab_ == spec.tab, AccentBlue()))
                {
                    if (!suppressTabClick)
                    {
                        SelectInspectorTab(spec.tab);
                    }
                }
                RenderInspectorTabContextMenu(spec.tab);
                ImGui::PopID();
                renderedAnyTab = true;
            }

            ImDrawList* drawList = ImGui::GetWindowDrawList();
            drawList->PushClipRect(stripMin, stripMax, true);
            const ImU32 fadeStrong = ColorU32(ImVec4(0.025f, 0.045f, 0.065f, 0.88f));
            const ImU32 fadeClear = ColorU32(ImVec4(0.025f, 0.045f, 0.065f, 0.00f));
            if (canScrollLeft)
            {
                const ImVec2 min(stripMin.x, stripMin.y);
                const ImVec2 max(stripMin.x + edgeWidth, stripMax.y);
                drawList->AddRectFilledMultiColor(min, max, fadeStrong, fadeClear, fadeClear, fadeStrong);
            }
            if (canScrollRight)
            {
                const ImVec2 min(stripMax.x - edgeWidth, stripMin.y);
                const ImVec2 max(stripMax.x, stripMax.y);
                drawList->AddRectFilledMultiColor(min, max, fadeClear, fadeStrong, fadeStrong, fadeClear);
            }
            drawList->PopClipRect();

            ImGui::EndChild();
            ImGui::PopStyleVar();
        }

        void RenderRightPanel()
        {
            if (!BeginPanelWindow(
                    "Inspector",
                    ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse))
            {
                EndPanelWindow();
                return;
            }
            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(6.0f, 3.0f));
            ImGui::PushStyleVar(ImGuiStyleVar_ItemInnerSpacing, ImVec2(4.0f, 4.0f));
            ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(5.0f, 5.0f));

            const bool hasVisibleInspectorTab = EnsureVisibleInspectorTab();

            RenderInspectorTabStrip();
            ImGui::Separator();

            ImGui::BeginChild(
                "inspector_content_scroll",
                ImVec2(0.0f, 0.0f),
                ImGuiChildFlags_None);
            if (!hasVisibleInspectorTab)
            {
                WrappedTextDisabled("All Inspector views are currently open as dockable panels. Close a panel to restore its pill tab here.");
                if (ImGui::Button("Restore All##InspectorViews"))
                {
                    RestoreAllInspectorDockViews();
                }
            }
            else
            {
                RenderInspectorTabContent(inspectorTab_);
            }
            ImGui::EndChild();

            ImGui::PopStyleVar(3);
            EndPanelWindow();
        }

        void RenderInspectorDockView(InspectorTab tab)
        {
            bool open = IsInspectorDockViewOpen(tab);
            if (!open)
            {
                return;
            }

            const ImGuiViewport* viewport = ImGui::GetMainViewport();
            const ImVec2 defaultSize = InspectorDockDefaultSize(tab);
            ImGui::SetNextWindowSize(defaultSize, ImGuiCond_FirstUseEver);
            ImGui::SetNextWindowPos(
                ImVec2(
                    viewport->WorkPos.x + viewport->WorkSize.x * 0.5f,
                    viewport->WorkPos.y + viewport->WorkSize.y * 0.5f),
                ImGuiCond_FirstUseEver,
                ImVec2(0.5f, 0.5f));
            const char* title = InspectorDockWindowTitle(tab);
            if (!BeginPanelWindow(title, &open, ImGuiWindowFlags_None))
            {
                EndPanelWindow();
                if (!open)
                {
                    SetInspectorDockViewOpen(tab, false);
                }
                return;
            }

            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(6.0f, 3.0f));
            ImGui::PushStyleVar(ImGuiStyleVar_ItemInnerSpacing, ImVec2(4.0f, 4.0f));
            ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(5.0f, 5.0f));
            RenderInspectorTabContent(tab);
            ImGui::PopStyleVar(3);
            EndPanelWindow();

            if (!open)
            {
                SetInspectorDockViewOpen(tab, false);
            }
        }

        void RenderInspectorDockViews()
        {
            for (const InspectorTabSpec& spec : InspectorTabs)
            {
                RenderInspectorDockView(spec.tab);
            }
        }

        #include "InspectorViews.cpp"


        void RenderTimelineView()
        {
            const std::vector<Core::TimelineRow>& visibleTimelineRows = TimelineRowsForCurrentFilters();

            TimelinePanelContext context;
            context.rows = &visibleTimelineRows;
            context.selectedPid = selectedPid_;
            context.activeFilter = timelineFilter_;
            context.timelineTableNeedsAutoSize = &timelineTableNeedsAutoSize_;
            context.monospaceFont = fonts_.monospace;
            context.selectedRowColor = TableSelectedRow();
            context.onFilterChanged = [this](Core::TimelineFilter filter) {
                if (SetTimelineFilter(filter))
                {
                    TimelineRowsForCurrentFilters();
                }
            };
            context.onSelectProcess = [this](std::uint32_t pid) {
                SelectProcess(pid, true);
            };
            RenderTimelinePanelContent(context);
        }

        void RenderLogsPanelContent()
        {
            GlassPane::UI::RenderLogsPanelContent(BuildLogsPanelContext());
        }

        void RenderBottomPanel()
        {
            if (!BeginPanelWindow("Indicators / Logs"))
            {
                EndPanelWindow();
                return;
            }
            LogsAndIndicatorsPanelContext context;
            context.logs = BuildLogsPanelContext();
            context.indicators = BuildIndicatorsPanelContext();
            RenderLogsAndIndicatorsPanel(context);
            EndPanelWindow();
        }

        void RenderSelectedIndicators()
        {
            GlassPane::UI::RenderIndicatorsPanelContent(BuildIndicatorsPanelContext());
        }

        LogsPanelContext BuildLogsPanelContext()
        {
            LogsPanelContext context;
            context.entries.reserve(logs_.size());
            for (const LogEntry& entry : logs_)
            {
                context.entries.push_back({ ToLogsPanelLevel(entry.level), entry.message });
            }
            context.monospaceFont = fonts_.monospace;
            context.accentColor = AccentBlue();
            context.mutedTextColor = MutedText();
            context.consoleBgColor = ConsoleBg();
            context.panelBorderColor = PanelBorder();
            context.onClear = [this]() {
                logs_.clear();
            };
            context.onSave = [this]() {
                SaveLogs();
            };
            return context;
        }

        AppStatusBarContext BuildAppStatusBarContext()
        {
            AppStatusBarContext context;
            constexpr ImVec4 ReadyGreen(0.32f, 0.74f, 0.46f, 1.0f);
            constexpr ImVec4 WorkingYellow(0.88f, 0.70f, 0.28f, 1.0f);
            constexpr ImVec4 FailedRed(0.88f, 0.32f, 0.32f, 1.0f);

            if (IsLongOperationActive())
            {
                std::lock_guard<std::mutex> lock(longOperationMutex_);
                context.statusText = std::string("Working: ") + LongOperationStatusLabel(longOperationKind_);
                context.indicatorColor = WorkingYellow;
            }
            else if (longOperationResultVisible_)
            {
                std::lock_guard<std::mutex> lock(longOperationMutex_);
                const bool success = longOperationResult_.success;
                context.statusText = std::string(success ? "Complete: " : "Failed: ") +
                    LongOperationStatusLabel(longOperationKind_);
                context.indicatorColor = success ? ReadyGreen : FailedRed;
            }
            else
            {
                context.statusText = "Ready";
                context.indicatorColor = ReadyGreen;
            }

            static const std::string liveOsBuild = WideToUtf8(OsBuildText());
            context.osBuild = loadedSnapshotActive_ && !loadedSnapshotMetadata_.osBuild.empty()
                ? WideToUtf8(loadedSnapshotMetadata_.osBuild)
                : liveOsBuild;
            context.architecture = BuildArchitecture();
            context.textColor = ImGui::GetStyleColorVec4(ImGuiCol_Text);
            context.mutedTextColor = MutedText();
            context.backgroundColor = ConsoleBg();
            context.borderColor = PanelBorder();
            return context;
        }

        IndicatorsPanelContext BuildIndicatorsPanelContext()
        {
            IndicatorsPanelContext context;
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                return context;
            }

            context.hasSelectedProcess = true;
            const Core::ChainAnalysisResult& chain = CachedChainAnalysis(*process);
            const Core::FileIdentity& fileIdentity = CachedFileIdentity(*process);
            const std::vector<Core::FileIdentityIndicator> fileIdentityIndicators =
                BuildProcessFileIdentityIndicators(*process, fileIdentity);

            context.processIndicators.reserve(process->indicators.size() + fileIdentityIndicators.size());
            for (const std::wstring& indicator : process->indicators)
            {
                IndicatorItemView item;
                item.text = indicator;
                context.processIndicators.push_back(std::move(item));
            }
            for (const Core::FileIdentityIndicator& indicator : fileIdentityIndicators)
            {
                IndicatorItemView item;
                item.text = indicator.message;
                item.hasSeverity = true;
                item.severityLabel = WideToUtf8(Core::SeverityToString(indicator.severity));
                item.severityColor = SeverityColor(indicator.severity);
                context.processIndicators.push_back(std::move(item));
            }

            const std::vector<Core::NetworkIndicatorMatch> networkIntelMatches =
                SelectedNetworkIndicatorMatchesForProcess(process->pid);
            if (!networkIntelMatches.empty())
            {
                IndicatorItemView item;
                item.text =
                    L"Network intelligence: " +
                    std::to_wstring(networkIntelMatches.size()) +
                    L" remote endpoint matched local indicator feed.";
                item.hasSeverity = true;
                item.severityLabel = WideToUtf8(networkIntelMatches.front().indicator.severity.empty()
                    ? std::wstring(L"Info")
                    : networkIntelMatches.front().indicator.severity);
                item.severityColor =
                    SeverityColor(NetworkIndicatorSeverityAsCoreSeverity(networkIntelMatches.front().indicator.severity));
                context.processIndicators.push_back(std::move(item));
            }

            context.chainIndicators = chain.chainIndicators;
            if (ModulesLoadedForProcess(*process) && !selectedModules_.indicators.empty())
            {
                context.moduleIndicators = selectedModules_.indicators;
            }

            if (compareResultValid_ && compareResult_.hasBaseline && compareResult_.hasCurrent)
            {
                context.compareSummary =
                    "Snapshot compare: " +
                    std::to_string(compareResult_.newProcesses.size()) +
                    " new processes, " +
                    std::to_string(compareResult_.exitedProcesses.size()) +
                    " exited processes, " +
                    std::to_string(compareResult_.changedProcesses.size()) +
                    " changed processes";
                if (compareResult_.networkCompared)
                {
                    context.compareSummary += ", " + std::to_string(compareResult_.newNetworkConnections.size()) +
                        " new network connection(s)";
                }
                context.compareSummary += ".";
            }
            return context;
        }

        bool ProcessMatchesFilters(const Core::ProcessInfo& process) const
        {
            const bool matchesSearch = MatchesSearch(process);
            const bool matchesSidebarFilterMode = MatchesSidebarFilterMode(process);
            const bool matchesTopToolbarSeverityFilters = MatchesTopToolbarSeverityFiltersIfApplicable(process);

            return matchesSearch && matchesSidebarFilterMode && matchesTopToolbarSeverityFilters;
        }

        bool MatchesSearch(const Core::ProcessInfo& process) const
        {
            const std::wstring& query = searchText_;
            if (query.empty())
            {
                return true;
            }

            if (FieldContainsQuery(process.name, query))
            {
                return true;
            }
            if (FieldContainsQuery(process.executablePath, query))
            {
                return true;
            }
            if (FieldContainsQuery(process.commandLine, query))
            {
                return true;
            }
            if (std::to_wstring(process.pid).find(query) != std::wstring::npos)
            {
                return true;
            }
            if (std::to_wstring(process.parentPid).find(query) != std::wstring::npos)
            {
                return true;
            }

            for (const std::wstring& indicator : process.indicators)
            {
                if (FieldContainsQuery(indicator, query))
                {
                    return true;
                }
            }
            for (const std::wstring& note : process.contextNotes)
            {
                if (FieldContainsQuery(note, query))
                {
                    return true;
                }
            }

            const Core::ProcessInfo* parent =
                Core::IsUsableParentRelationship(Core::GetParentRelationshipStatus(snapshot_, process))
                    ? Core::FindProcessByPid(snapshot_, process.parentPid)
                    : nullptr;
            if (parent != nullptr && FieldContainsQuery(parent->name, query))
            {
                return true;
            }

            return false;
        }

        bool MatchesSidebarFilterMode(const Core::ProcessInfo& process) const
        {
            switch (processFilterMode_)
            {
            case ProcessFilterMode::All:
                return true;
            case ProcessFilterMode::Suspicious:
                return process.suspicious;
            case ProcessFilterMode::Low:
                return process.suspicious && process.severity == Core::Severity::Low;
            case ProcessFilterMode::Medium:
                return process.suspicious && process.severity == Core::Severity::Medium;
            case ProcessFilterMode::High:
                return process.suspicious && process.severity == Core::Severity::High;
            default:
                return true;
            }
        }

        bool MatchesTopToolbarSeverityFiltersIfApplicable(const Core::ProcessInfo&) const
        {
            return true;
        }

        void SaveLogs()
        {
            wchar_t fileName[MAX_PATH] = L"glasspane-log.txt";

            OPENFILENAMEW dialog = {};
            dialog.lStructSize = sizeof(dialog);
            dialog.hwndOwner = hwnd_;
            dialog.lpstrFilter = L"Text Files (*.txt)\0*.txt\0All Files (*.*)\0*.*\0";
            dialog.lpstrFile = fileName;
            dialog.nMaxFile = MAX_PATH;
            dialog.lpstrDefExt = L"txt";
            dialog.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;

            if (GetSaveFileNameW(&dialog) == FALSE)
            {
                return;
            }

            std::ofstream output(fileName, std::ios::binary | std::ios::trunc);
            if (!output)
            {
                AddLog(LogLevel::High, "Log save failed: could not open output file.");
                return;
            }

            for (const LogEntry& entry : logs_)
            {
                output << '[' << LogLevelLabel(entry.level) << "] " << entry.message << "\n";
            }

            if (!output)
            {
                AddLog(LogLevel::High, "Log save failed while writing output file.");
                return;
            }

            AddLog(LogLevel::Info, "Log console saved: " + WideToUtf8(fileName));
        }











        HINSTANCE instance_ = nullptr;
        HWND hwnd_ = nullptr;
        HWND pickerOverlayHwnd_ = nullptr;
        ID3D11Device* device_ = nullptr;
        ID3D11DeviceContext* deviceContext_ = nullptr;
        IDXGISwapChain* swapChain_ = nullptr;
        ID3D11RenderTargetView* renderTargetView_ = nullptr;

        Core::ProcessSnapshot snapshot_;
        Core::ServiceCollectionResult serviceSnapshot_;
        Core::FocusedGraph focusedGraph_;
        Core::ProcessSnapshotCapture baselineCompareSnapshot_;
        Core::ProcessSnapshotCapture currentCompareSnapshot_;
        Core::SnapshotCompareResult compareResult_;
        Core::ChainAnalysisResult selectedChainCache_;
        Core::NetworkIndicatorLoadResult networkIndicatorLoadResult_;
        Core::NetworkIndicatorUpdateResult networkIndicatorUpdateResult_;
        Core::NetworkIndicatorFeed networkIndicatorFeed_;
        Export::SavedSnapshotMetadata loadedSnapshotMetadata_;
        Export::NetworkIntelligenceSnapshotMetadata loadedSnapshotNetworkIntel_;
        std::vector<Export::ProcessEvidenceSnapshot> loadedSnapshotEvidence_;
        std::unordered_map<std::uint32_t, std::size_t> loadedSnapshotEvidenceByPid_;
        std::vector<Core::NetworkIndicatorMatch> loadedSnapshotNetworkIndicatorMatches_;
        Core::ModuleCollectionResult selectedModules_;
        Core::NetworkCollectionResult networkSnapshot_;
        Core::ProcessSnapshot liveSnapshotBeforeLoad_;
        Core::ServiceCollectionResult liveServiceSnapshotBeforeLoad_;
        Core::NetworkCollectionResult liveNetworkSnapshotBeforeLoad_;
        Core::TokenInfo selectedToken_;
        Core::RuntimeInfo selectedRuntime_;
        Core::MemoryCollectionResult selectedMemory_;
        Core::HandleCollectionResult selectedHandles_;
        std::thread longOperationWorker_;
        std::mutex longOperationMutex_;
        LongOperationResult longOperationResult_;
        Core::TimelineFilter timelineFilter_ = Core::TimelineFilter::All;
        FontSet fonts_;
        std::uint32_t selectedPid_ = InvalidPid;
        std::uint32_t selectedModulesPid_ = InvalidPid;
        std::uint32_t selectedModulePid_ = InvalidPid;
        std::uint32_t selectedTokenPid_ = InvalidPid;
        std::uint32_t selectedRuntimePid_ = InvalidPid;
        std::uint32_t selectedMemoryPid_ = InvalidPid;
        std::uint32_t selectedHandlesPid_ = InvalidPid;
        std::uint32_t networkTableAutoFitPid_ = InvalidPid;
        std::uint64_t selectedModulesCreationTime_ = 0;
        std::uint64_t selectedTokenCreationTime_ = 0;
        std::uint64_t selectedRuntimeCreationTime_ = 0;
        std::uint64_t selectedMemoryCreationTime_ = 0;
        std::uint64_t selectedHandlesCreationTime_ = 0;
        ULONGLONG lastTriageRecomputeLogTick_ = 0;
        std::uint64_t findingsCacheCreationTime_ = 0;
        std::uint64_t selectedChainCacheCreationTime_ = 0;
        std::uint64_t selectedChainCacheSnapshotGeneration_ = 0;
        int networkTableAutoFitGeneration_ = 0;
        std::size_t selectedModuleIndex_ = 0;
        bool selectedModulesLoaded_ = false;
        bool selectedTokenLoaded_ = false;
        bool selectedRuntimeLoaded_ = false;
        bool selectedMemoryLoaded_ = false;
        bool selectedHandlesLoaded_ = false;
        bool compareResultValid_ = false;
        bool selectedChainCacheValid_ = false;
        bool processTableNeedsAutoSize_ = true;
        bool timelineTableNeedsAutoSize_ = true;
        bool modulesTableNeedsAutoSize_ = true;
        bool networkTableNeedsAutoSize_ = true;
        bool tokenTableNeedsAutoSize_ = true;
        bool runtimeTableNeedsAutoSize_ = true;
        bool memoryTableNeedsAutoSize_ = true;
        bool handlesTableNeedsAutoSize_ = true;
        bool tokenShowEnabledOnly_ = false;
        MemoryFilter memoryFilter_ = MemoryFilter::All;
        float inspectorTabScrollX_ = 0.0f;
        int inspectorTabEdgeHoverDirection_ = 0;
        ULONGLONG inspectorTabEdgeHoverStartedMs_ = 0;
        ULONGLONG inspectorTabAutoScrollCooldownUntilMs_ = 0;
        bool networkLoaded_ = false;
        bool networkIndicatorLoadAttempted_ = false;
        bool networkIndicatorUpdateAttempted_ = false;
        bool networkIndicatorUsedFallback_ = false;
        bool networkIndicatorUpdateInProgress_ = false;
        std::atomic_bool longOperationRunning_ = false;
        std::atomic_bool longOperationCompleted_ = false;
        bool longOperationResultVisible_ = false;
        int longOperationResultVisibleFrame_ = -1;
        bool longOperationCloseClickArmed_ = false;
        bool loadedSnapshotActive_ = false;
        bool liveSnapshotPreserved_ = false;
        bool liveNetworkLoadedBeforeLoad_ = false;
        bool comInitialized_ = false;
        bool pickWindowActive_ = false;
        bool pickerOverlayClassRegistered_ = false;
        bool scrollSelectedProcessIntoView_ = false;
        bool aboutPopupRequested_ = false;
        bool resetLayoutPopupRequested_ = false;
        bool networkIntelUpdatePopupRequested_ = false;
        bool deepEvidenceSnapshotPopupRequested_ = false;
        bool networkIntelUpdateDoNotShowAgainChoice_ = false;
        bool networkIntelUpdateConfirmationSuppressed_ = false;
        int aboutPopupOpenedFrame_ = -1;
        int resetLayoutPopupOpenedFrame_ = -1;
        int networkIntelUpdatePopupOpenedFrame_ = -1;
        int deepEvidenceSnapshotPopupOpenedFrame_ = -1;
        ProcessFilterMode processFilterMode_ = ProcessFilterMode::All;
        TriageFilter triageFilter_ = TriageFilter::All;
        HandleFilter handleFilter_ = HandleFilter::All;
        InspectorTab inspectorTab_ = InspectorTab::Triage;
        std::array<bool, InspectorTabs.size()> inspectorDockViewOpen_ = {};
        std::array<char, 256> searchBuffer_ = {};
        std::array<char, 256> handleSearchBuffer_ = {};
        std::array<char, 256> memorySearchBuffer_ = {};
        std::wstring searchText_;
        std::wstring handleSearchText_;
        std::wstring memorySearchText_;
        std::wstring lastRefreshTime_ = L"(not refreshed)";
        std::wstring lastNetworkRefreshTime_ = L"(not refreshed)";
        std::wstring loadedSnapshotStatus_;
        std::wstring liveLastRefreshTimeBeforeLoad_;
        std::wstring liveLastNetworkRefreshTimeBeforeLoad_;
        std::string lastTriageRecomputeLogMessage_;
        LongRunningOperationKind longOperationKind_ = LongRunningOperationKind::None;
        std::string longOperationTitle_;
        std::string longOperationStatus_;
        float longOperationProgress_ = 0.0f;
        std::size_t suspiciousCount_ = 0;
        std::size_t liveSuspiciousCountBeforeLoad_ = 0;
        std::uint32_t liveSelectedPidBeforeLoad_ = InvalidPid;
        CollectorTimings timings_;
        bool findingsCacheValid_ = false;
        bool selectedHighTriageCacheValid_ = false;
        bool graphFitRequested_ = true;
        bool graphLayoutDirty_ = true;
        bool graphLeftCanvasPanActive_ = false;
        bool graphLeftMouseDownStartedOnNode_ = false;
        bool visibleProcessRowsDirty_ = true;
        bool timelineRowsDirty_ = true;
        bool visibleHandlesDirty_ = true;
        bool visibleMemoryRegionsDirty_ = true;
        bool graphLayoutHasWorldBounds_ = false;
        bool graphLayoutSingleNode_ = false;
        bool graphLayoutSmallGraph_ = false;
        std::uint32_t findingsCachePid_ = InvalidPid;
        std::uint32_t selectedChainCachePid_ = InvalidPid;
        std::uint32_t selectedHighTriagePid_ = InvalidPid;
        std::uint32_t graphFitPid_ = InvalidPid;
        std::uint32_t graphLayoutFocusPid_ = InvalidPid;
        std::uint32_t visibleHandlesPid_ = InvalidPid;
        std::uint32_t visibleMemoryPid_ = InvalidPid;
        std::size_t graphFitNodeCount_ = 0;
        std::size_t graphLayoutNodeCount_ = 0;
        std::size_t graphLayoutEdgeCount_ = 0;
        std::size_t visibleHandlesSourceSize_ = 0;
        std::size_t visibleMemorySourceSize_ = 0;
        std::size_t visibleHandlesWithIndicatorsCount_ = 0;
        std::size_t visibleHandlesNameStatusCount_ = 0;
        std::uint64_t selectedHighTriageCreationTime_ = 0;
        std::uint64_t snapshotGeneration_ = 0;
        std::uint64_t processQueryRevision_ = 0;
        std::uint64_t visibleProcessRowsSnapshotGeneration_ = 0;
        std::uint64_t visibleProcessRowsQueryRevision_ = 0;
        std::uint64_t timelineRowsSnapshotGeneration_ = 0;
        std::uint64_t timelineRowsQueryRevision_ = 0;
        std::uint64_t visibleHandlesCreationTime_ = 0;
        std::uint64_t visibleMemoryCreationTime_ = 0;
        bool selectedHighTriage_ = false;
        float graphZoom_ = 1.0f;
        ImVec2 graphPan_ = ImVec2(0.0f, 0.0f);
        ImVec2 graphLayoutBaseNodeSize_ = ImVec2(302.0f, 106.0f);
        ImVec2 graphLayoutWorldMin_ = ImVec2(0.0f, 0.0f);
        ImVec2 graphLayoutWorldMax_ = ImVec2(0.0f, 0.0f);
        Core::TimelineFilter timelineRowsFilter_ = Core::TimelineFilter::All;
        HandleFilter visibleHandlesFilter_ = HandleFilter::All;
        MemoryFilter visibleMemoryFilter_ = MemoryFilter::All;
        GraphLayoutMode graphFitLayoutMode_ = GraphLayoutMode::TopDown;
        GraphLayoutMode graphLayoutMode_ = GraphLayoutMode::TopDown;
        GraphLayoutMode graphLayoutCachedMode_ = GraphLayoutMode::TopDown;
        std::wstring visibleHandlesSearchText_;
        std::wstring visibleMemorySearchText_;
        std::vector<VisibleProcessRow> visibleProcessRows_;
        std::vector<Core::TimelineRow> cachedTimelineRows_;
        std::vector<std::pair<std::size_t, std::size_t>> compareChangedProcessRows_;
        std::vector<Core::NetworkIndicatorMatch> networkIndicatorMatches_;
        std::vector<GraphLayoutNode> graphLayoutNodes_;
        std::vector<std::size_t> visibleHandleIndexes_;
        std::vector<std::size_t> visibleMemoryRegionIndexes_;
        std::vector<Core::Finding> selectedFindingsCache_;
        std::vector<LogEntry> logs_;
        std::unordered_map<std::wstring, CachedIconTexture> iconCache_;
        std::unordered_map<std::wstring, Core::FileIdentity> fileIdentityCache_;
        std::unordered_map<std::wstring, Core::ModuleCollectionResult> moduleEvidenceCache_;
        std::unordered_map<std::wstring, Core::TokenInfo> tokenEvidenceCache_;
        std::unordered_map<std::wstring, Core::RuntimeInfo> runtimeEvidenceCache_;
        std::unordered_map<std::wstring, Core::MemoryCollectionResult> memoryEvidenceCache_;
        std::unordered_map<std::wstring, Core::HandleCollectionResult> handleEvidenceCache_;
        std::unordered_map<std::wstring, std::vector<std::size_t>> networkIndicatorMatchIndexesByRemote_;
        std::unordered_map<std::uint32_t, std::size_t> graphLayoutNodeIndexByPid_;
        ID3D11ShaderResourceView* fallbackIconTexture_ = nullptr;
        ID3D11ShaderResourceView* appLogoTexture_ = nullptr;

        ImGuiID dockspaceId_ = 0;
        ImGuiID leftDockId_ = 0;
        ImGuiID centerDockId_ = 0;
        ImGuiID rightDockId_ = 0;
        ImGuiID bottomDockId_ = 0;
        bool dockspaceBuilt_ = false;
        bool resetDockLayoutRequested_ = false;
        bool dockLayoutFocusRequested_ = false;
        bool rightDockLayoutFocusRequested_ = false;
    };

    int RunImGuiApp(HINSTANCE instance, int showCommand)
    {
        ImGuiApp app(instance);
        if (!app.Create(showCommand))
        {
            return -1;
        }
        return app.Run();
    }
}


