#include "ImGuiApp.h"

#include "Fonts.h"
#include "ComparePanel.h"
#include "HeaderPanel.h"
#include "InspectorPresentation.h"
#include "LogsPanel.h"
#include "Modals.h"
#include "ProcessPanel.h"
#include "Theme.h"
#include "UiHelpers.h"
#include "TimelinePanel.h"

#include "../Core/ChainAnalysis.h"
#include "../Core/AuthoritativeTriage.h"
#include "../Core/FileIdentity.h"
#include "../Core/GraphModel.h"
#include "../Core/HandleCollector.h"
#include "../Core/MemoryCollector.h"
#include "../Core/ModuleCollector.h"
#include "../Core/NetworkCollector.h"
#include "../Core/NetworkIndicatorMatcher.h"
#include "../Core/NetworkIndicatorUpdater.h"
#include "../Core/NativeHandleObservationBuilder.h"
#include "../Core/NativeSourceEvidence.h"
#include "../Core/ObservationShadow.h"
#include "../Core/ProcessCollector.h"
#include "../Core/ProcessIconPolicy.h"
#include "../Core/ProductVersion.h"
#include "../Core/ProcessTree.h"
#include "../Core/ProcessTriageCache.h"
#include "../Core/RuntimeCollector.h"
#include "../Core/SelectedProcessEnrichedLifecycle.h"
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
#include <chrono>
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
#include <stdexcept>
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
            ExecutableContext,
            Rwx
        };

        enum class TriageFilter
        {
            All,
            Contributing,
            Context,
            Limitations
        };

        enum class HandleFilter
        {
            All,
            MaterialAccess,
            Process,
            Token,
            File,
            Registry,
            NamedObjects,
            WithAccessCategories
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
            Core::ProcessIconState state = Core::ProcessIconState::Unavailable;
            Core::ProcessIconTextureOwnership ownership =
                Core::ProcessIconTextureOwnership::None;
            std::string diagnostic;
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
            return Core::ProductVersion::CurrentDisplayVersion;
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

        Core::NativeHandleAccessCategories HandleAccessCategories(
            const Core::HandleInfo& handle)
        {
            return Core::CategorizeNativeHandleAccess(
                Core::ClassifyNativeHandleObjectKind(handle),
                handle.grantedAccessRaw);
        }

        bool HandleHasMaterialAccess(const Core::HandleInfo& handle)
        {
            const Core::NativeHandleAccessCategories access =
                HandleAccessCategories(handle);
            return access.HasSensitiveProcessAccess() ||
                access.HasSensitiveThreadAccess() ||
                access.HasTokenManipulationAccess();
        }

        std::wstring HandleAccessCategoryText(const Core::HandleInfo& handle)
        {
            const Core::NativeHandleAccessCategories access =
                HandleAccessCategories(handle);
            std::vector<std::wstring> labels;
            if (access.synchronize) labels.push_back(L"Synchronize");
            if (access.query) labels.push_back(L"Query");
            if (access.vmRead) labels.push_back(L"VM read");
            if (access.vmWrite) labels.push_back(L"VM write");
            if (access.vmOperation) labels.push_back(L"VM operation");
            if (access.createThread) labels.push_back(L"Create thread");
            if (access.duplicateHandle) labels.push_back(L"Duplicate handle");
            if (access.createProcess) labels.push_back(L"Create process");
            if (access.threadSetContext) labels.push_back(L"Set thread context");
            if (access.threadImpersonate) labels.push_back(L"Thread impersonation");
            if (access.tokenDuplicate) labels.push_back(L"Duplicate token");
            if (access.tokenAssignPrimary) labels.push_back(L"Assign primary token");
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
            case HandleFilter::MaterialAccess:
                return HandleHasMaterialAccess(handle);
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
            case HandleFilter::WithAccessCategories:
                return !HandleAccessCategoryText(handle).empty();
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
            searchable += ToLower(HandleAccessCategoryText(handle));
            searchable += L" ";
            searchable += ToLower(HandleStatusText(handle));
            return searchable.find(loweredSearch) != std::wstring::npos;
        }

        bool HasExecutableMemoryContext(const Core::MemoryRegionInfo& region)
        {
            return region.isExecutable &&
                (region.isWritable || region.isPrivate ||
                    (!region.isImage && !region.isMapped) || region.isGuard);
        }

        std::wstring MemoryAttributeText(const Core::MemoryRegionInfo& region)
        {
            std::vector<std::wstring> attributes;
            if (region.isExecutable && region.isWritable)
            {
                attributes.push_back(L"Writable executable");
            }
            if (region.isExecutable && region.isPrivate)
            {
                attributes.push_back(L"Private executable");
            }
            if (region.isExecutable && !region.isImage && !region.isMapped)
            {
                attributes.push_back(L"Executable without image/mapped backing");
            }
            if (region.isGuard)
            {
                attributes.push_back(L"Guard-page protection");
            }
            if (attributes.empty() && region.isExecutable)
            {
                attributes.push_back(L"Executable");
            }
            return JoinWide(attributes, L"; ");
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
            case MemoryFilter::ExecutableContext:
                return HasExecutableMemoryContext(region);
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
            searchable += ToLower(MemoryAttributeText(region));
            return searchable.find(loweredSearch) != std::wstring::npos;
        }

        Core::Severity HistoricalFindingSeverityAsCoreSeverity(
            Core::FindingSeverity severity)
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

        std::wstring TriageFilterLabel(TriageFilter filter)
        {
            switch (filter)
            {
            case TriageFilter::Contributing:
                return L"Contributing";
            case TriageFilter::Context:
                return L"Context";
            case TriageFilter::Limitations:
                return L"Limitations";
            case TriageFilter::All:
            default:
                return L"All";
            }
        }

        bool NativeEvidenceMatchesFilter(
            const Core::NativeSourceEvidenceRecord& evidence,
            TriageFilter filter)
        {
            switch (filter)
            {
            case TriageFilter::Contributing:
                return evidence.contributedToVerdict;
            case TriageFilter::Context:
                return !evidence.contributedToVerdict &&
                    !evidence.collectionLimitation;
            case TriageFilter::Limitations:
                return evidence.collectionLimitation ||
                    evidence.disposition ==
                        Core::ObservationDisposition::CollectionNote ||
                    evidence.disposition ==
                        Core::ObservationDisposition::EvidenceIntegrityNote;
            case TriageFilter::All:
            default:
                return true;
            }
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

                // Selected-process lifecycle work is driven before ImGui starts
                // the frame. Rendering only reads the last atomic publication.
                ProcessSelectedProcessEnrichedLifecycle();

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
                    RebuildProcessTriageCacheAfterEvidenceMutation();
                    InvalidateSelectedNativeEvidence(
                        Core::SelectedProcessEnrichedRebuildReason::
                            ExactIndicatorMatchesChanged);
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
                RebuildProcessTriageCacheAfterEvidenceMutation();
                InvalidateSelectedNativeEvidence(
                    Core::SelectedProcessEnrichedRebuildReason::
                        ExactIndicatorMatchesChanged);
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

        Core::ProcessTriageCacheSourceStamp CurrentProcessTriageCacheStamp() const
        {
            Core::ProcessTriageCacheSourceStamp stamp;
            stamp.processGeneration = snapshotGeneration_;
            stamp.evidenceGeneration = baselineEvidenceGeneration_;
            stamp.scopeGeneration = baselineScopeGeneration_;
            stamp.loadedSnapshot = loadedSnapshotActive_;
            return stamp;
        }

        Core::PersistedTriageContext CaptureAuthoritativeTriageContext() const
        {
            std::vector<Core::PersistedProcessTriageRecord> records;
            records.reserve((std::min)(
                snapshot_.processes.size(),
                Core::PersistedTriageMaxProcessRecords));
            std::optional<Core::PersistedProcessTriageRecord> selectedRecord;
            const Core::ProcessInfo* selectedProcess =
                Core::FindProcessByPid(snapshot_, selectedPid_);

            if (loadedSnapshotActive_ &&
                loadedSnapshotMetadata_.schemaVersion >=
                    Export::GlassPaneSnapshotTriageSchemaVersion)
            {
                records = loadedSnapshotTriage_.processRecords;
                // Schema 5 has no legacy runtime authority. Preserve captured
                // TriageEngine summaries, but downgrade a schema-4 captured
                // legacy-fallback record to the honest NotCaptured state.
                for (Core::PersistedProcessTriageRecord& record : records)
                {
                    if (record.summary.analysisLevel ==
                        Core::PersistedTriageAnalysisLevel::LegacyFallback)
                    {
                        record.summary =
                            Core::MakeNotCapturedPersistedTriageSummary();
                    }
                }
                if (selectedProcess != nullptr)
                {
                    const Core::ProcessIdentityKey selectedIdentity =
                        Core::MakeProcessIdentityKey(*selectedProcess);
                    if (loadedSnapshotTriage_.selectedRecord.has_value() &&
                        loadedSnapshotTriage_.selectedRecord->identity ==
                            selectedIdentity)
                    {
                        selectedRecord = loadedSnapshotTriage_.selectedRecord;
                        if (selectedRecord->summary.analysisLevel ==
                            Core::PersistedTriageAnalysisLevel::LegacyFallback)
                        {
                            selectedRecord->summary =
                                Core::MakeNotCapturedPersistedTriageSummary();
                        }
                    }
                }
                return Core::MakePersistedTriageContext(
                    std::move(records),
                    std::move(selectedRecord));
            }

            const Core::ProcessTriageCacheSourceStamp expectedStamp =
                CurrentProcessTriageCacheStamp();
            for (const Core::ProcessInfo& process : snapshot_.processes)
            {
                Core::PersistedProcessTriageRecord record;
                record.identity = Core::MakeProcessIdentityKey(process);
                if (loadedSnapshotActive_)
                {
                    record.summary =
                        Core::MakeNotCapturedPersistedTriageSummary();
                }
                else
                {
                    const Core::ProcessTriageAuthority authority =
                        Core::SelectNativeProcessTriageAuthority(
                            processTriageCache_,
                            process,
                            expectedStamp);
                    Core::PersistedTriageProjectionResult projection;
                    if (authority.UsesBaselineTriage())
                    {
                        const std::size_t baselineSourceCount = (std::min)(
                            authority.baseline->baseline.nativeFactCount,
                            Core::PersistedTriageMaxSourceEvidenceCount);
                        projection = Core::ProjectPersistedTriageSummary(
                            authority.baseline->triage,
                            Core::PersistedTriageAnalysisLevel::Baseline,
                            baselineSourceCount);
                    }
                    else
                    {
                        record.summary =
                            Core::MakeNotCapturedPersistedTriageSummary();
                    }
                    if (projection.success)
                    {
                        record.summary = std::move(projection.summary);
                    }
                    else
                    {
                        record.summary =
                            Core::MakeNotCapturedPersistedTriageSummary();
                    }
                }
                records.push_back(std::move(record));
            }

            if (selectedProcess != nullptr)
            {
                const Core::ProcessIdentityKey selectedIdentity =
                    Core::MakeProcessIdentityKey(*selectedProcess);
                if (!loadedSnapshotActive_ &&
                    SelectedProcessEnrichedPublicationMatchesCurrent() &&
                    Core::ObservationShadowMatches(
                        selectedObservationShadow_,
                        true,
                        selectedProcess->pid,
                        ProcessCacheStamp(*selectedProcess),
                        selectedEvidenceGeneration_))
                {
                    const Core::SelectedProcessTriageAuthority authority =
                        Core::SelectNativeSelectedProcessTriageAuthority(
                            selectedObservationShadow_,
                            true,
                            *selectedProcess,
                            selectedEvidenceGeneration_,
                            ObservationShadowEntityScope(
                                *selectedProcess,
                                false),
                            processTriageCache_,
                            expectedStamp);
                    const std::size_t sourceCount = (std::min)(
                        selectedObservationShadow_.inventory.records.size(),
                        Core::PersistedTriageMaxSourceEvidenceCount);
                    Core::PersistedTriageProjectionResult projection;
                    if (authority.UsesEnrichedTriage() &&
                        authority.triageResult != nullptr &&
                        authority.baselineTriageResult != nullptr)
                    {
                        projection = Core::ProjectPersistedTriageSummary(
                            *authority.triageResult,
                            Core::PersistedTriageAnalysisLevel::Enriched,
                            sourceCount,
                            authority.baselineTriageResult);
                    }
                    if (projection.success)
                    {
                        Core::PersistedProcessTriageRecord enriched;
                        enriched.identity = selectedIdentity;
                        enriched.summary = std::move(projection.summary);
                        selectedRecord = std::move(enriched);
                    }
                }
            }

            return Core::MakePersistedTriageContext(
                std::move(records),
                std::move(selectedRecord));
        }

        Core::PersistedTriageSummary CaptureSelectedAuthoritativeTriageSummary() const
        {
            const Core::PersistedTriageContext context =
                CaptureAuthoritativeTriageContext();
            if (context.selectedRecord.has_value())
            {
                return context.selectedRecord->summary;
            }
            if (const Core::ProcessInfo* selectedProcess =
                    Core::FindProcessByPid(snapshot_, selectedPid_);
                selectedProcess != nullptr)
            {
                if (const Core::PersistedProcessTriageRecord* baseline =
                        context.FindProcess(
                            Core::MakeProcessIdentityKey(*selectedProcess));
                    baseline != nullptr)
                {
                    return baseline->summary;
                }
            }
            return Core::MakeNotCapturedPersistedTriageSummary();
        }

        Export::SavedNativeSourceEvidenceContext
        CaptureNativeSourceEvidenceContext() const
        {
            if (loadedSnapshotActive_)
            {
                return loadedSnapshotMetadata_.schemaVersion >=
                        Export::GlassPaneSnapshotNativeEvidenceSchemaVersion
                    ? loadedSnapshotNativeSourceEvidence_
                    : Export::SavedNativeSourceEvidenceContext{};
            }

            Export::SavedNativeSourceEvidenceContext context;
            const Core::ProcessInfo* process =
                Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr ||
                !SelectedProcessEnrichedPublicationMatchesCurrent() ||
                !selectedNativeSourceEvidence_.success ||
                !Core::ObservationShadowMatches(
                    selectedObservationShadow_,
                    true,
                    process->pid,
                    ProcessCacheStamp(*process),
                    selectedEvidenceGeneration_))
            {
                return context;
            }

            Export::SavedNativeSourceEvidenceRecord selected;
            selected.identity = Core::MakeProcessIdentityKey(*process);
            selected.records = selectedNativeSourceEvidence_.records;
            context.selectedRecord = std::move(selected);
            return context;
        }

        bool ProcessAuthorityProjectionMatchesCurrent() const
        {
            return processAuthorityProjectionValid_ &&
                processAuthorityProjectionStamp_ == CurrentProcessTriageCacheStamp() &&
                processAuthoritySeverities_.size() == snapshot_.processes.size() &&
                processAuthoritySuspicious_.size() == snapshot_.processes.size() &&
                processAuthorityAvailable_.size() == snapshot_.processes.size() &&
                processAuthorityUnavailableKinds_.size() == snapshot_.processes.size();
        }

        Core::Severity ProcessAuthoritySeverityAt(std::size_t processIndex) const
        {
            if (ProcessAuthorityProjectionMatchesCurrent() &&
                processIndex < processAuthoritySeverities_.size())
            {
                return processAuthoritySeverities_[processIndex];
            }
            return Core::Severity::None;
        }

        bool ProcessAuthorityUnavailableAt(std::size_t processIndex) const
        {
            return !ProcessAuthorityProjectionMatchesCurrent() ||
                processIndex >= processAuthorityUnavailableKinds_.size() ||
                processAuthorityUnavailableKinds_[processIndex] !=
                    Core::ProcessTriageUnavailableKind::None;
        }

        bool ProcessAuthorityIsSuspiciousAt(std::size_t processIndex) const
        {
            if (ProcessAuthorityProjectionMatchesCurrent() &&
                processIndex < processAuthoritySuspicious_.size())
            {
                return processAuthoritySuspicious_[processIndex] != 0;
            }
            return false;
        }

        std::size_t ProcessIndexForAuthority(const Core::ProcessInfo& process) const
        {
            const auto indexed = snapshot_.indexByPid.find(process.pid);
            if (indexed == snapshot_.indexByPid.end() ||
                indexed->second >= snapshot_.processes.size())
            {
                return snapshot_.processes.size();
            }

            const Core::ProcessInfo& indexedProcess = snapshot_.processes[indexed->second];
            if (&indexedProcess == &process)
            {
                return indexed->second;
            }

            // Duplicate PID rows are a bounded exceptional case. Resolve the
            // exact snapshot object before considering an identity-equivalent
            // external value; never project one creation identity onto another.
            for (std::size_t processIndex = 0;
                processIndex < snapshot_.processes.size();
                ++processIndex)
            {
                if (&snapshot_.processes[processIndex] == &process)
                {
                    return processIndex;
                }
            }

            return Core::MakeProcessIdentityKey(indexedProcess) ==
                    Core::MakeProcessIdentityKey(process)
                ? indexed->second
                : snapshot_.processes.size();
        }

        Core::Severity ProcessAuthoritySeverity(const Core::ProcessInfo& process) const
        {
            const std::size_t processIndex = ProcessIndexForAuthority(process);
            return processIndex < snapshot_.processes.size()
                ? ProcessAuthoritySeverityAt(processIndex)
                : Core::Severity::None;
        }

        bool ProcessAuthorityIsSuspicious(const Core::ProcessInfo& process) const
        {
            const std::size_t processIndex = ProcessIndexForAuthority(process);
            return processIndex < snapshot_.processes.size()
                ? ProcessAuthorityIsSuspiciousAt(processIndex)
                : false;
        }

        void RebuildProcessAuthorityProjection()
        {
            const auto started = std::chrono::steady_clock::now();
            const Core::ProcessTriageCacheSourceStamp expectedStamp =
                CurrentProcessTriageCacheStamp();

            std::vector<Core::Severity> nextSeverities;
            std::vector<std::uint8_t> nextSuspicious;
            std::vector<std::uint8_t> nextAvailable;
            std::vector<Core::ProcessTriageUnavailableKind> nextUnavailableKinds;
            nextSeverities.reserve(snapshot_.processes.size());
            nextSuspicious.reserve(snapshot_.processes.size());
            nextAvailable.reserve(snapshot_.processes.size());
            nextUnavailableKinds.reserve(snapshot_.processes.size());

            std::size_t nextSuspiciousCount = 0;
            std::size_t nextUnavailableCount = 0;
            std::array<
                std::size_t,
                static_cast<std::size_t>(
                    Core::ProcessTriageUnavailableKind::InvalidVerdict) + 1>
                nextUnavailableCountsByKind{};
            std::array<
                std::string,
                static_cast<std::size_t>(
                    Core::ProcessTriageUnavailableKind::InvalidVerdict) + 1>
                nextUnavailableFirstIdentityByKind{};
            std::array<
                std::string,
                static_cast<std::size_t>(
                    Core::ProcessTriageUnavailableKind::InvalidVerdict) + 1>
                nextUnavailableFirstDiagnosticByKind{};
            for (const Core::ProcessInfo& process : snapshot_.processes)
            {
                Core::TriageVerdict projectedVerdict =
                    Core::TriageVerdict::Informational;
                Core::ProcessTriageUnavailableKind unavailableKind =
                    Core::ProcessTriageUnavailableKind::CacheNotAttempted;
                bool unavailable = true;
                std::string unavailableDiagnostic;

                if (loadedSnapshotActive_)
                {
                    const Core::PersistedProcessTriageRecord* record =
                        loadedSnapshotTriage_.FindProcess(
                            Core::MakeProcessIdentityKey(process));
                    if (record != nullptr && record->summary.captured &&
                        record->summary.evaluationSucceeded &&
                        !record->summary.usingFallback)
                    {
                        projectedVerdict = record->summary.authoritativeVerdict;
                        unavailable = false;
                        unavailableKind =
                            Core::ProcessTriageUnavailableKind::None;
                    }
                    else
                    {
                        projectedVerdict =
                            Core::TriageVerdict::Informational;
                        unavailable = true;
                        unavailableKind =
                            Core::ProcessTriageUnavailableKind::BaselineEntryMissing;
                        unavailableDiagnostic =
                            "No successful captured TriageEngine result matched the process identity.";
                    }
                }
                else
                {
                    const Core::ProcessTriageAuthority authority =
                        Core::SelectNativeProcessTriageAuthority(
                            processTriageCache_,
                            process,
                            expectedStamp);
                    projectedVerdict = authority.verdict;
                    unavailable = authority.unavailable;
                    unavailableKind = authority.unavailableKind;
                    unavailableDiagnostic = authority.unavailableReason;
                }

                const Core::TriageSurfaceClassification classification =
                    Core::ClassifyTriageVerdictForSurfaces(projectedVerdict);
                nextSeverities.push_back(classification.severity);
                nextSuspicious.push_back(classification.suspicious ? 1U : 0U);
                nextAvailable.push_back(
                    unavailableKind == Core::ProcessTriageUnavailableKind::None
                        ? 1U
                        : 0U);
                nextUnavailableKinds.push_back(unavailableKind);
                if (classification.suspicious)
                {
                    ++nextSuspiciousCount;
                }
                if (unavailable)
                {
                    ++nextUnavailableCount;
                    const std::size_t unavailableIndex =
                        static_cast<std::size_t>(unavailableKind);
                    if (unavailableIndex < nextUnavailableCountsByKind.size())
                    {
                        ++nextUnavailableCountsByKind[unavailableIndex];
                        if (nextUnavailableFirstIdentityByKind[
                                unavailableIndex].empty())
                        {
                            nextUnavailableFirstIdentityByKind[unavailableIndex] =
                                "PID " + std::to_string(process.pid) +
                                (process.hasCreationTime
                                    ? ", creation " + std::to_string(
                                        process.creationTimeFileTime)
                                    : ", creation unavailable");
                            nextUnavailableFirstDiagnosticByKind[
                                unavailableIndex] = unavailableDiagnostic;
                        }
                    }
                }
            }

            processAuthoritySeverities_ = std::move(nextSeverities);
            processAuthoritySuspicious_ = std::move(nextSuspicious);
            processAuthorityAvailable_ = std::move(nextAvailable);
            processAuthorityUnavailableKinds_ = std::move(nextUnavailableKinds);
            processAuthorityProjectionStamp_ = expectedStamp;
            processAuthorityProjectionValid_ = true;
            processAuthorityUnavailableCount_ = nextUnavailableCount;
            processAuthorityUnavailableCountsByKind_ =
                nextUnavailableCountsByKind;
            processAuthorityUnavailableFirstIdentityByKind_ =
                std::move(nextUnavailableFirstIdentityByKind);
            processAuthorityUnavailableFirstDiagnosticByKind_ =
                std::move(nextUnavailableFirstDiagnosticByKind);
            suspiciousCount_ = nextSuspiciousCount;
            processAuthorityProjectionBuildMicroseconds_ =
                ObservationShadowElapsedMicroseconds(started);

            visibleProcessRowsDirty_ = true;
            timelineRowsDirty_ = true;
            if (selectedPid_ != InvalidPid)
            {
                RebuildFocusedGraph("authority-projection");
            }
        }

        void RebuildProcessTriageCache()
        {
            const Core::ProcessTriageCacheSourceStamp expectedStamp =
                CurrentProcessTriageCacheStamp();
            if (loadedSnapshotActive_)
            {
                // Offline review uses captured authority exactly. Older
                // schemas remain explicitly not captured; current policy is
                // never run implicitly against historical evidence.
                processTriageCache_ = {};
                if (!ProcessAuthorityProjectionMatchesCurrent())
                {
                    RebuildProcessAuthorityProjection();
                }
                return;
            }
            if (processTriageCache_.MatchesStamp(expectedStamp))
            {
                if (!ProcessAuthorityProjectionMatchesCurrent())
                {
                    RebuildProcessAuthorityProjection();
                }
                return;
            }

            ++baselineCacheBuildInvocationCount_;
            Core::ProcessTriageCache next;
            try
            {
                Core::ProcessTriageCacheBuildOptions options;
                options.sourceStamp = expectedStamp;
                options.sourceKind = loadedSnapshotActive_
                    ? Core::ObservationSourceKind::Imported
                    : Core::ObservationSourceKind::Direct;
                options.collectionTimestamp = WideToUtf8(lastRefreshTime_);
                options.networkContextCaptured = networkLoaded_;
                options.networkCollectionAttempted = networkLoaded_;
                options.serviceContextCaptured = serviceSnapshot_.attempted;
                if (loadedSnapshotActive_ && !networkLoaded_)
                {
                    options.limitations.push_back(
                        "Network context was not captured in this saved snapshot.");
                }
                if (loadedSnapshotActive_ && !serviceSnapshot_.attempted)
                {
                    options.limitations.push_back(
                        "Service context was not captured in this saved snapshot.");
                }

                next = Core::BuildProcessTriageCache(
                    snapshot_,
                    networkSnapshot_,
                    networkIndicatorMatches_,
                    serviceSnapshot_,
                    options);
            }
            catch (...)
            {
                next.attempted = true;
                next.success = false;
                next.status = Core::ProcessTriageCacheStatus::InternalFailure;
                next.sourceStamp = expectedStamp;
                next.summary.sourceProcessCount = snapshot_.processes.size();
                next.summary.failedEntryCount = snapshot_.processes.size();
                next.statusMessage =
                    "Baseline process triage cache construction failed; no partial candidate was installed.";
            }
            processTriageCache_ = std::move(next);
            RebuildProcessAuthorityProjection();
        }

        void RebuildProcessTriageCacheAfterEvidenceMutation()
        {
            ++baselineEvidenceGeneration_;
            RebuildProcessTriageCache();
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
            RebuildProcessTriageCacheAfterEvidenceMutation();
            InvalidateSelectedNativeEvidence(
                Core::SelectedProcessEnrichedRebuildReason::NetworkChanged);

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

        std::filesystem::path AlternateLocalNetworkIndicatorFeedPath() const
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
                const std::filesystem::path fallbackPath = AlternateLocalNetworkIndicatorFeedPath();
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
                            "Intel feed portable path missing; using alternate local Indicators path: " +
                                WideToUtf8(loadPathText)
                        });
                    }

                    if (result.networkLoadResult.success)
                    {
                        result.status =
                            std::string("Intel feed loaded ") +
                            (usedFallback ? "from alternate local Indicators path: " : "from portable Indicators folder: ") +
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
                status += networkIndicatorUsedFallback_ ? L", loaded from alternate local Indicators path" : L", loaded from portable Indicators folder";
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
                return L"Source: alternate local Indicators path";
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

        void RenderFileIdentityFields(
            const char* id,
            const Core::FileIdentity& identity,
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

            ImGui::PopID();
        }

        void InvalidateSelectedNativeEvidence(
            Core::SelectedProcessEnrichedRebuildReason reason =
                Core::SelectedProcessEnrichedRebuildReason::
                    CollectionStateChanged,
            bool requestRebuild = true)
        {
            // This generation now identifies already-collected selected
            // evidence, not a legacy Finding recomputation.
            ++selectedEvidenceGeneration_;
            selectedNativeSourceEvidence_ = {};
            Core::ClearObservationShadowState(selectedObservationShadow_);
            const Core::SelectedProcessEnrichedSourceStamp currentSource =
                CurrentSelectedProcessEnrichedSourceStamp();
            Core::UpdateSelectedProcessEnrichedSelection(
                selectedEnrichedLifecycle_,
                currentSource);
            selectedEnrichedLifecycle_.publicationAccepted = false;
            selectedEnrichedLifecycle_.storedSource = {};
            if (requestRebuild)
            {
                RequestSelectedProcessEnrichedRebuild(reason);
            }
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
            ClearProcessIconAssignments(Core::ProcessIconRefreshKind::ProcessGenerationChanged);
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


        static std::string ObservationShadowEntityScope(
            const Core::ProcessInfo& process,
            bool loadedSnapshotActive)
        {
            std::string scope = loadedSnapshotActive
                ? "selected-process/snapshot/pid:"
                : "selected-process/live/pid:";
            scope += std::to_string(process.pid);
            scope += process.hasCreationTime
                ? "/created:" + std::to_string(process.creationTimeFileTime)
                : "/creation:unavailable";
            return scope;
        }

        Core::SelectedProcessEnrichedSourceStamp
        CurrentSelectedProcessEnrichedSourceStamp() const
        {
            Core::SelectedProcessEnrichedSourceStamp stamp;
            stamp.scope = loadedSnapshotActive_
                ? Core::SelectedProcessAnalysisScope::LoadedSnapshot
                : Core::SelectedProcessAnalysisScope::Live;
            stamp.processGeneration = snapshotGeneration_;
            stamp.evidenceGeneration = selectedEvidenceGeneration_;
            stamp.scopeGeneration = baselineScopeGeneration_;

            const Core::ProcessInfo* process =
                Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process != nullptr)
            {
                stamp.hasEntity = true;
                stamp.identity = Core::MakeProcessIdentityKey(*process);
                stamp.entityScope = ObservationShadowEntityScope(
                    *process,
                    loadedSnapshotActive_);
            }
            return stamp;
        }

        bool RequestSelectedProcessEnrichedRebuild(
            Core::SelectedProcessEnrichedRebuildReason reason)
        {
            return Core::RequestSelectedProcessEnrichedRebuild(
                selectedEnrichedLifecycle_,
                CurrentSelectedProcessEnrichedSourceStamp(),
                reason);
        }

        bool SelectedProcessEnrichedPublicationMatchesCurrent() const
        {
            return Core::SelectedProcessEnrichedPublicationMatches(
                selectedEnrichedLifecycle_,
                CurrentSelectedProcessEnrichedSourceStamp());
        }

        const Core::ObservationShadowState&
        AuthoritativeSelectedObservationShadow() const
        {
            static const Core::ObservationShadowState unavailable;
            return SelectedProcessEnrichedPublicationMatchesCurrent()
                ? selectedObservationShadow_
                : unavailable;
        }

        Core::ObservationShadowSourceContext BuildObservationShadowSourceContext(
            const Core::ProcessInfo& process) const
        {
            Core::ObservationShadowSourceContext context;
            context.entityScope = ObservationShadowEntityScope(process, loadedSnapshotActive_);
            context.sourceKind = loadedSnapshotActive_
                ? Core::ObservationSourceKind::Imported
                : Core::ObservationSourceKind::Derived;
            context.producerIdentifier = "core.native-observation-builder";
            context.collectionMethod = loadedSnapshotActive_
                ? "persisted-selected-process-native-evidence"
                : "live-selected-process-native-evidence";
            context.sourceAvailable = true;
            context.rawSourceReference = context.entityScope;

            const std::uint64_t creationTime = ProcessCacheStamp(process);

            // Native selected-process producers consume only values already
            // collected for this exact evidence generation. No collection or
            // policy parsing is performed from render code.
            context.nativeInputSupplied = true;
            Core::NativeSelectedProcessObservationInput& native =
                context.nativeInput;
            native.identity = Core::MakeProcessIdentityKey(process);
            native.entityScope = context.entityScope;

            native.commandLine.identity = native.identity;
            native.commandLine.supplied = true;
            native.commandLine.collectionAttempted = true;
            native.commandLine.available = process.commandLineAccessible;
            native.commandLine.commandLine = process.commandLineAccessible
                ? WideToUtf8(process.commandLine)
                : std::string{};
            native.commandLine.source.sourceKind = process.commandLineAccessible
                ? Core::ObservationSourceKind::Direct
                : Core::ObservationSourceKind::Unavailable;
            native.commandLine.source.completeness =
                process.commandLineAccessible
                    ? Core::ObservationSourceCompleteness::Complete
                    : Core::ObservationSourceCompleteness::Unavailable;
            native.commandLine.source.sourceIdentifier =
                "core.process-snapshot.command-line";
            native.commandLine.source.collectionMethod =
                "selected-process-snapshot";
            native.commandLine.source.rawSourceReference = context.entityScope;

            if (process.parentPid != 0 &&
                process.parentRelationshipVerified)
            {
                const Core::ProcessInfo* parent =
                    Core::FindProcessByPid(snapshot_, process.parentPid);
                if (parent != nullptr)
                {
                    bool correlationRelationship = false;
                    std::string relationshipRule =
                        "native.relationship.verified-parent-context";
                    if (selectedChainCacheValid_ &&
                        selectedChainCachePid_ == process.pid &&
                        selectedChainCacheCreationTime_ == creationTime &&
                        selectedChainCacheSnapshotGeneration_ ==
                            snapshotGeneration_)
                    {
                        const auto typedRelationship = std::find_if(
                            selectedChainCache_.chainIndicatorFacts.begin(),
                            selectedChainCache_.chainIndicatorFacts.end(),
                            [&](const Core::ChainIndicatorFact& fact)
                            {
                                return fact.kind ==
                                        Core::ChainIndicatorFactKind::ProcessRelationship &&
                                    fact.sourcePid == parent->pid &&
                                    fact.targetPid == process.pid &&
                                    !fact.sourceRuleId.empty();
                            });
                        if (typedRelationship !=
                            selectedChainCache_.chainIndicatorFacts.end())
                        {
                            correlationRelationship = true;
                            relationshipRule =
                                typedRelationship->sourceRuleId;
                        }
                    }

                    Core::NativeRelationshipFact relationship;
                    relationship.subjectIdentity = native.identity;
                    relationship.relatedIdentity =
                        Core::MakeProcessIdentityKey(*parent);
                    relationship.kind =
                        Core::NativeRelationshipKind::DirectParent;
                    relationship.semantics = correlationRelationship
                        ? Core::NativeRelationshipSemantics::ExecutionCorrelation
                        : Core::NativeRelationshipSemantics::Context;
                    relationship.verified = true;
                    relationship.semanticFactKey =
                        "relationship.parent|pid:" +
                        std::to_string(parent->pid) + "->pid:" +
                        std::to_string(process.pid);
                    relationship.sourceRuleId = relationshipRule;
                    relationship.rawValue =
                        "PID " + std::to_string(parent->pid) +
                        " -> PID " + std::to_string(process.pid);
                    relationship.normalizedValue =
                        "pid:" + std::to_string(parent->pid) +
                        "->pid:" + std::to_string(process.pid);
                    relationship.evidence.push_back(
                        "The process snapshot retained a verified parent identity link.");
                    relationship.source.sourceKind =
                        Core::ObservationSourceKind::Direct;
                    relationship.source.completeness =
                        Core::ObservationSourceCompleteness::Complete;
                    relationship.source.sourceIdentifier =
                        "core.process-tree";
                    relationship.source.collectionMethod =
                        "selected-process-chain-analysis";
                    relationship.source.rawSourceReference =
                        context.entityScope;
                    native.relationships.push_back(std::move(relationship));
                }
            }

            // Preserve the remainder of the already-verified process ancestry
            // as typed relationship context. These records are identity-keyed
            // and non-contributing; process names remain display data only.
            const std::vector<const Core::ProcessInfo*> parentChain =
                Core::GetParentChain(snapshot_, process.pid);
            const std::size_t ancestorEnd = parentChain.size() > 2
                ? parentChain.size() - 2
                : 0;
            std::size_t emittedAncestorCount = 0;
            for (std::size_t index = 0;
                index < ancestorEnd &&
                    native.relationships.size() <
                        Core::NativeObservationMaxRelationshipFacts;
                ++index)
            {
                const Core::ProcessInfo* ancestor = parentChain[index];
                if (ancestor == nullptr || ancestor->pid == process.pid)
                {
                    continue;
                }

                Core::NativeRelationshipFact relationship;
                relationship.subjectIdentity = native.identity;
                relationship.relatedIdentity =
                    Core::MakeProcessIdentityKey(*ancestor);
                relationship.kind = Core::NativeRelationshipKind::Ancestor;
                relationship.semantics =
                    Core::NativeRelationshipSemantics::Context;
                relationship.verified = true;
                relationship.semanticFactKey =
                    "relationship.ancestor|pid:" +
                    std::to_string(ancestor->pid) + "->pid:" +
                    std::to_string(process.pid);
                relationship.sourceRuleId =
                    "native.relationship.verified-ancestor-context";
                relationship.rawValue =
                    "Ancestor PID " + std::to_string(ancestor->pid) +
                    " -> selected PID " + std::to_string(process.pid);
                relationship.normalizedValue =
                    "ancestor-pid:" + std::to_string(ancestor->pid) +
                    "->pid:" + std::to_string(process.pid);
                relationship.evidence.push_back(
                    "The process snapshot retained a verified ancestry link.");
                relationship.source.sourceKind =
                    Core::ObservationSourceKind::Direct;
                relationship.source.completeness =
                    Core::ObservationSourceCompleteness::Complete;
                relationship.source.sourceIdentifier = "core.process-tree";
                relationship.source.collectionMethod =
                    "selected-process-chain-analysis";
                relationship.source.rawSourceReference = context.entityScope;
                native.relationships.push_back(std::move(relationship));
                ++emittedAncestorCount;
            }
            if (emittedAncestorCount < ancestorEnd)
            {
                native.limitations.push_back(
                    "Additional verified ancestry context was omitted by the bounded native relationship cap.");
            }

            if (!IsSyntheticSystemProcessEntry(process))
            {
                const auto identity = fileIdentityCache_.find(
                    ToLower(process.executablePath));
                if (identity != fileIdentityCache_.end())
                {
                    const Core::FileIdentity& file = identity->second;
                    native.fileIdentity.identity = native.identity;
                    native.fileIdentity.supplied = true;
                    native.fileIdentity.artifactKey =
                        "selected-process-executable";
                    native.fileIdentity.rawPath =
                        WideToUtf8(file.path);
                    native.fileIdentity.normalizedPath =
                        WideToUtf8(ToLower(file.path));
                    native.fileIdentity.pathContext =
                        Core::ClassifyNativeFilePathContext(
                            native.fileIdentity.normalizedPath);
                    if (!file.exists)
                    {
                        native.fileIdentity.signatureState =
                            Core::NativeFileSignatureState::Unavailable;
                    }
                    else if (!file.signaturePresent)
                    {
                        native.fileIdentity.signatureState =
                            Core::NativeFileSignatureState::SignatureAbsent;
                    }
                    else
                    {
                        native.fileIdentity.signatureState =
                            file.signatureValid
                                ? Core::NativeFileSignatureState::AuthenticatedValid
                                : Core::NativeFileSignatureState::AuthenticatedInvalid;
                    }
                    native.fileIdentity.signerSubject =
                        WideToUtf8(file.signerName);
                    native.fileIdentity.source.sourceKind = file.exists
                        ? Core::ObservationSourceKind::Direct
                        : Core::ObservationSourceKind::Unavailable;
                    native.fileIdentity.source.completeness = file.exists
                        ? Core::ObservationSourceCompleteness::Complete
                        : Core::ObservationSourceCompleteness::Unavailable;
                    native.fileIdentity.source.sourceIdentifier =
                        "core.file-identity";
                    native.fileIdentity.source.collectionMethod =
                        "selected-process-file-identity";
                    native.fileIdentity.source.rawSourceReference =
                        context.entityScope;
                    if (!file.errorMessage.empty())
                    {
                        native.fileIdentity.source.limitations.push_back(
                            WideToUtf8(file.errorMessage));
                    }
                }
            }

            if (networkLoaded_)
            {
                Core::NativeNetworkObservationInput& network =
                    native.network;
                network.identity = native.identity;
                network.supplied = true;
                network.collectionAttempted = true;
                network.available = networkSnapshot_.success;
                network.connections =
                    SelectedNetworkConnectionsForExport();
                if (network.connections.size() >
                    Core::NativeObservationMaxNetworkConnections)
                {
                    network.truncated = true;
                    network.omittedContextFactCount +=
                        network.connections.size() -
                        Core::NativeObservationMaxNetworkConnections;
                    network.connections.resize(
                        Core::NativeObservationMaxNetworkConnections);
                }
                network.exactIndicatorMatches =
                    SelectedNetworkIndicatorMatchesForProcess(process.pid);
                if (network.exactIndicatorMatches.size() >
                    Core::NativeObservationMaxNetworkIndicators)
                {
                    network.truncated = true;
                    network.omittedMaterialFactCount +=
                        network.exactIndicatorMatches.size() -
                        Core::NativeObservationMaxNetworkIndicators;
                    network.exactIndicatorMatches.resize(
                        Core::NativeObservationMaxNetworkIndicators);
                }
                network.source.sourceKind = networkSnapshot_.success
                    ? Core::ObservationSourceKind::Direct
                    : Core::ObservationSourceKind::Unavailable;
                network.source.completeness = networkSnapshot_.success
                    ? Core::ObservationSourceCompleteness::Complete
                    : Core::ObservationSourceCompleteness::Unavailable;
                network.source.sourceIdentifier =
                    "core.network-snapshot";
                network.source.collectionMethod =
                    "selected-process-network-context";
                network.source.rawSourceReference = context.entityScope;
                if (!networkSnapshot_.statusMessage.empty())
                {
                    network.source.limitations.push_back(
                        WideToUtf8(networkSnapshot_.statusMessage));
                }
            }

            if (ModulesLoadedForProcess(process))
            {
                Core::NativeModuleObservationInput& modules =
                    native.modules;
                modules.identity = native.identity;
                modules.supplied = true;
                modules.collectionAttempted = true;
                modules.available = selectedModules_.success;
                modules.collection = selectedModules_;
                if (modules.collection.modules.size() >
                    Core::NativeObservationMaxModules)
                {
                    modules.truncated = true;
                    modules.omittedContextFactCount =
                        modules.collection.modules.size() -
                        Core::NativeObservationMaxModules;
                    modules.collection.modules.resize(
                        Core::NativeObservationMaxModules);
                }
                modules.source.sourceKind = selectedModules_.success
                    ? Core::ObservationSourceKind::Direct
                    : Core::ObservationSourceKind::Unavailable;
                modules.source.completeness = selectedModules_.success
                    ? Core::ObservationSourceCompleteness::Complete
                    : Core::ObservationSourceCompleteness::Unavailable;
                modules.source.sourceIdentifier = "core.module-collector";
                modules.source.collectionMethod =
                    "selected-process-module-metadata";
                modules.source.rawSourceReference = context.entityScope;
                if (!selectedModules_.statusMessage.empty())
                {
                    modules.source.limitations.push_back(
                        WideToUtf8(selectedModules_.statusMessage));
                }
            }

            if (MemoryLoadedForProcess(process))
            {
                Core::NativeMemoryObservationInput& memory = native.memory;
                memory.identity = native.identity;
                memory.supplied = true;
                memory.collectionAttempted = true;
                memory.available = selectedMemory_.success;
                memory.collection = selectedMemory_;
                if (memory.collection.regions.size() >
                    Core::NativeObservationMaxMemoryRegions)
                {
                    memory.truncated = true;
                    memory.omittedContextFactCount =
                        memory.collection.regions.size() -
                        Core::NativeObservationMaxMemoryRegions;
                    memory.collection.regions.resize(
                        Core::NativeObservationMaxMemoryRegions);
                }
                memory.source.sourceKind = selectedMemory_.success
                    ? Core::ObservationSourceKind::Direct
                    : Core::ObservationSourceKind::Unavailable;
                memory.source.completeness = selectedMemory_.success
                    ? Core::ObservationSourceCompleteness::Complete
                    : Core::ObservationSourceCompleteness::Unavailable;
                memory.source.sourceIdentifier = "core.memory-collector";
                memory.source.collectionMethod =
                    "selected-process-static-memory-metadata";
                memory.source.rawSourceReference = context.entityScope;
                if (!selectedMemory_.statusMessage.empty())
                {
                    memory.source.limitations.push_back(
                        WideToUtf8(selectedMemory_.statusMessage));
                }
            }

            if (TokenLoadedForProcess(process))
            {
                Core::NativeTokenObservationInput& token = native.token;
                token.identity = native.identity;
                token.entityScope = context.entityScope;
                token.supplied = true;
                token.collectionAttempted = true;
                token.token = selectedToken_;
                if (token.token.privileges.size() >
                    Core::NativeTokenObservationMaxPrivileges)
                {
                    token.privilegesTruncated = true;
                    token.omittedPrivilegeCount =
                        token.token.privileges.size() -
                        Core::NativeTokenObservationMaxPrivileges;
                    token.token.privileges.resize(
                        Core::NativeTokenObservationMaxPrivileges);
                }
                token.source.sourceKind = selectedToken_.success
                    ? Core::ObservationSourceKind::Direct
                    : Core::ObservationSourceKind::Unavailable;
                token.source.completeness = selectedToken_.success
                    ? Core::NativeTokenSourceCompleteness::Complete
                    : Core::NativeTokenSourceCompleteness::Unavailable;
                token.source.sourceIdentifier = "core.token-collector";
                token.source.collectionMethod =
                    "selected-process-token-metadata";
                token.source.rawSourceReference = context.entityScope;
                if (!selectedToken_.errorMessage.empty())
                {
                    token.source.limitations.push_back(
                        WideToUtf8(selectedToken_.errorMessage));
                }
            }

            if (HandlesLoadedForProcess(process))
            {
                Core::NativeHandleObservationInput& handles =
                    native.handles;
                handles.sourceIdentity = native.identity;
                handles.entityScope = context.entityScope;
                handles.supplied = true;
                handles.collectionAttempted = true;
                handles.collection = selectedHandles_;
                handles.omittedHandleCount =
                    selectedHandles_.selectedProcessHandlesOmitted;
                handles.sourceTruncated =
                    selectedHandles_.queryBufferTruncated ||
                    selectedHandles_.retentionCapReached ||
                    handles.omittedHandleCount != 0;
                if (selectedHandles_.queryBufferTruncated &&
                    handles.omittedHandleCount == 0)
                {
                    // A successful native response that reports more rows than
                    // fit in its returned buffer leaves an unknown material
                    // tail. Represent the conservative lower bound explicitly.
                    handles.omittedHandleCount = 1;
                }
                if (handles.collection.handles.size() >
                    Core::NativeHandleObservationMaxRows)
                {
                    handles.sourceTruncated = true;
                    handles.omittedHandleCount +=
                        handles.collection.handles.size() -
                        Core::NativeHandleObservationMaxRows;
                    handles.collection.handles.resize(
                        Core::NativeHandleObservationMaxRows);
                }
                handles.source.sourceKind = selectedHandles_.success
                    ? Core::ObservationSourceKind::Direct
                    : Core::ObservationSourceKind::Unavailable;
                handles.source.sourceIdentifier = "core.handle-collector";
                handles.source.collectionMethod =
                    "selected-process-handle-metadata";
                handles.source.rawSourceReference = context.entityScope;
                if (!selectedHandles_.statusMessage.empty())
                {
                    handles.source.limitations.push_back(
                        WideToUtf8(selectedHandles_.statusMessage));
                }
                handles.targetIdentities.reserve((std::min)(
                    handles.collection.handles.size(),
                    Core::NativeHandleObservationMaxTargetIdentities));
                for (const Core::HandleInfo& handle :
                    handles.collection.handles)
                {
                    if (!handle.targetPid.has_value() ||
                        handles.targetIdentities.size() >=
                            Core::NativeHandleObservationMaxTargetIdentities)
                    {
                        continue;
                    }
                    Core::NativeHandleTargetIdentity binding;
                    binding.handleValue = handle.handleValue;
                    binding.objectKind =
                        Core::ClassifyNativeHandleObjectKind(handle);
                    binding.targetPid = handle.targetPid.value();
                    const Core::ProcessInfo* target =
                        Core::FindProcessByPid(snapshot_, binding.targetPid);
                    if (target != nullptr && target->hasCreationTime)
                    {
                        binding.identityResolved = true;
                        binding.identity =
                            Core::MakeProcessIdentityKey(*target);
                    }
                    else if (target != nullptr &&
                        binding.targetPid != process.pid)
                    {
                        // A PID-only target cannot exclude reuse and therefore
                        // remains non-contributing context in the native policy.
                        binding.pidReuseAmbiguous = true;
                    }
                    handles.targetIdentities.push_back(std::move(binding));
                }
            }

            if (RuntimeLoadedForProcess(process))
            {
                Core::NativeRuntimeObservationInput& runtime =
                    native.runtime;
                runtime.identity = native.identity;
                runtime.entityScope = context.entityScope;
                runtime.supplied = true;
                runtime.collectionAttempted = true;
                runtime.available = selectedRuntime_.success;
                runtime.declaredThreadCount =
                    selectedRuntime_.threadCount;
                runtime.declaredHandleCount =
                    selectedRuntime_.handleCount;
                runtime.processBasePriorityAvailable = true;
                runtime.processBasePriority =
                    selectedRuntime_.basePriority;
                runtime.source.sourceKind = selectedRuntime_.success
                    ? Core::ObservationSourceKind::Direct
                    : Core::ObservationSourceKind::Unavailable;
                runtime.source.completeness = selectedRuntime_.success
                    ? Core::NativeRuntimeSourceCompleteness::Complete
                    : Core::NativeRuntimeSourceCompleteness::Unavailable;
                runtime.source.sourceIdentifier = "core.runtime-collector";
                runtime.source.collectionMethod =
                    "selected-process-runtime-metadata";
                runtime.source.rawSourceReference = context.entityScope;
                if (!selectedRuntime_.errorMessage.empty())
                {
                    runtime.limitations.push_back(
                        WideToUtf8(selectedRuntime_.errorMessage));
                }

                const std::size_t threadLimit = (std::min)(
                    selectedRuntime_.threads.size(),
                    Core::NativeRuntimeObservationMaxThreads);
                runtime.sourceFactsTruncated =
                    selectedRuntime_.threads.size() > threadLimit ||
                    selectedRuntime_.threadCount > threadLimit;
                runtime.threads.reserve(threadLimit);
                for (std::size_t index = 0; index < threadLimit; ++index)
                {
                    const Core::ThreadInfo& sourceThread =
                        selectedRuntime_.threads[index];
                    if (sourceThread.threadId == 0)
                    {
                        // RuntimeCollector uses a zero-ID sentinel when thread
                        // enumeration itself fails. It is collection coverage,
                        // not a thread artifact and must not invalidate otherwise
                        // usable selected-process evidence.
                        runtime.sourceFactsTruncated = true;
                        std::string limitation = sourceThread.errorMessage.empty()
                            ? std::string(
                                "Thread enumeration did not return a stable thread identity.")
                            : WideToUtf8(sourceThread.errorMessage);
                        if (limitation.size() >
                            Core::ObservationLimitationItemMaxCharacters)
                        {
                            limitation.resize(
                                Core::ObservationLimitationItemMaxCharacters);
                        }
                        if (runtime.limitations.size() <
                            Core::NativeRuntimeObservationMaxLimitations)
                        {
                            runtime.limitations.push_back(
                                std::move(limitation));
                        }
                        continue;
                    }
                    Core::NativeRuntimeThreadInput thread;
                    thread.threadId = sourceThread.threadId;
                    thread.ownerProcessId = sourceThread.ownerProcessId;
                    thread.ownerIdentityKnown =
                        sourceThread.ownerProcessId != 0;
                    thread.ownerMatchesSelectedProcess =
                        sourceThread.ownerProcessId == process.pid;
                    thread.basePriorityAvailable = true;
                    thread.basePriority = sourceThread.basePriority;
                    thread.currentPriorityAvailable =
                        sourceThread.hasCurrentPriority;
                    thread.currentPriority =
                        sourceThread.currentPriority;
                    thread.source = runtime.source;

                    if (!sourceThread.startAddress.empty())
                    {
                        std::wistringstream addressStream(
                            sourceThread.startAddress);
                        addressStream >> std::hex >> thread.startAddress;
                        thread.startAddressAvailable =
                            !addressStream.fail();
                    }
                    if (!sourceThread.startAddressResolvedModule.empty())
                    {
                        thread.startKind =
                            Core::NativeRuntimeThreadStartKind::ImageBacked;
                        thread.resolvedModuleIdentity = WideToUtf8(
                            sourceThread.startAddressResolvedModule);
                    }
                    else if (thread.startAddressAvailable)
                    {
                        thread.startKind =
                            Core::NativeRuntimeThreadStartKind::Unresolved;
                        if (MemoryLoadedForProcess(process))
                        {
                            for (const Core::MemoryRegionInfo& region :
                                selectedMemory_.regions)
                            {
                                if (thread.startAddress < region.baseAddress ||
                                    thread.startAddress - region.baseAddress >=
                                        region.regionSize)
                                {
                                    continue;
                                }
                                if (region.isPrivate && region.isExecutable)
                                {
                                    thread.startKind = Core::
                                        NativeRuntimeThreadStartKind::
                                            PrivateExecutableMetadata;
                                }
                                else if (region.isImage || region.isMapped ||
                                    !region.mappedFilePath.empty())
                                {
                                    thread.startKind = Core::
                                        NativeRuntimeThreadStartKind::ImageBacked;
                                }
                                else
                                {
                                    thread.startKind = Core::
                                        NativeRuntimeThreadStartKind::
                                            OutsideKnownModule;
                                }
                                break;
                            }
                        }
                    }
                    if (!sourceThread.state.empty())
                    {
                        thread.evidence.push_back(
                            "Captured thread state: " +
                            WideToUtf8(sourceThread.state) + ".");
                    }
                    if (!sourceThread.errorMessage.empty())
                    {
                        thread.limitations.push_back(
                            WideToUtf8(sourceThread.errorMessage));
                    }
                    runtime.threads.push_back(std::move(thread));
                }

                if (selectedRuntime_.success)
                {
                    Core::NativeAffinityObservationInput& affinity =
                        native.affinity;
                    affinity.identity = native.identity;
                    affinity.supplied = true;
                    affinity.collectionAttempted = true;
                    affinity.available =
                        selectedRuntime_.processAffinityMask != 0 &&
                        selectedRuntime_.systemAffinityMask != 0;
                    affinity.processAffinityMask =
                        selectedRuntime_.processAffinityMask;
                    affinity.systemAffinityMask =
                        selectedRuntime_.systemAffinityMask;
                    affinity.source.sourceKind = affinity.available
                        ? Core::ObservationSourceKind::Direct
                        : Core::ObservationSourceKind::Unavailable;
                    affinity.source.completeness = affinity.available
                        ? Core::ObservationSourceCompleteness::Complete
                        : Core::ObservationSourceCompleteness::Unavailable;
                    affinity.source.sourceIdentifier =
                        "core.runtime-collector";
                    affinity.source.collectionMethod =
                        "selected-process-affinity-metadata";
                    affinity.source.rawSourceReference = context.entityScope;
                    if (!affinity.available &&
                        !selectedRuntime_.errorMessage.empty())
                    {
                        affinity.source.limitations.push_back(
                            WideToUtf8(selectedRuntime_.errorMessage));
                    }

                    Core::NativePriorityObservationInput& priority =
                        native.priority;
                    priority.identity = native.identity;
                    priority.entityScope = context.entityScope;
                    priority.supplied = true;
                    priority.collectionAttempted = true;
                    priority.available =
                        selectedRuntime_.priorityClassRaw != 0;
                    priority.rawPriorityClass =
                        selectedRuntime_.priorityClassRaw;
                    priority.priorityClass =
                        Core::ClassifyNativeProcessPriorityClass(
                            selectedRuntime_.priorityClassRaw);
                    priority.basePriorityAvailable = true;
                    priority.basePriority = selectedRuntime_.basePriority;
                    priority.limitations = runtime.limitations;
                    priority.source = runtime.source;
                }
            }

            return context;
        }

        static std::uint64_t ObservationShadowElapsedMicroseconds(
            const std::chrono::steady_clock::time_point started)
        {
            const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - started).count();
            return elapsed > 0 ? static_cast<std::uint64_t>(elapsed) : 0;
        }

        void ProcessSelectedProcessEnrichedLifecycle() noexcept
        {
            // Saved-snapshot review consumes captured schema-4/5 authority.
            // Older schemas explicitly have no captured TriageEngine result;
            // no saved scope is implicitly re-evaluated under current policy.
            if (loadedSnapshotActive_)
            {
                return;
            }

            Core::SelectedProcessEnrichedSourceStamp capturedSource;
            if (!Core::TryBeginSelectedProcessEnrichedBuild(
                    selectedEnrichedLifecycle_,
                    capturedSource))
            {
                return;
            }

            const auto started = std::chrono::steady_clock::now();
            ++observationShadowNativeBuildInvocationCount_;

            Core::ObservationShadowState nextState;
            const Core::ProcessInfo* process =
                Core::FindProcessByPid(snapshot_, capturedSource.identity.pid);
            try
            {
                if (process == nullptr ||
                    Core::MakeProcessIdentityKey(*process) !=
                        capturedSource.identity)
                {
                    throw std::runtime_error(
                        "Selected process identity changed before the enriched build started.");
                }
                const Core::ObservationShadowSourceContext sourceContext =
                    BuildObservationShadowSourceContext(*process);
                nextState = Core::BuildNativeObservationShadowState(
                    sourceContext,
                    true,
                    process->pid,
                    ProcessCacheStamp(*process),
                    capturedSource.evidenceGeneration);
            }
            catch (...)
            {
                try
                {
                    Core::ObservationShadowSourceContext failureContext;
                    failureContext.entityScope = capturedSource.entityScope;
                    failureContext.sourceKind =
                        Core::ObservationSourceKind::Derived;
                    nextState = Core::MakeFailedObservationShadowState(
                        failureContext,
                        capturedSource.hasEntity,
                        capturedSource.identity.pid,
                        capturedSource.identity.hasCreationTime
                            ? capturedSource.identity.creationTimeFileTime
                            : 0,
                        capturedSource.evidenceGeneration,
                        "Native observation production failed; enriched triage is unavailable for this generation.",
                        ObservationShadowElapsedMicroseconds(started));
                }
                catch (...)
                {
                    const Core::SelectedProcessEnrichedSourceStamp currentSource =
                        CurrentSelectedProcessEnrichedSourceStamp();
                    Core::CompleteSelectedProcessEnrichedBuild(
                        selectedEnrichedLifecycle_,
                        capturedSource,
                        currentSource,
                        nextState,
                        static_cast<std::uint64_t>(GetTickCount64()),
                        ObservationShadowElapsedMicroseconds(started));
                    selectedNativeSourceEvidence_ = {};
                    Core::ClearObservationShadowState(selectedObservationShadow_);
                    return;
                }
            }

            if (Core::TryRefineObservationShadowState(nextState))
            {
                ++observationShadowRefinementInvocationCount_;
            }
            if (Core::TryActivateObservationShadowCorrelations(nextState))
            {
                ++observationShadowCorrelationInvocationCount_;
            }
            if (Core::TryBuildObservationShadowTriage(nextState))
            {
                ++observationShadowTriageInvocationCount_;
            }

            Core::NativeSourceEvidenceProjectionResult nextSourceEvidence;
            if (nextState.refinement.Succeeded())
            {
                const Core::TriageResult* triage =
                    nextState.triage.Succeeded()
                        ? &nextState.triage
                        : nullptr;
                nextSourceEvidence =
                    Core::ProjectNativeSourceEvidence(
                        nextState.refinement,
                        triage);
            }

            const Core::SelectedProcessEnrichedSourceStamp currentSource =
                CurrentSelectedProcessEnrichedSourceStamp();
            const std::uint64_t completionDurationMicroseconds =
                ObservationShadowElapsedMicroseconds(started);
            const bool publicationAccepted =
                Core::CompleteSelectedProcessEnrichedBuild(
                    selectedEnrichedLifecycle_,
                    capturedSource,
                    currentSource,
                    nextState,
                    static_cast<std::uint64_t>(GetTickCount64()),
                    completionDurationMicroseconds);

            const bool completedForCurrentSource =
                capturedSource == currentSource;
            if (publicationAccepted || completedForCurrentSource)
            {
                selectedObservationShadow_ = std::move(nextState);
            }
            else
            {
                Core::ClearObservationShadowState(selectedObservationShadow_);
            }
            selectedNativeSourceEvidence_ = publicationAccepted
                ? std::move(nextSourceEvidence)
                : Core::NativeSourceEvidenceProjectionResult{};
            try
            {
                const std::uint64_t durationMs =
                    completionDurationMicroseconds / 1000;
                std::string message;
                LogLevel level = LogLevel::Info;
                if (publicationAccepted)
                {
                    message = selectedObservationShadow_.diagnosticMessage;
                    if (message.empty())
                    {
                        message =
                            "Native enriched TriageEngine result built for PID " +
                            std::to_string(capturedSource.identity.pid) +
                            " (" + std::to_string(durationMs) + " ms).";
                    }
                }
                else
                {
                    level = LogLevel::Warning;
                    message =
                        "Native enriched TriageEngine analysis could not be completed for PID " +
                        std::to_string(capturedSource.identity.pid) +
                        "; current baseline authority remains available when present (" +
                        std::to_string(durationMs) + " ms).";
                }
                if (message.size() > Core::ObservationShadowDiagnosticMaxCharacters)
                {
                    message.resize(Core::ObservationShadowDiagnosticMaxCharacters);
                }
                AddLog(level, message);
            }
            catch (...)
            {
                // Diagnostic logging is subordinate to the value-owned shadow.
            }
        }

        // Capture/export actions may ensure a request exists, but they never
        // run the pipeline from an ImGui callback. The next pre-frame lifecycle
        // pass processes the coalesced request.
        void SynchronizeNativeObservationEngineForCurrentEvidence() noexcept
        {
            RequestSelectedProcessEnrichedRebuild(
                Core::SelectedProcessEnrichedRebuildReason::
                    AllSelectedEvidenceChanged);
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

        std::size_t CountSuspiciousProcesses() const
        {
            std::size_t count = 0;
            for (std::size_t processIndex = 0;
                processIndex < snapshot_.processes.size();
                ++processIndex)
            {
                if (ProcessAuthorityIsSuspiciousAt(processIndex))
                {
                    ++count;
                }
            }
            return count;
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
                    visibleProcessRows_.push_back({
                        row.processIndex,
                        row.depth,
                        ProcessAuthoritySeverityAt(row.processIndex),
                        ProcessAuthorityUnavailableAt(row.processIndex)
                    });
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
            const std::vector<Core::Severity> emptySeverities;
            const std::vector<std::uint8_t> emptySuspicious;
            const std::vector<std::uint8_t> emptyAvailable;
            const bool authorityCurrent =
                ProcessAuthorityProjectionMatchesCurrent();
            const std::vector<Core::TimelineRow> rows =
                Core::BuildTimelineRows(
                    snapshot_,
                    timelineFilter_,
                    authorityCurrent
                        ? processAuthoritySeverities_
                        : emptySeverities,
                    authorityCurrent
                        ? processAuthoritySuspicious_
                        : emptySuspicious,
                    authorityCurrent
                        ? processAuthorityAvailable_
                        : emptyAvailable);
            cachedTimelineRows_.reserve(rows.size());
            for (Core::TimelineRow row : rows)
            {
                if (row.sourceProcessIndex >= snapshot_.processes.size())
                {
                    continue;
                }

                const Core::ProcessInfo& timelineProcess =
                    snapshot_.processes[row.sourceProcessIndex];
                if (timelineProcess.pid != row.pid)
                {
                    continue;
                }

                if (ProcessMatchesFilters(timelineProcess))
                {
                    cachedTimelineRows_.push_back(std::move(row));
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
            visibleHandlesWithTypedAccessCount_ = 0;
            visibleHandlesNameStatusCount_ = 0;
            for (std::size_t index = 0; index < selectedHandles_.handles.size(); ++index)
            {
                const Core::HandleInfo& handle = selectedHandles_.handles[index];
                if (!HandleAccessCategoryText(handle).empty())
                {
                    ++visibleHandlesWithTypedAccessCount_;
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
            InvalidateSelectedNativeEvidence();
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

            const Core::ProcessInfo* selectedProcess =
                Core::FindProcessByPid(snapshot_, selectedPid_);
            if (selectedProcess != nullptr)
            {
                Core::UpdateSelectedProcessEnrichedSelection(
                    selectedEnrichedLifecycle_,
                    CurrentSelectedProcessEnrichedSourceStamp());
                EnsureSelectedProcessEvidenceLoaded(
                    *selectedProcess,
                    refreshSelectedEvidence);
            }
            RebuildFocusedGraph("snapshot-refresh");
            RequestGraphFit();
            RebuildVisibleProcessRowsIfNeeded();
            RebuildGraphWorldLayoutIfNeeded();
            InvalidateSelectedNativeEvidence(
                Core::SelectedProcessEnrichedRebuildReason::
                    ProcessSnapshotChanged);
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

            const Core::SelectedProcessEnrichedSourceStamp previousSource =
                CurrentSelectedProcessEnrichedSourceStamp();
            const Core::ProcessIdentityKey selectedIdentity =
                Core::MakeProcessIdentityKey(*selectedProcess);
            const bool changed = !previousSource.hasEntity ||
                previousSource.identity != selectedIdentity ||
                previousSource.scope != Core::SelectedProcessAnalysisScope::Live;
            if (changed)
            {
                ClearSelectedProcessEvidence();
                MarkSelectedEvidenceTablesNeedAutoSize();
            }

            selectedPid_ = pid;
            Core::UpdateSelectedProcessEnrichedSelection(
                selectedEnrichedLifecycle_,
                CurrentSelectedProcessEnrichedSourceStamp());
            EnsureSelectedProcessEvidenceLoaded(*selectedProcess);
            if (changed)
            {
                RequestSelectedProcessEnrichedRebuild(
                    Core::SelectedProcessEnrichedRebuildReason::
                        SelectionChanged);
            }
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
                    Core::SeverityRank(ProcessAuthoritySeverity(*selectedProcess)) >=
                        Core::SeverityRank(Core::Severity::High)
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
                    Core::SeverityRank(ProcessAuthoritySeverity(*selectedProcess)) >=
                        Core::SeverityRank(Core::Severity::High)
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

            ImGui::DockBuilderDockWindow("Source Evidence", bottomDockId_);
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

            RenderDockedContentPanel("Source Evidence", [this]() { RenderSelectedSourceEvidence(); });
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
            context.unavailableCount = processAuthorityUnavailableCount_;
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
            context.resolveProcessIcon = [this](const Core::ProcessInfo& process) {
                return reinterpret_cast<ImTextureID>(GetProcessIconTexture(process));
            };
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

                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::TextDisabled("Baseline captured triage");
                ImGui::TableSetColumnIndex(1);
                ImGui::Text(
                    "%zu",
                    compareResultValid_
                        ? compareResult_.baselineTriageCapturedProcessCount
                        : 0);
                ImGui::TableSetColumnIndex(2);
                ImGui::TextDisabled("Current captured triage");
                ImGui::TableSetColumnIndex(3);
                ImGui::Text(
                    "%zu",
                    compareResultValid_
                        ? compareResult_.currentTriageCapturedProcessCount
                        : 0);

                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::TextDisabled("Comparable triage");
                ImGui::TableSetColumnIndex(1);
                ImGui::Text(
                    "%zu",
                    compareResultValid_
                        ? compareResult_.comparableTriageProcessCount
                        : 0);
                ImGui::TableSetColumnIndex(2);
                ImGui::TextDisabled("Triage availability changes");
                ImGui::TableSetColumnIndex(3);
                ImGui::Text(
                    "%zu",
                    compareResultValid_
                        ? compareResult_.triageAvailabilityMismatchCount
                        : 0);

                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::TextDisabled("Triage identities unavailable");
                ImGui::TableSetColumnIndex(1);
                ImGui::Text(
                    "%zu",
                    compareResultValid_
                        ? compareResult_.triageIdentityUnavailableCount
                        : 0);
                ImGui::TableSetColumnIndex(2);
                ImGui::TextDisabled("Selected triage changes");
                ImGui::TableSetColumnIndex(3);
                ImGui::Text(
                    "%zu",
                    compareResultValid_
                        ? compareResult_.selectedTriage.fields.size()
                        : 0);
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
            bool selectableRows,
            bool showHistoricalSeverity)
        {
            constexpr ImGuiTableFlags flags =
                ImGuiTableFlags_BordersInnerV |
                ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Resizable |
                ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_SizingStretchProp;
            const float tableHeight = std::min(260.0f, std::max(118.0f, ImGui::GetTextLineHeightWithSpacing() * (static_cast<float>(processes.size()) + 2.0f)));
            const int columnCount = showHistoricalSeverity ? 6 : 5;
            if (!ImGui::BeginTable(
                    tableId,
                    columnCount,
                    flags,
                    ImVec2(0.0f, tableHeight)))
            {
                return;
            }

            ImGui::TableSetupColumn("Process", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 72.0f);
            ImGui::TableSetupColumn("PPID", ImGuiTableColumnFlags_WidthFixed, 72.0f);
            ImGui::TableSetupColumn("Authoritative triage", ImGuiTableColumnFlags_WidthFixed, 132.0f);
            if (showHistoricalSeverity)
            {
                ImGui::TableSetupColumn(
                    "Historical source severity",
                    ImGuiTableColumnFlags_WidthFixed,
                    126.0f);
            }
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
                    if (process.authoritativeTriage.captured)
                    {
                        const std::string verdict =
                            Core::TriageVerdictDisplayText(
                                process.authoritativeTriage.authoritativeVerdict) +
                            " - " +
                            Core::PersistedTriageAnalysisLevelDisplayText(
                                process.authoritativeTriage.analysisLevel);
                        ImGui::TextUnformatted(verdict.c_str());
                        if (process.authoritativeTriage.usingFallback &&
                            ImGui::IsItemHovered() &&
                            !process.authoritativeTriage.fallbackReason.empty())
                        {
                            ImGui::SetTooltip(
                                "%s",
                                process.authoritativeTriage.fallbackReason.c_str());
                        }
                    }
                    else
                    {
                        ImGui::TextDisabled("Not captured");
                    }
                    if (showHistoricalSeverity)
                    {
                        ImGui::TableSetColumnIndex(4);
                        SeverityText(process.severity);
                    }
                    ImGui::TableSetColumnIndex(showHistoricalSeverity ? 5 : 4);
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
            ImGui::TableSetupColumn("Legacy source severity", ImGuiTableColumnFlags_WidthFixed, 126.0f);
            ImGui::TableSetupColumn("Process", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 70.0f);
            ImGui::TableSetupColumn("Source finding", ImGuiTableColumnFlags_WidthStretch);
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
                    if (finding->severityCaptured)
                    {
                        SeverityText(
                            HistoricalFindingSeverityAsCoreSeverity(
                                finding->severity));
                    }
                    else
                    {
                        ImGui::TextDisabled("Not captured");
                    }
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
            state.hasNotes = !compareResult_.notes.empty() ||
                !compareResult_.selectedTriage.fields.empty();
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
                if (!compareResult_.selectedTriage.fields.empty())
                {
                    ImGui::TextUnformatted(
                        "Selected-process authoritative triage changes:");
                    for (const Core::SnapshotChangedField& field :
                        compareResult_.selectedTriage.fields)
                    {
                        ImGui::Bullet();
                        ImGui::SameLine();
                        WrappedTextDisabled(
                            field.field + L": " + field.baselineValue +
                            L" -> " + field.currentValue);
                    }
                }
            };
            callbacks.renderNewProcesses = [this]() {
                RenderCompareProcessTable(
                    "CompareNewProcessesTable##SnapshotCompare",
                    compareResult_.newProcesses,
                    true,
                    compareResult_.currentSourceEvidenceModelKind ==
                        Core::SnapshotSourceEvidenceModelKind::HistoricalLegacy);
            };
            callbacks.renderExitedProcesses = [this]() {
                RenderCompareProcessTable(
                    "CompareExitedProcessesTable##SnapshotCompare",
                    compareResult_.exitedProcesses,
                    false,
                    compareResult_.baselineSourceEvidenceModelKind ==
                        Core::SnapshotSourceEvidenceModelKind::HistoricalLegacy);
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
            context.snapshot = &snapshot_;
            context.rows = &visibleTimelineRows;
            context.selectedPid = selectedPid_;
            context.activeFilter = timelineFilter_;
            context.timelineTableNeedsAutoSize = &timelineTableNeedsAutoSize_;
            context.monospaceFont = fonts_.monospace;
            context.selectedRowColor = TableSelectedRow();
            context.resolveProcessIcon = [this](const Core::ProcessInfo& process) {
                return reinterpret_cast<ImTextureID>(GetProcessIconTexture(process));
            };
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
            if (!BeginPanelWindow("Source Evidence / Logs"))
            {
                EndPanelWindow();
                return;
            }
            LogsAndEvidencePanelContext context;
            context.logs = BuildLogsPanelContext();
            context.evidence = BuildSourceEvidencePanelContext();
            RenderLogsAndEvidencePanel(context);
            EndPanelWindow();
        }

        void RenderSelectedSourceEvidence()
        {
            GlassPane::UI::RenderSourceEvidencePanelContent(BuildSourceEvidencePanelContext());
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

        SourceEvidencePanelContext BuildSourceEvidencePanelContext()
        {
            SourceEvidencePanelContext context;
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                return context;
            }

            context.hasSelectedProcess = true;
            context.historical = UsesHistoricalSourceEvidence();
            if (context.historical)
            {
                context.records.reserve(
                    process->indicators.size() + process->contextNotes.size());
                for (const std::wstring& historical : process->indicators)
                {
                    SourceEvidenceItemView item;
                    item.title = historical.empty()
                        ? L"Historical source record"
                        : historical;
                    item.role = "Imported historical metadata; not current TriageEngine input.";
                    context.records.push_back(std::move(item));
                }
                for (const std::wstring& note : process->contextNotes)
                {
                    SourceEvidenceItemView item;
                    item.title = L"Historical collection/context note";
                    item.summary = note;
                    item.role = "Imported historical metadata; not current TriageEngine input.";
                    context.records.push_back(std::move(item));
                }
            }
            else
            {
                const std::vector<Core::NativeSourceEvidenceRecord>& records =
                    SelectedNativeSourceEvidenceForProcess(*process);
                context.records.reserve(records.size());
                for (const Core::NativeSourceEvidenceRecord& record : records)
                {
                    SourceEvidenceItemView item;
                    item.title = Utf8ToWide(record.title.c_str());
                    item.summary = Utf8ToWide(record.summary.c_str());
                    item.metadata =
                        Core::EvidenceDomainDisplayText(record.domain) + " / " +
                        Core::ObservationDispositionDisplayText(record.disposition);
                    item.role = record.collectionLimitation
                        ? "Collection limitation"
                        : (record.contributedToVerdict
                            ? "Contributed to verdict"
                            : "Supporting context");
                    context.records.push_back(std::move(item));
                }
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

            if (UsesHistoricalSourceEvidence())
            {
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
            const Core::Severity authoritySeverity = ProcessAuthoritySeverity(process);
            const bool authoritySuspicious = ProcessAuthorityIsSuspicious(process);
            switch (processFilterMode_)
            {
            case ProcessFilterMode::All:
                return true;
            case ProcessFilterMode::Suspicious:
                return authoritySuspicious;
            case ProcessFilterMode::Low:
                return authoritySuspicious && authoritySeverity == Core::Severity::Low;
            case ProcessFilterMode::Medium:
                return authoritySuspicious && authoritySeverity == Core::Severity::Medium;
            case ProcessFilterMode::High:
                return authoritySuspicious && authoritySeverity == Core::Severity::High;
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
        Core::ProcessTriageCache processTriageCache_;
        Core::ProcessTriageCacheSourceStamp processAuthorityProjectionStamp_;
        std::vector<Core::Severity> processAuthoritySeverities_;
        std::vector<std::uint8_t> processAuthoritySuspicious_;
        std::vector<std::uint8_t> processAuthorityAvailable_;
        std::vector<Core::ProcessTriageUnavailableKind> processAuthorityUnavailableKinds_;
        bool processAuthorityProjectionValid_ = false;
        std::size_t processAuthorityUnavailableCount_ = 0;
        std::array<
            std::size_t,
            static_cast<std::size_t>(
                Core::ProcessTriageUnavailableKind::InvalidVerdict) + 1>
            processAuthorityUnavailableCountsByKind_{};
        std::array<
            std::string,
            static_cast<std::size_t>(
                Core::ProcessTriageUnavailableKind::InvalidVerdict) + 1>
            processAuthorityUnavailableFirstIdentityByKind_{};
        std::array<
            std::string,
            static_cast<std::size_t>(
                Core::ProcessTriageUnavailableKind::InvalidVerdict) + 1>
            processAuthorityUnavailableFirstDiagnosticByKind_{};
        std::uint64_t processAuthorityProjectionBuildMicroseconds_ = 0;
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
        Core::PersistedTriageContext loadedSnapshotTriage_;
        Export::SavedNativeSourceEvidenceContext loadedSnapshotNativeSourceEvidence_;
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
        LongRunningOperationKind longOperationKind_ = LongRunningOperationKind::None;
        std::string longOperationTitle_;
        std::string longOperationStatus_;
        float longOperationProgress_ = 0.0f;
        std::size_t suspiciousCount_ = 0;
        std::size_t liveSuspiciousCountBeforeLoad_ = 0;
        std::uint32_t liveSelectedPidBeforeLoad_ = InvalidPid;
        CollectorTimings timings_;
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
        std::uint32_t selectedChainCachePid_ = InvalidPid;
        std::uint32_t graphFitPid_ = InvalidPid;
        std::uint32_t graphLayoutFocusPid_ = InvalidPid;
        std::uint32_t visibleHandlesPid_ = InvalidPid;
        std::uint32_t visibleMemoryPid_ = InvalidPid;
        std::size_t graphFitNodeCount_ = 0;
        std::size_t graphLayoutNodeCount_ = 0;
        std::size_t graphLayoutEdgeCount_ = 0;
        std::size_t visibleHandlesSourceSize_ = 0;
        std::size_t visibleMemorySourceSize_ = 0;
        std::size_t visibleHandlesWithTypedAccessCount_ = 0;
        std::size_t visibleHandlesNameStatusCount_ = 0;
        std::uint64_t snapshotGeneration_ = 0;
        std::uint64_t baselineEvidenceGeneration_ = 0;
        std::uint64_t baselineScopeGeneration_ = 0;
        std::uint64_t baselineCacheBuildInvocationCount_ = 0;
        std::uint64_t selectedEvidenceGeneration_ = 0;
        std::uint64_t observationShadowNativeBuildInvocationCount_ = 0;
        std::uint64_t observationShadowRefinementInvocationCount_ = 0;
        std::uint64_t observationShadowCorrelationInvocationCount_ = 0;
        std::uint64_t observationShadowTriageInvocationCount_ = 0;
        std::uint64_t processQueryRevision_ = 0;
        std::uint64_t visibleProcessRowsSnapshotGeneration_ = 0;
        std::uint64_t visibleProcessRowsQueryRevision_ = 0;
        std::uint64_t timelineRowsSnapshotGeneration_ = 0;
        std::uint64_t timelineRowsQueryRevision_ = 0;
        std::uint64_t visibleHandlesCreationTime_ = 0;
        std::uint64_t visibleMemoryCreationTime_ = 0;
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
        Core::ObservationShadowState selectedObservationShadow_;
        Core::NativeSourceEvidenceProjectionResult selectedNativeSourceEvidence_;
        Core::SelectedProcessEnrichedLifecycleState selectedEnrichedLifecycle_;
        std::vector<LogEntry> logs_;
        std::unordered_map<
            Core::ProcessIconCacheKey,
            CachedIconTexture,
            Core::ProcessIconCacheKeyHash> iconCache_;
        std::unordered_map<std::wstring, Core::FileIdentity> fileIdentityCache_;
        std::unordered_map<std::wstring, Core::ModuleCollectionResult> moduleEvidenceCache_;
        std::unordered_map<std::wstring, Core::TokenInfo> tokenEvidenceCache_;
        std::unordered_map<std::wstring, Core::RuntimeInfo> runtimeEvidenceCache_;
        std::unordered_map<std::wstring, Core::MemoryCollectionResult> memoryEvidenceCache_;
        std::unordered_map<std::wstring, Core::HandleCollectionResult> handleEvidenceCache_;
        std::unordered_map<std::wstring, std::vector<std::size_t>> networkIndicatorMatchIndexesByRemote_;
        std::unordered_map<std::uint32_t, std::size_t> graphLayoutNodeIndexByPid_;
        ID3D11ShaderResourceView* genericProcessIconTexture_ = nullptr;
        ID3D11ShaderResourceView* appLogoTexture_ = nullptr;
        std::uint64_t processIconCacheHits_ = 0;
        std::uint64_t processIconCacheMisses_ = 0;
        std::uint64_t processIconExtractionAttempts_ = 0;
        std::uint64_t processIconExtractionSuccesses_ = 0;
        std::uint64_t processIconGenericFallbackUses_ = 0;
        std::uint64_t genericProcessIconTextureBuilds_ = 0;

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


