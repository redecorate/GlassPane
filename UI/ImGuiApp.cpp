#include "ImGuiApp.h"

#ifndef GLASSPANE_ENABLE_IMGUI

namespace GlassPane::UI
{
    int RunImGuiApp(HINSTANCE, int)
    {
        MessageBoxW(
            nullptr,
            L"Dear ImGui is not enabled for this build. Add third_party\\imgui, add the ImGui source files to the project, and define GLASSPANE_ENABLE_IMGUI.",
            L"GlassPane ImGui",
            MB_ICONINFORMATION | MB_OK);
        return -1;
    }
}

#else

#include "Fonts.h"
#include "Theme.h"

#include "../Core/ChainAnalysis.h"
#include "../Core/CorrelationEngine.h"
#include "../Core/FileIdentity.h"
#include "../Core/GraphModel.h"
#include "../Core/HandleCollector.h"
#include "../Core/MemoryCollector.h"
#include "../Core/ModuleCollector.h"
#include "../Core/NetworkCollector.h"
#include "../Core/ProcessCollector.h"
#include "../Core/ProcessTree.h"
#include "../Core/RuntimeCollector.h"
#include "../Core/TimelineModel.h"
#include "../Core/TokenCollector.h"
#include "../Export/JsonExporter.h"
#include "../Export/MarkdownReportExporter.h"

#include "imgui.h"
#ifdef IMGUI_HAS_DOCK
#include "imgui_internal.h"
#endif
#include "backends/imgui_impl_dx11.h"
#include "backends/imgui_impl_win32.h"

#include <Windows.h>
#include <commdlg.h>
#include <d3d11.h>
#include <shellapi.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <exception>
#include <fstream>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "d3dcompiler.lib")
#pragma comment(lib, "Comdlg32.lib")
#pragma comment(lib, "Shell32.lib")

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);

namespace GlassPane::UI
{
    namespace
    {
        constexpr UINT WindowWidth = 1440;
        constexpr UINT WindowHeight = 900;
        constexpr std::uint32_t InvalidPid = 0;
        constexpr const char* GlassPaneBaseVersion = "v0.3.1";
#ifdef _DEBUG
        constexpr const char* GlassPaneBuildSuffix = "-Debug";
#else
        constexpr const char* GlassPaneBuildSuffix = "-Release";
#endif
        constexpr const char* GlassPaneGithubUrl = "https://github.com/redecorate/GlassPane";

        enum class LogLevel
        {
            Info,
            Warning,
            High
        };

        struct CollectorTimings
        {
            std::uint64_t processSnapshotMs = 0;
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
        };

        enum class ProcessFilterMode
        {
            All,
            Suspicious,
            Low,
            Medium,
            High
        };

        enum class InspectorTab
        {
            Triage,
            Details,
            Chain,
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

        struct InspectorTabSpec
        {
            const char* label;
            InspectorTab tab;
        };

        constexpr std::array<InspectorTabSpec, 9> InspectorTabs = {
            InspectorTabSpec{"Triage", InspectorTab::Triage},
            InspectorTabSpec{"Details", InspectorTab::Details},
            InspectorTabSpec{"Chain", InspectorTab::Chain},
            InspectorTabSpec{"Memory", InspectorTab::Memory},
            InspectorTabSpec{"Runtime", InspectorTab::Runtime},
            InspectorTabSpec{"Handles", InspectorTab::Handles},
            InspectorTabSpec{"Modules", InspectorTab::Modules},
            InspectorTabSpec{"Network", InspectorTab::Network},
            InspectorTabSpec{"Token", InspectorTab::Token},
        };

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

        struct VisibleProcessRow
        {
            std::size_t processIndex = 0;
            std::size_t depth = 0;
            Core::Severity filterSeverity = Core::Severity::None;
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
        };

        struct CachedIconTexture
        {
            ID3D11ShaderResourceView* texture = nullptr;
            bool ownsTexture = false;
        };

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

        std::string WideToUtf8(const std::wstring& value)
        {
            try
            {
                if (value.empty())
                {
                    return {};
                }

                constexpr std::size_t MaxDisplayCharacters = 4096;
                const std::size_t inputLength = std::min(value.size(), MaxDisplayCharacters);
                if (inputLength == 0)
                {
                    return {};
                }

                const int required = WideCharToMultiByte(
                    CP_UTF8,
                    0,
                    value.data(),
                    static_cast<int>(inputLength),
                    nullptr,
                    0,
                    nullptr,
                    nullptr);
                if (required <= 0)
                {
                    return "(invalid)";
                }

                std::string result(static_cast<std::size_t>(required), '\0');
                const int written = WideCharToMultiByte(
                    CP_UTF8,
                    0,
                    value.data(),
                    static_cast<int>(inputLength),
                    result.data(),
                    required,
                    nullptr,
                    nullptr);
                if (written <= 0)
                {
                    return "(invalid)";
                }

                return result;
            }
            catch (const std::exception&)
            {
                return "(invalid)";
            }
            catch (...)
            {
                return "(invalid)";
            }
        }

        std::wstring Utf8ToWide(const char* value)
        {
            if (value == nullptr || value[0] == '\0')
            {
                return {};
            }

            const int length = static_cast<int>(strlen(value));
            const int required = MultiByteToWideChar(CP_UTF8, 0, value, length, nullptr, 0);
            if (required <= 0)
            {
                return {};
            }

            std::wstring result(static_cast<std::size_t>(required), L'\0');
            MultiByteToWideChar(CP_UTF8, 0, value, length, result.data(), required);
            return result;
        }

        std::wstring ToLower(std::wstring value)
        {
            std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) {
                return static_cast<wchar_t>(std::towlower(ch));
            });
            return value;
        }

        bool FieldContainsQuery(const std::wstring& field, const std::wstring& loweredQuery)
        {
            if (loweredQuery.empty() || field.empty())
            {
                return false;
            }

            return ToLower(field).find(loweredQuery) != std::wstring::npos;
        }

        std::string DisplayName(const std::wstring& value)
        {
            try
            {
                if (value.empty())
                {
                    return "(unknown)";
                }

                constexpr std::size_t MaxDisplayCharacters = 256;
                const std::string displayName = WideToUtf8(value.substr(0, MaxDisplayCharacters));
                if (displayName.empty())
                {
                    return "(unknown)";
                }

                return displayName;
            }
            catch (const std::exception&)
            {
                return "(invalid)";
            }
            catch (...)
            {
                return "(invalid)";
            }
        }

        std::string WrapForCurrentWidth(const std::string& text)
        {
            if (text.empty())
            {
                return text;
            }

            const float availableWidth = std::max(ImGui::GetContentRegionAvail().x, 96.0f);
            const float averageCharacterWidth = std::max(ImGui::GetFontSize() * 0.56f, 6.0f);
            const std::size_t maxLineLength = std::max<std::size_t>(
                24,
                static_cast<std::size_t>(availableWidth / averageCharacterWidth));

            std::string wrapped;
            wrapped.reserve(text.size() + text.size() / maxLineLength + 8);

            std::size_t lineStart = 0;
            while (lineStart < text.size())
            {
                const std::size_t remaining = text.size() - lineStart;
                if (remaining <= maxLineLength)
                {
                    wrapped.append(text, lineStart, remaining);
                    break;
                }

                const std::size_t preferredEnd = lineStart + maxLineLength;
                std::size_t breakPosition = std::string::npos;
                for (std::size_t index = preferredEnd; index > lineStart; --index)
                {
                    const char ch = text[index - 1];
                    if (ch == ' ' || ch == '\\' || ch == '/' || ch == ';' || ch == ',' || ch == '|')
                    {
                        breakPosition = index;
                        break;
                    }
                }

                if (breakPosition == std::string::npos || breakPosition <= lineStart)
                {
                    breakPosition = preferredEnd;
                }

                wrapped.append(text, lineStart, breakPosition - lineStart);
                wrapped.push_back('\n');
                lineStart = breakPosition;
                while (lineStart < text.size() && text[lineStart] == ' ')
                {
                    ++lineStart;
                }
            }

            return wrapped;
        }

        std::string Shorten(const std::string& value, std::size_t maxLength)
        {
            if (value.size() <= maxLength)
            {
                return value;
            }
            if (maxLength <= 3)
            {
                return value.substr(0, maxLength);
            }
            return value.substr(0, maxLength - 3) + "...";
        }

        std::wstring OptionalSessionId(const std::optional<std::uint32_t>& sessionId)
        {
            return sessionId.has_value() ? std::to_wstring(sessionId.value()) : L"(unknown)";
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

        std::wstring FileTimestamp()
        {
            SYSTEMTIME local = {};
            GetLocalTime(&local);

            wchar_t buffer[32] = {};
            swprintf_s(
                buffer,
                L"%04u%02u%02u-%02u%02u%02u",
                local.wYear,
                local.wMonth,
                local.wDay,
                local.wHour,
                local.wMinute,
                local.wSecond);
            return buffer;
        }

        std::wstring SanitizedFileNamePart(std::wstring value)
        {
            if (value.empty())
            {
                return L"unknown";
            }

            const std::wstring lowered = ToLower(value);
            if (lowered.size() > 4 && lowered.substr(lowered.size() - 4) == L".exe")
            {
                value.resize(value.size() - 4);
            }

            std::wstring sanitized;
            sanitized.reserve(value.size());
            bool previousDash = false;
            for (wchar_t ch : value)
            {
                const bool invalid =
                    ch < 32 ||
                    ch == L'<' ||
                    ch == L'>' ||
                    ch == L':' ||
                    ch == L'"' ||
                    ch == L'/' ||
                    ch == L'\\' ||
                    ch == L'|' ||
                    ch == L'?' ||
                    ch == L'*' ||
                    std::iswspace(ch) != 0;
                if (invalid)
                {
                    if (!previousDash && !sanitized.empty())
                    {
                        sanitized.push_back(L'-');
                        previousDash = true;
                    }
                    continue;
                }

                sanitized.push_back(static_cast<wchar_t>(std::towlower(ch)));
                previousDash = false;
            }

            while (!sanitized.empty() && sanitized.back() == L'-')
            {
                sanitized.pop_back();
            }

            return sanitized.empty() ? std::wstring(L"unknown") : sanitized;
        }

        ImVec4 SeverityColor(Core::Severity severity)
        {
            switch (severity)
            {
            case Core::Severity::High:
                return ImVec4(0.96f, 0.24f, 0.22f, 1.0f);
            case Core::Severity::Medium:
                return ImVec4(0.96f, 0.52f, 0.20f, 1.0f);
            case Core::Severity::Low:
                return ImVec4(0.82f, 0.70f, 0.36f, 1.0f);
            case Core::Severity::Info:
                return ImVec4(0.45f, 0.67f, 0.95f, 1.0f);
            case Core::Severity::None:
            default:
                return ImVec4(0.66f, 0.72f, 0.80f, 1.0f);
            }
        }

        ImU32 SeverityU32(Core::Severity severity)
        {
            return ImGui::ColorConvertFloat4ToU32(SeverityColor(severity));
        }

        ImU32 ColorU32(const ImVec4& color)
        {
            return ImGui::ColorConvertFloat4ToU32(color);
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

        void EndPanelWindow()
        {
            ImGui::End();
            ImGui::PopStyleColor();
        }

        void RenderModalCloseHint()
        {
            const char* hint = "Click anywhere to close";
            const ImGuiViewport* viewport = ImGui::GetMainViewport();
            const ImVec2 textSize = ImGui::CalcTextSize(hint);
            const ImVec2 position(
                viewport->WorkPos.x + (viewport->WorkSize.x - textSize.x) * 0.5f,
                viewport->WorkPos.y + viewport->WorkSize.y - textSize.y - 28.0f);
            ImGui::GetForegroundDrawList()->AddText(position, ColorU32(MutedText()), hint);
        }

        bool BeginGlassPaneModal(
            const char* title,
            int openedFrame,
            const ImVec2& size,
            bool* closeRequested)
        {
            if (closeRequested != nullptr)
            {
                *closeRequested = false;
            }

            ImGui::SetNextWindowSize(size, ImGuiCond_Appearing);
            ImGui::PushStyleColor(ImGuiCol_ModalWindowDimBg, ImVec4(0.0f, 0.0f, 0.0f, 0.58f));
            ImGuiWindowFlags flags =
                ImGuiWindowFlags_AlwaysAutoResize |
                ImGuiWindowFlags_NoSavedSettings |
                ImGuiWindowFlags_NoCollapse;
#ifdef IMGUI_HAS_DOCK
            flags |= ImGuiWindowFlags_NoDocking;
#endif
            const bool visible = ImGui::BeginPopupModal(title, nullptr, flags);
            ImGui::PopStyleColor();
            if (!visible)
            {
                return false;
            }

            const ImVec2 popupMin = ImGui::GetWindowPos();
            const ImVec2 popupMax(
                popupMin.x + ImGui::GetWindowSize().x,
                popupMin.y + ImGui::GetWindowSize().y);
            const bool mouseInsidePopup = ImGui::IsMouseHoveringRect(popupMin, popupMax, false);
            const bool canCloseFromOutsideClick = ImGui::GetFrameCount() > openedFrame;
            if (closeRequested != nullptr &&
                ((canCloseFromOutsideClick && ImGui::IsMouseClicked(ImGuiMouseButton_Left) && !mouseInsidePopup) ||
                    ImGui::IsKeyPressed(ImGuiKey_Escape)))
            {
                *closeRequested = true;
            }
            RenderModalCloseHint();
            return true;
        }

        void EndGlassPaneModal(bool closeRequested)
        {
            if (closeRequested)
            {
                ImGui::CloseCurrentPopup();
            }
            ImGui::EndPopup();
        }

        void TextWide(const std::wstring& value)
        {
            const std::string text = WideToUtf8(value);
            ImGui::TextUnformatted(text.c_str());
        }

        void WrappedTextWide(const std::wstring& value)
        {
            const std::string text = WrapForCurrentWidth(WideToUtf8(value));
            ImGui::PushTextWrapPos(0.0f);
            ImGui::TextUnformatted(text.c_str());
            ImGui::PopTextWrapPos();
        }

        void WrappedTextColored(const ImVec4& color, const std::string& value)
        {
            const std::string text = WrapForCurrentWidth(value);
            ImGui::PushStyleColor(ImGuiCol_Text, color);
            ImGui::PushTextWrapPos(0.0f);
            ImGui::TextUnformatted(text.c_str());
            ImGui::PopTextWrapPos();
            ImGui::PopStyleColor();
        }

        void WrappedTextDisabled(const std::wstring& value)
        {
            WrappedTextColored(ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled), WideToUtf8(value));
        }

        void WrappedTextDisabled(const std::string& value)
        {
            WrappedTextColored(ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled), value);
        }

        void RenderWrappedTooltip(const std::string& text, float wrapWidth = 520.0f)
        {
            if (text.empty())
            {
                return;
            }

            ImGui::BeginTooltip();
            ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + wrapWidth);
            ImGui::TextUnformatted(text.c_str());
            ImGui::PopTextWrapPos();
            ImGui::EndTooltip();
        }

        void RenderWrappedTooltip(const std::wstring& text, float wrapWidth = 520.0f)
        {
            RenderWrappedTooltip(WideToUtf8(text), wrapWidth);
        }

        void ClippedTextWithTooltip(const std::wstring& value, float tooltipWrapWidth = 600.0f)
        {
            const std::string text = WideToUtf8(value);
            ImGui::TextUnformatted(text.c_str());
            if (ImGui::IsItemHovered() && !text.empty())
            {
                RenderWrappedTooltip(text, tooltipWrapWidth);
            }
        }

        bool PushFontIfAvailable(ImFont* font)
        {
            if (font == nullptr)
            {
                return false;
            }

            ImGui::PushFont(font);
            return true;
        }

        void PopFontIfPushed(bool pushed)
        {
            if (pushed)
            {
                ImGui::PopFont();
            }
        }

        void LabelValue(const char* label, const std::wstring& value)
        {
            ImGui::TextDisabled("%s", label);
            ImGui::SameLine(145.0f);
            TextWide(value.empty() ? L"(empty)" : value);
        }

        void LabelValue(const char* label, const char* value)
        {
            ImGui::TextDisabled("%s", label);
            ImGui::SameLine(145.0f);
            ImGui::TextUnformatted(value);
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

        std::wstring FileSizeText(std::uint64_t bytes)
        {
            std::wstringstream stream;
            stream << bytes << L" bytes";
            if (bytes >= 1024)
            {
                const double kib = static_cast<double>(bytes) / 1024.0;
                stream << L" (";
                if (kib >= 1024.0)
                {
                    stream << std::fixed << std::setprecision(1) << (kib / 1024.0) << L" MiB";
                }
                else
                {
                    stream << std::fixed << std::setprecision(1) << kib << L" KiB";
                }
                stream << L")";
            }
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

        void SeverityText(Core::Severity severity)
        {
            ImGui::TextColored(SeverityColor(severity), "%s", WideToUtf8(Core::SeverityToString(severity)).c_str());
        }

        void SeverityBadge(Core::Severity severity)
        {
            const std::string label = WideToUtf8(Core::SeverityToString(severity));
            const ImVec2 textSize = ImGui::CalcTextSize(label.c_str());
            const ImVec2 min = ImGui::GetCursorScreenPos();
            const ImVec2 max(min.x + textSize.x + 18.0f, min.y + textSize.y + 8.0f);
            ImDrawList* drawList = ImGui::GetWindowDrawList();
            const ImU32 border = SeverityU32(severity);
            const ImU32 fill = Core::SeverityRank(severity) >= Core::SeverityRank(Core::Severity::Low)
                ? IM_COL32(38, 28, 24, 255)
                : IM_COL32(24, 30, 38, 255);
            drawList->AddRectFilled(min, max, fill, 4.0f);
            drawList->AddRect(min, max, border, 4.0f, 0, 1.4f);
            drawList->AddText(ImVec2(min.x + 9.0f, min.y + 4.0f), border, label.c_str());
            ImGui::Dummy(ImVec2(textSize.x + 18.0f, textSize.y + 8.0f));
        }

        void StatCard(
            const char* label,
            const std::string& value,
            const ImVec4& accent,
            float width,
            ImFont* labelFont,
            ImFont* valueFont)
        {
            constexpr float cardHeight = 54.0f;
            ImGui::PushStyleColor(ImGuiCol_ChildBg, CardBg());
            ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(accent.x, accent.y, accent.z, 0.20f));
            ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(6.0f, 2.0f));
            ImGui::BeginChild(
                label,
                ImVec2(width, cardHeight),
                ImGuiChildFlags_Borders | ImGuiChildFlags_AlwaysUseWindowPadding,
                ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
            const float textBlockHeight = ImGui::GetTextLineHeight() * 2.0f + 4.0f;
            ImGui::SetCursorPosY(std::max(ImGui::GetCursorPosY(), (cardHeight - textBlockHeight) * 0.5f));
            const bool pushedLabelFont = PushFontIfAvailable(labelFont);
            ImGui::TextDisabled("%s", label);
            PopFontIfPushed(pushedLabelFont);
            const bool pushedValueFont = PushFontIfAvailable(valueFont);
            ImGui::TextColored(accent, "%s", Shorten(value, 24).c_str());
            PopFontIfPushed(pushedValueFont);
            ImGui::EndChild();
            ImGui::PopStyleVar();
            ImGui::PopStyleColor(2);
        }

        bool ChipButton(const char* label, bool active, const ImVec4& accent)
        {
            const ImVec4 inactive = CardBg();
            ImGui::PushStyleColor(ImGuiCol_Button, active ? ImVec4(accent.x * 0.30f, accent.y * 0.30f, accent.z * 0.30f, 1.0f) : inactive);
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, active ? ImVec4(accent.x * 0.40f, accent.y * 0.40f, accent.z * 0.40f, 1.0f) : PanelHover());
            ImGui::PushStyleColor(ImGuiCol_ButtonActive, active ? ImVec4(accent.x * 0.50f, accent.y * 0.50f, accent.z * 0.50f, 1.0f) : ImVec4(0.105f, 0.155f, 0.220f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_Border, active ? ImVec4(accent.x, accent.y, accent.z, 0.65f) : PanelBorder());
            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(10.0f, 5.0f));
            const bool clicked = ImGui::Button(label, ImVec2(0.0f, 29.0f));
            ImGui::PopStyleVar();
            ImGui::PopStyleColor();
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
            ImGui::PopStyleColor(3);
            return clicked;
        }

        float ChipButtonWidth(const char* label)
        {
            return ImGui::CalcTextSize(label).x + 20.0f;
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
            ImGui::PushStyleColor(ImGuiCol_ChildBg, CardBg());
            ImGui::PushStyleColor(ImGuiCol_Border, PanelBorder());
            ImGui::BeginChild(
                id,
                ImVec2(0.0f, 0.0f),
                ImGuiChildFlags_Borders | ImGuiChildFlags_AlwaysUseWindowPadding | ImGuiChildFlags_AutoResizeY);
            const bool pushedHeadingFont = PushFontIfAvailable(headingFont);
            ImGui::TextColored(ImVec4(AccentBlue().x, AccentBlue().y, AccentBlue().z, 0.92f), "%s", title);
            PopFontIfPushed(pushedHeadingFont);
            ImGui::Spacing();
        }

        void EndInspectorCard()
        {
            ImGui::EndChild();
            ImGui::PopStyleColor(2);
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
            windowClass.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
            windowClass.hIconSm = LoadIconW(nullptr, IDI_APPLICATION);

            if (RegisterClassExW(&windowClass) == 0)
            {
                return false;
            }

            hwnd_ = CreateWindowW(
                windowClass.lpszClassName,
                L"GlassPane - ImGui",
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

            if (!CreateDeviceD3D())
            {
                CleanupDeviceD3D();
                DestroyWindow(hwnd_);
                hwnd_ = nullptr;
                UnregisterClassW(windowClass.lpszClassName, instance_);
                return false;
            }

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

        bool CreateDeviceD3D()
        {
            DXGI_SWAP_CHAIN_DESC swapChainDescription = {};
            swapChainDescription.BufferCount = 2;
            swapChainDescription.BufferDesc.Width = 0;
            swapChainDescription.BufferDesc.Height = 0;
            swapChainDescription.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
            swapChainDescription.BufferDesc.RefreshRate.Numerator = 60;
            swapChainDescription.BufferDesc.RefreshRate.Denominator = 1;
            swapChainDescription.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
            swapChainDescription.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
            swapChainDescription.OutputWindow = hwnd_;
            swapChainDescription.SampleDesc.Count = 1;
            swapChainDescription.SampleDesc.Quality = 0;
            swapChainDescription.Windowed = TRUE;
            swapChainDescription.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

            constexpr D3D_FEATURE_LEVEL featureLevels[] = {
                D3D_FEATURE_LEVEL_11_0,
                D3D_FEATURE_LEVEL_10_0
            };

            const HRESULT result = D3D11CreateDeviceAndSwapChain(
                nullptr,
                D3D_DRIVER_TYPE_HARDWARE,
                nullptr,
                0,
                featureLevels,
                ARRAYSIZE(featureLevels),
                D3D11_SDK_VERSION,
                &swapChainDescription,
                &swapChain_,
                &device_,
                nullptr,
                &deviceContext_);

            if (FAILED(result))
            {
                return false;
            }

            CreateRenderTarget();
            return true;
        }

        void CreateRenderTarget()
        {
            ID3D11Texture2D* backBuffer = nullptr;
            if (SUCCEEDED(swapChain_->GetBuffer(0, IID_PPV_ARGS(&backBuffer))))
            {
                device_->CreateRenderTargetView(backBuffer, nullptr, &renderTargetView_);
                backBuffer->Release();
            }
        }

        void CleanupRenderTarget()
        {
            if (renderTargetView_ != nullptr)
            {
                renderTargetView_->Release();
                renderTargetView_ = nullptr;
            }
        }

        void ResizeRenderTarget(UINT width, UINT height)
        {
            CleanupRenderTarget();
            swapChain_->ResizeBuffers(0, width, height, DXGI_FORMAT_UNKNOWN, 0);
            CreateRenderTarget();
        }

        void CleanupDeviceD3D()
        {
            CleanupRenderTarget();
            if (swapChain_ != nullptr)
            {
                swapChain_->Release();
                swapChain_ = nullptr;
            }
            if (deviceContext_ != nullptr)
            {
                deviceContext_->Release();
                deviceContext_ = nullptr;
            }
            if (device_ != nullptr)
            {
                device_->Release();
                device_ = nullptr;
            }
        }

        void Cleanup()
        {
            ReleasePickerCapture();
            DestroyPickWindowOverlay();
            pickWindowActive_ = false;

            ImGui_ImplDX11_Shutdown();
            ImGui_ImplWin32_Shutdown();
            ImGui::DestroyContext();

            ReleaseIconCache();
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

        ID3D11ShaderResourceView* GetProcessIconTexture(const Core::ProcessInfo& process)
        {
            const std::wstring cacheKey = process.executablePath.empty()
                ? L"__glasspane_default_icon__"
                : ToLower(process.executablePath);

            const auto cached = iconCache_.find(cacheKey);
            if (cached != iconCache_.end())
            {
                return cached->second.texture;
            }

            ID3D11ShaderResourceView* texture = nullptr;
            bool ownsTexture = false;

            HICON extractedIcon = nullptr;
            if (!process.executablePath.empty())
            {
                HICON largeIcon = nullptr;
                if (ExtractIconExW(process.executablePath.c_str(), 0, &largeIcon, nullptr, 1) > 0 && largeIcon != nullptr)
                {
                    extractedIcon = largeIcon;
                }
            }

            if (extractedIcon != nullptr)
            {
                texture = CreateTextureFromIcon(extractedIcon);
                DestroyIcon(extractedIcon);
                ownsTexture = texture != nullptr;
            }

            if (texture == nullptr)
            {
                texture = GetFallbackIconTexture();
                ownsTexture = false;
            }

            iconCache_[cacheKey] = { texture, ownsTexture };
            return texture;
        }

        ID3D11ShaderResourceView* GetFallbackIconTexture()
        {
            if (fallbackIconTexture_ != nullptr)
            {
                return fallbackIconTexture_;
            }

            HICON fallbackIcon = LoadIconW(nullptr, IDI_APPLICATION);
            fallbackIconTexture_ = CreateTextureFromIcon(fallbackIcon);
            return fallbackIconTexture_;
        }

        ID3D11ShaderResourceView* CreateTextureFromIcon(HICON icon) const
        {
            if (icon == nullptr || device_ == nullptr)
            {
                return nullptr;
            }

            constexpr int iconSize = 32;
            BITMAPINFO bitmapInfo = {};
            bitmapInfo.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
            bitmapInfo.bmiHeader.biWidth = iconSize;
            bitmapInfo.bmiHeader.biHeight = -iconSize;
            bitmapInfo.bmiHeader.biPlanes = 1;
            bitmapInfo.bmiHeader.biBitCount = 32;
            bitmapInfo.bmiHeader.biCompression = BI_RGB;

            HDC screenDc = GetDC(nullptr);
            if (screenDc == nullptr)
            {
                return nullptr;
            }

            void* bits = nullptr;
            HBITMAP bitmap = CreateDIBSection(screenDc, &bitmapInfo, DIB_RGB_COLORS, &bits, nullptr, 0);
            if (bitmap == nullptr || bits == nullptr)
            {
                if (bitmap != nullptr)
                {
                    DeleteObject(bitmap);
                }
                ReleaseDC(nullptr, screenDc);
                return nullptr;
            }

            HDC memoryDc = CreateCompatibleDC(screenDc);
            if (memoryDc == nullptr)
            {
                DeleteObject(bitmap);
                ReleaseDC(nullptr, screenDc);
                return nullptr;
            }

            HGDIOBJ oldBitmap = SelectObject(memoryDc, bitmap);
            std::memset(bits, 0, static_cast<std::size_t>(iconSize * iconSize * 4));
            DrawIconEx(memoryDc, 0, 0, icon, iconSize, iconSize, 0, nullptr, DI_NORMAL);
            SelectObject(memoryDc, oldBitmap);

            D3D11_TEXTURE2D_DESC textureDescription = {};
            textureDescription.Width = iconSize;
            textureDescription.Height = iconSize;
            textureDescription.MipLevels = 1;
            textureDescription.ArraySize = 1;
            textureDescription.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
            textureDescription.SampleDesc.Count = 1;
            textureDescription.Usage = D3D11_USAGE_DEFAULT;
            textureDescription.BindFlags = D3D11_BIND_SHADER_RESOURCE;

            D3D11_SUBRESOURCE_DATA initialData = {};
            initialData.pSysMem = bits;
            initialData.SysMemPitch = iconSize * 4;

            ID3D11Texture2D* texture = nullptr;
            ID3D11ShaderResourceView* textureView = nullptr;
            if (SUCCEEDED(device_->CreateTexture2D(&textureDescription, &initialData, &texture)) && texture != nullptr)
            {
                if (FAILED(device_->CreateShaderResourceView(texture, nullptr, &textureView)))
                {
                    textureView = nullptr;
                }
                texture->Release();
            }

            DeleteDC(memoryDc);
            DeleteObject(bitmap);
            ReleaseDC(nullptr, screenDc);

            return textureView;
        }

        void ReleaseIconCache()
        {
            for (auto& [path, icon] : iconCache_)
            {
                (void)path;
                if (icon.ownsTexture && icon.texture != nullptr)
                {
                    icon.texture->Release();
                    icon.texture = nullptr;
                }
            }
            iconCache_.clear();

            if (fallbackIconTexture_ != nullptr)
            {
                fallbackIconTexture_->Release();
                fallbackIconTexture_ = nullptr;
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

        static std::uint64_t ElapsedMs(ULONGLONG started)
        {
            return static_cast<std::uint64_t>(GetTickCount64() - started);
        }

        static std::uint64_t ProcessCacheStamp(const Core::ProcessInfo& process)
        {
            return process.hasCreationTime ? process.creationTimeFileTime : 0;
        }

        static bool CacheMatchesProcess(
            std::uint32_t cachedPid,
            std::uint64_t cachedCreationTime,
            const Core::ProcessInfo& process)
        {
            if (cachedPid != process.pid)
            {
                return false;
            }

            if (process.hasCreationTime)
            {
                return cachedCreationTime == process.creationTimeFileTime;
            }

            return cachedCreationTime == 0;
        }

        bool ModulesLoadedForProcess(const Core::ProcessInfo& process) const
        {
            return selectedModulesLoaded_ &&
                CacheMatchesProcess(selectedModulesPid_, selectedModulesCreationTime_, process);
        }

        bool TokenLoadedForProcess(const Core::ProcessInfo& process) const
        {
            return selectedTokenLoaded_ &&
                CacheMatchesProcess(selectedTokenPid_, selectedTokenCreationTime_, process);
        }

        bool RuntimeLoadedForProcess(const Core::ProcessInfo& process) const
        {
            return selectedRuntimeLoaded_ &&
                CacheMatchesProcess(selectedRuntimePid_, selectedRuntimeCreationTime_, process);
        }

        bool MemoryLoadedForProcess(const Core::ProcessInfo& process) const
        {
            return selectedMemoryLoaded_ &&
                CacheMatchesProcess(selectedMemoryPid_, selectedMemoryCreationTime_, process);
        }

        bool HandlesLoadedForProcess(const Core::ProcessInfo& process) const
        {
            return selectedHandlesLoaded_ &&
                CacheMatchesProcess(selectedHandlesPid_, selectedHandlesCreationTime_, process);
        }

        void ClearSelectedProcessEvidence()
        {
            selectedModules_ = {};
            selectedModulesLoaded_ = false;
            selectedModulesPid_ = InvalidPid;
            selectedModulesCreationTime_ = 0;
            selectedModulePid_ = InvalidPid;
            selectedModuleIndex_ = 0;

            selectedToken_ = {};
            selectedTokenLoaded_ = false;
            selectedTokenPid_ = InvalidPid;
            selectedTokenCreationTime_ = 0;

            selectedRuntime_ = {};
            selectedRuntimeLoaded_ = false;
            selectedRuntimePid_ = InvalidPid;
            selectedRuntimeCreationTime_ = 0;

            selectedMemory_ = {};
            selectedMemoryLoaded_ = false;
            selectedMemoryPid_ = InvalidPid;
            selectedMemoryCreationTime_ = 0;
            visibleMemoryRegionsDirty_ = true;
            visibleMemoryRegionIndexes_.clear();
            visibleMemoryPid_ = InvalidPid;
            visibleMemoryCreationTime_ = 0;
            visibleMemorySourceSize_ = 0;
            visibleMemorySearchText_.clear();

            selectedHandles_ = {};
            selectedHandlesLoaded_ = false;
            selectedHandlesPid_ = InvalidPid;
            selectedHandlesCreationTime_ = 0;
            visibleHandlesDirty_ = true;
            visibleHandleIndexes_.clear();
            visibleHandlesPid_ = InvalidPid;
            visibleHandlesCreationTime_ = 0;
            visibleHandlesSourceSize_ = 0;
            visibleHandlesWithIndicatorsCount_ = 0;
            visibleHandlesNameStatusCount_ = 0;
            visibleHandlesSearchText_.clear();

            InvalidateFindingsCache();
        }

        void RefreshNetwork(bool logActivity = true)
        {
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
            context.fileIdentity = &fileIdentity;
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

        void MarkSelectedEvidenceTablesNeedAutoSize()
        {
            modulesTableNeedsAutoSize_ = true;
            networkTableNeedsAutoSize_ = true;
            tokenTableNeedsAutoSize_ = true;
            runtimeTableNeedsAutoSize_ = true;
            memoryTableNeedsAutoSize_ = true;
            handlesTableNeedsAutoSize_ = true;
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

            AddLog(
                selectedFindingsCache_.empty() ? LogLevel::Info : LogLevel::Warning,
                "Triage findings recomputed for PID " + std::to_string(process.pid) +
                    ": " + std::to_string(selectedFindingsCache_.size()) +
                    " finding(s) in " + std::to_string(timings_.findingsMs) + " ms.");
            return selectedFindingsCache_;
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

            const Core::ChainAnalysisResult chain = Core::AnalyzeChain(snapshot_, process->pid);
            const Core::FileIdentity& fileIdentity = CachedFileIdentity(process->executablePath);
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

        void RefreshSnapshot()
        {
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
            RebuildFocusedGraph("snapshot-refresh");
            RequestGraphFit();
            RebuildVisibleProcessRowsIfNeeded();
            RebuildGraphWorldLayoutIfNeeded();
            InvalidateFindingsCache();
            AddLog(
                suspiciousCount_ == 0 ? LogLevel::Info : LogLevel::Warning,
                "Snapshot loaded: " + std::to_string(snapshot_.processes.size()) +
                    " processes, " + std::to_string(suspiciousCount_) +
                    " suspicious in " + std::to_string(timings_.processSnapshotMs) +
                    " ms. Filter " + std::to_string(timings_.processFilterMs) +
                    " ms, graph layout " + std::to_string(timings_.graphLayoutMs) + " ms.");
        }

        void RefreshHandlesForSelectionChange(const Core::ProcessInfo& process)
        {
            if (HandlesLoadedForProcess(process))
            {
                return;
            }

            const ULONGLONG started = GetTickCount64();
            RefreshHandles(false);
            const ULONGLONG elapsedMs = GetTickCount64() - started;

            std::string message =
                "Handles refreshed for selected PID " + std::to_string(process.pid) +
                ": " + std::to_string(selectedHandles_.handles.size()) +
                " handle(s), " + std::to_string(selectedHandles_.sensitiveCount) +
                " sensitive, " + std::to_string(elapsedMs) + " ms.";
            if (!selectedHandles_.success && !selectedHandles_.statusMessage.empty())
            {
                message += " " + WideToUtf8(selectedHandles_.statusMessage);
            }

            AddLog(selectedHandles_.success ? LogLevel::Info : LogLevel::Warning, message);
        }

        void RefreshRuntimeForSelectionChange(const Core::ProcessInfo& process)
        {
            if (RuntimeLoadedForProcess(process))
            {
                return;
            }

            const ULONGLONG started = GetTickCount64();
            RefreshRuntime(false);
            const ULONGLONG elapsedMs = GetTickCount64() - started;

            std::string message =
                "Runtime refreshed for selected PID " + std::to_string(process.pid) +
                ": " + std::to_string(selectedRuntime_.threadCount) +
                " thread(s), " + std::to_string(selectedRuntime_.handleCount) +
                " handle(s), " + std::to_string(elapsedMs) + " ms.";
            if (!selectedRuntime_.success && !selectedRuntime_.errorMessage.empty())
            {
                message += " " + WideToUtf8(selectedRuntime_.errorMessage);
            }

            AddLog(selectedRuntime_.success ? LogLevel::Info : LogLevel::Warning, message);
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

        void RequestGraphFit()
        {
            graphFitRequested_ = true;
            graphFitPid_ = focusedGraph_.focusPid;
        }

        void RebuildFocusedGraph(const char*)
        {
            const ULONGLONG started = GetTickCount64();
            focusedGraph_ = Core::BuildFocusedTree(snapshot_, selectedPid_, 2);
            timings_.graphLayoutMs = ElapsedMs(started);
            graphLayoutDirty_ = true;
        }

        void RebuildGraphWorldLayoutIfNeeded()
        {
            if (!graphLayoutDirty_ &&
                graphLayoutFocusPid_ == focusedGraph_.focusPid &&
                graphLayoutNodeCount_ == focusedGraph_.nodes.size() &&
                graphLayoutEdgeCount_ == focusedGraph_.edges.size() &&
                graphLayoutCachedMode_ == graphLayoutMode_)
            {
                return;
            }

            const ULONGLONG started = GetTickCount64();
            graphLayoutNodes_.clear();
            graphLayoutNodeIndexByPid_.clear();
            graphLayoutHasWorldBounds_ = false;
            graphLayoutSingleNode_ = focusedGraph_.nodes.size() == 1;
            graphLayoutSmallGraph_ = focusedGraph_.nodes.size() >= 2 && focusedGraph_.nodes.size() <= 5;
            graphLayoutBaseNodeSize_ = graphLayoutSingleNode_
                ? ImVec2(342.0f, 126.0f)
                : (graphLayoutSmallGraph_ ? ImVec2(318.0f, 112.0f) : ImVec2(302.0f, 106.0f));

            std::unordered_map<std::size_t, std::vector<std::size_t>> levels;
            std::size_t maxDepth = 0;
            for (std::size_t nodeIndex = 0; nodeIndex < focusedGraph_.nodes.size(); ++nodeIndex)
            {
                const Core::FocusedGraphNode& node = focusedGraph_.nodes[nodeIndex];
                levels[node.depth].push_back(nodeIndex);
                maxDepth = std::max(maxDepth, node.depth);
            }

            graphLayoutNodes_.resize(focusedGraph_.nodes.size());
            const float siblingSpacing = graphLayoutSingleNode_ ? 0.0f : (graphLayoutSmallGraph_ ? 170.0f : 190.0f);
            const float levelSpacing = graphLayoutMode_ == GraphLayoutMode::LeftToRight ? 166.0f : 132.0f;
            for (std::size_t depth = 0; depth <= maxDepth; ++depth)
            {
                auto level = levels.find(depth);
                if (level == levels.end())
                {
                    continue;
                }

                std::vector<std::size_t>& nodeIndexes = level->second;
                std::sort(nodeIndexes.begin(), nodeIndexes.end(), [this](std::size_t leftIndex, std::size_t rightIndex) {
                    if (leftIndex >= focusedGraph_.nodes.size() || rightIndex >= focusedGraph_.nodes.size())
                    {
                        return leftIndex < rightIndex;
                    }
                    return focusedGraph_.nodes[leftIndex].pid < focusedGraph_.nodes[rightIndex].pid;
                });

                const float count = static_cast<float>(nodeIndexes.size());
                if (graphLayoutMode_ == GraphLayoutMode::LeftToRight)
                {
                    const float totalHeight =
                        count * graphLayoutBaseNodeSize_.y + std::max(0.0f, count - 1.0f) * siblingSpacing;
                    const float startY = -totalHeight * 0.5f + graphLayoutBaseNodeSize_.y * 0.5f;
                    const float x = static_cast<float>(depth) * (graphLayoutBaseNodeSize_.x + levelSpacing);
                    for (std::size_t index = 0; index < nodeIndexes.size(); ++index)
                    {
                        const std::size_t nodeIndex = nodeIndexes[index];
                        if (nodeIndex >= graphLayoutNodes_.size())
                        {
                            continue;
                        }
                        graphLayoutNodes_[nodeIndex].nodeIndex = nodeIndex;
                        graphLayoutNodes_[nodeIndex].worldCenter = ImVec2(
                            x,
                            startY + static_cast<float>(index) * (graphLayoutBaseNodeSize_.y + siblingSpacing));
                    }
                }
                else
                {
                    const float totalWidth =
                        count * graphLayoutBaseNodeSize_.x + std::max(0.0f, count - 1.0f) * siblingSpacing;
                    const float startX = -totalWidth * 0.5f + graphLayoutBaseNodeSize_.x * 0.5f;
                    const float y = static_cast<float>(depth) * (graphLayoutBaseNodeSize_.y + levelSpacing);
                    for (std::size_t index = 0; index < nodeIndexes.size(); ++index)
                    {
                        const std::size_t nodeIndex = nodeIndexes[index];
                        if (nodeIndex >= graphLayoutNodes_.size())
                        {
                            continue;
                        }
                        graphLayoutNodes_[nodeIndex].nodeIndex = nodeIndex;
                        graphLayoutNodes_[nodeIndex].worldCenter = ImVec2(
                            startX + static_cast<float>(index) * (graphLayoutBaseNodeSize_.x + siblingSpacing),
                            y);
                    }
                }
            }

            for (std::size_t layoutIndex = 0; layoutIndex < graphLayoutNodes_.size(); ++layoutIndex)
            {
                const GraphLayoutNode& visual = graphLayoutNodes_[layoutIndex];
                if (visual.nodeIndex >= focusedGraph_.nodes.size())
                {
                    continue;
                }

                graphLayoutNodeIndexByPid_[focusedGraph_.nodes[visual.nodeIndex].pid] = layoutIndex;
                const ImVec2 min(
                    visual.worldCenter.x - graphLayoutBaseNodeSize_.x * 0.5f,
                    visual.worldCenter.y - graphLayoutBaseNodeSize_.y * 0.5f);
                const ImVec2 max(
                    visual.worldCenter.x + graphLayoutBaseNodeSize_.x * 0.5f,
                    visual.worldCenter.y + graphLayoutBaseNodeSize_.y * 0.5f);
                if (!graphLayoutHasWorldBounds_)
                {
                    graphLayoutWorldMin_ = min;
                    graphLayoutWorldMax_ = max;
                    graphLayoutHasWorldBounds_ = true;
                }
                else
                {
                    graphLayoutWorldMin_.x = std::min(graphLayoutWorldMin_.x, min.x);
                    graphLayoutWorldMin_.y = std::min(graphLayoutWorldMin_.y, min.y);
                    graphLayoutWorldMax_.x = std::max(graphLayoutWorldMax_.x, max.x);
                    graphLayoutWorldMax_.y = std::max(graphLayoutWorldMax_.y, max.y);
                }
            }

            graphLayoutFocusPid_ = focusedGraph_.focusPid;
            graphLayoutNodeCount_ = focusedGraph_.nodes.size();
            graphLayoutEdgeCount_ = focusedGraph_.edges.size();
            graphLayoutCachedMode_ = graphLayoutMode_;
            graphLayoutDirty_ = false;
            timings_.graphLayoutMs = ElapsedMs(started);
        }

        void ResetGraphView()
        {
            graphZoom_ = 1.0f;
            graphPan_ = ImVec2(0.0f, 0.0f);
            RequestGraphFit();
        }

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
            if (changed)
            {
                RefreshToken(false);
                RefreshRuntimeForSelectionChange(*selectedProcess);
                RefreshHandlesForSelectionChange(*selectedProcess);
                if (inspectorTab_ == InspectorTab::Network)
                {
                    RequestNetworkTableAutoFit(selectedPid_);
                }
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
                Core::SeverityRank(selectedProcess->severity) >= Core::SeverityRank(Core::Severity::High)
                    ? LogLevel::High
                    : LogLevel::Info,
                "Picked HWND " + FormatWindowHandle(pickedWindow) +
                    " owned by " + DisplayName(selectedProcess->name) +
                    " (PID " + std::to_string(selectedProcess->pid) + ").");
        }

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

        std::string ActiveChipLabel() const
        {
            switch (processFilterMode_)
            {
            case ProcessFilterMode::All:
                return "All";
            case ProcessFilterMode::Suspicious:
                return "Suspicious";
            case ProcessFilterMode::Low:
                return "Low";
            case ProcessFilterMode::Medium:
                return "Medium";
            case ProcessFilterMode::High:
                return "High";
            default:
                return "All";
            }
        }

        void RenderUi()
        {
            RenderToolbar();
            RenderAboutPopup();
            RenderResetLayoutPopup();

#ifdef IMGUI_HAS_DOCK
            RenderDockedWorkspace();
#else
            RenderFixedWorkspace();
#endif
        }

        void RenderFixedWorkspace()
        {
            const ImGuiViewport* viewport = ImGui::GetMainViewport();
            constexpr float margin = 10.0f;
            constexpr float gap = 10.0f;
            constexpr float headerHeight = 108.0f;
            const float bottomHeight = std::clamp(viewport->WorkSize.y * 0.18f, 150.0f, 220.0f);
            const float bodyTop = headerHeight + gap;
            const float bodyHeight = std::max(280.0f, viewport->WorkSize.y - bodyTop - bottomHeight - (margin * 2.0f));
            const float leftWidth = std::clamp(viewport->WorkSize.x * 0.20f, 300.0f, 365.0f);
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
            constexpr float headerHeight = 108.0f;
            const float bodyTop = headerHeight + gap;
            const ImVec2 dockHostPos(
                viewport->WorkPos.x + margin,
                viewport->WorkPos.y + bodyTop);
            const ImVec2 dockHostSize(
                std::max(640.0f, viewport->WorkSize.x - (margin * 2.0f)),
                std::max(360.0f, viewport->WorkSize.y - bodyTop - margin));

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

            dockspaceId_ = ImGui::GetID("GlassPaneDockSpace-v0.2.3");
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

            ImGui::DockBuilderSplitNode(dockMain, ImGuiDir_Down, 0.19f, &dockBottom, &dockMain);
            ImGui::DockBuilderSplitNode(dockMain, ImGuiDir_Left, 0.17f, &dockLeft, &dockMain);
            ImGui::DockBuilderSplitNode(dockMain, ImGuiDir_Right, 0.205f, &dockRight, &dockCenter);

            leftDockId_ = dockLeft;
            centerDockId_ = dockCenter;
            rightDockId_ = dockRight;
            bottomDockId_ = dockBottom;

            ImGui::DockBuilderDockWindow("Processes", leftDockId_);

            ImGui::DockBuilderDockWindow("Graph", centerDockId_);
            ImGui::DockBuilderDockWindow("Timeline", centerDockId_);

            ImGui::DockBuilderDockWindow("Inspector", rightDockId_);

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

            if (rightDockLayoutFocusRequested_)
            {
                ImGui::SetNextWindowFocus();
            }
            RenderRightPanel();
            rightDockLayoutFocusRequested_ = false;

            RenderDockedContentPanel("Indicators", [this]() { RenderSelectedIndicators(); });
            RenderDockedContentPanel("Logs", [this]() { RenderLogsPanelContent(); });

            ApplyDockNodeChromeFlags(dockspaceId_);
        }

        void RequestDockLayoutReset()
        {
            resetDockLayoutRequested_ = true;
            dockspaceBuilt_ = false;
        }
#endif

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
            if (aboutPopupRequested_)
            {
                ImGui::OpenPopup("About GlassPane");
                aboutPopupOpenedFrame_ = ImGui::GetFrameCount();
                aboutPopupRequested_ = false;
            }

            bool closeRequested = false;
            if (BeginGlassPaneModal(
                    "About GlassPane",
                    aboutPopupOpenedFrame_,
                    ImVec2(520.0f, 0.0f),
                    &closeRequested))
            {
                const std::string appVersion = GlassPaneVersion();
                const bool pushedTitleFont = PushFontIfAvailable(fonts_.title);
                ImGui::TextColored(AccentBlue(), "GlassPane");
                PopFontIfPushed(pushedTitleFont);
                ImGui::TextDisabled("Version: %s", appVersion.c_str());
                ImGui::Spacing();
                WrappedTextWide(L"Read-only Windows process and forensic context analysis dashboard.");

                ImGui::SeparatorText("Build");
                LabelValue("Architecture", BuildArchitecture());
                LabelValue("Configuration", BuildConfiguration());

                ImGui::SeparatorText("Links");
                ImGui::TextDisabled("GitHub");
                ImGui::SameLine(120.0f);
                ImGui::TextColored(AccentBlue(), "%s", GlassPaneGithubUrl);

                ImGui::SeparatorText("Safety Model");
                ImGui::BulletText("Read-only inspection");
                ImGui::BulletText("No process killing");
                ImGui::BulletText("No injection");
                ImGui::BulletText("No tampering");
                ImGui::BulletText("No remediation");

                ImGui::SeparatorText("Disclaimer");
                WrappedTextDisabled("Findings are evidence worth investigating, not proof of malicious activity.");

                ImGui::Spacing();
                if (ImGui::Button("Copy GitHub URL"))
                {
                    ImGui::SetClipboardText(GlassPaneGithubUrl);
                    AddLog(LogLevel::Info, "Copied GlassPane GitHub URL to clipboard.");
                }
                ImGui::SameLine();
                if (ImGui::Button("Close"))
                {
                    closeRequested = true;
                }

                EndGlassPaneModal(closeRequested);
            }
        }

        void RenderResetLayoutPopup()
        {
            if (resetLayoutPopupRequested_)
            {
                ImGui::OpenPopup("Reset Layout?");
                resetLayoutPopupOpenedFrame_ = ImGui::GetFrameCount();
                resetLayoutPopupRequested_ = false;
            }

            bool closeRequested = false;
            if (BeginGlassPaneModal(
                    "Reset Layout?",
                    resetLayoutPopupOpenedFrame_,
                    ImVec2(560.0f, 0.0f),
                    &closeRequested))
            {
                const bool pushedTitleFont = PushFontIfAvailable(fonts_.bold);
                ImGui::TextColored(AccentBlue(), "Reset Layout?");
                PopFontIfPushed(pushedTitleFont);
                ImGui::Spacing();
                WrappedTextDisabled("This will restore the default GlassPane workspace layout.");
                ImGui::Spacing();
                ImGui::Separator();
                ImGui::Spacing();

                if (ImGui::Button("Reset Layout"))
                {
                    RequestDockLayoutReset();
                    closeRequested = true;
                }
                ImGui::SameLine();
                if (ImGui::Button("Cancel"))
                {
                    closeRequested = true;
                }

                EndGlassPaneModal(closeRequested);
            }
        }

        void RenderToolbar()
        {
            const ImGuiViewport* viewport = ImGui::GetMainViewport();
            const float headerWindowWidth = std::max(viewport->WorkSize.x - 16.0f, 960.0f);
            ImGui::SetNextWindowPos(
                ImVec2(viewport->WorkPos.x + 8.0f, viewport->WorkPos.y + 8.0f),
                ImGuiCond_Always);
            ImGui::SetNextWindowSize(
                ImVec2(headerWindowWidth, 96.0f),
                ImGuiCond_Always);

            ImGui::PushStyleColor(ImGuiCol_WindowBg, HeaderBg());
            ImGui::PushStyleColor(ImGuiCol_Border, PanelBorder());
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(16.0f, 11.0f));
            ImGuiWindowFlags headerFlags =
                ImGuiWindowFlags_NoTitleBar |
                ImGuiWindowFlags_NoCollapse |
                ImGuiWindowFlags_NoResize |
                ImGuiWindowFlags_NoMove |
                ImGuiWindowFlags_NoScrollbar;
#ifdef IMGUI_HAS_DOCK
            headerFlags |= ImGuiWindowFlags_NoDocking;
#endif
            ImGui::Begin(
                "GlassPane Header",
                nullptr,
                headerFlags);

            const bool narrowHeader = headerWindowWidth < 1180.0f;
            const bool compactHeader = headerWindowWidth < 1320.0f;
            const float statsWidth = narrowHeader ? 376.0f : (compactHeader ? 456.0f : 516.0f);
            const float brandWidth = narrowHeader ? 360.0f : (compactHeader ? 440.0f : 500.0f);
            const float processCardWidth = narrowHeader ? 92.0f : (compactHeader ? 112.0f : 128.0f);
            const float suspiciousCardWidth = narrowHeader ? 98.0f : (compactHeader ? 112.0f : 128.0f);
            const float refreshCardWidth = narrowHeader ? 166.0f : (compactHeader ? 208.0f : 228.0f);
            constexpr float rowHeight = 64.0f;
            const float contentTop = ImGui::GetCursorPosY();
            const float centeredRowY = contentTop + std::max(0.0f, (ImGui::GetContentRegionAvail().y - rowHeight) * 0.5f);

            if (ImGui::BeginTable("HeaderLayoutTable##TopToolbar", 3, ImGuiTableFlags_SizingStretchProp))
            {
                ImGui::TableSetupColumn("brand", ImGuiTableColumnFlags_WidthFixed, brandWidth);
                ImGui::TableSetupColumn("controls", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("stats", ImGuiTableColumnFlags_WidthFixed, statsWidth);
                ImGui::TableNextRow();

                ImGui::TableSetColumnIndex(0);
                ImGui::SetCursorPosY(centeredRowY + 2.0f);
                const ImVec2 titlePosition = ImGui::GetCursorScreenPos();
                bool pushedTitleFont = PushFontIfAvailable(fonts_.title);
                const ImVec2 titleSize = ImGui::CalcTextSize("GlassPane");
                PopFontIfPushed(pushedTitleFont);
                ImGui::InvisibleButton("##glasspane_about_title", titleSize);
                const bool titleHovered = ImGui::IsItemHovered();
                if (titleHovered)
                {
                    ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
                    ImGui::SetTooltip("About GlassPane");
                }
                if (titleHovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
                {
                    aboutPopupRequested_ = true;
                }
                ImGui::SetCursorScreenPos(titlePosition);
                pushedTitleFont = PushFontIfAvailable(fonts_.title);
                ImGui::TextColored(
                    titleHovered ? ImVec4(0.56f, 0.76f, 0.98f, 1.0f) : AccentBlue(),
                    "GlassPane");
                PopFontIfPushed(pushedTitleFont);
                ImGui::SetCursorPosY(centeredRowY + 36.0f);
                if (ImGui::Button("Refresh"))
                {
                    RefreshSnapshot();
                }
                ImGui::SameLine();
                if (ImGui::Button("Pick Window"))
                {
                    StartPickWindowMode();
                }
                ImGui::SameLine();
                if (ImGui::Button("Export JSON"))
                {
                    ExportSnapshot();
                }
                ImGui::SameLine();
                if (ImGui::Button("Refresh Modules"))
                {
                    RefreshModules();
                }
#ifdef IMGUI_HAS_DOCK
                ImGui::SameLine();
                if (ImGui::Button("Reset Layout"))
                {
                    resetLayoutPopupRequested_ = true;
                }
#endif

                ImGui::TableSetColumnIndex(1);
                ImGui::SetCursorPosY(centeredRowY + 21.0f);
                const float controlsAvail = ImGui::GetContentRegionAvail().x;
                const float minSearchWidth = narrowHeader ? 160.0f : (compactHeader ? 220.0f : 260.0f);
                const float maxSearchWidth = narrowHeader ? 240.0f : (compactHeader ? 360.0f : 460.0f);
                const float searchWidth = std::clamp(controlsAvail - 72.0f, minSearchWidth, maxSearchWidth);
                const float controlsWidth =
                    ImGui::CalcTextSize("Search").x +
                    searchWidth +
                    16.0f;
                const float centeredControlsX = ImGui::GetCursorPosX() + std::max(0.0f, (controlsAvail - controlsWidth) * 0.5f);
                ImGui::SetCursorPosX(centeredControlsX);
                ImGui::BeginGroup();
                ImGui::TextColored(MutedText(), "Search");
                ImGui::SameLine();
                ImGui::SetNextItemWidth(searchWidth);
                if (ImGui::InputTextWithHint("##ProcessPanelSearch", "name, path, command line, PID, indicator", searchBuffer_.data(), searchBuffer_.size()))
                {
                    SetProcessSearchText(ToLower(Utf8ToWide(searchBuffer_.data())));
                }
                ImGui::EndGroup();

                if (pickWindowActive_)
                {
                    ImGui::SetCursorPosX(centeredControlsX);
                    ImGui::SetCursorPosY(centeredRowY + 52.0f);
                    const bool pushedPickerFont = PushFontIfAvailable(fonts_.smallUi);
                    ImGui::TextColored(
                        ImVec4(AccentBlue().x, AccentBlue().y, AccentBlue().z, 0.95f),
                        "Pick mode: click a window. Esc cancels.");
                    PopFontIfPushed(pushedPickerFont);
                }

                ImGui::TableSetColumnIndex(2);
                ImGui::SetCursorPosY(centeredRowY + 5.0f);
                StatCard("Processes", std::to_string(snapshot_.processes.size()), AccentBlue(), processCardWidth, fonts_.smallUi, fonts_.bold);
                ImGui::SameLine();
                StatCard("Suspicious", std::to_string(suspiciousCount_), SeverityColor(Core::Severity::High), suspiciousCardWidth, fonts_.smallUi, fonts_.bold);
                ImGui::SameLine();
                StatCard("Last refresh", WideToUtf8(lastRefreshTime_), PrimaryText(), refreshCardWidth, fonts_.smallUi, fonts_.monospace);

                ImGui::EndTable();
            }
            ImGui::End();
            ImGui::PopStyleVar();
            ImGui::PopStyleColor(2);
        }

        void RenderProcessesPanel()
        {
            if (!BeginPanelWindow("Processes"))
            {
                EndPanelWindow();
                return;
            }
            const bool pushedProcessesFont = PushFontIfAvailable(fonts_.bold);
            ImGui::TextColored(AccentBlue(), "Processes");
            PopFontIfPushed(pushedProcessesFont);
            ImGui::SameLine();
            ImGui::TextDisabled("%zu total", snapshot_.processes.size());
            const bool pushedProcessHelperFont = PushFontIfAvailable(fonts_.smallUi);
            ImGui::TextColored(MutedText(), "Search combines with the active preset");
            if (!searchText_.empty())
            {
                ImGui::SameLine();
                ImGui::TextColored(AccentBlue(), "search active");
            }
            PopFontIfPushed(pushedProcessHelperFont);

            ImGui::PushID("process_filter_chips");
            if (ChipButton("All##ProcessFilter", processFilterMode_ == ProcessFilterMode::All, AccentBlue()))
            {
                SetProcessFilterMode(ProcessFilterMode::All);
            }
            SameLineIfChipFits("Suspicious");
            if (ChipButton("Suspicious##ProcessFilter", processFilterMode_ == ProcessFilterMode::Suspicious, SeverityColor(Core::Severity::High)))
            {
                SetProcessFilterMode(ProcessFilterMode::Suspicious);
            }
            SameLineIfChipFits("Low");
            if (ChipButton("Low##ProcessFilter", processFilterMode_ == ProcessFilterMode::Low, SeverityColor(Core::Severity::Low)))
            {
                SetProcessFilterMode(ProcessFilterMode::Low);
            }
            SameLineIfChipFits("Medium");
            if (ChipButton("Medium##ProcessFilter", processFilterMode_ == ProcessFilterMode::Medium, SeverityColor(Core::Severity::Medium)))
            {
                SetProcessFilterMode(ProcessFilterMode::Medium);
            }
            SameLineIfChipFits("High");
            if (ChipButton("High##ProcessFilter", processFilterMode_ == ProcessFilterMode::High, SeverityColor(Core::Severity::High)))
            {
                SetProcessFilterMode(ProcessFilterMode::High);
            }
            ImGui::PopID();
            ImGui::TextDisabled("Active: %s", ActiveChipLabel().c_str());
            ImGui::Dummy(ImVec2(0.0f, 2.0f));

            const ImGuiTableFlags flags =
                ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Resizable |
                ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_SizingStretchProp |
                ImGuiTableFlags_NoSavedSettings;

            RebuildVisibleProcessRowsIfNeeded();
            const std::vector<VisibleProcessRow>& visibleRows = visibleProcessRows_;
            const float footerHeight = ImGui::GetFrameHeightWithSpacing() + 12.0f;
            if (visibleRows.empty())
            {
                ImGui::BeginChild(
                    "process_empty_state",
                    ImVec2(0.0f, -footerHeight),
                    ImGuiChildFlags_None,
                    ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
                ImGui::TextDisabled("No matching processes.");
                ImGui::EndChild();
            }
            else
            {
                AcknowledgeTableAutoSizeRequest(processTableNeedsAutoSize_);
                if (ImGui::BeginTable("ProcessesTable##ProcessPanel", 4, flags, ImVec2(0.0f, -footerHeight)))
            {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn("Process", ImGuiTableColumnFlags_WidthStretch, 0.0f, 0);
                ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 58.0f, 1);
                ImGui::TableSetupColumn("PPID", ImGuiTableColumnFlags_WidthFixed, 58.0f, 2);
                ImGui::TableSetupColumn("Severity", ImGuiTableColumnFlags_WidthFixed, 86.0f, 3);
                ImGui::TableHeadersRow();

                ImGuiListClipper clipper;
                clipper.Begin(static_cast<int>(visibleRows.size()));
                while (clipper.Step())
                {
                    for (int rowIndex = clipper.DisplayStart; rowIndex < clipper.DisplayEnd; ++rowIndex)
                    {
                        const VisibleProcessRow& row = visibleRows[static_cast<std::size_t>(rowIndex)];
                        if (row.processIndex >= snapshot_.processes.size())
                        {
                            continue;
                        }

                        const Core::ProcessInfo& process = snapshot_.processes[row.processIndex];
                        const bool selected = selectedPid_ == process.pid;
                        ImGui::TableNextRow();
                        if (selected)
                        {
                            const ImU32 selectedRow = ColorU32(TableSelectedRow());
                            ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, selectedRow);
                            ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1, selectedRow);
                        }
                        ImGui::PushID(static_cast<int>(process.pid));

                        ImGui::TableSetColumnIndex(0);
                        ImGui::Indent(static_cast<float>(row.depth) * 16.0f);
                        const std::string name = DisplayName(process.name);
                        if (ImGui::Selectable(name.c_str(), selected, ImGuiSelectableFlags_SpanAllColumns, ImVec2(0.0f, 32.0f)))
                        {
                            SelectProcess(process.pid, true);
                        }
                        if (selected)
                        {
                            const ImVec2 min = ImGui::GetItemRectMin();
                            const ImVec2 max = ImGui::GetItemRectMax();
                            ImGui::GetWindowDrawList()->AddRectFilled(
                                min,
                                ImVec2(min.x + 3.0f, max.y),
                                ColorU32(AccentBlue()),
                                2.0f);
                            if (scrollSelectedProcessIntoView_)
                            {
                                ImGui::SetScrollHereY(0.5f);
                                scrollSelectedProcessIntoView_ = false;
                            }
                        }
                        ImGui::Unindent(static_cast<float>(row.depth) * 16.0f);

                        const bool pushedPidFont = PushFontIfAvailable(fonts_.monospace);
                        ImGui::TableSetColumnIndex(1);
                        ImGui::Text("%u", process.pid);
                        ImGui::TableSetColumnIndex(2);
                        ImGui::Text("%u", process.parentPid);
                        PopFontIfPushed(pushedPidFont);
                        ImGui::TableSetColumnIndex(3);
                        SeverityText(row.filterSeverity);

                        ImGui::PopID();
                    }
                }

                ImGui::EndTable();
            }
            }
            ImGui::TextDisabled("%zu processes", snapshot_.processes.size());
            ImGui::SameLine();
            ImGui::TextDisabled("|");
            ImGui::SameLine();
            ImGui::TextColored(SeverityColor(Core::Severity::High), "%zu suspicious", suspiciousCount_);
            ImGui::SameLine();
            ImGui::TextDisabled("| %zu visible", visibleRows.size());
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
                ImGui::EndTabBar();
            }
            EndPanelWindow();
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
            for (std::size_t index = 0; index < InspectorTabs.size(); ++index)
            {
                contentWidth += ChipButtonWidth(InspectorTabs[index].label);
                if (index + 1 < InspectorTabs.size())
                {
                    contentWidth += spacing;
                }
            }
            const float maxScroll = std::max(0.0f, contentWidth - visibleWidth);
            inspectorTabScrollX_ = std::clamp(inspectorTabScrollX_, 0.0f, maxScroll);

            ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(spacing, 4.0f));
            ImGui::BeginChild(
                "inspector_tab_strip",
                ImVec2(0.0f, stripHeight),
                ImGuiChildFlags_None,
                ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoNavInputs);

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

            ImGui::SetCursorPosX(ImGui::GetCursorPosX() - inspectorTabScrollX_);
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 2.0f);
            for (std::size_t index = 0; index < InspectorTabs.size(); ++index)
            {
                const InspectorTabSpec& spec = InspectorTabs[index];
                if (index > 0)
                {
                    ImGui::SameLine(0.0f, spacing);
                }
                if (ChipButton(spec.label, inspectorTab_ == spec.tab, AccentBlue()))
                {
                    if (!suppressTabClick)
                    {
                        SelectInspectorTab(spec.tab);
                    }
                }
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

            RenderInspectorTabStrip();
            ImGui::Separator();

            ImGui::BeginChild(
                "inspector_content_scroll",
                ImVec2(0.0f, 0.0f),
                ImGuiChildFlags_None);
            switch (inspectorTab_)
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
            ImGui::EndChild();

            ImGui::PopStyleVar(3);
            EndPanelWindow();
        }

        void RenderTriagePanel()
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                ImGui::TextUnformatted("No process selected.");
                return;
            }

            const Core::ChainAnalysisResult chain = Core::AnalyzeChain(snapshot_, process->pid);
            const Core::FileIdentity& fileIdentity = CachedFileIdentity(process->executablePath);
            const std::vector<Core::Finding>& findings =
                FindingsForSelectedProcess(*process, chain, fileIdentity);
            const std::wstring triageSummary = Core::TriageSummary(findings);

            BeginInspectorCard("triage_summary", "Triage Summary", fonts_.bold);
            ImGui::TextDisabled("Selected Process");
            ImGui::SameLine(145.0f);
            TextWide((process->name.empty() ? L"(unknown)" : process->name) + L"  PID " + std::to_wstring(process->pid));
            ImGui::TextDisabled("Triage Verdict");
            ImGui::SameLine(145.0f);
            const Core::Severity verdictColorSeverity = findings.empty()
                ? Core::Severity::None
                : FindingSeverityAsCoreSeverity(Core::HighestFindingSeverity(findings));
            ImGui::TextColored(SeverityColor(verdictColorSeverity), "%s", WideToUtf8(triageSummary).c_str());
            ImGui::TextDisabled("Highest Severity");
            ImGui::SameLine(145.0f);
            if (findings.empty())
            {
                ImGui::TextDisabled("None");
            }
            else
            {
                SeverityText(FindingSeverityAsCoreSeverity(Core::HighestFindingSeverity(findings)));
            }
            LabelValue("Finding Count", std::to_wstring(findings.size()));
            ImGui::Spacing();
            if (ImGui::SmallButton("Copy Triage Summary"))
            {
                CopyTextToClipboard(FormatTriageSummaryForClipboard(*process, findings));
                AddLog(LogLevel::Info, "Copied triage summary to clipboard.");
            }
            ImGui::SameLine();
            if (ImGui::SmallButton("Copy All Findings"))
            {
                CopyTextToClipboard(FormatFindingsForClipboard(*process, findings));
                AddLog(LogLevel::Info, "Copied all triage findings to clipboard.");
            }
            ImGui::SameLine();
            if (ImGui::SmallButton("Export Report"))
            {
                ExportSelectedMarkdownReport();
            }
            EndInspectorCard();

            ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(6.0f, 6.0f));
            if (ChipButton("All##TriageFilter", triageFilter_ == TriageFilter::All, AccentBlue()))
            {
                triageFilter_ = TriageFilter::All;
            }
            SameLineIfChipFits("Info");
            if (ChipButton("Info##TriageFilter", triageFilter_ == TriageFilter::Info, FindingSeverityColor(Core::FindingSeverity::Info)))
            {
                triageFilter_ = TriageFilter::Info;
            }
            SameLineIfChipFits("Low");
            if (ChipButton("Low##TriageFilter", triageFilter_ == TriageFilter::Low, FindingSeverityColor(Core::FindingSeverity::Low)))
            {
                triageFilter_ = TriageFilter::Low;
            }
            SameLineIfChipFits("Medium");
            if (ChipButton("Medium##TriageFilter", triageFilter_ == TriageFilter::Medium, FindingSeverityColor(Core::FindingSeverity::Medium)))
            {
                triageFilter_ = TriageFilter::Medium;
            }
            SameLineIfChipFits("High");
            if (ChipButton("High##TriageFilter", triageFilter_ == TriageFilter::High, FindingSeverityColor(Core::FindingSeverity::High)))
            {
                triageFilter_ = TriageFilter::High;
            }
            ImGui::PopStyleVar();
            ImGui::Spacing();

            if (findings.empty())
            {
                BeginInspectorCard("triage_clean", "Findings", fonts_.bold);
                WrappedTextDisabled("No triage findings for this process.");
                WrappedTextDisabled("Review details, modules, network, and chain context for raw evidence.");
                EndInspectorCard();
                return;
            }

            std::size_t visibleFindings = 0;
            for (std::size_t index = 0; index < findings.size(); ++index)
            {
                const Core::Finding& finding = findings[index];
                if (!FindingMatchesFilter(finding, triageFilter_))
                {
                    continue;
                }

                ++visibleFindings;
                const std::string cardId = "triage_finding_" + std::to_string(index);
                const ImVec4 accent = FindingSeverityColor(finding.severity);
                ImGui::PushStyleColor(ImGuiCol_ChildBg, FindingCardBg(finding.severity));
                ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(accent.x, accent.y, accent.z, 0.55f));
                ImGui::BeginChild(
                    cardId.c_str(),
                    ImVec2(0.0f, 0.0f),
                    ImGuiChildFlags_Borders | ImGuiChildFlags_AlwaysUseWindowPadding | ImGuiChildFlags_AutoResizeY);

                SeverityBadge(FindingSeverityAsCoreSeverity(finding.severity));
                ImGui::SameLine();
                const bool pushedFindingTitleFont = PushFontIfAvailable(fonts_.bold);
                ImGui::TextColored(ImVec4(0.88f, 0.93f, 0.98f, 1.0f), "%s", WideToUtf8(finding.title.empty() ? L"(untitled finding)" : finding.title).c_str());
                PopFontIfPushed(pushedFindingTitleFont);
                ImGui::SameLine();
                if (ImGui::SmallButton("Copy Finding"))
                {
                    CopyTextToClipboard(FormatFindingForClipboard(finding));
                    AddLog(LogLevel::Info, "Copied triage finding to clipboard.");
                }

                ImGui::TextDisabled("Category");
                ImGui::SameLine(145.0f);
                TextWide(finding.category.empty() ? L"(none)" : finding.category);
                WrappedTextWide(finding.description);

                if (!finding.evidence.empty())
                {
                    ImGui::SeparatorText("Evidence");
                    for (const std::wstring& evidence : finding.evidence)
                    {
                        ImGui::TextColored(ImVec4(accent.x, accent.y, accent.z, 0.80f), "-");
                        ImGui::SameLine();
                        WrappedTextDisabled(evidence);
                    }
                }
                ImGui::EndChild();
                ImGui::PopStyleColor(2);
                ImGui::Spacing();
            }

            if (visibleFindings == 0)
            {
                BeginInspectorCard("triage_filter_empty", "Findings", fonts_.bold);
                WrappedTextDisabled("No findings match the current triage filter.");
                WrappedTextDisabled("Current filter: " + WideToUtf8(TriageFilterLabel(triageFilter_)));
                EndInspectorCard();
            }
        }

        void RenderDetailsPanel()
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                ImGui::TextUnformatted("No process selected.");
                return;
            }

            const Core::ParentRelationshipStatus parentRelationshipStatus =
                Core::GetParentRelationshipStatus(snapshot_, *process);
            const Core::ProcessInfo* parent =
                Core::IsUsableParentRelationship(parentRelationshipStatus)
                    ? Core::FindProcessByPid(snapshot_, process->parentPid)
                    : nullptr;
            const Core::ChainAnalysisResult chain = Core::AnalyzeChain(snapshot_, process->pid);
            const NetworkSummary networkSummary = GetNetworkSummary(process->pid);
            const Core::FileIdentity& fileIdentity = CachedFileIdentity(process->executablePath);
            const std::vector<Core::FileIdentityIndicator> fileIdentityIndicators =
                Core::BuildFileIdentityIndicators(fileIdentity, process->name, true);
            const std::vector<Core::Finding>& findings =
                FindingsForSelectedProcess(*process, chain, fileIdentity);
            if (!ProcessMatchesFilters(*process))
            {
                ImGui::TextColored(
                    ImVec4(0.96f, 0.52f, 0.20f, 1.0f),
                    "Selected process hidden by filters.");
                ImGui::Spacing();
            }

            ImGui::PushStyleColor(ImGuiCol_ChildBg, CardBg());
            ImGui::PushStyleColor(ImGuiCol_Border, PanelBorder());
            ImGui::BeginChild(
                "details_header",
                ImVec2(0.0f, 0.0f),
                ImGuiChildFlags_Borders | ImGuiChildFlags_AlwaysUseWindowPadding | ImGuiChildFlags_AutoResizeY);

            ID3D11ShaderResourceView* processIcon = GetProcessIconTexture(*process);
            if (processIcon != nullptr)
            {
                ImGui::Image(reinterpret_cast<ImTextureID>(processIcon), ImVec2(40.0f, 40.0f));
                ImGui::SameLine();
            }
            else
            {
                const ImVec2 iconMin = ImGui::GetCursorScreenPos();
                const ImVec2 iconMax(iconMin.x + 40.0f, iconMin.y + 40.0f);
                ImGui::GetWindowDrawList()->AddRectFilled(iconMin, iconMax, IM_COL32(44, 58, 78, 255), 5.0f);
                ImGui::GetWindowDrawList()->AddRect(iconMin, iconMax, ColorU32(AccentBlue()), 5.0f, 0, 1.0f);
                ImGui::Dummy(ImVec2(40.0f, 40.0f));
                ImGui::SameLine();
            }

            ImGui::BeginGroup();
            const bool pushedProcessTitleFont = PushFontIfAvailable(fonts_.title);
            TextWide(process->name.empty() ? L"(unknown process)" : process->name);
            PopFontIfPushed(pushedProcessTitleFont);
            ImGui::TextDisabled("Triage");
            ImGui::SameLine(82.0f);
            ImGui::TextColored(SeverityColor(findings.empty()
                ? Core::Severity::None
                : FindingSeverityAsCoreSeverity(Core::HighestFindingSeverity(findings))),
                "%s",
                WideToUtf8(Core::TriageSummary(findings)).c_str());
            ImGui::TextDisabled("Process severity");
            ImGui::SameLine(118.0f);
            SeverityBadge(process->severity);
            if (!findings.empty())
            {
                const Core::Severity triageSeverity = FindingSeverityAsCoreSeverity(Core::HighestFindingSeverity(findings));
                if (triageSeverity != process->severity)
                {
                    ImGui::SameLine();
                    ImGui::TextDisabled("Triage severity");
                    ImGui::SameLine();
                    SeverityBadge(triageSeverity);
                }
            }
            const bool pushedHeaderPidFont = PushFontIfAvailable(fonts_.monospace);
            ImGui::TextDisabled("PID %u  |  PPID %u", process->pid, process->parentPid);
            PopFontIfPushed(pushedHeaderPidFont);
            ImGui::EndGroup();

            if (!process->executablePath.empty())
            {
                ImGui::Spacing();
                const bool pushedPathFont = PushFontIfAvailable(fonts_.monospace);
                WrappedTextDisabled(process->executablePath);
                PopFontIfPushed(pushedPathFont);
            }
            ImGui::EndChild();
            ImGui::PopStyleColor(2);
            ImGui::Spacing();

            BeginInspectorCard("details_identity", "Identity", fonts_.bold);
            LabelValue("PID", std::to_wstring(process->pid));
            ImGui::SameLine();
            if (ImGui::SmallButton("Copy PID"))
            {
                CopyTextToClipboard(std::to_wstring(process->pid));
                AddLog(LogLevel::Info, "Copied selected PID to clipboard.");
            }
            LabelValue("Parent PID", parent == nullptr
                ? std::to_wstring(process->parentPid)
                : std::to_wstring(process->parentPid) + L" (" + parent->name + L")");
            LabelValue("Parent Link", ParentRelationshipStatusText(parentRelationshipStatus));
            LabelValue("Session", OptionalSessionId(process->sessionId));
            LabelValue("Architecture", process->architecture);
            EndInspectorCard();

            BeginInspectorCard("details_execution", "Execution", fonts_.bold);
            LabelValue("Start Time", process->hasCreationTime ? process->creationTimeLocal : L"(not accessible)");
            ImGui::TextDisabled("Executable Path");
            ImGui::SameLine();
            if (ImGui::SmallButton("Copy Path"))
            {
                CopyTextToClipboard(process->executablePath);
                AddLog(LogLevel::Info, "Copied executable path to clipboard.");
            }
            const bool pushedExecutionPathFont = PushFontIfAvailable(fonts_.monospace);
            WrappedTextWide(process->executablePath.empty() ? L"(not accessible)" : process->executablePath);
            PopFontIfPushed(pushedExecutionPathFont);
            ImGui::TextDisabled("Command Line");
            ImGui::SameLine();
            if (ImGui::SmallButton("Copy Command"))
            {
                CopyTextToClipboard(process->commandLine);
                AddLog(LogLevel::Info, "Copied command line to clipboard.");
            }
            if (!process->commandLineAccessible)
            {
                TextWide(L"(not accessible)");
            }
            else
            {
                const bool pushedCommandFont = PushFontIfAvailable(fonts_.monospace);
                WrappedTextWide(process->commandLine.empty() ? L"(empty)" : process->commandLine);
                PopFontIfPushed(pushedCommandFont);
            }
            EndInspectorCard();

            BeginInspectorCard("details_file_identity", "File Identity", fonts_.bold);
            RenderFileIdentityFields(
                "process_file_identity",
                fileIdentity,
                fileIdentityIndicators,
                "process executable");
            EndInspectorCard();

            BeginInspectorCard("details_security", "Security", fonts_.bold);
            LabelValue("Triage", Core::TriageSummary(findings));
            LabelValue("Suspicious", process->IsSuspicious() ? "Yes" : "No");
            ImGui::TextDisabled("Severity");
            ImGui::SameLine(145.0f);
            SeverityText(process->severity);
            ImGui::TextDisabled("Chain Severity");
            ImGui::SameLine(145.0f);
            SeverityText(chain.chainSeverity);
            LabelValue("Network Connections", std::to_wstring(networkSummary.connectionCount));
            LabelValue("Listening Sockets", std::to_wstring(networkSummary.listeningCount));
            LabelValue("Public Remote", std::to_wstring(networkSummary.publicRemoteCount));
            EndInspectorCard();

            BeginInspectorCard("details_indicators", "Indicators", fonts_.bold);
            const std::vector<std::wstring> networkIndicators = BuildNetworkIndicators(*process, networkSummary);
            if (process->indicators.empty() && networkIndicators.empty() && fileIdentityIndicators.empty())
            {
                ImGui::TextDisabled("No process indicators.");
            }
            else
            {
                for (const std::wstring& indicator : process->indicators)
                {
                    ImGui::Bullet();
                    ImGui::SameLine();
                    WrappedTextWide(indicator);
                }
                for (const Core::FileIdentityIndicator& indicator : fileIdentityIndicators)
                {
                    ImGui::Bullet();
                    ImGui::SameLine();
                    SeverityText(indicator.severity);
                    ImGui::SameLine();
                    WrappedTextWide(indicator.message);
                }
                for (const std::wstring& indicator : networkIndicators)
                {
                    ImGui::Bullet();
                    ImGui::SameLine();
                    WrappedTextWide(indicator);
                }
            }
            EndInspectorCard();

            BeginInspectorCard("details_context", "Context Notes", fonts_.bold);
            const std::vector<std::wstring> networkContextNotes = BuildNetworkContextNotes(*process, chain, networkSummary);
            if (process->contextNotes.empty() && networkContextNotes.empty())
            {
                ImGui::TextDisabled("No context notes.");
            }
            else
            {
                for (const std::wstring& note : process->contextNotes)
                {
                    ImGui::Bullet();
                    ImGui::SameLine();
                    WrappedTextWide(note);
                }
                for (const std::wstring& note : networkContextNotes)
                {
                    ImGui::Bullet();
                    ImGui::SameLine();
                    WrappedTextWide(note);
                }
            }
            EndInspectorCard();
        }

        void RenderChainPanel()
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                ImGui::TextUnformatted("No process selected.");
                return;
            }

            const Core::ChainAnalysisResult chain = Core::AnalyzeChain(snapshot_, process->pid);
            ImGui::TextDisabled("Chain Severity");
            ImGui::SameLine(145.0f);
            SeverityText(chain.chainSeverity);

            if (ImGui::Button("Copy Chain"))
            {
                const std::string chainText = WideToUtf8(chain.formattedParentChain);
                ImGui::SetClipboardText(chainText.c_str());
                AddLog(LogLevel::Info, "Copied selected process chain to clipboard.");
            }
            ImGui::SameLine();
            if (ImGui::Button("Export Selected"))
            {
                ExportSelectedDetails();
            }

            ImGui::SeparatorText("Parent Chain");
            WrappedTextWide(chain.formattedParentChain.empty() ? L"(unavailable)" : chain.formattedParentChain);

            ImGui::SeparatorText("Processes");
            for (const Core::ChainProcessSummary& item : chain.parentChain)
            {
                ImGui::PushID(static_cast<int>(item.pid));
                if (ImGui::Selectable(DisplayName(item.name).c_str(), item.pid == selectedPid_))
                {
                    SelectProcess(item.pid, true);
                }
                ImGui::SameLine();
                const bool pushedChainPidFont = PushFontIfAvailable(fonts_.monospace);
                ImGui::TextDisabled("PID %u", item.pid);
                PopFontIfPushed(pushedChainPidFont);
                ImGui::SameLine();
                SeverityText(item.severity);
                ImGui::PopID();
            }

            ImGui::SeparatorText("Chain Indicators");
            if (chain.chainIndicators.empty())
            {
                ImGui::TextDisabled("No chain indicators.");
            }
            else
            {
                for (const std::wstring& indicator : chain.chainIndicators)
                {
                    ImGui::Bullet();
                    ImGui::SameLine();
                    WrappedTextWide(indicator);
                }
            }
        }

        void RenderModulesPanel()
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                ImGui::TextUnformatted("No process selected.");
                return;
            }

            const bool pushedModuleTitleFont = PushFontIfAvailable(fonts_.bold);
            ImGui::TextColored(ImVec4(0.72f, 0.84f, 0.96f, 1.0f), "%s", DisplayName(process->name).c_str());
            PopFontIfPushed(pushedModuleTitleFont);
            ImGui::SameLine();
            const bool pushedModulePidFont = PushFontIfAvailable(fonts_.monospace);
            ImGui::TextDisabled("PID %u", process->pid);
            PopFontIfPushed(pushedModulePidFont);

            ImGui::Separator();
            if (ImGui::Button("Refresh Modules"))
            {
                RefreshModules();
            }
            ImGui::SameLine();
            if (ImGui::Button("Export Selected"))
            {
                ExportSelectedDetails();
            }

            if (!ModulesLoadedForProcess(*process))
            {
                ImGui::Spacing();
                ImGui::PushStyleColor(ImGuiCol_ChildBg, PanelBgRaised());
                ImGui::PushStyleColor(ImGuiCol_Border, PanelBorder());
                ImGui::BeginChild(
                    "modules_empty_state",
                    ImVec2(0.0f, 0.0f),
                    ImGuiChildFlags_Borders | ImGuiChildFlags_AlwaysUseWindowPadding | ImGuiChildFlags_AutoResizeY,
                    ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
                ImGui::TextColored(AccentBlue(), "Modules not loaded for this process.");
                ImGui::TextDisabled("Click Refresh Modules to inspect loaded DLLs.");
                ImGui::EndChild();
                ImGui::PopStyleColor(2);
                return;
            }

            if (selectedModules_.success)
            {
                WrappedTextColored(
                    ImVec4(0.55f, 0.72f, 0.92f, 1.0f),
                    WideToUtf8(selectedModules_.statusMessage));
            }
            else
            {
                WrappedTextColored(
                    ImVec4(0.96f, 0.52f, 0.20f, 1.0f),
                    "Modules unavailable: " + WideToUtf8(selectedModules_.statusMessage));
                WrappedTextDisabled("Protected, exited, or cross-architecture processes may not expose module details.");
            }

            if (!selectedModules_.indicators.empty())
            {
                ImGui::SeparatorText("Module Indicators");
                for (const std::wstring& indicator : selectedModules_.indicators)
                {
                    ImGui::Bullet();
                    ImGui::SameLine();
                    WrappedTextWide(indicator);
                }
            }

            if (selectedModules_.modules.empty())
            {
                ImGui::Spacing();
                WrappedTextDisabled("No modules returned for the selected process.");
                return;
            }

            const ImGuiTableFlags flags =
                ImGuiTableFlags_BordersInnerV |
                ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Resizable |
                ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_SizingStretchProp |
                ImGuiTableFlags_NoSavedSettings;
            AcknowledgeTableAutoSizeRequest(modulesTableNeedsAutoSize_);
            if (ImGui::BeginTable("ModulesTable##ModulesPanel", 4, flags))
            {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn("Module", ImGuiTableColumnFlags_WidthFixed, 155.0f);
                ImGui::TableSetupColumn("Base", ImGuiTableColumnFlags_WidthFixed, 112.0f);
                ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 76.0f);
                ImGui::TableSetupColumn("Path", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableHeadersRow();

                ImGuiListClipper clipper;
                clipper.Begin(static_cast<int>(selectedModules_.modules.size()));
                while (clipper.Step())
                {
                    for (int rowIndex = clipper.DisplayStart; rowIndex < clipper.DisplayEnd; ++rowIndex)
                    {
                        const std::size_t moduleIndex = static_cast<std::size_t>(rowIndex);
                        const Core::ModuleInfo& module = selectedModules_.modules[moduleIndex];
                        const bool moduleSelected =
                            selectedModulePid_ == selectedPid_ &&
                            selectedModuleIndex_ == moduleIndex;

                        ImGui::TableNextRow();
                        if (moduleSelected)
                        {
                            const ImU32 selectedRow = ColorU32(TableSelectedRow());
                            ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, selectedRow);
                            ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1, selectedRow);
                        }
                        ImGui::PushID(static_cast<int>(moduleIndex));

                        ImGui::TableSetColumnIndex(0);
                        if (ImGui::Selectable(
                            WideToUtf8(module.moduleName.empty() ? L"(unknown)" : module.moduleName).c_str(),
                            moduleSelected,
                            ImGuiSelectableFlags_SpanAllColumns,
                            ImVec2(0.0f, 24.0f)))
                        {
                            selectedModulePid_ = selectedPid_;
                            selectedModuleIndex_ = moduleIndex;
                        }

                        ImGui::TableSetColumnIndex(1);
                        const bool pushedBaseFont = PushFontIfAvailable(fonts_.monospace);
                        TextWide(module.baseAddress);
                        ImGui::TableSetColumnIndex(2);
                        ImGui::Text("%u", module.sizeBytes);
                        ImGui::TableSetColumnIndex(3);
                        ClippedTextWithTooltip(module.modulePath.empty() ? L"(path unavailable)" : module.modulePath);
                        PopFontIfPushed(pushedBaseFont);
                        ImGui::PopID();
                    }
                }
                ImGui::EndTable();
            }

            if (selectedModulePid_ == selectedPid_ && selectedModuleIndex_ < selectedModules_.modules.size())
            {
                const Core::ModuleInfo& module = selectedModules_.modules[selectedModuleIndex_];
                ImGui::SeparatorText("Selected Module");
                ImGui::TextDisabled("Module");
                ImGui::SameLine(92.0f);
                TextWide(module.moduleName.empty() ? L"(unknown)" : module.moduleName);

                const bool pushedSelectedModuleFont = PushFontIfAvailable(fonts_.monospace);
                ImGui::TextDisabled("Base");
                ImGui::SameLine(92.0f);
                TextWide(module.baseAddress);
                ImGui::TextDisabled("Size");
                ImGui::SameLine(92.0f);
                ImGui::Text("%u", module.sizeBytes);
                ImGui::TextDisabled("Path");
                WrappedTextWide(module.modulePath.empty() ? L"(path unavailable)" : module.modulePath);
                PopFontIfPushed(pushedSelectedModuleFont);

                const Core::FileIdentity& moduleFileIdentity = CachedFileIdentity(module.modulePath);
                const std::vector<Core::FileIdentityIndicator> moduleFileIdentityIndicators =
                    Core::BuildFileIdentityIndicators(moduleFileIdentity, module.moduleName, false);
                ImGui::SeparatorText("File Identity");
                RenderFileIdentityFields(
                    "selected_module_file_identity",
                    moduleFileIdentity,
                    moduleFileIdentityIndicators,
                    "selected module");
            }
        }

        void RenderTokenPanel()
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                ImGui::TextUnformatted("No process selected.");
                return;
            }

            const bool pushedTokenTitleFont = PushFontIfAvailable(fonts_.bold);
            ImGui::TextColored(ImVec4(0.72f, 0.84f, 0.96f, 1.0f), "%s", DisplayName(process->name).c_str());
            PopFontIfPushed(pushedTokenTitleFont);
            ImGui::SameLine();
            const bool pushedTokenPidFont = PushFontIfAvailable(fonts_.monospace);
            ImGui::TextDisabled("PID %u", process->pid);
            PopFontIfPushed(pushedTokenPidFont);

            ImGui::Separator();
            if (ImGui::Button("Refresh Token"))
            {
                RefreshToken(true);
            }

            if (!TokenLoadedForProcess(*process))
            {
                ImGui::Spacing();
                BeginInspectorCard("token_empty_state", "Token", fonts_.bold);
                WrappedTextDisabled("Token data is not loaded for this process.");
                WrappedTextDisabled("Click Refresh Token to inspect read-only token metadata.");
                EndInspectorCard();
                return;
            }

            const Core::TokenInfo& token = selectedToken_;
            const std::wstring tokenUser = TokenUserText(token);
            const std::wstring integritySummary = token.integrityLevelName.empty()
                ? L"(unavailable)"
                : token.integrityLevelName + L" (" + std::to_wstring(token.integrityRid) + L")";

            if (!token.success)
            {
                BeginInspectorCard("token_unavailable", "Token", fonts_.bold);
                WrappedTextDisabled(
                    L"Token unavailable: " +
                    (token.errorMessage.empty() ? std::wstring(L"access denied or process exited") : token.errorMessage));
                EndInspectorCard();
                return;
            }

            BeginInspectorCard("token_summary", "Token Summary", fonts_.bold);
            if (ImGui::BeginTable(
                "TokenSummaryGrid##TokenPanel",
                2,
                ImGuiTableFlags_SizingStretchSame | ImGuiTableFlags_NoSavedSettings | ImGuiTableFlags_PadOuterX))
            {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                TokenSummaryCell("User", tokenUser, ImGui::GetStyleColorVec4(ImGuiCol_Text), fonts_.bold);
                ImGui::TableSetColumnIndex(1);
                TokenSummaryCell("Integrity", integritySummary, ImGui::GetStyleColorVec4(ImGuiCol_Text), fonts_.bold);
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                TokenSummaryCell(
                    "Elevated",
                    YesNo(token.isElevated),
                    token.isElevated ? SeverityColor(Core::Severity::Medium) : ImGui::GetStyleColorVec4(ImGuiCol_Text),
                    fonts_.bold);
                ImGui::TableSetColumnIndex(1);
                TokenSummaryCell(
                    "Admin",
                    YesNo(token.isAdmin),
                    token.isAdmin ? SeverityColor(Core::Severity::Low) : ImGui::GetStyleColorVec4(ImGuiCol_Text),
                    fonts_.bold);
                ImGui::EndTable();
            }
            EndInspectorCard();

            BeginInspectorCard("token_identity", "Identity", fonts_.bold);
            InspectorFieldRow("token_user", "User", tokenUser);
            InspectorFieldRow(
                "token_session",
                "Session",
                token.sessionId.has_value() ? std::to_wstring(token.sessionId.value()) : L"(unavailable)");
            ImGui::Spacing();
            ImGui::TextDisabled("SID");
            if (!token.userSid.empty())
            {
                ImGui::SameLine();
                if (ImGui::SmallButton("Copy SID"))
                {
                    CopyTextToClipboard(token.userSid);
                }
            }
            const bool pushedSidFont = PushFontIfAvailable(fonts_.monospace);
            WrappedTextDisabled(token.userSid.empty() ? L"(unavailable)" : token.userSid);
            PopFontIfPushed(pushedSidFont);
            EndInspectorCard();

            BeginInspectorCard("token_security", "Token Security", fonts_.bold);
            InspectorFieldRow("token_integrity", "Integrity", integritySummary);
            InspectorFieldRow("token_elevated", "Elevated", YesNo(token.isElevated));
            InspectorFieldRow("token_admin", "Admin", YesNo(token.isAdmin));
            InspectorFieldRow("token_elevation_type", "Elevation Type", token.elevationType.empty() ? L"(unavailable)" : token.elevationType);
            InspectorFieldRow("token_type", "Token Type", token.tokenType.empty() ? L"(unavailable)" : token.tokenType);
            if (!token.impersonationLevel.empty())
            {
                InspectorFieldRow("token_impersonation", "Impersonation", token.impersonationLevel);
            }
            InspectorFieldRow("token_appcontainer", "AppContainer", YesNo(token.isAppContainer));
            if (!token.errorMessage.empty())
            {
                ImGui::SeparatorText("Context");
                WrappedTextDisabled(token.errorMessage);
            }
            EndInspectorCard();

            const Core::ChainAnalysisResult chain = Core::AnalyzeChain(snapshot_, process->pid);
            const Core::FileIdentity& fileIdentity = CachedFileIdentity(process->executablePath);
            const std::vector<Core::Finding>& findings =
                FindingsForSelectedProcess(*process, chain, fileIdentity);
            bool hasTokenFindings = false;
            for (const Core::Finding& finding : findings)
            {
                if (finding.category == L"Token")
                {
                    if (!hasTokenFindings)
                    {
                        BeginInspectorCard("token_context", "Token Context", fonts_.bold);
                        hasTokenFindings = true;
                    }
                    SeverityText(FindingSeverityAsCoreSeverity(finding.severity));
                    ImGui::SameLine();
                    WrappedTextWide(finding.title);
                    for (const std::wstring& evidence : finding.evidence)
                    {
                        ImGui::Bullet();
                        ImGui::SameLine();
                        WrappedTextDisabled(evidence);
                    }
                    ImGui::Spacing();
                }
            }
            if (hasTokenFindings)
            {
                EndInspectorCard();
            }

            BeginInspectorCard("token_privileges", "Privileges", fonts_.bold);
            if (token.privileges.empty())
            {
                WrappedTextDisabled("No privileges returned for this token.");
            }
            else
            {
                if (ImGui::Checkbox("Show enabled only", &tokenShowEnabledOnly_))
                {
                    tokenTableNeedsAutoSize_ = true;
                }
                ImGui::Spacing();

                std::vector<const Core::PrivilegeInfo*> visiblePrivileges;
                visiblePrivileges.reserve(token.privileges.size());
                for (const Core::PrivilegeInfo& privilege : token.privileges)
                {
                    if (tokenShowEnabledOnly_ && (!privilege.enabled || privilege.removed))
                    {
                        continue;
                    }
                    visiblePrivileges.push_back(&privilege);
                }

                if (visiblePrivileges.empty())
                {
                    WrappedTextDisabled("No privileges match the current filter.");
                }
                else
                {
                const ImGuiTableFlags flags =
                    ImGuiTableFlags_BordersInnerV |
                    ImGuiTableFlags_RowBg |
                    ImGuiTableFlags_Resizable |
                    ImGuiTableFlags_SizingStretchProp |
                    ImGuiTableFlags_NoSavedSettings;
                    AcknowledgeTableAutoSizeRequest(tokenTableNeedsAutoSize_);
                if (ImGui::BeginTable("TokenPrivilegesTable##TokenPanel", 3, flags))
                {
                    ImGui::TableSetupColumn("Privilege", ImGuiTableColumnFlags_WidthFixed, 172.0f);
                    ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 104.0f);
                    ImGui::TableSetupColumn("Description", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableHeadersRow();

                    ImGuiListClipper clipper;
                    clipper.Begin(static_cast<int>(visiblePrivileges.size()));
                    while (clipper.Step())
                    {
                        for (int rowIndex = clipper.DisplayStart; rowIndex < clipper.DisplayEnd; ++rowIndex)
                        {
                            const Core::PrivilegeInfo& privilege = *visiblePrivileges[static_cast<std::size_t>(rowIndex)];
                            ImGui::TableNextRow();
                            if (privilege.enabled && !privilege.removed)
                            {
                                ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, ColorU32(ImVec4(0.18f, 0.15f, 0.07f, 0.55f)));
                            }

                            ImGui::TableSetColumnIndex(0);
                            const bool pushedPrivilegeFont = PushFontIfAvailable(fonts_.monospace);
                            ClippedTextWithTooltip(privilege.name.empty() ? L"(unknown)" : privilege.name);
                            PopFontIfPushed(pushedPrivilegeFont);

                            ImGui::TableSetColumnIndex(1);
                            const std::wstring state = PrivilegeStateText(privilege);
                            if (privilege.enabled && !privilege.removed)
                            {
                                ImGui::TextColored(SeverityColor(Core::Severity::Low), "%s", WideToUtf8(state).c_str());
                            }
                            else
                            {
                                TextWide(state);
                            }

                            ImGui::TableSetColumnIndex(2);
                            ClippedTextWithTooltip(privilege.displayName.empty() ? L"(description unavailable)" : privilege.displayName);
                        }
                    }
                    ImGui::EndTable();
                }
                }
            }
            EndInspectorCard();
        }

        void RenderHandlesPanel()
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                ImGui::TextUnformatted("No process selected.");
                return;
            }

            const bool pushedHandleTitleFont = PushFontIfAvailable(fonts_.bold);
            ImGui::TextColored(ImVec4(0.72f, 0.84f, 0.96f, 1.0f), "%s", DisplayName(process->name).c_str());
            PopFontIfPushed(pushedHandleTitleFont);
            ImGui::SameLine();
            const bool pushedHandlePidFont = PushFontIfAvailable(fonts_.monospace);
            ImGui::TextDisabled("PID %u", process->pid);
            PopFontIfPushed(pushedHandlePidFont);

            ImGui::Separator();
            if (ImGui::Button("Refresh Handles"))
            {
                RefreshHandles(true);
            }
            ImGui::SameLine();
            if (ImGui::Button("Export Selected"))
            {
                ExportSelectedDetails();
            }

            if (!HandlesLoadedForProcess(*process))
            {
                ImGui::Spacing();
                BeginInspectorCard("handles_empty_state", "Handles", fonts_.bold);
                WrappedTextDisabled("Handle data is not loaded for this process.");
                WrappedTextDisabled("Click Refresh Handles to inspect read-only handle metadata.");
                EndInspectorCard();
                return;
            }

            if (!selectedHandles_.success)
            {
                BeginInspectorCard("handles_unavailable", "Handles", fonts_.bold);
                WrappedTextColored(
                    ImVec4(0.96f, 0.52f, 0.20f, 1.0f),
                    "Handles unavailable: " + WideToUtf8(selectedHandles_.statusMessage.empty()
                        ? L"collection did not complete"
                        : selectedHandles_.statusMessage));
                EndInspectorCard();
                return;
            }

            if (selectedHandles_.handles.empty())
            {
                BeginInspectorCard("handles_none", "Handles", fonts_.bold);
                WrappedTextDisabled("No handles returned for this process.");
                EndInspectorCard();
                return;
            }

            BeginInspectorCard("handles_filters", "Filters", fonts_.bold);
            ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x);
            if (ImGui::InputTextWithHint(
                "##HandlesPanelSearch",
                "Search handle, type, target, access, indicator",
                handleSearchBuffer_.data(),
                handleSearchBuffer_.size()))
            {
                const std::wstring loweredSearch = ToLower(Utf8ToWide(handleSearchBuffer_.data()));
                if (handleSearchText_ != loweredSearch)
                {
                    handleSearchText_ = loweredSearch;
                    visibleHandlesDirty_ = true;
                    handlesTableNeedsAutoSize_ = true;
                }
            }

            if (ChipButton("All##HandleFilter", handleFilter_ == HandleFilter::All, AccentBlue()))
            {
                if (handleFilter_ != HandleFilter::All)
                {
                    handleFilter_ = HandleFilter::All;
                    visibleHandlesDirty_ = true;
                    handlesTableNeedsAutoSize_ = true;
                }
            }
            SameLineIfChipFits("Sensitive");
            if (ChipButton("Sensitive##HandleFilter", handleFilter_ == HandleFilter::Sensitive, SeverityColor(Core::Severity::Medium)))
            {
                if (handleFilter_ != HandleFilter::Sensitive)
                {
                    handleFilter_ = HandleFilter::Sensitive;
                    visibleHandlesDirty_ = true;
                    handlesTableNeedsAutoSize_ = true;
                }
            }
            SameLineIfChipFits("Process");
            if (ChipButton("Process##HandleFilter", handleFilter_ == HandleFilter::Process, AccentBlue()))
            {
                if (handleFilter_ != HandleFilter::Process)
                {
                    handleFilter_ = HandleFilter::Process;
                    visibleHandlesDirty_ = true;
                    handlesTableNeedsAutoSize_ = true;
                }
            }
            SameLineIfChipFits("Token");
            if (ChipButton("Token##HandleFilter", handleFilter_ == HandleFilter::Token, AccentBlue()))
            {
                if (handleFilter_ != HandleFilter::Token)
                {
                    handleFilter_ = HandleFilter::Token;
                    visibleHandlesDirty_ = true;
                    handlesTableNeedsAutoSize_ = true;
                }
            }
            SameLineIfChipFits("File");
            if (ChipButton("File##HandleFilter", handleFilter_ == HandleFilter::File, AccentBlue()))
            {
                if (handleFilter_ != HandleFilter::File)
                {
                    handleFilter_ = HandleFilter::File;
                    visibleHandlesDirty_ = true;
                    handlesTableNeedsAutoSize_ = true;
                }
            }
            SameLineIfChipFits("Registry");
            if (ChipButton("Registry##HandleFilter", handleFilter_ == HandleFilter::Registry, AccentBlue()))
            {
                if (handleFilter_ != HandleFilter::Registry)
                {
                    handleFilter_ = HandleFilter::Registry;
                    visibleHandlesDirty_ = true;
                    handlesTableNeedsAutoSize_ = true;
                }
            }
            SameLineIfChipFits("Named Objects");
            if (ChipButton("Named Objects##HandleFilter", handleFilter_ == HandleFilter::NamedObjects, AccentBlue()))
            {
                if (handleFilter_ != HandleFilter::NamedObjects)
                {
                    handleFilter_ = HandleFilter::NamedObjects;
                    visibleHandlesDirty_ = true;
                    handlesTableNeedsAutoSize_ = true;
                }
            }
            SameLineIfChipFits("With Indicators");
            if (ChipButton("With Indicators##HandleFilter", handleFilter_ == HandleFilter::WithIndicators, SeverityColor(Core::Severity::Low)))
            {
                if (handleFilter_ != HandleFilter::WithIndicators)
                {
                    handleFilter_ = HandleFilter::WithIndicators;
                    visibleHandlesDirty_ = true;
                    handlesTableNeedsAutoSize_ = true;
                }
            }
            EndInspectorCard();

            RebuildVisibleHandlesIfNeeded(*process);

            BeginInspectorCard("handles_summary", "Handle Summary", fonts_.bold);
            LabelValue("Total Loaded", std::to_wstring(selectedHandles_.handles.size()));
            LabelValue("Visible", std::to_wstring(visibleHandleIndexes_.size()));
            LabelValue("Sensitive", std::to_wstring(selectedHandles_.sensitiveCount));
            LabelValue("With Indicators", std::to_wstring(visibleHandlesWithIndicatorsCount_));
            LabelValue("Name Unavail/Skipped", std::to_wstring(visibleHandlesNameStatusCount_));
            ImGui::TextDisabled("Status");
            WrappedTextDisabled(selectedHandles_.statusMessage.empty() ? L"(no status)" : selectedHandles_.statusMessage);
            EndInspectorCard();

            if (visibleHandleIndexes_.empty())
            {
                BeginInspectorCard("handles_filter_empty", "Handles", fonts_.bold);
                WrappedTextDisabled("No handles match the current filters.");
                EndInspectorCard();
                return;
            }

            const ImGuiTableFlags flags =
                ImGuiTableFlags_BordersInnerV |
                ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Resizable |
                ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_SizingStretchProp |
                ImGuiTableFlags_NoSavedSettings;
            AcknowledgeTableAutoSizeRequest(handlesTableNeedsAutoSize_);
            if (ImGui::BeginTable("HandlesTable##HandlesPanel", 5, flags))
            {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn("Handle", ImGuiTableColumnFlags_WidthFixed, 76.0f);
                ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 88.0f);
                ImGui::TableSetupColumn("Target / Name", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Access", ImGuiTableColumnFlags_WidthFixed, 92.0f);
                ImGui::TableSetupColumn("Indicators", ImGuiTableColumnFlags_WidthFixed, 118.0f);
                ImGui::TableHeadersRow();

                ImGuiListClipper clipper;
                clipper.Begin(static_cast<int>(visibleHandleIndexes_.size()));
                while (clipper.Step())
                {
                    for (int rowIndex = clipper.DisplayStart; rowIndex < clipper.DisplayEnd; ++rowIndex)
                    {
                        const std::size_t visibleIndex = static_cast<std::size_t>(rowIndex);
                        const std::size_t handleIndex = visibleHandleIndexes_[visibleIndex];
                        if (handleIndex >= selectedHandles_.handles.size())
                        {
                            continue;
                        }
                        const Core::HandleInfo& handle = selectedHandles_.handles[handleIndex];
                        ImGui::TableNextRow();
                        if (handle.isSensitive)
                        {
                            ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, ColorU32(ImVec4(0.26f, 0.11f, 0.045f, 0.68f)));
                        }
                        else if (!handle.indicators.empty())
                        {
                            ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, ColorU32(ImVec4(0.15f, 0.12f, 0.05f, 0.42f)));
                        }
                        ImGui::PushID(static_cast<int>(handleIndex));

                        ImGui::TableSetColumnIndex(0);
                        const bool pushedHandleFont = PushFontIfAvailable(fonts_.monospace);
                        if (handle.isSensitive)
                        {
                            ImGui::TextColored(SeverityColor(Core::Severity::Medium), "%s", WideToUtf8(HandleValueText(handle.handleValue)).c_str());
                        }
                        else
                        {
                            ClippedTextWithTooltip(HandleValueText(handle.handleValue));
                        }
                        PopFontIfPushed(pushedHandleFont);

                        ImGui::TableSetColumnIndex(1);
                        const std::wstring objectTypeText = HandleObjectTypeText(handle);
                        ImGui::TextUnformatted(WideToUtf8(objectTypeText).c_str());
                        if (ImGui::IsItemHovered())
                        {
                            if (IsRawObjectTypeIndex(handle.objectType))
                            {
                                RenderWrappedTooltip(
                                    L"Object type name unavailable. Raw object type index: " + handle.objectType + L".",
                                    520.0f);
                            }
                            else
                            {
                                RenderWrappedTooltip(objectTypeText, 520.0f);
                            }
                        }

                        ImGui::TableSetColumnIndex(2);
                        ImGui::TextUnformatted(WideToUtf8(HandleTargetText(handle)).c_str());
                        if (ImGui::IsItemHovered())
                        {
                            RenderWrappedTooltip(HandleTargetTooltipText(handle), 600.0f);
                        }

                        ImGui::TableSetColumnIndex(3);
                        const bool pushedAccessFont = PushFontIfAvailable(fonts_.monospace);
                        TextWide(handle.grantedAccess.empty() ? L"(unknown)" : handle.grantedAccess);
                        PopFontIfPushed(pushedAccessFont);
                        if (ImGui::IsItemHovered())
                        {
                            RenderWrappedTooltip(HandleAccessTooltipText(handle), 520.0f);
                        }

                        ImGui::TableSetColumnIndex(4);
                        const std::wstring indicators = HandleIndicatorText(handle);
                        const std::wstring status = HandleStatusText(handle);
                        if (!indicators.empty())
                        {
                            ImGui::TextColored(
                                handle.isSensitive ? SeverityColor(Core::Severity::Medium) : SeverityColor(Core::Severity::Low),
                                "%s",
                                WideToUtf8(indicators).c_str());
                            if (ImGui::IsItemHovered())
                            {
                                RenderWrappedTooltip(indicators, 560.0f);
                            }
                        }
                        else if (!status.empty())
                        {
                            ImGui::TextDisabled("%s", WideToUtf8(status).c_str());
                            if (ImGui::IsItemHovered() && !handle.errorMessage.empty())
                            {
                                RenderWrappedTooltip(handle.errorMessage, 560.0f);
                            }
                        }
                        else
                        {
                            ImGui::TextDisabled("None");
                        }

                        ImGui::PopID();
                    }
                }

                ImGui::EndTable();
            }
        }

        void RenderNetworkPanel()
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                ImGui::TextUnformatted("No process selected.");
                return;
            }

            const bool pushedNetworkTitleFont = PushFontIfAvailable(fonts_.bold);
            ImGui::TextColored(ImVec4(0.72f, 0.84f, 0.96f, 1.0f), "%s", DisplayName(process->name).c_str());
            PopFontIfPushed(pushedNetworkTitleFont);
            ImGui::SameLine();
            const bool pushedNetworkPidFont = PushFontIfAvailable(fonts_.monospace);
            ImGui::TextDisabled("PID %u", process->pid);
            PopFontIfPushed(pushedNetworkPidFont);

            ImGui::Separator();
            if (ImGui::Button("Refresh Network"))
            {
                RefreshNetwork(true);
            }
            ImGui::SameLine();
            ImGui::TextDisabled("Last refresh: %s", WideToUtf8(lastNetworkRefreshTime_).c_str());

            if (!networkLoaded_)
            {
                ImGui::Spacing();
                ImGui::PushStyleColor(ImGuiCol_ChildBg, PanelBgRaised());
                ImGui::PushStyleColor(ImGuiCol_Border, PanelBorder());
                ImGui::BeginChild(
                    "network_empty_state",
                    ImVec2(0.0f, 0.0f),
                    ImGuiChildFlags_Borders | ImGuiChildFlags_AlwaysUseWindowPadding | ImGuiChildFlags_AutoResizeY,
                    ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
                ImGui::TextColored(AccentBlue(), "Network data not loaded.");
                ImGui::TextDisabled("Click Refresh Network to inspect local socket ownership.");
                ImGui::EndChild();
                ImGui::PopStyleColor(2);
                return;
            }

            if (!networkSnapshot_.success)
            {
                WrappedTextColored(
                    ImVec4(0.96f, 0.52f, 0.20f, 1.0f),
                    "Network unavailable: " + WideToUtf8(networkSnapshot_.statusMessage));
            }
            else
            {
                WrappedTextDisabled(networkSnapshot_.statusMessage);
            }

            const std::vector<const Core::NetworkConnection*> selectedConnections = SelectedNetworkConnections();
            const NetworkSummary summary = GetNetworkSummary(process->pid);
            ImGui::TextDisabled(
                "%zu connections | %zu listening | %zu public remote",
                summary.connectionCount,
                summary.listeningCount,
                summary.publicRemoteCount);

            if (selectedConnections.empty())
            {
                ImGui::Spacing();
                ImGui::TextDisabled("No network connections for this process.");
                return;
            }

            const ImGuiTableFlags flags =
                ImGuiTableFlags_BordersInnerV |
                ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Resizable |
                ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_SizingStretchProp |
                ImGuiTableFlags_NoSavedSettings;
            AcknowledgeTableAutoSizeRequest(networkTableNeedsAutoSize_);
            if (ImGui::BeginTable("NetworkTable##NetworkPanel", 5, flags))
            {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn("Protocol", ImGuiTableColumnFlags_WidthFixed, 76.0f);
                ImGui::TableSetupColumn("Local", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Remote", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 96.0f);
                ImGui::TableSetupColumn("Type/Scope", ImGuiTableColumnFlags_WidthFixed, 150.0f);
                ImGui::TableHeadersRow();

                ImGuiListClipper clipper;
                clipper.Begin(static_cast<int>(selectedConnections.size()));
                while (clipper.Step())
                {
                    for (int rowIndex = clipper.DisplayStart; rowIndex < clipper.DisplayEnd; ++rowIndex)
                    {
                        const Core::NetworkConnection* connection =
                            selectedConnections[static_cast<std::size_t>(rowIndex)];
                        if (connection == nullptr)
                        {
                            continue;
                        }

                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0);
                        TextWide(connection->protocol);

                        const bool pushedEndpointFont = PushFontIfAvailable(fonts_.monospace);
                        ImGui::TableSetColumnIndex(1);
                        ClippedTextWithTooltip(NetworkEndpoint(*connection, false));
                        ImGui::TableSetColumnIndex(2);
                        ClippedTextWithTooltip(NetworkEndpoint(*connection, true));
                        ImGui::TableSetColumnIndex(3);
                        TextWide(connection->state.empty() ? L"-" : connection->state);
                        PopFontIfPushed(pushedEndpointFont);

                        ImGui::TableSetColumnIndex(4);
                        if (connection->isPublicRemote)
                        {
                            ImGui::TextColored(SeverityColor(Core::Severity::Low), "%s", WideToUtf8(NetworkScopeText(*connection)).c_str());
                        }
                        else
                        {
                            TextWide(NetworkScopeText(*connection));
                        }
                    }
                }

                ImGui::EndTable();
            }
        }

        void RenderRuntimePanel()
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                ImGui::TextUnformatted("No process selected.");
                return;
            }

            const bool pushedRuntimeTitleFont = PushFontIfAvailable(fonts_.bold);
            ImGui::TextColored(ImVec4(0.72f, 0.84f, 0.96f, 1.0f), "%s", DisplayName(process->name).c_str());
            PopFontIfPushed(pushedRuntimeTitleFont);
            ImGui::SameLine();
            const bool pushedRuntimePidFont = PushFontIfAvailable(fonts_.monospace);
            ImGui::TextDisabled("PID %u", process->pid);
            PopFontIfPushed(pushedRuntimePidFont);

            ImGui::Separator();
            if (ImGui::Button("Refresh Runtime"))
            {
                RefreshRuntime(true);
            }

            if (!RuntimeLoadedForProcess(*process))
            {
                ImGui::Spacing();
                BeginInspectorCard("runtime_empty_state", "Runtime", fonts_.bold);
                WrappedTextDisabled("Runtime data is not loaded for this process.");
                WrappedTextDisabled("Click Refresh Runtime to inspect read-only scheduling, memory, CPU, and thread metadata.");
                EndInspectorCard();
                return;
            }

            const Core::RuntimeInfo& runtime = selectedRuntime_;
            if (!runtime.success)
            {
                BeginInspectorCard("runtime_unavailable", "Runtime", fonts_.bold);
                WrappedTextColored(
                    ImVec4(0.96f, 0.52f, 0.20f, 1.0f),
                    "Runtime unavailable: " + WideToUtf8(runtime.errorMessage.empty()
                        ? L"access denied or process exited"
                        : runtime.errorMessage));
                if (!runtime.threads.empty())
                {
                    WrappedTextDisabled("Thread snapshot data may still be partial.");
                }
                EndInspectorCard();
            }

            if (runtime.success)
            {
                BeginInspectorCard("runtime_scheduling", "Scheduling", fonts_.bold);
                LabelValue("Priority Class", runtime.priorityClassName.empty() ? L"(unavailable)" : runtime.priorityClassName);
                LabelValue("Base Priority", std::to_wstring(runtime.basePriority));
                LabelValue("Affinity", runtime.affinityMaskString.empty() ? L"(unavailable)" : runtime.affinityMaskString);
                LabelValue("Processor Group", runtime.processorGroup.empty() ? L"(unavailable)" : runtime.processorGroup);
                LabelValue("Architecture", runtime.architecture.empty() ? L"(unknown)" : runtime.architecture);
                LabelValue("WOW64", YesNo(runtime.isWow64));
                EndInspectorCard();

                BeginInspectorCard("runtime_cpu", "CPU Time", fonts_.bold);
                LabelValue("User", runtime.userCpuTime.empty() ? L"(unavailable)" : runtime.userCpuTime);
                LabelValue("Kernel", runtime.kernelCpuTime.empty() ? L"(unavailable)" : runtime.kernelCpuTime);
                LabelValue("Total", runtime.totalCpuTime.empty() ? L"(unavailable)" : runtime.totalCpuTime);
                EndInspectorCard();

                BeginInspectorCard("runtime_memory", "Memory", fonts_.bold);
                LabelValue("Working Set", FileSizeText(runtime.workingSetSize));
                LabelValue("Peak Working Set", FileSizeText(runtime.peakWorkingSetSize));
                LabelValue("Private Bytes", FileSizeText(runtime.privateBytes));
                LabelValue("Pagefile Usage", FileSizeText(runtime.pagefileUsage));
                LabelValue("Peak Pagefile", FileSizeText(runtime.peakPagefileUsage));
                EndInspectorCard();

                BeginInspectorCard("runtime_counts", "Counts", fonts_.bold);
                LabelValue("Threads", std::to_wstring(runtime.threadCount));
                LabelValue("Handles", std::to_wstring(runtime.handleCount));
                if (!runtime.errorMessage.empty())
                {
                    ImGui::SeparatorText("Status");
                    WrappedTextDisabled(runtime.errorMessage);
                }
                EndInspectorCard();
            }

            const Core::ChainAnalysisResult chain = Core::AnalyzeChain(snapshot_, process->pid);
            const Core::FileIdentity& fileIdentity = CachedFileIdentity(process->executablePath);
            const std::vector<Core::Finding>& findings =
                FindingsForSelectedProcess(*process, chain, fileIdentity);
            bool hasRuntimeContext = !runtime.contextNotes.empty();
            for (const Core::Finding& finding : findings)
            {
                if (finding.category == L"Runtime")
                {
                    hasRuntimeContext = true;
                    break;
                }
            }

            if (hasRuntimeContext)
            {
                BeginInspectorCard("runtime_context", "Runtime Context", fonts_.bold);
                for (const std::wstring& note : runtime.contextNotes)
                {
                    ImGui::Bullet();
                    ImGui::SameLine();
                    WrappedTextDisabled(note);
                }
                for (const Core::Finding& finding : findings)
                {
                    if (finding.category != L"Runtime")
                    {
                        continue;
                    }

                    SeverityText(FindingSeverityAsCoreSeverity(finding.severity));
                    ImGui::SameLine();
                    WrappedTextWide(finding.title);
                    for (const std::wstring& evidence : finding.evidence)
                    {
                        ImGui::Bullet();
                        ImGui::SameLine();
                        WrappedTextDisabled(evidence);
                    }
                    ImGui::Spacing();
                }
                EndInspectorCard();
            }

            BeginInspectorCard("runtime_threads", "Threads", fonts_.bold);
            if (runtime.threads.empty())
            {
                WrappedTextDisabled("No thread metadata returned for this process.");
                EndInspectorCard();
                return;
            }

            const ImGuiTableFlags flags =
                ImGuiTableFlags_BordersInnerV |
                ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Resizable |
                ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_SizingStretchProp |
                ImGuiTableFlags_NoSavedSettings;
            AcknowledgeTableAutoSizeRequest(runtimeTableNeedsAutoSize_);
            if (ImGui::BeginTable("RuntimeThreadsTable##RuntimePanel", 5, flags, ImVec2(0.0f, 270.0f)))
            {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn("Thread ID", ImGuiTableColumnFlags_WidthFixed, 88.0f);
                ImGui::TableSetupColumn("Base", ImGuiTableColumnFlags_WidthFixed, 64.0f);
                ImGui::TableSetupColumn("Current", ImGuiTableColumnFlags_WidthFixed, 76.0f);
                ImGui::TableSetupColumn("Start Address", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Module", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableHeadersRow();

                ImGuiListClipper clipper;
                clipper.Begin(static_cast<int>(runtime.threads.size()));
                while (clipper.Step())
                {
                    for (int rowIndex = clipper.DisplayStart; rowIndex < clipper.DisplayEnd; ++rowIndex)
                    {
                        const Core::ThreadInfo& thread = runtime.threads[static_cast<std::size_t>(rowIndex)];
                        ImGui::TableNextRow();

                        const bool pushedThreadFont = PushFontIfAvailable(fonts_.monospace);
                        ImGui::TableSetColumnIndex(0);
                        ImGui::Text("%u", thread.threadId);
                        if (ImGui::IsItemHovered() && !thread.errorMessage.empty())
                        {
                            RenderWrappedTooltip(thread.errorMessage, 560.0f);
                        }

                        ImGui::TableSetColumnIndex(1);
                        ImGui::Text("%d", thread.basePriority);

                        ImGui::TableSetColumnIndex(2);
                        if (thread.hasCurrentPriority)
                        {
                            ImGui::Text("%d", thread.currentPriority);
                        }
                        else
                        {
                            ImGui::TextDisabled("N/A");
                        }

                        ImGui::TableSetColumnIndex(3);
                        ClippedTextWithTooltip(thread.startAddress.empty() ? L"Unavailable" : thread.startAddress);

                        ImGui::TableSetColumnIndex(4);
                        ClippedTextWithTooltip(thread.startAddressResolvedModule.empty()
                            ? L"(unresolved)"
                            : thread.startAddressResolvedModule);
                        PopFontIfPushed(pushedThreadFont);
                    }
                }

                ImGui::EndTable();
            }
            EndInspectorCard();
        }

        void RenderMemoryPanel()
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                ImGui::TextUnformatted("No process selected.");
                return;
            }

            const bool pushedMemoryTitleFont = PushFontIfAvailable(fonts_.bold);
            ImGui::TextColored(ImVec4(0.72f, 0.84f, 0.96f, 1.0f), "%s", DisplayName(process->name).c_str());
            PopFontIfPushed(pushedMemoryTitleFont);
            ImGui::SameLine();
            const bool pushedMemoryPidFont = PushFontIfAvailable(fonts_.monospace);
            ImGui::TextDisabled("PID %u", process->pid);
            PopFontIfPushed(pushedMemoryPidFont);

            ImGui::Separator();
            if (ImGui::Button("Refresh Memory"))
            {
                RefreshMemory(true);
            }

            if (!MemoryLoadedForProcess(*process))
            {
                ImGui::Spacing();
                BeginInspectorCard("memory_empty_state", "Memory", fonts_.bold);
                WrappedTextDisabled("Memory region metadata is not loaded for this process.");
                WrappedTextDisabled("Click Refresh Memory to inspect virtual memory region metadata. GlassPane does not dump or read region contents.");
                EndInspectorCard();
                return;
            }

            const Core::MemoryCollectionResult& memory = selectedMemory_;
            if (!memory.success)
            {
                BeginInspectorCard("memory_unavailable", "Memory", fonts_.bold);
                WrappedTextColored(
                    ImVec4(0.96f, 0.52f, 0.20f, 1.0f),
                    "Memory unavailable: " + WideToUtf8(memory.statusMessage.empty()
                        ? L"access denied, protected process, or process exited"
                        : memory.statusMessage));
                EndInspectorCard();
                if (memory.regions.empty())
                {
                    return;
                }
            }

            BeginInspectorCard("memory_summary", "Memory Summary", fonts_.bold);
            LabelValue("Total Regions", std::to_wstring(memory.totalRegions));
            LabelValue("Executable", std::to_wstring(memory.executableRegions));
            LabelValue("Private Executable", std::to_wstring(memory.privateExecutableRegions));
            LabelValue("RWX", std::to_wstring(memory.rwxRegions));
            LabelValue("Suspicious", std::to_wstring(memory.suspiciousRegions));
            LabelValue("Guard Pages", std::to_wstring(memory.guardRegions));
            if (!memory.statusMessage.empty())
            {
                ImGui::SeparatorText("Status");
                WrappedTextDisabled(memory.statusMessage);
            }
            EndInspectorCard();

            BeginInspectorCard("memory_filters", "Filters", fonts_.bold);
            ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x);
            if (ImGui::InputTextWithHint(
                "##MemoryPanelSearch",
                "Search address, protection, type, mapped file, indicator",
                memorySearchBuffer_.data(),
                memorySearchBuffer_.size()))
            {
                const std::wstring loweredSearch = ToLower(Utf8ToWide(memorySearchBuffer_.data()));
                if (memorySearchText_ != loweredSearch)
                {
                    memorySearchText_ = loweredSearch;
                    visibleMemoryRegionsDirty_ = true;
                    memoryTableNeedsAutoSize_ = true;
                }
            }

            if (ChipButton("All##MemoryFilter", memoryFilter_ == MemoryFilter::All, AccentBlue()))
            {
                if (memoryFilter_ != MemoryFilter::All)
                {
                    memoryFilter_ = MemoryFilter::All;
                    visibleMemoryRegionsDirty_ = true;
                    memoryTableNeedsAutoSize_ = true;
                }
            }
            SameLineIfChipFits("Executable");
            if (ChipButton("Executable##MemoryFilter", memoryFilter_ == MemoryFilter::Executable, AccentBlue()))
            {
                if (memoryFilter_ != MemoryFilter::Executable)
                {
                    memoryFilter_ = MemoryFilter::Executable;
                    visibleMemoryRegionsDirty_ = true;
                    memoryTableNeedsAutoSize_ = true;
                }
            }
            SameLineIfChipFits("Writable");
            if (ChipButton("Writable##MemoryFilter", memoryFilter_ == MemoryFilter::Writable, SeverityColor(Core::Severity::Low)))
            {
                if (memoryFilter_ != MemoryFilter::Writable)
                {
                    memoryFilter_ = MemoryFilter::Writable;
                    visibleMemoryRegionsDirty_ = true;
                    memoryTableNeedsAutoSize_ = true;
                }
            }
            SameLineIfChipFits("Private");
            if (ChipButton("Private##MemoryFilter", memoryFilter_ == MemoryFilter::Private, AccentBlue()))
            {
                if (memoryFilter_ != MemoryFilter::Private)
                {
                    memoryFilter_ = MemoryFilter::Private;
                    visibleMemoryRegionsDirty_ = true;
                    memoryTableNeedsAutoSize_ = true;
                }
            }
            SameLineIfChipFits("Image");
            if (ChipButton("Image##MemoryFilter", memoryFilter_ == MemoryFilter::Image, AccentBlue()))
            {
                if (memoryFilter_ != MemoryFilter::Image)
                {
                    memoryFilter_ = MemoryFilter::Image;
                    visibleMemoryRegionsDirty_ = true;
                    memoryTableNeedsAutoSize_ = true;
                }
            }
            SameLineIfChipFits("Suspicious");
            if (ChipButton("Suspicious##MemoryFilter", memoryFilter_ == MemoryFilter::Suspicious, SeverityColor(Core::Severity::Medium)))
            {
                if (memoryFilter_ != MemoryFilter::Suspicious)
                {
                    memoryFilter_ = MemoryFilter::Suspicious;
                    visibleMemoryRegionsDirty_ = true;
                    memoryTableNeedsAutoSize_ = true;
                }
            }
            SameLineIfChipFits("RWX");
            if (ChipButton("RWX##MemoryFilter", memoryFilter_ == MemoryFilter::Rwx, SeverityColor(Core::Severity::Medium)))
            {
                if (memoryFilter_ != MemoryFilter::Rwx)
                {
                    memoryFilter_ = MemoryFilter::Rwx;
                    visibleMemoryRegionsDirty_ = true;
                    memoryTableNeedsAutoSize_ = true;
                }
            }
            EndInspectorCard();

            RebuildVisibleMemoryRegionsIfNeeded(*process);

            BeginInspectorCard("memory_regions", "Regions", fonts_.bold);
            LabelValue("Visible", std::to_wstring(visibleMemoryRegionIndexes_.size()));
            if (visibleMemoryRegionIndexes_.empty())
            {
                WrappedTextDisabled("No memory regions match the current filters.");
                EndInspectorCard();
                return;
            }

            const ImGuiTableFlags flags =
                ImGuiTableFlags_BordersInnerV |
                ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Resizable |
                ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_SizingStretchProp |
                ImGuiTableFlags_NoSavedSettings;
            AcknowledgeTableAutoSizeRequest(memoryTableNeedsAutoSize_);
            if (ImGui::BeginTable("MemoryRegionsTable##MemoryPanel", 7, flags, ImVec2(0.0f, 340.0f)))
            {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn("Base", ImGuiTableColumnFlags_WidthFixed, 124.0f);
                ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 82.0f);
                ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 78.0f);
                ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 76.0f);
                ImGui::TableSetupColumn("Protection", ImGuiTableColumnFlags_WidthFixed, 108.0f);
                ImGui::TableSetupColumn("Mapped file", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Indicators", ImGuiTableColumnFlags_WidthFixed, 140.0f);
                ImGui::TableHeadersRow();

                ImGuiListClipper clipper;
                clipper.Begin(static_cast<int>(visibleMemoryRegionIndexes_.size()));
                while (clipper.Step())
                {
                    for (int rowIndex = clipper.DisplayStart; rowIndex < clipper.DisplayEnd; ++rowIndex)
                    {
                        const std::size_t visibleIndex = static_cast<std::size_t>(rowIndex);
                        const std::size_t regionIndex = visibleMemoryRegionIndexes_[visibleIndex];
                        if (regionIndex >= memory.regions.size())
                        {
                            continue;
                        }
                        const Core::MemoryRegionInfo& region = memory.regions[regionIndex];
                        ImGui::TableNextRow();
                        if (region.isSuspicious)
                        {
                            ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, ColorU32(ImVec4(0.24f, 0.10f, 0.05f, 0.55f)));
                        }
                        else if (region.isGuard)
                        {
                            ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, ColorU32(ImVec4(0.12f, 0.14f, 0.18f, 0.48f)));
                        }

                        ImGui::PushID(rowIndex);
                        const bool pushedAddressFont = PushFontIfAvailable(fonts_.monospace);
                        ImGui::TableSetColumnIndex(0);
                        ClippedTextWithTooltip(region.baseAddressString);
                        ImGui::TableSetColumnIndex(1);
                        TextWide(region.regionSizeString);
                        PopFontIfPushed(pushedAddressFont);

                        ImGui::TableSetColumnIndex(2);
                        TextWide(region.stateName);
                        ImGui::TableSetColumnIndex(3);
                        TextWide(region.typeName);
                        ImGui::TableSetColumnIndex(4);
                        const bool pushedProtectFont = PushFontIfAvailable(fonts_.monospace);
                        ClippedTextWithTooltip(region.protectName);
                        PopFontIfPushed(pushedProtectFont);

                        ImGui::TableSetColumnIndex(5);
                        ClippedTextWithTooltip(region.mappedFilePath.empty() ? L"(none)" : region.mappedFilePath);

                        ImGui::TableSetColumnIndex(6);
                        const std::wstring indicators = MemoryIndicatorText(region);
                        if (indicators.empty())
                        {
                            ImGui::TextDisabled("None");
                        }
                        else
                        {
                            ImGui::TextColored(
                                region.isSuspicious ? SeverityColor(Core::Severity::Medium) : SeverityColor(Core::Severity::Info),
                                "%s",
                                WideToUtf8(indicators).c_str());
                            if (ImGui::IsItemHovered())
                            {
                                RenderWrappedTooltip(indicators, 600.0f);
                            }
                        }
                        ImGui::PopID();
                    }
                }
                ImGui::EndTable();
            }
            EndInspectorCard();
        }

        void RenderGraphView()
        {
            const auto clampZoom = [](float zoom) {
                return std::clamp(zoom, 0.4f, 2.5f);
            };
            const auto layoutLabel = [](GraphLayoutMode mode) {
                return mode == GraphLayoutMode::LeftToRight ? "Left To Right" : "Top Down";
            };

            const bool pushedHeadingFont = PushFontIfAvailable(fonts_.bold);
            ImGui::TextColored(AccentBlue(), "Process Graph");
            PopFontIfPushed(pushedHeadingFont);
            ImGui::SameLine();
            ImGui::TextColored(MutedText(), "focused process relationships");

            const float toolbarWidth = 612.0f;
            const float toolbarX = ImGui::GetCursorPosX() + std::max(0.0f, ImGui::GetContentRegionAvail().x - toolbarWidth);
            if (ImGui::GetContentRegionAvail().x > toolbarWidth + 12.0f)
            {
                ImGui::SameLine(toolbarX);
            }
            else
            {
                ImGui::Spacing();
            }

            if (ImGui::Button("Focus"))
            {
                RebuildFocusedGraph("graph-focus-button");
                RequestGraphFit();
                AddLog(LogLevel::Info, "Graph focused on selected process.");
            }
            ImGui::SameLine();
            if (ImGui::Button("Fit"))
            {
                RequestGraphFit();
                AddLog(LogLevel::Info, "Graph fit requested.");
            }
            ImGui::SameLine();
            if (ImGui::Button("Refresh"))
            {
                RebuildFocusedGraph("graph-refresh-button");
                RequestGraphFit();
                AddLog(LogLevel::Info, "Graph refreshed.");
            }
            ImGui::SameLine();
            ImGui::TextDisabled("Layout");
            ImGui::SameLine();
            ImGui::SetNextItemWidth(124.0f);
            if (ImGui::BeginCombo("##graph_layout", layoutLabel(graphLayoutMode_)))
            {
                const bool topDownSelected = graphLayoutMode_ == GraphLayoutMode::TopDown;
                if (ImGui::Selectable("Top Down", topDownSelected))
                {
                    graphLayoutMode_ = GraphLayoutMode::TopDown;
                    RequestGraphFit();
                }
                if (topDownSelected)
                {
                    ImGui::SetItemDefaultFocus();
                }

                const bool leftToRightSelected = graphLayoutMode_ == GraphLayoutMode::LeftToRight;
                if (ImGui::Selectable("Left To Right", leftToRightSelected))
                {
                    graphLayoutMode_ = GraphLayoutMode::LeftToRight;
                    RequestGraphFit();
                }
                if (leftToRightSelected)
                {
                    ImGui::SetItemDefaultFocus();
                }
                ImGui::EndCombo();
            }
            ImGui::SameLine();
            if (ImGui::Button("Zoom -"))
            {
                graphZoom_ = clampZoom(graphZoom_ * 0.86f);
            }
            ImGui::SameLine();
            if (ImGui::Button("Zoom +"))
            {
                graphZoom_ = clampZoom(graphZoom_ * 1.16f);
            }
            ImGui::SameLine();
            if (ImGui::Button("Reset"))
            {
                ResetGraphView();
            }
            ImGui::SameLine();
            ImGui::TextDisabled("%.0f%%", graphZoom_ * 100.0f);

            const Core::ProcessInfo* selectedGraphProcess = Core::FindProcessByPid(snapshot_, selectedPid_);
            const bool selectedHiddenByFilters = selectedGraphProcess != nullptr && !ProcessMatchesFilters(*selectedGraphProcess);

            ImGui::Spacing();
            const ImVec2 available = ImGui::GetContentRegionAvail();
            const ImVec2 childSize(std::max(available.x, 320.0f), std::max(available.y, 260.0f));
            ImGui::PushStyleColor(ImGuiCol_ChildBg, GraphCanvasBg());
            ImGui::BeginChild(
                "graph_canvas",
                childSize,
                false,
                ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
            ImGui::PopStyleColor();

            const ImVec2 canvasOrigin = ImGui::GetWindowPos();
            const ImVec2 canvasSize = ImGui::GetWindowSize();
            const ImVec2 canvasMax(canvasOrigin.x + canvasSize.x, canvasOrigin.y + canvasSize.y);
            ImDrawList* drawList = ImGui::GetWindowDrawList();
            const bool selectedHasHighTriageFinding = SelectedProcessHasHighTriageFinding();

            drawList->PushClipRect(canvasOrigin, canvasMax, true);
            drawList->AddRectFilledMultiColor(
                canvasOrigin,
                canvasMax,
                IM_COL32(6, 10, 16, 255),
                IM_COL32(9, 15, 23, 255),
                IM_COL32(12, 18, 27, 255),
                ColorU32(GraphCanvasBg()));
            drawList->AddRectFilled(
                canvasOrigin,
                canvasMax,
                ColorU32(ImVec4(GraphCanvasBg().x, GraphCanvasBg().y, GraphCanvasBg().z, 0.58f)),
                8.0f);
            drawList->AddRect(canvasOrigin, canvasMax, ColorU32(PanelBorder()), 8.0f, 0, 1.2f);

            if (!std::isfinite(graphZoom_))
            {
                graphZoom_ = 1.0f;
            }
            graphZoom_ = clampZoom(graphZoom_);

            const float gridStep = std::max(42.0f, 80.0f * graphZoom_);
            float firstGridX = canvasOrigin.x + std::fmod(graphPan_.x, gridStep);
            if (firstGridX > canvasOrigin.x)
            {
                firstGridX -= gridStep;
            }
            for (float x = firstGridX; x < canvasMax.x; x += gridStep)
            {
                drawList->AddLine(
                    ImVec2(x, canvasOrigin.y + 12.0f),
                    ImVec2(x, canvasMax.y - 12.0f),
                    ColorU32(GraphGridLine()),
                    1.0f);
            }

            float firstGridY = canvasOrigin.y + std::fmod(graphPan_.y, gridStep);
            if (firstGridY > canvasOrigin.y)
            {
                firstGridY -= gridStep;
            }
            for (float y = firstGridY; y < canvasMax.y; y += gridStep)
            {
                drawList->AddLine(
                    ImVec2(canvasOrigin.x + 12.0f, y),
                    ImVec2(canvasMax.x - 12.0f, y),
                    ColorU32(GraphGridLine()),
                    1.0f);
            }

            if (focusedGraph_.nodes.empty())
            {
                drawList->AddText(
                    ImVec2(canvasOrigin.x + 16.0f, canvasOrigin.y + 16.0f),
                    ColorU32(MutedText()),
                    "No focused graph available.");
                drawList->PopClipRect();
                ImGui::EndChild();
                return;
            }

            RebuildGraphWorldLayoutIfNeeded();

            struct GraphVisualNode
            {
                std::size_t nodeIndex = 0;
                ImVec2 worldCenter = ImVec2(0.0f, 0.0f);
                ImVec2 min = ImVec2(0.0f, 0.0f);
                ImVec2 max = ImVec2(0.0f, 0.0f);
                Core::Severity displaySeverity = Core::Severity::None;
            };

            const bool singleNodeGraph = graphLayoutSingleNode_;
            const bool smallGraph = graphLayoutSmallGraph_;
            const ImVec2 baseNodeSize = graphLayoutBaseNodeSize_;
            std::vector<GraphVisualNode> visualNodes(graphLayoutNodes_.size());
            for (std::size_t layoutIndex = 0; layoutIndex < graphLayoutNodes_.size(); ++layoutIndex)
            {
                visualNodes[layoutIndex].nodeIndex = graphLayoutNodes_[layoutIndex].nodeIndex;
                visualNodes[layoutIndex].worldCenter = graphLayoutNodes_[layoutIndex].worldCenter;
            }

            if (graphLayoutHasWorldBounds_ &&
                (graphFitRequested_ ||
                    graphFitPid_ != focusedGraph_.focusPid ||
                    graphFitNodeCount_ != focusedGraph_.nodes.size() ||
                    graphFitLayoutMode_ != graphLayoutMode_))
            {
                const float padding = singleNodeGraph ? 120.0f : 74.0f;
                const float worldWidth = std::max(1.0f, graphLayoutWorldMax_.x - graphLayoutWorldMin_.x);
                const float worldHeight = std::max(1.0f, graphLayoutWorldMax_.y - graphLayoutWorldMin_.y);
                const float fitX = std::max(1.0f, canvasSize.x - padding * 2.0f) / worldWidth;
                const float fitY = std::max(1.0f, canvasSize.y - padding * 2.0f) / worldHeight;
                const float maxFitZoom = singleNodeGraph ? 1.28f : (smallGraph ? 1.16f : 1.0f);
                graphZoom_ = clampZoom(std::min(std::min(fitX, fitY), maxFitZoom));
                if (singleNodeGraph)
                {
                    graphPan_ = ImVec2(canvasSize.x * 0.5f, canvasSize.y * 0.5f);
                }
                else
                {
                    const ImVec2 worldCenter(
                        (graphLayoutWorldMin_.x + graphLayoutWorldMax_.x) * 0.5f,
                        (graphLayoutWorldMin_.y + graphLayoutWorldMax_.y) * 0.5f);
                    graphPan_ = ImVec2(
                        canvasSize.x * 0.5f - worldCenter.x * graphZoom_,
                        canvasSize.y * 0.5f - worldCenter.y * graphZoom_);
                }
                graphFitRequested_ = false;
                graphFitPid_ = focusedGraph_.focusPid;
                graphFitNodeCount_ = focusedGraph_.nodes.size();
                graphFitLayoutMode_ = graphLayoutMode_;
            }

            const bool canvasHovered = ImGui::IsWindowHovered(ImGuiHoveredFlags_AllowWhenBlockedByActiveItem);
            ImGuiIO& io = ImGui::GetIO();
            if (canvasHovered && io.MouseWheel != 0.0f)
            {
                const float previousZoom = graphZoom_;
                const ImVec2 mouseCanvas(
                    io.MousePos.x - canvasOrigin.x,
                    io.MousePos.y - canvasOrigin.y);
                const ImVec2 worldUnderMouse(
                    (mouseCanvas.x - graphPan_.x) / previousZoom,
                    (mouseCanvas.y - graphPan_.y) / previousZoom);
                const float zoomFactor = io.MouseWheel > 0.0f ? 1.13f : 0.88f;
                graphZoom_ = clampZoom(graphZoom_ * zoomFactor);
                graphPan_ = ImVec2(
                    mouseCanvas.x - worldUnderMouse.x * graphZoom_,
                    mouseCanvas.y - worldUnderMouse.y * graphZoom_);
            }

            const float nodeDrawScale = std::clamp(graphZoom_, 0.62f, 1.18f);
            const ImVec2 nodeSize(baseNodeSize.x * nodeDrawScale, baseNodeSize.y * nodeDrawScale);

            auto updateVisualRects = [&]() {
                for (GraphVisualNode& visual : visualNodes)
                {
                    const ImVec2 screenCenter(
                        canvasOrigin.x + graphPan_.x + visual.worldCenter.x * graphZoom_,
                        canvasOrigin.y + graphPan_.y + visual.worldCenter.y * graphZoom_);
                    visual.min = ImVec2(screenCenter.x - nodeSize.x * 0.5f, screenCenter.y - nodeSize.y * 0.5f);
                    visual.max = ImVec2(screenCenter.x + nodeSize.x * 0.5f, screenCenter.y + nodeSize.y * 0.5f);
                    if (visual.nodeIndex < focusedGraph_.nodes.size())
                    {
                        const Core::FocusedGraphNode& node = focusedGraph_.nodes[visual.nodeIndex];
                        visual.displaySeverity =
                            node.pid == selectedPid_ && selectedHasHighTriageFinding
                                ? Core::Severity::High
                                : node.severity;
                    }
                }
            };
            updateVisualRects();

            bool mouseOverNode = false;
            if (canvasHovered)
            {
                for (const GraphVisualNode& visual : visualNodes)
                {
                    if (ImGui::IsMouseHoveringRect(visual.min, visual.max))
                    {
                        mouseOverNode = true;
                        break;
                    }
                }
            }

            if (canvasHovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
            {
                graphLeftMouseDownStartedOnNode_ = mouseOverNode;
                graphLeftCanvasPanActive_ = !mouseOverNode;
            }

            const bool leftCanvasDrag =
                graphLeftCanvasPanActive_ &&
                ImGui::IsMouseDown(ImGuiMouseButton_Left) &&
                ImGui::IsMouseDragging(ImGuiMouseButton_Left, 0.0f);
            const bool alternateCanvasDrag =
                canvasHovered &&
                (ImGui::IsMouseDragging(ImGuiMouseButton_Middle, 0.0f) ||
                    ImGui::IsMouseDragging(ImGuiMouseButton_Right, 0.0f));
            if (leftCanvasDrag || alternateCanvasDrag)
            {
                graphPan_.x += io.MouseDelta.x;
                graphPan_.y += io.MouseDelta.y;
                ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
                updateVisualRects();
            }

            auto edgeAnchor = [&](std::uint32_t pid, bool parentSide) -> ImVec2 {
                const auto nodeIndex = graphLayoutNodeIndexByPid_.find(pid);
                if (nodeIndex == graphLayoutNodeIndexByPid_.end() || nodeIndex->second >= visualNodes.size())
                {
                    return ImVec2(0.0f, 0.0f);
                }

                const GraphVisualNode& visual = visualNodes[nodeIndex->second];
                if (graphLayoutMode_ == GraphLayoutMode::LeftToRight)
                {
                    return parentSide
                        ? ImVec2(visual.max.x, (visual.min.y + visual.max.y) * 0.5f)
                        : ImVec2(visual.min.x, (visual.min.y + visual.max.y) * 0.5f);
                }

                return parentSide
                    ? ImVec2((visual.min.x + visual.max.x) * 0.5f, visual.max.y)
                    : ImVec2((visual.min.x + visual.max.x) * 0.5f, visual.min.y);
            };

            for (const Core::FocusedGraphEdge& edge : focusedGraph_.edges)
            {
                if (graphLayoutNodeIndexByPid_.find(edge.parentPid) == graphLayoutNodeIndexByPid_.end() ||
                    graphLayoutNodeIndexByPid_.find(edge.childPid) == graphLayoutNodeIndexByPid_.end())
                {
                    continue;
                }

                const ImVec2 start = edgeAnchor(edge.parentPid, true);
                const ImVec2 end = edgeAnchor(edge.childPid, false);
                const ImU32 color = edge.inSelectedChain
                    ? ColorU32(ImVec4(AccentBlue().x, AccentBlue().y, AccentBlue().z, 0.92f))
                    : IM_COL32(94, 108, 130, 210);
                if (graphLayoutMode_ == GraphLayoutMode::LeftToRight)
                {
                    const float midpoint = (start.x + end.x) * 0.5f;
                    if (edge.inSelectedChain)
                    {
                        drawList->AddBezierCubic(
                            start,
                            ImVec2(midpoint, start.y),
                            ImVec2(midpoint, end.y),
                            end,
                            ColorU32(ImVec4(AccentBlue().x, AccentBlue().y, AccentBlue().z, 0.18f)),
                            7.0f);
                    }
                    drawList->AddBezierCubic(
                        start,
                        ImVec2(midpoint, start.y),
                        ImVec2(midpoint, end.y),
                        end,
                        color,
                        edge.inSelectedChain ? 4.6f : 2.4f);
                }
                else
                {
                    const float midpoint = (start.y + end.y) * 0.5f;
                    if (edge.inSelectedChain)
                    {
                        drawList->AddBezierCubic(
                            start,
                            ImVec2(start.x, midpoint),
                            ImVec2(end.x, midpoint),
                            end,
                            ColorU32(ImVec4(AccentBlue().x, AccentBlue().y, AccentBlue().z, 0.18f)),
                            7.0f);
                    }
                    drawList->AddBezierCubic(
                        start,
                        ImVec2(start.x, midpoint),
                        ImVec2(end.x, midpoint),
                        end,
                        color,
                        edge.inSelectedChain ? 4.6f : 2.4f);
                }
            }

            std::uint32_t pendingSelectedPid = InvalidPid;
            ImVec2 singleNodeMin;
            ImVec2 singleNodeMax;
            bool hasSingleNodeBounds = false;
            for (const GraphVisualNode& visual : visualNodes)
            {
                if (visual.nodeIndex >= focusedGraph_.nodes.size())
                {
                    continue;
                }

                const Core::FocusedGraphNode& node = focusedGraph_.nodes[visual.nodeIndex];
                if (singleNodeGraph)
                {
                    singleNodeMin = visual.min;
                    singleNodeMax = visual.max;
                    hasSingleNodeBounds = true;
                }

                const bool hovered = ImGui::IsMouseHoveringRect(visual.min, visual.max);
                const ImVec2 leftDragDelta = ImGui::GetMouseDragDelta(ImGuiMouseButton_Left);
                const bool leftClickWithoutDrag =
                    (leftDragDelta.x * leftDragDelta.x + leftDragDelta.y * leftDragDelta.y) < 36.0f;
                if (hovered &&
                    graphLeftMouseDownStartedOnNode_ &&
                    leftClickWithoutDrag &&
                    ImGui::IsMouseReleased(ImGuiMouseButton_Left))
                {
                    pendingSelectedPid = node.pid;
                }

                ImU32 fill = node.focus ? ColorU32(ImVec4(0.090f, 0.165f, 0.245f, 1.0f)) : ColorU32(CardBg());
                if (Core::SeverityRank(visual.displaySeverity) >= Core::SeverityRank(Core::Severity::High))
                {
                    fill = node.focus ? IM_COL32(58, 38, 46, 255) : IM_COL32(46, 22, 28, 255);
                }
                else if (Core::SeverityRank(visual.displaySeverity) >= Core::SeverityRank(Core::Severity::Low))
                {
                    fill = node.focus ? IM_COL32(58, 49, 36, 255) : IM_COL32(42, 33, 25, 255);
                }

                const ImU32 border = Core::SeverityRank(visual.displaySeverity) >= Core::SeverityRank(Core::Severity::Low)
                    ? SeverityU32(visual.displaySeverity)
                    : (node.inSelectedChain ? ColorU32(AccentBlue()) : ColorU32(PanelBorder()));
                if (node.focus)
                {
                    drawList->AddRect(
                        ImVec2(visual.min.x - 4.0f, visual.min.y - 4.0f),
                        ImVec2(visual.max.x + 4.0f, visual.max.y + 4.0f),
                        ColorU32(ImVec4(AccentBlue().x, AccentBlue().y, AccentBlue().z, 0.68f)),
                        9.0f,
                        0,
                        2.0f);
                }
                drawList->AddRectFilled(
                    ImVec2(visual.min.x + 3.0f, visual.min.y + 4.0f),
                    ImVec2(visual.max.x + 3.0f, visual.max.y + 4.0f),
                    IM_COL32(0, 0, 0, 72),
                    9.0f);
                drawList->AddRectFilled(visual.min, visual.max, fill, 9.0f);
                drawList->AddRect(visual.min, visual.max, border, 9.0f, 0, node.focus ? 3.2f : 1.8f);
                drawList->AddRectFilled(
                    ImVec2(visual.min.x, visual.min.y),
                    ImVec2(visual.min.x + 5.0f, visual.max.y),
                    border,
                    9.0f,
                    ImDrawFlags_RoundCornersLeft);

                const std::string title = Shorten(DisplayName(node.name), nodeDrawScale < 0.78f ? 22 : 30);
                const std::string pidText = "PID " + std::to_string(node.pid);
                const float leftPadding = std::max(12.0f, 18.0f * nodeDrawScale);
                drawList->AddText(
                    ImVec2(visual.min.x + leftPadding, visual.min.y + 15.0f * nodeDrawScale),
                    ColorU32(PrimaryText()),
                    title.c_str());
                drawList->AddText(
                    ImVec2(visual.min.x + leftPadding, visual.min.y + 48.0f * nodeDrawScale),
                    ColorU32(MutedText()),
                    pidText.c_str());

                if (Core::SeverityRank(visual.displaySeverity) >= Core::SeverityRank(Core::Severity::Low))
                {
                    const std::string severityLabel = WideToUtf8(Core::SeverityToString(visual.displaySeverity));
                    const ImVec2 badgeTextSize = ImGui::CalcTextSize(severityLabel.c_str());
                    const ImVec2 badgeMin(
                        visual.max.x - badgeTextSize.x - 28.0f,
                        visual.min.y + 15.0f * nodeDrawScale);
                    const ImVec2 badgeMax(
                        visual.max.x - 12.0f,
                        badgeMin.y + 24.0f);
                    if (badgeMin.x > visual.min.x + leftPadding + 90.0f)
                    {
                        drawList->AddRectFilled(badgeMin, badgeMax, IM_COL32(20, 22, 26, 180), 4.0f);
                        drawList->AddRect(badgeMin, badgeMax, SeverityU32(visual.displaySeverity), 4.0f, 0, 1.0f);
                        drawList->AddText(
                            ImVec2(badgeMin.x + 8.0f, badgeMin.y + 4.0f),
                            SeverityU32(visual.displaySeverity),
                            severityLabel.c_str());
                    }
                }
                else if (node.inSelectedChain)
                {
                    drawList->AddText(
                        ImVec2(visual.min.x + leftPadding, visual.min.y + 76.0f * nodeDrawScale),
                        ColorU32(AccentBlue()),
                        "chain");
                }

                if (hovered)
                {
                    drawList->AddRect(
                        visual.min,
                        visual.max,
                        ColorU32(ImVec4(AccentBlue().x, AccentBlue().y, AccentBlue().z, 0.82f)),
                        9.0f,
                        0,
                        1.5f);
                    ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
                }
            }

            if (hasSingleNodeBounds)
            {
                const Core::ProcessInfo* summaryProcess = selectedGraphProcess != nullptr
                    ? selectedGraphProcess
                    : Core::FindProcessByPid(snapshot_, focusedGraph_.nodes.front().pid);

                const char* relationshipMessage = "No visible parent or child relationships for this process.";
                const ImVec2 messageSize = ImGui::CalcTextSize(relationshipMessage);
                const float clusterCenterX = (singleNodeMin.x + singleNodeMax.x) * 0.5f;
                const auto centeredClusterX = [&](float width) {
                    const float minX = canvasOrigin.x + 18.0f;
                    const float maxX = std::max(minX, canvasMax.x - width - 18.0f);
                    return std::clamp(clusterCenterX - width * 0.5f, minX, maxX);
                };
                const float messageY = std::min(
                    singleNodeMax.y + 22.0f,
                    canvasOrigin.y + canvasSize.y - 72.0f);
                drawList->AddText(
                    ImVec2(centeredClusterX(messageSize.x), messageY),
                    ColorU32(MutedText()),
                    relationshipMessage);

                if (summaryProcess != nullptr)
                {
                    struct GraphSummaryBadge
                    {
                        std::string label;
                        std::string value;
                        ImVec4 color;
                        float width = 0.0f;
                    };

                    std::vector<GraphSummaryBadge> badges;
                    const Core::ChainAnalysisResult chain = Core::AnalyzeChain(snapshot_, summaryProcess->pid);
                    const Core::FileIdentity& fileIdentity = CachedFileIdentity(summaryProcess->executablePath);
                    const std::vector<Core::Finding>& findings =
                        FindingsForSelectedProcess(*summaryProcess, chain, fileIdentity);

                    Core::Severity triageSeverity = Core::Severity::None;
                    std::string triageValue = "Clean";
                    if (!findings.empty())
                    {
                        triageSeverity = FindingSeverityAsCoreSeverity(Core::HighestFindingSeverity(findings));
                        triageValue = WideToUtf8(Core::SeverityToString(triageSeverity));
                    }
                    else if (!summaryProcess->indicators.empty() || !summaryProcess->contextNotes.empty())
                    {
                        triageSeverity = Core::Severity::Info;
                        triageValue = "Info";
                    }

                    badges.push_back({ "Triage", triageValue, SeverityColor(triageSeverity), 0.0f });
                    if (networkLoaded_)
                    {
                        const NetworkSummary networkSummary = GetNetworkSummary(summaryProcess->pid);
                        badges.push_back({
                            "Network",
                            std::to_string(networkSummary.connectionCount) +
                                (networkSummary.connectionCount == 1 ? " connection" : " connections"),
                            networkSummary.publicRemoteCount > 0 ? SeverityColor(Core::Severity::Low) : AccentBlue(),
                            0.0f });
                    }
                    if (ModulesLoadedForProcess(*summaryProcess))
                    {
                        badges.push_back({
                            "Modules",
                            std::to_string(selectedModules_.modules.size()) + " loaded",
                            AccentBlue(),
                            0.0f });
                    }

                    float badgeRowWidth = 0.0f;
                    for (GraphSummaryBadge& badge : badges)
                    {
                        badge.width =
                            ImGui::CalcTextSize(badge.label.c_str()).x +
                            ImGui::CalcTextSize(badge.value.c_str()).x +
                            34.0f;
                        badgeRowWidth += badge.width;
                    }
                    badgeRowWidth += std::max<std::size_t>(badges.size(), 1) > 1
                        ? static_cast<float>(badges.size() - 1) * 8.0f
                        : 0.0f;

                    float badgeX = centeredClusterX(badgeRowWidth);
                    const float badgeY = messageY + 30.0f;
                    for (const GraphSummaryBadge& badge : badges)
                    {
                        const ImVec2 badgeMin(badgeX, badgeY);
                        const ImVec2 badgeMax(badgeX + badge.width, badgeY + 28.0f);
                        drawList->AddRectFilled(badgeMin, badgeMax, ColorU32(CardBg()), 6.0f);
                        drawList->AddRect(badgeMin, badgeMax, ColorU32(ImVec4(badge.color.x, badge.color.y, badge.color.z, 0.48f)), 6.0f);
                        drawList->AddText(ImVec2(badgeMin.x + 10.0f, badgeMin.y + 6.0f), ColorU32(MutedText()), badge.label.c_str());
                        drawList->AddText(
                            ImVec2(badgeMin.x + ImGui::CalcTextSize(badge.label.c_str()).x + 18.0f, badgeMin.y + 6.0f),
                            ColorU32(badge.color),
                            badge.value.c_str());
                        badgeX = badgeMax.x + 8.0f;
                    }
                }
            }

            if (selectedHiddenByFilters)
            {
                const ImVec2 overlayMin(canvasOrigin.x + 18.0f, canvasOrigin.y + 18.0f);
                const ImVec2 overlayMax(
                    std::min(canvasOrigin.x + canvasSize.x - 18.0f, overlayMin.x + 420.0f),
                    overlayMin.y + 76.0f);
                drawList->AddRectFilled(overlayMin, overlayMax, ColorU32(ImVec4(CardBg().x, CardBg().y, CardBg().z, 0.96f)), 8.0f);
                drawList->AddRect(overlayMin, overlayMax, ColorU32(ImVec4(SeverityColor(Core::Severity::Medium).x, SeverityColor(Core::Severity::Medium).y, SeverityColor(Core::Severity::Medium).z, 0.52f)), 8.0f);
                drawList->AddText(
                    ImVec2(overlayMin.x + 14.0f, overlayMin.y + 13.0f),
                    ColorU32(PrimaryText()),
                    "Selected process is hidden by filters.");
                drawList->AddText(
                    ImVec2(overlayMin.x + 14.0f, overlayMin.y + 38.0f),
                    ColorU32(MutedText()),
                    "Clear search and switch to All to reveal it.");

                const ImVec2 buttonMin(overlayMax.x - 128.0f, overlayMin.y + 24.0f);
                const ImVec2 buttonMax(buttonMin.x + 110.0f, buttonMin.y + 30.0f);
                const bool buttonHovered = ImGui::IsMouseHoveringRect(buttonMin, buttonMax);
                drawList->AddRectFilled(
                    buttonMin,
                    buttonMax,
                    buttonHovered ? ColorU32(PanelHover()) : ColorU32(CardBg()),
                    6.0f);
                drawList->AddRect(
                    buttonMin,
                    buttonMax,
                    ColorU32(ImVec4(AccentBlue().x, AccentBlue().y, AccentBlue().z, buttonHovered ? 0.92f : 0.58f)),
                    6.0f,
                    0,
                    1.2f);
                const char* showSelectedLabel = "Show selected";
                const ImVec2 labelSize = ImGui::CalcTextSize(showSelectedLabel);
                drawList->AddText(
                    ImVec2(
                        buttonMin.x + (buttonMax.x - buttonMin.x - labelSize.x) * 0.5f,
                        buttonMin.y + (buttonMax.y - buttonMin.y - labelSize.y) * 0.5f),
                    ColorU32(PrimaryText()),
                    showSelectedLabel);

                if (buttonHovered)
                {
                    ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
                }
                if (buttonHovered && ImGui::IsMouseReleased(ImGuiMouseButton_Left))
                {
                    ShowSelectedProcessInFilters();
                }
            }

            drawList->PopClipRect();
            ImGui::EndChild();

            if (pendingSelectedPid != InvalidPid)
            {
                SelectGraphNode(pendingSelectedPid);
            }

            if (!ImGui::IsMouseDown(ImGuiMouseButton_Left))
            {
                graphLeftCanvasPanActive_ = false;
                graphLeftMouseDownStartedOnNode_ = false;
            }
        }

        void RenderTimelineView()
        {
            ImGui::TextUnformatted("Filter:");
            ImGui::SameLine();
            int filterValue = static_cast<int>(timelineFilter_);
            if (ImGui::RadioButton("All", filterValue == static_cast<int>(Core::TimelineFilter::All)))
            {
                if (timelineFilter_ != Core::TimelineFilter::All)
                {
                    timelineFilter_ = Core::TimelineFilter::All;
                    timelineRowsDirty_ = true;
                    timelineTableNeedsAutoSize_ = true;
                }
            }
            ImGui::SameLine();
            if (ImGui::RadioButton("Suspicious only", filterValue == static_cast<int>(Core::TimelineFilter::SuspiciousOnly)))
            {
                if (timelineFilter_ != Core::TimelineFilter::SuspiciousOnly)
                {
                    timelineFilter_ = Core::TimelineFilter::SuspiciousOnly;
                    timelineRowsDirty_ = true;
                    timelineTableNeedsAutoSize_ = true;
                }
            }
            ImGui::SameLine();
            if (ImGui::RadioButton("High severity only", filterValue == static_cast<int>(Core::TimelineFilter::HighSeverityOnly)))
            {
                if (timelineFilter_ != Core::TimelineFilter::HighSeverityOnly)
                {
                    timelineFilter_ = Core::TimelineFilter::HighSeverityOnly;
                    timelineRowsDirty_ = true;
                    timelineTableNeedsAutoSize_ = true;
                }
            }

            const std::vector<Core::TimelineRow>& visibleTimelineRows = TimelineRowsForCurrentFilters();
            const ImGuiTableFlags flags =
                ImGuiTableFlags_BordersInnerV |
                ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Resizable |
                ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_SizingStretchProp |
                ImGuiTableFlags_NoSavedSettings;
            if (visibleTimelineRows.empty())
            {
                ImGui::Spacing();
                ImGui::TextDisabled("No matching timeline rows.");
                return;
            }

            AcknowledgeTableAutoSizeRequest(timelineTableNeedsAutoSize_);
            if (ImGui::BeginTable("TimelineTable##TimelinePanel", 6, flags))
            {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn("Timestamp", ImGuiTableColumnFlags_WidthFixed, 150.0f);
                ImGui::TableSetupColumn("Process", ImGuiTableColumnFlags_WidthFixed, 190.0f);
                ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 70.0f);
                ImGui::TableSetupColumn("Parent", ImGuiTableColumnFlags_WidthFixed, 210.0f);
                ImGui::TableSetupColumn("Severity", ImGuiTableColumnFlags_WidthFixed, 90.0f);
                ImGui::TableSetupColumn("Indicator", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableHeadersRow();

                ImGuiListClipper clipper;
                clipper.Begin(static_cast<int>(visibleTimelineRows.size()));
                while (clipper.Step())
                {
                    for (int rowIndex = clipper.DisplayStart; rowIndex < clipper.DisplayEnd; ++rowIndex)
                    {
                        const Core::TimelineRow& row = visibleTimelineRows[static_cast<std::size_t>(rowIndex)];

                        ImGui::TableNextRow();
                        if (row.pid == selectedPid_)
                        {
                            const ImU32 selectedRow = ColorU32(TableSelectedRow());
                            ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, selectedRow);
                            ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1, selectedRow);
                        }
                        ImGui::PushID(static_cast<int>(row.pid));

                        ImGui::TableSetColumnIndex(0);
                        const bool pushedTimelineTimeFont = PushFontIfAvailable(fonts_.monospace);
                        if (ImGui::Selectable(
                            WideToUtf8(row.hasCreationTime ? row.creationTimeLocal : L"(unavailable)").c_str(),
                            row.pid == selectedPid_,
                            ImGuiSelectableFlags_SpanAllColumns,
                            ImVec2(0.0f, 24.0f)))
                        {
                            SelectProcess(row.pid, true);
                        }
                        PopFontIfPushed(pushedTimelineTimeFont);

                        ImGui::TableSetColumnIndex(1);
                        TextWide(row.processName.empty() ? L"(unknown)" : row.processName);
                        ImGui::TableSetColumnIndex(2);
                        const bool pushedTimelinePidFont = PushFontIfAvailable(fonts_.monospace);
                        ImGui::Text("%u", row.pid);
                        PopFontIfPushed(pushedTimelinePidFont);
                        ImGui::TableSetColumnIndex(3);
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
                        TextWide(parentText);
                        ImGui::TableSetColumnIndex(4);
                        SeverityText(row.severity);
                        ImGui::TableSetColumnIndex(5);
                        TextWide(row.firstIndicator);

                        ImGui::PopID();
                    }
                }
                ImGui::EndTable();
            }
        }

        void RenderLogsPanelContent()
        {
            ImGui::TextColored(AccentBlue(), "Console");
            ImGui::SameLine();
            ImGui::TextColored(MutedText(), "%zu entries", logs_.size());
            const float buttonsWidth = ImGui::CalcTextSize("Clear").x + ImGui::CalcTextSize("Save").x + 54.0f;
            ImGui::SameLine(ImGui::GetCursorPosX() + std::max(0.0f, ImGui::GetContentRegionAvail().x - buttonsWidth));
            if (ImGui::Button("Clear"))
            {
                logs_.clear();
            }
            ImGui::SameLine();
            if (ImGui::Button("Save"))
            {
                SaveLogs();
            }

            ImGui::PushStyleColor(ImGuiCol_ChildBg, ConsoleBg());
            ImGui::PushStyleColor(ImGuiCol_Border, PanelBorder());
            ImGui::BeginChild("log_console", ImVec2(0.0f, 0.0f), ImGuiChildFlags_Borders | ImGuiChildFlags_AlwaysUseWindowPadding);
            const bool pushedLogFont = PushFontIfAvailable(fonts_.monospace);
            for (const LogEntry& entry : logs_)
            {
                std::string timestamp;
                std::string message = entry.message;
                if (entry.message.size() > 21 && entry.message[4] == '-' && entry.message[13] == ':')
                {
                    timestamp = entry.message.substr(0, 19);
                    message = entry.message.substr(21);
                }

                if (!timestamp.empty())
                {
                    ImGui::TextDisabled("%s", timestamp.c_str());
                    ImGui::SameLine(176.0f);
                }
                ImGui::TextColored(LogColor(entry.level), "[%s]", LogLevelLabel(entry.level));
                ImGui::SameLine();
                ImGui::TextWrapped("%s", message.c_str());
            }
            PopFontIfPushed(pushedLogFont);
            ImGui::EndChild();
            ImGui::PopStyleColor(2);
        }

        void RenderBottomPanel()
        {
            if (!BeginPanelWindow("Indicators / Logs"))
            {
                EndPanelWindow();
                return;
            }
            if (ImGui::BeginTabBar("bottom_tabs"))
            {
                if (ImGui::BeginTabItem("Logs"))
                {
                    RenderLogsPanelContent();
                    ImGui::EndTabItem();
                }
                if (ImGui::BeginTabItem("Indicators"))
                {
                    RenderSelectedIndicators();
                    ImGui::EndTabItem();
                }
                ImGui::EndTabBar();
            }
            EndPanelWindow();
        }

        void RenderSelectedIndicators()
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                ImGui::TextUnformatted("No process selected.");
                return;
            }

            const Core::ChainAnalysisResult chain = Core::AnalyzeChain(snapshot_, process->pid);
            const Core::FileIdentity& fileIdentity = CachedFileIdentity(process->executablePath);
            const std::vector<Core::FileIdentityIndicator> fileIdentityIndicators =
                Core::BuildFileIdentityIndicators(fileIdentity, process->name, true);
            ImGui::TextDisabled("Process Indicators");
            if (process->indicators.empty() && fileIdentityIndicators.empty())
            {
                ImGui::TextUnformatted("None");
            }
            else
            {
                for (const std::wstring& indicator : process->indicators)
                {
                    ImGui::Bullet();
                    ImGui::SameLine();
                    WrappedTextWide(indicator);
                }
                for (const Core::FileIdentityIndicator& indicator : fileIdentityIndicators)
                {
                    ImGui::Bullet();
                    ImGui::SameLine();
                    SeverityText(indicator.severity);
                    ImGui::SameLine();
                    WrappedTextWide(indicator.message);
                }
            }

            ImGui::Separator();
            ImGui::TextDisabled("Chain Indicators");
            if (chain.chainIndicators.empty())
            {
                ImGui::TextUnformatted("None");
            }
            else
            {
                for (const std::wstring& indicator : chain.chainIndicators)
                {
                    ImGui::Bullet();
                    ImGui::SameLine();
                    WrappedTextWide(indicator);
                }
            }

            if (ModulesLoadedForProcess(*process) && !selectedModules_.indicators.empty())
            {
                ImGui::Separator();
                ImGui::TextDisabled("Module Indicators");
                for (const std::wstring& indicator : selectedModules_.indicators)
                {
                    ImGui::Bullet();
                    ImGui::SameLine();
                    WrappedTextWide(indicator);
                }
            }
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

        void RefreshModules()
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                AddLog(LogLevel::Warning, "No selected process for module refresh.");
                selectedModules_ = {};
                selectedModulesLoaded_ = false;
                selectedModulesPid_ = InvalidPid;
                selectedModulesCreationTime_ = 0;
                return;
            }

            const ULONGLONG started = GetTickCount64();
            selectedModules_ = Core::CollectProcessModules(*process);
            timings_.modulesMs = ElapsedMs(started);
            selectedModulesLoaded_ = true;
            modulesTableNeedsAutoSize_ = true;
            selectedModulesPid_ = process->pid;
            selectedModulesCreationTime_ = ProcessCacheStamp(*process);
            selectedModulePid_ = InvalidPid;
            selectedModuleIndex_ = 0;
            InvalidateFindingsCache();
            AddLog(
                selectedModules_.success ? LogLevel::Info : LogLevel::Warning,
                "Module refresh for PID " + std::to_string(process->pid) + ": " +
                    WideToUtf8(selectedModules_.statusMessage) +
                    " (" + std::to_string(timings_.modulesMs) + " ms).");
        }

        void RefreshToken(bool logActivity = true)
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                selectedToken_ = {};
                selectedTokenLoaded_ = false;
                selectedTokenPid_ = InvalidPid;
                selectedTokenCreationTime_ = 0;
                InvalidateFindingsCache();
                if (logActivity)
                {
                    AddLog(LogLevel::Warning, "No selected process for token refresh.");
                }
                return;
            }

            const ULONGLONG started = GetTickCount64();
            selectedToken_ = Core::CollectProcessTokenInfo(*process);
            timings_.tokenMs = ElapsedMs(started);
            selectedTokenLoaded_ = true;
            tokenTableNeedsAutoSize_ = true;
            selectedTokenPid_ = process->pid;
            selectedTokenCreationTime_ = ProcessCacheStamp(*process);
            InvalidateFindingsCache();

            if (logActivity)
            {
                AddLog(
                    selectedToken_.success ? LogLevel::Info : LogLevel::Warning,
                    "Token refresh for PID " + std::to_string(process->pid) + ": " +
                        (selectedToken_.success ? "loaded token metadata" : WideToUtf8(selectedToken_.errorMessage)) +
                        " (" + std::to_string(timings_.tokenMs) + " ms).");
            }
        }

        void RefreshRuntime(bool logActivity = true)
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                selectedRuntime_ = {};
                selectedRuntimeLoaded_ = false;
                selectedRuntimePid_ = InvalidPid;
                selectedRuntimeCreationTime_ = 0;
                InvalidateFindingsCache();
                if (logActivity)
                {
                    AddLog(LogLevel::Warning, "No selected process for runtime refresh.");
                }
                return;
            }

            const ULONGLONG started = GetTickCount64();
            selectedRuntime_ = Core::CollectProcessRuntimeInfo(*process);
            timings_.runtimeMs = ElapsedMs(started);
            selectedRuntimeLoaded_ = true;
            runtimeTableNeedsAutoSize_ = true;
            selectedRuntimePid_ = process->pid;
            selectedRuntimeCreationTime_ = ProcessCacheStamp(*process);
            InvalidateFindingsCache();

            if (logActivity)
            {
                AddLog(
                    selectedRuntime_.success ? LogLevel::Info : LogLevel::Warning,
                    "Runtime refresh for PID " + std::to_string(process->pid) + ": " +
                        std::to_string(selectedRuntime_.threadCount) +
                        " thread(s), " +
                        std::to_string(selectedRuntime_.handleCount) +
                        " handle(s) in " + std::to_string(timings_.runtimeMs) + " ms.");
            }
        }

        void RefreshMemory(bool logActivity = true)
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                selectedMemory_ = {};
                selectedMemoryLoaded_ = false;
                selectedMemoryPid_ = InvalidPid;
                selectedMemoryCreationTime_ = 0;
                visibleMemoryRegionsDirty_ = true;
                visibleMemoryRegionIndexes_.clear();
                visibleMemoryPid_ = InvalidPid;
                visibleMemoryCreationTime_ = 0;
                visibleMemorySourceSize_ = 0;
                visibleMemorySearchText_.clear();
                InvalidateFindingsCache();
                if (logActivity)
                {
                    AddLog(LogLevel::Warning, "No selected process for memory refresh.");
                }
                return;
            }

            const ULONGLONG started = GetTickCount64();
            selectedMemory_ = Core::CollectMemoryRegionsForPid(process->pid);
            timings_.memoryMs = ElapsedMs(started);
            selectedMemoryLoaded_ = true;
            memoryTableNeedsAutoSize_ = true;
            selectedMemoryPid_ = process->pid;
            selectedMemoryCreationTime_ = ProcessCacheStamp(*process);
            visibleMemoryRegionsDirty_ = true;
            InvalidateFindingsCache();

            if (logActivity)
            {
                AddLog(
                    selectedMemory_.success ? LogLevel::Info : LogLevel::Warning,
                    "Memory refresh for PID " + std::to_string(process->pid) + ": " +
                        std::to_string(selectedMemory_.regions.size()) +
                        " region(s), " +
                        std::to_string(selectedMemory_.suspiciousRegions) +
                        " suspicious in " + std::to_string(timings_.memoryMs) + " ms.");
            }
        }

        void RefreshHandles(bool logActivity = true)
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                selectedHandles_ = {};
                selectedHandlesLoaded_ = false;
                selectedHandlesPid_ = InvalidPid;
                selectedHandlesCreationTime_ = 0;
                visibleHandlesDirty_ = true;
                visibleHandleIndexes_.clear();
                visibleHandlesPid_ = InvalidPid;
                visibleHandlesCreationTime_ = 0;
                visibleHandlesSourceSize_ = 0;
                visibleHandlesWithIndicatorsCount_ = 0;
                visibleHandlesNameStatusCount_ = 0;
                visibleHandlesSearchText_.clear();
                InvalidateFindingsCache();
                if (logActivity)
                {
                    AddLog(LogLevel::Warning, "No selected process for handle refresh.");
                }
                return;
            }

            const ULONGLONG started = GetTickCount64();
            selectedHandles_ = Core::CollectProcessHandles(*process, &snapshot_);
            timings_.handlesMs = ElapsedMs(started);
            selectedHandlesLoaded_ = true;
            handlesTableNeedsAutoSize_ = true;
            selectedHandlesPid_ = process->pid;
            selectedHandlesCreationTime_ = ProcessCacheStamp(*process);
            visibleHandlesDirty_ = true;
            InvalidateFindingsCache();

            if (logActivity)
            {
                AddLog(
                    selectedHandles_.success ? LogLevel::Info : LogLevel::Warning,
                    "Handle refresh for PID " + std::to_string(process->pid) + ": " +
                        std::to_string(selectedHandles_.handles.size()) +
                        " handle(s), " +
                        std::to_string(selectedHandles_.sensitiveCount) +
                        " sensitive in " + std::to_string(timings_.handlesMs) + " ms.");
            }
        }

        void ExportSnapshot()
        {
            wchar_t fileName[MAX_PATH] = L"glasspane-snapshot.json";
            if (!PromptForJsonPath(fileName))
            {
                return;
            }

            std::wstring error;
            const ULONGLONG started = GetTickCount64();
            if (!Export::ExportSnapshotToJson(snapshot_, fileName, &error))
            {
                timings_.jsonExportMs = ElapsedMs(started);
                AddLog(LogLevel::High, "Snapshot export failed: " + WideToUtf8(error));
                MessageBoxW(hwnd_, error.c_str(), L"Export failed", MB_ICONERROR | MB_OK);
                return;
            }
            timings_.jsonExportMs = ElapsedMs(started);

            AddLog(LogLevel::Info, "Snapshot exported: " + WideToUtf8(fileName) +
                " (" + std::to_string(timings_.jsonExportMs) + " ms).");
        }

        void ExportSelectedDetails()
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                AddLog(LogLevel::Warning, "No selected process to export.");
                return;
            }

            if (!ModulesLoadedForProcess(*process))
            {
                RefreshModules();
            }

            if (!networkLoaded_)
            {
                RefreshNetwork(true);
            }
            const std::vector<Core::NetworkConnection> selectedNetworkConnections = SelectedNetworkConnectionsForExport();

            wchar_t fileName[MAX_PATH] = L"glasspane-selected-process.json";
            if (!PromptForJsonPath(fileName))
            {
                return;
            }

            std::wstring error;
            const Core::HandleCollectionResult* handlesForExport =
                HandlesLoadedForProcess(*process) ? &selectedHandles_ : nullptr;
            const Core::RuntimeInfo* runtimeForExport =
                RuntimeLoadedForProcess(*process) ? &selectedRuntime_ : nullptr;
            const Core::MemoryCollectionResult* memoryForExport =
                MemoryLoadedForProcess(*process) ? &selectedMemory_ : nullptr;
            const ULONGLONG started = GetTickCount64();
            if (!Export::ExportSelectedProcessDetailsToJson(
                snapshot_,
                selectedPid_,
                selectedModules_,
                selectedNetworkConnections,
                handlesForExport,
                runtimeForExport,
                memoryForExport,
                fileName,
                &error))
            {
                timings_.jsonExportMs = ElapsedMs(started);
                AddLog(LogLevel::High, "Selected process export failed: " + WideToUtf8(error));
                MessageBoxW(hwnd_, error.c_str(), L"Export selected failed", MB_ICONERROR | MB_OK);
                return;
            }
            timings_.jsonExportMs = ElapsedMs(started);

            AddLog(LogLevel::Info, "Selected process exported: " + WideToUtf8(fileName) +
                " (" + std::to_string(timings_.jsonExportMs) + " ms).");
        }

        void ExportSelectedMarkdownReport()
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                AddLog(LogLevel::Warning, "No selected process for report export.");
                return;
            }

            const std::wstring defaultFileName =
                L"glasspane-report-" +
                SanitizedFileNamePart(process->name) +
                L"-" +
                std::to_wstring(process->pid) +
                L"-" +
                FileTimestamp() +
                L".md";

            wchar_t fileName[MAX_PATH] = {};
            wcsncpy_s(fileName, defaultFileName.c_str(), _TRUNCATE);
            if (!PromptForMarkdownPath(fileName))
            {
                return;
            }

            const Core::ChainAnalysisResult chain = Core::AnalyzeChain(snapshot_, process->pid);
            const Core::FileIdentity& fileIdentity = CachedFileIdentity(process->executablePath);
            const std::vector<Core::FileIdentityIndicator> fileIdentityIndicators =
                Core::BuildFileIdentityIndicators(fileIdentity, process->name, true);
            const std::vector<Core::Finding> findings =
                FindingsForSelectedProcess(*process, chain, fileIdentity);
            const std::vector<Core::NetworkConnection> selectedNetworkConnections =
                networkLoaded_
                    ? SelectedNetworkConnectionsForExport()
                    : std::vector<Core::NetworkConnection>{};
            const std::string appVersion = GlassPaneVersion();

            Export::SelectedProcessMarkdownReportContext reportContext;
            reportContext.snapshot = &snapshot_;
            reportContext.pid = selectedPid_;
            reportContext.appVersion = Utf8ToWide(appVersion.c_str());
            reportContext.buildConfiguration = Utf8ToWide(BuildConfiguration());
            reportContext.findings = findings;
            reportContext.fileIdentity = &fileIdentity;
            reportContext.fileIdentityIndicators = fileIdentityIndicators;
            reportContext.modulesLoaded = ModulesLoadedForProcess(*process);
            reportContext.modules = reportContext.modulesLoaded ? &selectedModules_ : nullptr;
            reportContext.networkLoaded = networkLoaded_;
            reportContext.networkSuccess = networkSnapshot_.success;
            reportContext.networkStatusMessage = networkSnapshot_.statusMessage;
            reportContext.networkConnections = reportContext.networkLoaded ? &selectedNetworkConnections : nullptr;
            reportContext.tokenLoaded = TokenLoadedForProcess(*process);
            reportContext.token = reportContext.tokenLoaded ? &selectedToken_ : nullptr;
            reportContext.runtimeLoaded = RuntimeLoadedForProcess(*process);
            reportContext.runtime = reportContext.runtimeLoaded ? &selectedRuntime_ : nullptr;
            reportContext.memoryLoaded = MemoryLoadedForProcess(*process);
            reportContext.memory = reportContext.memoryLoaded ? &selectedMemory_ : nullptr;
            reportContext.handlesLoaded = HandlesLoadedForProcess(*process);
            reportContext.handles = reportContext.handlesLoaded ? &selectedHandles_ : nullptr;

            AddLog(
                LogLevel::Info,
                "Markdown report export started for " + DisplayName(process->name) +
                    " (PID " + std::to_string(process->pid) + ").");

            std::wstring error;
            const ULONGLONG started = GetTickCount64();
            if (!Export::ExportSelectedProcessMarkdownReport(reportContext, fileName, &error))
            {
                timings_.markdownReportMs = ElapsedMs(started);
                AddLog(LogLevel::High, "Markdown report export failed: " + WideToUtf8(error));
                MessageBoxW(hwnd_, error.c_str(), L"Export report failed", MB_ICONERROR | MB_OK);
                return;
            }
            timings_.markdownReportMs = ElapsedMs(started);

            AddLog(LogLevel::Info, "Markdown report exported: " + WideToUtf8(fileName) +
                " (" + std::to_string(timings_.markdownReportMs) + " ms).");
        }

        bool PromptForJsonPath(wchar_t (&fileName)[MAX_PATH]) const
        {
            OPENFILENAMEW dialog = {};
            dialog.lStructSize = sizeof(dialog);
            dialog.hwndOwner = hwnd_;
            dialog.lpstrFilter = L"JSON Files (*.json)\0*.json\0All Files (*.*)\0*.*\0";
            dialog.lpstrFile = fileName;
            dialog.nMaxFile = MAX_PATH;
            dialog.lpstrDefExt = L"json";
            dialog.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
            return GetSaveFileNameW(&dialog) != FALSE;
        }

        bool PromptForMarkdownPath(wchar_t (&fileName)[MAX_PATH]) const
        {
            OPENFILENAMEW dialog = {};
            dialog.lStructSize = sizeof(dialog);
            dialog.hwndOwner = hwnd_;
            dialog.lpstrFilter = L"Markdown Files (*.md)\0*.md\0All Files (*.*)\0*.*\0";
            dialog.lpstrFile = fileName;
            dialog.nMaxFile = MAX_PATH;
            dialog.lpstrDefExt = L"md";
            dialog.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
            return GetSaveFileNameW(&dialog) != FALSE;
        }

        HINSTANCE instance_ = nullptr;
        HWND hwnd_ = nullptr;
        HWND pickerOverlayHwnd_ = nullptr;
        ID3D11Device* device_ = nullptr;
        ID3D11DeviceContext* deviceContext_ = nullptr;
        IDXGISwapChain* swapChain_ = nullptr;
        ID3D11RenderTargetView* renderTargetView_ = nullptr;

        Core::ProcessSnapshot snapshot_;
        Core::FocusedGraph focusedGraph_;
        Core::ModuleCollectionResult selectedModules_;
        Core::NetworkCollectionResult networkSnapshot_;
        Core::TokenInfo selectedToken_;
        Core::RuntimeInfo selectedRuntime_;
        Core::MemoryCollectionResult selectedMemory_;
        Core::HandleCollectionResult selectedHandles_;
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
        std::uint64_t findingsCacheCreationTime_ = 0;
        int networkTableAutoFitGeneration_ = 0;
        std::size_t selectedModuleIndex_ = 0;
        bool selectedModulesLoaded_ = false;
        bool selectedTokenLoaded_ = false;
        bool selectedRuntimeLoaded_ = false;
        bool selectedMemoryLoaded_ = false;
        bool selectedHandlesLoaded_ = false;
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
        bool pickWindowActive_ = false;
        bool pickerOverlayClassRegistered_ = false;
        bool scrollSelectedProcessIntoView_ = false;
        bool aboutPopupRequested_ = false;
        bool resetLayoutPopupRequested_ = false;
        int aboutPopupOpenedFrame_ = -1;
        int resetLayoutPopupOpenedFrame_ = -1;
        ProcessFilterMode processFilterMode_ = ProcessFilterMode::All;
        TriageFilter triageFilter_ = TriageFilter::All;
        HandleFilter handleFilter_ = HandleFilter::All;
        InspectorTab inspectorTab_ = InspectorTab::Triage;
        std::array<char, 256> searchBuffer_ = {};
        std::array<char, 256> handleSearchBuffer_ = {};
        std::array<char, 256> memorySearchBuffer_ = {};
        std::wstring searchText_;
        std::wstring handleSearchText_;
        std::wstring memorySearchText_;
        std::wstring lastRefreshTime_ = L"(not refreshed)";
        std::wstring lastNetworkRefreshTime_ = L"(not refreshed)";
        std::size_t suspiciousCount_ = 0;
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
        std::vector<GraphLayoutNode> graphLayoutNodes_;
        std::vector<std::size_t> visibleHandleIndexes_;
        std::vector<std::size_t> visibleMemoryRegionIndexes_;
        std::vector<Core::Finding> selectedFindingsCache_;
        std::vector<LogEntry> logs_;
        std::unordered_map<std::wstring, CachedIconTexture> iconCache_;
        std::unordered_map<std::wstring, Core::FileIdentity> fileIdentityCache_;
        std::unordered_map<std::uint32_t, std::size_t> graphLayoutNodeIndexByPid_;
        ID3D11ShaderResourceView* fallbackIconTexture_ = nullptr;

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

#endif
