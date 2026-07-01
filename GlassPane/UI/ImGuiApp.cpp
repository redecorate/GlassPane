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
#include "../Core/ModuleCollector.h"
#include "../Core/NetworkCollector.h"
#include "../Core/ProcessCollector.h"
#include "../Core/ProcessTree.h"
#include "../Core/TimelineModel.h"
#include "../Core/TokenCollector.h"
#include "../Export/JsonExporter.h"

#include "imgui.h"
#include "backends/imgui_impl_dx11.h"
#include "backends/imgui_impl_win32.h"

#include <Windows.h>
#include <commdlg.h>
#include <d3d11.h>
#include <shellapi.h>

#include <algorithm>
#include <array>
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

        enum class LogLevel
        {
            Info,
            Warning,
            High
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
            Token,
            Handles
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
            return ImGuiWindowFlags_NoTitleBar |
                ImGuiWindowFlags_NoCollapse |
                ImGuiWindowFlags_NoResize |
                ImGuiWindowFlags_NoMove |
                ImGuiWindowFlags_NoSavedSettings;
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
            if (ImGui::BeginTable("field_row", 2, flags))
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

        void RefreshNetwork(bool logActivity = true)
        {
            networkSnapshot_ = Core::CollectNetworkConnectionSnapshot();
            networkLoaded_ = true;
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
                        " sockets cached.");
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

            Core::FileIdentity identity = Core::CollectFileIdentity(path);
            auto inserted = fileIdentityCache_.emplace(key, std::move(identity));
            const Core::FileIdentity& cached = inserted.first->second;
            if (!cached.errorMessage.empty())
            {
                AddLog(
                    LogLevel::Warning,
                    "File identity note for " + Shorten(WideToUtf8(path.empty() ? L"(empty path)" : path), 96) +
                        ": " + WideToUtf8(cached.errorMessage));
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
                selectedModulesLoaded_ && selectedModulesPid_ == process.pid
                    ? &selectedModules_
                    : nullptr;
            const Core::TokenInfo* token =
                selectedTokenLoaded_ && selectedTokenPid_ == process.pid
                    ? &selectedToken_
                    : nullptr;
            const Core::HandleCollectionResult* handles =
                selectedHandlesLoaded_ && selectedHandlesPid_ == process.pid
                    ? &selectedHandles_
                    : nullptr;

            Core::CorrelationContext context;
            context.process = &process;
            context.chain = &chain;
            context.modules = modules;
            context.networkConnections = &selectedNetworkConnections;
            context.fileIdentity = &fileIdentity;
            context.token = token;
            context.handles = handles;
            return Core::CorrelateFindings(context);
        }

        void InvalidateFindingsCache()
        {
            findingsCacheValid_ = false;
            findingsCachePid_ = InvalidPid;
            selectedFindingsCache_.clear();
        }

        const std::vector<Core::Finding>& FindingsForSelectedProcess(
            const Core::ProcessInfo& process,
            const Core::ChainAnalysisResult& chain,
            const Core::FileIdentity& fileIdentity)
        {
            if (findingsCacheValid_ && findingsCachePid_ == process.pid)
            {
                return selectedFindingsCache_;
            }

            selectedFindingsCache_ = BuildFindingsForSelectedProcess(process, chain, fileIdentity);
            findingsCachePid_ = process.pid;
            findingsCacheValid_ = true;

            AddLog(
                selectedFindingsCache_.empty() ? LogLevel::Info : LogLevel::Warning,
                "Triage findings recomputed for PID " + std::to_string(process.pid) +
                    ": " + std::to_string(selectedFindingsCache_.size()) + " finding(s).");
            return selectedFindingsCache_;
        }

        bool SelectedProcessHasHighTriageFinding()
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                return false;
            }

            const Core::ChainAnalysisResult chain = Core::AnalyzeChain(snapshot_, process->pid);
            const Core::FileIdentity& fileIdentity = CachedFileIdentity(process->executablePath);
            const std::vector<Core::Finding>& findings =
                FindingsForSelectedProcess(*process, chain, fileIdentity);
            return !findings.empty() &&
                Core::HighestFindingSeverity(findings) == Core::FindingSeverity::High;
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
            return BuildVisibleProcessRows().size();
        }

        std::vector<VisibleProcessRow> BuildVisibleProcessRows() const
        {
            const std::vector<Core::TreeRow> rows = Core::BuildTreeRows(snapshot_);
            std::vector<VisibleProcessRow> visibleRows;
            for (const Core::TreeRow& row : rows)
            {
                if (row.processIndex >= snapshot_.processes.size())
                {
                    continue;
                }

                const Core::ProcessInfo& process = snapshot_.processes[row.processIndex];
                if (ProcessMatchesFilters(process))
                {
                    visibleRows.push_back({ row.processIndex, row.depth, process.severity });
                }
            }
            return visibleRows;
        }

        void RefreshSnapshot()
        {
            AddLog(LogLevel::Info, "Refreshing process snapshot.");
            const std::uint32_t previousSelectedPid = selectedPid_;
            fileIdentityCache_.clear();
            InvalidateFindingsCache();
            snapshot_ = Core::CollectProcessSnapshot();
            selectedModules_ = {};
            selectedModulesLoaded_ = false;
            selectedModulesPid_ = InvalidPid;
            selectedModulePid_ = InvalidPid;
            selectedModuleIndex_ = 0;
            selectedToken_ = {};
            selectedTokenLoaded_ = false;
            selectedTokenPid_ = InvalidPid;
            selectedHandles_ = {};
            selectedHandlesLoaded_ = false;
            selectedHandlesPid_ = InvalidPid;
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
            focusedGraph_ = Core::BuildFocusedTree(snapshot_, selectedPid_, 2);
            InvalidateFindingsCache();
            AddLog(
                suspiciousCount_ == 0 ? LogLevel::Info : LogLevel::Warning,
                "Snapshot loaded: " + std::to_string(snapshot_.processes.size()) +
                    " processes, " + std::to_string(suspiciousCount_) + " suspicious.");
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
                selectedModules_ = {};
                selectedModulesLoaded_ = false;
                selectedModulesPid_ = InvalidPid;
                selectedModulePid_ = InvalidPid;
                selectedModuleIndex_ = 0;
                selectedToken_ = {};
                selectedTokenLoaded_ = false;
                selectedTokenPid_ = InvalidPid;
                selectedHandles_ = {};
                selectedHandlesLoaded_ = false;
                selectedHandlesPid_ = InvalidPid;
                InvalidateFindingsCache();
            }

            selectedPid_ = pid;
            if (changed)
            {
                RefreshToken(false);
            }
            if (focusGraph)
            {
                focusedGraph_ = Core::BuildFocusedTree(snapshot_, selectedPid_, 2);
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

        void LogFilterState()
        {
            AddLog(
                LogLevel::Info,
                "Filters changed: visible=" + std::to_string(CountVisibleProcesses()) +
                    ", search=\"" + WideToUtf8(searchText_) +
                    "\", active=" + ActiveChipLabel() + ".");
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
            processFilterMode_ = ProcessFilterMode::All;
            searchText_.clear();
            searchBuffer_.fill('\0');
            selectedPid_ = preservedSelectedPid;
            focusedGraph_ = Core::BuildFocusedTree(snapshot_, selectedPid_, 2);
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
            ConfigureDockspace();
            RenderToolbar();

            const ImGuiViewport* viewport = ImGui::GetMainViewport();
            constexpr float margin = 10.0f;
            constexpr float gap = 10.0f;
            constexpr float headerHeight = 108.0f;
            const float bottomHeight = std::clamp(viewport->WorkSize.y * 0.18f, 150.0f, 220.0f);
            const float bodyTop = headerHeight + gap;
            const float bodyHeight = std::max(280.0f, viewport->WorkSize.y - bodyTop - bottomHeight - (margin * 2.0f));
            const float leftWidth = std::clamp(viewport->WorkSize.x * 0.23f, 320.0f, 405.0f);
            const float rightWidth = std::clamp(viewport->WorkSize.x * 0.24f, 340.0f, 430.0f);
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

        void ConfigureDockspace()
        {
#ifdef IMGUI_HAS_DOCK
            const ImGuiViewport* viewport = ImGui::GetMainViewport();
            dockspaceId_ = ImGui::DockSpaceOverViewport();

            if (dockspaceBuilt_)
            {
                return;
            }

            dockspaceBuilt_ = true;
            leftDockId_ = dockspaceId_;
            centerDockId_ = dockspaceId_;
            rightDockId_ = dockspaceId_;
            bottomDockId_ = dockspaceId_;
            (void)viewport;
#endif
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
            ImGui::Begin(
                "GlassPane Header",
                nullptr,
                ImGuiWindowFlags_NoTitleBar |
                    ImGuiWindowFlags_NoCollapse |
                    ImGuiWindowFlags_NoResize |
                    ImGuiWindowFlags_NoMove |
                    ImGuiWindowFlags_NoScrollbar);

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

            if (ImGui::BeginTable("header_layout", 3, ImGuiTableFlags_SizingStretchProp))
            {
                ImGui::TableSetupColumn("brand", ImGuiTableColumnFlags_WidthFixed, brandWidth);
                ImGui::TableSetupColumn("controls", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("stats", ImGuiTableColumnFlags_WidthFixed, statsWidth);
                ImGui::TableNextRow();

                ImGui::TableSetColumnIndex(0);
                ImGui::SetCursorPosY(centeredRowY + 2.0f);
                const bool pushedTitleFont = PushFontIfAvailable(fonts_.title);
                ImGui::TextColored(AccentBlue(), "GlassPane");
                PopFontIfPushed(pushedTitleFont);
                ImGui::SameLine();
                ImGui::SetCursorPosY(centeredRowY + 5.0f);
                const bool pushedSubtitleFont = PushFontIfAvailable(fonts_.smallUi);
                ImGui::TextColored(MutedText(), "Windows process relationship analysis");
                PopFontIfPushed(pushedSubtitleFont);
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
                if (ImGui::InputTextWithHint("##search", "name, path, command line, PID, indicator", searchBuffer_.data(), searchBuffer_.size()))
                {
                    searchText_ = ToLower(Utf8ToWide(searchBuffer_.data()));
                    LogFilterState();
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
            ImGui::PushStyleColor(ImGuiCol_WindowBg, PanelBg());
            ImGui::Begin("Processes", nullptr, PanelWindowFlags());
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

            if (ChipButton("All", processFilterMode_ == ProcessFilterMode::All, AccentBlue()))
            {
                processFilterMode_ = ProcessFilterMode::All;
                LogFilterState();
            }
            SameLineIfChipFits("Suspicious");
            if (ChipButton("Suspicious", processFilterMode_ == ProcessFilterMode::Suspicious, SeverityColor(Core::Severity::High)))
            {
                processFilterMode_ = ProcessFilterMode::Suspicious;
                LogFilterState();
            }
            SameLineIfChipFits("Low");
            if (ChipButton("Low", processFilterMode_ == ProcessFilterMode::Low, SeverityColor(Core::Severity::Low)))
            {
                processFilterMode_ = ProcessFilterMode::Low;
                LogFilterState();
            }
            SameLineIfChipFits("Medium");
            if (ChipButton("Medium", processFilterMode_ == ProcessFilterMode::Medium, SeverityColor(Core::Severity::Medium)))
            {
                processFilterMode_ = ProcessFilterMode::Medium;
                LogFilterState();
            }
            SameLineIfChipFits("High");
            if (ChipButton("High", processFilterMode_ == ProcessFilterMode::High, SeverityColor(Core::Severity::High)))
            {
                processFilterMode_ = ProcessFilterMode::High;
                LogFilterState();
            }
            ImGui::TextDisabled("Active: %s", ActiveChipLabel().c_str());
            ImGui::Dummy(ImVec2(0.0f, 2.0f));

            const ImGuiTableFlags flags =
                ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Resizable |
                ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_SizingStretchProp;

            const std::vector<VisibleProcessRow> visibleRows = BuildVisibleProcessRows();
            const float footerHeight = ImGui::GetFrameHeightWithSpacing() + 12.0f;
            if (ImGui::BeginTable("process_table", 4, flags, ImVec2(0.0f, -footerHeight)))
            {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn("Process", ImGuiTableColumnFlags_WidthStretch, 0.0f, 0);
                ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 58.0f, 1);
                ImGui::TableSetupColumn("PPID", ImGuiTableColumnFlags_WidthFixed, 58.0f, 2);
                ImGui::TableSetupColumn("Severity", ImGuiTableColumnFlags_WidthFixed, 86.0f, 3);
                ImGui::TableHeadersRow();

                for (const VisibleProcessRow& row : visibleRows)
                {
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

                ImGui::EndTable();
            }
            if (visibleRows.empty())
            {
                ImGui::TextDisabled("No matching processes.");
            }
            ImGui::TextDisabled("%zu processes", snapshot_.processes.size());
            ImGui::SameLine();
            ImGui::TextDisabled("|");
            ImGui::SameLine();
            ImGui::TextColored(SeverityColor(Core::Severity::High), "%zu suspicious", suspiciousCount_);
            ImGui::SameLine();
            ImGui::TextDisabled("| %zu visible", visibleRows.size());
            ImGui::End();
            ImGui::PopStyleColor();
        }

        void RenderCenterPanel()
        {
            ImGui::PushStyleColor(ImGuiCol_WindowBg, PanelBg());
            ImGui::Begin("Graph / Timeline", nullptr, PanelWindowFlags());
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
            ImGui::End();
            ImGui::PopStyleColor();
        }

        void RenderRightPanel()
        {
            ImGui::PushStyleColor(ImGuiCol_WindowBg, PanelBg());
            ImGui::Begin("Inspector", nullptr, PanelWindowFlags());
            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(6.0f, 3.0f));
            ImGui::PushStyleVar(ImGuiStyleVar_ItemInnerSpacing, ImVec2(4.0f, 4.0f));
            ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(5.0f, 5.0f));

            if (ChipButton("Triage", inspectorTab_ == InspectorTab::Triage, AccentBlue()))
            {
                inspectorTab_ = InspectorTab::Triage;
            }
            SameLineIfChipFits("Details");
            if (ChipButton("Details", inspectorTab_ == InspectorTab::Details, AccentBlue()))
            {
                inspectorTab_ = InspectorTab::Details;
            }
            SameLineIfChipFits("Chain");
            if (ChipButton("Chain", inspectorTab_ == InspectorTab::Chain, AccentBlue()))
            {
                inspectorTab_ = InspectorTab::Chain;
            }
            SameLineIfChipFits("Modules");
            if (ChipButton("Modules", inspectorTab_ == InspectorTab::Modules, AccentBlue()))
            {
                inspectorTab_ = InspectorTab::Modules;
            }
            SameLineIfChipFits("Network");
            if (ChipButton("Network", inspectorTab_ == InspectorTab::Network, AccentBlue()))
            {
                inspectorTab_ = InspectorTab::Network;
            }
            SameLineIfChipFits("Token");
            if (ChipButton("Token", inspectorTab_ == InspectorTab::Token, AccentBlue()))
            {
                inspectorTab_ = InspectorTab::Token;
            }
            SameLineIfChipFits("Handles");
            if (ChipButton("Handles", inspectorTab_ == InspectorTab::Handles, AccentBlue()))
            {
                inspectorTab_ = InspectorTab::Handles;
            }
            ImGui::Separator();

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

            ImGui::PopStyleVar(3);
            ImGui::End();
            ImGui::PopStyleColor();
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
            EndInspectorCard();

            ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(6.0f, 6.0f));
            if (ChipButton("All", triageFilter_ == TriageFilter::All, AccentBlue()))
            {
                triageFilter_ = TriageFilter::All;
            }
            SameLineIfChipFits("Info");
            if (ChipButton("Info", triageFilter_ == TriageFilter::Info, FindingSeverityColor(Core::FindingSeverity::Info)))
            {
                triageFilter_ = TriageFilter::Info;
            }
            SameLineIfChipFits("Low");
            if (ChipButton("Low", triageFilter_ == TriageFilter::Low, FindingSeverityColor(Core::FindingSeverity::Low)))
            {
                triageFilter_ = TriageFilter::Low;
            }
            SameLineIfChipFits("Medium");
            if (ChipButton("Medium", triageFilter_ == TriageFilter::Medium, FindingSeverityColor(Core::FindingSeverity::Medium)))
            {
                triageFilter_ = TriageFilter::Medium;
            }
            SameLineIfChipFits("High");
            if (ChipButton("High", triageFilter_ == TriageFilter::High, FindingSeverityColor(Core::FindingSeverity::High)))
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

            const Core::ProcessInfo* parent = Core::FindProcessByPid(snapshot_, process->parentPid);
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
            if (ImGui::SmallButton("Copy Chain"))
            {
                CopyTextToClipboard(chain.formattedParentChain);
                AddLog(LogLevel::Info, "Copied parent chain to clipboard.");
            }
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

            if (!selectedModulesLoaded_ || selectedModulesPid_ != selectedPid_)
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

            const ImGuiTableFlags flags =
                ImGuiTableFlags_BordersInnerV |
                ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Resizable |
                ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_SizingStretchProp;
            if (ImGui::BeginTable("modules_table", 4, flags))
            {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn("Module", ImGuiTableColumnFlags_WidthFixed, 155.0f);
                ImGui::TableSetupColumn("Base", ImGuiTableColumnFlags_WidthFixed, 112.0f);
                ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 76.0f);
                ImGui::TableSetupColumn("Path", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableHeadersRow();

                for (std::size_t moduleIndex = 0; moduleIndex < selectedModules_.modules.size(); ++moduleIndex)
                {
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
                ImGui::EndTable();
            }

            if (selectedModules_.modules.empty())
            {
                WrappedTextDisabled("No modules returned for the selected process.");
            }
            else if (selectedModulePid_ == selectedPid_ && selectedModuleIndex_ < selectedModules_.modules.size())
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

            if (!selectedTokenLoaded_ || selectedTokenPid_ != selectedPid_)
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
                "token_summary_grid",
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
                ImGui::Checkbox("Show enabled only", &tokenShowEnabledOnly_);
                ImGui::Spacing();

                const ImGuiTableFlags flags =
                    ImGuiTableFlags_BordersInnerV |
                    ImGuiTableFlags_RowBg |
                    ImGuiTableFlags_SizingStretchProp |
                    ImGuiTableFlags_NoSavedSettings;
                if (ImGui::BeginTable("token_privileges_table", 3, flags))
                {
                    ImGui::TableSetupColumn("Privilege", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize, 172.0f);
                    ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize, 104.0f);
                    ImGui::TableSetupColumn("Description", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableHeadersRow();

                    std::size_t visiblePrivilegeCount = 0;
                    for (const Core::PrivilegeInfo& privilege : token.privileges)
                    {
                        if (tokenShowEnabledOnly_ && (!privilege.enabled || privilege.removed))
                        {
                            continue;
                        }

                        ++visiblePrivilegeCount;
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
                        WrappedTextDisabled(privilege.displayName.empty() ? L"(description unavailable)" : privilege.displayName);
                    }
                    ImGui::EndTable();

                    if (visiblePrivilegeCount == 0)
                    {
                        WrappedTextDisabled("No privileges match the current filter.");
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

            if (!selectedHandlesLoaded_ || selectedHandlesPid_ != selectedPid_)
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
                "##handle_search",
                "Search handle, type, target, access, indicator",
                handleSearchBuffer_.data(),
                handleSearchBuffer_.size()))
            {
                handleSearchText_ = ToLower(Utf8ToWide(handleSearchBuffer_.data()));
            }

            if (ChipButton("All", handleFilter_ == HandleFilter::All, AccentBlue()))
            {
                handleFilter_ = HandleFilter::All;
            }
            SameLineIfChipFits("Sensitive");
            if (ChipButton("Sensitive", handleFilter_ == HandleFilter::Sensitive, SeverityColor(Core::Severity::Medium)))
            {
                handleFilter_ = HandleFilter::Sensitive;
            }
            SameLineIfChipFits("Process");
            if (ChipButton("Process", handleFilter_ == HandleFilter::Process, AccentBlue()))
            {
                handleFilter_ = HandleFilter::Process;
            }
            SameLineIfChipFits("Token");
            if (ChipButton("Token", handleFilter_ == HandleFilter::Token, AccentBlue()))
            {
                handleFilter_ = HandleFilter::Token;
            }
            SameLineIfChipFits("File");
            if (ChipButton("File", handleFilter_ == HandleFilter::File, AccentBlue()))
            {
                handleFilter_ = HandleFilter::File;
            }
            SameLineIfChipFits("Registry");
            if (ChipButton("Registry", handleFilter_ == HandleFilter::Registry, AccentBlue()))
            {
                handleFilter_ = HandleFilter::Registry;
            }
            SameLineIfChipFits("Named Objects");
            if (ChipButton("Named Objects", handleFilter_ == HandleFilter::NamedObjects, AccentBlue()))
            {
                handleFilter_ = HandleFilter::NamedObjects;
            }
            SameLineIfChipFits("With Indicators");
            if (ChipButton("With Indicators", handleFilter_ == HandleFilter::WithIndicators, SeverityColor(Core::Severity::Low)))
            {
                handleFilter_ = HandleFilter::WithIndicators;
            }
            EndInspectorCard();

            std::size_t withIndicatorsCount = 0;
            std::size_t nameStatusCount = 0;
            std::vector<const Core::HandleInfo*> visibleHandles;
            visibleHandles.reserve(selectedHandles_.handles.size());
            for (const Core::HandleInfo& handle : selectedHandles_.handles)
            {
                if (!handle.indicators.empty())
                {
                    ++withIndicatorsCount;
                }
                if (!HandleStatusText(handle).empty())
                {
                    ++nameStatusCount;
                }
                if (HandleMatchesFilter(handle, handleFilter_) &&
                    HandleMatchesSearch(handle, handleSearchText_))
                {
                    visibleHandles.push_back(&handle);
                }
            }

            BeginInspectorCard("handles_summary", "Handle Summary", fonts_.bold);
            LabelValue("Total Loaded", std::to_wstring(selectedHandles_.handles.size()));
            LabelValue("Visible", std::to_wstring(visibleHandles.size()));
            LabelValue("Sensitive", std::to_wstring(selectedHandles_.sensitiveCount));
            LabelValue("With Indicators", std::to_wstring(withIndicatorsCount));
            LabelValue("Name Unavail/Skipped", std::to_wstring(nameStatusCount));
            ImGui::TextDisabled("Status");
            WrappedTextDisabled(selectedHandles_.statusMessage.empty() ? L"(no status)" : selectedHandles_.statusMessage);
            EndInspectorCard();

            if (visibleHandles.empty())
            {
                BeginInspectorCard("handles_filter_empty", "Handles", fonts_.bold);
                WrappedTextDisabled("No handles match the current filters.");
                EndInspectorCard();
                return;
            }

            const ImGuiTableFlags flags =
                ImGuiTableFlags_BordersInnerV |
                ImGuiTableFlags_RowBg |
                ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_SizingStretchProp |
                ImGuiTableFlags_NoSavedSettings;
            if (ImGui::BeginTable("handles_table", 5, flags))
            {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn("Handle", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize, 76.0f);
                ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize, 88.0f);
                ImGui::TableSetupColumn("Target / Name", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Access", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize, 92.0f);
                ImGui::TableSetupColumn("Indicators", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize, 118.0f);
                ImGui::TableHeadersRow();

                for (std::size_t handleIndex = 0; handleIndex < visibleHandles.size(); ++handleIndex)
                {
                    const Core::HandleInfo& handle = *visibleHandles[handleIndex];
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

            const ImGuiTableFlags flags =
                ImGuiTableFlags_BordersInnerV |
                ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Resizable |
                ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_SizingStretchProp;
            if (ImGui::BeginTable("network_table", 5, flags))
            {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn("Protocol", ImGuiTableColumnFlags_WidthFixed, 76.0f);
                ImGui::TableSetupColumn("Local", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Remote", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 96.0f);
                ImGui::TableSetupColumn("Type/Scope", ImGuiTableColumnFlags_WidthFixed, 150.0f);
                ImGui::TableHeadersRow();

                for (const Core::NetworkConnection* connection : selectedConnections)
                {
                    if (connection == nullptr)
                    {
                        continue;
                    }

                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    TextWide(connection->protocol);

                    const bool pushedEndpointFont = PushFontIfAvailable(fonts_.monospace);
                    ImGui::TableSetColumnIndex(1);
                    WrappedTextWide(NetworkEndpoint(*connection, false));
                    ImGui::TableSetColumnIndex(2);
                    WrappedTextWide(NetworkEndpoint(*connection, true));
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

                ImGui::EndTable();
            }

            if (selectedConnections.empty())
            {
                ImGui::TextDisabled("No network connections for this process.");
            }
        }

        void RenderGraphView()
        {
            const bool pushedHeadingFont = PushFontIfAvailable(fonts_.bold);
            ImGui::TextColored(AccentBlue(), "Process Graph");
            PopFontIfPushed(pushedHeadingFont);
            ImGui::SameLine();
            ImGui::TextColored(MutedText(), "focused process relationships");

            const float toolbarWidth =
                ImGui::CalcTextSize("Focus").x + ImGui::CalcTextSize("Fit").x + ImGui::CalcTextSize("Refresh").x + 86.0f;
            const float toolbarX = ImGui::GetCursorPosX() + std::max(0.0f, ImGui::GetContentRegionAvail().x - toolbarWidth);
            ImGui::SameLine(toolbarX);
            if (ImGui::Button("Focus"))
            {
                focusedGraph_ = Core::BuildFocusedTree(snapshot_, selectedPid_, 2);
                AddLog(LogLevel::Info, "Graph focused on selected process.");
            }
            ImGui::SameLine();
            if (ImGui::Button("Fit"))
            {
                AddLog(LogLevel::Info, "Graph fit requested. Current layout auto-fits visible nodes.");
            }
            ImGui::SameLine();
            if (ImGui::Button("Refresh"))
            {
                focusedGraph_ = Core::BuildFocusedTree(snapshot_, selectedPid_, 2);
                AddLog(LogLevel::Info, "Graph refreshed.");
            }
            const Core::ProcessInfo* selectedGraphProcess = Core::FindProcessByPid(snapshot_, selectedPid_);
            const bool selectedHiddenByFilters = selectedGraphProcess != nullptr && !ProcessMatchesFilters(*selectedGraphProcess);

            ImGui::Spacing();
            const ImVec2 canvasOrigin = ImGui::GetCursorScreenPos();
            const ImVec2 available = ImGui::GetContentRegionAvail();
            const ImVec2 canvasSize(std::max(available.x, 320.0f), std::max(available.y, 260.0f));
            ImDrawList* drawList = ImGui::GetWindowDrawList();
            const bool selectedHasHighTriageFinding = SelectedProcessHasHighTriageFinding();
            drawList->AddRectFilledMultiColor(
                canvasOrigin,
                ImVec2(canvasOrigin.x + canvasSize.x, canvasOrigin.y + canvasSize.y),
                IM_COL32(6, 10, 16, 255),
                IM_COL32(9, 15, 23, 255),
                IM_COL32(12, 18, 27, 255),
                ColorU32(GraphCanvasBg()));
            drawList->AddRectFilled(
                canvasOrigin,
                ImVec2(canvasOrigin.x + canvasSize.x, canvasOrigin.y + canvasSize.y),
                ColorU32(ImVec4(GraphCanvasBg().x, GraphCanvasBg().y, GraphCanvasBg().z, 0.58f)),
                8.0f);
            drawList->AddRect(
                canvasOrigin,
                ImVec2(canvasOrigin.x + canvasSize.x, canvasOrigin.y + canvasSize.y),
                ColorU32(PanelBorder()),
                8.0f,
                0,
                1.2f);
            for (float x = canvasOrigin.x + 40.0f; x < canvasOrigin.x + canvasSize.x; x += 80.0f)
            {
                drawList->AddLine(
                    ImVec2(x, canvasOrigin.y + 12.0f),
                    ImVec2(x, canvasOrigin.y + canvasSize.y - 12.0f),
                    ColorU32(GraphGridLine()),
                    1.0f);
            }
            for (float y = canvasOrigin.y + 40.0f; y < canvasOrigin.y + canvasSize.y; y += 80.0f)
            {
                drawList->AddLine(
                    ImVec2(canvasOrigin.x + 12.0f, y),
                    ImVec2(canvasOrigin.x + canvasSize.x - 12.0f, y),
                    ColorU32(GraphGridLine()),
                    1.0f);
            }

            ImGui::InvisibleButton("graph_canvas", canvasSize);

            if (focusedGraph_.nodes.empty())
            {
                drawList->AddText(
                    ImVec2(canvasOrigin.x + 16.0f, canvasOrigin.y + 16.0f),
                    IM_COL32(170, 180, 192, 255),
                    "No focused graph available.");
                return;
            }

            std::unordered_map<std::uint32_t, ImVec2> positions;
            std::unordered_map<std::uint32_t, std::size_t> nodeIndexByPid;
            std::unordered_map<std::size_t, std::vector<std::size_t>> levels;
            std::size_t maxDepth = 0;

            for (std::size_t nodeIndex = 0; nodeIndex < focusedGraph_.nodes.size(); ++nodeIndex)
            {
                const Core::FocusedGraphNode& node = focusedGraph_.nodes[nodeIndex];
                levels[node.depth].push_back(nodeIndex);
                nodeIndexByPid[node.pid] = nodeIndex;
                maxDepth = std::max(maxDepth, node.depth);
            }

            const bool singleNodeGraph = focusedGraph_.nodes.size() == 1;
            const bool smallGraph = focusedGraph_.nodes.size() >= 2 && focusedGraph_.nodes.size() <= 5;
            const ImVec2 nodeSize = singleNodeGraph
                ? ImVec2(326.0f, 122.0f)
                : (smallGraph ? ImVec2(304.0f, 110.0f) : ImVec2(286.0f, 104.0f));
            const float topRowY = canvasOrigin.y + nodeSize.y * 0.5f + 42.0f;
            const float bottomRowY = canvasOrigin.y + canvasSize.y - nodeSize.y * 0.5f - 36.0f;
            const float levelHeight = maxDepth == 0
                ? 0.0f
                : std::max(86.0f, (bottomRowY - topRowY) / static_cast<float>(maxDepth));

            for (auto& [depth, nodeIndexes] : levels)
            {
                std::sort(nodeIndexes.begin(), nodeIndexes.end(), [this](std::size_t leftIndex, std::size_t rightIndex) {
                    if (leftIndex >= focusedGraph_.nodes.size() || rightIndex >= focusedGraph_.nodes.size())
                    {
                        return leftIndex < rightIndex;
                    }
                    return focusedGraph_.nodes[leftIndex].pid < focusedGraph_.nodes[rightIndex].pid;
                });

                float rowY = maxDepth == 0
                    ? canvasOrigin.y + canvasSize.y * 0.5f
                    : topRowY + static_cast<float>(depth) * levelHeight;
                if (singleNodeGraph)
                {
                    const float minY = canvasOrigin.y + nodeSize.y * 0.5f + 54.0f;
                    const float maxY = canvasOrigin.y + canvasSize.y - nodeSize.y * 0.5f - 112.0f;
                    rowY = maxY >= minY
                        ? std::clamp(canvasOrigin.y + canvasSize.y * 0.43f, minY, maxY)
                        : canvasOrigin.y + canvasSize.y * 0.5f;
                }

                const float horizontalMarginScale = smallGraph ? 0.52f : 0.58f;
                const float rowLeft = canvasOrigin.x + nodeSize.x * horizontalMarginScale;
                const float rowRight = canvasOrigin.x + canvasSize.x - nodeSize.x * horizontalMarginScale;
                for (std::size_t index = 0; index < nodeIndexes.size(); ++index)
                {
                    const std::size_t nodeIndex = nodeIndexes[index];
                    if (nodeIndex >= focusedGraph_.nodes.size())
                    {
                        continue;
                    }

                    const Core::FocusedGraphNode& node = focusedGraph_.nodes[nodeIndex];
                    const float x = nodeIndexes.size() <= 1
                        ? canvasOrigin.x + canvasSize.x * 0.5f
                        : rowLeft + ((rowRight - rowLeft) * static_cast<float>(index) /
                            static_cast<float>(nodeIndexes.size() - 1));
                    positions[node.pid] = ImVec2(
                        std::clamp(x, canvasOrigin.x + nodeSize.x * 0.6f, canvasOrigin.x + canvasSize.x - nodeSize.x * 0.6f),
                        rowY);
                }
            }

            for (const Core::FocusedGraphEdge& edge : focusedGraph_.edges)
            {
                if (nodeIndexByPid.find(edge.parentPid) == nodeIndexByPid.end() ||
                    nodeIndexByPid.find(edge.childPid) == nodeIndexByPid.end())
                {
                    continue;
                }

                const auto parent = positions.find(edge.parentPid);
                const auto child = positions.find(edge.childPid);
                if (parent == positions.end() || child == positions.end())
                {
                    continue;
                }

                const ImU32 color = edge.inSelectedChain
                    ? ColorU32(ImVec4(AccentBlue().x, AccentBlue().y, AccentBlue().z, 0.92f))
                    : IM_COL32(92, 106, 128, 205);
                const ImVec2 start(parent->second.x, parent->second.y + nodeSize.y * 0.5f);
                const ImVec2 end(child->second.x, child->second.y - nodeSize.y * 0.5f);
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
                    edge.inSelectedChain ? 4.6f : 2.6f);
            }

            std::uint32_t pendingSelectedPid = InvalidPid;
            ImVec2 singleNodeMin;
            ImVec2 singleNodeMax;
            bool hasSingleNodeBounds = false;
            for (std::size_t nodeIndex = 0; nodeIndex < focusedGraph_.nodes.size(); ++nodeIndex)
            {
                const Core::FocusedGraphNode& node = focusedGraph_.nodes[nodeIndex];
                const auto position = positions.find(node.pid);
                if (position == positions.end())
                {
                    continue;
                }

                const ImVec2 min(position->second.x - nodeSize.x * 0.5f, position->second.y - nodeSize.y * 0.5f);
                const ImVec2 max(position->second.x + nodeSize.x * 0.5f, position->second.y + nodeSize.y * 0.5f);
                if (singleNodeGraph)
                {
                    singleNodeMin = min;
                    singleNodeMax = max;
                    hasSingleNodeBounds = true;
                }
                const Core::Severity displaySeverity =
                    node.pid == selectedPid_ && selectedHasHighTriageFinding
                        ? Core::Severity::High
                        : node.severity;
                const bool hovered = ImGui::IsMouseHoveringRect(min, max);
                if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
                {
                    pendingSelectedPid = node.pid;
                }

                ImU32 fill = node.focus ? ColorU32(ImVec4(0.090f, 0.165f, 0.245f, 1.0f)) : ColorU32(CardBg());
                if (Core::SeverityRank(displaySeverity) >= Core::SeverityRank(Core::Severity::High))
                {
                    fill = node.focus ? IM_COL32(58, 38, 46, 255) : IM_COL32(46, 22, 28, 255);
                }
                else if (Core::SeverityRank(displaySeverity) >= Core::SeverityRank(Core::Severity::Low))
                {
                    fill = node.focus ? IM_COL32(58, 49, 36, 255) : IM_COL32(42, 33, 25, 255);
                }
                const ImU32 border = Core::SeverityRank(displaySeverity) >= Core::SeverityRank(Core::Severity::Low)
                    ? SeverityU32(displaySeverity)
                    : (node.inSelectedChain ? ColorU32(AccentBlue()) : ColorU32(PanelBorder()));
                if (node.focus)
                {
                    drawList->AddRect(
                        ImVec2(min.x - 4.0f, min.y - 4.0f),
                        ImVec2(max.x + 4.0f, max.y + 4.0f),
                        ColorU32(ImVec4(AccentBlue().x, AccentBlue().y, AccentBlue().z, 0.68f)),
                        9.0f,
                        0,
                        2.0f);
                }
                drawList->AddRectFilled(
                    ImVec2(min.x + 3.0f, min.y + 4.0f),
                    ImVec2(max.x + 3.0f, max.y + 4.0f),
                    IM_COL32(0, 0, 0, 72),
                    9.0f);
                drawList->AddRectFilled(min, max, fill, 9.0f);
                drawList->AddRect(min, max, border, 9.0f, 0, node.focus ? 3.2f : 1.8f);
                drawList->AddRectFilled(
                    ImVec2(min.x, min.y),
                    ImVec2(min.x + 5.0f, max.y),
                    border,
                    9.0f,
                    ImDrawFlags_RoundCornersLeft);

                const std::string title = Shorten(DisplayName(node.name), 30);
                const std::string pidText = "PID " + std::to_string(node.pid);
                drawList->AddText(ImVec2(min.x + 18.0f, min.y + 16.0f), ColorU32(PrimaryText()), title.c_str());
                drawList->AddText(ImVec2(min.x + 18.0f, min.y + 48.0f), ColorU32(MutedText()), pidText.c_str());
                if (Core::SeverityRank(displaySeverity) >= Core::SeverityRank(Core::Severity::Low))
                {
                    const std::string severityLabel = WideToUtf8(Core::SeverityToString(displaySeverity));
                    const ImVec2 badgeTextSize = ImGui::CalcTextSize(severityLabel.c_str());
                    const ImVec2 badgeMin(max.x - badgeTextSize.x - 30.0f, min.y + 15.0f);
                    const ImVec2 badgeMax(max.x - 14.0f, min.y + 39.0f);
                    drawList->AddRectFilled(badgeMin, badgeMax, IM_COL32(20, 22, 26, 180), 4.0f);
                    drawList->AddRect(badgeMin, badgeMax, SeverityU32(displaySeverity), 4.0f, 0, 1.0f);
                    drawList->AddText(
                        ImVec2(badgeMin.x + 8.0f, badgeMin.y + 4.0f),
                        SeverityU32(displaySeverity),
                        severityLabel.c_str());
                }
                else if (node.inSelectedChain)
                {
                    drawList->AddText(ImVec2(min.x + 18.0f, min.y + 76.0f), ColorU32(AccentBlue()), "chain");
                }
                if (hovered)
                {
                    drawList->AddRect(min, max, ColorU32(ImVec4(AccentBlue().x, AccentBlue().y, AccentBlue().z, 0.82f)), 9.0f, 0, 1.5f);
                }
            }

            if (hasSingleNodeBounds)
            {
                const Core::ProcessInfo* summaryProcess = selectedGraphProcess != nullptr
                    ? selectedGraphProcess
                    : Core::FindProcessByPid(snapshot_, focusedGraph_.nodes.front().pid);

                const char* relationshipMessage = "No visible parent or child relationships for this process.";
                const ImVec2 messageSize = ImGui::CalcTextSize(relationshipMessage);
                const float messageY = std::min(
                    singleNodeMax.y + 22.0f,
                    canvasOrigin.y + canvasSize.y - 72.0f);
                drawList->AddText(
                    ImVec2(canvasOrigin.x + (canvasSize.x - messageSize.x) * 0.5f, messageY),
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
                    if (selectedModulesLoaded_ && selectedModulesPid_ == summaryProcess->pid)
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

                    float badgeX = canvasOrigin.x + (canvasSize.x - badgeRowWidth) * 0.5f;
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

            ImGui::SetCursorScreenPos(ImVec2(canvasOrigin.x, canvasOrigin.y + canvasSize.y));

            if (pendingSelectedPid != InvalidPid)
            {
                SelectGraphNode(pendingSelectedPid);
            }
        }

        void RenderTimelineView()
        {
            ImGui::TextUnformatted("Filter:");
            ImGui::SameLine();
            int filterValue = static_cast<int>(timelineFilter_);
            if (ImGui::RadioButton("All", filterValue == static_cast<int>(Core::TimelineFilter::All)))
            {
                timelineFilter_ = Core::TimelineFilter::All;
            }
            ImGui::SameLine();
            if (ImGui::RadioButton("Suspicious only", filterValue == static_cast<int>(Core::TimelineFilter::SuspiciousOnly)))
            {
                timelineFilter_ = Core::TimelineFilter::SuspiciousOnly;
            }
            ImGui::SameLine();
            if (ImGui::RadioButton("High severity only", filterValue == static_cast<int>(Core::TimelineFilter::HighSeverityOnly)))
            {
                timelineFilter_ = Core::TimelineFilter::HighSeverityOnly;
            }

            const std::vector<Core::TimelineRow> rows = Core::BuildTimelineRows(snapshot_, timelineFilter_);
            std::size_t visibleTimelineRows = 0;
            const ImGuiTableFlags flags =
                ImGuiTableFlags_BordersInnerV |
                ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Resizable |
                ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_SizingStretchProp;
            if (ImGui::BeginTable("timeline_table", 6, flags))
            {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn("Timestamp", ImGuiTableColumnFlags_WidthFixed, 150.0f);
                ImGui::TableSetupColumn("Process", ImGuiTableColumnFlags_WidthFixed, 190.0f);
                ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 70.0f);
                ImGui::TableSetupColumn("Parent", ImGuiTableColumnFlags_WidthFixed, 210.0f);
                ImGui::TableSetupColumn("Severity", ImGuiTableColumnFlags_WidthFixed, 90.0f);
                ImGui::TableSetupColumn("Indicator", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableHeadersRow();

                for (const Core::TimelineRow& row : rows)
                {
                    const Core::ProcessInfo* timelineProcess = Core::FindProcessByPid(snapshot_, row.pid);
                    if (timelineProcess == nullptr || !ProcessMatchesFilters(*timelineProcess))
                    {
                        continue;
                    }
                    ++visibleTimelineRows;

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
                ImGui::EndTable();
            }
            if (visibleTimelineRows == 0)
            {
                ImGui::TextDisabled("No matching timeline rows.");
            }
        }

        void RenderBottomPanel()
        {
            ImGui::PushStyleColor(ImGuiCol_WindowBg, PanelBg());
            ImGui::Begin("Indicators / Logs", nullptr, PanelWindowFlags());
            if (ImGui::BeginTabBar("bottom_tabs"))
            {
                if (ImGui::BeginTabItem("Logs"))
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
                    ImGui::EndTabItem();
                }
                if (ImGui::BeginTabItem("Indicators"))
                {
                    RenderSelectedIndicators();
                    ImGui::EndTabItem();
                }
                ImGui::EndTabBar();
            }
            ImGui::End();
            ImGui::PopStyleColor();
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

            if (selectedModulesLoaded_ && selectedModulesPid_ == selectedPid_ && !selectedModules_.indicators.empty())
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
            const std::wstring query = ToLower(searchText_);
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

            const Core::ProcessInfo* parent = Core::FindProcessByPid(snapshot_, process.parentPid);
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
                return;
            }

            selectedModules_ = Core::CollectProcessModules(*process);
            selectedModulesLoaded_ = true;
            selectedModulesPid_ = selectedPid_;
            selectedModulePid_ = InvalidPid;
            selectedModuleIndex_ = 0;
            InvalidateFindingsCache();
            AddLog(
                selectedModules_.success ? LogLevel::Info : LogLevel::Warning,
                "Module refresh for PID " + std::to_string(process->pid) + ": " + WideToUtf8(selectedModules_.statusMessage));
        }

        void RefreshToken(bool logActivity = true)
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                selectedToken_ = {};
                selectedTokenLoaded_ = false;
                selectedTokenPid_ = InvalidPid;
                InvalidateFindingsCache();
                if (logActivity)
                {
                    AddLog(LogLevel::Warning, "No selected process for token refresh.");
                }
                return;
            }

            selectedToken_ = Core::CollectProcessTokenInfo(*process);
            selectedTokenLoaded_ = true;
            selectedTokenPid_ = selectedPid_;
            InvalidateFindingsCache();

            if (logActivity)
            {
                AddLog(
                    selectedToken_.success ? LogLevel::Info : LogLevel::Warning,
                    "Token refresh for PID " + std::to_string(process->pid) + ": " +
                        (selectedToken_.success ? "loaded token metadata." : WideToUtf8(selectedToken_.errorMessage)));
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
                InvalidateFindingsCache();
                if (logActivity)
                {
                    AddLog(LogLevel::Warning, "No selected process for handle refresh.");
                }
                return;
            }

            selectedHandles_ = Core::CollectProcessHandles(*process, &snapshot_);
            selectedHandlesLoaded_ = true;
            selectedHandlesPid_ = selectedPid_;
            InvalidateFindingsCache();

            if (logActivity)
            {
                AddLog(
                    selectedHandles_.success ? LogLevel::Info : LogLevel::Warning,
                    "Handle refresh for PID " + std::to_string(process->pid) + ": " +
                        std::to_string(selectedHandles_.handles.size()) +
                        " handle(s), " +
                        std::to_string(selectedHandles_.sensitiveCount) +
                        " sensitive.");
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
            if (!Export::ExportSnapshotToJson(snapshot_, fileName, &error))
            {
                AddLog(LogLevel::High, "Snapshot export failed: " + WideToUtf8(error));
                MessageBoxW(hwnd_, error.c_str(), L"Export failed", MB_ICONERROR | MB_OK);
                return;
            }

            AddLog(LogLevel::Info, "Snapshot exported: " + WideToUtf8(fileName));
        }

        void ExportSelectedDetails()
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                AddLog(LogLevel::Warning, "No selected process to export.");
                return;
            }

            if (!selectedModulesLoaded_ || selectedModulesPid_ != selectedPid_)
            {
                selectedModules_ = Core::CollectProcessModules(*process);
                selectedModulesLoaded_ = true;
                selectedModulesPid_ = selectedPid_;
                InvalidateFindingsCache();
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
            if (!Export::ExportSelectedProcessDetailsToJson(
                snapshot_,
                selectedPid_,
                selectedModules_,
                selectedNetworkConnections,
                selectedHandlesLoaded_ && selectedHandlesPid_ == selectedPid_ ? &selectedHandles_ : nullptr,
                fileName,
                &error))
            {
                AddLog(LogLevel::High, "Selected process export failed: " + WideToUtf8(error));
                MessageBoxW(hwnd_, error.c_str(), L"Export selected failed", MB_ICONERROR | MB_OK);
                return;
            }

            AddLog(LogLevel::Info, "Selected process exported: " + WideToUtf8(fileName));
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
        Core::HandleCollectionResult selectedHandles_;
        Core::TimelineFilter timelineFilter_ = Core::TimelineFilter::All;
        FontSet fonts_;
        std::uint32_t selectedPid_ = InvalidPid;
        std::uint32_t selectedModulesPid_ = InvalidPid;
        std::uint32_t selectedModulePid_ = InvalidPid;
        std::uint32_t selectedTokenPid_ = InvalidPid;
        std::uint32_t selectedHandlesPid_ = InvalidPid;
        std::size_t selectedModuleIndex_ = 0;
        bool selectedModulesLoaded_ = false;
        bool selectedTokenLoaded_ = false;
        bool selectedHandlesLoaded_ = false;
        bool tokenShowEnabledOnly_ = false;
        bool networkLoaded_ = false;
        bool pickWindowActive_ = false;
        bool pickerOverlayClassRegistered_ = false;
        bool scrollSelectedProcessIntoView_ = false;
        ProcessFilterMode processFilterMode_ = ProcessFilterMode::All;
        TriageFilter triageFilter_ = TriageFilter::All;
        HandleFilter handleFilter_ = HandleFilter::All;
        InspectorTab inspectorTab_ = InspectorTab::Triage;
        std::array<char, 256> searchBuffer_ = {};
        std::array<char, 256> handleSearchBuffer_ = {};
        std::wstring searchText_;
        std::wstring handleSearchText_;
        std::wstring lastRefreshTime_ = L"(not refreshed)";
        std::wstring lastNetworkRefreshTime_ = L"(not refreshed)";
        std::size_t suspiciousCount_ = 0;
        bool findingsCacheValid_ = false;
        std::uint32_t findingsCachePid_ = InvalidPid;
        std::vector<Core::Finding> selectedFindingsCache_;
        std::vector<LogEntry> logs_;
        std::unordered_map<std::wstring, CachedIconTexture> iconCache_;
        std::unordered_map<std::wstring, Core::FileIdentity> fileIdentityCache_;
        ID3D11ShaderResourceView* fallbackIconTexture_ = nullptr;

        ImGuiID dockspaceId_ = 0;
        ImGuiID leftDockId_ = 0;
        ImGuiID centerDockId_ = 0;
        ImGuiID rightDockId_ = 0;
        ImGuiID bottomDockId_ = 0;
        bool dockspaceBuilt_ = false;
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
