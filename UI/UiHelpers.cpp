#include "UiHelpers.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <cwctype>
#include <cstring>
#include <exception>
#include <iomanip>
#include <sstream>

namespace GlassPane::UI
{
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

        void RenderWrappedTooltip(const std::string& text, float wrapWidth)
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

        void RenderWrappedTooltip(const std::wstring& text, float wrapWidth)
        {
            RenderWrappedTooltip(WideToUtf8(text), wrapWidth);
        }

        void ClippedTextWithTooltip(const std::wstring& value, float tooltipWrapWidth)
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
}
