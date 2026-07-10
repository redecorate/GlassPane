#pragma once

#include "../Core/ProcessInfo.h"
#include "imgui.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace GlassPane::UI
{
    std::string WideToUtf8(const std::wstring& value);
    std::wstring Utf8ToWide(const char* value);
    std::wstring ToLower(std::wstring value);
    bool FieldContainsQuery(const std::wstring& field, const std::wstring& loweredQuery);
    std::string DisplayName(const std::wstring& value);
    std::string WrapForCurrentWidth(const std::string& text);
    std::string Shorten(const std::string& value, std::size_t maxLength);
    std::string EllipsizeToWidth(const std::string& value, float maxWidth);
    std::wstring OptionalSessionId(const std::optional<std::uint32_t>& sessionId);
    std::wstring LocalTimestamp();
    std::wstring FileTimestamp();
    std::wstring SanitizedFileNamePart(std::wstring value);
    std::wstring FileSizeText(std::uint64_t bytes);

    ImVec4 SeverityColor(Core::Severity severity);
    ImU32 SeverityU32(Core::Severity severity);
    ImU32 ColorU32(const ImVec4& color);
    ImVec4 GlassPrimaryTextColor();
    ImVec4 GlassMutedTextColor();
    ImVec4 GlassPanelBackground();
    ImVec4 GlassRaisedPanelBackground();
    ImVec4 GlassCardBackground();
    ImVec4 GlassHoverColor();
    ImVec4 GlassBorderColor();
    ImVec4 GlassSelectedRowColor(const ImVec4& accent);

    void TextWide(const std::wstring& value);
    void WrappedTextWide(const std::wstring& value);
    void WrappedTextColored(const ImVec4& color, const std::string& value);
    void WrappedTextDisabled(const std::wstring& value);
    void WrappedTextDisabled(const std::string& value);
    void RenderWrappedTooltip(const std::string& text, float wrapWidth = 520.0f);
    void RenderWrappedTooltip(const std::wstring& text, float wrapWidth = 520.0f);
    void RenderEmptyState(const char* primary, const char* detail = nullptr);
    void RenderDisabledReasonTooltip(const char* reason);
    void TextEllipsizedWithTooltip(const std::string& value, float maxWidth, float tooltipWrapWidth = 520.0f);
    void ClippedTextWithTooltip(const std::wstring& value, float tooltipWrapWidth = 600.0f);
    bool PushFontIfAvailable(ImFont* font);
    void PopFontIfPushed(bool pushed);
    void LabelValue(const char* label, const std::wstring& value);
    void LabelValue(const char* label, const char* value);
    void SeverityText(Core::Severity severity);
    void SeverityBadge(Core::Severity severity);
    void RenderGlassSectionHeader(const char* label, ImFont* font, const ImVec4& accent);
    void RenderGlassSubtleSeparator();
    void PushGlassCardStyle();
    void PopGlassCardStyle();
    void PushGlassButtonStyle();
    void PopGlassButtonStyle();
    void PushGlassChipStyle(bool active, const ImVec4& accent);
    void PopGlassChipStyle();
}
