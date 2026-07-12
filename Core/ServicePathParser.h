#pragma once

#include "ServiceInfo.h"

#include <functional>
#include <string>
#include <string_view>

namespace GlassPane::Core
{
    constexpr std::size_t ServiceEnvironmentExpansionHardLimitCharacters = 32768;

    enum class ServiceEnvironmentExpansionStatus
    {
        Success,
        Failed,
        OutputTooLong
    };

    struct ServiceEnvironmentExpansionResult
    {
        ServiceEnvironmentExpansionStatus status = ServiceEnvironmentExpansionStatus::Failed;
        std::wstring expandedValue;
    };

    using ServiceEnvironmentExpander =
        std::function<ServiceEnvironmentExpansionResult(std::wstring_view)>;

    struct ServiceImagePathParseResult
    {
        std::wstring rawImagePath;
        std::wstring expandedImagePath;
        std::wstring executablePath;
        ServicePathParseStatus status = ServicePathParseStatus::NotAttempted;
        ServicePathConfidence confidence = ServicePathConfidence::None;
        std::wstring message;
        std::wstring svchostGroup;
        bool rawInputTruncated = false;
        bool expandedInputTruncated = false;
        bool svchostGroupTruncated = false;
    };

    // The default overload expands variables from the current GlassPane process
    // environment, not from the configured service account's environment.
    ServiceImagePathParseResult ParseServiceImagePath(const std::wstring& imagePath);

    // Supplying an expander keeps parser decisions deterministic and directly
    // testable without changing process or machine environment state.
    ServiceImagePathParseResult ParseServiceImagePath(
        const std::wstring& imagePath,
        const ServiceEnvironmentExpander& environmentExpander);
}
