#pragma once

#include "NetworkConnection.h"

#include <string>

namespace GlassPane::Core
{
    struct NetworkIndicator
    {
        std::wstring type;
        std::wstring value;
        std::wstring normalizedValue;
        std::wstring category;
        std::wstring severity;
        std::wstring confidence;
        std::wstring source;
        std::wstring description;
        std::wstring firstSeen;
        std::wstring lastSeen;
    };

    struct NetworkIndicatorMatch
    {
        NetworkConnection connection;
        NetworkIndicator indicator;
    };
}
