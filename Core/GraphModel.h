#pragma once

#include "ProcessInfo.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace GlassPane::Core
{
    struct FocusedGraphNode
    {
        std::uint32_t pid = 0;
        std::uint32_t parentPid = 0;
        std::wstring name;
        bool suspicious = false;
        Severity severity = Severity::None;
        bool focus = false;
        bool inSelectedChain = false;
        std::size_t depth = 0;
    };

    struct FocusedGraphEdge
    {
        std::uint32_t parentPid = 0;
        std::uint32_t childPid = 0;
        bool inSelectedChain = false;
    };

    struct FocusedGraph
    {
        std::uint32_t focusPid = 0;
        std::vector<FocusedGraphNode> nodes;
        std::vector<FocusedGraphEdge> edges;
    };

    FocusedGraph BuildFocusedTree(
        const ProcessSnapshot& snapshot,
        std::uint32_t focusPid,
        std::size_t descendantDepth = 2);
}
