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
        // Ephemeral index into the ProcessSnapshot used to build this graph.
        // It is not serialized and keeps authority projection identity-exact.
        std::size_t sourceProcessIndex = 0;
        std::uint32_t pid = 0;
        std::uint32_t parentPid = 0;
        std::wstring name;
        bool authorityAvailable = false;
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

    // Authority vectors are aligned to snapshot.processes. A missing entry is
    // rendered as neutral/unavailable; ProcessInfo legacy severity is never
    // consulted by the graph model.
    FocusedGraph BuildFocusedTree(
        const ProcessSnapshot& snapshot,
        std::uint32_t focusPid,
        const std::vector<Severity>& authoritativeSeverities,
        const std::vector<std::uint8_t>& authoritativeSuspicious,
        const std::vector<std::uint8_t>& authoritativeAvailable,
        std::size_t descendantDepth = 2);
}
