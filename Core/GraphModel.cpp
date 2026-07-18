#include "GraphModel.h"

#include "ChainAnalysis.h"

#include <unordered_set>

namespace GlassPane::Core
{
    namespace
    {
        std::size_t SourceProcessIndex(
            const ProcessSnapshot& snapshot,
            const ProcessInfo& process)
        {
            const auto indexed = snapshot.indexByPid.find(process.pid);
            if (indexed != snapshot.indexByPid.end() &&
                indexed->second < snapshot.processes.size() &&
                &snapshot.processes[indexed->second] == &process)
            {
                return indexed->second;
            }
            for (std::size_t processIndex = 0;
                processIndex < snapshot.processes.size();
                ++processIndex)
            {
                if (&snapshot.processes[processIndex] == &process)
                {
                    return processIndex;
                }
            }
            return snapshot.processes.size();
        }

        void AddNode(
            const ProcessSnapshot& snapshot,
            FocusedGraph& graph,
            const ProcessInfo& process,
            const std::vector<Severity>& authoritativeSeverities,
            const std::vector<std::uint8_t>& authoritativeSuspicious,
            const std::vector<std::uint8_t>& authoritativeAvailable,
            std::size_t depth,
            std::uint32_t focusPid,
            const std::unordered_set<std::uint32_t>& chainPids,
            std::unordered_set<std::uint32_t>& added)
        {
            if (added.find(process.pid) != added.end())
            {
                return;
            }

            added.insert(process.pid);
            const std::size_t sourceProcessIndex =
                SourceProcessIndex(snapshot, process);
            const bool authorityAvailable =
                sourceProcessIndex < authoritativeSeverities.size() &&
                sourceProcessIndex < authoritativeSuspicious.size() &&
                sourceProcessIndex < authoritativeAvailable.size() &&
                authoritativeAvailable[sourceProcessIndex] != 0;
            graph.nodes.push_back({
                sourceProcessIndex,
                process.pid,
                process.parentPid,
                process.name,
                authorityAvailable,
                authorityAvailable
                    ? authoritativeSuspicious[sourceProcessIndex] != 0
                    : false,
                authorityAvailable
                    ? authoritativeSeverities[sourceProcessIndex]
                    : Severity::None,
                process.pid == focusPid,
                chainPids.find(process.pid) != chainPids.end(),
                depth
            });
        }

        void AddEdge(
            FocusedGraph& graph,
            std::uint32_t parentPid,
            std::uint32_t childPid,
            const std::unordered_set<std::uint64_t>& chainEdges,
            std::unordered_set<std::uint64_t>& addedEdges)
        {
            const std::uint64_t key =
                (static_cast<std::uint64_t>(parentPid) << 32) | static_cast<std::uint64_t>(childPid);
            if (addedEdges.find(key) != addedEdges.end())
            {
                return;
            }

            addedEdges.insert(key);
            graph.edges.push_back({
                parentPid,
                childPid,
                chainEdges.find(key) != chainEdges.end()
            });
        }

        void AppendDescendants(
            const ProcessSnapshot& snapshot,
            FocusedGraph& graph,
            const ProcessInfo& parent,
            const std::vector<Severity>& authoritativeSeverities,
            const std::vector<std::uint8_t>& authoritativeSuspicious,
            const std::vector<std::uint8_t>& authoritativeAvailable,
            std::size_t parentDepth,
            std::size_t remainingDepth,
            std::uint32_t focusPid,
            const std::unordered_set<std::uint32_t>& chainPids,
            const std::unordered_set<std::uint64_t>& chainEdges,
            std::unordered_set<std::uint32_t>& addedNodes,
            std::unordered_set<std::uint64_t>& addedEdges)
        {
            if (remainingDepth == 0)
            {
                return;
            }

            for (const ProcessInfo* child : GetChildren(snapshot, parent.pid))
            {
                AddEdge(graph, parent.pid, child->pid, chainEdges, addedEdges);
                AddNode(
                    snapshot,
                    graph,
                    *child,
                    authoritativeSeverities,
                    authoritativeSuspicious,
                    authoritativeAvailable,
                    parentDepth + 1,
                    focusPid,
                    chainPids,
                    addedNodes);
                AppendDescendants(
                    snapshot,
                    graph,
                    *child,
                    authoritativeSeverities,
                    authoritativeSuspicious,
                    authoritativeAvailable,
                    parentDepth + 1,
                    remainingDepth - 1,
                    focusPid,
                    chainPids,
                    chainEdges,
                    addedNodes,
                    addedEdges);
            }
        }
    }

    FocusedGraph BuildFocusedTree(
        const ProcessSnapshot& snapshot,
        std::uint32_t focusPid,
        const std::vector<Severity>& authoritativeSeverities,
        const std::vector<std::uint8_t>& authoritativeSuspicious,
        const std::vector<std::uint8_t>& authoritativeAvailable,
        std::size_t descendantDepth)
    {
        FocusedGraph graph;
        graph.focusPid = focusPid;

        const ProcessInfo* focusProcess = FindProcessByPid(snapshot, focusPid);
        if (focusProcess == nullptr)
        {
            return graph;
        }

        std::unordered_set<std::uint32_t> addedNodes;
        std::unordered_set<std::uint64_t> addedEdges;
        const std::vector<const ProcessInfo*> parentChain = GetParentChain(snapshot, focusPid);
        std::unordered_set<std::uint32_t> chainPids;
        std::unordered_set<std::uint64_t> chainEdges;

        for (std::size_t index = 0; index < parentChain.size(); ++index)
        {
            chainPids.insert(parentChain[index]->pid);
            if (index > 0)
            {
                const std::uint64_t edgeKey =
                    (static_cast<std::uint64_t>(parentChain[index - 1]->pid) << 32) |
                    static_cast<std::uint64_t>(parentChain[index]->pid);
                chainEdges.insert(edgeKey);
            }
        }

        for (std::size_t index = 0; index < parentChain.size(); ++index)
        {
            AddNode(
                snapshot,
                graph,
                *parentChain[index],
                authoritativeSeverities,
                authoritativeSuspicious,
                authoritativeAvailable,
                index,
                focusPid,
                chainPids,
                addedNodes);
            if (index > 0)
            {
                AddEdge(
                    graph,
                    parentChain[index - 1]->pid,
                    parentChain[index]->pid,
                    chainEdges,
                    addedEdges);
            }
        }

        const std::size_t focusDepth = parentChain.empty() ? 0 : parentChain.size() - 1;
        AppendDescendants(
            snapshot,
            graph,
            *focusProcess,
            authoritativeSeverities,
            authoritativeSuspicious,
            authoritativeAvailable,
            focusDepth,
            descendantDepth,
            focusPid,
            chainPids,
            chainEdges,
            addedNodes,
            addedEdges);

        return graph;
    }
}
