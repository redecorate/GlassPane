#include "GraphModel.h"

#include "ChainAnalysis.h"

#include <unordered_set>

namespace GlassPane::Core
{
    namespace
    {
        void AddNode(
            FocusedGraph& graph,
            const ProcessInfo& process,
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
            graph.nodes.push_back({
                process.pid,
                process.parentPid,
                process.name,
                process.IsSuspicious(),
                process.severity,
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
                AddNode(graph, *child, parentDepth + 1, focusPid, chainPids, addedNodes);
                AppendDescendants(
                    snapshot,
                    graph,
                    *child,
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
            AddNode(graph, *parentChain[index], index, focusPid, chainPids, addedNodes);
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
