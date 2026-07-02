#include "ProcessTree.h"

#include <algorithm>
#include <cwctype>
#include <string>
#include <unordered_set>

namespace GlassPane::Core
{
    namespace
    {
        std::wstring ToLower(std::wstring value)
        {
            std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) {
                return static_cast<wchar_t>(std::towlower(ch));
            });
            return value;
        }

        bool ProcessLess(const ProcessSnapshot& snapshot, std::uint32_t leftPid, std::uint32_t rightPid)
        {
            const auto leftIt = snapshot.indexByPid.find(leftPid);
            const auto rightIt = snapshot.indexByPid.find(rightPid);
            if (leftIt == snapshot.indexByPid.end() || rightIt == snapshot.indexByPid.end())
            {
                return leftPid < rightPid;
            }

            const ProcessInfo& left = snapshot.processes[leftIt->second];
            const ProcessInfo& right = snapshot.processes[rightIt->second];
            const std::wstring leftName = ToLower(left.name);
            const std::wstring rightName = ToLower(right.name);
            if (leftName == rightName)
            {
                return left.pid < right.pid;
            }
            return leftName < rightName;
        }

        bool RootLess(const ProcessSnapshot& snapshot, std::size_t leftIndex, std::size_t rightIndex)
        {
            const ProcessInfo& left = snapshot.processes[leftIndex];
            const ProcessInfo& right = snapshot.processes[rightIndex];
            return ProcessLess(snapshot, left.pid, right.pid);
        }

        void AppendTreeRows(
            const ProcessSnapshot& snapshot,
            std::uint32_t pid,
            std::size_t depth,
            std::unordered_set<std::uint32_t>& visited,
            std::vector<TreeRow>& rows)
        {
            const auto it = snapshot.indexByPid.find(pid);
            if (it == snapshot.indexByPid.end() || visited.find(pid) != visited.end())
            {
                return;
            }

            visited.insert(pid);
            rows.push_back({ it->second, depth });

            const ProcessInfo& process = snapshot.processes[it->second];
            for (const std::uint32_t childPid : process.children)
            {
                AppendTreeRows(snapshot, childPid, depth + 1, visited, rows);
            }
        }
    }

    void BuildProcessTree(ProcessSnapshot& snapshot)
    {
        snapshot.Reindex();
        snapshot.roots.clear();

        for (ProcessInfo& process : snapshot.processes)
        {
            process.children.clear();
        }

        for (ProcessInfo& process : snapshot.processes)
        {
            const bool hasValidParent = process.parentPid != 0 &&
                process.parentPid != process.pid &&
                snapshot.indexByPid.find(process.parentPid) != snapshot.indexByPid.end();

            if (hasValidParent)
            {
                ProcessInfo& parent = snapshot.processes[snapshot.indexByPid[process.parentPid]];
                parent.children.push_back(process.pid);
            }
            else
            {
                snapshot.roots.push_back(snapshot.indexByPid[process.pid]);
            }
        }

        for (ProcessInfo& process : snapshot.processes)
        {
            std::sort(process.children.begin(), process.children.end(), [&](std::uint32_t left, std::uint32_t right) {
                return ProcessLess(snapshot, left, right);
            });
        }

        std::sort(snapshot.roots.begin(), snapshot.roots.end(), [&](std::size_t left, std::size_t right) {
            return RootLess(snapshot, left, right);
        });
    }

    std::vector<TreeRow> BuildTreeRows(const ProcessSnapshot& snapshot)
    {
        std::vector<TreeRow> rows;
        rows.reserve(snapshot.processes.size());
        std::unordered_set<std::uint32_t> visited;

        for (const std::size_t rootIndex : snapshot.roots)
        {
            if (rootIndex < snapshot.processes.size())
            {
                AppendTreeRows(snapshot, snapshot.processes[rootIndex].pid, 0, visited, rows);
            }
        }

        for (const ProcessInfo& process : snapshot.processes)
        {
            if (visited.find(process.pid) == visited.end())
            {
                AppendTreeRows(snapshot, process.pid, 0, visited, rows);
            }
        }

        return rows;
    }
}
