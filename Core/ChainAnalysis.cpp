#include "ChainAnalysis.h"

#include "ProcessTree.h"

#include <algorithm>
#include <cwctype>
#include <initializer_list>
#include <sstream>
#include <string>
#include <unordered_set>
#include <utility>

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

        bool IsEncodedCommandSwitch(const std::wstring& token)
        {
            const std::wstring lowered = ToLower(token);
            return lowered == L"-encodedcommand" ||
                lowered == L"/encodedcommand" ||
                lowered == L"--encoded-command";
        }

        bool HasEncodedCommandSwitch(const std::wstring& commandLine)
        {
            std::wstring token;
            bool quoted = false;
            for (std::size_t index = 0; index <= commandLine.size(); ++index)
            {
                const wchar_t character = index < commandLine.size()
                    ? commandLine[index]
                    : L' ';
                if (character == L'"')
                {
                    quoted = !quoted;
                    continue;
                }
                if (!quoted && std::iswspace(character) != 0)
                {
                    if (IsEncodedCommandSwitch(token))
                    {
                        return true;
                    }
                    token.clear();
                    continue;
                }
                token.push_back(character);
            }
            return false;
        }

        std::wstring BoundedChainFactValue(std::wstring value, bool& truncated)
        {
            if (value.size() > ChainIndicatorFactValueMaxCharacters)
            {
                value.resize(ChainIndicatorFactValueMaxCharacters);
                truncated = true;
            }
            return value;
        }

        void AddChainFacts(
            ChainAnalysisResult& analysis,
            std::initializer_list<ChainIndicatorFact> facts)
        {
            for (ChainIndicatorFact fact : facts)
            {
                if (analysis.chainIndicatorFacts.size() >=
                    ChainIndicatorFactMaxCount)
                {
                    analysis.chainIndicatorFactsTruncated = true;
                    break;
                }
                if (fact.sourceRuleId.size() >
                    ChainIndicatorFactRuleIdMaxCharacters)
                {
                    fact.sourceRuleId.resize(
                        ChainIndicatorFactRuleIdMaxCharacters);
                    analysis.chainIndicatorFactsTruncated = true;
                }
                // Retained only for historical sidecar shape compatibility.
                // Native chain facts are not derived from a legacy indicator.
                fact.sourceIndicatorOrdinal = 0;
                fact.rawValue = BoundedChainFactValue(
                    std::move(fact.rawValue),
                    analysis.chainIndicatorFactsTruncated);
                fact.normalizedValue = BoundedChainFactValue(
                    std::move(fact.normalizedValue),
                    analysis.chainIndicatorFactsTruncated);
                analysis.chainIndicatorFacts.push_back(std::move(fact));
            }
        }
    }

    const ProcessInfo* FindProcessByPid(const ProcessSnapshot& snapshot, std::uint32_t pid)
    {
        const auto it = snapshot.indexByPid.find(pid);
        if (it == snapshot.indexByPid.end() || it->second >= snapshot.processes.size())
        {
            return nullptr;
        }
        return &snapshot.processes[it->second];
    }

    std::vector<const ProcessInfo*> GetChildren(const ProcessSnapshot& snapshot, std::uint32_t pid)
    {
        std::vector<const ProcessInfo*> children;
        const ProcessInfo* process = FindProcessByPid(snapshot, pid);
        if (process == nullptr)
        {
            return children;
        }

        children.reserve(process->children.size());
        for (const std::uint32_t childPid : process->children)
        {
            const ProcessInfo* child = FindProcessByPid(snapshot, childPid);
            if (child != nullptr)
            {
                children.push_back(child);
            }
        }

        return children;
    }

    std::vector<const ProcessInfo*> GetParentChain(const ProcessSnapshot& snapshot, std::uint32_t pid)
    {
        std::vector<const ProcessInfo*> chain;
        std::unordered_set<std::uint32_t> visited;

        const ProcessInfo* current = FindProcessByPid(snapshot, pid);
        while (current != nullptr && visited.find(current->pid) == visited.end())
        {
            visited.insert(current->pid);
            chain.push_back(current);

            if (current->parentPid == 0 || current->parentPid == current->pid)
            {
                break;
            }

            if (!IsUsableParentRelationship(GetParentRelationshipStatus(snapshot, *current)))
            {
                break;
            }

            current = FindProcessByPid(snapshot, current->parentPid);
        }

        std::reverse(chain.begin(), chain.end());
        return chain;
    }

    std::wstring FormatParentChain(const ProcessSnapshot& snapshot, std::uint32_t pid)
    {
        const std::vector<const ProcessInfo*> chain = GetParentChain(snapshot, pid);
        std::wstringstream formatted;

        for (std::size_t index = 0; index < chain.size(); ++index)
        {
            const ProcessInfo* process = chain[index];
            if (index > 0)
            {
                formatted << L" -> ";
            }

            formatted << (process->name.empty() ? L"(unknown)" : process->name);
        }

        return formatted.str();
    }

    ChainAnalysisResult AnalyzeChain(const ProcessSnapshot& snapshot, std::uint32_t pid)
    {
        ChainAnalysisResult analysis;
        analysis.pid = pid;
        const std::vector<const ProcessInfo*> chain = GetParentChain(snapshot, pid);
        analysis.formattedParentChain = FormatParentChain(snapshot, pid);

        for (const ProcessInfo* process : chain)
        {
            analysis.parentChain.push_back({
                process->pid,
                process->name
            });

            if (process->commandLineAccessible &&
                HasEncodedCommandSwitch(process->commandLine))
            {
                AddChainFacts(
                    analysis,
                    {{
                        ChainIndicatorFactKind::EncodedCommand,
                        "native.chain.command.encoded-switch",
                        process->pid,
                        0,
                        process->commandLine,
                        L"encoded-command-switch"
                    }});
            }
        }

        for (std::size_t index = 1; index < chain.size(); ++index)
        {
            const ProcessInfo* parent = chain[index - 1];
            const ProcessInfo* child = chain[index];
            if (child->commandLineAccessible &&
                HasEncodedCommandSwitch(child->commandLine))
            {
                AddChainFacts(
                    analysis,
                    {{
                        ChainIndicatorFactKind::ProcessRelationship,
                        "native.chain.relationship.encoded-command-parent",
                        parent->pid,
                        child->pid,
                        L"PID " + std::to_wstring(parent->pid) +
                            L" -> PID " + std::to_wstring(child->pid),
                        L"pid:" + std::to_wstring(parent->pid) +
                            L"->pid:" + std::to_wstring(child->pid)
                    }});
            }
        }

        return analysis;
    }
}
