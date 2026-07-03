#include "ChainAnalysis.h"

#include "ProcessTree.h"

#include <algorithm>
#include <cwctype>
#include <sstream>
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

        bool InSet(const std::unordered_set<std::wstring>& values, const std::wstring& value)
        {
            return values.find(ToLower(value)) != values.end();
        }

        bool Contains(const std::wstring& haystack, const std::wstring& needle)
        {
            return haystack.find(needle) != std::wstring::npos;
        }

        bool IsPowerShell(const std::wstring& loweredName)
        {
            return loweredName == L"powershell.exe" || loweredName == L"pwsh.exe";
        }

        bool HasEncodedCommandSwitch(const std::wstring& loweredCommandLine)
        {
            return Contains(loweredCommandLine, L"-enc") ||
                Contains(loweredCommandLine, L"-encodedcommand");
        }

        bool HasIndicator(const std::vector<std::wstring>& indicators, const std::wstring& indicator)
        {
            return std::find(indicators.begin(), indicators.end(), indicator) != indicators.end();
        }

        void Escalate(Severity& target, Severity severity)
        {
            if (SeverityRank(severity) > SeverityRank(target))
            {
                target = severity;
            }
        }

        void AddChainIndicator(
            ChainAnalysisResult& analysis,
            Severity severity,
            const std::wstring& indicator)
        {
            if (!HasIndicator(analysis.chainIndicators, indicator))
            {
                analysis.chainIndicators.push_back(indicator);
            }
            Escalate(analysis.chainSeverity, severity);
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
            if (SeverityRank(process->severity) >= SeverityRank(Severity::Low))
            {
                formatted << L" [" << SeverityToString(process->severity) << L"]";
            }
        }

        return formatted.str();
    }

    ChainAnalysisResult AnalyzeChain(const ProcessSnapshot& snapshot, std::uint32_t pid)
    {
        static const std::unordered_set<std::wstring> officeProcesses = {
            L"winword.exe",
            L"excel.exe",
            L"powerpnt.exe",
            L"outlook.exe",
            L"msaccess.exe",
            L"onenote.exe",
            L"mspub.exe",
            L"visio.exe"
        };

        static const std::unordered_set<std::wstring> browsers = {
            L"chrome.exe",
            L"msedge.exe",
            L"firefox.exe"
        };

        static const std::unordered_set<std::wstring> scriptInterpreters = {
            L"powershell.exe",
            L"pwsh.exe",
            L"cmd.exe",
            L"wscript.exe",
            L"cscript.exe",
            L"mshta.exe",
            L"python.exe",
            L"pythonw.exe",
            L"node.exe"
        };

        static const std::unordered_set<std::wstring> scriptHosts = {
            L"wscript.exe",
            L"cscript.exe",
            L"mshta.exe"
        };

        static const std::unordered_set<std::wstring> lolbins = {
            L"rundll32.exe",
            L"regsvr32.exe",
            L"mshta.exe",
            L"certutil.exe",
            L"bitsadmin.exe",
            L"wmic.exe",
            L"msiexec.exe",
            L"powershell.exe",
            L"pwsh.exe"
        };

        ChainAnalysisResult analysis;
        analysis.pid = pid;
        const std::vector<const ProcessInfo*> chain = GetParentChain(snapshot, pid);
        analysis.formattedParentChain = FormatParentChain(snapshot, pid);

        for (const ProcessInfo* process : chain)
        {
            analysis.parentChain.push_back({
                process->pid,
                process->name,
                process->severity
            });

            Escalate(analysis.chainSeverity, process->severity);

            const std::wstring loweredName = ToLower(process->name);
            const std::wstring loweredCommandLine = ToLower(process->commandLine);
            if (IsPowerShell(loweredName) && HasEncodedCommandSwitch(loweredCommandLine))
            {
                const Severity encodedSeverity =
                    SeverityRank(process->severity) >= SeverityRank(Severity::Low)
                        ? process->severity
                        : Severity::Medium;
                AddChainIndicator(
                    analysis,
                    encodedSeverity,
                    L"Encoded PowerShell appears in process ancestry");
            }
        }

        for (std::size_t index = 1; index < chain.size(); ++index)
        {
            const ProcessInfo* parent = chain[index - 1];
            const ProcessInfo* child = chain[index];
            const std::wstring parentName = ToLower(parent->name);
            const std::wstring childName = ToLower(child->name);
            const std::wstring childCommandLine = ToLower(child->commandLine);

            if (InSet(officeProcesses, parentName) && InSet(scriptInterpreters, childName))
            {
                AddChainIndicator(analysis, Severity::High, L"Office application spawned a shell");
            }

            if (InSet(browsers, parentName) && InSet(scriptInterpreters, childName))
            {
                AddChainIndicator(analysis, Severity::High, L"Browser spawned script interpreter");
            }

            if (InSet(scriptHosts, parentName) && InSet(lolbins, childName))
            {
                AddChainIndicator(analysis, Severity::High, L"Script host launched LOLBin");
            }

            if (InSet(officeProcesses, parentName) &&
                IsPowerShell(childName) &&
                HasEncodedCommandSwitch(childCommandLine))
            {
                AddChainIndicator(
                    analysis,
                    Severity::High,
                    L"Office application spawned encoded PowerShell");
            }
        }

        return analysis;
    }
}
