#include "SuspicionRules.h"

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

        const ProcessInfo* FindParent(const ProcessSnapshot& snapshot, const ProcessInfo& process)
        {
            const auto it = snapshot.indexByPid.find(process.parentPid);
            if (it == snapshot.indexByPid.end())
            {
                return nullptr;
            }
            return &snapshot.processes[it->second];
        }

        void AddIndicator(ProcessInfo& process, Severity severity, const std::wstring& indicator)
        {
            process.indicators.push_back(indicator);
            if (SeverityRank(severity) > SeverityRank(process.severity))
            {
                process.severity = severity;
            }
        }
    }

    void ApplySuspiciousRules(ProcessSnapshot& snapshot)
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

        static const std::unordered_set<std::wstring> scriptHosts = {
            L"wscript.exe",
            L"cscript.exe",
            L"mshta.exe"
        };

        static const std::unordered_set<std::wstring> encodedCommandHighRiskParents = {
            L"winword.exe",
            L"excel.exe",
            L"outlook.exe",
            L"chrome.exe",
            L"msedge.exe",
            L"firefox.exe",
            L"wscript.exe",
            L"cscript.exe",
            L"mshta.exe",
            L"rundll32.exe"
        };

        static const std::unordered_set<std::wstring> shells = {
            L"cmd.exe",
            L"powershell.exe",
            L"pwsh.exe"
        };

        for (ProcessInfo& process : snapshot.processes)
        {
            process.suspicious = false;
            process.severity = Severity::None;
            process.indicators.clear();
            process.contextNotes.clear();
        }

        for (ProcessInfo& process : snapshot.processes)
        {
            const std::wstring loweredName = ToLower(process.name);
            const std::wstring loweredPath = ToLower(process.executablePath);
            const std::wstring loweredCommandLine = ToLower(process.commandLine);
            const ProcessInfo* parent = FindParent(snapshot, process);
            const std::wstring loweredParentName = parent == nullptr ? L"" : ToLower(parent->name);

            if (parent != nullptr && InSet(shells, loweredName) && InSet(officeProcesses, parent->name))
            {
                AddIndicator(process, Severity::High, L"Office process spawned cmd.exe or PowerShell");
            }

            if (parent != nullptr && InSet(shells, loweredName) && InSet(scriptHosts, parent->name))
            {
                AddIndicator(process, Severity::High, L"Script host spawned cmd.exe or PowerShell");
            }

            if (Contains(loweredPath, L"\\appdata\\") || Contains(loweredPath, L"\\temp\\"))
            {
                AddIndicator(process, Severity::Low, L"Executable path is under AppData or Temp");
            }

            if (IsPowerShell(loweredName) && HasEncodedCommandSwitch(loweredCommandLine))
            {
                Severity severity = Severity::Medium;

                if (loweredParentName == L"codex.exe")
                {
                    severity = Severity::Low;
                    process.contextNotes.push_back(L"Encoded PowerShell launched by Codex developer tooling.");
                }
                else if (InSet(encodedCommandHighRiskParents, loweredParentName))
                {
                    severity = Severity::High;
                }

                AddIndicator(process, severity, L"PowerShell command line contains encoded command switch");
            }

            process.suspicious = SeverityRank(process.severity) >= SeverityRank(Severity::Low);
        }
    }
}
