#include "CorrelationEngine.h"

#include <algorithm>
#include <cwctype>
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

        bool Contains(const std::wstring& haystack, const std::wstring& needle)
        {
            return haystack.find(needle) != std::wstring::npos;
        }

        bool InSet(const std::unordered_set<std::wstring>& values, const std::wstring& value)
        {
            return values.find(ToLower(value)) != values.end();
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

        bool IsRiskyUserWritablePath(const std::wstring& path)
        {
            const std::wstring loweredPath = ToLower(path);
            return Contains(loweredPath, L"\\appdata\\") ||
                Contains(loweredPath, L"\\temp\\") ||
                Contains(loweredPath, L"\\downloads\\") ||
                Contains(loweredPath, L"\\desktop\\");
        }

        bool IsMicrosoftLookingName(const std::wstring& imageName)
        {
            static const std::unordered_set<std::wstring> names = {
                L"audiodg.exe",
                L"bitsadmin.exe",
                L"calc.exe",
                L"certutil.exe",
                L"conhost.exe",
                L"consent.exe",
                L"control.exe",
                L"csrss.exe",
                L"ctfmon.exe",
                L"dllhost.exe",
                L"dwm.exe",
                L"explorer.exe",
                L"fontdrvhost.exe",
                L"lsass.exe",
                L"msbuild.exe",
                L"mshta.exe",
                L"msiexec.exe",
                L"notepad.exe",
                L"powershell.exe",
                L"regsvr32.exe",
                L"rundll32.exe",
                L"runtimebroker.exe",
                L"services.exe",
                L"sihost.exe",
                L"smartscreen.exe",
                L"smss.exe",
                L"spoolsv.exe",
                L"svchost.exe",
                L"taskhostw.exe",
                L"werfault.exe",
                L"wininit.exe",
                L"winlogon.exe",
                L"wscript.exe",
                L"cscript.exe",
                L"wmic.exe"
            };

            return InSet(names, imageName);
        }

        bool IsMicrosoftSigner(const FileIdentity& identity)
        {
            return Contains(ToLower(identity.signerName), L"microsoft");
        }

        bool IsHighIntegrity(const TokenInfo& token)
        {
            constexpr std::uint32_t HighIntegrityRid = 0x00003000;
            return token.integrityRid >= HighIntegrityRid ||
                token.integrityLevelName == L"High" ||
                token.integrityLevelName == L"System" ||
                token.integrityLevelName == L"Protected Process";
        }

        bool HasEnabledPrivilege(const TokenInfo& token, const std::wstring& privilegeName)
        {
            for (const PrivilegeInfo& privilege : token.privileges)
            {
                if (ToLower(privilege.name) == ToLower(privilegeName) && privilege.enabled && !privilege.removed)
                {
                    return true;
                }
            }
            return false;
        }

        bool HasSuspiciousProcessEvidence(const ProcessInfo& process)
        {
            return process.IsSuspicious() ||
                SeverityRank(process.severity) >= SeverityRank(Severity::Low) ||
                !process.indicators.empty();
        }

        bool ChainContainsOfficeProcess(
            const ChainAnalysisResult& chain,
            std::wstring* officeProcessName)
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

            for (const ChainProcessSummary& process : chain.parentChain)
            {
                if (InSet(officeProcesses, process.name))
                {
                    if (officeProcessName != nullptr)
                    {
                        *officeProcessName = process.name;
                    }
                    return true;
                }
            }
            return false;
        }

        FindingSeverity FindingSeverityFromCoreSeverity(Severity severity)
        {
            switch (severity)
            {
            case Severity::High:
                return FindingSeverity::High;
            case Severity::Medium:
                return FindingSeverity::Medium;
            case Severity::Low:
                return FindingSeverity::Low;
            case Severity::Info:
            case Severity::None:
            default:
                return FindingSeverity::Info;
            }
        }

        std::wstring ProcessSeverityEvidence(Severity severity)
        {
            return L"Process severity is " + std::wstring(SeverityToString(severity)) + L".";
        }

        std::wstring EndpointText(const NetworkConnection& connection)
        {
            std::wstringstream text;
            text << L"Public remote endpoint: ";
            if (!connection.remoteAddress.empty())
            {
                text << connection.remoteAddress;
                if (connection.remotePort != 0)
                {
                    text << L":" << connection.remotePort;
                }
            }
            else
            {
                text << L"(remote address unavailable)";
            }

            if (!connection.protocol.empty())
            {
                text << L" (" << connection.protocol;
                if (!connection.state.empty())
                {
                    text << L" " << connection.state;
                }
                text << L")";
            }
            return text.str();
        }

        std::wstring HandleValueText(std::uint64_t handleValue)
        {
            std::wstringstream stream;
            stream << L"0x" << std::uppercase << std::hex << handleValue;
            return stream.str();
        }

        std::wstring JoinAccessLabels(const std::vector<std::wstring>& labels)
        {
            if (labels.empty())
            {
                return L"(no decoded process access labels)";
            }

            std::wstringstream stream;
            for (std::size_t index = 0; index < labels.size(); ++index)
            {
                if (index > 0)
                {
                    stream << L", ";
                }
                stream << labels[index];
            }
            return stream.str();
        }

        std::wstring HandleTargetText(const HandleInfo& handle)
        {
            if (handle.targetPid.has_value())
            {
                std::wstring text = handle.targetProcessName.empty()
                    ? L"PID " + std::to_wstring(handle.targetPid.value())
                    : handle.targetProcessName + L" PID " + std::to_wstring(handle.targetPid.value());
                return text;
            }

            if (!handle.objectName.empty())
            {
                return handle.objectName;
            }

            return L"(target/name unavailable)";
        }

        std::wstring HandleEvidenceText(const HandleInfo& handle)
        {
            std::wstringstream stream;
            stream << L"Handle " << HandleValueText(handle.handleValue)
                   << L" type " << (handle.objectType.empty() ? L"(unknown)" : handle.objectType)
                   << L" target/name " << HandleTargetText(handle)
                   << L" access " << (handle.grantedAccess.empty() ? L"(unknown)" : handle.grantedAccess);
            if (!handle.decodedAccess.empty())
            {
                stream << L" (" << JoinAccessLabels(handle.decodedAccess) << L")";
            }
            stream << L".";
            return stream.str();
        }

        bool HasFindingAtLeast(const std::vector<Finding>& findings, FindingSeverity severity)
        {
            for (const Finding& finding : findings)
            {
                if (FindingSeverityRank(finding.severity) >= FindingSeverityRank(severity))
                {
                    return true;
                }
            }
            return false;
        }

        bool IsProcessHandle(const HandleInfo& handle)
        {
            return ToLower(handle.objectType) == L"process";
        }

        bool IsTokenHandle(const HandleInfo& handle)
        {
            return ToLower(handle.objectType) == L"token";
        }

        bool IsHandleToProcessName(const HandleInfo& handle, const std::wstring& processName)
        {
            return IsProcessHandle(handle) && ToLower(handle.targetProcessName) == ToLower(processName);
        }

        bool HasSensitiveProcessAccess(const HandleInfo& handle)
        {
            constexpr std::uint32_t ProcessVmWrite = 0x0020;
            constexpr std::uint32_t ProcessCreateThread = 0x0002;
            constexpr std::uint32_t ProcessDupHandle = 0x0040;
            constexpr std::uint32_t ProcessVmOperation = 0x0008;
            constexpr std::uint32_t SensitiveMask =
                ProcessVmWrite |
                ProcessCreateThread |
                ProcessDupHandle |
                ProcessVmOperation;
            return (handle.grantedAccessRaw & SensitiveMask) != 0;
        }

        std::vector<const HandleInfo*> MatchingHandles(
            const HandleCollectionResult* handles,
            bool (*predicate)(const HandleInfo&))
        {
            std::vector<const HandleInfo*> matches;
            if (handles == nullptr || !handles->success)
            {
                return matches;
            }

            for (const HandleInfo& handle : handles->handles)
            {
                if (predicate(handle))
                {
                    matches.push_back(&handle);
                }
            }
            return matches;
        }

        void AddHandleEvidence(
            std::vector<std::wstring>& evidence,
            const std::vector<const HandleInfo*>& handles)
        {
            constexpr std::size_t MaxHandleEvidence = 4;
            const std::size_t count = std::min(handles.size(), MaxHandleEvidence);
            for (std::size_t index = 0; index < count; ++index)
            {
                evidence.push_back(HandleEvidenceText(*handles[index]));
                for (const std::wstring& indicator : handles[index]->indicators)
                {
                    evidence.push_back(L"Handle indicator: " + indicator);
                }
            }
            if (handles.size() > MaxHandleEvidence)
            {
                evidence.push_back(L"Additional matching handles: " + std::to_wstring(handles.size() - MaxHandleEvidence) + L".");
            }
        }

        std::vector<const NetworkConnection*> PublicRemoteConnections(
            const std::vector<NetworkConnection>* connections)
        {
            std::vector<const NetworkConnection*> publicConnections;
            if (connections == nullptr)
            {
                return publicConnections;
            }

            for (const NetworkConnection& connection : *connections)
            {
                if (connection.isPublicRemote)
                {
                    publicConnections.push_back(&connection);
                }
            }
            return publicConnections;
        }

        void AddEndpointEvidence(
            std::vector<std::wstring>& evidence,
            const std::vector<const NetworkConnection*>& connections)
        {
            constexpr std::size_t MaxEndpointEvidence = 3;
            const std::size_t count = std::min(connections.size(), MaxEndpointEvidence);
            for (std::size_t index = 0; index < count; ++index)
            {
                evidence.push_back(EndpointText(*connections[index]));
            }
            if (connections.size() > MaxEndpointEvidence)
            {
                evidence.push_back(L"Additional public remote connections: " + std::to_wstring(connections.size() - MaxEndpointEvidence) + L".");
            }
        }

        void AddFinding(std::vector<Finding>& findings, Finding finding)
        {
            findings.push_back(std::move(finding));
        }
    }

    std::vector<Finding> CorrelateFindings(const CorrelationContext& context)
    {
        std::vector<Finding> findings;
        if (context.process == nullptr)
        {
            return findings;
        }

        const ProcessInfo& process = *context.process;
        const std::wstring loweredName = ToLower(process.name);
        const std::wstring loweredCommandLine = ToLower(process.commandLine);
        const std::vector<const NetworkConnection*> publicConnections =
            PublicRemoteConnections(context.networkConnections);

        if (context.chain != nullptr)
        {
            std::wstring officeProcessName;
            if (ChainContainsOfficeProcess(*context.chain, &officeProcessName) &&
                IsPowerShell(loweredName) &&
                HasEncodedCommandSwitch(loweredCommandLine))
            {
                AddFinding(findings, {
                    FindingSeverity::High,
                    L"Office-spawned encoded PowerShell",
                    L"PowerShell with an encoded command appears in an Office parent-chain context; this warrants investigation.",
                    {
                        L"Parent chain contains Office process: " + officeProcessName + L".",
                        L"Selected process is " + (process.name.empty() ? L"(unknown)" : process.name) + L".",
                        L"Command line contains -EncodedCommand or -enc.",
                        L"Parent chain: " + (context.chain->formattedParentChain.empty() ? L"(unavailable)" : context.chain->formattedParentChain)
                    },
                    L"Execution Chain"
                });
            }
        }

        if (!publicConnections.empty() &&
            SeverityRank(process.severity) >= SeverityRank(Severity::Medium))
        {
            std::vector<std::wstring> evidence = {
                ProcessSeverityEvidence(process.severity),
                L"Selected process has at least one public remote connection."
            };
            AddEndpointEvidence(evidence, publicConnections);
            AddFinding(findings, {
                FindingSeverity::High,
                L"Suspicious process with public outbound connection",
                L"Existing local indicators plus a public outbound connection create a suspicious context that warrants investigation.",
                evidence,
                L"Network"
            });
        }

        if (context.fileIdentity != nullptr)
        {
            const FileIdentity& identity = *context.fileIdentity;
            const bool signatureAbsentOrInvalid = !identity.signaturePresent ||
                (identity.signaturePresent && !identity.signatureValid);

            if (identity.exists &&
                IsRiskyUserWritablePath(identity.path) &&
                signatureAbsentOrInvalid)
            {
                AddFinding(findings, {
                    FindingSeverity::Medium,
                    L"Unsigned executable in user-writable path",
                    L"The selected executable is in a user-writable location and lacks a valid trusted signature; this is an unusual execution context.",
                    {
                        L"Executable path: " + identity.path,
                        identity.signaturePresent
                            ? L"Signature is present but invalid."
                            : L"Signature is absent.",
                        L"Path is under AppData, Temp, Downloads, or Desktop."
                    },
                    L"File Identity"
                });
            }

            if (identity.signaturePresent && !identity.signatureValid)
            {
                AddFinding(findings, {
                    FindingSeverity::Medium,
                    L"Invalid Authenticode signature",
                    L"The file has an Authenticode signature, but Windows did not validate it.",
                    {
                        L"Signature present: yes.",
                        L"Signature valid: no.",
                        identity.errorMessage.empty()
                            ? L"Signature verification failed without additional detail."
                            : L"Verification note: " + identity.errorMessage
                    },
                    L"File Identity"
                });
            }

            if (identity.exists &&
                IsMicrosoftLookingName(process.name) &&
                !IsMicrosoftSigner(identity))
            {
                AddFinding(findings, {
                    FindingSeverity::Medium,
                    L"Microsoft-looking binary not signed by Microsoft",
                    L"The process name resembles a common Microsoft binary, but the signer does not look like Microsoft.",
                    {
                        L"Process name: " + (process.name.empty() ? L"(unknown)" : process.name),
                        identity.signerName.empty()
                            ? L"Signer name is absent."
                            : L"Signer name: " + identity.signerName,
                        L"Signer name does not contain Microsoft."
                    },
                    L"File Identity"
                });
            }
        }

        if (context.token != nullptr)
        {
            const TokenInfo& token = *context.token;
            if (!token.success)
            {
                AddFinding(findings, {
                    FindingSeverity::Info,
                    L"Token unavailable",
                    L"Token metadata could not be read for the selected process.",
                    {
                        token.errorMessage.empty()
                            ? L"Token inspection did not return details."
                            : L"Token inspection error: " + token.errorMessage
                    },
                    L"Token"
                });
            }
            else
            {
                const bool suspiciousProcess = HasSuspiciousProcessEvidence(process);
                const bool highIntegrity = IsHighIntegrity(token);

                if (context.fileIdentity != nullptr &&
                    context.fileIdentity->exists &&
                    IsRiskyUserWritablePath(context.fileIdentity->path) &&
                    highIntegrity)
                {
                    AddFinding(findings, {
                        FindingSeverity::Medium,
                        L"High integrity process from user-writable path",
                        L"The selected process is running at high integrity from a user-writable location; this unusual execution context warrants investigation.",
                        {
                            L"Integrity level: " + (token.integrityLevelName.empty() ? L"(unknown)" : token.integrityLevelName) + L".",
                            L"Executable path: " + context.fileIdentity->path,
                            L"Path is under AppData, Temp, Downloads, or Desktop."
                        },
                        L"Token"
                    });
                }

                if (suspiciousProcess && (token.isElevated || highIntegrity))
                {
                    AddFinding(findings, {
                        FindingSeverity::Medium,
                        L"Suspicious process running elevated",
                        L"Existing local process indicators are present while the token is elevated or high integrity.",
                        {
                            ProcessSeverityEvidence(process.severity),
                            token.isElevated ? L"Token elevation: elevated." : L"Token elevation: not elevated flag, but integrity is elevated.",
                            L"Integrity level: " + (token.integrityLevelName.empty() ? L"(unknown)" : token.integrityLevelName) + L"."
                        },
                        L"Token"
                    });
                }

                if (suspiciousProcess && HasEnabledPrivilege(token, L"SeDebugPrivilege"))
                {
                    AddFinding(findings, {
                        FindingSeverity::High,
                        L"Suspicious process with SeDebugPrivilege enabled",
                        L"Existing local process indicators are present and SeDebugPrivilege is enabled in the token.",
                        {
                            ProcessSeverityEvidence(process.severity),
                            L"Token privilege SeDebugPrivilege is enabled."
                        },
                        L"Token"
                    });
                }

                if (suspiciousProcess && HasEnabledPrivilege(token, L"SeImpersonatePrivilege"))
                {
                    AddFinding(findings, {
                        FindingSeverity::Medium,
                        L"Suspicious process with SeImpersonatePrivilege enabled",
                        L"Existing local process indicators are present and SeImpersonatePrivilege is enabled in the token.",
                        {
                            ProcessSeverityEvidence(process.severity),
                            L"Token privilege SeImpersonatePrivilege is enabled."
                        },
                        L"Token"
                    });
                }

                if (token.isAppContainer)
                {
                    AddFinding(findings, {
                        FindingSeverity::Info,
                        L"AppContainer token context",
                        L"The selected process is running with an AppContainer token.",
                        {
                            L"AppContainer: yes.",
                            L"User: " + (token.domainName.empty() ? token.userName : token.domainName + L"\\" + token.userName)
                        },
                        L"Token"
                    });
                }
            }
        }

        if (context.handles != nullptr && context.handles->success)
        {
            const bool suspiciousContext =
                SeverityRank(process.severity) >= SeverityRank(Severity::Medium) ||
                HasFindingAtLeast(findings, FindingSeverity::Medium);

            const std::vector<const HandleInfo*> lsassHandles = MatchingHandles(
                context.handles,
                [](const HandleInfo& handle) {
                    return IsHandleToProcessName(handle, L"lsass.exe");
                });

            if (suspiciousContext && !lsassHandles.empty())
            {
                std::vector<std::wstring> evidence = {
                    L"Selected process has suspicious context from existing local evidence.",
                    L"Handle inspection found a process handle targeting lsass.exe."
                };
                AddHandleEvidence(evidence, lsassHandles);
                AddFinding(findings, {
                    FindingSeverity::High,
                    L"Suspicious process has handle to LSASS",
                    L"A process with suspicious context holds a handle to lsass.exe; this warrants investigation.",
                    evidence,
                    L"Handles"
                });
            }

            const std::vector<const HandleInfo*> processAccessHandles = MatchingHandles(
                context.handles,
                [](const HandleInfo& handle) {
                    return IsProcessHandle(handle) &&
                        handle.targetPid.has_value() &&
                        handle.targetPid.value() != handle.owningPid &&
                        HasSensitiveProcessAccess(handle);
                });

            if (suspiciousContext && !processAccessHandles.empty())
            {
                std::vector<std::wstring> evidence = {
                    L"Selected process has suspicious context from existing local evidence.",
                    L"At least one process handle grants VM_WRITE, VM_OPERATION, CREATE_THREAD, or DUP_HANDLE access."
                };
                AddHandleEvidence(evidence, processAccessHandles);
                AddFinding(findings, {
                    FindingSeverity::Medium,
                    L"Suspicious process has sensitive process handle access",
                    L"A process with suspicious context holds a handle to another process with access rights commonly used for cross-process activity.",
                    evidence,
                    L"Handles"
                });
            }

            const std::vector<const HandleInfo*> tokenHandles = MatchingHandles(
                context.handles,
                [](const HandleInfo& handle) {
                    return IsTokenHandle(handle);
                });

            if (!tokenHandles.empty())
            {
                std::vector<std::wstring> evidence = {
                    L"Handle inspection found one or more Token object handles."
                };
                AddHandleEvidence(evidence, tokenHandles);
                AddFinding(findings, {
                    FindingSeverity::Info,
                    L"Token handle present",
                    L"The selected process has at least one Token object handle. This is context only and may be expected.",
                    evidence,
                    L"Handles"
                });
            }

            std::vector<const HandleInfo*> sensitiveHandles;
            for (const HandleInfo& handle : context.handles->handles)
            {
                if (handle.isSensitive)
                {
                    sensitiveHandles.push_back(&handle);
                }
            }

            if (suspiciousContext &&
                !sensitiveHandles.empty() &&
                lsassHandles.empty() &&
                processAccessHandles.empty())
            {
                std::vector<std::wstring> evidence = {
                    L"Selected process has suspicious context from existing local evidence.",
                    L"Handle inspection found sensitive handle indicators."
                };
                AddHandleEvidence(evidence, sensitiveHandles);
                AddFinding(findings, {
                    FindingSeverity::Medium,
                    L"Suspicious process holds sensitive handle",
                    L"A process with suspicious context holds one or more handles marked sensitive by local handle rules.",
                    evidence,
                    L"Handles"
                });
            }
        }

        const bool alreadyHasElevatedPublicConnectionFinding =
            !publicConnections.empty() &&
            SeverityRank(process.severity) >= SeverityRank(Severity::Medium);
        if (!publicConnections.empty() && !alreadyHasElevatedPublicConnectionFinding)
        {
            std::vector<std::wstring> evidence = {
                L"Selected process has at least one public remote connection."
            };
            AddEndpointEvidence(evidence, publicConnections);
            AddFinding(findings, {
                FindingSeverity::Low,
                L"Public remote connection",
                L"The selected process has a public remote connection. This may be expected, but it is useful triage context.",
                evidence,
                L"Network"
            });
        }

        if (!process.indicators.empty())
        {
            std::vector<std::wstring> evidence;
            for (const std::wstring& indicator : process.indicators)
            {
                evidence.push_back(L"Process indicator: " + indicator);
            }
            for (const std::wstring& note : process.contextNotes)
            {
                evidence.push_back(L"Context note: " + note);
            }
            AddFinding(findings, {
                FindingSeverityFromCoreSeverity(process.severity),
                L"Existing process indicators",
                L"Existing local process rules matched this process; review the underlying indicators for context.",
                evidence,
                L"Process Indicators"
            });
        }

        if (context.chain != nullptr && !context.chain->chainIndicators.empty())
        {
            std::vector<std::wstring> evidence;
            for (const std::wstring& indicator : context.chain->chainIndicators)
            {
                evidence.push_back(L"Chain indicator: " + indicator);
            }
            evidence.push_back(L"Parent chain: " + (context.chain->formattedParentChain.empty() ? L"(unavailable)" : context.chain->formattedParentChain));
            AddFinding(findings, {
                FindingSeverityFromCoreSeverity(context.chain->chainSeverity),
                L"Suspicious parent-chain context",
                L"The parent chain contains unusual execution context that warrants investigation.",
                evidence,
                L"Execution Chain"
            });
        }

        if (context.modules != nullptr)
        {
            if (!context.modules->success && !context.modules->statusMessage.empty())
            {
                AddFinding(findings, {
                    FindingSeverity::Info,
                    L"Modules unavailable",
                    L"Module inspection did not complete for the selected process.",
                    {
                        L"Module refresh status: " + context.modules->statusMessage
                    },
                    L"Modules"
                });
            }
            else if (!context.modules->indicators.empty())
            {
                std::vector<std::wstring> evidence;
                constexpr std::size_t MaxModuleEvidence = 8;
                const std::size_t count = std::min(context.modules->indicators.size(), MaxModuleEvidence);
                for (std::size_t index = 0; index < count; ++index)
                {
                    evidence.push_back(L"Module indicator: " + context.modules->indicators[index]);
                }
                if (context.modules->indicators.size() > MaxModuleEvidence)
                {
                    evidence.push_back(L"Additional module indicators: " + std::to_wstring(context.modules->indicators.size() - MaxModuleEvidence) + L".");
                }
                AddFinding(findings, {
                    FindingSeverity::Low,
                    L"Module indicators present",
                    L"One or more loaded modules have local path or accessibility indicators.",
                    evidence,
                    L"Modules"
                });
            }
        }

        return findings;
    }

    FindingSeverity HighestFindingSeverity(const std::vector<Finding>& findings)
    {
        FindingSeverity highest = FindingSeverity::Info;
        for (const Finding& finding : findings)
        {
            if (FindingSeverityRank(finding.severity) > FindingSeverityRank(highest))
            {
                highest = finding.severity;
            }
        }
        return highest;
    }

    std::wstring TriageSummary(const std::vector<Finding>& findings)
    {
        if (findings.empty())
        {
            return L"Clean";
        }

        switch (HighestFindingSeverity(findings))
        {
        case FindingSeverity::High:
            return L"High Attention";
        case FindingSeverity::Medium:
        case FindingSeverity::Low:
            return L"Suspicious";
        case FindingSeverity::Info:
        default:
            return L"Informational";
        }
    }
}
