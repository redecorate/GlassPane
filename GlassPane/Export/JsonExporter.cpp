#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "JsonExporter.h"

#include "../Core/ChainAnalysis.h"
#include "../Core/CorrelationEngine.h"
#include "../Core/FileIdentity.h"
#include "../Core/HandleInfo.h"
#include "../Core/TokenCollector.h"

#include <Windows.h>

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace GlassPane::Export
{
    namespace
    {
        std::string WideToUtf8(const std::wstring& value)
        {
            if (value.empty())
            {
                return {};
            }

            const int required = WideCharToMultiByte(
                CP_UTF8,
                0,
                value.data(),
                static_cast<int>(value.size()),
                nullptr,
                0,
                nullptr,
                nullptr);

            if (required <= 0)
            {
                return {};
            }

            std::string result(static_cast<std::size_t>(required), '\0');
            WideCharToMultiByte(
                CP_UTF8,
                0,
                value.data(),
                static_cast<int>(value.size()),
                result.data(),
                required,
                nullptr,
                nullptr);
            return result;
        }

        std::string EscapeJson(const std::string& value)
        {
            std::string escaped;
            escaped.reserve(value.size() + 8);

            for (const unsigned char ch : value)
            {
                switch (ch)
                {
                case '\\':
                    escaped += "\\\\";
                    break;
                case '"':
                    escaped += "\\\"";
                    break;
                case '\b':
                    escaped += "\\b";
                    break;
                case '\f':
                    escaped += "\\f";
                    break;
                case '\n':
                    escaped += "\\n";
                    break;
                case '\r':
                    escaped += "\\r";
                    break;
                case '\t':
                    escaped += "\\t";
                    break;
                default:
                    if (ch < 0x20)
                    {
                        constexpr char hex[] = "0123456789abcdef";
                        escaped += "\\u00";
                        escaped += hex[(ch >> 4) & 0x0f];
                        escaped += hex[ch & 0x0f];
                    }
                    else
                    {
                        escaped += static_cast<char>(ch);
                    }
                    break;
                }
            }

            return escaped;
        }

        void WriteJsonString(std::ostream& output, const std::wstring& value)
        {
            output << '"' << EscapeJson(WideToUtf8(value)) << '"';
        }

        void WriteJsonStringArray(std::ostream& output, const std::vector<std::wstring>& values)
        {
            output << '[';
            for (std::size_t index = 0; index < values.size(); ++index)
            {
                if (index > 0)
                {
                    output << ", ";
                }
                WriteJsonString(output, values[index]);
            }
            output << ']';
        }

        void WriteFileIdentityIndicatorArray(
            std::ostream& output,
            const std::vector<Core::FileIdentityIndicator>& indicators,
            const std::string& indent)
        {
            output << '[';
            if (!indicators.empty())
            {
                output << '\n';
            }

            for (std::size_t index = 0; index < indicators.size(); ++index)
            {
                const Core::FileIdentityIndicator& indicator = indicators[index];
                output << indent << "  {\n";
                output << indent << "    \"severity\": ";
                WriteJsonString(output, Core::SeverityToString(indicator.severity));
                output << ",\n";
                output << indent << "    \"message\": ";
                WriteJsonString(output, indicator.message);
                output << "\n";
                output << indent << "  }";
                if (index + 1 < indicators.size())
                {
                    output << ',';
                }
                output << '\n';
            }

            if (!indicators.empty())
            {
                output << indent;
            }
            output << ']';
        }

        void WriteFileIdentityObject(
            std::ostream& output,
            const Core::FileIdentity& identity,
            const std::vector<Core::FileIdentityIndicator>& indicators,
            const std::string& indent)
        {
            output << "{\n";
            output << indent << "  \"path\": ";
            WriteJsonString(output, identity.path);
            output << ",\n";
            output << indent << "  \"exists\": " << (identity.exists ? "true" : "false") << ",\n";
            output << indent << "  \"sha256\": ";
            WriteJsonString(output, identity.sha256);
            output << ",\n";
            output << indent << "  \"fileSize\": " << identity.fileSize << ",\n";
            output << indent << "  \"signerName\": ";
            WriteJsonString(output, identity.signerName);
            output << ",\n";
            output << indent << "  \"signaturePresent\": " << (identity.signaturePresent ? "true" : "false") << ",\n";
            output << indent << "  \"signatureValid\": " << (identity.signatureValid ? "true" : "false") << ",\n";
            output << indent << "  \"companyName\": ";
            WriteJsonString(output, identity.companyName);
            output << ",\n";
            output << indent << "  \"productName\": ";
            WriteJsonString(output, identity.productName);
            output << ",\n";
            output << indent << "  \"fileDescription\": ";
            WriteJsonString(output, identity.fileDescription);
            output << ",\n";
            output << indent << "  \"originalFilename\": ";
            WriteJsonString(output, identity.originalFilename);
            output << ",\n";
            output << indent << "  \"versionString\": ";
            WriteJsonString(output, identity.versionString);
            output << ",\n";
            output << indent << "  \"errorMessage\": ";
            WriteJsonString(output, identity.errorMessage);
            output << ",\n";
            output << indent << "  \"indicators\": ";
            WriteFileIdentityIndicatorArray(output, indicators, indent + "  ");
            output << "\n";
            output << indent << "}";
        }

        void WriteFindingArray(std::ostream& output, const std::vector<Core::Finding>& findings)
        {
            output << "[\n";
            for (std::size_t index = 0; index < findings.size(); ++index)
            {
                const Core::Finding& finding = findings[index];
                output << "    {\n";
                output << "      \"severity\": ";
                WriteJsonString(output, Core::FindingSeverityToString(finding.severity));
                output << ",\n";
                output << "      \"title\": ";
                WriteJsonString(output, finding.title);
                output << ",\n";
                output << "      \"description\": ";
                WriteJsonString(output, finding.description);
                output << ",\n";
                output << "      \"category\": ";
                WriteJsonString(output, finding.category);
                output << ",\n";
                output << "      \"evidence\": ";
                WriteJsonStringArray(output, finding.evidence);
                output << "\n";
                output << "    }";
                if (index + 1 < findings.size())
                {
                    output << ',';
                }
                output << '\n';
            }
            output << "  ]";
        }

        void WriteModuleArray(std::ostream& output, const std::vector<Core::ModuleInfo>& modules)
        {
            output << "[\n";
            for (std::size_t index = 0; index < modules.size(); ++index)
            {
                const Core::ModuleInfo& module = modules[index];
                const Core::FileIdentity fileIdentity = Core::CollectFileIdentity(module.modulePath);
                const std::vector<Core::FileIdentityIndicator> fileIdentityIndicators =
                    Core::BuildFileIdentityIndicators(fileIdentity, module.moduleName, false);
                output << "      {\n";
                output << "        \"moduleName\": ";
                WriteJsonString(output, module.moduleName);
                output << ",\n";
                output << "        \"modulePath\": ";
                WriteJsonString(output, module.modulePath);
                output << ",\n";
                output << "        \"baseAddress\": ";
                WriteJsonString(output, module.baseAddress);
                output << ",\n";
                output << "        \"sizeBytes\": " << module.sizeBytes << ",\n";
                output << "        \"readable\": " << (module.readable ? "true" : "false") << ",\n";
                output << "        \"fileIdentity\": ";
                WriteFileIdentityObject(output, fileIdentity, fileIdentityIndicators, "        ");
                output << ",\n";
                output << "        \"indicators\": ";
                WriteJsonStringArray(output, module.indicators);
                output << "\n";
                output << "      }";
                if (index + 1 < modules.size())
                {
                    output << ',';
                }
                output << '\n';
            }
            output << "    ]";
        }

        void WriteNetworkArray(std::ostream& output, const std::vector<Core::NetworkConnection>& connections)
        {
            output << "[\n";
            for (std::size_t index = 0; index < connections.size(); ++index)
            {
                const Core::NetworkConnection& connection = connections[index];
                output << "      {\n";
                output << "        \"owningPid\": " << connection.owningPid << ",\n";
                output << "        \"processName\": ";
                WriteJsonString(output, connection.processName);
                output << ",\n";
                output << "        \"protocol\": ";
                WriteJsonString(output, connection.protocol);
                output << ",\n";
                output << "        \"localAddress\": ";
                WriteJsonString(output, connection.localAddress);
                output << ",\n";
                output << "        \"localPort\": " << connection.localPort << ",\n";
                output << "        \"remoteAddress\": ";
                WriteJsonString(output, connection.remoteAddress);
                output << ",\n";
                output << "        \"remotePort\": " << connection.remotePort << ",\n";
                output << "        \"state\": ";
                WriteJsonString(output, connection.state);
                output << ",\n";
                output << "        \"addressFamily\": ";
                WriteJsonString(output, connection.addressFamily);
                output << ",\n";
                output << "        \"isListening\": " << (connection.isListening ? "true" : "false") << ",\n";
                output << "        \"isLoopback\": " << (connection.isLoopback ? "true" : "false") << ",\n";
                output << "        \"isLan\": " << (connection.isLan ? "true" : "false") << ",\n";
                output << "        \"isPublicRemote\": " << (connection.isPublicRemote ? "true" : "false") << "\n";
                output << "      }";
                if (index + 1 < connections.size())
                {
                    output << ',';
                }
                output << '\n';
            }
            output << "    ]";
        }

        void WritePrivilegeArray(std::ostream& output, const std::vector<Core::PrivilegeInfo>& privileges, const std::string& indent)
        {
            output << "[\n";
            for (std::size_t index = 0; index < privileges.size(); ++index)
            {
                const Core::PrivilegeInfo& privilege = privileges[index];
                output << indent << "  {\n";
                output << indent << "    \"name\": ";
                WriteJsonString(output, privilege.name);
                output << ",\n";
                output << indent << "    \"displayName\": ";
                WriteJsonString(output, privilege.displayName);
                output << ",\n";
                output << indent << "    \"enabled\": " << (privilege.enabled ? "true" : "false") << ",\n";
                output << indent << "    \"enabledByDefault\": " << (privilege.enabledByDefault ? "true" : "false") << ",\n";
                output << indent << "    \"removed\": " << (privilege.removed ? "true" : "false") << ",\n";
                output << indent << "    \"usedForAccess\": " << (privilege.usedForAccess ? "true" : "false") << "\n";
                output << indent << "  }";
                if (index + 1 < privileges.size())
                {
                    output << ',';
                }
                output << '\n';
            }
            output << indent << "]";
        }

        void WriteTokenObject(std::ostream& output, const Core::TokenInfo& token, const std::string& indent)
        {
            output << "{\n";
            output << indent << "  \"success\": " << (token.success ? "true" : "false") << ",\n";
            output << indent << "  \"errorMessage\": ";
            WriteJsonString(output, token.errorMessage);
            output << ",\n";
            output << indent << "  \"userName\": ";
            WriteJsonString(output, token.userName);
            output << ",\n";
            output << indent << "  \"domainName\": ";
            WriteJsonString(output, token.domainName);
            output << ",\n";
            output << indent << "  \"userSid\": ";
            WriteJsonString(output, token.userSid);
            output << ",\n";
            output << indent << "  \"integrityLevelName\": ";
            WriteJsonString(output, token.integrityLevelName);
            output << ",\n";
            output << indent << "  \"integrityRid\": " << token.integrityRid << ",\n";
            output << indent << "  \"elevationType\": ";
            WriteJsonString(output, token.elevationType);
            output << ",\n";
            output << indent << "  \"isElevated\": " << (token.isElevated ? "true" : "false") << ",\n";
            output << indent << "  \"isAdmin\": " << (token.isAdmin ? "true" : "false") << ",\n";
            output << indent << "  \"isAppContainer\": " << (token.isAppContainer ? "true" : "false") << ",\n";
            output << indent << "  \"sessionId\": ";
            if (token.sessionId.has_value())
            {
                output << token.sessionId.value();
            }
            else
            {
                output << "null";
            }
            output << ",\n";
            output << indent << "  \"tokenType\": ";
            WriteJsonString(output, token.tokenType);
            output << ",\n";
            output << indent << "  \"impersonationLevel\": ";
            WriteJsonString(output, token.impersonationLevel);
            output << ",\n";
            output << indent << "  \"privileges\": ";
            WritePrivilegeArray(output, token.privileges, indent + "  ");
            output << "\n";
            output << indent << "}";
        }

        std::wstring HandleValueText(std::uint64_t handleValue)
        {
            std::wstringstream stream;
            stream << L"0x" << std::uppercase << std::hex << handleValue;
            return stream.str();
        }

        void WriteHandleArray(std::ostream& output, const std::vector<Core::HandleInfo>& handles, const std::string& indent)
        {
            output << "[\n";
            for (std::size_t index = 0; index < handles.size(); ++index)
            {
                const Core::HandleInfo& handle = handles[index];
                output << indent << "  {\n";
                output << indent << "    \"owningPid\": " << handle.owningPid << ",\n";
                output << indent << "    \"handleValue\": ";
                WriteJsonString(output, HandleValueText(handle.handleValue));
                output << ",\n";
                output << indent << "    \"handleValueRaw\": " << handle.handleValue << ",\n";
                output << indent << "    \"objectType\": ";
                WriteJsonString(output, handle.objectType);
                output << ",\n";
                output << indent << "    \"objectName\": ";
                WriteJsonString(output, handle.objectName);
                output << ",\n";
                output << indent << "    \"grantedAccess\": ";
                WriteJsonString(output, handle.grantedAccess);
                output << ",\n";
                output << indent << "    \"grantedAccessRaw\": " << handle.grantedAccessRaw << ",\n";
                output << indent << "    \"targetPid\": ";
                if (handle.targetPid.has_value())
                {
                    output << handle.targetPid.value();
                }
                else
                {
                    output << "null";
                }
                output << ",\n";
                output << indent << "    \"targetProcessName\": ";
                WriteJsonString(output, handle.targetProcessName);
                output << ",\n";
                output << indent << "    \"isSensitive\": " << (handle.isSensitive ? "true" : "false") << ",\n";
                output << indent << "    \"typeResolved\": " << (handle.typeResolved ? "true" : "false") << ",\n";
                output << indent << "    \"nameResolved\": " << (handle.nameResolved ? "true" : "false") << ",\n";
                output << indent << "    \"decodedAccess\": ";
                WriteJsonStringArray(output, handle.decodedAccess);
                output << ",\n";
                output << indent << "    \"indicators\": ";
                WriteJsonStringArray(output, handle.indicators);
                output << ",\n";
                output << indent << "    \"errorMessage\": ";
                WriteJsonString(output, handle.errorMessage);
                output << "\n";
                output << indent << "  }";
                if (index + 1 < handles.size())
                {
                    output << ',';
                }
                output << '\n';
            }
            output << indent << "]";
        }

        void WriteHandleInspectionObject(
            std::ostream& output,
            const Core::HandleCollectionResult* handles,
            const std::string& indent)
        {
            output << "{\n";
            output << indent << "  \"loaded\": " << (handles != nullptr ? "true" : "false") << ",\n";
            output << indent << "  \"pid\": " << (handles != nullptr ? handles->pid : 0) << ",\n";
            output << indent << "  \"success\": " << (handles != nullptr && handles->success ? "true" : "false") << ",\n";
            output << indent << "  \"statusMessage\": ";
            WriteJsonString(output, handles != nullptr ? handles->statusMessage : L"Handle inspection was not loaded before export.");
            output << ",\n";
            output << indent << "  \"systemHandleCount\": " << (handles != nullptr ? handles->systemHandleCount : 0) << ",\n";
            output << indent << "  \"handleCount\": " << (handles != nullptr ? handles->handles.size() : 0) << ",\n";
            output << indent << "  \"sensitiveCount\": " << (handles != nullptr ? handles->sensitiveCount : 0) << ",\n";
            output << indent << "  \"handles\": ";
            if (handles != nullptr)
            {
                WriteHandleArray(output, handles->handles, indent + "  ");
                output << "\n";
            }
            else
            {
                output << "[]\n";
            }
            output << indent << "}";
        }

        std::size_t CountListeningConnections(const std::vector<Core::NetworkConnection>& connections)
        {
            return static_cast<std::size_t>(std::count_if(
                connections.begin(),
                connections.end(),
                [](const Core::NetworkConnection& connection) {
                    return connection.isListening;
                }));
        }

        std::size_t CountPublicRemoteConnections(const std::vector<Core::NetworkConnection>& connections)
        {
            return static_cast<std::size_t>(std::count_if(
                connections.begin(),
                connections.end(),
                [](const Core::NetworkConnection& connection) {
                    return connection.isPublicRemote;
                }));
        }

        std::string UtcTimestamp()
        {
            SYSTEMTIME utc = {};
            GetSystemTime(&utc);

            char buffer[32] = {};
            sprintf_s(
                buffer,
                "%04u-%02u-%02uT%02u:%02u:%02uZ",
                utc.wYear,
                utc.wMonth,
                utc.wDay,
                utc.wHour,
                utc.wMinute,
                utc.wSecond);
            return buffer;
        }
    }

    bool ExportSnapshotToJson(
        const Core::ProcessSnapshot& snapshot,
        const std::wstring& filePath,
        std::wstring* errorMessage)
    {
        std::ofstream output(filePath, std::ios::binary | std::ios::trunc);
        if (!output)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = L"Could not open the export file for writing.";
            }
            return false;
        }

        output << "{\n";
        output << "  \"schemaVersion\": \"0.4\",\n";
        output << "  \"generatedUtc\": \"" << UtcTimestamp() << "\",\n";
        output << "  \"processCount\": " << snapshot.processes.size() << ",\n";
        output << "  \"processes\": [\n";

        for (std::size_t index = 0; index < snapshot.processes.size(); ++index)
        {
            const Core::ProcessInfo& process = snapshot.processes[index];
            const Core::ChainAnalysisResult chainAnalysis = Core::AnalyzeChain(snapshot, process.pid);
            output << "    {\n";
            output << "      \"pid\": " << process.pid << ",\n";
            output << "      \"parentPid\": " << process.parentPid << ",\n";
            output << "      \"name\": ";
            WriteJsonString(output, process.name);
            output << ",\n";
            output << "      \"executablePath\": ";
            WriteJsonString(output, process.executablePath);
            output << ",\n";
            output << "      \"commandLine\": ";
            WriteJsonString(output, process.commandLine);
            output << ",\n";
            output << "      \"commandLineAccessible\": " << (process.commandLineAccessible ? "true" : "false") << ",\n";
            output << "      \"sessionId\": ";
            if (process.sessionId.has_value())
            {
                output << process.sessionId.value();
            }
            else
            {
                output << "null";
            }
            output << ",\n";
            output << "      \"architecture\": ";
            WriteJsonString(output, process.architecture);
            output << ",\n";
            output << "      \"hasCreationTime\": " << (process.hasCreationTime ? "true" : "false") << ",\n";
            output << "      \"creationTimeLocal\": ";
            WriteJsonString(output, process.creationTimeLocal);
            output << ",\n";
            output << "      \"suspicious\": " << (process.IsSuspicious() ? "true" : "false") << ",\n";
            output << "      \"severity\": ";
            WriteJsonString(output, Core::SeverityToString(process.severity));
            output << ",\n";
            output << "      \"indicators\": ";
            WriteJsonStringArray(output, process.indicators);
            output << ",\n";
            output << "      \"contextNotes\": ";
            WriteJsonStringArray(output, process.contextNotes);
            output << ",\n";
            output << "      \"parentChain\": [";
            for (std::size_t chainIndex = 0; chainIndex < chainAnalysis.parentChain.size(); ++chainIndex)
            {
                if (chainIndex > 0)
                {
                    output << ", ";
                }

                const Core::ChainProcessSummary& chainProcess = chainAnalysis.parentChain[chainIndex];
                output << "{";
                output << "\"pid\": " << chainProcess.pid << ", ";
                output << "\"name\": ";
                WriteJsonString(output, chainProcess.name);
                output << ", \"severity\": ";
                WriteJsonString(output, Core::SeverityToString(chainProcess.severity));
                output << "}";
            }
            output << "],\n";
            output << "      \"chainSeverity\": ";
            WriteJsonString(output, Core::SeverityToString(chainAnalysis.chainSeverity));
            output << ",\n";
            output << "      \"chainIndicators\": ";
            WriteJsonStringArray(output, chainAnalysis.chainIndicators);
            output << ",\n";
            output << "      \"children\": [";
            for (std::size_t childIndex = 0; childIndex < process.children.size(); ++childIndex)
            {
                if (childIndex > 0)
                {
                    output << ", ";
                }
                output << process.children[childIndex];
            }
            output << "]\n";
            output << "    }";
            if (index + 1 < snapshot.processes.size())
            {
                output << ',';
            }
            output << '\n';
        }

        output << "  ]\n";
        output << "}\n";

        if (!output)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = L"An error occurred while writing the export file.";
            }
            return false;
        }

        return true;
    }

    bool ExportSelectedProcessDetailsToJson(
        const Core::ProcessSnapshot& snapshot,
        std::uint32_t pid,
        const Core::ModuleCollectionResult& modules,
        const std::vector<Core::NetworkConnection>& networkConnections,
        const std::wstring& filePath,
        std::wstring* errorMessage)
    {
        return ExportSelectedProcessDetailsToJson(
            snapshot,
            pid,
            modules,
            networkConnections,
            nullptr,
            filePath,
            errorMessage);
    }

    bool ExportSelectedProcessDetailsToJson(
        const Core::ProcessSnapshot& snapshot,
        std::uint32_t pid,
        const Core::ModuleCollectionResult& modules,
        const std::vector<Core::NetworkConnection>& networkConnections,
        const Core::HandleCollectionResult* handles,
        const std::wstring& filePath,
        std::wstring* errorMessage)
    {
        const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot, pid);
        if (process == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = L"Selected process is no longer present in the snapshot.";
            }
            return false;
        }

        std::ofstream output(filePath, std::ios::binary | std::ios::trunc);
        if (!output)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = L"Could not open the export file for writing.";
            }
            return false;
        }

        const Core::ChainAnalysisResult chainAnalysis = Core::AnalyzeChain(snapshot, process->pid);
        const Core::FileIdentity processFileIdentity = Core::CollectFileIdentity(process->executablePath);
        const std::vector<Core::FileIdentityIndicator> processFileIdentityIndicators =
            Core::BuildFileIdentityIndicators(processFileIdentity, process->name, true);
        const Core::TokenInfo tokenInfo = Core::CollectProcessTokenInfo(*process);
        const Core::HandleCollectionResult* selectedHandles =
            handles != nullptr && handles->pid == process->pid
                ? handles
                : nullptr;
        const std::size_t listeningNetworkCount = CountListeningConnections(networkConnections);
        const std::size_t publicRemoteNetworkCount = CountPublicRemoteConnections(networkConnections);
        std::vector<std::wstring> networkIndicators;
        if (listeningNetworkCount > 0)
        {
            networkIndicators.push_back(L"Network: process has listening socket.");
        }
        if (publicRemoteNetworkCount > 0)
        {
            networkIndicators.push_back(L"Network: process has public remote connection.");
        }
        if (process->IsSuspicious() && publicRemoteNetworkCount > 0)
        {
            networkIndicators.push_back(L"Network: suspicious process has outbound public connection.");
        }

        std::vector<std::wstring> networkContextNotes;
        const Core::Severity effectiveSeverity =
            Core::SeverityRank(chainAnalysis.chainSeverity) > Core::SeverityRank(process->severity)
                ? chainAnalysis.chainSeverity
                : process->severity;
        if (publicRemoteNetworkCount > 0 &&
            Core::SeverityRank(effectiveSeverity) >= Core::SeverityRank(Core::Severity::Medium))
        {
            networkContextNotes.push_back(L"Network context: elevated process or chain severity with public outbound connection. No severity escalation applied.");
        }

        Core::CorrelationContext correlationContext;
        correlationContext.process = process;
        correlationContext.chain = &chainAnalysis;
        correlationContext.modules = &modules;
        correlationContext.networkConnections = &networkConnections;
        correlationContext.fileIdentity = &processFileIdentity;
        correlationContext.token = &tokenInfo;
        correlationContext.handles = selectedHandles;
        const std::vector<Core::Finding> findings = Core::CorrelateFindings(correlationContext);
        const std::wstring highestFindingSeverity = findings.empty()
            ? L"None"
            : std::wstring(Core::FindingSeverityToString(Core::HighestFindingSeverity(findings)));

        output << "{\n";
        output << "  \"schemaVersion\": \"0.8-selected-details\",\n";
        output << "  \"generatedUtc\": \"" << UtcTimestamp() << "\",\n";
        output << "  \"triage\": {\n";
        output << "    \"summary\": ";
        WriteJsonString(output, Core::TriageSummary(findings));
        output << ",\n";
        output << "    \"highestSeverity\": ";
        WriteJsonString(output, highestFindingSeverity);
        output << ",\n";
        output << "    \"findingCount\": " << findings.size() << ",\n";
        output << "    \"findings\": ";
        WriteFindingArray(output, findings);
        output << "\n";
        output << "  },\n";
        output << "  \"process\": {\n";
        output << "    \"pid\": " << process->pid << ",\n";
        output << "    \"parentPid\": " << process->parentPid << ",\n";
        output << "    \"name\": ";
        WriteJsonString(output, process->name);
        output << ",\n";
        output << "    \"executablePath\": ";
        WriteJsonString(output, process->executablePath);
        output << ",\n";
        output << "    \"fileIdentity\": ";
        WriteFileIdentityObject(output, processFileIdentity, processFileIdentityIndicators, "    ");
        output << ",\n";
        output << "    \"commandLine\": ";
        WriteJsonString(output, process->commandLine);
        output << ",\n";
        output << "    \"commandLineAccessible\": " << (process->commandLineAccessible ? "true" : "false") << ",\n";
        output << "    \"architecture\": ";
        WriteJsonString(output, process->architecture);
        output << ",\n";
        output << "    \"hasCreationTime\": " << (process->hasCreationTime ? "true" : "false") << ",\n";
        output << "    \"creationTimeLocal\": ";
        WriteJsonString(output, process->creationTimeLocal);
        output << ",\n";
        output << "    \"suspicious\": " << (process->IsSuspicious() ? "true" : "false") << ",\n";
        output << "    \"severity\": ";
        WriteJsonString(output, Core::SeverityToString(process->severity));
        output << ",\n";
        output << "    \"indicators\": ";
        WriteJsonStringArray(output, process->indicators);
        output << ",\n";
        output << "    \"contextNotes\": ";
        WriteJsonStringArray(output, process->contextNotes);
        output << ",\n";
        output << "    \"parentChain\": [";
        for (std::size_t chainIndex = 0; chainIndex < chainAnalysis.parentChain.size(); ++chainIndex)
        {
            if (chainIndex > 0)
            {
                output << ", ";
            }

            const Core::ChainProcessSummary& chainProcess = chainAnalysis.parentChain[chainIndex];
            output << "{";
            output << "\"pid\": " << chainProcess.pid << ", ";
            output << "\"name\": ";
            WriteJsonString(output, chainProcess.name);
            output << ", \"severity\": ";
            WriteJsonString(output, Core::SeverityToString(chainProcess.severity));
            output << "}";
        }
        output << "],\n";
        output << "    \"chainSeverity\": ";
        WriteJsonString(output, Core::SeverityToString(chainAnalysis.chainSeverity));
        output << ",\n";
        output << "    \"chainIndicators\": ";
        WriteJsonStringArray(output, chainAnalysis.chainIndicators);
        output << "\n";
        output << "  },\n";
        output << "  \"tokenInspection\": ";
        WriteTokenObject(output, tokenInfo, "  ");
        output << ",\n";
        output << "  \"handleInspection\": ";
        WriteHandleInspectionObject(output, selectedHandles, "  ");
        output << ",\n";
        output << "  \"moduleInspection\": {\n";
        output << "    \"pid\": " << modules.pid << ",\n";
        output << "    \"success\": " << (modules.success ? "true" : "false") << ",\n";
        output << "    \"statusMessage\": ";
        WriteJsonString(output, modules.statusMessage);
        output << ",\n";
        output << "    \"moduleIndicators\": ";
        WriteJsonStringArray(output, modules.indicators);
        output << ",\n";
        output << "    \"modules\": ";
        WriteModuleArray(output, modules.modules);
        output << "\n";
        output << "  },\n";
        output << "  \"networkInspection\": {\n";
        output << "    \"connectionCount\": " << networkConnections.size() << ",\n";
        output << "    \"listeningCount\": " << listeningNetworkCount << ",\n";
        output << "    \"publicRemoteCount\": " << publicRemoteNetworkCount << ",\n";
        output << "    \"indicators\": ";
        WriteJsonStringArray(output, networkIndicators);
        output << ",\n";
        output << "    \"contextNotes\": ";
        WriteJsonStringArray(output, networkContextNotes);
        output << ",\n";
        output << "    \"connections\": ";
        WriteNetworkArray(output, networkConnections);
        output << "\n";
        output << "  }\n";
        output << "}\n";

        if (!output)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = L"An error occurred while writing the export file.";
            }
            return false;
        }

        return true;
    }

    bool ExportSelectedProcessDetailsToJson(
        const Core::ProcessSnapshot& snapshot,
        std::uint32_t pid,
        const Core::ModuleCollectionResult& modules,
        const std::wstring& filePath,
        std::wstring* errorMessage)
    {
        const std::vector<Core::NetworkConnection> emptyNetworkConnections;
        return ExportSelectedProcessDetailsToJson(
            snapshot,
            pid,
            modules,
            emptyNetworkConnections,
            nullptr,
            filePath,
            errorMessage);
    }
}
