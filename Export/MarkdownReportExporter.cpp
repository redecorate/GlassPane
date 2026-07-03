#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "MarkdownReportExporter.h"

#include "../Core/ChainAnalysis.h"
#include "../Core/CorrelationEngine.h"
#include "../Core/ProcessTree.h"

#include <Windows.h>

#include <algorithm>
#include <cwctype>
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

        std::wstring LocalTimestamp()
        {
            SYSTEMTIME local = {};
            GetLocalTime(&local);

            wchar_t buffer[64] = {};
            swprintf_s(
                buffer,
                L"%04u-%02u-%02u %02u:%02u:%02u",
                local.wYear,
                local.wMonth,
                local.wDay,
                local.wHour,
                local.wMinute,
                local.wSecond);
            return buffer;
        }

        std::wstring ValueOr(const std::wstring& value, const wchar_t* fallback)
        {
            return value.empty() ? std::wstring(fallback) : value;
        }

        std::wstring YesNo(bool value)
        {
            return value ? L"Yes" : L"No";
        }

        std::wstring ParentRelationshipStatusText(Core::ParentRelationshipStatus status)
        {
            switch (status)
            {
            case Core::ParentRelationshipStatus::Verified:
                return L"Validated by creation time";
            case Core::ParentRelationshipStatus::Unverified:
                return L"Unverified; creation time unavailable";
            case Core::ParentRelationshipStatus::InvalidPidReuse:
                return L"Invalid; PID reuse suspected";
            case Core::ParentRelationshipStatus::MissingParent:
                return L"Parent PID not present in snapshot";
            case Core::ParentRelationshipStatus::NoParent:
            default:
                return L"(none)";
            }
        }

        std::wstring FileSizeText(std::uint64_t bytes)
        {
            std::wstringstream stream;
            stream << bytes << L" bytes";
            if (bytes >= 1024)
            {
                const double kib = static_cast<double>(bytes) / 1024.0;
                stream << L" (";
                if (kib >= 1024.0)
                {
                    stream << std::fixed << std::setprecision(1) << (kib / 1024.0) << L" MiB";
                }
                else
                {
                    stream << std::fixed << std::setprecision(1) << kib << L" KiB";
                }
                stream << L")";
            }
            return stream.str();
        }

        std::wstring TokenUserText(const Core::TokenInfo& token)
        {
            if (token.userName.empty() && token.domainName.empty())
            {
                return L"(unavailable)";
            }
            if (token.domainName.empty())
            {
                return token.userName;
            }
            if (token.userName.empty())
            {
                return token.domainName;
            }
            return token.domainName + L"\\" + token.userName;
        }

        std::wstring PrivilegeStateText(const Core::PrivilegeInfo& privilege)
        {
            std::vector<std::wstring> states;
            if (privilege.removed)
            {
                states.push_back(L"Removed");
            }
            if (privilege.enabled)
            {
                states.push_back(L"Enabled");
            }
            if (privilege.enabledByDefault)
            {
                states.push_back(L"Default");
            }
            if (privilege.usedForAccess)
            {
                states.push_back(L"Used");
            }
            if (states.empty())
            {
                return L"Disabled";
            }

            std::wstring joined;
            for (std::size_t index = 0; index < states.size(); ++index)
            {
                if (index > 0)
                {
                    joined += L", ";
                }
                joined += states[index];
            }
            return joined;
        }

        std::wstring HandleValueText(std::uint64_t handleValue)
        {
            std::wstringstream stream;
            stream << L"0x" << std::uppercase << std::hex << handleValue;
            return stream.str();
        }

        std::wstring JoinMemoryIndicators(const Core::MemoryRegionInfo& region)
        {
            if (region.indicators.empty())
            {
                return L"(none)";
            }

            std::wstring joined;
            for (std::size_t index = 0; index < region.indicators.size(); ++index)
            {
                if (index > 0)
                {
                    joined += L"; ";
                }
                joined += region.indicators[index];
            }
            return joined;
        }

        std::wstring NetworkEndpoint(const Core::NetworkConnection& connection, bool remote)
        {
            const std::wstring& address = remote ? connection.remoteAddress : connection.localAddress;
            const std::uint16_t port = remote ? connection.remotePort : connection.localPort;
            if (remote && (address.empty() || port == 0 || connection.isListening))
            {
                return L"-";
            }
            if (address.empty())
            {
                return L"(unknown)";
            }

            std::wstringstream stream;
            stream << address << L":" << port;
            return stream.str();
        }

        std::wstring NetworkScopeText(const Core::NetworkConnection& connection)
        {
            std::vector<std::wstring> scopes;
            if (connection.isListening)
            {
                scopes.push_back(L"Listening");
            }
            if (connection.isLoopback)
            {
                scopes.push_back(L"Loopback");
            }
            if (connection.isLan)
            {
                scopes.push_back(L"LAN");
            }
            if (connection.isPublicRemote)
            {
                scopes.push_back(L"Public remote");
            }
            if (scopes.empty())
            {
                return L"Local/unspecified";
            }

            std::wstring joined;
            for (std::size_t index = 0; index < scopes.size(); ++index)
            {
                if (index > 0)
                {
                    joined += L", ";
                }
                joined += scopes[index];
            }
            return joined;
        }

        std::wstring ToLower(std::wstring value)
        {
            std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) {
                return static_cast<wchar_t>(towlower(ch));
            });
            return value;
        }

        bool IsImportantPrivilege(const std::wstring& privilegeName)
        {
            const std::wstring lowered = ToLower(privilegeName);
            static const wchar_t* important[] = {
                L"sedebugprivilege",
                L"seimpersonateprivilege",
                L"seassignprimarytokenprivilege",
                L"setcbprivilege",
                L"sebackupprivilege",
                L"serestoreprivilege",
                L"setakeownershipprivilege",
                L"seloaddriverprivilege",
                L"secreatetokenprivilege"
            };

            for (const wchar_t* value : important)
            {
                if (lowered == value)
                {
                    return true;
                }
            }
            return false;
        }

        std::string EscapeMarkdownInline(const std::string& value)
        {
            std::string escaped;
            escaped.reserve(value.size() + 8);

            for (const char ch : value)
            {
                switch (ch)
                {
                case '\r':
                    break;
                case '\n':
                    escaped += "<br>";
                    break;
                case '\\':
                case '`':
                case '*':
                case '_':
                case '{':
                case '}':
                case '[':
                case ']':
                case '(':
                case ')':
                case '#':
                case '+':
                case '-':
                case '!':
                case '|':
                case '>':
                    escaped.push_back('\\');
                    escaped.push_back(ch);
                    break;
                default:
                    escaped.push_back(ch);
                    break;
                }
            }

            return escaped;
        }

        std::string EscapeMarkdownInline(const std::wstring& value)
        {
            return EscapeMarkdownInline(WideToUtf8(value));
        }

        std::size_t MaxBacktickRun(const std::string& value)
        {
            std::size_t maxRun = 0;
            std::size_t currentRun = 0;
            for (const char ch : value)
            {
                if (ch == '`')
                {
                    ++currentRun;
                    maxRun = std::max(maxRun, currentRun);
                }
                else
                {
                    currentRun = 0;
                }
            }
            return maxRun;
        }

        void WriteCodeBlock(std::ostream& output, const std::wstring& value)
        {
            const std::string text = WideToUtf8(value.empty() ? L"(empty)" : value);
            const std::size_t fenceLength = std::max<std::size_t>(3, MaxBacktickRun(text) + 1);
            const std::string fence(fenceLength, '`');
            output << fence << "text\n" << text << "\n" << fence << "\n";
        }

        void WriteBullet(std::ostream& output, const std::wstring& value)
        {
            output << "- " << EscapeMarkdownInline(value) << "\n";
        }

        void WriteTableHeader(std::ostream& output, const std::vector<std::string>& columns)
        {
            output << "|";
            for (const std::string& column : columns)
            {
                output << " " << column << " |";
            }
            output << "\n|";
            for (std::size_t index = 0; index < columns.size(); ++index)
            {
                output << " --- |";
            }
            output << "\n";
        }

        void WriteTableRow(std::ostream& output, const std::vector<std::wstring>& cells)
        {
            output << "|";
            for (const std::wstring& cell : cells)
            {
                output << " " << EscapeMarkdownInline(cell.empty() ? L"(empty)" : cell) << " |";
            }
            output << "\n";
        }

        std::wstring SignatureText(const Core::FileIdentity& identity)
        {
            if (!identity.exists)
            {
                return L"(unavailable)";
            }
            if (identity.signatureValid)
            {
                return L"Valid";
            }
            if (identity.signaturePresent)
            {
                return L"Present but invalid";
            }
            return L"Unsigned";
        }

        std::size_t CountPublicRemote(const std::vector<Core::NetworkConnection>& connections)
        {
            return static_cast<std::size_t>(std::count_if(
                connections.begin(),
                connections.end(),
                [](const Core::NetworkConnection& connection) {
                    return connection.isPublicRemote;
                }));
        }

        std::size_t CountListening(const std::vector<Core::NetworkConnection>& connections)
        {
            return static_cast<std::size_t>(std::count_if(
                connections.begin(),
                connections.end(),
                [](const Core::NetworkConnection& connection) {
                    return connection.isListening;
                }));
        }
    }

    bool ExportSelectedProcessMarkdownReport(
        const SelectedProcessMarkdownReportContext& context,
        const std::wstring& filePath,
        std::wstring* errorMessage)
    {
        if (context.snapshot == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = L"Report context does not include a process snapshot.";
            }
            return false;
        }

        const Core::ProcessInfo* process = Core::FindProcessByPid(*context.snapshot, context.pid);
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
                *errorMessage = L"Could not open the report file for writing.";
            }
            return false;
        }

        const Core::ChainAnalysisResult chain = Core::AnalyzeChain(*context.snapshot, process->pid);
        const std::wstring triageVerdict = Core::TriageSummary(context.findings);
        const std::wstring highestSeverity = context.findings.empty()
            ? L"None"
            : std::wstring(Core::FindingSeverityToString(Core::HighestFindingSeverity(context.findings)));

        output << "# GlassPane Selected Process Report\n\n";
        output << "- Generated: " << EscapeMarkdownInline(LocalTimestamp()) << "\n";
        output << "- GlassPane version: " << EscapeMarkdownInline(ValueOr(context.appVersion, L"(unknown)")) << "\n";
        output << "- Build configuration: " << EscapeMarkdownInline(ValueOr(context.buildConfiguration, L"(unknown)")) << "\n\n";

        output << "## Summary\n\n";
        output << "- Process: " << EscapeMarkdownInline(ValueOr(process->name, L"(unknown)")) << "\n";
        output << "- PID: `" << process->pid << "`\n";
        output << "- Triage verdict: " << EscapeMarkdownInline(triageVerdict) << "\n";
        output << "- Highest finding severity: " << EscapeMarkdownInline(highestSeverity) << "\n";
        output << "- Finding count: " << context.findings.size() << "\n\n";

        output << "## Findings\n\n";
        if (context.findings.empty())
        {
            output << "No triage findings were generated for this process.\n\n";
        }
        else
        {
            for (const Core::Finding& finding : context.findings)
            {
                output << "### " << EscapeMarkdownInline(Core::FindingSeverityToString(finding.severity))
                       << ": " << EscapeMarkdownInline(ValueOr(finding.title, L"(untitled finding)")) << "\n\n";
                output << "- Category: " << EscapeMarkdownInline(ValueOr(finding.category, L"(none)")) << "\n";
                output << "- Description: " << EscapeMarkdownInline(ValueOr(finding.description, L"(none)")) << "\n";
                if (!finding.evidence.empty())
                {
                    output << "- Evidence:\n";
                    for (const std::wstring& evidence : finding.evidence)
                    {
                        output << "  - " << EscapeMarkdownInline(evidence) << "\n";
                    }
                }
                output << "\n";
            }
        }

        output << "## Process Identity\n\n";
        WriteTableHeader(output, { "Field", "Value" });
        WriteTableRow(output, { L"Name", ValueOr(process->name, L"(unknown)") });
        WriteTableRow(output, { L"PID", std::to_wstring(process->pid) });
        WriteTableRow(output, { L"Parent PID", std::to_wstring(process->parentPid) });
        WriteTableRow(output, { L"Parent Link", ParentRelationshipStatusText(Core::GetParentRelationshipStatus(*context.snapshot, *process)) });
        WriteTableRow(output, { L"Architecture", ValueOr(process->architecture, L"(unknown)") });
        WriteTableRow(output, { L"Session", process->sessionId.has_value() ? std::to_wstring(process->sessionId.value()) : L"(unknown)" });
        WriteTableRow(output, { L"Start Time", process->hasCreationTime ? process->creationTimeLocal : L"(unavailable)" });
        WriteTableRow(output, { L"Suspicious", YesNo(process->IsSuspicious()) });
        WriteTableRow(output, { L"Severity", Core::SeverityToString(process->severity) });
        output << "\nExecutable path:\n\n";
        WriteCodeBlock(output, process->executablePath.empty() ? L"(not accessible)" : process->executablePath);
        output << "\nCommand line:\n\n";
        WriteCodeBlock(output, process->commandLine.empty() ? L"(empty or not accessible)" : process->commandLine);
        output << "\n";

        output << "## Parent Chain\n\n";
        if (chain.parentChain.empty())
        {
            output << "Parent chain unavailable for this process.\n\n";
        }
        else
        {
            output << EscapeMarkdownInline(chain.formattedParentChain.empty() ? Core::FormatParentChain(*context.snapshot, process->pid) : chain.formattedParentChain) << "\n\n";
            WriteTableHeader(output, { "PID", "Process", "Severity" });
            for (const Core::ChainProcessSummary& chainProcess : chain.parentChain)
            {
                WriteTableRow(output, {
                    std::to_wstring(chainProcess.pid),
                    ValueOr(chainProcess.name, L"(unknown)"),
                    Core::SeverityToString(chainProcess.severity)
                });
            }
            output << "\n";
        }
        output << "- Chain severity: " << EscapeMarkdownInline(Core::SeverityToString(chain.chainSeverity)) << "\n";
        if (!chain.chainIndicators.empty())
        {
            output << "- Chain indicators:\n";
            for (const std::wstring& indicator : chain.chainIndicators)
            {
                output << "  - " << EscapeMarkdownInline(indicator) << "\n";
            }
        }
        output << "\n";

        output << "## File Identity\n\n";
        if (context.fileIdentity == nullptr)
        {
            output << "File identity was unavailable for this report.\n\n";
        }
        else
        {
            const Core::FileIdentity& identity = *context.fileIdentity;
            WriteTableHeader(output, { "Field", "Value" });
            WriteTableRow(output, { L"File size", identity.exists ? FileSizeText(identity.fileSize) : L"(unavailable)" });
            WriteTableRow(output, { L"Signature present", YesNo(identity.signaturePresent) });
            WriteTableRow(output, { L"Signature valid", YesNo(identity.signatureValid) });
            WriteTableRow(output, { L"Signature status", SignatureText(identity) });
            WriteTableRow(output, { L"Signer", ValueOr(identity.signerName, L"(none)") });
            WriteTableRow(output, { L"Company", ValueOr(identity.companyName, L"(none)") });
            WriteTableRow(output, { L"Product", ValueOr(identity.productName, L"(none)") });
            WriteTableRow(output, { L"Description", ValueOr(identity.fileDescription, L"(none)") });
            WriteTableRow(output, { L"Original filename", ValueOr(identity.originalFilename, L"(none)") });
            WriteTableRow(output, { L"Version", ValueOr(identity.versionString, L"(none)") });
            output << "\nSHA256:\n\n";
            WriteCodeBlock(output, identity.sha256.empty() ? L"(unavailable)" : identity.sha256);
            if (!identity.errorMessage.empty())
            {
                output << "\nIdentity note: " << EscapeMarkdownInline(identity.errorMessage) << "\n";
            }
            if (!context.fileIdentityIndicators.empty())
            {
                output << "\nFile identity indicators:\n";
                for (const Core::FileIdentityIndicator& indicator : context.fileIdentityIndicators)
                {
                    output << "- " << EscapeMarkdownInline(Core::SeverityToString(indicator.severity))
                           << ": " << EscapeMarkdownInline(indicator.message) << "\n";
                }
            }
            output << "\n";
        }

        output << "## Token Summary\n\n";
        if (!context.tokenLoaded || context.token == nullptr)
        {
            output << "Token data was not refreshed for this process.\n\n";
        }
        else if (!context.token->success)
        {
            output << "Token data unavailable: "
                   << EscapeMarkdownInline(ValueOr(context.token->errorMessage, L"access denied or process exited"))
                   << "\n\n";
        }
        else
        {
            const Core::TokenInfo& token = *context.token;
            WriteTableHeader(output, { "Field", "Value" });
            WriteTableRow(output, { L"User", TokenUserText(token) });
            WriteTableRow(output, { L"SID", ValueOr(token.userSid, L"(unavailable)") });
            WriteTableRow(output, { L"Integrity", ValueOr(token.integrityLevelName, L"(unknown)") });
            WriteTableRow(output, { L"Elevated", YesNo(token.isElevated) });
            WriteTableRow(output, { L"Admin", YesNo(token.isAdmin) });
            WriteTableRow(output, { L"Elevation type", ValueOr(token.elevationType, L"(unknown)") });
            WriteTableRow(output, { L"Token type", ValueOr(token.tokenType, L"(unknown)") });
            output << "\nImportant enabled privileges:\n";
            bool wrotePrivilege = false;
            for (const Core::PrivilegeInfo& privilege : token.privileges)
            {
                if (privilege.enabled && IsImportantPrivilege(privilege.name))
                {
                    wrotePrivilege = true;
                    output << "- " << EscapeMarkdownInline(ValueOr(privilege.name, L"(unknown privilege)"))
                           << " - " << EscapeMarkdownInline(PrivilegeStateText(privilege));
                    if (!privilege.displayName.empty())
                    {
                        output << " - " << EscapeMarkdownInline(privilege.displayName);
                    }
                    output << "\n";
                }
            }
            if (!wrotePrivilege)
            {
                output << "- No important enabled privileges were observed in the loaded token metadata.\n";
            }
            output << "\n";
        }

        if (!context.runtimeLoaded || context.runtime == nullptr)
        {
            output << "## Runtime\n\n";
            output << "Runtime data was not loaded for this process.\n\n";
        }
        else
        {
            const Core::RuntimeInfo& runtime = *context.runtime;
            output << "## Runtime\n\n";
            if (!runtime.success)
            {
                output << "Runtime data unavailable: "
                       << EscapeMarkdownInline(ValueOr(runtime.errorMessage, L"access denied or process exited"))
                       << "\n\n";
            }
            else
            {
                output << "### Scheduling\n\n";
                WriteTableHeader(output, { "Field", "Value" });
                WriteTableRow(output, { L"Priority class", ValueOr(runtime.priorityClassName, L"(unavailable)") });
                WriteTableRow(output, { L"Base priority", std::to_wstring(runtime.basePriority) });
                WriteTableRow(output, { L"Affinity mask", ValueOr(runtime.affinityMaskString, L"(unavailable)") });
                WriteTableRow(output, { L"Processor group", ValueOr(runtime.processorGroup, L"(unavailable)") });
                WriteTableRow(output, { L"Architecture", ValueOr(runtime.architecture, L"(unknown)") });
                WriteTableRow(output, { L"WOW64", YesNo(runtime.isWow64) });
                output << "\n### CPU Time\n\n";
                WriteTableHeader(output, { "Field", "Value" });
                WriteTableRow(output, { L"User", ValueOr(runtime.userCpuTime, L"(unavailable)") });
                WriteTableRow(output, { L"Kernel", ValueOr(runtime.kernelCpuTime, L"(unavailable)") });
                WriteTableRow(output, { L"Total", ValueOr(runtime.totalCpuTime, L"(unavailable)") });
                output << "\n### Memory\n\n";
                WriteTableHeader(output, { "Field", "Value" });
                WriteTableRow(output, { L"Working set", FileSizeText(runtime.workingSetSize) });
                WriteTableRow(output, { L"Peak working set", FileSizeText(runtime.peakWorkingSetSize) });
                WriteTableRow(output, { L"Private bytes", FileSizeText(runtime.privateBytes) });
                WriteTableRow(output, { L"Pagefile usage", FileSizeText(runtime.pagefileUsage) });
                WriteTableRow(output, { L"Peak pagefile usage", FileSizeText(runtime.peakPagefileUsage) });
                output << "\n### Counts\n\n";
                WriteTableHeader(output, { "Field", "Value" });
                WriteTableRow(output, { L"Threads", std::to_wstring(runtime.threadCount) });
                WriteTableRow(output, { L"Handles", std::to_wstring(runtime.handleCount) });
                output << "\n";
                if (!runtime.contextNotes.empty())
                {
                    output << "Runtime context notes:\n";
                    for (const std::wstring& note : runtime.contextNotes)
                    {
                        WriteBullet(output, note);
                    }
                    output << "\n";
                }
            }

            output << "### Thread Summary\n\n";
            if (runtime.threads.empty())
            {
                output << "No thread metadata returned for this process.\n\n";
            }
            else
            {
                WriteTableHeader(output, { "Thread ID", "Base", "Current", "Start Address", "Module" });
                constexpr std::size_t MaxThreadRows = 25;
                const std::size_t threadRows = std::min(runtime.threads.size(), MaxThreadRows);
                for (std::size_t index = 0; index < threadRows; ++index)
                {
                    const Core::ThreadInfo& thread = runtime.threads[index];
                    WriteTableRow(output, {
                        std::to_wstring(thread.threadId),
                        std::to_wstring(thread.basePriority),
                        thread.hasCurrentPriority ? std::to_wstring(thread.currentPriority) : L"Unavailable",
                        ValueOr(thread.startAddress, L"Unavailable"),
                        ValueOr(thread.startAddressResolvedModule, L"(unresolved)")
                    });
                }
                if (runtime.threads.size() > MaxThreadRows)
                {
                    output << "\nAdditional thread rows omitted: " << (runtime.threads.size() - MaxThreadRows) << ".\n";
                }
                output << "\n";
            }
        }

        output << "## Memory Regions\n\n";
        if (!context.memoryLoaded || context.memory == nullptr)
        {
            output << "Memory data was not loaded for this process.\n\n";
        }
        else if (!context.memory->success)
        {
            output << "Memory data unavailable: "
                   << EscapeMarkdownInline(ValueOr(context.memory->statusMessage, L"access denied, protected process, or process exited"))
                   << "\n\n";
        }
        else
        {
            const Core::MemoryCollectionResult& memory = *context.memory;
            WriteTableHeader(output, { "Field", "Value" });
            WriteTableRow(output, { L"Total regions", std::to_wstring(memory.totalRegions) });
            WriteTableRow(output, { L"Executable regions", std::to_wstring(memory.executableRegions) });
            WriteTableRow(output, { L"Private executable regions", std::to_wstring(memory.privateExecutableRegions) });
            WriteTableRow(output, { L"RWX regions", std::to_wstring(memory.rwxRegions) });
            WriteTableRow(output, { L"Suspicious regions", std::to_wstring(memory.suspiciousRegions) });
            WriteTableRow(output, { L"Guard regions", std::to_wstring(memory.guardRegions) });
            output << "\n";

            std::vector<const Core::MemoryRegionInfo*> interestingRegions;
            for (const Core::MemoryRegionInfo& region : memory.regions)
            {
                if (region.isSuspicious || !region.indicators.empty())
                {
                    interestingRegions.push_back(&region);
                }
            }

            if (interestingRegions.empty())
            {
                output << "No suspicious or indicator-bearing memory regions were observed in the loaded metadata.\n\n";
            }
            else
            {
                output << "Suspicious/indicator-bearing memory regions:\n\n";
                WriteTableHeader(output, { "Base", "Size", "Type", "Protection", "Mapped File", "Indicators" });
                constexpr std::size_t MaxMemoryRows = 40;
                const std::size_t rowsToWrite = std::min(interestingRegions.size(), MaxMemoryRows);
                for (std::size_t index = 0; index < rowsToWrite; ++index)
                {
                    const Core::MemoryRegionInfo& region = *interestingRegions[index];
                    WriteTableRow(output, {
                        ValueOr(region.baseAddressString, L"(unknown)"),
                        ValueOr(region.regionSizeString, L"(unknown)"),
                        ValueOr(region.typeName, L"(unknown)"),
                        ValueOr(region.protectName, L"(unknown)"),
                        ValueOr(region.mappedFilePath, L"(none)"),
                        JoinMemoryIndicators(region)
                    });
                }
                if (interestingRegions.size() > MaxMemoryRows)
                {
                    output << "\nAdditional memory rows omitted: " << (interestingRegions.size() - MaxMemoryRows) << ".\n";
                }
                output << "\n";
            }
        }

        output << "## Network Connections\n\n";
        if (!context.networkLoaded)
        {
            output << "Network data was not loaded for this process.\n\n";
        }
        else if (!context.networkSuccess)
        {
            output << "Network unavailable: "
                   << EscapeMarkdownInline(ValueOr(context.networkStatusMessage, L"could not inspect local socket ownership"))
                   << "\n\n";
        }
        else if (context.networkConnections == nullptr)
        {
            output << "Network data unavailable: report context did not include selected-process connections.\n\n";
        }
        else
        {
            const std::vector<Core::NetworkConnection>& connections = *context.networkConnections;
            if (!context.networkStatusMessage.empty())
            {
                output << "Network status: " << EscapeMarkdownInline(context.networkStatusMessage) << "\n\n";
            }
            output << "- Connections: " << connections.size() << "\n";
            output << "- Listening sockets: " << CountListening(connections) << "\n";
            output << "- Public remote connections: " << CountPublicRemote(connections) << "\n\n";
            if (connections.empty())
            {
                output << "No network connections for this process.\n\n";
            }
            else
            {
                WriteTableHeader(output, { "Protocol", "Local", "Remote", "State", "Scope" });
                for (const Core::NetworkConnection& connection : connections)
                {
                    WriteTableRow(output, {
                        ValueOr(connection.protocol, L"(unknown)"),
                        NetworkEndpoint(connection, false),
                        NetworkEndpoint(connection, true),
                        ValueOr(connection.state, L"-"),
                        NetworkScopeText(connection)
                    });
                }
                output << "\n";
            }
        }

        output << "## Modules\n\n";
        if (!context.modulesLoaded || context.modules == nullptr)
        {
            output << "Modules were not refreshed for this process.\n\n";
        }
        else
        {
            const Core::ModuleCollectionResult& modules = *context.modules;
            if (!modules.success)
            {
                output << "Modules unavailable: "
                       << EscapeMarkdownInline(ValueOr(modules.statusMessage, L"could not inspect modules"))
                       << "\n\n";
            }
            else if (!modules.statusMessage.empty())
            {
                output << "Module status: " << EscapeMarkdownInline(modules.statusMessage) << "\n\n";
            }

            if (!modules.indicators.empty())
            {
                output << "Module indicators:\n";
                for (const std::wstring& indicator : modules.indicators)
                {
                    WriteBullet(output, indicator);
                }
                output << "\n";
            }

            if (modules.modules.empty())
            {
                output << "No modules returned for the selected process.\n\n";
            }
            else
            {
                WriteTableHeader(output, { "Module", "Base", "Size", "Readable", "Path" });
                for (const Core::ModuleInfo& module : modules.modules)
                {
                    WriteTableRow(output, {
                        ValueOr(module.moduleName, L"(unknown)"),
                        ValueOr(module.baseAddress, L"(unknown)"),
                        std::to_wstring(module.sizeBytes),
                        YesNo(module.readable),
                        ValueOr(module.modulePath, L"(path unavailable)")
                    });
                }
                output << "\n";
            }
        }

        output << "## Handles\n\n";
        if (!context.handlesLoaded || context.handles == nullptr)
        {
            output << "Handles were not refreshed for this process.\n\n";
        }
        else if (!context.handles->success)
        {
            output << "Handles unavailable: "
                   << EscapeMarkdownInline(ValueOr(context.handles->statusMessage, L"collection did not complete"))
                   << "\n\n";
        }
        else if (context.handles->handles.empty())
        {
            output << "No handles returned for this process.\n\n";
        }
        else
        {
            output << "- Total handles loaded: " << context.handles->handles.size() << "\n";
            output << "- Sensitive handles: " << context.handles->sensitiveCount << "\n\n";
            WriteTableHeader(output, { "Handle", "Type", "Target", "Access", "Sensitive", "Indicators" });
            for (const Core::HandleInfo& handle : context.handles->handles)
            {
                std::wstring target = handle.objectName;
                if (target.empty() && handle.targetPid.has_value())
                {
                    target = L"PID " + std::to_wstring(handle.targetPid.value());
                    if (!handle.targetProcessName.empty())
                    {
                        target += L" (" + handle.targetProcessName + L")";
                    }
                }
                std::wstring indicators;
                for (std::size_t index = 0; index < handle.indicators.size(); ++index)
                {
                    if (index > 0)
                    {
                        indicators += L"; ";
                    }
                    indicators += handle.indicators[index];
                }

                WriteTableRow(output, {
                    HandleValueText(handle.handleValue),
                    ValueOr(handle.objectType, L"(unknown)"),
                    ValueOr(target, L"(name unavailable)"),
                    ValueOr(handle.grantedAccess, L"(unknown)"),
                    YesNo(handle.isSensitive),
                    ValueOr(indicators, L"(none)")
                });
            }
            output << "\n";
        }

        output << "## Context Notes and Indicators\n\n";
        output << "Process indicators:\n";
        if (process->indicators.empty())
        {
            output << "- None\n";
        }
        else
        {
            for (const std::wstring& indicator : process->indicators)
            {
                WriteBullet(output, indicator);
            }
        }
        output << "\nContext notes:\n";
        if (process->contextNotes.empty())
        {
            output << "- None\n";
        }
        else
        {
            for (const std::wstring& note : process->contextNotes)
            {
                WriteBullet(output, note);
            }
        }
        output << "\n";

        output << "## Known Limitations and Disclaimer\n\n";
        output << "- This report reflects the current GlassPane snapshot and selected-process details loaded before export.\n";
        output << "- Protected, exited, higher-integrity, or cross-architecture processes may hide paths, command lines, modules, token metadata, or handles.\n";
        output << "- Unloaded sections are explicitly marked as not loaded instead of being collected during report generation.\n";
        output << "- Findings are evidence worth investigating, not proof of malicious activity.\n";
        output << "- GlassPane performs read-only inspection and does not kill, inject into, tamper with, remediate, or modify processes.\n";

        if (!output)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = L"An error occurred while writing the Markdown report.";
            }
            return false;
        }

        return true;
    }
}
