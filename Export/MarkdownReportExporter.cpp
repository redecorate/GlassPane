#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "MarkdownReportExporter.h"

#include "../Core/ChainAnalysis.h"
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

        std::wstring Utf8ToWide(const std::string& value)
        {
            if (value.empty())
            {
                return {};
            }

            const int required = MultiByteToWideChar(
                CP_UTF8,
                MB_ERR_INVALID_CHARS,
                value.data(),
                static_cast<int>(value.size()),
                nullptr,
                0);
            if (required <= 0)
            {
                return {};
            }

            std::wstring result(static_cast<std::size_t>(required), L'\0');
            MultiByteToWideChar(
                CP_UTF8,
                MB_ERR_INVALID_CHARS,
                value.data(),
                static_cast<int>(value.size()),
                result.data(),
                required);
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

        std::wstring NetworkIntelEndpoint(const Core::NetworkIndicatorMatch& match)
        {
            if (match.connection.remoteAddress.empty())
            {
                return L"(remote unavailable)";
            }
            if (match.connection.remotePort == 0)
            {
                return match.connection.remoteAddress;
            }
            return match.connection.remoteAddress + L":" + std::to_wstring(match.connection.remotePort);
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

        std::string EscapeServiceMarkdownInline(const std::wstring& value)
        {
            const std::string utf8 = WideToUtf8(value);
            std::string htmlSafe;
            htmlSafe.reserve(utf8.size() + 8);
            for (const char ch : utf8)
            {
                if (ch == '&')
                {
                    htmlSafe += "&amp;";
                }
                else if (ch == '<')
                {
                    htmlSafe += "&lt;";
                }
                else
                {
                    htmlSafe.push_back(ch);
                }
            }
            return EscapeMarkdownInline(htmlSafe);
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

        std::string PersistedTriageVerdictText(
            const Core::PersistedTriageSummary& summary)
        {
            return summary.captured
                ? Core::TriageVerdictDisplayText(summary.authoritativeVerdict)
                : std::string("Not captured");
        }

        std::string PersistedTriageDomainText(
            const Core::PersistedTriageSummary& summary)
        {
            if (summary.contributingDomains.empty())
            {
                return "None";
            }

            std::string text;
            for (const Core::EvidenceDomain domain : summary.contributingDomains)
            {
                if (!text.empty())
                {
                    text += ", ";
                }
                text += Core::EvidenceDomainDisplayText(domain);
            }
            return text;
        }

        void WritePersistedTriageRationaleSection(
            std::ostream& output,
            const char* heading,
            const std::vector<std::string>& entries,
            const char* emptyText)
        {
            output << "### " << heading << "\n\n";
            if (entries.empty())
            {
                output << emptyText << "\n\n";
                return;
            }

            for (const std::string& entry : entries)
            {
                output << "- " << EscapeMarkdownInline(entry) << "\n";
            }
            output << "\n";
        }

        void WritePersistedTriageRationale(
            std::ostream& output,
            const Core::PersistedTriageSummary& summary)
        {
            if (!summary.captured)
            {
                output << "Authoritative TriageEngine results were not captured for this process.\n\n";
                return;
            }

            if (summary.usingFallback)
            {
                output << "This schema-4 capture retained a historical legacy-fallback state. It is preserved as captured metadata and was not recomputed.\n\n";
                return;
            }

            WritePersistedTriageRationaleSection(
                output,
                "Verdict basis",
                summary.verdictBasis,
                "No review-relevant observation or completed correlation contributed.");
            WritePersistedTriageRationaleSection(
                output,
                "Completed correlations",
                summary.completedCorrelations,
                "None observed.");
            WritePersistedTriageRationaleSection(
                output,
                "Supporting context",
                summary.supportingContext,
                "None observed.");
            WritePersistedTriageRationaleSection(
                output,
                "Collection limitations",
                summary.collectionLimitations,
                "None observed.");
            WritePersistedTriageRationaleSection(
                output,
                "Evidence-integrity context",
                summary.evidenceIntegrityContext,
                "None observed.");
            WritePersistedTriageRationaleSection(
                output,
                "Unresolved correlations",
                summary.unresolvedCorrelations,
                "None observed.");
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

        std::wstring JoinServiceTruncationNotes(const Core::ServiceInfo& service)
        {
            std::vector<std::wstring> notes;
            if (service.serviceNameTruncated)
            {
                notes.emplace_back(L"service name");
            }
            if (service.displayNameTruncated)
            {
                notes.emplace_back(L"display name");
            }
            if (service.descriptionTruncated)
            {
                notes.emplace_back(L"description");
            }
            if (service.serviceAccountTruncated)
            {
                notes.emplace_back(L"configured account");
            }
            if (service.rawImagePathTruncated)
            {
                notes.emplace_back(L"raw ImagePath");
            }
            if (service.expandedImagePathTruncated)
            {
                notes.emplace_back(L"expanded ImagePath");
            }
            if (service.svchostGroupTruncated)
            {
                notes.emplace_back(L"svchost group");
            }
            if (service.pathParseMessageTruncated)
            {
                notes.emplace_back(L"path parse message");
            }
            if (service.statusMessageTruncated)
            {
                notes.emplace_back(L"service status message");
            }

            std::wstring summary;
            for (std::size_t index = 0; index < notes.size(); ++index)
            {
                if (index != 0)
                {
                    summary += L", ";
                }
                summary += notes[index];
            }
            return summary;
        }

        void WriteServiceContextSection(
            std::ostream& output,
            const Core::ServiceCollectionResult* serviceContext,
            std::uint32_t selectedPid)
        {
            constexpr std::size_t ServiceRenderCap = 32;

            const bool attempted = serviceContext != nullptr && serviceContext->attempted;
            const bool renderablePartial =
                attempted &&
                serviceContext->partial &&
                !serviceContext->services.empty();
            const bool unavailable =
                attempted &&
                !serviceContext->success &&
                !renderablePartial;
            const bool partial =
                attempted &&
                !unavailable &&
                (serviceContext->partial || serviceContext->truncated || !serviceContext->success);

            std::vector<const Core::ServiceInfo*> correlatedServices;
            if (attempted && !unavailable)
            {
                const auto correlation = serviceContext->serviceIndexesByPid.find(selectedPid);
                if (correlation != serviceContext->serviceIndexesByPid.end())
                {
                    std::vector<bool> includedIndexes(serviceContext->services.size(), false);
                    correlatedServices.reserve(
                        (std::min)(correlation->second.size(), Core::ServiceMaxRecords));
                    for (const std::size_t serviceIndex : correlation->second)
                    {
                        if (serviceIndex >= serviceContext->services.size())
                        {
                            continue;
                        }

                        const Core::ServiceInfo& service = serviceContext->services[serviceIndex];
                        if (service.scmProcessId == 0 ||
                            service.scmProcessId != selectedPid ||
                            !service.pidReliableForState)
                        {
                            continue;
                        }
                        if (includedIndexes[serviceIndex])
                        {
                            continue;
                        }
                        includedIndexes[serviceIndex] = true;
                        correlatedServices.push_back(&service);
                    }
                }
            }

            const std::size_t retainedCount = serviceContext == nullptr
                ? 0
                : serviceContext->services.size();
            const std::size_t visibleRecordCount = serviceContext == nullptr
                ? 0
                : (std::max)(serviceContext->totalEnumerated, retainedCount);
            const wchar_t* collectionStatus = !attempted
                ? L"Not captured"
                : unavailable
                    ? L"Unavailable"
                    : partial
                        ? L"Partial"
                        : L"Complete";

            output << "## Service Context\n\n";
            output << "- Selected PID: `" << selectedPid << "`\n";
            output << "- Correlated service count: " << correlatedServices.size() << "\n";
            output << "- Active service records visible to the collection: " << visibleRecordCount << "\n";
            output << "- Collection status: " << EscapeServiceMarkdownInline(collectionStatus) << "\n";
            output << "- Association: SCM-reported PID association\n\n";

            if (!attempted)
            {
                output << "> Service context was not captured in this snapshot.\n\n";
                return;
            }

            if (unavailable)
            {
                output << "> Service context could not be collected.\n\n";
                if (!serviceContext->statusMessage.empty())
                {
                    output << "Collection detail: "
                           << EscapeServiceMarkdownInline(serviceContext->statusMessage)
                           << "\n\n";
                }
                return;
            }

            if (partial)
            {
                output << "> Service context is partial. Some configuration details may be unavailable.\n\n";
            }
            if (serviceContext->truncated && visibleRecordCount > retainedCount)
            {
                output << "> " << (visibleRecordCount - retainedCount)
                       << " active service records were omitted from the collected context.\n\n";
            }
            if (serviceContext->configurationUnavailableCount != 0)
            {
                output << "- Configuration records unavailable: "
                       << serviceContext->configurationUnavailableCount << "\n";
            }
            if (serviceContext->descriptionUnavailableCount != 0)
            {
                output << "- Description records unavailable: "
                       << serviceContext->descriptionUnavailableCount << "\n";
            }
            if (!serviceContext->statusMessage.empty())
            {
                output << "- Collection detail: "
                       << EscapeServiceMarkdownInline(serviceContext->statusMessage) << "\n";
            }
            if (serviceContext->configurationUnavailableCount != 0 ||
                serviceContext->descriptionUnavailableCount != 0 ||
                !serviceContext->statusMessage.empty())
            {
                output << "\n";
            }

            if (correlatedServices.empty())
            {
                output << "> No active Windows services were correlated to this process by SCM-reported PID.\n\n";
                return;
            }

            const std::size_t renderCount = (std::min)(correlatedServices.size(), ServiceRenderCap);
            for (std::size_t serviceNumber = 0; serviceNumber < renderCount; ++serviceNumber)
            {
                const Core::ServiceInfo& service = *correlatedServices[serviceNumber];
                output << "### Associated service " << (serviceNumber + 1) << "\n\n";
                output << "- Service name: "
                       << EscapeServiceMarkdownInline(ValueOr(service.serviceName, L"(empty)")) << "\n";
                output << "- Display name: "
                       << EscapeServiceMarkdownInline(ValueOr(service.displayName, L"(empty)")) << "\n";
                output << "- Description: "
                       << (service.descriptionAvailable
                            ? EscapeServiceMarkdownInline(ValueOr(service.description, L"(empty)"))
                            : std::string("Unavailable"))
                       << "\n";

                output << "- State: "
                       << EscapeServiceMarkdownInline(Core::ServiceStateDisplayText(service.stateRaw)) << "\n";
                output << "- SCM-reported PID: `" << service.scmProcessId << "`\n";
                output << "- Process model: "
                       << EscapeServiceMarkdownInline(Core::ServiceProcessModelDisplayText(service.processModel)) << "\n";
                output << "- Service type: "
                       << EscapeServiceMarkdownInline(Core::ServiceTypeDisplayText(service.serviceTypeRaw)) << "\n";
                if (!service.svchostGroup.empty())
                {
                    output << "- svchost group: " << EscapeServiceMarkdownInline(service.svchostGroup) << "\n";
                }

                if (service.configurationAvailable)
                {
                    output << "- Configured start type: "
                           << EscapeServiceMarkdownInline(Core::ServiceStartTypeDisplayText(service.startTypeRaw)) << "\n";
                    output << "- Configured account: "
                           << EscapeServiceMarkdownInline(ValueOr(service.serviceAccount, L"(empty)")) << "\n";
                    output << "- Path parse status: "
                           << EscapeServiceMarkdownInline(Core::ServicePathParseStatusDisplayText(service.pathParseStatus)) << "\n";
                    output << "- Path confidence: "
                           << EscapeServiceMarkdownInline(Core::ServicePathConfidenceDisplayText(service.pathConfidence)) << "\n";
                    if (!service.pathParseMessage.empty())
                    {
                        output << "- Path parse detail: "
                               << EscapeServiceMarkdownInline(service.pathParseMessage) << "\n";
                    }
                    output << "\nConfigured raw ImagePath:\n\n";
                    WriteCodeBlock(output, service.rawImagePath);
                    if (!service.expandedImagePath.empty() &&
                        service.expandedImagePath != service.rawImagePath)
                    {
                        output << "\nExpanded ImagePath:\n\n";
                        WriteCodeBlock(output, service.expandedImagePath);
                    }
                    if (!service.executablePath.empty())
                    {
                        output << "\nParsed executable path:\n\n";
                        WriteCodeBlock(output, service.executablePath);
                    }
                }
                else
                {
                    output << "- Configured context: Unavailable\n";
                }

                output << "\n- Configuration metadata: "
                       << (service.configurationAvailable ? "Available" : "Unavailable") << "\n";
                output << "- Description metadata: "
                       << (service.descriptionAvailable ? "Available" : "Unavailable") << "\n";
                const std::wstring truncationNotes = JoinServiceTruncationNotes(service);
                if (!truncationNotes.empty())
                {
                    output << "- Truncated fields: " << EscapeServiceMarkdownInline(truncationNotes) << "\n";
                }
                if (!service.statusMessage.empty())
                {
                    output << "- Service status: "
                           << EscapeServiceMarkdownInline(service.statusMessage) << "\n";
                }
                output << "\n";
            }

            if (correlatedServices.size() > renderCount)
            {
                output << "> " << (correlatedServices.size() - renderCount)
                       << " additional correlated services were omitted from this report.\n\n";
            }
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

        const Core::PersistedTriageValidationResult triageValidation =
            Core::ValidatePersistedTriageSummary(context.authoritativeTriage);
        if (!triageValidation)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = L"Report context contains invalid authoritative triage data.";
            }
            return false;
        }
        const Core::NativeSourceEvidenceValidationResult evidenceValidation =
            Core::ValidateNativeSourceEvidenceRecords(
                context.nativeSourceEvidence);
        if (!evidenceValidation)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = L"Report context contains invalid native source evidence.";
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
        const Core::PersistedTriageSummary& triage = context.authoritativeTriage;

        output << "# GlassPane Selected Process Report\n\n";
        output << "- Generated: " << EscapeMarkdownInline(LocalTimestamp()) << "\n";
        output << "- GlassPane version: " << WideToUtf8(ValueOr(context.appVersion, L"(unknown)")) << "\n";
        output << "- Build configuration: " << EscapeMarkdownInline(ValueOr(context.buildConfiguration, L"(unknown)")) << "\n\n";

        output << "## Process Identity\n\n";
        WriteTableHeader(output, { "Field", "Value" });
        WriteTableRow(output, { L"Name", ValueOr(process->name, L"(unknown)") });
        WriteTableRow(output, { L"PID", std::to_wstring(process->pid) });
        WriteTableRow(output, { L"Parent PID", std::to_wstring(process->parentPid) });
        WriteTableRow(output, { L"Parent Link", ParentRelationshipStatusText(Core::GetParentRelationshipStatus(*context.snapshot, *process)) });
        WriteTableRow(output, { L"Architecture", ValueOr(process->architecture, L"(unknown)") });
        WriteTableRow(output, { L"Session", process->sessionId.has_value() ? std::to_wstring(process->sessionId.value()) : L"(unknown)" });
        WriteTableRow(output, { L"Start Time", process->hasCreationTime ? process->creationTimeLocal : L"(unavailable)" });
        WriteTableRow(output, {
            L"Authoritative triage",
            triage.captured
                ? Utf8ToWide(
                    Core::TriageVerdictDisplayText(triage.authoritativeVerdict))
                : L"Not captured"
        });
        output << "\nExecutable path:\n\n";
        WriteCodeBlock(output, process->executablePath.empty() ? L"(not accessible)" : process->executablePath);
        output << "\nCommand line:\n\n";
        WriteCodeBlock(output, process->commandLine.empty() ? L"(empty or not accessible)" : process->commandLine);
        output << "\n";

        output << "## Triage Summary\n\n";
        output << "- Process: " << EscapeMarkdownInline(ValueOr(process->name, L"(unknown)")) << "\n";
        output << "- PID: `" << process->pid << "`\n";
        output << "- Triage verdict: "
               << EscapeMarkdownInline(PersistedTriageVerdictText(triage))
               << "\n";
        output << "- Analysis level: "
               << EscapeMarkdownInline(
                    Core::PersistedTriageAnalysisLevelDisplayText(triage.analysisLevel))
               << "\n";
        output << "- TriageEngine result available: "
               << (triage.captured && triage.evaluationSucceeded &&
                       !triage.usingFallback
                    ? "Yes" : "No")
               << "\n";
        if (triage.captured && triage.usingFallback)
        {
            output << "- Fallback reason: "
                   << EscapeMarkdownInline(triage.fallbackReason)
                   << "\n";
        }
        output << "- Triage model: ";
        if (triage.captured)
        {
            output << triage.triageModelVersion;
        }
        else
        {
            output << "Not captured";
        }
        output << "\n";
        if (triage.captured &&
            triage.analysisLevel == Core::PersistedTriageAnalysisLevel::Enriched &&
            triage.baselineVerdictAvailable)
        {
            output << "- Baseline verdict: "
                   << EscapeMarkdownInline(
                        Core::TriageVerdictDisplayText(triage.baselineVerdict))
                   << "\n";
            output << "- Enriched evidence changed verdict: "
                   << (triage.enrichedChangedVerdict ? "Yes" : "No")
                   << "\n";
        }
        output << "- Contributing domains: "
               << EscapeMarkdownInline(PersistedTriageDomainText(triage))
               << "\n";
        const std::size_t availableSourceEvidenceCount =
            context.nativeSourceEvidence.size() +
            context.historicalLegacyEvidence.size();
        output << "- Source evidence count: "
               << (triage.captured
                    ? triage.sourceEvidenceCount
                    : availableSourceEvidenceCount)
               << "\n";
        if (triage.captured &&
            triage.sourceEvidenceCount != availableSourceEvidenceCount)
        {
            output << "- Source evidence rows available in this report: "
                   << availableSourceEvidenceCount << "\n";
        }
        output << "\n";

        WritePersistedTriageRationale(output, triage);

        output << "## Source Evidence\n\n";
        if (!context.nativeSourceEvidence.empty())
        {
            output << "These bounded native records were projected from refined typed observations. They distinguish verdict contribution, supporting context, and collection limitations.\n\n";
            for (const Core::NativeSourceEvidenceRecord& evidence :
                 context.nativeSourceEvidence)
            {
                output << "### "
                       << EscapeMarkdownInline(evidence.title.empty()
                            ? evidence.stableRuleId
                            : evidence.title)
                       << "\n\n";
                output << "- Rule: `"
                       << EscapeMarkdownInline(evidence.stableRuleId)
                       << "`\n";
                output << "- Domain: "
                       << EscapeMarkdownInline(
                            Core::EvidenceDomainDisplayText(evidence.domain))
                       << "\n";
                output << "- Disposition: "
                       << EscapeMarkdownInline(
                            Core::ObservationDispositionDisplayText(
                                evidence.disposition))
                       << "\n";
                output << "- Strength / confidence: "
                       << EscapeMarkdownInline(
                            Core::ObservationStrengthDisplayText(
                                evidence.strength))
                       << " / "
                       << EscapeMarkdownInline(
                            Core::ObservationConfidenceDisplayText(
                                evidence.confidence))
                       << "\n";
                output << "- Verdict role: "
                       << (evidence.collectionLimitation
                            ? "Collection limitation"
                            : evidence.contributedToVerdict
                                ? "Contributing evidence"
                                : "Supporting context")
                       << "\n";
                if (!evidence.summary.empty())
                {
                    output << "- Summary: "
                           << EscapeMarkdownInline(evidence.summary)
                           << "\n";
                }
                if (!evidence.details.empty())
                {
                    output << "- Details:\n";
                    for (const std::string& detail : evidence.details)
                    {
                        output << "  - "
                               << EscapeMarkdownInline(detail) << "\n";
                    }
                }
                if (!evidence.limitations.empty())
                {
                    output << "- Limitations:\n";
                    for (const std::string& limitation : evidence.limitations)
                    {
                        output << "  - "
                               << EscapeMarkdownInline(limitation) << "\n";
                    }
                }
                output << "\n";
            }
        }
        else if (context.historicalLegacyEvidence.empty())
        {
            output << "No native source-evidence records were retained for this process.\n\n";
        }

        if (!context.historicalLegacyEvidence.empty())
        {
            output << "## Historical Source Evidence\n\n";
            output << "These imported records preserve pre-native snapshot wording and severity as historical metadata only. They were not reinterpreted as current observations.\n\n";
            for (const Core::Finding& finding :
                 context.historicalLegacyEvidence)
            {
                output << "### " << EscapeMarkdownInline(Core::HistoricalFindingSeverityText(finding))
                       << ": " << EscapeMarkdownInline(ValueOr(finding.title, L"(untitled finding)")) << "\n\n";
                output << "- Historical source severity: " <<
                    EscapeMarkdownInline(Core::HistoricalFindingSeverityText(finding)) << "\n";
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

        WriteServiceContextSection(output, context.serviceContext, process->pid);

        output << "## Parent Chain\n\n";
        if (chain.parentChain.empty())
        {
            output << "Parent chain unavailable for this process.\n\n";
        }
        else
        {
            output << EscapeMarkdownInline(chain.formattedParentChain.empty() ? Core::FormatParentChain(*context.snapshot, process->pid) : chain.formattedParentChain) << "\n\n";
            WriteTableHeader(output, { "PID", "Process" });
            for (const Core::ChainProcessSummary& chainProcess : chain.parentChain)
            {
                WriteTableRow(output, {
                    std::to_wstring(chainProcess.pid),
                    ValueOr(chainProcess.name, L"(unknown)")
                });
            }
            output << "\n";
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
            WriteTableRow(output, { L"Guard regions", std::to_wstring(memory.guardRegions) });
            output << "\n";

            std::vector<const Core::MemoryRegionInfo*> executableContextRegions;
            for (const Core::MemoryRegionInfo& region : memory.regions)
            {
                if (region.isExecutable || region.isGuard)
                {
                    executableContextRegions.push_back(&region);
                }
            }

            if (executableContextRegions.empty())
            {
                output << "No executable or guarded memory-region metadata was retained.\n\n";
            }
            else
            {
                output << "Executable and guarded memory-region context:\n\n";
                WriteTableHeader(output, { "Base", "Size", "Type", "Protection", "Writable", "Executable", "Private", "Guarded", "Mapped File" });
                constexpr std::size_t MaxMemoryRows = 40;
                const std::size_t rowsToWrite = std::min(executableContextRegions.size(), MaxMemoryRows);
                for (std::size_t index = 0; index < rowsToWrite; ++index)
                {
                    const Core::MemoryRegionInfo& region = *executableContextRegions[index];
                    WriteTableRow(output, {
                        ValueOr(region.baseAddressString, L"(unknown)"),
                        ValueOr(region.regionSizeString, L"(unknown)"),
                        ValueOr(region.typeName, L"(unknown)"),
                        ValueOr(region.protectName, L"(unknown)"),
                        YesNo(region.isWritable),
                        YesNo(region.isExecutable),
                        YesNo(region.isPrivate),
                        YesNo(region.isGuard),
                        ValueOr(region.mappedFilePath, L"(none)")
                    });
                }
                if (executableContextRegions.size() > MaxMemoryRows)
                {
                    output << "\nAdditional memory rows omitted: " << (executableContextRegions.size() - MaxMemoryRows) << ".\n";
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

        output << "## Network Intelligence Matches\n\n";
        if (!context.networkIntelFeedLoaded)
        {
            output << "Network intelligence feed was not loaded.\n\n";
        }
        else if (context.networkIndicatorMatches == nullptr)
        {
            output << "Network intelligence match data was not included in this report context.\n\n";
        }
        else if (context.networkIndicatorMatches->empty())
        {
            output << "No network intelligence matches were found for loaded network data.\n\n";
        }
        else
        {
            if (context.networkIndicatorFeed != nullptr)
            {
                output << "Feed: "
                       << EscapeMarkdownInline(ValueOr(context.networkIndicatorFeed->metadata.feedName, L"(unnamed feed)"))
                       << " ("
                       << context.networkIndicatorFeed->indicators.size()
                       << " indicator";
                if (context.networkIndicatorFeed->indicators.size() != 1)
                {
                    output << "s";
                }
                output << ")\n\n";
            }
            else if (!context.networkIntelStatusMessage.empty())
            {
                output << EscapeMarkdownInline(context.networkIntelStatusMessage) << "\n\n";
            }

            WriteTableHeader(output, { "Remote Endpoint", "Category", "Severity", "Confidence", "Source", "Last Seen", "Description" });
            for (const Core::NetworkIndicatorMatch& match : *context.networkIndicatorMatches)
            {
                WriteTableRow(output, {
                    NetworkIntelEndpoint(match),
                    ValueOr(match.indicator.category, L"(unspecified)"),
                    ValueOr(match.indicator.severity, L"(unspecified)"),
                    ValueOr(match.indicator.confidence, L"(unspecified)"),
                    ValueOr(match.indicator.source, L"(unspecified)"),
                    ValueOr(match.indicator.lastSeen, L"(unknown)"),
                    ValueOr(match.indicator.description, L"")
                });
            }
            output << "\n";
            output << "Network intelligence matches mean the endpoint appears in the local indicator feed. They are evidence worth reviewing, not proof of malicious activity.\n\n";
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
        else
        {
            if (context.handles->IsPartial())
            {
                output << "- Collection status: Partial\n";
                output << "- Retained handles: "
                       << context.handles->handles.size() << "\n";
                output << "- Selected-process handles reported: "
                       << context.handles->selectedProcessHandlesMatched << "\n";
                if (context.handles->selectedProcessHandlesOmitted != 0)
                {
                    output << "- Selected-process handles omitted: "
                           << context.handles->selectedProcessHandlesOmitted
                           << "\n";
                }
                const std::size_t incompleteNames =
                    context.handles->namesSkipped +
                    context.handles->namesFailed;
                if (incompleteNames != 0)
                {
                    output << "- Object names skipped or unresolved: "
                           << incompleteNames << "\n";
                }
                output << "\nCollection limitation: "
                       << EscapeMarkdownInline(ValueOr(
                            context.handles->statusMessage,
                            L"Additional handles or optional metadata may not have been evaluated because safety limits were reached."))
                       << "\n\n";
            }

            if (context.handles->handles.empty())
            {
                output << "No handles returned for this process.\n\n";
            }
            else
            {
                if (!context.handles->IsPartial())
                {
                    output << "- Total handles loaded: "
                           << context.handles->handles.size() << "\n\n";
                }
                WriteTableHeader(output, { "Handle", "Type", "Target", "Access", "Decoded Access" });
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
                    else if (target.empty() && handle.targetThreadId.has_value())
                    {
                        target = L"TID " +
                            std::to_wstring(handle.targetThreadId.value());
                    }
                    std::wstring decodedAccess;
                    for (std::size_t index = 0; index < handle.decodedAccess.size(); ++index)
                    {
                        if (index > 0)
                        {
                            decodedAccess += L"; ";
                        }
                        decodedAccess += handle.decodedAccess[index];
                    }

                    WriteTableRow(output, {
                        HandleValueText(handle.handleValue),
                        ValueOr(handle.objectType, L"(unknown)"),
                        ValueOr(target, L"(name unavailable)"),
                        ValueOr(handle.grantedAccess, L"(unknown)"),
                        ValueOr(decodedAccess, L"(none)")
                    });
                }
                output << "\n";
            }
        }

        output << "## Additional Collection Context\n\n";
        output << "Context notes:\n";
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
        output << "- Source evidence is worth reviewing and is not proof of malicious activity.\n";
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

    bool ExportSnapshotCompareMarkdownReport(
        const SnapshotCompareMarkdownReportContext& context,
        const std::wstring& filePath,
        std::wstring* errorMessage)
    {
        if (context.baseline == nullptr || context.current == nullptr || context.result == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = L"Snapshot compare report context is incomplete.";
            }
            return false;
        }

        if (!context.baseline->captured || !context.current->captured ||
            !context.result->hasBaseline || !context.result->hasCurrent)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = L"Capture both baseline and current snapshots before exporting a compare report.";
            }
            return false;
        }

        std::ofstream output(filePath, std::ios::binary | std::ios::trunc);
        if (!output)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = L"Could not open the compare report file for writing.";
            }
            return false;
        }

        const Core::SnapshotCompareResult& result = *context.result;
        const auto endpointText = [](const Core::SnapshotNetworkEndpoint& endpoint, bool remote) {
            const std::wstring& address = remote ? endpoint.remoteAddress : endpoint.localAddress;
            const std::uint16_t port = remote ? endpoint.remotePort : endpoint.localPort;
            if (remote && (endpoint.isListening || endpoint.protocol == L"UDP" || address.empty() || port == 0))
            {
                return std::wstring(L"-");
            }
            if (address.empty())
            {
                return std::wstring(L"(unknown)");
            }
            return address + L":" + std::to_wstring(port);
        };

        constexpr std::size_t MaxCompareReportRows = 200;

        const auto writeTruncationNote = [&output](std::size_t written, std::size_t total) {
            if (total > written)
            {
                output << "\n_Report section truncated. "
                       << (total - written)
                       << " additional row(s) omitted._\n";
            }
        };

        const auto cappedCount = [MaxCompareReportRows](std::size_t total) {
            return std::min<std::size_t>(MaxCompareReportRows, total);
        };

        const auto nativeLimitationsText = [](
            const std::vector<std::string>& limitations) {
            std::vector<std::string> canonical = limitations;
            std::sort(canonical.begin(), canonical.end());
            canonical.erase(
                std::unique(canonical.begin(), canonical.end()),
                canonical.end());
            if (canonical.empty())
            {
                return std::wstring(L"None");
            }
            std::wstringstream text;
            for (std::size_t index = 0; index < canonical.size(); ++index)
            {
                if (index != 0)
                {
                    text << L"; ";
                }
                text << Utf8ToWide(canonical[index]);
            }
            return text.str();
        };

        const auto writeNativeEvidenceRows =
            [&output,
             &writeTruncationNote,
             &cappedCount,
             &nativeLimitationsText](
                const std::vector<Core::NativeSourceEvidenceRecord>& records,
                const wchar_t* observation) {
                WriteTableHeader(output, {
                    "Observation",
                    "Stable Rule",
                    "Domain",
                    "Disposition",
                    "Artifact Family",
                    "Contributed",
                    "Collection Limitation",
                    "Limitations"
                });
                const std::size_t rowsToWrite = cappedCount(records.size());
                for (std::size_t index = 0; index < rowsToWrite; ++index)
                {
                    const Core::NativeSourceEvidenceRecord& record =
                        records[index];
                    WriteTableRow(output, {
                        observation,
                        ValueOr(
                            Utf8ToWide(record.stableRuleId),
                            L"(missing)"),
                        Utf8ToWide(
                            Core::EvidenceDomainDisplayText(record.domain)),
                        Utf8ToWide(
                            Core::ObservationDispositionDisplayText(
                                record.disposition)),
                        ValueOr(
                            Utf8ToWide(record.artifactFamily),
                            L"(none)"),
                        YesNo(record.contributedToVerdict),
                        YesNo(record.collectionLimitation),
                        nativeLimitationsText(record.limitations)
                    });
                }
                writeTruncationNote(rowsToWrite, records.size());
                output << "\n";
            };

        const auto writeProcessRows = [&output, &writeTruncationNote, &cappedCount](
            const std::vector<Core::SnapshotProcessRecord>& records,
            const wchar_t* observation) {
            WriteTableHeader(output, {
                "Observation",
                "Process",
                "PID",
                "PPID",
                "Authoritative Triage",
                "Path"
            });
            const std::size_t rowsToWrite = cappedCount(records.size());
            for (std::size_t index = 0; index < rowsToWrite; ++index)
            {
                const Core::SnapshotProcessRecord& process = records[index];
                WriteTableRow(output, {
                    observation,
                    ValueOr(process.processName, L"(unknown)"),
                    std::to_wstring(process.pid),
                    std::to_wstring(process.parentPid),
                    process.authoritativeTriage.captured
                        ? Utf8ToWide(
                            Core::TriageVerdictDisplayText(
                                process.authoritativeTriage.authoritativeVerdict) +
                            " - " +
                            Core::PersistedTriageAnalysisLevelDisplayText(
                                process.authoritativeTriage.analysisLevel))
                        : std::wstring(L"Not captured"),
                    ValueOr(process.executablePath, L"(unavailable)")
                });
            }
            writeTruncationNote(rowsToWrite, records.size());
            output << "\n";
        };

        output << "# GlassPane Snapshot Compare Report\n\n";
        output << "- Generated: " << EscapeMarkdownInline(LocalTimestamp()) << "\n";
        output << "- GlassPane version: " << WideToUtf8(ValueOr(context.appVersion, L"(unknown)")) << "\n";
        output << "- Build configuration: " << EscapeMarkdownInline(ValueOr(context.buildConfiguration, L"(unknown)")) << "\n";
        output << "- Baseline captured: " << EscapeMarkdownInline(ValueOr(context.baseline->captureTimeLocal, L"(missing)")) << "\n";
        output << "- Current captured: " << EscapeMarkdownInline(ValueOr(context.current->captureTimeLocal, L"(missing)")) << "\n\n";

        output << "## Summary\n\n";
        WriteTableHeader(output, { "Metric", "Count" });
        WriteTableRow(output, { L"Baseline processes", std::to_wstring(context.baseline->processes.size()) });
        WriteTableRow(output, { L"Current processes", std::to_wstring(context.current->processes.size()) });
        WriteTableRow(output, { L"New processes", std::to_wstring(result.newProcesses.size()) });
        WriteTableRow(output, { L"Exited processes", std::to_wstring(result.exitedProcesses.size()) });
        WriteTableRow(output, { L"Changed processes", std::to_wstring(result.changedProcesses.size()) });
        WriteTableRow(output, { L"New network connections", result.networkCompared ? std::to_wstring(result.newNetworkConnections.size()) : L"Unavailable" });
        WriteTableRow(output, { L"Closed network connections", result.networkCompared ? std::to_wstring(result.closedNetworkConnections.size()) : L"Unavailable" });
        WriteTableRow(output, {
            L"Baseline source-evidence model",
            Core::SnapshotSourceEvidenceModelKindDisplayText(
                result.baselineSourceEvidenceModelKind)
        });
        WriteTableRow(output, {
            L"Current source-evidence model",
            Core::SnapshotSourceEvidenceModelKindDisplayText(
                result.currentSourceEvidenceModelKind)
        });
        WriteTableRow(output, {
            L"Selected native source evidence changes",
            result.sourceEvidenceModelMismatch
                ? L"Model mismatch"
                : result.nativeSourceEvidenceCompared
                    ? std::to_wstring(
                        result.selectedNativeEvidence.newRecords.size() +
                        result.selectedNativeEvidence.removedRecords.size() +
                        result.selectedNativeEvidence.changedRecords.size())
                    : L"Unavailable"
        });
        WriteTableRow(output, {
            L"Historical legacy source evidence changes",
            result.findingsCompared
                ? std::to_wstring(result.newFindings.size() + result.removedFindings.size() + result.changedFindings.size())
                : L"Not compared"
        });
        WriteTableRow(output, {
            L"Baseline processes with captured authoritative triage",
            std::to_wstring(result.baselineTriageCapturedProcessCount)
        });
        WriteTableRow(output, {
            L"Current processes with captured authoritative triage",
            std::to_wstring(result.currentTriageCapturedProcessCount)
        });
        WriteTableRow(output, {
            L"Comparable authoritative triage records",
            std::to_wstring(result.comparableTriageProcessCount)
        });
        WriteTableRow(output, {
            L"Authoritative triage identities unavailable",
            std::to_wstring(result.triageIdentityUnavailableCount)
        });
        WriteTableRow(output, {
            L"Authoritative triage availability changes",
            std::to_wstring(result.triageAvailabilityMismatchCount)
        });
        WriteTableRow(output, {
            L"Selected-process authoritative triage changes",
            std::to_wstring(result.selectedTriage.fields.size())
        });
        output << "\n";

        output << "## Selected Process Authoritative Triage Changes\n\n";
        if (result.selectedTriage.fields.empty())
        {
            if (result.selectedTriage.baseline.has_value() !=
                result.selectedTriage.current.has_value())
            {
                output << "Selected-process authoritative triage was captured on only one side.\n\n";
            }
            else
            {
                output << "No safely comparable selected-process authoritative triage changes were observed.\n\n";
            }
        }
        else
        {
            WriteTableHeader(output, { "Field", "Baseline", "Current" });
            for (const Core::SnapshotChangedField& field :
                result.selectedTriage.fields)
            {
                WriteTableRow(output, {
                    field.field,
                    field.baselineValue,
                    field.currentValue
                });
            }
            output << "\n";
        }

        output << "## New Processes\n\n";
        if (result.newProcesses.empty())
        {
            output << "No new processes were observed.\n\n";
        }
        else
        {
            writeProcessRows(result.newProcesses, L"New process observed");
        }

        output << "## Exited Processes\n\n";
        if (result.exitedProcesses.empty())
        {
            output << "No exited processes were observed.\n\n";
        }
        else
        {
            writeProcessRows(result.exitedProcesses, L"Process exited");
        }

        output << "## Changed Processes\n\n";
        if (result.changedProcesses.empty())
        {
            output << "No meaningful process attribute changes were observed.\n\n";
        }
        else
        {
            WriteTableHeader(output, { "Process", "PID", "Field", "Baseline", "Current" });
            std::size_t writtenRows = 0;
            for (const Core::SnapshotProcessChange& change : result.changedProcesses)
            {
                for (const Core::SnapshotChangedField& field : change.fields)
                {
                    if (writtenRows >= MaxCompareReportRows)
                    {
                        break;
                    }
                    WriteTableRow(output, {
                        ValueOr(change.current.processName, L"(unknown)"),
                        std::to_wstring(change.current.pid),
                        field.field,
                        field.baselineValue,
                        field.currentValue
                    });
                    ++writtenRows;
                }

                if (writtenRows >= MaxCompareReportRows)
                {
                    break;
                }
            }
            std::size_t totalRows = 0;
            for (const Core::SnapshotProcessChange& change : result.changedProcesses)
            {
                totalRows += change.fields.size();
            }
            writeTruncationNote(writtenRows, totalRows);
            output << "\n";
        }

        output << "## Network Changes\n\n";
        if (!result.networkCompared)
        {
            output << "Network comparison unavailable because network data was not loaded or did not collect successfully for both snapshots.\n\n";
        }
        else if (result.newNetworkConnections.empty() && result.closedNetworkConnections.empty())
        {
            output << "No network connection changes were observed in the captured socket ownership data.\n\n";
        }
        else
        {
            if (!result.newNetworkConnections.empty())
            {
                output << "### New Connections\n\n";
                WriteTableHeader(output, { "Observation", "Process", "PID", "Protocol", "Local", "Remote", "State" });
                const std::size_t rowsToWrite = cappedCount(result.newNetworkConnections.size());
                for (std::size_t index = 0; index < rowsToWrite; ++index)
                {
                    const Core::SnapshotNetworkEndpoint& endpoint = result.newNetworkConnections[index];
                    WriteTableRow(output, {
                        L"Network connection appeared",
                        ValueOr(endpoint.processName, L"(unknown)"),
                        std::to_wstring(endpoint.owningPid),
                        ValueOr(endpoint.protocol, L"(unknown)"),
                        endpointText(endpoint, false),
                        endpointText(endpoint, true),
                        ValueOr(endpoint.state, L"-")
                    });
                }
                writeTruncationNote(rowsToWrite, result.newNetworkConnections.size());
                output << "\n";
            }

            if (!result.closedNetworkConnections.empty())
            {
                output << "### Closed Connections\n\n";
                WriteTableHeader(output, { "Observation", "Process", "PID", "Protocol", "Local", "Remote", "State" });
                const std::size_t rowsToWrite = cappedCount(result.closedNetworkConnections.size());
                for (std::size_t index = 0; index < rowsToWrite; ++index)
                {
                    const Core::SnapshotNetworkEndpoint& endpoint = result.closedNetworkConnections[index];
                    WriteTableRow(output, {
                        L"Network connection closed",
                        ValueOr(endpoint.processName, L"(unknown)"),
                        std::to_wstring(endpoint.owningPid),
                        ValueOr(endpoint.protocol, L"(unknown)"),
                        endpointText(endpoint, false),
                        endpointText(endpoint, true),
                        ValueOr(endpoint.state, L"-")
                    });
                }
                writeTruncationNote(rowsToWrite, result.closedNetworkConnections.size());
                output << "\n";
            }
        }

        output << "## Selected Native Source Evidence Changes\n\n";
        if (result.sourceEvidenceModelMismatch)
        {
            output << "The captures use different source-evidence models. Native and historical records were kept separate and were not title-matched.\n\n";
        }
        else if (result.nativeSourceEvidenceModelVersionMismatch)
        {
            output << "Native source-evidence model versions differ, so selected records were not semantically compared.\n\n";
        }
        else if (result.baselineSourceEvidenceModelKind !=
            Core::SnapshotSourceEvidenceModelKind::Native)
        {
            output << "Not applicable because these captures do not both use the native source-evidence model.\n\n";
        }
        else if (result.selectedNativeEvidence.availabilityMismatch)
        {
            output << "Selected native source evidence was captured on only one side and was not semantically compared.\n\n";
        }
        else if (!result.selectedNativeEvidence.semanticCompared)
        {
            output << "No safely identified selected-process native source-evidence pair was available for semantic comparison.\n\n";
        }
        else if (result.selectedNativeEvidence.newRecords.empty() &&
            result.selectedNativeEvidence.removedRecords.empty() &&
            result.selectedNativeEvidence.changedRecords.empty())
        {
            output << "No semantic selected-process native source-evidence changes were observed. Presentation-only title, summary, detail, provenance, strength, and confidence changes do not affect this comparison.\n\n";
        }
        else
        {
            if (!result.selectedNativeEvidence.newRecords.empty())
            {
                output << "### Native Evidence Appeared\n\n";
                writeNativeEvidenceRows(
                    result.selectedNativeEvidence.newRecords,
                    L"Appeared");
            }

            if (!result.selectedNativeEvidence.changedRecords.empty())
            {
                output << "### Native Evidence Changed\n\n";
                WriteTableHeader(output, {
                    "Stable Rule",
                    "Domain",
                    "Disposition",
                    "Artifact Family",
                    "Field",
                    "Baseline",
                    "Current"
                });
                std::size_t writtenRows = 0;
                for (const Core::SnapshotNativeSourceEvidenceChange& change :
                     result.selectedNativeEvidence.changedRecords)
                {
                    for (const Core::SnapshotChangedField& field :
                         change.fields)
                    {
                        if (writtenRows >= MaxCompareReportRows)
                        {
                            break;
                        }
                        WriteTableRow(output, {
                            ValueOr(
                                Utf8ToWide(change.current.stableRuleId),
                                L"(missing)"),
                            Utf8ToWide(
                                Core::EvidenceDomainDisplayText(
                                    change.current.domain)),
                            Utf8ToWide(
                                Core::ObservationDispositionDisplayText(
                                    change.current.disposition)),
                            ValueOr(
                                Utf8ToWide(change.current.artifactFamily),
                                L"(none)"),
                            field.field,
                            field.baselineValue,
                            field.currentValue
                        });
                        ++writtenRows;
                    }
                    if (writtenRows >= MaxCompareReportRows)
                    {
                        break;
                    }
                }
                std::size_t totalRows = 0;
                for (const Core::SnapshotNativeSourceEvidenceChange& change :
                     result.selectedNativeEvidence.changedRecords)
                {
                    totalRows += change.fields.size();
                }
                writeTruncationNote(writtenRows, totalRows);
                output << "\n";
            }

            if (!result.selectedNativeEvidence.removedRecords.empty())
            {
                output << "### Native Evidence Removed\n\n";
                writeNativeEvidenceRows(
                    result.selectedNativeEvidence.removedRecords,
                    L"Removed");
            }
        }

        output << "## Historical Legacy Source Evidence Changes\n\n";
        if (!result.findingsCompared)
        {
            output << "Historical legacy source evidence was not compared. This section is used only when both captures retain the historical model.\n\n";
        }
        else if (result.newFindings.empty() && result.removedFindings.empty() && result.changedFindings.empty())
        {
            output << "No historical legacy source-finding or process-indicator changes were observed.\n\n";
        }
        else
        {
            if (!result.newFindings.empty())
            {
                output << "### New Historical Legacy Source Findings\n\n";
                WriteTableHeader(output, { "Observation", "Historical Legacy Source Severity", "Process", "PID", "Source Finding", "Category" });
                const std::size_t rowsToWrite = cappedCount(result.newFindings.size());
                for (std::size_t index = 0; index < rowsToWrite; ++index)
                {
                    const Core::SnapshotFindingRecord& finding = result.newFindings[index];
                    WriteTableRow(output, {
                        L"Historical legacy source finding appeared",
                        Core::SnapshotFindingSeverityText(finding),
                        ValueOr(finding.processName, L"(unknown)"),
                        std::to_wstring(finding.pid),
                        ValueOr(finding.title, L"(untitled)"),
                        ValueOr(finding.category, L"(none)")
                    });
                }
                writeTruncationNote(rowsToWrite, result.newFindings.size());
                output << "\n";
            }

            if (!result.changedFindings.empty())
            {
                output << "### Changed Historical Legacy Source Findings\n\n";
                WriteTableHeader(output, { "Process", "PID", "Source Finding", "Baseline Historical Legacy Source Severity", "Current Historical Legacy Source Severity" });
                const std::size_t rowsToWrite = cappedCount(result.changedFindings.size());
                for (std::size_t index = 0; index < rowsToWrite; ++index)
                {
                    const Core::SnapshotFindingChange& change = result.changedFindings[index];
                    WriteTableRow(output, {
                        ValueOr(change.current.processName, L"(unknown)"),
                        std::to_wstring(change.current.pid),
                        ValueOr(change.current.title, L"(untitled)"),
                        Core::SnapshotFindingSeverityText(change.baseline),
                        Core::SnapshotFindingSeverityText(change.current)
                    });
                }
                writeTruncationNote(rowsToWrite, result.changedFindings.size());
                output << "\n";
            }

            if (!result.removedFindings.empty())
            {
                output << "### Removed Historical Legacy Source Findings\n\n";
                WriteTableHeader(output, { "Observation", "Historical Legacy Source Severity", "Process", "PID", "Source Finding", "Category" });
                const std::size_t rowsToWrite = cappedCount(result.removedFindings.size());
                for (std::size_t index = 0; index < rowsToWrite; ++index)
                {
                    const Core::SnapshotFindingRecord& finding = result.removedFindings[index];
                    WriteTableRow(output, {
                        L"Historical legacy source finding removed",
                        Core::SnapshotFindingSeverityText(finding),
                        ValueOr(finding.processName, L"(unknown)"),
                        std::to_wstring(finding.pid),
                        ValueOr(finding.title, L"(untitled)"),
                        ValueOr(finding.category, L"(none)")
                    });
                }
                writeTruncationNote(rowsToWrite, result.removedFindings.size());
                output << "\n";
            }
        }

        output << "## Notes and Limitations\n\n";
        if (result.notes.empty())
        {
            output << "- No compare-specific limitations were recorded.\n";
        }
        else
        {
            for (const std::wstring& note : result.notes)
            {
                WriteBullet(output, note);
            }
        }
        output << "- Snapshot compare is local and in-memory.\n";
        output << "- New or changed evidence is context worth reviewing, not proof of malicious activity.\n";
        output << "- GlassPane performs read-only inspection and does not kill, inject into, tamper with, remediate, or modify processes.\n";

        if (!output)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = L"An error occurred while writing the compare report.";
            }
            return false;
        }

        return true;
    }
}
