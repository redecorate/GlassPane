#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "JsonExporter.h"

#include "../Core/ChainAnalysis.h"
#include "../Core/FileIdentity.h"
#include "../Core/HandleInfo.h"
#include "../Core/RuntimeInfo.h"
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

        void WriteJsonString(std::ostream& output, const std::string& value)
        {
            output << '"' << EscapeJson(value) << '"';
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

        void WriteJsonStringArray(std::ostream& output, const std::vector<std::string>& values)
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

        void WritePersistedTriageSummary(
            std::ostream& output,
            const Core::PersistedTriageSummary& summary,
            const std::string& indent)
        {
            output << "{\n";
            output << indent << "  \"captured\": "
                   << (summary.captured ? "true" : "false") << ",\n";
            output << indent << "  \"evaluation_succeeded\": "
                   << (summary.evaluationSucceeded ? "true" : "false") << ",\n";
            if (summary.analysisLevel ==
                Core::PersistedTriageAnalysisLevel::LegacyFallback)
            {
                output << indent << "  \"historical_legacy_fallback\": true,\n";
            }
            output << indent << "  \"analysis_level\": ";
            WriteJsonString(
                output,
                Core::PersistedTriageAnalysisLevelDisplayText(summary.analysisLevel));
            output << ",\n";
            output << indent << "  \"authoritative_verdict\": ";
            WriteJsonString(
                output,
                summary.captured
                    ? Core::TriageVerdictDisplayText(summary.authoritativeVerdict)
                    : std::string("Not captured"));
            output << ",\n";
            output << indent << "  \"baseline_verdict\": ";
            if (summary.baselineVerdictAvailable)
            {
                WriteJsonString(
                    output,
                    Core::TriageVerdictDisplayText(summary.baselineVerdict));
            }
            else
            {
                output << "null";
            }
            output << ",\n";
            output << indent << "  \"enriched_changed_verdict\": "
                   << (summary.enrichedChangedVerdict ? "true" : "false") << ",\n";
            output << indent << "  \"triage_model_version\": "
                   << summary.triageModelVersion << ",\n";
            output << indent << "  \"source_evidence_count\": "
                   << summary.sourceEvidenceCount << ",\n";
            output << indent << "  \"contributing_domains\": [";
            for (std::size_t index = 0; index < summary.contributingDomains.size(); ++index)
            {
                if (index > 0)
                {
                    output << ", ";
                }
                WriteJsonString(
                    output,
                    Core::EvidenceDomainDisplayText(summary.contributingDomains[index]));
            }
            output << "],\n";
            output << indent << "  \"verdict_basis\": ";
            WriteJsonStringArray(output, summary.verdictBasis);
            output << ",\n";
            output << indent << "  \"completed_correlations\": ";
            WriteJsonStringArray(output, summary.completedCorrelations);
            output << ",\n";
            output << indent << "  \"supporting_context\": ";
            WriteJsonStringArray(output, summary.supportingContext);
            output << ",\n";
            output << indent << "  \"collection_limitations\": ";
            WriteJsonStringArray(output, summary.collectionLimitations);
            output << ",\n";
            output << indent << "  \"evidence_integrity_context\": ";
            WriteJsonStringArray(output, summary.evidenceIntegrityContext);
            output << ",\n";
            output << indent << "  \"unresolved_correlations\": ";
            WriteJsonStringArray(output, summary.unresolvedCorrelations);
            output << ",\n";
            if (summary.analysisLevel ==
                Core::PersistedTriageAnalysisLevel::LegacyFallback)
            {
                output << indent <<
                    "  \"historical_legacy_fallback_reason\": ";
                WriteJsonString(output, summary.fallbackReason);
                output << ",\n";
            }
            output << indent << "  \"status\": ";
            WriteJsonString(output, summary.status);
            output << "\n" << indent << "}";
        }

        void WriteFileIdentityObject(
            std::ostream& output,
            const Core::FileIdentity& identity,
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
                output << "      \"legacy_source_severity_captured\": " <<
                    (finding.severityCaptured ? "true" : "false") << ",\n";
                output << "      \"legacy_source_severity\": ";
                if (finding.severityCaptured)
                {
                    WriteJsonString(output, Core::FindingSeverityToString(finding.severity));
                }
                else
                {
                    output << "null";
                }
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

        void WriteNativeSourceEvidenceArray(
            std::ostream& output,
            const std::vector<Core::NativeSourceEvidenceRecord>& records)
        {
            output << "[\n";
            for (std::size_t index = 0; index < records.size(); ++index)
            {
                const Core::NativeSourceEvidenceRecord& record = records[index];
                output << "    {\n";
                output << "      \"stable_rule_id\": ";
                WriteJsonString(output, record.stableRuleId);
                output << ",\n      \"title\": ";
                WriteJsonString(output, record.title);
                output << ",\n      \"summary\": ";
                WriteJsonString(output, record.summary);
                output << ",\n      \"details\": ";
                WriteJsonStringArray(output, record.details);
                output << ",\n      \"limitations\": ";
                WriteJsonStringArray(output, record.limitations);
                output << ",\n      \"domain\": ";
                WriteJsonString(output, Core::EvidenceDomainDisplayText(record.domain));
                output << ",\n      \"disposition\": ";
                WriteJsonString(output, Core::ObservationDispositionDisplayText(record.disposition));
                output << ",\n      \"strength\": ";
                WriteJsonString(output, Core::ObservationStrengthDisplayText(record.strength));
                output << ",\n      \"confidence\": ";
                WriteJsonString(output, Core::ObservationConfidenceDisplayText(record.confidence));
                output << ",\n      \"artifact_family\": ";
                WriteJsonString(output, record.artifactFamily);
                output << ",\n      \"provenance_summary\": ";
                WriteJsonString(output, record.provenanceSummary);
                output << ",\n      \"contributed_to_verdict\": "
                       << (record.contributedToVerdict ? "true" : "false");
                output << ",\n      \"suppressed_duplicate\": "
                       << (record.suppressedDuplicate ? "true" : "false");
                output << ",\n      \"collection_limitation\": "
                       << (record.collectionLimitation ? "true" : "false")
                       << "\n    }";
                if (index + 1 < records.size())
                {
                    output << ',';
                }
                output << '\n';
            }
            output << "  ]";
        }

        void WriteModuleArray(
            std::ostream& output,
            const std::vector<Core::ModuleInfo>& modules,
            const std::vector<Core::FileIdentity>* fileIdentities)
        {
            output << "[\n";
            for (std::size_t index = 0; index < modules.size(); ++index)
            {
                const Core::ModuleInfo& module = modules[index];
                const Core::FileIdentity* fileIdentity =
                    fileIdentities != nullptr && index < fileIdentities->size()
                        ? &(*fileIdentities)[index]
                        : nullptr;
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
                output << "        \"fileIdentityCaptured\": "
                       << (fileIdentity != nullptr ? "true" : "false") << ",\n";
                output << "        \"fileIdentity\": ";
                if (fileIdentity != nullptr)
                {
                    WriteFileIdentityObject(output, *fileIdentity, "        ");
                }
                else
                {
                    output << "null";
                }
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

        const char* HandleCollectionStateText(
            Core::HandleCollectionState state)
        {
            switch (state)
            {
            case Core::HandleCollectionState::NotAttempted:
                return "not_attempted";
            case Core::HandleCollectionState::Success:
                return "success";
            case Core::HandleCollectionState::Partial:
                return "partial";
            case Core::HandleCollectionState::Unavailable:
                return "unavailable";
            case Core::HandleCollectionState::Failed:
                return "failed";
            default:
                return "failed";
            }
        }

        const char* HandleQueryFailureKindText(
            Core::HandleQueryFailureKind kind)
        {
            switch (kind)
            {
            case Core::HandleQueryFailureKind::None:
                return "none";
            case Core::HandleQueryFailureKind::BudgetExceeded:
                return "budget_exceeded";
            case Core::HandleQueryFailureKind::AllocationFailed:
                return "allocation_failed";
            case Core::HandleQueryFailureKind::ApiUnavailable:
                return "api_unavailable";
            case Core::HandleQueryFailureKind::ApiFailed:
                return "api_failed";
            case Core::HandleQueryFailureKind::InvalidBuffer:
                return "invalid_buffer";
            default:
                return "none";
            }
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
                output << indent << "    \"objectTypeIndex\": " << handle.objectTypeIndex << ",\n";
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
                output << indent << "    \"targetThreadId\": ";
                if (handle.targetThreadId.has_value())
                {
                    output << handle.targetThreadId.value();
                }
                else
                {
                    output << "null";
                }
                output << ",\n";
                output << indent << "    \"targetProcessName\": ";
                WriteJsonString(output, handle.targetProcessName);
                output << ",\n";
                output << indent << "    \"typeResolved\": " << (handle.typeResolved ? "true" : "false") << ",\n";
                output << indent << "    \"nameResolved\": " << (handle.nameResolved ? "true" : "false") << ",\n";
                output << indent << "    \"decodedAccess\": ";
                WriteJsonStringArray(output, handle.decodedAccess);
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
            output << indent << "  \"collectionState\": \""
                   << HandleCollectionStateText(
                        handles != nullptr
                            ? handles->state
                            : Core::HandleCollectionState::NotAttempted)
                   << "\",\n";
            output << indent << "  \"queryFailureKind\": \""
                   << HandleQueryFailureKindText(
                        handles != nullptr
                            ? handles->queryFailureKind
                            : Core::HandleQueryFailureKind::None)
                   << "\",\n";
            output << indent << "  \"success\": " << (handles != nullptr && handles->success ? "true" : "false") << ",\n";
            output << indent << "  \"statusMessage\": ";
            WriteJsonString(output, handles != nullptr ? handles->statusMessage : L"Handle inspection was not loaded before export.");
            output << ",\n";
            output << indent << "  \"systemHandleCount\": " << (handles != nullptr ? handles->systemHandleCount : 0) << ",\n";
            output << indent << "  \"systemEntriesScanned\": " << (handles != nullptr ? handles->systemEntriesScanned : 0) << ",\n";
            output << indent << "  \"selectedProcessHandlesMatched\": " << (handles != nullptr ? handles->selectedProcessHandlesMatched : 0) << ",\n";
            output << indent << "  \"selectedProcessHandlesOmitted\": " << (handles != nullptr ? handles->selectedProcessHandlesOmitted : 0) << ",\n";
            output << indent << "  \"namesAttempted\": " << (handles != nullptr ? handles->namesAttempted : 0) << ",\n";
            output << indent << "  \"namesResolved\": " << (handles != nullptr ? handles->namesResolved : 0) << ",\n";
            output << indent << "  \"namesSkipped\": " << (handles != nullptr ? handles->namesSkipped : 0) << ",\n";
            output << indent << "  \"namesFailed\": " << (handles != nullptr ? handles->namesFailed : 0) << ",\n";
            output << indent << "  \"typeResolutionsAttempted\": " << (handles != nullptr ? handles->typeResolutionsAttempted : 0) << ",\n";
            output << indent << "  \"typeResolutionsResolved\": " << (handles != nullptr ? handles->typeResolutionsResolved : 0) << ",\n";
            output << indent << "  \"typeResolutionsSkipped\": " << (handles != nullptr ? handles->typeResolutionsSkipped : 0) << ",\n";
            output << indent << "  \"typeResolutionsFailed\": " << (handles != nullptr ? handles->typeResolutionsFailed : 0) << ",\n";
            output << indent << "  \"targetsResolved\": " << (handles != nullptr ? handles->targetsResolved : 0) << ",\n";
            output << indent << "  \"targetsUnresolved\": " << (handles != nullptr ? handles->targetsUnresolved : 0) << ",\n";
            output << indent << "  \"queryBufferTruncated\": " << (handles != nullptr && handles->queryBufferTruncated ? "true" : "false") << ",\n";
            output << indent << "  \"retentionCapReached\": " << (handles != nullptr && handles->retentionCapReached ? "true" : "false") << ",\n";
            output << indent << "  \"nameResolutionCapReached\": " << (handles != nullptr && handles->nameResolutionCapReached ? "true" : "false") << ",\n";
            output << indent << "  \"typeResolutionCapReached\": " << (handles != nullptr && handles->typeResolutionCapReached ? "true" : "false") << ",\n";
            output << indent << "  \"typeOrTargetResolutionPartial\": " << (handles != nullptr && handles->typeOrTargetResolutionPartial ? "true" : "false") << ",\n";
            output << indent << "  \"handleCount\": " << (handles != nullptr ? handles->handles.size() : 0) << ",\n";
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

        void WriteRuntimeObject(
            std::ostream& output,
            const Core::RuntimeInfo* runtime,
            const std::string& indent)
        {
            output << "{\n";
            output << indent << "  \"loaded\": " << (runtime != nullptr ? "true" : "false") << ",\n";
            output << indent << "  \"success\": " << (runtime != nullptr && runtime->success ? "true" : "false") << ",\n";
            output << indent << "  \"errorMessage\": ";
            WriteJsonString(output, runtime != nullptr ? runtime->errorMessage : L"Runtime data was not loaded before export.");
            output << ",\n";
            output << indent << "  \"processId\": " << (runtime != nullptr ? runtime->processId : 0) << ",\n";
            output << indent << "  \"priorityClassRaw\": " << (runtime != nullptr ? runtime->priorityClassRaw : 0) << ",\n";
            output << indent << "  \"priorityClassName\": ";
            WriteJsonString(output, runtime != nullptr ? runtime->priorityClassName : L"");
            output << ",\n";
            output << indent << "  \"basePriority\": " << (runtime != nullptr ? runtime->basePriority : 0) << ",\n";
            output << indent << "  \"processAffinityMask\": " << (runtime != nullptr ? runtime->processAffinityMask : 0) << ",\n";
            output << indent << "  \"systemAffinityMask\": " << (runtime != nullptr ? runtime->systemAffinityMask : 0) << ",\n";
            output << indent << "  \"affinityMaskString\": ";
            WriteJsonString(output, runtime != nullptr ? runtime->affinityMaskString : L"");
            output << ",\n";
            output << indent << "  \"processorGroup\": ";
            WriteJsonString(output, runtime != nullptr ? runtime->processorGroup : L"");
            output << ",\n";
            output << indent << "  \"threadCount\": " << (runtime != nullptr ? runtime->threadCount : 0) << ",\n";
            output << indent << "  \"handleCount\": " << (runtime != nullptr ? runtime->handleCount : 0) << ",\n";
            output << indent << "  \"workingSetSize\": " << (runtime != nullptr ? runtime->workingSetSize : 0) << ",\n";
            output << indent << "  \"peakWorkingSetSize\": " << (runtime != nullptr ? runtime->peakWorkingSetSize : 0) << ",\n";
            output << indent << "  \"privateBytes\": " << (runtime != nullptr ? runtime->privateBytes : 0) << ",\n";
            output << indent << "  \"pagefileUsage\": " << (runtime != nullptr ? runtime->pagefileUsage : 0) << ",\n";
            output << indent << "  \"peakPagefileUsage\": " << (runtime != nullptr ? runtime->peakPagefileUsage : 0) << ",\n";
            output << indent << "  \"userCpuTime\": ";
            WriteJsonString(output, runtime != nullptr ? runtime->userCpuTime : L"");
            output << ",\n";
            output << indent << "  \"kernelCpuTime\": ";
            WriteJsonString(output, runtime != nullptr ? runtime->kernelCpuTime : L"");
            output << ",\n";
            output << indent << "  \"totalCpuTime\": ";
            WriteJsonString(output, runtime != nullptr ? runtime->totalCpuTime : L"");
            output << ",\n";
            output << indent << "  \"userCpuTime100ns\": " << (runtime != nullptr ? runtime->userCpuTime100ns : 0) << ",\n";
            output << indent << "  \"kernelCpuTime100ns\": " << (runtime != nullptr ? runtime->kernelCpuTime100ns : 0) << ",\n";
            output << indent << "  \"totalCpuTime100ns\": " << (runtime != nullptr ? runtime->totalCpuTime100ns : 0) << ",\n";
            output << indent << "  \"architecture\": ";
            WriteJsonString(output, runtime != nullptr ? runtime->architecture : L"");
            output << ",\n";
            output << indent << "  \"isWow64\": " << (runtime != nullptr && runtime->isWow64 ? "true" : "false") << ",\n";
            output << indent << "  \"contextNotes\": ";
            if (runtime != nullptr)
            {
                WriteJsonStringArray(output, runtime->contextNotes);
            }
            else
            {
                output << "[]";
            }
            output << ",\n";
            output << indent << "  \"threads\": [";
            if (runtime != nullptr && !runtime->threads.empty())
            {
                output << '\n';
                for (std::size_t index = 0; index < runtime->threads.size(); ++index)
                {
                    const Core::ThreadInfo& thread = runtime->threads[index];
                    output << indent << "    {\n";
                    output << indent << "      \"threadId\": " << thread.threadId << ",\n";
                    output << indent << "      \"ownerProcessId\": " << thread.ownerProcessId << ",\n";
                    output << indent << "      \"basePriority\": " << thread.basePriority << ",\n";
                    output << indent << "      \"currentPriority\": ";
                    if (thread.hasCurrentPriority)
                    {
                        output << thread.currentPriority;
                    }
                    else
                    {
                        output << "null";
                    }
                    output << ",\n";
                    output << indent << "      \"startAddress\": ";
                    WriteJsonString(output, thread.startAddress);
                    output << ",\n";
                    output << indent << "      \"startAddressResolvedModule\": ";
                    WriteJsonString(output, thread.startAddressResolvedModule);
                    output << ",\n";
                    output << indent << "      \"state\": ";
                    WriteJsonString(output, thread.state);
                    output << ",\n";
                    output << indent << "      \"errorMessage\": ";
                    WriteJsonString(output, thread.errorMessage);
                    output << "\n";
                    output << indent << "    }";
                    if (index + 1 < runtime->threads.size())
                    {
                        output << ',';
                    }
                    output << '\n';
                }
                output << indent << "  ";
            }
            output << "]\n";
            output << indent << "}";
        }

        void WriteMemoryObject(
            std::ostream& output,
            const Core::MemoryCollectionResult* memory,
            const std::string& indent)
        {
            output << "{\n";
            output << indent << "  \"loaded\": " << (memory != nullptr ? "true" : "false") << ",\n";
            output << indent << "  \"pid\": " << (memory != nullptr ? memory->pid : 0) << ",\n";
            output << indent << "  \"success\": " << (memory != nullptr && memory->success ? "true" : "false") << ",\n";
            output << indent << "  \"statusMessage\": ";
            WriteJsonString(output, memory != nullptr ? memory->statusMessage : L"Memory data was not loaded before export.");
            output << ",\n";
            output << indent << "  \"totalRegions\": " << (memory != nullptr ? memory->totalRegions : 0) << ",\n";
            output << indent << "  \"executableRegions\": " << (memory != nullptr ? memory->executableRegions : 0) << ",\n";
            output << indent << "  \"privateExecutableRegions\": " << (memory != nullptr ? memory->privateExecutableRegions : 0) << ",\n";
            output << indent << "  \"rwxRegions\": " << (memory != nullptr ? memory->rwxRegions : 0) << ",\n";
            output << indent << "  \"guardRegions\": " << (memory != nullptr ? memory->guardRegions : 0) << ",\n";
            output << indent << "  \"memoryRegions\": [";
            if (memory != nullptr && !memory->regions.empty())
            {
                output << '\n';
                for (std::size_t index = 0; index < memory->regions.size(); ++index)
                {
                    const Core::MemoryRegionInfo& region = memory->regions[index];
                    output << indent << "    {\n";
                    output << indent << "      \"baseAddress\": " << region.baseAddress << ",\n";
                    output << indent << "      \"baseAddressString\": ";
                    WriteJsonString(output, region.baseAddressString);
                    output << ",\n";
                    output << indent << "      \"allocationBase\": " << region.allocationBase << ",\n";
                    output << indent << "      \"allocationBaseString\": ";
                    WriteJsonString(output, region.allocationBaseString);
                    output << ",\n";
                    output << indent << "      \"regionSize\": " << region.regionSize << ",\n";
                    output << indent << "      \"regionSizeString\": ";
                    WriteJsonString(output, region.regionSizeString);
                    output << ",\n";
                    output << indent << "      \"stateRaw\": " << region.stateRaw << ",\n";
                    output << indent << "      \"stateName\": ";
                    WriteJsonString(output, region.stateName);
                    output << ",\n";
                    output << indent << "      \"typeRaw\": " << region.typeRaw << ",\n";
                    output << indent << "      \"typeName\": ";
                    WriteJsonString(output, region.typeName);
                    output << ",\n";
                    output << indent << "      \"protectRaw\": " << region.protectRaw << ",\n";
                    output << indent << "      \"protectName\": ";
                    WriteJsonString(output, region.protectName);
                    output << ",\n";
                    output << indent << "      \"allocationProtectRaw\": " << region.allocationProtectRaw << ",\n";
                    output << indent << "      \"allocationProtectName\": ";
                    WriteJsonString(output, region.allocationProtectName);
                    output << ",\n";
                    output << indent << "      \"mappedFilePath\": ";
                    WriteJsonString(output, region.mappedFilePath);
                    output << ",\n";
                    output << indent << "      \"isReadable\": " << (region.isReadable ? "true" : "false") << ",\n";
                    output << indent << "      \"isWritable\": " << (region.isWritable ? "true" : "false") << ",\n";
                    output << indent << "      \"isExecutable\": " << (region.isExecutable ? "true" : "false") << ",\n";
                    output << indent << "      \"isCopyOnWrite\": " << (region.isCopyOnWrite ? "true" : "false") << ",\n";
                    output << indent << "      \"isGuard\": " << (region.isGuard ? "true" : "false") << ",\n";
                    output << indent << "      \"isPrivate\": " << (region.isPrivate ? "true" : "false") << ",\n";
                    output << indent << "      \"isImage\": " << (region.isImage ? "true" : "false") << ",\n";
                    output << indent << "      \"isMapped\": " << (region.isMapped ? "true" : "false");
                    output << "\n";
                    output << indent << "    }";
                    if (index + 1 < memory->regions.size())
                    {
                        output << ',';
                    }
                    output << '\n';
                }
                output << indent << "  ";
            }
            output << "]\n";
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
        return ExportSelectedProcessDetailsToJson(
            snapshot,
            pid,
            modules,
            networkConnections,
            handles,
            nullptr,
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
        const Core::RuntimeInfo* runtime,
        const std::wstring& filePath,
        std::wstring* errorMessage)
    {
        return ExportSelectedProcessDetailsToJson(
            snapshot,
            pid,
            modules,
            networkConnections,
            handles,
            runtime,
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
        const Core::RuntimeInfo* runtime,
        const Core::MemoryCollectionResult* memory,
        const std::wstring& filePath,
        std::wstring* errorMessage)
    {
        const Core::PersistedTriageSummary notCapturedTriage;
        return ExportSelectedProcessDetailsToJson(
            snapshot,
            pid,
            modules,
            networkConnections,
            handles,
            runtime,
            memory,
            SelectedProcessJsonEvidenceContext{},
            notCapturedTriage,
            nullptr,
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
        const Core::RuntimeInfo* runtime,
        const Core::MemoryCollectionResult* memory,
        const SelectedProcessJsonEvidenceContext& capturedEvidence,
        const Core::PersistedTriageSummary& authoritativeTriage,
        const std::vector<Core::NativeSourceEvidenceRecord>* nativeSourceEvidence,
        const std::vector<Core::Finding>* historicalLegacyEvidence,
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

        const bool hasCapturedEvidence =
            capturedEvidence.processFileIdentityCaptured ||
            capturedEvidence.tokenCaptured ||
            capturedEvidence.moduleFileIdentitiesCaptured ||
            authoritativeTriage.captured ||
            nativeSourceEvidence != nullptr ||
            historicalLegacyEvidence != nullptr;
        if ((hasCapturedEvidence && !capturedEvidence.identityCaptured) ||
            (capturedEvidence.identityCaptured &&
                capturedEvidence.identity != Core::MakeProcessIdentityKey(*process)) ||
            (!capturedEvidence.moduleFileIdentitiesCaptured &&
                !capturedEvidence.moduleFileIdentities.empty()) ||
            (capturedEvidence.moduleFileIdentitiesCaptured &&
                capturedEvidence.moduleFileIdentities.size() != modules.modules.size()))
        {
            if (errorMessage != nullptr)
            {
                *errorMessage =
                    L"Selected-process export contains stale or contradictory captured evidence.";
            }
            return false;
        }

        const Core::PersistedTriageValidationResult triageValidation =
            Core::ValidatePersistedTriageSummary(authoritativeTriage);
        if (!triageValidation)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = L"Selected-process export contains invalid authoritative triage data.";
            }
            return false;
        }
        const std::vector<Core::NativeSourceEvidenceRecord> emptyNativeEvidence;
        const std::vector<Core::Finding> emptyHistoricalEvidence;
        const std::vector<Core::NativeSourceEvidenceRecord>& nativeEvidence =
            nativeSourceEvidence == nullptr
                ? emptyNativeEvidence
                : *nativeSourceEvidence;
        const std::vector<Core::Finding>& historicalEvidence =
            historicalLegacyEvidence == nullptr
                ? emptyHistoricalEvidence
                : *historicalLegacyEvidence;
        if (!Core::ValidateNativeSourceEvidenceRecords(nativeEvidence))
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = L"Selected-process export contains invalid native source evidence.";
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
        const Core::FileIdentity* processFileIdentity =
            capturedEvidence.processFileIdentityCaptured
                ? &capturedEvidence.processFileIdentity
                : nullptr;
        const Core::TokenInfo* tokenInfo =
            capturedEvidence.tokenCaptured
                ? &capturedEvidence.token
                : nullptr;
        const std::vector<Core::FileIdentity>* moduleFileIdentities =
            capturedEvidence.moduleFileIdentitiesCaptured
                    ? &capturedEvidence.moduleFileIdentities
                    : nullptr;
        const Core::HandleCollectionResult* selectedHandles =
            handles != nullptr && handles->pid == process->pid
                ? handles
                : nullptr;
        const Core::RuntimeInfo* selectedRuntime =
            runtime != nullptr && runtime->processId == process->pid
                ? runtime
                : nullptr;
        const Core::MemoryCollectionResult* selectedMemory =
            memory != nullptr && memory->pid == process->pid
                ? memory
                : nullptr;
        const std::size_t listeningNetworkCount = CountListeningConnections(networkConnections);
        const std::size_t publicRemoteNetworkCount = CountPublicRemoteConnections(networkConnections);
        std::vector<std::wstring> networkContext;
        if (listeningNetworkCount > 0)
        {
            networkContext.push_back(L"Process has a listening socket.");
        }
        if (publicRemoteNetworkCount > 0)
        {
            networkContext.push_back(L"Process has a public remote connection.");
        }
        std::vector<std::wstring> networkContextNotes;

        output << "{\n";
        output << "  \"schemaVersion\": \"0.8-selected-details-v3-native\",\n";
        output << "  \"generatedUtc\": \"" << UtcTimestamp() << "\",\n";
        output << "  \"authoritative_triage\": ";
        WritePersistedTriageSummary(output, authoritativeTriage, "  ");
        output << ",\n";
        output << "  \"native_source_evidence\": ";
        WriteNativeSourceEvidenceArray(output, nativeEvidence);
        output << ",\n";
        if (!historicalEvidence.empty())
        {
            output << "  \"historical_legacy_evidence\": ";
            WriteFindingArray(output, historicalEvidence);
            output << ",\n";
        }
        output << "  \"process\": {\n";
        output << "    \"pid\": " << process->pid << ",\n";
        output << "    \"parentPid\": " << process->parentPid << ",\n";
        output << "    \"name\": ";
        WriteJsonString(output, process->name);
        output << ",\n";
        output << "    \"executablePath\": ";
        WriteJsonString(output, process->executablePath);
        output << ",\n";
        output << "    \"fileIdentityCaptured\": "
               << (processFileIdentity != nullptr ? "true" : "false") << ",\n";
        output << "    \"fileIdentity\": ";
        if (processFileIdentity != nullptr)
        {
            WriteFileIdentityObject(output, *processFileIdentity, "    ");
        }
        else
        {
            output << "null";
        }
        output << ",\n";
        output << "    \"commandLine\": ";
        WriteJsonString(output, process->commandLine);
        output << ",\n";
        output << "    \"commandLineAccessible\": " << (process->commandLineAccessible ? "true" : "false") << ",\n";
        output << "    \"architecture\": ";
        WriteJsonString(output, process->architecture);
        output << ",\n";
        output << "    \"hasCreationTime\": " << (process->hasCreationTime ? "true" : "false") << ",\n";
        output << "    \"creationTimeFileTime\": " << process->creationTimeFileTime << ",\n";
        output << "    \"creationTimeLocal\": ";
        WriteJsonString(output, process->creationTimeLocal);
        output << ",\n";
        output << "    \"parentRelationshipVerified\": " << (process->parentRelationshipVerified ? "true" : "false") << ",\n";
        output << "    \"parentRelationshipUnverified\": " << (process->parentRelationshipUnverified ? "true" : "false") << ",\n";
        output << "    \"parentPidReuseSuspected\": " << (process->parentPidReuseSuspected ? "true" : "false") << ",\n";
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
            output << "}";
        }
        output << "]\n";
        output << "  },\n";
        output << "  \"tokenInspectionCaptured\": "
               << (tokenInfo != nullptr ? "true" : "false") << ",\n";
        output << "  \"tokenInspection\": ";
        if (tokenInfo != nullptr)
        {
            WriteTokenObject(output, *tokenInfo, "  ");
        }
        else
        {
            output << "null";
        }
        output << ",\n";
        output << "  \"handleInspection\": ";
        WriteHandleInspectionObject(output, selectedHandles, "  ");
        output << ",\n";
        output << "  \"runtimeInfo\": ";
        WriteRuntimeObject(output, selectedRuntime, "  ");
        output << ",\n";
        output << "  \"memoryInspection\": ";
        WriteMemoryObject(output, selectedMemory, "  ");
        output << ",\n";
        output << "  \"moduleInspection\": {\n";
        output << "    \"pid\": " << modules.pid << ",\n";
        output << "    \"success\": " << (modules.success ? "true" : "false") << ",\n";
        output << "    \"statusMessage\": ";
        WriteJsonString(output, modules.statusMessage);
        output << ",\n";
        output << "    \"modules\": ";
        WriteModuleArray(output, modules.modules, moduleFileIdentities);
        output << "\n";
        output << "  },\n";
        output << "  \"networkInspection\": {\n";
        output << "    \"connectionCount\": " << networkConnections.size() << ",\n";
        output << "    \"listeningCount\": " << listeningNetworkCount << ",\n";
        output << "    \"publicRemoteCount\": " << publicRemoteNetworkCount << ",\n";
        output << "    \"context\": ";
        WriteJsonStringArray(output, networkContext);
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
