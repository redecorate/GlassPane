#include "BaselineObservationBuilder.h"

#include "ObservationPolicy.h"

#include <algorithm>
#include <iomanip>
#include <set>
#include <sstream>
#include <utility>

namespace GlassPane::Core
{
    namespace
    {
        constexpr char BaselineScopeLimitation[] =
            "Baseline evaluation uses only process-wide evidence already available after the normal endpoint refresh; selected-process deep evidence was not evaluated.";
        constexpr char TruncationLimitation[] =
            "A baseline source value was truncated to its bounded representation.";

        std::string UnknownEnumText(const char* label, std::uint32_t value)
        {
            std::ostringstream stream;
            stream << "Unknown " << label << " (0x"
                   << std::uppercase
                   << std::hex
                   << std::setw(8)
                   << std::setfill('0')
                   << value
                   << ')';
            return stream.str();
        }

        bool LimitString(std::string& value, std::size_t maximumCharacters)
        {
            if (value.size() <= maximumCharacters)
            {
                return false;
            }
            value.resize(maximumCharacters);
            return true;
        }

        void AppendUtf8CodePoint(
            std::uint32_t codePoint,
            std::string& output,
            std::size_t maximumCharacters,
            bool& truncated)
        {
            char encoded[4]{};
            std::size_t encodedLength = 0;
            if (codePoint <= 0x7F)
            {
                encoded[0] = static_cast<char>(codePoint);
                encodedLength = 1;
            }
            else if (codePoint <= 0x7FF)
            {
                encoded[0] = static_cast<char>(0xC0 | (codePoint >> 6));
                encoded[1] = static_cast<char>(0x80 | (codePoint & 0x3F));
                encodedLength = 2;
            }
            else if (codePoint <= 0xFFFF)
            {
                encoded[0] = static_cast<char>(0xE0 | (codePoint >> 12));
                encoded[1] = static_cast<char>(0x80 | ((codePoint >> 6) & 0x3F));
                encoded[2] = static_cast<char>(0x80 | (codePoint & 0x3F));
                encodedLength = 3;
            }
            else
            {
                encoded[0] = static_cast<char>(0xF0 | (codePoint >> 18));
                encoded[1] = static_cast<char>(0x80 | ((codePoint >> 12) & 0x3F));
                encoded[2] = static_cast<char>(0x80 | ((codePoint >> 6) & 0x3F));
                encoded[3] = static_cast<char>(0x80 | (codePoint & 0x3F));
                encodedLength = 4;
            }

            if (output.size() + encodedLength > maximumCharacters)
            {
                truncated = true;
                return;
            }
            output.append(encoded, encodedLength);
        }

        std::string WideToUtf8Bounded(
            const std::wstring& value,
            std::size_t maximumCharacters,
            bool& truncated,
            bool& invalidUnicode)
        {
            std::string output;
            output.reserve(std::min(value.size(), maximumCharacters));
            for (std::size_t index = 0; index < value.size(); ++index)
            {
                std::uint32_t codePoint = static_cast<std::uint32_t>(value[index]);
                if constexpr (sizeof(wchar_t) == 2)
                {
                    if (codePoint >= 0xD800 && codePoint <= 0xDBFF)
                    {
                        if (index + 1 < value.size())
                        {
                            const std::uint32_t low =
                                static_cast<std::uint32_t>(value[index + 1]);
                            if (low >= 0xDC00 && low <= 0xDFFF)
                            {
                                codePoint = 0x10000 +
                                    ((codePoint - 0xD800) << 10) +
                                    (low - 0xDC00);
                                ++index;
                            }
                            else
                            {
                                codePoint = 0xFFFD;
                                invalidUnicode = true;
                            }
                        }
                        else
                        {
                            codePoint = 0xFFFD;
                            invalidUnicode = true;
                        }
                    }
                    else if (codePoint >= 0xDC00 && codePoint <= 0xDFFF)
                    {
                        codePoint = 0xFFFD;
                        invalidUnicode = true;
                    }
                }
                else if (codePoint > 0x10FFFF ||
                    (codePoint >= 0xD800 && codePoint <= 0xDFFF))
                {
                    codePoint = 0xFFFD;
                    invalidUnicode = true;
                }

                const std::size_t previousSize = output.size();
                AppendUtf8CodePoint(
                    codePoint,
                    output,
                    maximumCharacters,
                    truncated);
                if (truncated && output.size() == previousSize)
                {
                    break;
                }
            }
            return output;
        }

        std::uint64_t Fingerprint(const std::string& value)
        {
            constexpr std::uint64_t Offset = 1469598103934665603ULL;
            constexpr std::uint64_t Prime = 1099511628211ULL;
            std::uint64_t hash = Offset;
            for (const unsigned char character : value)
            {
                hash ^= character;
                hash *= Prime;
            }
            return hash;
        }

        std::string FingerprintText(const std::string& value)
        {
            std::ostringstream stream;
            stream << std::hex << std::setw(16) << std::setfill('0')
                   << Fingerprint(value);
            return stream.str();
        }

        wchar_t LowerAscii(wchar_t character)
        {
            if (character >= L'A' && character <= L'Z')
            {
                return static_cast<wchar_t>(character - L'A' + L'a');
            }
            return character;
        }

        std::wstring LowerAscii(std::wstring value)
        {
            std::transform(
                value.begin(),
                value.end(),
                value.begin(),
                [](wchar_t character)
                {
                    return LowerAscii(character);
                });
            return value;
        }

        bool IsSpace(wchar_t character)
        {
            return character == L' ' || character == L'\t' ||
                character == L'\r' || character == L'\n' ||
                character == L'\f' || character == L'\v';
        }

        std::vector<std::wstring> CommandTokens(const std::wstring& commandLine)
        {
            std::vector<std::wstring> tokens;
            std::wstring token;
            bool quoted = false;
            for (wchar_t character : commandLine)
            {
                if (character == L'"')
                {
                    quoted = !quoted;
                    continue;
                }
                if (!quoted && IsSpace(character))
                {
                    if (!token.empty())
                    {
                        tokens.push_back(LowerAscii(std::move(token)));
                        token.clear();
                    }
                    continue;
                }
                token.push_back(character);
            }
            if (!token.empty())
            {
                tokens.push_back(LowerAscii(std::move(token)));
            }
            return tokens;
        }

        bool HasEncodedCommandToken(const std::wstring& commandLine)
        {
            const std::vector<std::wstring> tokens = CommandTokens(commandLine);
            return std::any_of(
                tokens.begin(),
                tokens.end(),
                [](const std::wstring& token)
                {
                    return token == L"-encodedcommand" ||
                        token == L"/encodedcommand" ||
                        token == L"--encoded-command";
                });
        }

        bool IsGenericUserWritablePath(const std::wstring& path)
        {
            const std::wstring lowered = LowerAscii(path);
            return lowered.find(L"\\appdata\\") != std::wstring::npos ||
                lowered.find(L"\\temp\\") != std::wstring::npos ||
                lowered.find(L"\\tmp\\") != std::wstring::npos;
        }

        std::string EntityScopeFor(
            const ProcessInfo& process,
            const BaselineObservationContext& context)
        {
            if (!context.entityScope.empty())
            {
                return context.entityScope;
            }
            std::ostringstream scope;
            scope << "process:pid:" << process.pid << ":creation:";
            if (process.hasCreationTime)
            {
                scope << process.creationTimeFileTime;
            }
            else
            {
                scope << "unavailable";
            }
            return scope.str();
        }

        std::string ProcessArtifactKey(const ProcessInfo& process)
        {
            std::ostringstream key;
            key << "pid:" << process.pid << ":creation:";
            if (process.hasCreationTime)
            {
                key << process.creationTimeFileTime;
            }
            else
            {
                key << "unavailable";
            }
            return key.str();
        }

        ObservationSourceKind EffectiveSourceKind(
            ObservationSourceKind sourceKind,
            const BaselineObservationContext& context)
        {
            if (sourceKind == ObservationSourceKind::Unavailable)
            {
                return sourceKind;
            }
            return context.importedEvidence
                ? ObservationSourceKind::Imported
                : sourceKind;
        }

        void AddBoundedLimitation(
            std::vector<std::string>& limitations,
            std::string limitation,
            bool& truncated)
        {
            if (LimitString(
                    limitation,
                    ObservationLimitationItemMaxCharacters))
            {
                truncated = true;
            }
            if (limitations.size() >= BaselineObservationMaxLimitations)
            {
                truncated = true;
                return;
            }
            limitations.push_back(std::move(limitation));
        }

        void CopyBoundedItems(
            const std::vector<std::string>& source,
            std::vector<std::string>& destination,
            std::size_t maximumItems,
            std::size_t maximumCharacters,
            bool& truncated)
        {
            for (const std::string& item : source)
            {
                if (destination.size() >= maximumItems)
                {
                    truncated = true;
                    return;
                }
                std::string bounded = item;
                if (LimitString(bounded, maximumCharacters))
                {
                    truncated = true;
                }
                destination.push_back(std::move(bounded));
            }
        }

        std::string BoundedCopy(
            const std::string& value,
            std::size_t maximumCharacters,
            bool& truncated)
        {
            std::string bounded = value;
            if (LimitString(bounded, maximumCharacters))
            {
                truncated = true;
            }
            return bounded;
        }

        struct ObservationSpec
        {
            const char* mappingRuleId = "baseline.unknown";
            std::string sourceRuleId;
            std::string producerIdentifier;
            std::string collectionMethod;
            std::string title;
            std::string summary;
            EvidenceDomain domain = EvidenceDomain::Unknown;
            ObservationDisposition disposition =
                ObservationDisposition::Informational;
            ObservationStrength strength = ObservationStrength::None;
            ObservationConfidence confidence = ObservationConfidence::Unknown;
            ObservationSourceKind sourceKind = ObservationSourceKind::Direct;
            bool contributesToVerdict = false;
            std::string groupingKey;
            std::string correlationKey;
            std::string rawValue;
            std::string normalizedValue;
            ObservationArtifactIdentity artifactIdentity;
            std::vector<ObservationArtifactAttribute> artifactAttributes;
            std::vector<std::string> evidence;
            std::vector<std::string> limitations;
            std::string assessmentRationale;
        };

        bool AddObservation(
            BaselineObservationResult& result,
            const BaselineObservationContext& context,
            const std::string& entityScope,
            ObservationSpec spec,
            std::set<std::string>& observationIds)
        {
            if (result.inventory.records.size() >=
                BaselineObservationMaxSourceFacts)
            {
                result.truncated = true;
                ++result.omittedFactCount;
                return true;
            }

            bool truncated = false;
            const std::string identityMaterial =
                spec.mappingRuleId + std::string("|") +
                spec.artifactIdentity.artifactKey + "|" +
                spec.normalizedValue + "|" + spec.rawValue;
            const std::string fingerprint = FingerprintText(identityMaterial);

            ObservationRecord record;
            record.source.sourceRecordId = "baseline-source:" + fingerprint;
            record.source.sourceRuleId = BoundedCopy(
                spec.sourceRuleId.empty()
                    ? std::string(spec.mappingRuleId)
                    : spec.sourceRuleId,
                ObservationRuleIdMaxCharacters,
                truncated);
            record.source.mappingRuleId = spec.mappingRuleId;
            record.source.sourceTitle = BoundedCopy(
                spec.title,
                ObservationTitleMaxCharacters,
                truncated);
            record.source.sourceMessage = BoundedCopy(
                spec.summary,
                ObservationSourceMessageMaxCharacters,
                truncated);
            record.source.sourceCategory = "Native baseline evidence";
            record.source.producerIdentifier = BoundedCopy(
                spec.producerIdentifier,
                ObservationProvenanceSourceIdentifierMaxCharacters,
                truncated);
            record.source.assessmentRationale = BoundedCopy(
                spec.assessmentRationale,
                ObservationLimitationItemMaxCharacters,
                truncated);
            record.source.rawValueExplicitlySupplied = !spec.rawValue.empty();
            record.source.normalizedValueExplicitlySupplied =
                !spec.normalizedValue.empty();

            Observation& observation = record.observation;
            observation.id = "baseline-observation:" + fingerprint;
            observation.ruleId = record.source.sourceRuleId;
            observation.title = record.source.sourceTitle;
            observation.summary = record.source.sourceMessage;
            observation.domain = spec.domain;
            observation.sourceKind = EffectiveSourceKind(
                spec.sourceKind,
                context);
            observation.disposition = spec.disposition;
            observation.strength = spec.strength;
            observation.confidence = spec.confidence;
            observation.contributesToVerdict = spec.contributesToVerdict;
            observation.entityScope = entityScope;
            observation.groupingKey = BoundedCopy(
                spec.groupingKey,
                ObservationGroupingKeyMaxCharacters,
                truncated);
            observation.correlationKey = BoundedCopy(
                spec.correlationKey,
                ObservationCorrelationKeyMaxCharacters,
                truncated);
            observation.rawValue = BoundedCopy(
                spec.rawValue,
                ObservationRawValueMaxCharacters,
                truncated);
            observation.normalizedValue = BoundedCopy(
                spec.normalizedValue,
                ObservationNormalizedValueMaxCharacters,
                truncated);
            observation.artifactIdentity = std::move(spec.artifactIdentity);
            observation.artifactIdentity.entityScope = entityScope;
            observation.artifactIdentity.artifactKey = BoundedCopy(
                observation.artifactIdentity.artifactKey,
                ObservationArtifactKeyMaxCharacters,
                truncated);
            observation.artifactAttributes = std::move(spec.artifactAttributes);
            if (observation.artifactAttributes.size() >
                ObservationMaxArtifactAttributes)
            {
                observation.artifactAttributes.resize(
                    ObservationMaxArtifactAttributes);
                truncated = true;
            }
            for (ObservationArtifactAttribute& attribute :
                observation.artifactAttributes)
            {
                truncated = LimitString(
                    attribute.key,
                    ObservationArtifactAttributeKeyMaxCharacters) || truncated;
                truncated = LimitString(
                    attribute.value,
                    ObservationArtifactAttributeValueMaxCharacters) || truncated;
            }
            CopyBoundedItems(
                spec.evidence,
                observation.evidence,
                ObservationMaxEvidenceItems,
                ObservationEvidenceItemMaxCharacters,
                truncated);
            CopyBoundedItems(
                spec.limitations,
                observation.limitations,
                ObservationMaxLimitationItems,
                ObservationLimitationItemMaxCharacters,
                truncated);
            if (truncated && observation.limitations.size() <
                    ObservationMaxLimitationItems)
            {
                observation.limitations.push_back(TruncationLimitation);
            }

            observation.provenance.sourceKind = observation.sourceKind;
            observation.provenance.sourceIdentifier =
                record.source.producerIdentifier;
            observation.provenance.collectionMethod = BoundedCopy(
                spec.collectionMethod,
                ObservationProvenanceCollectionMethodMaxCharacters,
                truncated);
            observation.provenance.collectionTimestamp = BoundedCopy(
                context.collectionTimestamp,
                ObservationProvenanceCollectionTimestampMaxCharacters,
                truncated);
            observation.provenance.sourceAvailable =
                observation.sourceKind != ObservationSourceKind::Unavailable;
            observation.provenance.rawSourceReference =
                record.source.sourceRecordId;
            observation.provenance.limitations = observation.limitations;

            observation = NormalizeObservationPolicy(std::move(observation));
            if (!ValidateObservation(observation).IsValid())
            {
                result.success = false;
                result.status = BaselineObservationStatus::InternalPolicyFailure;
                result.diagnostic =
                    "A native baseline observation failed bounded policy validation.";
                result.inventory = {};
                return false;
            }

            if (!observationIds.insert(observation.id).second)
            {
                ++result.duplicateExcludedCount;
            }
            result.inventory.records.push_back(std::move(record));
            ++result.nativeFactCount;
            result.truncated = result.truncated || truncated;
            return true;
        }

        void CountInventoryDisposition(
            ObservationInventory& inventory,
            ObservationDisposition disposition)
        {
            switch (disposition)
            {
            case ObservationDisposition::Informational:
                ++inventory.informationalCount;
                break;
            case ObservationDisposition::Context:
                ++inventory.contextCount;
                break;
            case ObservationDisposition::ReviewRelevant:
                ++inventory.reviewRelevantCount;
                break;
            case ObservationDisposition::CorrelatedOnly:
                ++inventory.correlatedOnlyCount;
                break;
            case ObservationDisposition::CollectionNote:
                ++inventory.collectionNoteCount;
                break;
            case ObservationDisposition::EvidenceIntegrityNote:
                ++inventory.evidenceIntegrityNoteCount;
                break;
            case ObservationDisposition::SuppressedExpected:
                ++inventory.suppressedExpectedCount;
                break;
            default:
                break;
            }
        }

        void FinalizeInventory(BaselineObservationResult& result)
        {
            ObservationInventory& inventory = result.inventory;
            inventory.status = ObservationInventoryStatus::Success;
            inventory.typedSourceFactCount = inventory.records.size();
            inventory.declaredSourceFactCount = inventory.records.size() +
                result.omittedFactCount;
            for (const ObservationRecord& record : inventory.records)
            {
                CountInventoryDisposition(
                    inventory,
                    record.observation.disposition);
            }
        }

        std::string ArtifactKeyOrDerived(
            const std::string& supplied,
            const std::string& identityMaterial)
        {
            if (!supplied.empty())
            {
                return supplied;
            }
            return "typed-artifact:" + FingerprintText(identityMaterial);
        }

        std::string PortText(std::uint16_t port)
        {
            return std::to_string(static_cast<unsigned int>(port));
        }

        std::string ServiceModelText(ServiceProcessModel model)
        {
            switch (model)
            {
            case ServiceProcessModel::OwnProcess:
                return "Own process";
            case ServiceProcessModel::SharedProcess:
                return "Shared process";
            case ServiceProcessModel::Unknown:
                return "Unknown";
            default:
                return UnknownEnumText(
                    "service process model",
                    static_cast<std::uint32_t>(model));
            }
        }

        std::string HexRaw(std::uint32_t value)
        {
            std::ostringstream stream;
            stream << "0x" << std::uppercase << std::hex << std::setw(8)
                   << std::setfill('0') << value;
            return stream.str();
        }
    }

    std::string BaselineObservationStatusDisplayText(
        BaselineObservationStatus status)
    {
        switch (status)
        {
        case BaselineObservationStatus::NotAttempted:
            return "Not attempted";
        case BaselineObservationStatus::Success:
            return "Success";
        case BaselineObservationStatus::InvalidEntityScope:
            return "Invalid entity scope";
        case BaselineObservationStatus::InvalidTypedFact:
            return "Invalid typed fact";
        case BaselineObservationStatus::OutputLimitExceeded:
            return "Output limit exceeded";
        case BaselineObservationStatus::InternalPolicyFailure:
            return "Internal policy failure";
        default:
            return UnknownEnumText(
                "baseline observation status",
                static_cast<std::uint32_t>(status));
        }
    }

    bool BaselineObservationResult::Succeeded() const
    {
        return attempted && success &&
            status == BaselineObservationStatus::Success &&
            inventory.Succeeded();
    }

    BaselineObservationResult BuildBaselineObservations(
        const ProcessInfo& process,
        const ProcessSnapshot& snapshot,
        const BaselineObservationContext& sourceContext)
    {
        BaselineObservationResult result;
        result.attempted = true;
        result.status = BaselineObservationStatus::Success;
        result.success = true;

        const BaselineObservationContext& context = sourceContext;
        const std::string entityScope = EntityScopeFor(process, context);
        if (entityScope.empty() ||
            entityScope.size() > ObservationEntityScopeMaxCharacters)
        {
            result.success = false;
            result.status = BaselineObservationStatus::InvalidEntityScope;
            result.diagnostic =
                "The baseline process identity scope is missing or exceeds its cap.";
            return result;
        }

        result.truncated = context.preboundedSourceFactsTruncated ||
            context.preboundedOmittedSourceFactCount != 0;
        result.omittedFactCount =
            context.preboundedOmittedSourceFactCount;

        AddBoundedLimitation(
            result.limitations,
            BaselineScopeLimitation,
            result.truncated);
        CopyBoundedItems(
            context.limitations,
            result.limitations,
            BaselineObservationMaxLimitations,
            ObservationLimitationItemMaxCharacters,
            result.truncated);

        std::set<std::string> observationIds;
        const std::string processArtifact = ProcessArtifactKey(process);

        if (context.includeNativeProcessIdentity)
        {
            bool valueTruncated = false;
            bool invalidUnicode = false;
            std::string processName = WideToUtf8Bounded(
                process.name,
                BaselineObservationFactValueMaxCharacters,
                valueTruncated,
                invalidUnicode);
            if (processName.empty())
            {
                processName = "Process identity available without a name";
            }
            ObservationSpec identity;
            identity.mappingRuleId = BaselineMappingProcessIdentity;
            identity.sourceRuleId = BaselineMappingProcessIdentity;
            identity.producerIdentifier = "core.process-snapshot";
            identity.collectionMethod = "normal-process-snapshot";
            identity.title = "Process identity observed";
            identity.summary =
                "The process identity was retained as baseline context.";
            identity.domain = EvidenceDomain::ProcessIdentity;
            identity.disposition = ObservationDisposition::Informational;
            identity.strength = ObservationStrength::None;
            identity.confidence = ObservationConfidence::High;
            identity.sourceKind = context.sourceKind;
            identity.groupingKey = "process-identity-context";
            identity.rawValue = processName;
            identity.normalizedValue = "pid:" + std::to_string(process.pid);
            identity.artifactIdentity = {
                ObservationArtifactKind::Process,
                entityScope,
                processArtifact
            };
            identity.artifactAttributes = {
                { "process.pid", std::to_string(process.pid) },
                { "process.parent-pid", std::to_string(process.parentPid) },
                { "process.creation-time-available", process.hasCreationTime ? "true" : "false" }
            };
            if (valueTruncated)
            {
                identity.limitations.push_back(TruncationLimitation);
            }
            if (invalidUnicode)
            {
                identity.limitations.push_back(
                    "Invalid Unicode in a process identity field was replaced during bounded UTF-8 conversion.");
            }
            if (!AddObservation(
                    result,
                    context,
                    entityScope,
                    std::move(identity),
                    observationIds))
            {
                return result;
            }
        }

        if (context.includeNativeExecutablePath)
        {
            if (!process.executablePath.empty())
            {
                bool pathTruncated = false;
                bool invalidUnicode = false;
                const std::string path = WideToUtf8Bounded(
                    process.executablePath,
                    BaselineObservationFactValueMaxCharacters,
                    pathTruncated,
                    invalidUnicode);
                bool normalizedTruncated = false;
                bool normalizedInvalidUnicode = false;
                const std::string normalizedPath = WideToUtf8Bounded(
                    LowerAscii(process.executablePath),
                    BaselineObservationFactValueMaxCharacters,
                    normalizedTruncated,
                    normalizedInvalidUnicode);
                const bool userWritable =
                    IsGenericUserWritablePath(process.executablePath);
                ObservationSpec pathObservation;
                pathObservation.mappingRuleId = userWritable
                    ? BaselineMappingUserWritablePath
                    : BaselineMappingExecutablePath;
                pathObservation.sourceRuleId = pathObservation.mappingRuleId;
                pathObservation.producerIdentifier = "core.process-snapshot";
                pathObservation.collectionMethod = "normal-process-snapshot";
                pathObservation.title = userWritable
                    ? "Executable path is in a broadly user-writable location"
                    : "Executable path observed";
                pathObservation.summary = userWritable
                    ? "The configured executable path is under a generic user-writable path category; this path context is not behavioral proof."
                    : "The executable path was retained as baseline context.";
                pathObservation.domain = EvidenceDomain::FilePath;
                pathObservation.disposition = userWritable
                    ? ObservationDisposition::Context
                    : ObservationDisposition::Informational;
                pathObservation.strength = userWritable
                    ? ObservationStrength::Weak
                    : ObservationStrength::None;
                pathObservation.confidence = ObservationConfidence::High;
                pathObservation.sourceKind = context.sourceKind;
                pathObservation.groupingKey = userWritable
                    ? "user-file-path-context"
                    : "executable-path-context";
                pathObservation.correlationKey = userWritable
                    ? "file-path-signature-context"
                    : "";
                pathObservation.rawValue = path;
                pathObservation.normalizedValue = normalizedPath;
                pathObservation.artifactIdentity = {
                    ObservationArtifactKind::File,
                    entityScope,
                    "process-executable:" + FingerprintText(normalizedPath)
                };
                pathObservation.evidence.push_back(path);
                if (pathTruncated || normalizedTruncated)
                {
                    pathObservation.limitations.push_back(TruncationLimitation);
                }
                if (invalidUnicode || normalizedInvalidUnicode)
                {
                    pathObservation.limitations.push_back(
                        "Invalid Unicode in the executable path was replaced during bounded UTF-8 conversion.");
                }
                if (!AddObservation(
                        result,
                        context,
                        entityScope,
                        std::move(pathObservation),
                        observationIds))
                {
                    return result;
                }
            }
            else
            {
                AddBoundedLimitation(
                    result.limitations,
                    "Executable path metadata was not present in the process-wide snapshot; collection-attempt state was not inferred.",
                    result.truncated);
            }
        }

        if (context.includeNativeCommandLine)
        {
            if (process.commandLineAccessible)
            {
                if (HasEncodedCommandToken(process.commandLine))
                {
                    bool rawTruncated = false;
                    bool rawInvalidUnicode = false;
                    bool normalizedTruncated = false;
                    bool normalizedInvalidUnicode = false;
                    const std::string rawCommand = WideToUtf8Bounded(
                        process.commandLine,
                        BaselineObservationFactValueMaxCharacters,
                        rawTruncated,
                        rawInvalidUnicode);
                    const std::string normalizedCommand = WideToUtf8Bounded(
                        LowerAscii(process.commandLine),
                        BaselineObservationFactValueMaxCharacters,
                        normalizedTruncated,
                        normalizedInvalidUnicode);
                    ObservationSpec command;
                    command.mappingRuleId = BaselineMappingEncodedCommand;
                    command.sourceRuleId = BaselineMappingEncodedCommand;
                    command.producerIdentifier = "core.process-snapshot";
                    command.collectionMethod = "normal-process-snapshot";
                    command.title = "Encoded command switch observed";
                    command.summary =
                        "A generic encoded-command switch was present in the process command line.";
                    command.domain = EvidenceDomain::CommandLine;
                    command.disposition = ObservationDisposition::ReviewRelevant;
                    command.strength = ObservationStrength::Moderate;
                    command.confidence = ObservationConfidence::High;
                    command.sourceKind = context.sourceKind;
                    command.contributesToVerdict = true;
                    command.groupingKey = "encoded-command-context";
                    command.correlationKey = "command-relationship-context";
                    command.rawValue = rawCommand;
                    command.normalizedValue = normalizedCommand;
                    command.artifactIdentity = {
                        ObservationArtifactKind::Process,
                        entityScope,
                        processArtifact
                    };
                    command.evidence.push_back(rawCommand);
                    if (rawTruncated || normalizedTruncated)
                    {
                        command.limitations.push_back(TruncationLimitation);
                    }
                    if (rawInvalidUnicode || normalizedInvalidUnicode)
                    {
                        command.limitations.push_back(
                            "Invalid Unicode in the command line was replaced during bounded UTF-8 conversion.");
                    }
                    if (!AddObservation(
                            result,
                            context,
                            entityScope,
                            std::move(command),
                            observationIds))
                    {
                        return result;
                    }
                }
            }
            else
            {
                ObservationSpec unavailable;
                unavailable.mappingRuleId =
                    BaselineMappingCommandLineUnavailable;
                unavailable.sourceRuleId =
                    BaselineMappingCommandLineUnavailable;
                unavailable.producerIdentifier = "core.process-snapshot";
                unavailable.collectionMethod = "normal-process-snapshot";
                unavailable.title = "Command-line metadata unavailable";
                unavailable.summary =
                    "Command-line collection was attempted by the baseline process snapshot but was not available.";
                unavailable.domain = EvidenceDomain::CollectionQuality;
                unavailable.disposition = ObservationDisposition::CollectionNote;
                unavailable.strength = ObservationStrength::None;
                unavailable.confidence = ObservationConfidence::High;
                unavailable.sourceKind = ObservationSourceKind::Unavailable;
                unavailable.groupingKey = "baseline-collection-quality";
                unavailable.artifactIdentity = {
                    ObservationArtifactKind::Process,
                    entityScope,
                    processArtifact
                };
                unavailable.limitations.push_back(
                    "Unavailable command-line metadata does not imply benign or suspicious activity.");
                if (!AddObservation(
                        result,
                        context,
                        entityScope,
                        std::move(unavailable),
                        observationIds))
                {
                    return result;
                }
            }
        }

        if (context.includeNativeRelationshipContext && process.parentPid != 0)
        {
            const auto parent = snapshot.indexByPid.find(process.parentPid);
            if (process.parentRelationshipVerified &&
                parent != snapshot.indexByPid.end() &&
                parent->second < snapshot.processes.size())
            {
                ObservationSpec relationship;
                relationship.mappingRuleId =
                    BaselineMappingProcessRelationshipContext;
                relationship.sourceRuleId =
                    "baseline.relationship.verified-parent-context";
                relationship.producerIdentifier = "core.process-snapshot";
                relationship.collectionMethod = "normal-process-tree-reindex";
                relationship.title = "Parent process relationship observed";
                relationship.summary =
                    "A verified parent link was retained as baseline relationship context.";
                relationship.domain = EvidenceDomain::ProcessRelationship;
                relationship.disposition = ObservationDisposition::Context;
                relationship.strength = ObservationStrength::None;
                relationship.confidence = ObservationConfidence::High;
                relationship.sourceKind = context.sourceKind;
                relationship.groupingKey = "process-family-relationship";
                relationship.normalizedValue =
                    "pid:" + std::to_string(process.parentPid) +
                    "->pid:" + std::to_string(process.pid);
                relationship.artifactIdentity = {
                    ObservationArtifactKind::Process,
                    entityScope,
                    processArtifact
                };
                if (!AddObservation(
                        result,
                        context,
                        entityScope,
                        std::move(relationship),
                        observationIds))
                {
                    return result;
                }
            }
            else if (process.parentRelationshipUnverified ||
                process.parentPidReuseSuspected)
            {
                ObservationSpec relationshipNote;
                relationshipNote.mappingRuleId =
                    BaselineMappingRelationshipUnavailable;
                relationshipNote.sourceRuleId =
                    BaselineMappingRelationshipUnavailable;
                relationshipNote.producerIdentifier = "core.process-snapshot";
                relationshipNote.collectionMethod =
                    "normal-process-tree-reindex";
                relationshipNote.title =
                    "Parent process relationship not verified";
                relationshipNote.summary =
                    "The baseline snapshot could not verify this parent relationship.";
                relationshipNote.domain = EvidenceDomain::CollectionQuality;
                relationshipNote.disposition =
                    ObservationDisposition::CollectionNote;
                relationshipNote.strength = ObservationStrength::None;
                relationshipNote.confidence = ObservationConfidence::High;
                relationshipNote.sourceKind =
                    ObservationSourceKind::Unavailable;
                relationshipNote.groupingKey = "baseline-collection-quality";
                relationshipNote.normalizedValue =
                    "pid:" + std::to_string(process.parentPid) +
                    "->pid:" + std::to_string(process.pid);
                relationshipNote.artifactIdentity = {
                    ObservationArtifactKind::Process,
                    entityScope,
                    processArtifact
                };
                if (!AddObservation(
                        result,
                        context,
                        entityScope,
                        std::move(relationshipNote),
                        observationIds))
                {
                    return result;
                }
            }
        }

        const std::size_t typedFactCount = std::min(
            context.typedProcessFacts.size(),
            BaselineObservationMaxTypedProcessFacts);
        if (typedFactCount < context.typedProcessFacts.size())
        {
            result.truncated = true;
            result.omittedFactCount +=
                context.typedProcessFacts.size() - typedFactCount;
        }
        for (std::size_t index = 0; index < typedFactCount; ++index)
        {
            const BaselineTypedProcessFact& fact =
                context.typedProcessFacts[index];
            ObservationSpec typed;
            typed.sourceRuleId = fact.sourceRuleId;
            typed.producerIdentifier = fact.sourceIdentifier.empty()
                ? "core.baseline-typed-process-source"
                : fact.sourceIdentifier;
            typed.collectionMethod = fact.collectionMethod.empty()
                ? "already-collected-typed-process-evidence"
                : fact.collectionMethod;
            typed.confidence = fact.confidence;
            typed.sourceKind = fact.sourceKind;
            typed.rawValue = fact.rawValue;
            typed.normalizedValue = fact.normalizedValue;
            typed.evidence = fact.evidence;
            typed.limitations = fact.limitations;
            typed.artifactIdentity = {
                ObservationArtifactKind::Process,
                entityScope,
                processArtifact
            };

            switch (fact.kind)
            {
            case BaselineTypedProcessFactKind::ReviewRelevantProcessRelationship:
                typed.mappingRuleId = BaselineMappingProcessRelationship;
                typed.title = "Typed process relationship requires correlation";
                typed.summary =
                    "A producer-authored process-relationship fact is available for typed correlation.";
                typed.domain = EvidenceDomain::ProcessRelationship;
                typed.disposition = ObservationDisposition::CorrelatedOnly;
                typed.strength = ObservationStrength::Moderate;
                typed.contributesToVerdict = false;
                typed.groupingKey = "process-family-relationship";
                typed.correlationKey = "command-relationship-context";
                typed.artifactAttributes.push_back({
                    "relationship.related-pid",
                    std::to_string(fact.relatedPid)
                });
                break;
            case BaselineTypedProcessFactKind::InvalidFileSignature:
                typed.mappingRuleId = BaselineMappingInvalidFileSignature;
                typed.title = "Invalid executable signature observed";
                typed.summary =
                    "An already-collected typed signature result reported an invalid executable signature.";
                typed.domain = EvidenceDomain::FileSignature;
                typed.disposition = ObservationDisposition::ReviewRelevant;
                typed.strength = ObservationStrength::Moderate;
                typed.contributesToVerdict = true;
                typed.groupingKey = "file-signature-status";
                typed.correlationKey = "file-path-signature-context";
                typed.artifactIdentity.kind = ObservationArtifactKind::File;
                typed.artifactIdentity.artifactKey = ArtifactKeyOrDerived(
                    fact.factKey,
                    processArtifact + "|signature|" + fact.normalizedValue);
                break;
            case BaselineTypedProcessFactKind::Unknown:
            default:
                result.success = false;
                result.status = BaselineObservationStatus::InvalidTypedFact;
                result.diagnostic =
                    "A baseline typed process fact has no recognized semantic kind.";
                result.inventory = {};
                result.nativeFactCount = 0;
                return result;
            }

            if (!AddObservation(
                    result,
                    context,
                    entityScope,
                    std::move(typed),
                    observationIds))
            {
                return result;
            }
        }

        const std::size_t connectionCount = std::min(
            context.networkConnections.size(),
            BaselineObservationMaxNetworkConnections);
        if (connectionCount < context.networkConnections.size())
        {
            result.truncated = true;
            result.omittedFactCount +=
                context.networkConnections.size() - connectionCount;
        }
        for (std::size_t index = 0; index < connectionCount; ++index)
        {
            const BaselineNetworkConnectionFact& fact =
                context.networkConnections[index];
            if (!fact.publicRemote)
            {
                continue;
            }
            const std::string endpointIdentity =
                fact.protocol + "|" + fact.localAddress + "|" +
                PortText(fact.localPort) + "|" + fact.remoteAddress + "|" +
                PortText(fact.remotePort);
            ObservationSpec connection;
            connection.mappingRuleId = BaselineMappingPublicNetworkConnection;
            connection.sourceRuleId = BaselineMappingPublicNetworkConnection;
            connection.producerIdentifier = fact.sourceIdentifier.empty()
                ? "core.network-snapshot"
                : fact.sourceIdentifier;
            connection.collectionMethod = fact.collectionMethod.empty()
                ? "normal-endpoint-network-refresh"
                : fact.collectionMethod;
            connection.title = "Public network connection observed";
            connection.summary =
                "A public network connection was observed; public connectivity alone is baseline context.";
            connection.domain = EvidenceDomain::Network;
            connection.disposition = ObservationDisposition::Context;
            connection.strength = ObservationStrength::Weak;
            connection.confidence = ObservationConfidence::High;
            connection.sourceKind = fact.sourceKind;
            connection.groupingKey = "public-network-activity";
            connection.rawValue = endpointIdentity;
            connection.normalizedValue = endpointIdentity;
            connection.artifactIdentity = {
                ObservationArtifactKind::NetworkConnection,
                entityScope,
                ArtifactKeyOrDerived(fact.artifactKey, endpointIdentity)
            };
            connection.artifactAttributes = {
                { "network.protocol", fact.protocol },
                { "network.local-port", PortText(fact.localPort) },
                { "network.remote-port", PortText(fact.remotePort) },
                { "network.public-remote", "true" }
            };
            connection.limitations = fact.limitations;
            if (!AddObservation(
                    result,
                    context,
                    entityScope,
                    std::move(connection),
                    observationIds))
            {
                return result;
            }
        }

        const std::size_t indicatorCount = std::min(
            context.networkIndicatorFacts.size(),
            BaselineObservationMaxNetworkIndicatorFacts);
        if (indicatorCount < context.networkIndicatorFacts.size())
        {
            result.truncated = true;
            result.omittedFactCount +=
                context.networkIndicatorFacts.size() - indicatorCount;
        }
        for (std::size_t index = 0; index < indicatorCount; ++index)
        {
            const BaselineNetworkIndicatorFact& fact =
                context.networkIndicatorFacts[index];
            ObservationSpec indicator;
            indicator.mappingRuleId = BaselineMappingExactNetworkIndicator;
            indicator.sourceRuleId = fact.sourceRuleId.empty()
                ? BaselineMappingExactNetworkIndicator
                : fact.sourceRuleId;
            indicator.producerIdentifier = fact.sourceIdentifier.empty()
                ? "core.network-indicator-matcher"
                : fact.sourceIdentifier;
            indicator.collectionMethod = fact.collectionMethod.empty()
                ? "verified-local-network-indicator-match"
                : fact.collectionMethod;
            indicator.title = "Exact network indicator match observed";
            indicator.summary =
                "An exact attributed Network Intelligence match was retained from already-available endpoint evidence.";
            indicator.domain = EvidenceDomain::Network;
            indicator.disposition = ObservationDisposition::ReviewRelevant;
            indicator.strength = fact.strength == ObservationStrength::Strong
                ? ObservationStrength::Strong
                : ObservationStrength::Moderate;
            indicator.confidence = fact.confidence;
            indicator.sourceKind = fact.sourceKind;
            indicator.contributesToVerdict = true;
            indicator.groupingKey = "network-indicator-match";
            indicator.correlationKey = "network-intelligence-context";
            indicator.rawValue = fact.rawValue;
            indicator.normalizedValue = fact.normalizedValue;
            indicator.artifactIdentity = {
                ObservationArtifactKind::NetworkConnection,
                entityScope,
                ArtifactKeyOrDerived(
                    fact.artifactKey,
                    fact.indicatorType + "|" + fact.normalizedValue)
            };
            indicator.artifactAttributes = {
                { "network-indicator.type", fact.indicatorType },
                { "network-indicator.exact-match", "true" }
            };
            indicator.assessmentRationale = fact.assessmentRationale;
            indicator.limitations = fact.limitations;
            if (indicator.strength == ObservationStrength::Strong &&
                indicator.assessmentRationale.empty())
            {
                indicator.strength = ObservationStrength::Moderate;
                indicator.limitations.push_back(
                    "A Strong source assessment requires an explicit rationale; this baseline fact was retained as Moderate.");
            }
            if (!AddObservation(
                    result,
                    context,
                    entityScope,
                    std::move(indicator),
                    observationIds))
            {
                return result;
            }
        }

        const std::size_t serviceCount = std::min(
            context.serviceAssociations.size(),
            BaselineObservationMaxServiceAssociations);
        if (serviceCount < context.serviceAssociations.size())
        {
            result.truncated = true;
            result.omittedFactCount +=
                context.serviceAssociations.size() - serviceCount;
        }
        for (std::size_t index = 0; index < serviceCount; ++index)
        {
            const BaselineServiceAssociationFact& fact =
                context.serviceAssociations[index];
            const std::string serviceIdentity = fact.serviceName + "|" +
                std::to_string(process.pid);
            ObservationSpec service;
            service.mappingRuleId = BaselineMappingServiceAssociation;
            service.sourceRuleId = BaselineMappingServiceAssociation;
            service.producerIdentifier = fact.sourceIdentifier.empty()
                ? "core.service-snapshot-pid-index"
                : fact.sourceIdentifier;
            service.collectionMethod = fact.collectionMethod.empty()
                ? "existing-scm-reported-pid-association"
                : fact.collectionMethod;
            service.title = "Active service association observed";
            service.summary =
                "An active service record was correlated by SCM-reported PID; this association is baseline context, not verified process ownership.";
            service.domain = EvidenceDomain::Service;
            service.disposition = ObservationDisposition::Context;
            service.strength = ObservationStrength::None;
            service.confidence = ObservationConfidence::High;
            service.sourceKind = fact.sourceKind;
            service.groupingKey = "service-pid-association";
            service.rawValue = fact.serviceName;
            service.normalizedValue = fact.serviceName;
            service.artifactIdentity = {
                ObservationArtifactKind::Service,
                entityScope,
                ArtifactKeyOrDerived(fact.artifactKey, serviceIdentity)
            };
            service.artifactAttributes = {
                { "service.process-model", ServiceModelText(fact.processModel) },
                { "service.state-raw", HexRaw(fact.stateRaw) },
                { "service.scm-pid", std::to_string(process.pid) }
            };
            service.evidence.push_back(fact.displayName.empty()
                ? fact.serviceName
                : fact.displayName);
            service.limitations = fact.limitations;
            if (!AddObservation(
                    result,
                    context,
                    entityScope,
                    std::move(service),
                    observationIds))
            {
                return result;
            }
        }

        const std::size_t collectionFactCount = std::min(
            context.collectionFacts.size(),
            BaselineObservationMaxCollectionFacts);
        if (collectionFactCount < context.collectionFacts.size())
        {
            result.truncated = true;
            result.omittedFactCount +=
                context.collectionFacts.size() - collectionFactCount;
        }
        for (std::size_t index = 0; index < collectionFactCount; ++index)
        {
            const BaselineCollectionFact& fact = context.collectionFacts[index];
            ObservationSpec note;
            note.sourceRuleId = fact.sourceRuleId;
            note.producerIdentifier = fact.sourceIdentifier;
            note.collectionMethod = fact.collectionMethod;
            note.domain = EvidenceDomain::CollectionQuality;
            note.disposition = ObservationDisposition::CollectionNote;
            note.strength = ObservationStrength::None;
            note.confidence = ObservationConfidence::High;
            note.sourceKind = ObservationSourceKind::Unavailable;
            note.contributesToVerdict = false;
            note.groupingKey = "baseline-collection-quality";
            note.rawValue = fact.statusMessage;
            note.normalizedValue = fact.statusMessage;
            note.limitations = fact.limitations;

            switch (fact.kind)
            {
            case BaselineCollectionFactKind::NetworkUnavailable:
                note.mappingRuleId =
                    BaselineMappingNetworkCollectionUnavailable;
                if (note.sourceRuleId.empty())
                {
                    note.sourceRuleId =
                        BaselineMappingNetworkCollectionUnavailable;
                }
                if (note.producerIdentifier.empty())
                {
                    note.producerIdentifier = "core.network-snapshot";
                }
                if (note.collectionMethod.empty())
                {
                    note.collectionMethod =
                        "normal-endpoint-network-refresh";
                }
                note.title = "Network baseline collection unavailable";
                note.summary =
                    "Endpoint network collection was explicitly reported unavailable for this baseline generation.";
                break;
            case BaselineCollectionFactKind::ServiceUnavailable:
                note.mappingRuleId =
                    BaselineMappingServiceCollectionUnavailable;
                if (note.sourceRuleId.empty())
                {
                    note.sourceRuleId =
                        BaselineMappingServiceCollectionUnavailable;
                }
                if (note.producerIdentifier.empty())
                {
                    note.producerIdentifier = "core.service-snapshot";
                }
                if (note.collectionMethod.empty())
                {
                    note.collectionMethod =
                        "normal-endpoint-service-refresh";
                }
                note.title = "Service baseline collection unavailable";
                note.summary =
                    "Endpoint service collection was explicitly attempted and reported unavailable for this baseline generation.";
                break;
            case BaselineCollectionFactKind::Unknown:
            default:
                result.success = false;
                result.status = BaselineObservationStatus::InvalidTypedFact;
                result.diagnostic =
                    "A baseline collection fact has no recognized semantic kind.";
                result.inventory = {};
                result.nativeFactCount = 0;
                return result;
            }

            note.limitations.push_back(
                "Collection availability does not establish benign or suspicious process behavior.");
            if (!AddObservation(
                    result,
                    context,
                    entityScope,
                    std::move(note),
                    observationIds))
            {
                return result;
            }
        }

        FinalizeInventory(result);
        std::ostringstream diagnostic;
        diagnostic << "Baseline observations built: "
                   << result.inventory.records.size()
                   << " typed facts represented";
        if (result.omittedFactCount != 0)
        {
            diagnostic << ", " << result.omittedFactCount
                       << " facts omitted by bounded caps";
        }
        diagnostic << '.';
        result.diagnostic = diagnostic.str();
        LimitString(
            result.diagnostic,
            BaselineObservationDiagnosticMaxCharacters);
        return result;
    }
}
