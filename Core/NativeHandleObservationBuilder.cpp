#include "NativeHandleObservationBuilder.h"

#include "ObservationPolicy.h"

#include <algorithm>
#include <climits>
#include <iomanip>
#include <map>
#include <sstream>
#include <string_view>
#include <tuple>
#include <utility>

namespace GlassPane::Core
{
    namespace
    {
        constexpr std::uint32_t SynchronizeAccess = 0x00100000U;

        constexpr std::uint32_t ProcessCreateThread = 0x00000002U;
        constexpr std::uint32_t ProcessVmOperation = 0x00000008U;
        constexpr std::uint32_t ProcessVmRead = 0x00000010U;
        constexpr std::uint32_t ProcessVmWrite = 0x00000020U;
        constexpr std::uint32_t ProcessDuplicateHandle = 0x00000040U;
        constexpr std::uint32_t ProcessCreateProcess = 0x00000080U;
        constexpr std::uint32_t ProcessQueryInformation = 0x00000400U;
        constexpr std::uint32_t ProcessQueryLimitedInformation = 0x00001000U;

        constexpr std::uint32_t ThreadSetContext = 0x00000010U;
        constexpr std::uint32_t ThreadQueryInformation = 0x00000040U;
        constexpr std::uint32_t ThreadImpersonate = 0x00000100U;
        constexpr std::uint32_t ThreadDirectImpersonation = 0x00000200U;
        constexpr std::uint32_t ThreadQueryLimitedInformation = 0x00000800U;

        constexpr std::uint32_t TokenAssignPrimary = 0x00000001U;
        constexpr std::uint32_t TokenDuplicate = 0x00000002U;
        constexpr std::uint32_t TokenQuery = 0x00000008U;
        constexpr std::uint32_t TokenQuerySource = 0x00000010U;

        struct TargetResolution
        {
            bool hasTarget = false;
            bool self = false;
            bool exact = false;
            bool ambiguous = false;
            std::uint32_t pid = 0;
            ProcessIdentityKey identity;
        };

        struct DeduplicatedHandle
        {
            HandleInfo handle;
            NativeHandleObjectKind kind = NativeHandleObjectKind::Unknown;
            TargetResolution target;
            NativeHandleAccessCategories access;
            std::string artifactKey;
            std::string semanticKey;
            std::size_t rowCount = 1;
        };

        using TargetIdentityKey = std::tuple<
            std::uint64_t,
            NativeHandleObjectKind,
            std::uint32_t>;
        using TargetIdentityIndex = std::map<
            TargetIdentityKey,
            std::vector<const NativeHandleTargetIdentity*>>;

        bool SameIdentity(
            const ProcessIdentityKey& left,
            const ProcessIdentityKey& right)
        {
            return left.pid == right.pid &&
                left.hasCreationTime == right.hasCreationTime &&
                left.creationTimeFileTime == right.creationTimeFileTime;
        }

        bool ValidIdentity(const ProcessIdentityKey& identity)
        {
            return identity.hasCreationTime ||
                identity.creationTimeFileTime == 0;
        }

        std::string EntityScope(const ProcessIdentityKey& identity)
        {
            std::ostringstream stream;
            stream << "process:pid:" << identity.pid << ":creation:";
            if (identity.hasCreationTime)
            {
                stream << identity.creationTimeFileTime;
            }
            else
            {
                stream << "unavailable";
            }
            return stream.str();
        }

        std::string ProcessArtifactKey(const ProcessIdentityKey& identity)
        {
            std::ostringstream stream;
            stream << "pid:" << identity.pid << ":creation:";
            if (identity.hasCreationTime)
            {
                stream << identity.creationTimeFileTime;
            }
            else
            {
                stream << "unavailable";
            }
            return stream.str();
        }

        wchar_t LowerAscii(wchar_t value)
        {
            return value >= L'A' && value <= L'Z'
                ? static_cast<wchar_t>(value - L'A' + L'a')
                : value;
        }

        bool EqualsAsciiInsensitive(
            std::wstring_view value,
            std::wstring_view expected)
        {
            if (value.size() != expected.size())
            {
                return false;
            }
            for (std::size_t index = 0; index < value.size(); ++index)
            {
                if (LowerAscii(value[index]) != LowerAscii(expected[index]))
                {
                    return false;
                }
            }
            return true;
        }

        void AppendUtf8CodePoint(
            std::string& output,
            std::uint32_t codePoint)
        {
            if (codePoint <= 0x7FU)
            {
                output.push_back(static_cast<char>(codePoint));
            }
            else if (codePoint <= 0x7FFU)
            {
                output.push_back(static_cast<char>(0xC0U | (codePoint >> 6U)));
                output.push_back(static_cast<char>(0x80U | (codePoint & 0x3FU)));
            }
            else if (codePoint <= 0xFFFFU)
            {
                output.push_back(static_cast<char>(0xE0U | (codePoint >> 12U)));
                output.push_back(static_cast<char>(0x80U | ((codePoint >> 6U) & 0x3FU)));
                output.push_back(static_cast<char>(0x80U | (codePoint & 0x3FU)));
            }
            else
            {
                output.push_back(static_cast<char>(0xF0U | (codePoint >> 18U)));
                output.push_back(static_cast<char>(0x80U | ((codePoint >> 12U) & 0x3FU)));
                output.push_back(static_cast<char>(0x80U | ((codePoint >> 6U) & 0x3FU)));
                output.push_back(static_cast<char>(0x80U | (codePoint & 0x3FU)));
            }
        }

        std::string WideToUtf8Bounded(
            std::wstring_view input,
            std::size_t maximumBytes,
            bool& truncated)
        {
            std::string output;
            output.reserve(std::min(input.size(), maximumBytes));
            for (std::size_t index = 0; index < input.size(); ++index)
            {
                std::uint32_t codePoint =
                    static_cast<std::uint32_t>(input[index]);
#if WCHAR_MAX <= 0xFFFF
                if (codePoint >= 0xD800U && codePoint <= 0xDBFFU &&
                    index + 1 < input.size())
                {
                    const std::uint32_t low =
                        static_cast<std::uint32_t>(input[index + 1]);
                    if (low >= 0xDC00U && low <= 0xDFFFU)
                    {
                        codePoint = 0x10000U +
                            ((codePoint - 0xD800U) << 10U) +
                            (low - 0xDC00U);
                        ++index;
                    }
                }
#endif
                std::string encoded;
                AppendUtf8CodePoint(encoded, codePoint);
                if (output.size() + encoded.size() > maximumBytes)
                {
                    truncated = true;
                    break;
                }
                output += encoded;
            }
            return output;
        }

        std::string BoundedCopy(
            std::string value,
            std::size_t maximumCharacters,
            bool& truncated)
        {
            if (value.size() > maximumCharacters)
            {
                value.resize(maximumCharacters);
                truncated = true;
            }
            return value;
        }

        std::uint64_t Fingerprint(std::string_view value)
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

        std::string Hex(std::uint64_t value, std::size_t width)
        {
            std::ostringstream stream;
            stream << std::hex << std::setw(static_cast<int>(width))
                   << std::setfill('0') << value;
            return stream.str();
        }

        std::string FingerprintText(std::string_view value)
        {
            return Hex(Fingerprint(value), 16);
        }

        std::string IdentityText(const ProcessIdentityKey& identity)
        {
            std::ostringstream stream;
            stream << identity.pid << '@';
            if (identity.hasCreationTime)
            {
                stream << identity.creationTimeFileTime;
            }
            else
            {
                stream << "unavailable";
            }
            return stream.str();
        }

        TargetResolution ResolveTarget(
            const NativeHandleObservationInput& input,
            const TargetIdentityIndex& targetIndex,
            const HandleInfo& handle,
            NativeHandleObjectKind kind)
        {
            TargetResolution result;
            if (!handle.targetPid.has_value())
            {
                return result;
            }
            result.hasTarget = true;
            result.pid = handle.targetPid.value();
            result.self = result.pid == input.sourceIdentity.pid;
            if (result.self)
            {
                result.exact = true;
                result.identity = input.sourceIdentity;
                return result;
            }

            const auto indexedBindings = targetIndex.find(
                { handle.handleValue, kind, result.pid });
            if (indexedBindings == targetIndex.end())
            {
                return result;
            }

            for (const NativeHandleTargetIdentity* bindingPointer :
                indexedBindings->second)
            {
                if (bindingPointer == nullptr)
                {
                    continue;
                }
                const NativeHandleTargetIdentity& binding = *bindingPointer;
                if (binding.targetPid != result.pid ||
                    (binding.identityResolved &&
                        binding.identity.pid != result.pid))
                {
                    result.ambiguous = true;
                    continue;
                }
                if (binding.pidReuseAmbiguous)
                {
                    result.ambiguous = true;
                    continue;
                }
                if (!binding.identityResolved ||
                    !binding.identity.hasCreationTime ||
                    binding.identity.pid != result.pid)
                {
                    continue;
                }
                if (result.exact &&
                    !SameIdentity(result.identity, binding.identity))
                {
                    result.exact = false;
                    result.ambiguous = true;
                    continue;
                }
                result.identity = binding.identity;
                result.exact = true;
            }
            if (result.ambiguous)
            {
                result.exact = false;
            }
            return result;
        }

        std::string TargetKey(const TargetResolution& target)
        {
            if (!target.hasTarget)
            {
                return "none";
            }
            if (target.self)
            {
                return "self:" + IdentityText(target.identity);
            }
            if (target.ambiguous)
            {
                return "ambiguous-pid:" + std::to_string(target.pid);
            }
            if (target.exact)
            {
                return "process:" + IdentityText(target.identity);
            }
            return "unresolved-pid:" + std::to_string(target.pid);
        }

        std::string ArtifactKey(
            const HandleInfo& handle,
            NativeHandleObjectKind kind,
            const TargetResolution& target)
        {
            std::ostringstream stream;
            stream << "handle:" << Hex(handle.handleValue, 16)
                   << ":type:" << static_cast<std::uint32_t>(kind)
                   << ":target:" << TargetKey(target)
                   << ":access:" << Hex(handle.grantedAccessRaw, 8);
            return stream.str();
        }

        void AddBooleanAttribute(
            std::vector<ObservationArtifactAttribute>& attributes,
            const char* key,
            bool value)
        {
            if (value)
            {
                attributes.push_back({ key, "true" });
            }
        }

        void CountDisposition(
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
            }
        }

        bool AddRecord(
            NativeHandleObservationBuildResult& result,
            const NativeHandleObservationInput& input,
            const std::string& entityScope,
            std::string mappingRuleId,
            std::string semanticKey,
            std::string title,
            std::string summary,
            EvidenceDomain domain,
            ObservationDisposition disposition,
            ObservationStrength strength,
            ObservationConfidence confidence,
            bool contributes,
            std::string groupingKey,
            std::string correlationKey,
            ObservationArtifactIdentity artifactIdentity,
            std::vector<ObservationArtifactAttribute> attributes,
            std::vector<std::string> evidence,
            std::vector<std::string> limitations,
            ObservationSourceKind sourceKind)
        {
            if (result.records.size() >=
                NativeHandleObservationMaxOutputRecords ||
                semanticKey.empty() ||
                semanticKey.size() >
                    NativeHandleObservationSemanticKeyMaxCharacters)
            {
                result.success = false;
                result.status = semanticKey.empty() ||
                    semanticKey.size() >
                        NativeHandleObservationSemanticKeyMaxCharacters
                    ? NativeHandleObservationBuildStatus::InvalidTypedFact
                    : NativeHandleObservationBuildStatus::InputLimitExceeded;
                result.diagnostic =
                    "Native handle observation output exceeded a bounded cap or lacked semantic identity.";
                return false;
            }

            bool bounded = false;
            const std::string fingerprint = FingerprintText(
                entityScope + "|" + semanticKey);
            NativeHandleObservationRecord output;
            output.semanticFactKey = semanticKey;
            ObservationRecord& record = output.record;
            record.source.sourceRecordId = "native-handle-source:" + fingerprint;
            record.source.sourceRuleId = BoundedCopy(
                mappingRuleId,
                ObservationRuleIdMaxCharacters,
                bounded);
            record.source.mappingRuleId = record.source.sourceRuleId;
            record.source.sourceTitle = BoundedCopy(
                title,
                ObservationTitleMaxCharacters,
                bounded);
            record.source.sourceMessage = BoundedCopy(
                summary,
                ObservationSourceMessageMaxCharacters,
                bounded);
            record.source.sourceCategory =
                NativeHandleObservationSourceCategory;
            record.source.producerIdentifier = BoundedCopy(
                input.source.sourceIdentifier.empty()
                    ? std::string("core.native-handle-observation")
                    : input.source.sourceIdentifier,
                ObservationProvenanceSourceIdentifierMaxCharacters,
                bounded);
            record.source.rawValueExplicitlySupplied = true;
            record.source.normalizedValueExplicitlySupplied = true;

            Observation& observation = record.observation;
            observation.id = "native-handle-observation:" + fingerprint;
            observation.ruleId = record.source.sourceRuleId;
            observation.title = record.source.sourceTitle;
            observation.summary = record.source.sourceMessage;
            observation.domain = domain;
            observation.sourceKind = sourceKind;
            observation.disposition = disposition;
            observation.strength = strength;
            observation.confidence = confidence;
            observation.contributesToVerdict = contributes;
            observation.entityScope = entityScope;
            observation.groupingKey = BoundedCopy(
                groupingKey,
                ObservationGroupingKeyMaxCharacters,
                bounded);
            observation.correlationKey = BoundedCopy(
                correlationKey,
                ObservationCorrelationKeyMaxCharacters,
                bounded);
            observation.rawValue = BoundedCopy(
                semanticKey,
                ObservationRawValueMaxCharacters,
                bounded);
            observation.normalizedValue = observation.rawValue;
            artifactIdentity.entityScope = entityScope;
            artifactIdentity.artifactKey = BoundedCopy(
                artifactIdentity.artifactKey,
                ObservationArtifactKeyMaxCharacters,
                bounded);
            observation.artifactIdentity = std::move(artifactIdentity);
            if (attributes.size() > ObservationMaxArtifactAttributes)
            {
                attributes.resize(ObservationMaxArtifactAttributes);
                bounded = true;
            }
            observation.artifactAttributes = std::move(attributes);

            auto appendBounded = [&](const std::vector<std::string>& source,
                                     std::vector<std::string>& destination,
                                     std::size_t maximumItems,
                                     std::size_t maximumCharacters)
            {
                for (const std::string& item : source)
                {
                    if (destination.size() >= maximumItems)
                    {
                        bounded = true;
                        break;
                    }
                    destination.push_back(BoundedCopy(
                        item,
                        maximumCharacters,
                        bounded));
                }
            };
            appendBounded(
                evidence,
                observation.evidence,
                ObservationMaxEvidenceItems,
                ObservationEvidenceItemMaxCharacters);
            appendBounded(
                limitations,
                observation.limitations,
                ObservationMaxLimitationItems,
                ObservationLimitationItemMaxCharacters);
            appendBounded(
                input.source.limitations,
                observation.limitations,
                ObservationMaxLimitationItems,
                ObservationLimitationItemMaxCharacters);
            appendBounded(
                input.limitations,
                observation.limitations,
                ObservationMaxLimitationItems,
                ObservationLimitationItemMaxCharacters);
            if (bounded && observation.limitations.size() <
                ObservationMaxLimitationItems)
            {
                observation.limitations.push_back(
                    "One or more native handle values were truncated to their bounded representation.");
            }

            observation.provenance.sourceKind = sourceKind;
            observation.provenance.sourceIdentifier =
                record.source.producerIdentifier;
            observation.provenance.collectionMethod = BoundedCopy(
                input.source.collectionMethod,
                ObservationProvenanceCollectionMethodMaxCharacters,
                bounded);
            observation.provenance.collectionTimestamp = BoundedCopy(
                input.source.collectionTimestamp,
                ObservationProvenanceCollectionTimestampMaxCharacters,
                bounded);
            observation.provenance.requiredPrivilege = BoundedCopy(
                input.source.requiredPrivilege,
                ObservationProvenanceRequiredPrivilegeMaxCharacters,
                bounded);
            observation.provenance.sourceAvailable =
                sourceKind != ObservationSourceKind::Unavailable;
            observation.provenance.rawSourceReference = BoundedCopy(
                input.source.rawSourceReference.empty()
                    ? record.source.sourceRecordId
                    : input.source.rawSourceReference,
                ObservationProvenanceRawSourceReferenceMaxCharacters,
                bounded);
            observation.provenance.limitations = observation.limitations;

            observation = NormalizeObservationPolicy(std::move(observation));
            if (!ValidateObservation(observation).IsValid())
            {
                result.success = false;
                result.status =
                    NativeHandleObservationBuildStatus::PolicyValidationFailed;
                result.diagnostic =
                    "A native handle observation failed bounded policy validation.";
                return false;
            }
            result.truncated = result.truncated || bounded;
            result.records.push_back(std::move(output));
            return true;
        }

        void ChoosePolicy(
            const DeduplicatedHandle& source,
            std::string& mapping,
            std::string& title,
            std::string& summary,
            ObservationDisposition& disposition,
            ObservationStrength& strength,
            bool& contributes,
            std::string& grouping,
            std::string& correlation,
            std::vector<std::string>& limitations)
        {
            mapping = NativeHandleMappingGenericContext;
            title = "Handle metadata observed";
            summary =
                "A handle and its typed access metadata were recorded for the selected process.";
            disposition = ObservationDisposition::Context;
            strength = ObservationStrength::None;
            contributes = false;
            grouping = "handle-access-context";
            correlation.clear();

            if (source.target.self)
            {
                mapping = NativeHandleMappingSelfAccessContext;
                title = "Self-handle access observed";
                summary =
                    "The selected process holds a handle that resolves to its own process identity.";
                return;
            }

            const bool exactExternal = source.target.hasTarget &&
                !source.target.self && source.target.exact &&
                !source.target.ambiguous;
            if (source.target.hasTarget && !exactExternal)
            {
                limitations.push_back(source.target.ambiguous
                    ? "Target identity is ambiguous because PID reuse could not be excluded; the handle remains non-contributing context."
                    : "Target creation identity was not resolved; the handle remains non-contributing context.");
            }

            if (source.kind == NativeHandleObjectKind::Process)
            {
                grouping = source.access.HasSensitiveProcessAccess()
                    ? "sensitive-handle-context"
                    : "handle-access-context";
                if (exactExternal &&
                    source.access.HasSensitiveProcessAccess())
                {
                    mapping = NativeHandleMappingSensitiveExternalAccess;
                    title = "Sensitive external process access observed";
                    summary =
                        "A handle to a resolved external process grants one or more typed cross-process access categories.";
                    disposition = ObservationDisposition::ReviewRelevant;
                    strength = ObservationStrength::Moderate;
                    contributes = true;
                    correlation = "sensitive-handle-context";
                }
                else if (exactExternal && source.access.vmRead)
                {
                    mapping = NativeHandleMappingExternalVmRead;
                    title = "External process memory-read access observed";
                    summary =
                        "A handle to a resolved external process grants virtual-memory read access.";
                    disposition = ObservationDisposition::ReviewRelevant;
                    strength = ObservationStrength::Weak;
                    contributes = true;
                    correlation = "sensitive-handle-context";
                }
                else if (exactExternal)
                {
                    mapping = NativeHandleMappingExternalAccessContext;
                    title = "External process handle context observed";
                    summary =
                        "A handle to a resolved external process grants context-only access categories.";
                }
            }
            else if (source.kind == NativeHandleObjectKind::Thread)
            {
                if (exactExternal &&
                    source.access.HasSensitiveThreadAccess())
                {
                    mapping = NativeHandleMappingSensitiveExternalThreadAccess;
                    title = "Sensitive external thread access observed";
                    summary =
                        "A handle to a resolved external thread grants typed context-change or impersonation access.";
                    disposition = ObservationDisposition::ReviewRelevant;
                    strength = ObservationStrength::Moderate;
                    contributes = true;
                    grouping = "sensitive-handle-context";
                    correlation = "sensitive-handle-context";
                }
            }
            else if (source.kind == NativeHandleObjectKind::Token)
            {
                grouping = "token-handle-context";
                if (source.access.HasTokenManipulationAccess())
                {
                    mapping = NativeHandleMappingTokenManipulationRights;
                    title = "Token manipulation access rights observed";
                    summary =
                        "A token handle grants duplication or primary-assignment access. It contributes only through an explicit typed correlation.";
                    disposition = ObservationDisposition::CorrelatedOnly;
                    strength = ObservationStrength::Moderate;
                    correlation = "token-manipulation-access";
                }
                else
                {
                    mapping = NativeHandleMappingTokenContext;
                    title = "Token handle context observed";
                    summary =
                        "A token handle was recorded. Token-handle presence alone is non-contributing context.";
                }
            }
        }

        std::vector<ObservationArtifactAttribute> Attributes(
            const DeduplicatedHandle& source,
            const ProcessIdentityKey& sourceIdentity)
        {
            std::vector<ObservationArtifactAttribute> attributes = {
                { "handle.source.pid", std::to_string(sourceIdentity.pid) },
                { "handle.source.creation-time", std::to_string(sourceIdentity.creationTimeFileTime) },
                { "handle.value", "0x" + Hex(source.handle.handleValue, 16) },
                { "handle.object-kind", NativeHandleObjectKindDisplayText(source.kind) },
                { "handle.access-mask", "0x" + Hex(source.handle.grantedAccessRaw, 8) },
                { "handle.source-row-count", std::to_string(source.rowCount) }
            };
            if (source.target.hasTarget)
            {
                attributes.push_back({
                    "handle.target.pid",
                    std::to_string(source.target.pid)
                });
                attributes.push_back({
                    "handle.target.identity",
                    TargetKey(source.target)
                });
                if (source.target.exact &&
                    source.target.identity.hasCreationTime)
                {
                    attributes.push_back({
                        "handle.target.creation-time",
                        std::to_string(
                            source.target.identity.creationTimeFileTime)
                    });
                }
            }
            AddBooleanAttribute(attributes, "access.synchronize", source.access.synchronize);
            AddBooleanAttribute(attributes, "access.query", source.access.query);
            AddBooleanAttribute(attributes, "access.vm-read", source.access.vmRead);
            AddBooleanAttribute(attributes, "access.vm-write", source.access.vmWrite);
            AddBooleanAttribute(attributes, "access.vm-operation", source.access.vmOperation);
            AddBooleanAttribute(attributes, "access.create-thread", source.access.createThread);
            AddBooleanAttribute(attributes, "access.duplicate-handle", source.access.duplicateHandle);
            AddBooleanAttribute(attributes, "access.create-process", source.access.createProcess);
            AddBooleanAttribute(attributes, "access.thread-set-context", source.access.threadSetContext);
            AddBooleanAttribute(attributes, "access.thread-impersonate", source.access.threadImpersonate);
            AddBooleanAttribute(attributes, "access.token-duplicate", source.access.tokenDuplicate);
            AddBooleanAttribute(attributes, "access.token-assign-primary", source.access.tokenAssignPrimary);
            return attributes;
        }

        void FinalizeInventory(NativeHandleObservationBuildResult& result)
        {
            result.inventory = {};
            result.representedArtifactCount = 0;
            for (const NativeHandleObservationRecord& source : result.records)
            {
                result.inventory.records.push_back(source.record);
                CountDisposition(
                    result.inventory,
                    source.record.observation.disposition);
                if (source.record.observation.domain == EvidenceDomain::Handle)
                {
                    ++result.representedArtifactCount;
                }
            }
            result.inventory.typedSourceFactCount =
                result.inventory.records.size();
        }
    }

    bool NativeHandleAccessCategories::HasSensitiveProcessAccess() const
    {
        return vmWrite || vmOperation || createThread || duplicateHandle ||
            createProcess;
    }

    bool NativeHandleAccessCategories::HasSensitiveThreadAccess() const
    {
        return threadSetContext || threadImpersonate;
    }

    bool NativeHandleAccessCategories::HasTokenManipulationAccess() const
    {
        return tokenDuplicate || tokenAssignPrimary;
    }

    NativeHandleObjectKind ClassifyNativeHandleObjectKind(
        const HandleInfo& handle)
    {
        if (!handle.typeResolved)
        {
            return NativeHandleObjectKind::Unknown;
        }
        if (EqualsAsciiInsensitive(handle.objectType, L"Process"))
        {
            return NativeHandleObjectKind::Process;
        }
        if (EqualsAsciiInsensitive(handle.objectType, L"Thread"))
        {
            return NativeHandleObjectKind::Thread;
        }
        if (EqualsAsciiInsensitive(handle.objectType, L"Token"))
        {
            return NativeHandleObjectKind::Token;
        }
        if (EqualsAsciiInsensitive(handle.objectType, L"Section"))
        {
            return NativeHandleObjectKind::Section;
        }
        if (EqualsAsciiInsensitive(handle.objectType, L"File"))
        {
            return NativeHandleObjectKind::File;
        }
        if (EqualsAsciiInsensitive(handle.objectType, L"Key"))
        {
            return NativeHandleObjectKind::RegistryKey;
        }
        return NativeHandleObjectKind::Other;
    }

    std::string NativeHandleObjectKindDisplayText(NativeHandleObjectKind kind)
    {
        switch (kind)
        {
        case NativeHandleObjectKind::Unknown:
            return "unknown";
        case NativeHandleObjectKind::Process:
            return "process";
        case NativeHandleObjectKind::Thread:
            return "thread";
        case NativeHandleObjectKind::Token:
            return "token";
        case NativeHandleObjectKind::Section:
            return "section";
        case NativeHandleObjectKind::File:
            return "file";
        case NativeHandleObjectKind::RegistryKey:
            return "registry-key";
        case NativeHandleObjectKind::Other:
            return "other";
        }
        return "unknown";
    }

    NativeHandleAccessCategories CategorizeNativeHandleAccess(
        NativeHandleObjectKind kind,
        std::uint32_t accessMask)
    {
        NativeHandleAccessCategories result;
        result.synchronize = (accessMask & SynchronizeAccess) != 0;
        switch (kind)
        {
        case NativeHandleObjectKind::Process:
            result.query = (accessMask &
                (ProcessQueryInformation |
                    ProcessQueryLimitedInformation)) != 0;
            result.vmRead = (accessMask & ProcessVmRead) != 0;
            result.vmWrite = (accessMask & ProcessVmWrite) != 0;
            result.vmOperation = (accessMask & ProcessVmOperation) != 0;
            result.createThread = (accessMask & ProcessCreateThread) != 0;
            result.duplicateHandle =
                (accessMask & ProcessDuplicateHandle) != 0;
            result.createProcess =
                (accessMask & ProcessCreateProcess) != 0;
            break;
        case NativeHandleObjectKind::Thread:
            result.query = (accessMask &
                (ThreadQueryInformation |
                    ThreadQueryLimitedInformation)) != 0;
            result.threadSetContext =
                (accessMask & ThreadSetContext) != 0;
            result.threadImpersonate = (accessMask &
                (ThreadImpersonate |
                    ThreadDirectImpersonation)) != 0;
            break;
        case NativeHandleObjectKind::Token:
            result.query = (accessMask &
                (TokenQuery | TokenQuerySource)) != 0;
            result.tokenDuplicate = (accessMask & TokenDuplicate) != 0;
            result.tokenAssignPrimary =
                (accessMask & TokenAssignPrimary) != 0;
            break;
        default:
            break;
        }
        return result;
    }

    bool NativeHandleObservationBuildResult::Succeeded() const
    {
        return attempted && success &&
            status == NativeHandleObservationBuildStatus::Success &&
            inventory.Succeeded();
    }

    NativeHandleObservationBuildResult BuildNativeHandleObservations(
        const NativeHandleObservationInput& input) noexcept
    {
        NativeHandleObservationBuildResult result;
        result.attempted = true;
        try
        {
            if (!ValidIdentity(input.sourceIdentity))
            {
                result.status =
                    NativeHandleObservationBuildStatus::InvalidIdentity;
                result.diagnostic = "The source process identity is contradictory.";
                return result;
            }
            const std::string entityScope = input.entityScope.empty()
                ? EntityScope(input.sourceIdentity)
                : input.entityScope;
            if (entityScope.empty() ||
                entityScope.size() > ObservationEntityScopeMaxCharacters)
            {
                result.status =
                    NativeHandleObservationBuildStatus::InvalidIdentity;
                result.diagnostic =
                    "The source process entity scope is missing or exceeds its cap.";
                return result;
            }
            if (input.collection.handles.size() >
                    NativeHandleObservationMaxRows ||
                input.targetIdentities.size() >
                    NativeHandleObservationMaxTargetIdentities ||
                input.limitations.size() > ObservationMaxLimitationItems)
            {
                result.status =
                    NativeHandleObservationBuildStatus::InputLimitExceeded;
                result.diagnostic =
                    "Native handle typed input exceeded a bounded cap.";
                return result;
            }
            if (!input.sourceTruncated && input.omittedHandleCount != 0)
            {
                result.status =
                    NativeHandleObservationBuildStatus::InvalidTypedFact;
                result.diagnostic =
                    "Omitted handle rows were declared without a truncated source capture.";
                return result;
            }

            result.success = true;
            if (!input.supplied)
            {
                result.status = NativeHandleObservationBuildStatus::Success;
                result.diagnostic =
                    "No selected-process handle evidence was supplied; optional absence is authoritative.";
                return result;
            }
            if (input.collection.pid != input.sourceIdentity.pid)
            {
                result.success = false;
                result.status =
                    NativeHandleObservationBuildStatus::InvalidIdentity;
                result.diagnostic =
                    "Handle collection identity does not match the selected process identity.";
                return result;
            }

            const std::string processArtifact =
                ProcessArtifactKey(input.sourceIdentity);
            if (!input.collection.success)
            {
                if (input.collectionAttempted)
                {
                    bool bounded = false;
                    std::vector<std::string> limitations = {
                        "Unavailable handle metadata does not imply benign or suspicious activity."
                    };
                    if (!input.collection.statusMessage.empty())
                    {
                        limitations.push_back(WideToUtf8Bounded(
                            input.collection.statusMessage,
                            ObservationLimitationItemMaxCharacters,
                            bounded));
                    }
                    if (!AddRecord(
                            result,
                            input,
                            entityScope,
                            NativeHandleMappingCollectionUnavailable,
                            "collection.handle-enumeration|" + processArtifact,
                            "Handle metadata unavailable",
                            "Handle enumeration was attempted for the selected process but was unavailable.",
                            EvidenceDomain::CollectionQuality,
                            ObservationDisposition::CollectionNote,
                            ObservationStrength::None,
                            ObservationConfidence::High,
                            false,
                            "selected-collection-quality",
                            {},
                            { ObservationArtifactKind::Process, entityScope, processArtifact },
                            {},
                            {},
                            std::move(limitations),
                            ObservationSourceKind::Unavailable))
                    {
                        result.records.clear();
                        return result;
                    }
                    result.truncated = result.truncated || bounded;
                }
                FinalizeInventory(result);
                result.status = NativeHandleObservationBuildStatus::Success;
                result.diagnostic =
                    "Native handle evidence represented as a collection limitation.";
                return result;
            }

            result.sourceRowCount = input.collection.handles.size();
            TargetIdentityIndex targetIndex;
            for (const NativeHandleTargetIdentity& binding :
                input.targetIdentities)
            {
                targetIndex[
                    { binding.handleValue,
                      binding.objectKind,
                      binding.targetPid }]
                    .push_back(&binding);
            }
            std::map<std::string, DeduplicatedHandle> deduplicated;
            for (const HandleInfo& handle : input.collection.handles)
            {
                if (handle.owningPid != input.sourceIdentity.pid)
                {
                    result.success = false;
                    result.status =
                        NativeHandleObservationBuildStatus::InvalidIdentity;
                    result.diagnostic =
                        "A handle row belongs to a different source process identity.";
                    result.records.clear();
                    return result;
                }
                DeduplicatedHandle source;
                source.handle = handle;
                source.kind = ClassifyNativeHandleObjectKind(handle);
                source.target = ResolveTarget(
                    input,
                    targetIndex,
                    handle,
                    source.kind);
                source.access = CategorizeNativeHandleAccess(
                    source.kind,
                    handle.grantedAccessRaw);
                source.artifactKey = ArtifactKey(
                    handle,
                    source.kind,
                    source.target);
                source.semanticKey =
                    "handle.access|" + source.artifactKey;
                const auto inserted = deduplicated.emplace(
                    source.semanticKey,
                    std::move(source));
                if (!inserted.second)
                {
                    ++inserted.first->second.rowCount;
                    ++result.duplicateRowCount;
                }
            }

            for (const auto& item : deduplicated)
            {
                const DeduplicatedHandle& source = item.second;
                std::string mapping;
                std::string title;
                std::string summary;
                ObservationDisposition disposition =
                    ObservationDisposition::Context;
                ObservationStrength strength = ObservationStrength::None;
                bool contributes = false;
                std::string grouping;
                std::string correlation;
                std::vector<std::string> limitations;
                if (!source.handle.errorMessage.empty())
                {
                    bool bounded = false;
                    limitations.push_back(WideToUtf8Bounded(
                        source.handle.errorMessage,
                        ObservationLimitationItemMaxCharacters,
                        bounded));
                    result.truncated = result.truncated || bounded;
                }
                ChoosePolicy(
                    source,
                    mapping,
                    title,
                    summary,
                    disposition,
                    strength,
                    contributes,
                    grouping,
                    correlation,
                    limitations);
                std::vector<std::string> evidence = {
                    "The raw access mask was categorized using typed access-bit constants."
                };
                if (!source.handle.objectName.empty())
                {
                    bool bounded = false;
                    evidence.push_back(
                        "Captured object identity: " + WideToUtf8Bounded(
                            source.handle.objectName,
                            ObservationEvidenceItemMaxCharacters,
                            bounded));
                    result.truncated = result.truncated || bounded;
                }
                if (!AddRecord(
                        result,
                        input,
                        entityScope,
                        std::move(mapping),
                        source.semanticKey,
                        std::move(title),
                        std::move(summary),
                        EvidenceDomain::Handle,
                        disposition,
                        strength,
                        ObservationConfidence::High,
                        contributes,
                        std::move(grouping),
                        std::move(correlation),
                        { ObservationArtifactKind::Handle, entityScope, source.artifactKey },
                        Attributes(source, input.sourceIdentity),
                        std::move(evidence),
                        std::move(limitations),
                        input.source.sourceKind))
                {
                    result.records.clear();
                    return result;
                }
            }

            if (input.sourceTruncated)
            {
                result.truncated = true;
                result.omittedHandleCount = input.omittedHandleCount;
                result.materialEvidenceOmitted = input.omittedHandleCount != 0;
                std::vector<std::string> limitations = {
                    input.omittedHandleCount == 0
                        ? "The source reported bounded handle coverage but did not identify omitted handle rows."
                        : "One or more handle rows were omitted; omitted access metadata could affect enriched triage completeness."
                };
                if (!AddRecord(
                        result,
                        input,
                        entityScope,
                        NativeHandleMappingCollectionTruncated,
                        "collection.handle-enumeration-truncated|" + processArtifact,
                        "Handle collection coverage was truncated",
                        "The selected-process handle capture reported bounded or partial coverage.",
                        EvidenceDomain::CollectionQuality,
                        ObservationDisposition::CollectionNote,
                        ObservationStrength::None,
                        ObservationConfidence::High,
                        false,
                        "selected-collection-quality",
                        {},
                        { ObservationArtifactKind::Process, entityScope, processArtifact },
                        {{ "handle.omitted-row-count", std::to_string(input.omittedHandleCount) }},
                        {},
                        std::move(limitations),
                        ObservationSourceKind::Direct))
                {
                    result.records.clear();
                    return result;
                }
            }

            FinalizeInventory(result);
            result.status = NativeHandleObservationBuildStatus::Success;
            result.diagnostic =
                "Native handle observations built: " +
                std::to_string(result.representedArtifactCount) +
                " typed records represented, " +
                std::to_string(result.duplicateRowCount) +
                " duplicate rows consolidated.";
            bool ignored = false;
            result.diagnostic = BoundedCopy(
                std::move(result.diagnostic),
                NativeHandleObservationDiagnosticMaxCharacters,
                ignored);
            return result;
        }
        catch (...)
        {
            result.success = false;
            result.status =
                NativeHandleObservationBuildStatus::PolicyValidationFailed;
            result.records.clear();
            result.inventory = {};
            result.diagnostic =
                "Native handle observation construction failed internally.";
            return result;
        }
    }
}
