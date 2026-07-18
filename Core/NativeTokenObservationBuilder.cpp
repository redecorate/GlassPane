#include "NativeTokenObservationBuilder.h"

#include "ObservationPolicy.h"

#include <algorithm>
#include <iomanip>
#include <map>
#include <sstream>
#include <string_view>
#include <utility>

namespace GlassPane::Core
{
    namespace
    {
        constexpr char NativeTokenCategory[] =
            "Native selected-process evidence";
        constexpr char TokenGroupingKey[] = "token-security-context";
        constexpr char TruncationLimitation[] =
            "The native token fact was truncated to its bounded representation.";
        constexpr std::uint32_t HighIntegrityRid = 0x00003000;

        struct TokenObservationSpec
        {
            std::string mappingRuleId;
            std::string semanticFactKey;
            std::string title;
            std::string summary;
            ObservationDisposition disposition = ObservationDisposition::Context;
            ObservationStrength strength = ObservationStrength::None;
            ObservationConfidence confidence = ObservationConfidence::High;
            std::string correlationKey;
            std::string rawValue;
            std::string normalizedValue;
            std::vector<ObservationArtifactAttribute> attributes;
            std::vector<std::string> evidence;
            std::vector<std::string> limitations;
            NativeTokenSourceCompleteness completeness =
                NativeTokenSourceCompleteness::Complete;
            ObservationSourceKind sourceKind = ObservationSourceKind::Direct;
            std::size_t sourceOrdinal = 0;
        };

        bool ValidIdentity(const ProcessIdentityKey& identity)
        {
            return identity.hasCreationTime || identity.creationTimeFileTime == 0;
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

        std::string TokenArtifactKey(const ProcessIdentityKey& identity)
        {
            std::ostringstream stream;
            stream << "selected-token:pid:" << identity.pid << ":creation:";
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

        std::string FingerprintText(std::string_view value)
        {
            std::ostringstream stream;
            stream << std::hex << std::setw(16) << std::setfill('0')
                   << Fingerprint(value);
            return stream.str();
        }

        bool LimitString(std::string& value, std::size_t maximum)
        {
            if (value.size() <= maximum)
            {
                return false;
            }
            value.resize(maximum);
            return true;
        }

        std::string Bounded(
            std::string value,
            std::size_t maximum,
            bool& truncated)
        {
            truncated = LimitString(value, maximum) || truncated;
            return value;
        }

        void AppendUtf8(std::string& output, std::uint32_t codePoint)
        {
            if (codePoint <= 0x7f)
            {
                output.push_back(static_cast<char>(codePoint));
            }
            else if (codePoint <= 0x7ff)
            {
                output.push_back(static_cast<char>(0xc0 | (codePoint >> 6)));
                output.push_back(static_cast<char>(0x80 | (codePoint & 0x3f)));
            }
            else if (codePoint <= 0xffff)
            {
                output.push_back(static_cast<char>(0xe0 | (codePoint >> 12)));
                output.push_back(static_cast<char>(
                    0x80 | ((codePoint >> 6) & 0x3f)));
                output.push_back(static_cast<char>(0x80 | (codePoint & 0x3f)));
            }
            else
            {
                output.push_back(static_cast<char>(0xf0 | (codePoint >> 18)));
                output.push_back(static_cast<char>(
                    0x80 | ((codePoint >> 12) & 0x3f)));
                output.push_back(static_cast<char>(
                    0x80 | ((codePoint >> 6) & 0x3f)));
                output.push_back(static_cast<char>(0x80 | (codePoint & 0x3f)));
            }
        }

        std::string Utf8(const std::wstring& value)
        {
            std::string output;
            output.reserve(value.size());
            for (std::size_t index = 0; index < value.size(); ++index)
            {
                std::uint32_t codePoint =
                    static_cast<std::uint32_t>(value[index]);
#if WCHAR_MAX <= 0xffff
                if (codePoint >= 0xd800 && codePoint <= 0xdbff &&
                    index + 1 < value.size())
                {
                    const std::uint32_t low =
                        static_cast<std::uint32_t>(value[index + 1]);
                    if (low >= 0xdc00 && low <= 0xdfff)
                    {
                        codePoint = 0x10000 + ((codePoint - 0xd800) << 10) +
                            (low - 0xdc00);
                        ++index;
                    }
                }
#endif
                if ((codePoint >= 0xd800 && codePoint <= 0xdfff) ||
                    codePoint > 0x10ffff)
                {
                    codePoint = 0xfffd;
                }
                AppendUtf8(output, codePoint);
            }
            return output;
        }

        char LowerAscii(char value)
        {
            return value >= 'A' && value <= 'Z'
                ? static_cast<char>(value - 'A' + 'a')
                : value;
        }

        std::string NormalizeIdentity(std::string value)
        {
            std::transform(
                value.begin(),
                value.end(),
                value.begin(),
                [](char character) { return LowerAscii(character); });
            return value;
        }

        bool IsDebugPrivilege(std::string_view normalizedName)
        {
            return normalizedName == "sedebugprivilege";
        }

        void CopyItems(
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
                destination.push_back(Bounded(
                    item,
                    maximumCharacters,
                    truncated));
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

        bool AppendRecord(
            NativeTokenObservationBuildResult& result,
            const NativeTokenObservationInput& input,
            const std::string& entityScope,
            const std::string& tokenArtifactKey,
            TokenObservationSpec spec)
        {
            if (result.records.size() >= ObservationInventoryMaxObservations)
            {
                result.success = false;
                result.status =
                    NativeTokenObservationBuildStatus::InputLimitExceeded;
                result.diagnostic =
                    "Native token observation output exceeded its cap.";
                result.records.clear();
                return false;
            }
            if (spec.semanticFactKey.empty() ||
                spec.semanticFactKey.size() >
                    NativeTokenObservationSemanticKeyMaxCharacters)
            {
                result.success = false;
                result.status =
                    NativeTokenObservationBuildStatus::InvalidTypedFact;
                result.diagnostic =
                    "A native token fact has no valid bounded semantic identity.";
                result.records.clear();
                return false;
            }

            bool truncated = false;
            const std::string identityMaterial = entityScope + "|" +
                spec.semanticFactKey + "|" +
                std::to_string(spec.sourceOrdinal) + "|" +
                input.source.rawSourceReference;
            const std::string fingerprint = FingerprintText(identityMaterial);

            NativeTokenObservationRecord output;
            output.completeness = spec.completeness;
            if (spec.disposition != ObservationDisposition::CollectionNote &&
                input.source.completeness !=
                    NativeTokenSourceCompleteness::Complete)
            {
                output.completeness = input.source.completeness;
            }
            output.semanticFactKey = spec.semanticFactKey;
            output.sourceRecordId = "native-token-source:" + fingerprint;

            ObservationRecord& record = output.record;
            record.source.sourceRecordId = output.sourceRecordId;
            record.source.sourceRuleId = Bounded(
                spec.mappingRuleId,
                ObservationRuleIdMaxCharacters,
                truncated);
            record.source.mappingRuleId = record.source.sourceRuleId;
            record.source.sourceTitle = Bounded(
                spec.title,
                ObservationTitleMaxCharacters,
                truncated);
            record.source.sourceMessage = Bounded(
                spec.summary,
                ObservationSourceMessageMaxCharacters,
                truncated);
            record.source.sourceCategory = NativeTokenCategory;
            record.source.producerIdentifier = Bounded(
                input.source.sourceIdentifier.empty()
                    ? std::string("core.native-token")
                    : input.source.sourceIdentifier,
                ObservationProvenanceSourceIdentifierMaxCharacters,
                truncated);
            record.source.rawValueExplicitlySupplied = !spec.rawValue.empty();
            record.source.normalizedValueExplicitlySupplied =
                !spec.normalizedValue.empty();
            record.source.sourceOrdinal = spec.sourceOrdinal;

            Observation& observation = record.observation;
            observation.id = "native-token-observation:" + fingerprint;
            observation.ruleId = record.source.sourceRuleId;
            observation.title = record.source.sourceTitle;
            observation.summary = record.source.sourceMessage;
            observation.domain = spec.disposition ==
                    ObservationDisposition::CollectionNote
                ? EvidenceDomain::CollectionQuality
                : EvidenceDomain::Token;
            observation.sourceKind =
                spec.disposition == ObservationDisposition::CollectionNote
                ? spec.sourceKind
                : input.source.sourceKind;
            observation.disposition = spec.disposition;
            observation.strength = spec.strength;
            observation.confidence = spec.confidence;
            observation.contributesToVerdict = false;
            observation.entityScope = entityScope;
            observation.groupingKey = TokenGroupingKey;
            observation.correlationKey = Bounded(
                spec.correlationKey,
                ObservationCorrelationKeyMaxCharacters,
                truncated);
            observation.rawValue = Bounded(
                spec.rawValue,
                ObservationRawValueMaxCharacters,
                truncated);
            observation.normalizedValue = Bounded(
                spec.normalizedValue,
                ObservationNormalizedValueMaxCharacters,
                truncated);
            observation.artifactIdentity = {
                ObservationArtifactKind::Token,
                entityScope,
                Bounded(
                    tokenArtifactKey,
                    ObservationArtifactKeyMaxCharacters,
                    truncated)
            };
            observation.artifactAttributes = std::move(spec.attributes);
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
            CopyItems(
                spec.evidence,
                observation.evidence,
                ObservationMaxEvidenceItems,
                ObservationEvidenceItemMaxCharacters,
                truncated);
            CopyItems(
                spec.limitations,
                observation.limitations,
                ObservationMaxLimitationItems,
                ObservationLimitationItemMaxCharacters,
                truncated);
            CopyItems(
                input.source.limitations,
                observation.limitations,
                ObservationMaxLimitationItems,
                ObservationLimitationItemMaxCharacters,
                truncated);
            CopyItems(
                input.limitations,
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
            observation.provenance.collectionMethod = Bounded(
                input.source.collectionMethod,
                ObservationProvenanceCollectionMethodMaxCharacters,
                truncated);
            observation.provenance.collectionTimestamp = Bounded(
                input.source.collectionTimestamp,
                ObservationProvenanceCollectionTimestampMaxCharacters,
                truncated);
            observation.provenance.requiredPrivilege = Bounded(
                input.source.requiredPrivilege,
                ObservationProvenanceRequiredPrivilegeMaxCharacters,
                truncated);
            observation.provenance.sourceAvailable =
                observation.sourceKind != ObservationSourceKind::Unavailable;
            observation.provenance.rawSourceReference = Bounded(
                input.source.rawSourceReference.empty()
                    ? output.sourceRecordId
                    : input.source.rawSourceReference,
                ObservationProvenanceRawSourceReferenceMaxCharacters,
                truncated);
            observation.provenance.limitations = observation.limitations;

            observation = NormalizeObservationPolicy(std::move(observation));
            if (!ValidateObservation(observation).IsValid())
            {
                result.success = false;
                result.status =
                    NativeTokenObservationBuildStatus::PolicyValidationFailed;
                result.diagnostic =
                    "A native token observation failed policy validation.";
                result.records.clear();
                return false;
            }
            if (truncated && output.completeness ==
                NativeTokenSourceCompleteness::Complete)
            {
                output.completeness = NativeTokenSourceCompleteness::Partial;
            }
            result.truncated = result.truncated || truncated;
            result.records.push_back(std::move(output));
            return true;
        }

        TokenObservationSpec CollectionNote(
            std::string mapping,
            std::string key,
            std::string title,
            std::string summary,
            std::string limitation,
            std::size_t ordinal)
        {
            TokenObservationSpec spec;
            spec.mappingRuleId = std::move(mapping);
            spec.semanticFactKey = std::move(key);
            spec.title = std::move(title);
            spec.summary = std::move(summary);
            spec.disposition = ObservationDisposition::CollectionNote;
            spec.confidence = ObservationConfidence::High;
            spec.completeness = NativeTokenSourceCompleteness::Unavailable;
            spec.sourceKind = ObservationSourceKind::Unavailable;
            spec.limitations.push_back(std::move(limitation));
            spec.sourceOrdinal = ordinal;
            return spec;
        }

        void FinalizeResult(NativeTokenObservationBuildResult& result)
        {
            std::map<std::string, std::size_t> primaryByIdentity;
            for (std::size_t index = 0; index < result.records.size(); ++index)
            {
                NativeTokenObservationRecord& source = result.records[index];
                const std::string key =
                    source.record.observation.entityScope + "|" +
                    source.semanticFactKey;
                const auto inserted = primaryByIdentity.emplace(key, index);
                if (!inserted.second)
                {
                    source.primary = false;
                    source.primaryObservationId = result.records[
                        inserted.first->second].record.observation.id;
                    ++result.duplicateCount;
                    continue;
                }
                source.primaryObservationId = source.record.observation.id;
                result.inventory.records.push_back(source.record);
                CountDisposition(
                    result.inventory,
                    source.record.observation.disposition);
            }
            for (const NativeTokenObservationRecord& source : result.records)
            {
                switch (source.completeness)
                {
                case NativeTokenSourceCompleteness::Complete:
                    ++result.completeFactCount;
                    break;
                case NativeTokenSourceCompleteness::Partial:
                    ++result.partialFactCount;
                    break;
                case NativeTokenSourceCompleteness::Unavailable:
                    ++result.unavailableFactCount;
                    break;
                }
            }
            result.inventory.typedSourceFactCount =
                result.inventory.records.size();
            result.nativeFactCount = result.records.size();
            result.representedFactCount = result.inventory.records.size();
            result.success = true;
            result.status = NativeTokenObservationBuildStatus::Success;
            result.diagnostic =
                "Native token observations built: " +
                std::to_string(result.representedFactCount) +
                " typed facts represented.";
            LimitString(
                result.diagnostic,
                NativeTokenObservationDiagnosticMaxCharacters);
        }
    }

    bool NativeTokenObservationBuildResult::Succeeded() const
    {
        return attempted && success &&
            status == NativeTokenObservationBuildStatus::Success &&
            inventory.status == ObservationInventoryStatus::Success;
    }

    NativeTokenObservationBuildResult BuildNativeTokenObservations(
        const NativeTokenObservationInput& input) noexcept
    {
        NativeTokenObservationBuildResult result;
        result.attempted = true;
        try
        {
            if (!ValidIdentity(input.identity))
            {
                result.status =
                    NativeTokenObservationBuildStatus::InvalidIdentity;
                result.diagnostic =
                    "The native token source identity is contradictory.";
                return result;
            }
            const std::string entityScope = input.entityScope.empty()
                ? EntityScope(input.identity)
                : input.entityScope;
            if (entityScope.empty() ||
                entityScope.size() > ObservationEntityScopeMaxCharacters)
            {
                result.status =
                    NativeTokenObservationBuildStatus::InvalidIdentity;
                result.diagnostic =
                    "The native token entity scope is missing or exceeds its cap.";
                return result;
            }
            if (input.token.privileges.size() >
                    NativeTokenObservationMaxPrivileges ||
                input.limitations.size() >
                    NativeTokenObservationMaxLimitations)
            {
                result.status =
                    NativeTokenObservationBuildStatus::InputLimitExceeded;
                result.diagnostic =
                    "Native token input exceeded a bounded cap.";
                return result;
            }
            if (input.omittedPrivilegeCount != 0 &&
                !input.privilegesTruncated)
            {
                result.status =
                    NativeTokenObservationBuildStatus::InvalidTypedFact;
                result.diagnostic =
                    "Omitted token privilege facts require an explicit truncation marker.";
                return result;
            }

            result.success = true;
            if (!input.supplied)
            {
                FinalizeResult(result);
                return result;
            }

            const std::string artifactKey = TokenArtifactKey(input.identity);
            std::size_t ordinal = 0;
            if (!input.token.success)
            {
                if (input.collectionAttempted)
                {
                    std::string error = Utf8(input.token.errorMessage);
                    if (error.empty())
                    {
                        error = "Token collection did not return typed evidence.";
                    }
                    TokenObservationSpec note = CollectionNote(
                        NativeTokenMappingCollectionFailure,
                        "token.collection.unavailable",
                        "Token evidence unavailable",
                        "Token collection was attempted but did not produce usable typed evidence.",
                        error,
                        ordinal++);
                    if (!AppendRecord(
                            result,
                            input,
                            entityScope,
                            artifactKey,
                            std::move(note)))
                    {
                        return result;
                    }
                }
                FinalizeResult(result);
                return result;
            }

            const std::string sid = Utf8(input.token.userSid);
            if (!sid.empty())
            {
                TokenObservationSpec spec;
                spec.mappingRuleId = NativeTokenMappingIdentity;
                spec.semanticFactKey = "token.identity.sid";
                spec.title = "Token user identity observed";
                spec.summary =
                    "A typed user SID was recorded for the selected-process token.";
                spec.rawValue = sid;
                spec.normalizedValue = NormalizeIdentity(sid);
                spec.attributes = {
                    { "token.user.sid", spec.normalizedValue },
                    { "token.user.local-system",
                        spec.normalizedValue == "s-1-5-18" ? "true" : "false" }
                };
                spec.sourceOrdinal = ordinal++;
                if (!AppendRecord(
                        result,
                        input,
                        entityScope,
                        artifactKey,
                        std::move(spec)))
                {
                    return result;
                }
            }

            if (input.token.sessionId.has_value())
            {
                TokenObservationSpec spec;
                spec.mappingRuleId = NativeTokenMappingSession;
                spec.semanticFactKey = "token.session";
                spec.title = "Token session context observed";
                spec.summary =
                    "The selected-process token session identifier was recorded as context.";
                spec.rawValue = std::to_string(*input.token.sessionId);
                spec.normalizedValue = spec.rawValue;
                spec.attributes = { { "token.session-id", spec.rawValue } };
                spec.sourceOrdinal = ordinal++;
                if (!AppendRecord(
                        result,
                        input,
                        entityScope,
                        artifactKey,
                        std::move(spec)))
                {
                    return result;
                }
            }

            if (input.token.integrityRid != 0 ||
                !input.token.integrityLevelName.empty())
            {
                TokenObservationSpec spec;
                spec.mappingRuleId = NativeTokenMappingIntegrity;
                spec.semanticFactKey = "token.integrity";
                spec.title = "Token integrity context observed";
                spec.summary =
                    "Token integrity is contextual metadata and does not contribute by itself.";
                spec.rawValue = Utf8(input.token.integrityLevelName);
                spec.normalizedValue =
                    std::to_string(input.token.integrityRid);
                spec.attributes = {
                    { "token.integrity-rid", spec.normalizedValue },
                    { "token.integrity-level", spec.rawValue },
                    { "token.integrity-high-or-greater",
                        input.token.integrityRid >= HighIntegrityRid
                            ? "true" : "false" }
                };
                spec.sourceOrdinal = ordinal++;
                if (!AppendRecord(
                        result,
                        input,
                        entityScope,
                        artifactKey,
                        std::move(spec)))
                {
                    return result;
                }
            }

            if (!input.token.elevationType.empty() ||
                input.token.isElevated || input.token.isAdmin)
            {
                TokenObservationSpec spec;
                spec.mappingRuleId = NativeTokenMappingElevation;
                spec.semanticFactKey = "token.elevation";
                spec.title = "Token elevation context observed";
                spec.summary =
                    "Token elevation state is contextual metadata and does not contribute by itself.";
                spec.rawValue = Utf8(input.token.elevationType);
                spec.normalizedValue = input.token.isElevated
                    ? "elevated"
                    : NormalizeIdentity(spec.rawValue);
                spec.attributes = {
                    { "token.elevation-type", spec.rawValue }
                };
                if (input.token.isElevated)
                {
                    spec.attributes.push_back({ "token.elevated", "true" });
                }
                if (input.token.isAdmin)
                {
                    spec.attributes.push_back({ "token.admin-member", "true" });
                }
                spec.sourceOrdinal = ordinal++;
                if (!AppendRecord(
                        result,
                        input,
                        entityScope,
                        artifactKey,
                        std::move(spec)))
                {
                    return result;
                }
            }

            if (!input.token.tokenType.empty())
            {
                TokenObservationSpec spec;
                spec.mappingRuleId = NativeTokenMappingType;
                spec.semanticFactKey = "token.type";
                spec.title = "Token type context observed";
                spec.summary =
                    "Token type and impersonation-level metadata were recorded as context.";
                spec.rawValue = Utf8(input.token.tokenType);
                spec.normalizedValue = NormalizeIdentity(spec.rawValue);
                spec.attributes = {
                    { "token.type", spec.rawValue },
                    { "token.impersonation-level",
                        Utf8(input.token.impersonationLevel) }
                };
                spec.sourceOrdinal = ordinal++;
                if (!AppendRecord(
                        result,
                        input,
                        entityScope,
                        artifactKey,
                        std::move(spec)))
                {
                    return result;
                }
            }

            if (input.token.isAppContainer)
            {
                TokenObservationSpec spec;
                spec.mappingRuleId = NativeTokenMappingAppContainer;
                spec.semanticFactKey = "token.app-container";
                spec.title = "AppContainer token context observed";
                spec.summary =
                    "AppContainer state is contextual metadata and does not contribute by itself.";
                spec.rawValue = "true";
                spec.normalizedValue = spec.rawValue;
                spec.attributes = {
                    { "token.app-container", spec.rawValue }
                };
                spec.sourceOrdinal = ordinal++;
                if (!AppendRecord(
                        result,
                        input,
                        entityScope,
                        artifactKey,
                        std::move(spec)))
                {
                    return result;
                }
            }

            struct OrderedPrivilege
            {
                const PrivilegeInfo* value = nullptr;
                std::string normalizedName;
                std::size_t inputOrdinal = 0;
            };
            std::vector<OrderedPrivilege> privileges;
            privileges.reserve(input.token.privileges.size());
            for (std::size_t index = 0;
                 index < input.token.privileges.size();
                 ++index)
            {
                privileges.push_back({
                    &input.token.privileges[index],
                    NormalizeIdentity(Utf8(input.token.privileges[index].name)),
                    index
                });
            }
            std::stable_sort(
                privileges.begin(),
                privileges.end(),
                [](const OrderedPrivilege& left,
                   const OrderedPrivilege& right)
                {
                    if (left.normalizedName != right.normalizedName)
                    {
                        return left.normalizedName < right.normalizedName;
                    }
                    if (left.value->enabled != right.value->enabled)
                    {
                        return left.value->enabled;
                    }
                    return left.inputOrdinal < right.inputOrdinal;
                });

            for (const OrderedPrivilege& ordered : privileges)
            {
                if (ordered.normalizedName.empty())
                {
                    result.success = false;
                    result.status =
                        NativeTokenObservationBuildStatus::InvalidTypedFact;
                    result.diagnostic =
                        "A supplied token privilege has no typed identity.";
                    result.records.clear();
                    return result;
                }
                const PrivilegeInfo& privilege = *ordered.value;
                const bool debugEnabled =
                    IsDebugPrivilege(ordered.normalizedName) &&
                    privilege.enabled && !privilege.removed;
                TokenObservationSpec spec;
                spec.mappingRuleId = debugEnabled
                    ? NativeTokenMappingDebugPrivilegeEnabled
                    : NativeTokenMappingPrivilege;
                spec.semanticFactKey =
                    "token.privilege|" + ordered.normalizedName;
                spec.title = debugEnabled
                    ? "Debug privilege enabled in selected token"
                    : "Token privilege state observed";
                spec.summary = debugEnabled
                    ? "The selected-process token has the debug privilege enabled. It remains inactive unless a typed access correlation completes."
                    : "A typed token privilege state was recorded as context.";
                spec.disposition = debugEnabled
                    ? ObservationDisposition::CorrelatedOnly
                    : ObservationDisposition::Context;
                spec.strength = debugEnabled
                    ? ObservationStrength::Weak
                    : ObservationStrength::None;
                spec.correlationKey = debugEnabled
                    ? NativeTokenSensitiveAccessCorrelationKey
                    : std::string{};
                spec.rawValue = Utf8(privilege.name);
                spec.normalizedValue = ordered.normalizedName;
                spec.attributes = {
                    { "token.privilege-child", ordered.normalizedName },
                    { "token.privilege.enabled", privilege.enabled ? "true" : "false" },
                    { "token.privilege.enabled-by-default",
                        privilege.enabledByDefault ? "true" : "false" },
                    { "token.privilege.removed", privilege.removed ? "true" : "false" },
                    { "token.privilege.used-for-access",
                        privilege.usedForAccess ? "true" : "false" }
                };
                spec.sourceOrdinal = ordinal++;
                if (!AppendRecord(
                        result,
                        input,
                        entityScope,
                        artifactKey,
                        std::move(spec)))
                {
                    return result;
                }
            }

            if (!input.token.errorMessage.empty())
            {
                TokenObservationSpec note = CollectionNote(
                    NativeTokenMappingCollectionPartial,
                    "token.collection.partial",
                    "Token evidence partially unavailable",
                    "Token collection returned typed evidence with one or more field-level limitations.",
                    Utf8(input.token.errorMessage),
                    ordinal++);
                note.completeness = NativeTokenSourceCompleteness::Partial;
                if (!AppendRecord(
                        result,
                        input,
                        entityScope,
                        artifactKey,
                        std::move(note)))
                {
                    return result;
                }
            }

            if (input.privilegesTruncated)
            {
                TokenObservationSpec note = CollectionNote(
                    NativeTokenMappingPrivilegeTruncation,
                    "token.collection.privileges-truncated",
                    "Token privilege coverage truncated",
                    "The captured token privilege list was truncated; represented privileges remain auditable.",
                    input.omittedPrivilegeCount == 0
                        ? "Privilege coverage was reported truncated without a known omitted-fact count."
                        : std::to_string(input.omittedPrivilegeCount) +
                            " privilege facts were omitted by the capture bound.",
                    ordinal++);
                note.completeness = NativeTokenSourceCompleteness::Partial;
                if (!AppendRecord(
                        result,
                        input,
                        entityScope,
                        artifactKey,
                        std::move(note)))
                {
                    return result;
                }
                result.truncated = true;
                result.omittedFactCount = input.omittedPrivilegeCount;
            }

            FinalizeResult(result);
            return result;
        }
        catch (...)
        {
            result.success = false;
            result.status =
                NativeTokenObservationBuildStatus::PolicyValidationFailed;
            result.diagnostic =
                "Native token observation construction failed atomically.";
            result.records.clear();
            result.inventory = {};
            return result;
        }
    }
}
