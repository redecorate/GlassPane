#include "NativeRuntimeObservationBuilder.h"

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
        constexpr char NativeCategory[] = "Native selected-process evidence";
        constexpr char StaticRuntimeLimitation[] =
            "Static thread metadata does not establish cross-process creation, payload execution, or injection.";

        struct ObservationSpec
        {
            std::string mappingRuleId;
            std::string sourceRuleId;
            std::string semanticFactKey;
            std::string title;
            std::string summary;
            EvidenceDomain domain = EvidenceDomain::Unknown;
            ObservationDisposition disposition =
                ObservationDisposition::Informational;
            ObservationStrength strength = ObservationStrength::None;
            ObservationConfidence confidence = ObservationConfidence::Unknown;
            bool contributesToVerdict = false;
            bool material = false;
            std::string groupingKey;
            std::string correlationKey;
            std::string rawValue;
            std::string normalizedValue;
            ObservationArtifactIdentity artifactIdentity;
            std::vector<ObservationArtifactAttribute> attributes;
            std::vector<std::string> evidence;
            std::vector<std::string> limitations;
            NativeRuntimeObservationSource source;
            std::size_t sourceOrdinal = 0;
        };

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

        std::string IdentityText(const ProcessIdentityKey& identity)
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

        std::string EntityScope(const ProcessIdentityKey& identity)
        {
            return "process:" + IdentityText(identity);
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

        bool LimitString(std::string& value, std::size_t maximumCharacters)
        {
            if (value.size() <= maximumCharacters)
            {
                return false;
            }
            value.resize(maximumCharacters);
            return true;
        }

        std::string BoundedCopy(
            const std::string& value,
            std::size_t maximumCharacters,
            bool& truncated)
        {
            std::string output = value;
            truncated = LimitString(output, maximumCharacters) || truncated;
            return output;
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
                destination.push_back(BoundedCopy(
                    item,
                    maximumCharacters,
                    truncated));
            }
        }

        std::string HexValue(std::uint64_t value)
        {
            std::ostringstream stream;
            stream << "0x" << std::hex << value;
            return stream.str();
        }

        ObservationConfidence ConfidenceFor(
            NativeRuntimeSourceCompleteness completeness)
        {
            switch (completeness)
            {
            case NativeRuntimeSourceCompleteness::Complete:
                return ObservationConfidence::High;
            case NativeRuntimeSourceCompleteness::Partial:
                return ObservationConfidence::Medium;
            case NativeRuntimeSourceCompleteness::Unavailable:
                return ObservationConfidence::Low;
            default:
                return ObservationConfidence::Unknown;
            }
        }

        bool AddRecord(
            NativeRuntimeObservationBuildResult& result,
            const std::string& entityScope,
            ObservationSpec spec)
        {
            if (result.records.size() >= NativeRuntimeObservationMaxRecords)
            {
                result.success = false;
                result.status =
                    NativeRuntimeObservationBuildStatus::InputLimitExceeded;
                result.diagnostic =
                    "Native runtime observation output exceeded its bounded cap.";
                result.records.clear();
                return false;
            }
            if (spec.semanticFactKey.empty() ||
                spec.semanticFactKey.size() >
                    NativeRuntimeObservationSemanticKeyMaxCharacters)
            {
                result.success = false;
                result.status =
                    NativeRuntimeObservationBuildStatus::InvalidTypedFact;
                result.diagnostic =
                    "A runtime fact has no valid bounded semantic identity.";
                result.records.clear();
                return false;
            }

            bool truncated = false;
            const std::string identityMaterial =
                entityScope + "|" + spec.semanticFactKey + "|" +
                std::to_string(spec.sourceOrdinal) + "|" +
                spec.source.rawSourceReference;
            const std::string fingerprint = FingerprintText(identityMaterial);

            NativeRuntimeObservationRecord output;
            output.semanticFactKey = spec.semanticFactKey;
            output.completeness = spec.source.completeness;
            output.material = spec.material;

            ObservationRecord& record = output.record;
            record.source.sourceRecordId = "native-runtime-source:" + fingerprint;
            record.source.sourceRuleId = BoundedCopy(
                spec.sourceRuleId.empty()
                    ? spec.mappingRuleId
                    : spec.sourceRuleId,
                ObservationRuleIdMaxCharacters,
                truncated);
            record.source.mappingRuleId = BoundedCopy(
                spec.mappingRuleId,
                ObservationRuleIdMaxCharacters,
                truncated);
            record.source.sourceTitle = BoundedCopy(
                spec.title,
                ObservationTitleMaxCharacters,
                truncated);
            record.source.sourceMessage = BoundedCopy(
                spec.summary,
                ObservationSourceMessageMaxCharacters,
                truncated);
            record.source.sourceCategory = NativeCategory;
            record.source.producerIdentifier = BoundedCopy(
                spec.source.sourceIdentifier.empty()
                    ? std::string("core.native-runtime")
                    : spec.source.sourceIdentifier,
                ObservationProvenanceSourceIdentifierMaxCharacters,
                truncated);
            record.source.rawValueExplicitlySupplied = !spec.rawValue.empty();
            record.source.normalizedValueExplicitlySupplied =
                !spec.normalizedValue.empty();

            Observation& observation = record.observation;
            observation.id = "native-runtime-observation:" + fingerprint;
            observation.ruleId = record.source.sourceRuleId;
            observation.title = record.source.sourceTitle;
            observation.summary = record.source.sourceMessage;
            observation.domain = spec.domain;
            observation.sourceKind =
                spec.source.completeness ==
                    NativeRuntimeSourceCompleteness::Unavailable
                    ? ObservationSourceKind::Unavailable
                    : spec.source.sourceKind;
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
            CopyBoundedItems(
                spec.source.limitations,
                observation.limitations,
                ObservationMaxLimitationItems,
                ObservationLimitationItemMaxCharacters,
                truncated);

            observation.provenance.sourceKind = observation.sourceKind;
            observation.provenance.sourceIdentifier =
                record.source.producerIdentifier;
            observation.provenance.collectionMethod = BoundedCopy(
                spec.source.collectionMethod,
                ObservationProvenanceCollectionMethodMaxCharacters,
                truncated);
            observation.provenance.collectionTimestamp = BoundedCopy(
                spec.source.collectionTimestamp,
                ObservationProvenanceCollectionTimestampMaxCharacters,
                truncated);
            observation.provenance.requiredPrivilege = BoundedCopy(
                spec.source.requiredPrivilege,
                ObservationProvenanceRequiredPrivilegeMaxCharacters,
                truncated);
            observation.provenance.sourceAvailable =
                observation.sourceKind != ObservationSourceKind::Unavailable;
            observation.provenance.rawSourceReference = BoundedCopy(
                spec.source.rawSourceReference.empty()
                    ? record.source.sourceRecordId
                    : spec.source.rawSourceReference,
                ObservationProvenanceRawSourceReferenceMaxCharacters,
                truncated);
            observation.provenance.limitations = observation.limitations;

            observation = NormalizeObservationPolicy(std::move(observation));
            if (!ValidateObservation(observation).IsValid())
            {
                result.success = false;
                result.status =
                    NativeRuntimeObservationBuildStatus::PolicyValidationFailed;
                result.diagnostic =
                    "A native runtime observation failed bounded policy validation.";
                result.records.clear();
                return false;
            }

            if (truncated && output.completeness ==
                NativeRuntimeSourceCompleteness::Complete)
            {
                output.completeness =
                    NativeRuntimeSourceCompleteness::Partial;
            }
            result.truncated = result.truncated || truncated;
            result.records.push_back(std::move(output));
            return true;
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
            default:
                break;
            }
        }

        bool FinishResult(NativeRuntimeObservationBuildResult& result)
        {
            std::map<std::string, std::size_t> primaryBySemanticIdentity;
            for (std::size_t index = 0; index < result.records.size(); ++index)
            {
                NativeRuntimeObservationRecord& current = result.records[index];
                const std::string key =
                    current.record.observation.entityScope + "\x1f" +
                    current.semanticFactKey;
                const auto inserted = primaryBySemanticIdentity.emplace(
                    key,
                    index);
                if (!inserted.second)
                {
                    current.primary = false;
                    current.primaryObservationId =
                        result.records[inserted.first->second]
                            .record.observation.id;
                    ++result.duplicateCount;
                    continue;
                }

                result.inventory.records.push_back(current.record);
                CountDisposition(
                    result.inventory,
                    current.record.observation.disposition);
                if (current.material)
                {
                    ++result.materialFactCount;
                }
            }

            result.inventory.status = ObservationInventoryStatus::Success;
            result.inventory.typedSourceFactCount =
                result.inventory.records.size();
            result.inventory.declaredSourceFactCount = result.records.size();
            result.nativeFactCount = result.records.size();
            result.representedFactCount = result.inventory.records.size();
            result.status = NativeRuntimeObservationBuildStatus::Success;
            result.success = true;
            result.diagnostic =
                "Native runtime/priority observations built: " +
                std::to_string(result.representedFactCount) +
                " typed facts represented.";
            LimitString(
                result.diagnostic,
                NativeRuntimeObservationDiagnosticMaxCharacters);
            return true;
        }

        bool ValidateCommonInput(
            const ProcessIdentityKey& identity,
            const std::string& requestedScope,
            std::string& entityScope,
            NativeRuntimeObservationBuildResult& result)
        {
            if (!ValidIdentity(identity))
            {
                result.status =
                    NativeRuntimeObservationBuildStatus::InvalidIdentity;
                result.diagnostic =
                    "The selected process identity is contradictory.";
                return false;
            }
            entityScope = requestedScope.empty()
                ? EntityScope(identity)
                : requestedScope;
            if (entityScope.empty() ||
                entityScope.size() > ObservationEntityScopeMaxCharacters)
            {
                result.status =
                    NativeRuntimeObservationBuildStatus::InvalidIdentity;
                result.diagnostic =
                    "The selected process entity scope is missing or exceeds its cap.";
                return false;
            }
            return true;
        }

        ObservationSpec CollectionNoteSpec(
            const char* mapping,
            std::string semanticFactKey,
            std::string title,
            std::string summary,
            std::string artifactKey,
            const NativeRuntimeObservationSource& source,
            bool material,
            std::size_t ordinal)
        {
            ObservationSpec note;
            note.mappingRuleId = mapping;
            note.semanticFactKey = std::move(semanticFactKey);
            note.title = std::move(title);
            note.summary = std::move(summary);
            note.domain = EvidenceDomain::CollectionQuality;
            note.disposition = ObservationDisposition::CollectionNote;
            note.strength = ObservationStrength::None;
            note.confidence = ObservationConfidence::Medium;
            note.material = material;
            note.groupingKey = "runtime-collection-quality";
            note.artifactIdentity = {
                ObservationArtifactKind::RuntimeObject,
                {},
                std::move(artifactKey)
            };
            note.source = source;
            note.source.completeness =
                NativeRuntimeSourceCompleteness::Unavailable;
            note.sourceOrdinal = ordinal;
            return note;
        }
    }

    std::string NativeRuntimeThreadStartKindDisplayText(
        NativeRuntimeThreadStartKind kind)
    {
        switch (kind)
        {
        case NativeRuntimeThreadStartKind::NotEvaluated:
            return "Not evaluated";
        case NativeRuntimeThreadStartKind::ImageBacked:
            return "Image backed";
        case NativeRuntimeThreadStartKind::Unresolved:
            return "Unresolved";
        case NativeRuntimeThreadStartKind::PrivateExecutableMetadata:
            return "Private executable metadata";
        case NativeRuntimeThreadStartKind::OutsideKnownModule:
            return "Outside known module";
        default:
            return "Unknown";
        }
    }

    std::string NativeRuntimeThreadStateDisplayText(
        NativeRuntimeThreadState state)
    {
        switch (state)
        {
        case NativeRuntimeThreadState::Unknown:
            return "Unknown";
        case NativeRuntimeThreadState::Ready:
            return "Ready";
        case NativeRuntimeThreadState::Running:
            return "Running";
        case NativeRuntimeThreadState::Waiting:
            return "Waiting";
        case NativeRuntimeThreadState::Transition:
            return "Transition";
        case NativeRuntimeThreadState::Terminated:
            return "Terminated";
        case NativeRuntimeThreadState::Suspended:
            return "Suspended";
        default:
            return "Unknown";
        }
    }

    std::string NativeRuntimeRelationshipKindDisplayText(
        NativeRuntimeRelationshipKind kind)
    {
        switch (kind)
        {
        case NativeRuntimeRelationshipKind::CrossProcessThreadCreation:
            return "Cross-process thread creation";
        case NativeRuntimeRelationshipKind::ExternalThreadStartAttribution:
            return "External thread-start attribution";
        default:
            return "Unknown";
        }
    }

    std::string NativeProcessPriorityClassDisplayText(
        NativeProcessPriorityClass priorityClass)
    {
        switch (priorityClass)
        {
        case NativeProcessPriorityClass::NotEvaluated:
            return "Not evaluated";
        case NativeProcessPriorityClass::Idle:
            return "Idle";
        case NativeProcessPriorityClass::BelowNormal:
            return "Below normal";
        case NativeProcessPriorityClass::Normal:
            return "Normal";
        case NativeProcessPriorityClass::AboveNormal:
            return "Above normal";
        case NativeProcessPriorityClass::High:
            return "High";
        case NativeProcessPriorityClass::Realtime:
            return "Realtime";
        case NativeProcessPriorityClass::Unknown:
            return "Unknown";
        default:
            return "Unknown";
        }
    }

    NativeProcessPriorityClass ClassifyNativeProcessPriorityClass(
        std::uint32_t rawPriorityClass)
    {
        // Stable Win32 priority-class values. Unknown nonzero values remain
        // typed context and never acquire policy significance.
        switch (rawPriorityClass)
        {
        case 0:
            return NativeProcessPriorityClass::NotEvaluated;
        case 0x00000040:
            return NativeProcessPriorityClass::Idle;
        case 0x00004000:
            return NativeProcessPriorityClass::BelowNormal;
        case 0x00000020:
            return NativeProcessPriorityClass::Normal;
        case 0x00008000:
            return NativeProcessPriorityClass::AboveNormal;
        case 0x00000080:
            return NativeProcessPriorityClass::High;
        case 0x00000100:
            return NativeProcessPriorityClass::Realtime;
        default:
            return NativeProcessPriorityClass::Unknown;
        }
    }

    std::string NativeRuntimeObservationBuildStatusDisplayText(
        NativeRuntimeObservationBuildStatus status)
    {
        switch (status)
        {
        case NativeRuntimeObservationBuildStatus::NotAttempted:
            return "Not attempted";
        case NativeRuntimeObservationBuildStatus::Success:
            return "Success";
        case NativeRuntimeObservationBuildStatus::InvalidIdentity:
            return "Invalid identity";
        case NativeRuntimeObservationBuildStatus::InputLimitExceeded:
            return "Input limit exceeded";
        case NativeRuntimeObservationBuildStatus::InvalidTypedFact:
            return "Invalid typed fact";
        case NativeRuntimeObservationBuildStatus::PolicyValidationFailed:
            return "Policy validation failed";
        default:
            return "Unknown";
        }
    }

    bool NativeRuntimeObservationBuildResult::Succeeded() const
    {
        return attempted && success &&
            status == NativeRuntimeObservationBuildStatus::Success &&
            inventory.status == ObservationInventoryStatus::Success;
    }

    NativeRuntimeObservationBuildResult BuildNativeRuntimeObservations(
        const NativeRuntimeObservationInput& input) noexcept
    {
        NativeRuntimeObservationBuildResult result;
        result.attempted = true;
        try
        {
            std::string entityScope;
            if (!ValidateCommonInput(
                    input.identity,
                    input.entityScope,
                    entityScope,
                    result))
            {
                return result;
            }
            if (input.threads.size() > NativeRuntimeObservationMaxThreads ||
                input.relationships.size() >
                    NativeRuntimeObservationMaxRelationships ||
                input.limitations.size() >
                    NativeRuntimeObservationMaxLimitations)
            {
                result.status =
                    NativeRuntimeObservationBuildStatus::InputLimitExceeded;
                result.diagnostic =
                    "Native runtime typed input exceeded a bounded cap.";
                return result;
            }
            if (input.omittedMaterialFactCount != 0 &&
                !input.sourceFactsTruncated)
            {
                result.status =
                    NativeRuntimeObservationBuildStatus::InvalidTypedFact;
                result.diagnostic =
                    "Omitted runtime facts require an explicit truncation marker.";
                return result;
            }
            if (!input.supplied)
            {
                FinishResult(result);
                return result;
            }

            std::size_t ordinal = 0;
            if (input.collectionAttempted && !input.available)
            {
                ObservationSpec note = CollectionNoteSpec(
                    NativeRuntimeMappingCollectionUnavailable,
                    "runtime.collection-unavailable",
                    "Runtime metadata unavailable",
                    "Runtime metadata collection did not return available evidence.",
                    "runtime-capture",
                    input.source,
                    false,
                    ordinal++);
                note.limitations = input.limitations;
                if (!AddRecord(result, entityScope, std::move(note)))
                {
                    return result;
                }
                FinishResult(result);
                return result;
            }
            if (!input.available)
            {
                FinishResult(result);
                return result;
            }

            ObservationSpec capture;
            capture.mappingRuleId = NativeRuntimeMappingCaptureContext;
            capture.semanticFactKey = "runtime.capture-context";
            capture.title = "Runtime metadata captured";
            capture.summary =
                "Point-in-time runtime metadata was captured for the selected process.";
            capture.domain = EvidenceDomain::Runtime;
            capture.disposition = ObservationDisposition::Context;
            capture.strength = ObservationStrength::None;
            capture.confidence = ConfidenceFor(input.source.completeness);
            capture.groupingKey = "runtime-capture-context";
            capture.normalizedValue = "runtime-metadata-present";
            capture.artifactIdentity = {
                ObservationArtifactKind::RuntimeObject,
                {},
                "runtime-capture"
            };
            capture.attributes = {
                { "declared-thread-count", std::to_string(input.declaredThreadCount) },
                { "declared-handle-count", std::to_string(input.declaredHandleCount) },
                { "captured-thread-row-count", std::to_string(input.threads.size()) },
                { "process-base-priority-available", input.processBasePriorityAvailable ? "true" : "false" }
            };
            if (input.processBasePriorityAvailable)
            {
                capture.attributes.push_back(
                    { "process-base-priority", std::to_string(input.processBasePriority) });
            }
            capture.limitations = input.limitations;
            capture.source = input.source;
            capture.sourceOrdinal = ordinal++;
            if (!AddRecord(result, entityScope, std::move(capture)))
            {
                return result;
            }

            for (const NativeRuntimeThreadInput& thread : input.threads)
            {
                if (thread.threadId == 0)
                {
                    result.success = false;
                    result.status =
                        NativeRuntimeObservationBuildStatus::InvalidTypedFact;
                    result.diagnostic =
                        "A supplied runtime thread fact has no stable thread identity.";
                    result.records.clear();
                    result.inventory = {};
                    return result;
                }

                ObservationSpec observation;
                observation.mappingRuleId = NativeRuntimeMappingThreadContext;
                observation.semanticFactKey =
                    "runtime.thread|" + std::to_string(thread.threadId);
                observation.title = "Thread runtime metadata observed";
                observation.summary =
                    "Point-in-time thread metadata was observed; its attributes are context and do not establish behavior by themselves.";
                observation.domain = EvidenceDomain::Runtime;
                observation.disposition = ObservationDisposition::Context;
                observation.strength = ObservationStrength::None;
                observation.confidence = ConfidenceFor(
                    thread.source.completeness);
                observation.groupingKey = "runtime-thread-context";
                observation.normalizedValue =
                    "thread-runtime-metadata";
                observation.artifactIdentity = {
                    ObservationArtifactKind::RuntimeObject,
                    {},
                    "thread:" + std::to_string(thread.threadId)
                };
                observation.attributes = {
                    { "thread-id", std::to_string(thread.threadId) },
                    { "owner-process-id", std::to_string(thread.ownerProcessId) },
                    { "owner-identity-known", thread.ownerIdentityKnown ? "true" : "false" },
                    { "owner-matches-selected", thread.ownerMatchesSelectedProcess ? "true" : "false" },
                    { "start-address-available", thread.startAddressAvailable ? "true" : "false" },
                    { "start-kind", NativeRuntimeThreadStartKindDisplayText(thread.startKind) },
                    { "state", NativeRuntimeThreadStateDisplayText(thread.state) }
                };
                if (thread.startAddressAvailable)
                {
                    observation.attributes.push_back(
                        { "start-address", HexValue(thread.startAddress) });
                }
                if (!thread.resolvedModuleIdentity.empty())
                {
                    observation.attributes.push_back(
                        { "resolved-module-identity", thread.resolvedModuleIdentity });
                }
                if (thread.basePriorityAvailable)
                {
                    observation.attributes.push_back(
                        { "base-priority", std::to_string(thread.basePriority) });
                    if (input.processBasePriorityAvailable)
                    {
                        observation.attributes.push_back({
                            "priority-differs-from-process-base",
                            thread.basePriority == input.processBasePriority
                                ? "false"
                                : "true"
                        });
                    }
                }
                if (thread.currentPriorityAvailable)
                {
                    observation.attributes.push_back(
                        { "current-priority", std::to_string(thread.currentPriority) });
                }
                observation.evidence = thread.evidence;
                observation.limitations = thread.limitations;
                observation.limitations.push_back(StaticRuntimeLimitation);
                if (thread.ownerIdentityKnown &&
                    !thread.ownerMatchesSelectedProcess)
                {
                    observation.limitations.push_back(
                        "The captured owner identity does not match the selected process identity; this record remains non-contributing context.");
                }
                observation.source = thread.source;
                observation.sourceOrdinal = ordinal++;
                if (!AddRecord(result, entityScope, std::move(observation)))
                {
                    return result;
                }
            }

            for (const NativeRuntimeRelationshipInput& relationship :
                input.relationships)
            {
                if (!ValidIdentity(relationship.selectedIdentity) ||
                    !ValidIdentity(relationship.sourceIdentity) ||
                    !ValidIdentity(relationship.targetIdentity) ||
                    !SameIdentity(relationship.selectedIdentity, input.identity) ||
                    (!SameIdentity(relationship.sourceIdentity, input.identity) &&
                        !SameIdentity(relationship.targetIdentity, input.identity)))
                {
                    result.success = false;
                    result.status =
                        NativeRuntimeObservationBuildStatus::InvalidTypedFact;
                    result.diagnostic =
                        "An explicit runtime relationship does not belong to the selected process identity.";
                    result.records.clear();
                    result.inventory = {};
                    return result;
                }

                const bool exactRelationship = relationship.verified &&
                    relationship.sourceIdentity.hasCreationTime &&
                    relationship.targetIdentity.hasCreationTime &&
                    relationship.sourceThreadId != 0 &&
                    relationship.targetThreadId != 0;
                const std::string relationKey =
                    "runtime.relationship|" +
                    std::to_string(static_cast<std::uint32_t>(relationship.kind)) +
                    "|source:" + IdentityText(relationship.sourceIdentity) +
                    "|target:" + IdentityText(relationship.targetIdentity) +
                    "|source-thread:" +
                    std::to_string(relationship.sourceThreadId) +
                    "|target-thread:" +
                    std::to_string(relationship.targetThreadId);
                ObservationSpec observation;
                observation.mappingRuleId =
                    NativeRuntimeMappingExplicitRelationship;
                observation.sourceRuleId = relationship.sourceRuleId;
                observation.semanticFactKey = relationKey;
                observation.title = "Explicit runtime relationship observed";
                observation.summary = exactRelationship
                    ? "An already-collected typed source/target runtime relationship was verified."
                    : "A typed source/target runtime relationship was supplied without exact identity verification and remains context only.";
                observation.domain = EvidenceDomain::Runtime;
                observation.disposition = exactRelationship
                    ? ObservationDisposition::CorrelatedOnly
                    : ObservationDisposition::Context;
                observation.strength = exactRelationship
                    ? ObservationStrength::Weak
                    : ObservationStrength::None;
                observation.confidence = exactRelationship
                    ? ConfidenceFor(relationship.source.completeness)
                    : ObservationConfidence::Low;
                observation.material = exactRelationship;
                observation.groupingKey = "runtime-explicit-relationship";
                observation.correlationKey = exactRelationship
                    ? "runtime-sensitive-access"
                    : std::string{};
                observation.normalizedValue = relationKey;
                observation.artifactIdentity = {
                    ObservationArtifactKind::RuntimeObject,
                    {},
                    "runtime-relation:" + FingerprintText(relationKey)
                };
                observation.attributes = {
                    { "relationship-kind", NativeRuntimeRelationshipKindDisplayText(relationship.kind) },
                    { "source-identity", IdentityText(relationship.sourceIdentity) },
                    { "target-identity", IdentityText(relationship.targetIdentity) },
                    { "source-pid", std::to_string(relationship.sourceIdentity.pid) },
                    { "source-creation-time", std::to_string(relationship.sourceIdentity.creationTimeFileTime) },
                    { "target-pid", std::to_string(relationship.targetIdentity.pid) },
                    { "target-creation-time", std::to_string(relationship.targetIdentity.creationTimeFileTime) },
                    { "source-thread-id", std::to_string(relationship.sourceThreadId) },
                    { "target-thread-id", std::to_string(relationship.targetThreadId) },
                    { "verified", exactRelationship ? "true" : "false" }
                };
                observation.evidence = relationship.evidence;
                observation.limitations = relationship.limitations;
                if (!exactRelationship)
                {
                    observation.limitations.push_back(
                        "A runtime relationship without verified PID and creation-time identities cannot activate a correlation.");
                }
                observation.source = relationship.source;
                observation.sourceOrdinal = ordinal++;
                if (!AddRecord(result, entityScope, std::move(observation)))
                {
                    return result;
                }
            }

            if (input.sourceFactsTruncated)
            {
                ObservationSpec note = CollectionNoteSpec(
                    NativeRuntimeMappingCollectionTruncated,
                    "runtime.collection-truncated",
                    "Runtime metadata collection was truncated",
                    "The supplied runtime capture indicates partial coverage; omitted facts were not interpreted as clean evidence.",
                    "runtime-capture",
                    input.source,
                    input.omittedMaterialFactCount != 0,
                    ordinal++);
                note.source.completeness =
                    NativeRuntimeSourceCompleteness::Partial;
                note.attributes = {
                    { "omitted-material-fact-count", std::to_string(input.omittedMaterialFactCount) }
                };
                note.limitations = input.limitations;
                if (!AddRecord(result, entityScope, std::move(note)))
                {
                    return result;
                }
                result.truncated = true;
                result.omittedMaterialFactCount =
                    input.omittedMaterialFactCount;
            }

            FinishResult(result);
            return result;
        }
        catch (...)
        {
            result.success = false;
            result.status =
                NativeRuntimeObservationBuildStatus::PolicyValidationFailed;
            result.records.clear();
            result.inventory = {};
            result.diagnostic =
                "Native runtime observation construction failed internally.";
            return result;
        }
    }

    NativeRuntimeObservationBuildResult BuildNativePriorityObservations(
        const NativePriorityObservationInput& input) noexcept
    {
        NativeRuntimeObservationBuildResult result;
        result.attempted = true;
        try
        {
            std::string entityScope;
            if (!ValidateCommonInput(
                    input.identity,
                    input.entityScope,
                    entityScope,
                    result))
            {
                return result;
            }
            if (input.limitations.size() >
                NativeRuntimeObservationMaxLimitations)
            {
                result.status =
                    NativeRuntimeObservationBuildStatus::InputLimitExceeded;
                result.diagnostic =
                    "Native priority typed input exceeded a bounded cap.";
                return result;
            }
            if (input.omittedMaterialFactCount != 0 &&
                !input.sourceFactsTruncated)
            {
                result.status =
                    NativeRuntimeObservationBuildStatus::InvalidTypedFact;
                result.diagnostic =
                    "Omitted priority facts require an explicit truncation marker.";
                return result;
            }
            if (!input.supplied)
            {
                FinishResult(result);
                return result;
            }

            if (input.collectionAttempted && !input.available)
            {
                ObservationSpec note = CollectionNoteSpec(
                    NativePriorityMappingCollectionUnavailable,
                    "priority.collection-unavailable",
                    "Priority metadata unavailable",
                    "Priority metadata collection did not return available evidence.",
                    "process-priority",
                    input.source,
                    false,
                    0);
                note.limitations = input.limitations;
                if (!AddRecord(result, entityScope, std::move(note)))
                {
                    return result;
                }
                FinishResult(result);
                return result;
            }
            if (!input.available)
            {
                FinishResult(result);
                return result;
            }

            ObservationSpec priority;
            priority.mappingRuleId = NativePriorityMappingProcessContext;
            priority.semanticFactKey = "priority.process";
            priority.title = "Process priority metadata observed";
            priority.summary =
                "The process priority class was observed as point-in-time context and does not contribute by itself.";
            priority.domain = EvidenceDomain::Runtime;
            priority.disposition = ObservationDisposition::Context;
            priority.strength = ObservationStrength::None;
            priority.confidence = ConfidenceFor(input.source.completeness);
            priority.groupingKey = "runtime-priority-context";
            priority.normalizedValue =
                "process-priority:" + std::to_string(
                    static_cast<std::uint32_t>(input.priorityClass));
            priority.artifactIdentity = {
                ObservationArtifactKind::RuntimeObject,
                {},
                "process-priority"
            };
            priority.attributes = {
                { "priority-class", NativeProcessPriorityClassDisplayText(input.priorityClass) },
                { "raw-priority-class", std::to_string(input.rawPriorityClass) },
                { "base-priority-available", input.basePriorityAvailable ? "true" : "false" },
                {
                    "differs-from-normal-class",
                    input.priorityClass != NativeProcessPriorityClass::NotEvaluated &&
                        input.priorityClass != NativeProcessPriorityClass::Unknown &&
                        input.priorityClass != NativeProcessPriorityClass::Normal
                        ? "true"
                        : "false"
                }
            };
            if (input.basePriorityAvailable)
            {
                priority.attributes.push_back(
                    { "base-priority", std::to_string(input.basePriority) });
            }
            priority.evidence = input.evidence;
            priority.limitations = input.limitations;
            priority.source = input.source;
            if (!AddRecord(result, entityScope, std::move(priority)))
            {
                return result;
            }

            if (input.sourceFactsTruncated)
            {
                ObservationSpec note = CollectionNoteSpec(
                    NativePriorityMappingCollectionTruncated,
                    "priority.collection-truncated",
                    "Priority metadata collection was truncated",
                    "The supplied priority capture indicates partial coverage; omitted facts were not interpreted as clean evidence.",
                    "process-priority",
                    input.source,
                    input.omittedMaterialFactCount != 0,
                    1);
                note.source.completeness =
                    NativeRuntimeSourceCompleteness::Partial;
                note.attributes = {
                    { "omitted-material-fact-count", std::to_string(input.omittedMaterialFactCount) }
                };
                note.limitations = input.limitations;
                if (!AddRecord(result, entityScope, std::move(note)))
                {
                    return result;
                }
                result.truncated = true;
                result.omittedMaterialFactCount =
                    input.omittedMaterialFactCount;
            }

            FinishResult(result);
            return result;
        }
        catch (...)
        {
            result.success = false;
            result.status =
                NativeRuntimeObservationBuildStatus::PolicyValidationFailed;
            result.records.clear();
            result.inventory = {};
            result.diagnostic =
                "Native priority observation construction failed internally.";
            return result;
        }
    }
}
