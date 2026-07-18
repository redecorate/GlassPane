#include "ObservationRefinement.h"

#include <algorithm>
#include <chrono>
#include <iomanip>
#include <iterator>
#include <map>
#include <set>
#include <sstream>
#include <tuple>
#include <utility>

namespace GlassPane::Core
{
    namespace
    {
        using RefinementClock = std::chrono::steady_clock;

        constexpr const char* DuplicateSuppressorId =
            "structural.duplicate-source-fact";
        constexpr const char* DuplicateSuppressionReason =
            "A typed source reported the same fact as another retained observation; the duplicate does not contribute independently.";

        struct WorkingObservation
        {
            RefinedObservationMember member;
            std::size_t inputOrdinal = 0;
        };

        struct ArtifactIdentityKey
        {
            ObservationArtifactKind kind = ObservationArtifactKind::None;
            std::string entityScope;
            std::string artifactKey;

            bool operator<(const ArtifactIdentityKey& other) const
            {
                return std::tie(kind, entityScope, artifactKey) <
                    std::tie(other.kind, other.entityScope, other.artifactKey);
            }
        };

        struct GroupIdentity
        {
            std::string entityScope;
            std::string groupingKey;
            EvidenceDomain domain = EvidenceDomain::Unknown;
            bool artifactScoped = false;
            ArtifactIdentityKey artifact;
            std::size_t singletonOrdinal = 0;

            bool operator<(const GroupIdentity& other) const
            {
                return std::tie(
                    entityScope,
                    domain,
                    artifactScoped,
                    artifact.kind,
                    artifact.entityScope,
                    artifact.artifactKey,
                    groupingKey,
                    singletonOrdinal) <
                    std::tie(
                        other.entityScope,
                        other.domain,
                        other.artifactScoped,
                        other.artifact.kind,
                        other.artifact.entityScope,
                        other.artifact.artifactKey,
                        other.groupingKey,
                        other.singletonOrdinal);
            }
        };

        struct CorrelationIdentity
        {
            std::string entityScope;
            std::string correlationKey;

            bool operator<(const CorrelationIdentity& other) const
            {
                return std::tie(entityScope, correlationKey) <
                    std::tie(other.entityScope, other.correlationKey);
            }
        };

        struct DuplicateIdentity
        {
            std::string entityScope;
            EvidenceDomain domain = EvidenceDomain::Unknown;
            bool artifactScoped = false;
            ArtifactIdentityKey artifact;
            std::string factIdentity;

            bool operator<(const DuplicateIdentity& other) const
            {
                return std::tie(
                    entityScope,
                    domain,
                    artifactScoped,
                    artifact.kind,
                    artifact.entityScope,
                    artifact.artifactKey,
                    factIdentity) <
                    std::tie(
                        other.entityScope,
                        other.domain,
                        other.artifactScoped,
                        other.artifact.kind,
                        other.artifact.entityScope,
                        other.artifact.artifactKey,
                        other.factIdentity);
            }
        };

        std::uint64_t ElapsedMicroseconds(RefinementClock::time_point started)
        {
            const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                RefinementClock::now() - started).count();
            return elapsed > 0 ? static_cast<std::uint64_t>(elapsed) : 0;
        }

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

        void AddWarning(
            ObservationRefinementResult& result,
            std::string warning)
        {
            if (warning.size() > ObservationRefinementWarningMaxCharacters)
            {
                warning.resize(ObservationRefinementWarningMaxCharacters);
            }
            if (result.warnings.size() >= ObservationRefinementMaxWarnings)
            {
                result.warningsTruncated = true;
                return;
            }
            result.warnings.push_back(std::move(warning));
        }

        void CopySourceFactSummary(
            ObservationRefinementSummary& summary,
            const ObservationInventory& inventory)
        {
            summary.typedSourceFactCount = inventory.typedSourceFactCount;
            summary.declaredSourceFactCount =
                inventory.declaredSourceFactCount;
        }

        ObservationRefinementResult FailureResult(
            ObservationRefinementStatus status,
            const ObservationInventory& inventory,
            const char* warning,
            RefinementClock::time_point started)
        {
            ObservationRefinementResult result;
            result.attempted = true;
            result.status = status;
            CopySourceFactSummary(result.summary, inventory);
            result.summary.rawObservationCount = inventory.records.size();
            AddWarning(result, warning);
            result.summary.refinementWarningCount = result.warnings.size();
            result.summary.refinementDurationMicroseconds =
                ElapsedMicroseconds(started);
            return result;
        }

        bool SourceMetadataWithinCaps(
            const ObservationRecordSourceMetadata& source)
        {
            return source.sourceRecordId.size() <= ObservationIdMaxCharacters &&
                source.sourceRuleId.size() <= ObservationRuleIdMaxCharacters &&
                source.mappingRuleId.size() <= ObservationRuleIdMaxCharacters &&
                source.sourceTitle.size() <= ObservationTitleMaxCharacters &&
                source.sourceMessage.size() <= ObservationSourceMessageMaxCharacters &&
                source.sourceCategory.size() <= ObservationSourceCategoryMaxCharacters &&
                source.producerIdentifier.size() <=
                    ObservationProvenanceSourceIdentifierMaxCharacters &&
                source.assessmentRationale.size() <=
                    ObservationLimitationItemMaxCharacters;
        }

        bool IsCollectionRecord(const Observation& observation)
        {
            if (observation.disposition == ObservationDisposition::CollectionNote ||
                observation.domain == EvidenceDomain::CollectionQuality)
            {
                return true;
            }
            if (observation.disposition ==
                    ObservationDisposition::EvidenceIntegrityNote ||
                observation.domain == EvidenceDomain::EvidenceIntegrity)
            {
                return false;
            }
            return observation.sourceKind == ObservationSourceKind::Unavailable ||
                !observation.provenance.sourceAvailable;
        }

        bool IsEvidenceIntegrityRecord(const Observation& observation)
        {
            return observation.disposition ==
                    ObservationDisposition::EvidenceIntegrityNote ||
                observation.domain == EvidenceDomain::EvidenceIntegrity;
        }

        std::uint64_t FingerprintHash(const std::string& canonicalIdentity)
        {
            std::uint64_t hash = 14695981039346656037ULL;
            for (const unsigned char byte : canonicalIdentity)
            {
                hash ^= byte;
                hash *= 1099511628211ULL;
            }
            return hash;
        }

        std::string SemanticFingerprint(const std::string& canonicalIdentity)
        {
            std::ostringstream stream;
            stream << "semantic:"
                   << std::hex
                   << std::setw(16)
                   << std::setfill('0')
                   << FingerprintHash(canonicalIdentity);
            std::string fingerprint = stream.str();
            if (fingerprint.size() > ObservationSemanticFingerprintMaxCharacters)
            {
                fingerprint.resize(ObservationSemanticFingerprintMaxCharacters);
            }
            return fingerprint;
        }

        ArtifactIdentityKey ArtifactKeyOf(const Observation& observation)
        {
            ArtifactIdentityKey key;
            if (HasObservationArtifactIdentity(observation))
            {
                key.kind = observation.artifactIdentity.kind;
                key.entityScope = observation.artifactIdentity.entityScope;
                key.artifactKey = observation.artifactIdentity.artifactKey;
            }
            return key;
        }

        DuplicateIdentity MakeDuplicateIdentity(
            const Observation& observation,
            std::string factIdentity)
        {
            DuplicateIdentity identity;
            identity.entityScope = observation.entityScope;
            identity.domain = observation.domain;
            identity.artifactScoped =
                HasObservationArtifactIdentity(observation);
            if (identity.artifactScoped)
            {
                identity.artifact = ArtifactKeyOf(observation);
            }
            identity.factIdentity = std::move(factIdentity);
            return identity;
        }

        std::string CanonicalPrefix(const Observation& observation)
        {
            std::string prefix = observation.entityScope + "|" +
                std::to_string(static_cast<std::uint32_t>(observation.domain)) +
                "|";
            if (HasObservationArtifactIdentity(observation))
            {
                prefix += "artifact:" +
                    std::to_string(static_cast<std::uint32_t>(
                        observation.artifactIdentity.kind)) +
                    "|" + observation.artifactIdentity.entityScope +
                    "|" + observation.artifactIdentity.artifactKey + "|";
            }
            return prefix;
        }

        bool EarlierPrimary(
            const WorkingObservation& candidate,
            const WorkingObservation& current)
        {
            const std::size_t candidateOrdinal =
                candidate.member.sourceRecord.source.sourceOrdinal;
            const std::size_t currentOrdinal =
                current.member.sourceRecord.source.sourceOrdinal;
            if (candidateOrdinal != currentOrdinal)
            {
                return candidateOrdinal < currentOrdinal;
            }
            return candidate.inputOrdinal < current.inputOrdinal;
        }

        bool EarlierArtifactPrimary(
            const WorkingObservation& candidate,
            const WorkingObservation& current)
        {
            const Observation& candidateObservation =
                candidate.member.sourceRecord.observation;
            const Observation& currentObservation =
                current.member.sourceRecord.observation;
            const bool candidateContributes =
                CanContributeToVerdict(candidateObservation);
            const bool currentContributes =
                CanContributeToVerdict(currentObservation);
            if (candidateContributes != currentContributes)
            {
                return candidateContributes;
            }
            if (candidateObservation.strength != currentObservation.strength)
            {
                return static_cast<std::uint32_t>(
                        candidateObservation.strength) >
                    static_cast<std::uint32_t>(currentObservation.strength);
            }
            return EarlierPrimary(candidate, current);
        }

        bool ApplyMemberSuppression(
            RefinedObservationMember& member,
            const char* suppressorId,
            const char* reason)
        {
            ObservationSuppression suppression;
            suppression.suppressorId = suppressorId;
            suppression.reason = reason;
            if (!IsValidObservationSuppression(suppression))
            {
                return false;
            }
            member.suppressed = true;
            member.suppression = std::move(suppression);
            return true;
        }

        void MarkDuplicate(
            WorkingObservation& duplicate,
            const WorkingObservation& primary,
            const std::string& fingerprint)
        {
            duplicate.member.role = RefinedObservationRole::Duplicate;
            duplicate.member.primaryObservationId =
                primary.member.sourceRecord.observation.id;
            duplicate.member.semanticFingerprint = fingerprint;
            ApplyMemberSuppression(
                duplicate.member,
                DuplicateSuppressorId,
                DuplicateSuppressionReason);
        }

        void MarkExactDuplicateIds(std::vector<WorkingObservation>& records)
        {
            std::map<DuplicateIdentity, std::vector<std::size_t>> indexesByIdentity;
            for (std::size_t index = 0; index < records.size(); ++index)
            {
                const Observation& observation =
                    records[index].member.sourceRecord.observation;
                if (observation.entityScope.empty() || observation.id.empty())
                {
                    continue;
                }
                indexesByIdentity[MakeDuplicateIdentity(
                    observation,
                    "observation-id:" + observation.id)].push_back(index);
            }

            for (auto& entry : indexesByIdentity)
            {
                std::vector<std::size_t>& indexes = entry.second;
                if (indexes.size() < 2)
                {
                    continue;
                }
                std::size_t primaryIndex = indexes.front();
                for (const std::size_t index : indexes)
                {
                    if (EarlierPrimary(records[index], records[primaryIndex]))
                    {
                        primaryIndex = index;
                    }
                }
                WorkingObservation& primary = records[primaryIndex];
                const Observation& observation =
                    primary.member.sourceRecord.observation;
                const std::string fingerprint = SemanticFingerprint(
                    CanonicalPrefix(observation) + entry.first.factIdentity);
                primary.member.role = RefinedObservationRole::Primary;
                primary.member.primaryObservationId = observation.id;
                primary.member.semanticFingerprint = fingerprint;
                for (const std::size_t index : indexes)
                {
                    if (index != primaryIndex)
                    {
                        MarkDuplicate(records[index], primary, fingerprint);
                    }
                }
            }
        }

        void MarkTypedDuplicates(std::vector<WorkingObservation>& records)
        {
            MarkExactDuplicateIds(records);
        }

        void ApplyStructuralSuppressions(
            std::vector<WorkingObservation>& records)
        {
            // Native producers assign Context and CollectionNote dispositions
            // directly; there is no separate source-wrapper suppression pass.
            (void)records;
        }

        GroupIdentity MakeGroupIdentity(
            const WorkingObservation& record)
        {
            const Observation& observation = record.member.sourceRecord.observation;
            GroupIdentity identity;
            identity.entityScope = observation.entityScope;
            identity.domain = observation.domain;
            identity.artifactScoped =
                HasObservationArtifactIdentity(observation);
            if (identity.artifactScoped)
            {
                // Artifact identity takes precedence over semantic presentation
                // keys. Several properties of one source artifact are one
                // evidence unit even when source attributes use different keys.
                identity.artifact = ArtifactKeyOf(observation);
            }
            else
            {
                identity.groupingKey = observation.groupingKey;
            }
            if (!identity.artifactScoped &&
                (identity.entityScope.empty() || identity.groupingKey.empty()))
            {
                identity.singletonOrdinal = record.inputOrdinal + 1;
            }
            return identity;
        }

        void AssignArtifactRoles(std::vector<WorkingObservation>& records)
        {
            std::map<GroupIdentity, std::size_t> primaryByArtifact;
            for (std::size_t index = 0; index < records.size(); ++index)
            {
                WorkingObservation& record = records[index];
                if (record.member.role == RefinedObservationRole::Duplicate ||
                    !HasObservationArtifactIdentity(
                        record.member.sourceRecord.observation))
                {
                    continue;
                }
                const GroupIdentity identity = MakeGroupIdentity(record);
                const auto existing = primaryByArtifact.find(identity);
                if (existing == primaryByArtifact.end() ||
                    EarlierArtifactPrimary(
                        record,
                        records[existing->second]))
                {
                    primaryByArtifact[identity] = index;
                }
            }

            for (std::size_t index = 0; index < records.size(); ++index)
            {
                WorkingObservation& record = records[index];
                const Observation& observation =
                    record.member.sourceRecord.observation;
                if (record.member.role == RefinedObservationRole::Duplicate ||
                    !HasObservationArtifactIdentity(observation))
                {
                    continue;
                }
                const GroupIdentity identity = MakeGroupIdentity(record);
                const auto primary = primaryByArtifact.find(identity);
                if (primary == primaryByArtifact.end())
                {
                    continue;
                }
                WorkingObservation& primaryRecord = records[primary->second];
                const Observation& primaryObservation =
                    primaryRecord.member.sourceRecord.observation;
                const std::string fingerprint = SemanticFingerprint(
                    CanonicalPrefix(observation) + "artifact-evidence-unit");
                record.member.semanticFingerprint = fingerprint;
                record.member.primaryObservationId = primaryObservation.id;
                record.member.role = index == primary->second
                    ? RefinedObservationRole::Primary
                    : RefinedObservationRole::ArtifactAttribute;
            }
        }

        void MergeArtifactGroupSemanticLabels(
            RefinedObservationGroup& group,
            const Observation& observation)
        {
            if (!HasCompleteObservationArtifactIdentity(group.artifactIdentity))
            {
                return;
            }
            if (group.groupingKey != observation.groupingKey)
            {
                group.groupingKey.clear();
            }
            if (group.semanticFamily != observation.groupingKey)
            {
                group.semanticFamily.clear();
            }
        }

        bool BuildGroups(
            std::vector<WorkingObservation> records,
            ObservationRefinementResult& result)
        {
            std::map<GroupIdentity, std::size_t> groupIndexByIdentity;
            result.groups.reserve(records.size());
            for (WorkingObservation& record : records)
            {
                const GroupIdentity identity = MakeGroupIdentity(record);
                const auto existing = groupIndexByIdentity.find(identity);
                if (existing != groupIndexByIdentity.end())
                {
                    MergeArtifactGroupSemanticLabels(
                        result.groups[existing->second],
                        record.member.sourceRecord.observation);
                    result.groups[existing->second].members.push_back(
                        std::move(record.member));
                    continue;
                }
                if (result.groups.size() >= ObservationRefinementMaxGroups)
                {
                    return false;
                }
                RefinedObservationGroup group;
                group.entityScope = identity.entityScope;
                const Observation& observation =
                    record.member.sourceRecord.observation;
                group.groupingKey = observation.groupingKey;
                group.semanticFamily = observation.groupingKey;
                group.domain = identity.domain;
                if (identity.artifactScoped)
                {
                    group.artifactIdentity = observation.artifactIdentity;
                }
                group.members.push_back(std::move(record.member));
                const std::size_t groupIndex = result.groups.size();
                result.groups.push_back(std::move(group));
                groupIndexByIdentity.emplace(identity, groupIndex);
            }

            for (RefinedObservationGroup& group : result.groups)
            {
                if (!HasCompleteObservationArtifactIdentity(
                        group.artifactIdentity))
                {
                    continue;
                }
                group.artifactAttributeCount =
                    static_cast<std::size_t>(std::count_if(
                        group.members.begin(),
                        group.members.end(),
                        [](const RefinedObservationMember& member)
                        {
                            return member.role ==
                                    RefinedObservationRole::Primary ||
                                member.role ==
                                    RefinedObservationRole::ArtifactAttribute;
                        }));
            }
            return true;
        }

        void PopulateArtifactSummary(ObservationRefinementResult& result)
        {
            std::set<ArtifactIdentityKey> distinctArtifacts;
            std::map<EvidenceDomain, std::set<ArtifactIdentityKey>>
                artifactsByDomain;
            for (const RefinedObservationGroup& group : result.groups)
            {
                if (!HasCompleteObservationArtifactIdentity(
                        group.artifactIdentity))
                {
                    continue;
                }
                ++result.summary.artifactGroupCount;
                result.summary.artifactAttributeCount +=
                    group.artifactAttributeCount;
                const ArtifactIdentityKey key{
                    group.artifactIdentity.kind,
                    group.artifactIdentity.entityScope,
                    group.artifactIdentity.artifactKey
                };
                distinctArtifacts.insert(key);
                artifactsByDomain[group.domain].insert(key);
            }
            result.summary.distinctArtifactCount = distinctArtifacts.size();
            result.summary.distinctArtifactCountsByDomain.reserve(
                artifactsByDomain.size());
            for (const auto& entry : artifactsByDomain)
            {
                result.summary.distinctArtifactCountsByDomain.push_back({
                    entry.first,
                    entry.second.size()
                });
            }
        }

        std::vector<EvidenceDomain> OtherBehavioralDomains(
            EvidenceDomain anchorDomain)
        {
            const std::vector<EvidenceDomain> behavioralDomains = {
                EvidenceDomain::ProcessIdentity,
                EvidenceDomain::FilePath,
                EvidenceDomain::FileSignature,
                EvidenceDomain::CommandLine,
                EvidenceDomain::ProcessRelationship,
                EvidenceDomain::Network,
                EvidenceDomain::Service,
                EvidenceDomain::Module,
                EvidenceDomain::Handle,
                EvidenceDomain::Runtime,
                EvidenceDomain::MemoryMetadata,
                EvidenceDomain::Token,
                EvidenceDomain::Persistence,
                EvidenceDomain::ImportedEvidence
            };
            std::vector<EvidenceDomain> result;
            result.reserve(behavioralDomains.size() - 1);
            std::copy_if(
                behavioralDomains.begin(),
                behavioralDomains.end(),
                std::back_inserter(result),
                [&](EvidenceDomain domain)
                {
                    return domain != anchorDomain;
                });
            return result;
        }

        std::vector<CorrelationDomainRequirement> AnchoredCorrelationRequirements(
            EvidenceDomain anchorDomain)
        {
            return {
                {
                    CorrelationDomainRequirementMode::AllOf,
                    { anchorDomain }
                },
                {
                    CorrelationDomainRequirementMode::AnyOf,
                    OtherBehavioralDomains(anchorDomain)
                }
            };
        }

        std::vector<CorrelationDomainRequirement> RequirementsForKey(
            const std::string& correlationKey,
            bool& known)
        {
            known = true;
            if (correlationKey == "command-relationship-context")
            {
                return {{
                    CorrelationDomainRequirementMode::AllOf,
                    { EvidenceDomain::CommandLine, EvidenceDomain::ProcessRelationship }
                }};
            }
            if (correlationKey == "file-path-signature-context")
            {
                return {{
                    CorrelationDomainRequirementMode::AllOf,
                    { EvidenceDomain::FilePath, EvidenceDomain::FileSignature }
                }};
            }
            if (correlationKey == "identity-signature-context")
            {
                return {{
                    CorrelationDomainRequirementMode::AllOf,
                    { EvidenceDomain::ProcessIdentity, EvidenceDomain::FileSignature }
                }};
            }
            if (correlationKey == "network-intelligence-context")
            {
                return AnchoredCorrelationRequirements(EvidenceDomain::Network);
            }
            if (correlationKey == "sensitive-handle-context")
            {
                return AnchoredCorrelationRequirements(EvidenceDomain::Handle);
            }
            if (correlationKey ==
                "sensitive-access-debug-privilege")
            {
                return {{
                    CorrelationDomainRequirementMode::AllOf,
                    { EvidenceDomain::Handle, EvidenceDomain::Token }
                }};
            }
            if (correlationKey == "runtime-sensitive-access")
            {
                return {{
                    CorrelationDomainRequirementMode::AllOf,
                    { EvidenceDomain::Handle, EvidenceDomain::Runtime }
                }};
            }
            if (correlationKey == "local-signal-runtime-context")
            {
                return AnchoredCorrelationRequirements(EvidenceDomain::Runtime);
            }
            if (correlationKey == "local-signal-memory-context")
            {
                return AnchoredCorrelationRequirements(EvidenceDomain::MemoryMetadata);
            }
            known = false;
            return {};
        }

        bool RequirementSatisfied(
            const CorrelationDomainRequirement& requirement,
            const std::vector<EvidenceDomain>& available)
        {
            const auto isAvailable = [&](EvidenceDomain domain)
            {
                return std::find(available.begin(), available.end(), domain) !=
                    available.end();
            };
            if (requirement.mode == CorrelationDomainRequirementMode::AnyOf)
            {
                return std::any_of(
                    requirement.domains.begin(),
                    requirement.domains.end(),
                    isAvailable);
            }
            return std::all_of(
                requirement.domains.begin(),
                requirement.domains.end(),
                isAvailable);
        }

        bool BuildCorrelations(
            const std::vector<WorkingObservation>& records,
            ObservationRefinementResult& result)
        {
            std::map<std::string, std::set<EvidenceDomain>> domainsByEntity;
            for (const WorkingObservation& record : records)
            {
                const Observation effective = EffectiveObservation(record.member);
                if (record.member.role ==
                        RefinedObservationRole::ArtifactAttribute ||
                    effective.entityScope.empty() ||
                    effective.domain == EvidenceDomain::Unknown ||
                    effective.disposition == ObservationDisposition::Informational ||
                    effective.disposition == ObservationDisposition::CollectionNote ||
                    effective.disposition == ObservationDisposition::EvidenceIntegrityNote ||
                    effective.disposition == ObservationDisposition::SuppressedExpected)
                {
                    continue;
                }
                domainsByEntity[effective.entityScope].insert(effective.domain);
            }

            std::size_t correlationSourceIdCount = 0;
            std::map<CorrelationIdentity, std::size_t> indexByIdentity;
            for (const WorkingObservation& record : records)
            {
                const Observation& observation = record.member.sourceRecord.observation;
                if (observation.entityScope.empty() || observation.correlationKey.empty())
                {
                    continue;
                }
                const CorrelationIdentity identity{
                    observation.entityScope,
                    observation.correlationKey
                };
                auto existing = indexByIdentity.find(identity);
                if (existing == indexByIdentity.end())
                {
                    if (result.correlations.size() >=
                        ObservationRefinementMaxCorrelations)
                    {
                        return false;
                    }
                    ObservationCorrelationPreparation preparation;
                    preparation.entityScope = observation.entityScope;
                    preparation.correlationKey = observation.correlationKey;
                    preparation.requirements = RequirementsForKey(
                        observation.correlationKey,
                        preparation.requirementsKnown);
                    const auto available = domainsByEntity.find(observation.entityScope);
                    if (available != domainsByEntity.end())
                    {
                        preparation.availableSupportingDomains.assign(
                            available->second.begin(),
                            available->second.end());
                    }
                    const std::size_t newIndex = result.correlations.size();
                    result.correlations.push_back(std::move(preparation));
                    existing = indexByIdentity.emplace(identity, newIndex).first;
                }
                if (correlationSourceIdCount >=
                    ObservationRefinementMaxCorrelationSourceIds)
                {
                    return false;
                }
                ObservationCorrelationPreparation& preparation =
                    result.correlations[existing->second];
                preparation.sourceObservationIds.push_back(observation.id);
                ++correlationSourceIdCount;
                preparation.containsCorrelatedOnly =
                    preparation.containsCorrelatedOnly ||
                    observation.disposition == ObservationDisposition::CorrelatedOnly;
            }

            for (ObservationCorrelationPreparation& preparation : result.correlations)
            {
                preparation.incomplete = !preparation.requirementsKnown ||
                    !std::all_of(
                        preparation.requirements.begin(),
                        preparation.requirements.end(),
                        [&](const CorrelationDomainRequirement& requirement)
                        {
                            return RequirementSatisfied(
                                requirement,
                                preparation.availableSupportingDomains);
                        });
            }
            return true;
        }

        std::vector<Observation> RawObservations(
            const ObservationInventory& inventory)
        {
            std::vector<Observation> observations;
            observations.reserve(inventory.records.size());
            for (const ObservationRecord& record : inventory.records)
            {
                observations.push_back(record.observation);
            }
            return observations;
        }

        std::vector<Observation> EffectiveBehaviorObservations(
            const std::vector<WorkingObservation>& records)
        {
            std::vector<Observation> observations;
            observations.reserve(records.size());
            for (const WorkingObservation& record : records)
            {
                observations.push_back(EffectiveObservation(record.member));
            }
            return observations;
        }
    }

    std::string ObservationRefinementStatusDisplayText(
        ObservationRefinementStatus status)
    {
        switch (status)
        {
        case ObservationRefinementStatus::NotAttempted:
            return "Not attempted";
        case ObservationRefinementStatus::Success:
            return "Success";
        case ObservationRefinementStatus::RawInventoryUnavailable:
            return "Raw inventory unavailable";
        case ObservationRefinementStatus::SourceLimitExceeded:
            return "Source observation limit exceeded";
        case ObservationRefinementStatus::InvalidSourceObservation:
            return "Invalid source observation";
        case ObservationRefinementStatus::GroupLimitExceeded:
            return "Group limit exceeded";
        case ObservationRefinementStatus::CorrelationLimitExceeded:
            return "Correlation limit exceeded";
        case ObservationRefinementStatus::CorrelationReferenceLimitExceeded:
            return "Correlation source-reference limit exceeded";
        case ObservationRefinementStatus::InternalPolicyFailure:
            return "Internal policy failure";
        default:
            return UnknownEnumText(
                "observation refinement status",
                static_cast<std::uint32_t>(status));
        }
    }

    bool ObservationRefinementResult::Succeeded() const
    {
        return success && status == ObservationRefinementStatus::Success;
    }

    Observation EffectiveObservation(const RefinedObservationMember& member)
    {
        Observation effective = member.suppressed
            ? ApplySuppression(
                member.sourceRecord.observation,
                member.suppression)
            : member.sourceRecord.observation;
        if (member.role == RefinedObservationRole::ArtifactAttribute)
        {
            // Multiple properties from one typed artifact remain auditable but
            // cannot reinforce their artifact's primary observation.
            effective.contributesToVerdict = false;
        }
        return effective;
    }

    ObservationRefinementResult RefineObservationInventory(
        const ObservationInventory& inventory)
    {
        const RefinementClock::time_point started = RefinementClock::now();
        try
        {
            if (!inventory.Succeeded())
            {
                return FailureResult(
                    ObservationRefinementStatus::RawInventoryUnavailable,
                    inventory,
                    "Raw Observation inventory was unavailable; no partial refinement was returned.",
                    started);
            }
            if (inventory.records.size() >
                ObservationRefinementMaxSourceObservations)
            {
                return FailureResult(
                    ObservationRefinementStatus::SourceLimitExceeded,
                    inventory,
                    "Source observation count exceeded the refinement cap; no partial refinement was returned.",
                    started);
            }
            for (const ObservationRecord& record : inventory.records)
            {
                if (!ValidateObservation(record.observation).IsValid() ||
                    !SourceMetadataWithinCaps(record.source))
                {
                    return FailureResult(
                        ObservationRefinementStatus::InvalidSourceObservation,
                        inventory,
                        "A source observation violated its bounded Core contract; no partial refinement was returned.",
                        started);
                }
            }

            ObservationRefinementResult result;
            result.attempted = true;
            result.status = ObservationRefinementStatus::Success;
            CopySourceFactSummary(result.summary, inventory);
            result.summary.rawObservationCount = inventory.records.size();
            result.summary.contributingDomainCountBefore =
                CollectContributingDomains(RawObservations(inventory)).size();

            std::vector<WorkingObservation> behavioralRecords;
            behavioralRecords.reserve(inventory.records.size());
            for (std::size_t index = 0; index < inventory.records.size(); ++index)
            {
                const ObservationRecord& record = inventory.records[index];
                const Observation& observation = record.observation;
                if (IsCollectionRecord(observation))
                {
                    result.collectionNotes.push_back(record);
                    continue;
                }
                if (IsEvidenceIntegrityRecord(observation))
                {
                    result.evidenceIntegrityNotes.push_back(record);
                    continue;
                }

                WorkingObservation working;
                working.inputOrdinal = index;
                working.member.sourceRecord = record;
                working.member.semanticFingerprint = SemanticFingerprint(
                    CanonicalPrefix(observation) + "unique|" + observation.id);
                working.member.primaryObservationId = observation.id;
                behavioralRecords.push_back(std::move(working));
            }

            // Establish presentation roles without changing any evidence field.
            std::map<GroupIdentity, std::size_t> firstByGroup;
            for (std::size_t index = 0; index < behavioralRecords.size(); ++index)
            {
                const GroupIdentity identity = MakeGroupIdentity(behavioralRecords[index]);
                const bool first = firstByGroup.emplace(identity, index).second;
                behavioralRecords[index].member.role = first
                    ? RefinedObservationRole::Primary
                    : RefinedObservationRole::Supporting;
            }

            MarkTypedDuplicates(behavioralRecords);
            AssignArtifactRoles(behavioralRecords);
            ApplyStructuralSuppressions(behavioralRecords);

            if (!BuildCorrelations(behavioralRecords, result))
            {
                return FailureResult(
                    result.correlations.size() >=
                            ObservationRefinementMaxCorrelations
                        ? ObservationRefinementStatus::CorrelationLimitExceeded
                        : ObservationRefinementStatus::CorrelationReferenceLimitExceeded,
                    inventory,
                    "Correlation-preparation metadata exceeded its cap; no partial refinement was returned.",
                    started);
            }

            const std::vector<Observation> effectiveObservations =
                EffectiveBehaviorObservations(behavioralRecords);
            result.summary.behavioralContextObservationCount =
                behavioralRecords.size();
            result.summary.collectionNoteCount = result.collectionNotes.size();
            result.summary.evidenceIntegrityNoteCount =
                result.evidenceIntegrityNotes.size();
            result.summary.duplicateCount = static_cast<std::size_t>(std::count_if(
                behavioralRecords.begin(),
                behavioralRecords.end(),
                [](const WorkingObservation& record)
                {
                    return record.member.role == RefinedObservationRole::Duplicate;
                }));
            result.summary.typedSourceFactDuplicateCount =
                result.summary.duplicateCount;
            result.summary.suppressedCount = static_cast<std::size_t>(std::count_if(
                behavioralRecords.begin(),
                behavioralRecords.end(),
                [](const WorkingObservation& record)
                {
                    return record.member.suppressed;
                }));
            result.summary.unresolvedCorrelatedOnlyCount =
                static_cast<std::size_t>(std::count_if(
                    effectiveObservations.begin(),
                    effectiveObservations.end(),
                    [](const Observation& observation)
                    {
                        return observation.disposition ==
                            ObservationDisposition::CorrelatedOnly;
                    }));
            result.summary.contributingDomainCountAfter =
                CollectContributingDomains(effectiveObservations).size();

            if (!BuildGroups(std::move(behavioralRecords), result))
            {
                return FailureResult(
                    ObservationRefinementStatus::GroupLimitExceeded,
                    inventory,
                    "Observation group count exceeded the refinement cap; no partial refinement was returned.",
                    started);
            }
            result.summary.groupCount = result.groups.size();
            PopulateArtifactSummary(result);
            result.summary.refinementWarningCount = result.warnings.size();
            result.summary.refinementDurationMicroseconds =
                ElapsedMicroseconds(started);
            result.success = true;
            return result;
        }
        catch (...)
        {
            return FailureResult(
                ObservationRefinementStatus::InternalPolicyFailure,
                inventory,
                "Observation refinement failed internally; no partial refinement was returned.",
                started);
        }
    }
}
