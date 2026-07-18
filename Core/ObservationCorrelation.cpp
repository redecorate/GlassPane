#include "ObservationCorrelation.h"

#include "ObservationPolicy.h"

#include <algorithm>
#include <chrono>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>
#include <tuple>
#include <utility>

namespace GlassPane::Core
{
    namespace
    {
        using CorrelationClock = std::chrono::steady_clock;

        struct ObservationView
        {
            const RefinedObservationMember* member = nullptr;
            Observation effective;
            std::size_t ordinal = 0;
        };

        struct PendingCorrelation
        {
            std::string ruleId;
            std::string entityScope;
            std::string correlationKey;
            std::string title;
            std::string rationale;
            CorrelationSignificance significance =
                CorrelationSignificance::Informational;
            std::vector<const ObservationView*> participants;
            std::vector<const ObservationView*> supporting;
        };

        enum class PendingBuildResult
        {
            NoMatch,
            Match
        };

        std::uint64_t ElapsedMicroseconds(CorrelationClock::time_point started)
        {
            const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                CorrelationClock::now() - started).count();
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
            ObservationCorrelationResult& result,
            std::string warning)
        {
            if (warning.size() > ObservationCorrelationWarningMaxCharacters)
            {
                warning.resize(ObservationCorrelationWarningMaxCharacters);
            }
            if (result.warnings.size() >= ObservationCorrelationMaxWarnings)
            {
                result.warningsTruncated = true;
                return;
            }
            result.warnings.push_back(std::move(warning));
        }

        ObservationCorrelationResult FailureResult(
            ObservationCorrelationStatus status,
            std::size_t preparedCount,
            const char* warning,
            CorrelationClock::time_point started)
        {
            ObservationCorrelationResult result;
            result.attempted = true;
            result.status = status;
            result.summary.preparedCorrelationCount = preparedCount;
            result.summary.correlationDurationMicroseconds =
                ElapsedMicroseconds(started);
            AddWarning(result, warning);
            return result;
        }

        bool IsKnownDomain(EvidenceDomain domain)
        {
            switch (domain)
            {
            case EvidenceDomain::Unknown:
            case EvidenceDomain::ProcessIdentity:
            case EvidenceDomain::FilePath:
            case EvidenceDomain::FileSignature:
            case EvidenceDomain::CommandLine:
            case EvidenceDomain::ProcessRelationship:
            case EvidenceDomain::Network:
            case EvidenceDomain::Service:
            case EvidenceDomain::Module:
            case EvidenceDomain::Handle:
            case EvidenceDomain::Runtime:
            case EvidenceDomain::MemoryMetadata:
            case EvidenceDomain::Token:
            case EvidenceDomain::Persistence:
            case EvidenceDomain::CollectionQuality:
            case EvidenceDomain::EvidenceIntegrity:
            case EvidenceDomain::ImportedEvidence:
                return true;
            default:
                return false;
            }
        }

        bool IsKnownRequirementMode(CorrelationDomainRequirementMode mode)
        {
            return mode == CorrelationDomainRequirementMode::AllOf ||
                mode == CorrelationDomainRequirementMode::AnyOf;
        }

        bool ValidatePreparation(
            const ObservationCorrelationPreparation& preparation,
            std::size_t& sourceReferenceCount)
        {
            if (preparation.entityScope.size() > ObservationEntityScopeMaxCharacters ||
                preparation.correlationKey.size() > ObservationCorrelationKeyMaxCharacters ||
                preparation.requirements.size() >
                    ObservationCorrelationMaxRequirementsPerPreparation ||
                preparation.sourceObservationIds.size() >
                    ObservationRefinementMaxCorrelationSourceIds)
            {
                return false;
            }
            for (const CorrelationDomainRequirement& requirement :
                preparation.requirements)
            {
                if (!IsKnownRequirementMode(requirement.mode) ||
                    requirement.domains.size() >
                        ObservationCorrelationMaxDomainsPerRequirement ||
                    std::any_of(
                        requirement.domains.begin(),
                        requirement.domains.end(),
                        [](EvidenceDomain domain)
                        {
                            return !IsKnownDomain(domain);
                        }))
                {
                    return false;
                }
            }
            if (preparation.availableSupportingDomains.size() >
                    ObservationCorrelationMaxDomainsPerRequirement ||
                std::any_of(
                    preparation.availableSupportingDomains.begin(),
                    preparation.availableSupportingDomains.end(),
                    [](EvidenceDomain domain)
                    {
                        return !IsKnownDomain(domain);
                    }))
            {
                return false;
            }
            for (const std::string& id : preparation.sourceObservationIds)
            {
                if (id.size() > ObservationIdMaxCharacters)
                {
                    return false;
                }
            }
            sourceReferenceCount += preparation.sourceObservationIds.size();
            return sourceReferenceCount <=
                ObservationRefinementMaxCorrelationSourceIds;
        }

        bool RequirementSatisfied(
            const CorrelationDomainRequirement& requirement,
            const std::vector<EvidenceDomain>& availableDomains)
        {
            const auto available = [&](EvidenceDomain domain)
            {
                return std::find(
                           availableDomains.begin(),
                           availableDomains.end(),
                           domain) != availableDomains.end();
            };
            return requirement.mode == CorrelationDomainRequirementMode::AnyOf
                ? std::any_of(
                    requirement.domains.begin(),
                    requirement.domains.end(),
                    available)
                : std::all_of(
                    requirement.domains.begin(),
                    requirement.domains.end(),
                    available);
        }

        bool PreparationCompletenessIsConsistent(
            const ObservationCorrelationPreparation& preparation)
        {
            const bool requirementsSatisfied = preparation.requirementsKnown &&
                std::all_of(
                    preparation.requirements.begin(),
                    preparation.requirements.end(),
                    [&](const CorrelationDomainRequirement& requirement)
                    {
                        return RequirementSatisfied(
                            requirement,
                            preparation.availableSupportingDomains);
                    });
            return preparation.incomplete == !requirementsSatisfied;
        }

        bool BuildViews(
            const ObservationRefinementResult& refinement,
            std::vector<ObservationView>& views)
        {
            std::size_t memberCount = 0;
            for (const RefinedObservationGroup& group : refinement.groups)
            {
                if (group.entityScope.size() > ObservationEntityScopeMaxCharacters ||
                    group.groupingKey.size() > ObservationGroupingKeyMaxCharacters ||
                    group.semanticFamily.size() > ObservationGroupingKeyMaxCharacters ||
                    !IsKnownDomain(group.domain))
                {
                    return false;
                }
                if (group.members.size() >
                    ObservationRefinementMaxSourceObservations - memberCount)
                {
                    return false;
                }
                memberCount += group.members.size();
                for (const RefinedObservationMember& member : group.members)
                {
                    const Observation& source = member.sourceRecord.observation;
                    const bool artifactGrouped =
                        HasCompleteObservationArtifactIdentity(
                            group.artifactIdentity);
                    const bool artifactMatches = artifactGrouped &&
                        source.artifactIdentity.kind ==
                            group.artifactIdentity.kind &&
                        source.artifactIdentity.entityScope ==
                            group.artifactIdentity.entityScope &&
                        source.artifactIdentity.artifactKey ==
                            group.artifactIdentity.artifactKey;
                    if (source.id.empty() ||
                        source.entityScope != group.entityScope ||
                        (!artifactGrouped &&
                            source.groupingKey != group.groupingKey) ||
                        (artifactGrouped && !artifactMatches) ||
                        source.domain != group.domain ||
                        !ValidateObservation(source).IsValid())
                    {
                        return false;
                    }
                    Observation effective = EffectiveObservation(member);
                    if (!ValidateObservation(effective).IsValid())
                    {
                        return false;
                    }
                    views.push_back({ &member, std::move(effective), views.size() });
                }
            }
            return true;
        }

        bool IsExcluded(const ObservationView& view)
        {
            const Observation& observation = view.effective;
            return view.member == nullptr ||
                view.member->role == RefinedObservationRole::Duplicate ||
                view.member->role == RefinedObservationRole::ArtifactAttribute ||
                view.member->suppressed ||
                observation.disposition == ObservationDisposition::SuppressedExpected ||
                observation.disposition == ObservationDisposition::CollectionNote ||
                observation.disposition == ObservationDisposition::EvidenceIntegrityNote ||
                observation.disposition == ObservationDisposition::Informational ||
                observation.domain == EvidenceDomain::Unknown ||
                observation.domain == EvidenceDomain::CollectionQuality ||
                observation.domain == EvidenceDomain::EvidenceIntegrity ||
                observation.sourceKind == ObservationSourceKind::Unavailable ||
                !observation.provenance.sourceAvailable;
        }

        bool HasMapping(const ObservationView& view, const char* mappingRuleId)
        {
            return view.member != nullptr &&
                view.member->sourceRecord.source.mappingRuleId == mappingRuleId;
        }

        bool HasAnyMapping(
            const ObservationView& view,
            std::initializer_list<const char*> mappingRuleIds)
        {
            return std::any_of(
                mappingRuleIds.begin(),
                mappingRuleIds.end(),
                [&](const char* mappingRuleId)
                {
                    return HasMapping(view, mappingRuleId);
                });
        }

        bool IsPreparedSource(
            const ObservationView& view,
            const ObservationCorrelationPreparation& preparation)
        {
            return std::find(
                       preparation.sourceObservationIds.begin(),
                       preparation.sourceObservationIds.end(),
                       view.effective.id) != preparation.sourceObservationIds.end();
        }

        int StrengthRank(ObservationStrength strength)
        {
            switch (strength)
            {
            case ObservationStrength::Strong:
                return 3;
            case ObservationStrength::Moderate:
                return 2;
            case ObservationStrength::Weak:
                return 1;
            default:
                return 0;
            }
        }

        int ConfidenceRank(ObservationConfidence confidence)
        {
            switch (confidence)
            {
            case ObservationConfidence::High:
                return 3;
            case ObservationConfidence::Medium:
                return 2;
            case ObservationConfidence::Low:
                return 1;
            default:
                return 0;
            }
        }

        bool BetterCandidate(
            const ObservationView& candidate,
            const ObservationView& current)
        {
            const int candidateStrength = StrengthRank(candidate.effective.strength);
            const int currentStrength = StrengthRank(current.effective.strength);
            if (candidateStrength != currentStrength)
            {
                return candidateStrength > currentStrength;
            }
            const int candidateConfidence = ConfidenceRank(candidate.effective.confidence);
            const int currentConfidence = ConfidenceRank(current.effective.confidence);
            if (candidateConfidence != currentConfidence)
            {
                return candidateConfidence > currentConfidence;
            }
            return candidate.ordinal < current.ordinal;
        }

        template <typename Predicate>
        std::vector<const ObservationView*> SelectCandidates(
            const std::vector<ObservationView>& views,
            const std::string& entityScope,
            Predicate predicate)
        {
            std::vector<const ObservationView*> selected;
            for (const ObservationView& view : views)
            {
                if (view.effective.entityScope == entityScope &&
                    !IsExcluded(view) && predicate(view))
                {
                    selected.push_back(&view);
                }
            }
            return selected;
        }

        const ObservationView* BestCandidate(
            const std::vector<const ObservationView*>& candidates)
        {
            if (candidates.empty())
            {
                return nullptr;
            }
            const ObservationView* best = candidates.front();
            for (const ObservationView* candidate : candidates)
            {
                if (BetterCandidate(*candidate, *best))
                {
                    best = candidate;
                }
            }
            return best;
        }

        const std::string* ArtifactAttributeValue(
            const ObservationView& view,
            const char* key)
        {
            const auto found = std::find_if(
                view.effective.artifactAttributes.begin(),
                view.effective.artifactAttributes.end(),
                [&](const ObservationArtifactAttribute& attribute)
                {
                    return attribute.key == key;
                });
            return found == view.effective.artifactAttributes.end()
                ? nullptr
                : &found->value;
        }

        bool RuntimeRelationshipMatchesHandleTarget(
            const ObservationView& runtime,
            const ObservationView& handle)
        {
            const std::string* handleSourcePid = ArtifactAttributeValue(
                handle,
                "handle.source.pid");
            const std::string* handleSourceCreation = ArtifactAttributeValue(
                handle,
                "handle.source.creation-time");
            const std::string* handleTargetPid = ArtifactAttributeValue(
                handle,
                "handle.target.pid");
            const std::string* handleTargetCreation = ArtifactAttributeValue(
                handle,
                "handle.target.creation-time");
            if (handleSourcePid == nullptr ||
                handleSourceCreation == nullptr ||
                handleTargetPid == nullptr ||
                handleTargetCreation == nullptr)
            {
                return false;
            }
            const std::string* runtimeSourcePid = ArtifactAttributeValue(
                runtime,
                "source-pid");
            const std::string* runtimeSourceCreation = ArtifactAttributeValue(
                runtime,
                "source-creation-time");
            const std::string* runtimeTargetPid = ArtifactAttributeValue(
                runtime,
                "target-pid");
            const std::string* runtimeTargetCreation = ArtifactAttributeValue(
                runtime,
                "target-creation-time");
            return runtimeSourcePid != nullptr &&
                runtimeSourceCreation != nullptr &&
                runtimeTargetPid != nullptr &&
                runtimeTargetCreation != nullptr &&
                *runtimeSourcePid == *handleSourcePid &&
                *runtimeSourceCreation == *handleSourceCreation &&
                *runtimeTargetPid == *handleTargetPid &&
                *runtimeTargetCreation == *handleTargetCreation;
        }

        void AppendDistinctView(
            std::vector<const ObservationView*>& output,
            const ObservationView* view)
        {
            if (view == nullptr ||
                std::any_of(
                    output.begin(),
                    output.end(),
                    [&](const ObservationView* current)
                    {
                        return current->effective.id == view->effective.id;
                    }))
            {
                return;
            }
            output.push_back(view);
        }

        void AppendRemainingAsSupport(
            PendingCorrelation& pending,
            const std::vector<const ObservationView*>& candidates)
        {
            for (const ObservationView* candidate : candidates)
            {
                const bool isParticipant = std::any_of(
                    pending.participants.begin(),
                    pending.participants.end(),
                    [&](const ObservationView* participant)
                    {
                        return participant->effective.id == candidate->effective.id;
                    });
                if (!isParticipant)
                {
                    AppendDistinctView(pending.supporting, candidate);
                }
            }
        }

        bool IsUnverifiedForStrong(const ObservationView& view)
        {
            if (!view.effective.provenance.sourceAvailable)
            {
                return true;
            }
            switch (view.effective.sourceKind)
            {
            case ObservationSourceKind::Direct:
            case ObservationSourceKind::Corroborated:
            case ObservationSourceKind::Derived:
            case ObservationSourceKind::Imported:
            case ObservationSourceKind::UserDefined:
                return false;
            case ObservationSourceKind::Unverified:
            case ObservationSourceKind::Unavailable:
            default:
                return true;
            }
        }

        bool AllParticipantsAtLeast(
            const std::vector<const ObservationView*>& participants,
            ObservationStrength minimumStrength,
            ObservationConfidence minimumConfidence)
        {
            return !participants.empty() && std::all_of(
                participants.begin(),
                participants.end(),
                [&](const ObservationView* participant)
                {
                    return StrengthRank(participant->effective.strength) >=
                            StrengthRank(minimumStrength) &&
                        ConfidenceRank(participant->effective.confidence) >=
                            ConfidenceRank(minimumConfidence) &&
                        !IsUnverifiedForStrong(*participant);
                });
        }

        PendingBuildResult BuildExecutionCorrelation(
            const ObservationCorrelationPreparation& preparation,
            const std::vector<ObservationView>& views,
            PendingCorrelation& pending)
        {
            const auto commands = SelectCandidates(
                views,
                preparation.entityScope,
                [&](const ObservationView& view)
                {
                    const bool nativeMapping = HasMapping(
                        view,
                        "baseline.command.encoded-switch");
                    const bool compatibleMapping = nativeMapping;
                    return view.effective.domain == EvidenceDomain::CommandLine &&
                        IsPreparedSource(view, preparation) &&
                        compatibleMapping;
                });
            const auto relationships = SelectCandidates(
                views,
                preparation.entityScope,
                [&](const ObservationView& view)
                {
                    const bool nativeMapping = HasMapping(
                        view,
                        "baseline.relationship.typed-context");
                    const bool compatibleMapping = nativeMapping;
                    return view.effective.domain == EvidenceDomain::ProcessRelationship &&
                        IsPreparedSource(view, preparation) &&
                        compatibleMapping;
                });
            const ObservationView* command = BestCandidate(commands);
            const ObservationView* relationship = BestCandidate(relationships);
            if (command == nullptr || relationship == nullptr)
            {
                return PendingBuildResult::NoMatch;
            }

            pending.ruleId = "correlation.execution.encoded-command-relationship";
            pending.entityScope = preparation.entityScope;
            pending.correlationKey = preparation.correlationKey;
            pending.title = "Encoded command and process relationship";
            pending.rationale =
                "Typed command-line evidence and a distinct process-relationship observation are present for the same entity.";
            pending.participants = { command, relationship };
            pending.significance =
                AllParticipantsAtLeast(
                    pending.participants,
                    ObservationStrength::Strong,
                    ObservationConfidence::High)
                    ? CorrelationSignificance::Strong
                    : CorrelationSignificance::Moderate;
            AppendRemainingAsSupport(pending, commands);
            AppendRemainingAsSupport(pending, relationships);
            return PendingBuildResult::Match;
        }

        bool IsUserWritablePath(const ObservationView& view)
        {
            const bool nativeMapping =
                HasMapping(view, "baseline.file.user-path-context");
            const bool compatibleMapping = nativeMapping;
            return view.effective.domain == EvidenceDomain::FilePath &&
                compatibleMapping;
        }

        bool IsExplicitInvalidSignature(const ObservationView& view)
        {
            const bool nativeMapping =
                HasMapping(view, "baseline.file.signature-invalid");
            const bool compatibleMapping = nativeMapping;
            return view.effective.domain == EvidenceDomain::FileSignature &&
                view.effective.disposition == ObservationDisposition::ReviewRelevant &&
                CanContributeToVerdict(view.effective) &&
                compatibleMapping;
        }

        PendingBuildResult BuildPathSignatureCorrelation(
            const ObservationCorrelationPreparation& preparation,
            const std::vector<ObservationView>& views,
            PendingCorrelation& pending)
        {
            const auto paths = SelectCandidates(
                views,
                preparation.entityScope,
                [&](const ObservationView& view)
                {
                    return IsPreparedSource(view, preparation) &&
                        IsUserWritablePath(view);
                });
            const auto signatures = SelectCandidates(
                views,
                preparation.entityScope,
                IsExplicitInvalidSignature);
            const ObservationView* path = BestCandidate(paths);
            const ObservationView* signature = BestCandidate(signatures);
            if (path == nullptr || signature == nullptr)
            {
                return PendingBuildResult::NoMatch;
            }

            pending.ruleId = "correlation.file.user-path-invalid-signature";
            pending.entityScope = preparation.entityScope;
            pending.correlationKey = preparation.correlationKey;
            pending.title = "User-writable path and invalid signature";
            pending.rationale =
                "A user-writable executable-path observation and an explicit invalid-signature observation are present in independent file evidence domains.";
            pending.significance = CorrelationSignificance::Moderate;
            pending.participants = { path, signature };
            AppendRemainingAsSupport(pending, paths);
            AppendRemainingAsSupport(pending, signatures);
            return PendingBuildResult::Match;
        }


        bool IsExactNetworkIndicator(const ObservationView& view)
        {
            const bool nativeMapping = HasMapping(
                view,
                "baseline.network.indicator-exact-match");
            const bool compatibleMapping = nativeMapping;
            return view.effective.domain == EvidenceDomain::Network &&
                view.effective.disposition == ObservationDisposition::ReviewRelevant &&
                CanContributeToVerdict(view.effective) &&
                compatibleMapping;
        }

        PendingBuildResult BuildNetworkIntelligenceCorrelation(
            const ObservationCorrelationPreparation& preparation,
            const std::vector<ObservationView>& views,
            PendingCorrelation& pending)
        {
            const auto indicators = SelectCandidates(
                views,
                preparation.entityScope,
                [&](const ObservationView& view)
                {
                    return IsPreparedSource(view, preparation) &&
                        IsExactNetworkIndicator(view);
                });
            const auto localEvidence = SelectCandidates(
                views,
                preparation.entityScope,
                [](const ObservationView& view)
                {
                    return view.effective.domain != EvidenceDomain::Network &&
                        view.effective.disposition == ObservationDisposition::ReviewRelevant &&
                        CanContributeToVerdict(view.effective);
                });
            const ObservationView* indicator = BestCandidate(indicators);
            const ObservationView* local = BestCandidate(localEvidence);
            if (indicator == nullptr || local == nullptr)
            {
                return PendingBuildResult::NoMatch;
            }

            pending.ruleId = "correlation.network.exact-indicator-local-evidence";
            pending.entityScope = preparation.entityScope;
            pending.correlationKey = preparation.correlationKey;
            pending.title = "Exact network indicator and local evidence";
            pending.rationale =
                "An exact attributed network-indicator observation and independent local review-relevant evidence are present for the same entity.";
            pending.participants = { indicator, local };
            pending.significance = CorrelationSignificance::Moderate;

            const bool explicitStrongIndicator =
                indicator->effective.strength == ObservationStrength::Strong &&
                indicator->effective.confidence == ObservationConfidence::High &&
                !indicator->member->sourceRecord.source.assessmentRationale.empty();
            if (explicitStrongIndicator &&
                AllParticipantsAtLeast(
                    pending.participants,
                    ObservationStrength::Moderate,
                    ObservationConfidence::High))
            {
                pending.significance = CorrelationSignificance::Strong;
                pending.rationale =
                    "An exact attributed network-indicator observation retains an explicit Strong assessment rationale and is accompanied by high-confidence, independent local evidence.";
            }
            AppendRemainingAsSupport(pending, indicators);
            AppendRemainingAsSupport(pending, localEvidence);
            return PendingBuildResult::Match;
        }

        bool IsSensitiveHandleAnchor(const ObservationView& view)
        {
            const bool nativeMapping = HasAnyMapping(view, {
                    "native.handle.external-process-sensitive-access",
                    "native.handle.external-thread-sensitive-access",
                    "native.handle.external-process-vm-read"
                });
            const bool compatibleMapping = nativeMapping;
            return view.effective.domain == EvidenceDomain::Handle &&
                compatibleMapping &&
                (view.effective.disposition == ObservationDisposition::ReviewRelevant ||
                    view.effective.disposition == ObservationDisposition::CorrelatedOnly);
        }

        bool IsEnabledDebugPrivilege(const ObservationView& view)
        {
            return view.effective.domain == EvidenceDomain::Token &&
                view.member->sourceRecord.source.mappingRuleId ==
                    "native.token.privilege.debug-enabled" &&
                view.effective.disposition ==
                    ObservationDisposition::CorrelatedOnly;
        }

        bool IsHandlePartner(const ObservationView& view)
        {
            switch (view.effective.domain)
            {
            case EvidenceDomain::FilePath:
                return IsUserWritablePath(view);
            case EvidenceDomain::FileSignature:
            case EvidenceDomain::CommandLine:
            case EvidenceDomain::ProcessRelationship:
                return view.effective.disposition ==
                        ObservationDisposition::ReviewRelevant &&
                    CanContributeToVerdict(view.effective);
            default:
                return false;
            }
        }

        PendingBuildResult BuildHandleCorrelation(
            const ObservationCorrelationPreparation& preparation,
            const std::vector<ObservationView>& views,
            PendingCorrelation& pending)
        {
            const auto handles = SelectCandidates(
                views,
                preparation.entityScope,
                [&](const ObservationView& view)
                {
                    return IsPreparedSource(view, preparation) &&
                        IsSensitiveHandleAnchor(view);
                });
            const auto localEvidence = SelectCandidates(
                views,
                preparation.entityScope,
                IsHandlePartner);
            const ObservationView* handle = BestCandidate(handles);
            const ObservationView* local = BestCandidate(localEvidence);
            if (handle == nullptr || local == nullptr)
            {
                return PendingBuildResult::NoMatch;
            }

            pending.ruleId = "correlation.handle.sensitive-access-local-evidence";
            pending.entityScope = preparation.entityScope;
            pending.correlationKey = preparation.correlationKey;
            pending.title = "Sensitive handle activity and local evidence";
            pending.rationale =
                "Typed sensitive handle activity and independent local identity or execution evidence are present for the same entity.";
            pending.significance = CorrelationSignificance::Moderate;
            pending.participants = { handle, local };
            AppendRemainingAsSupport(pending, handles);
            AppendRemainingAsSupport(pending, localEvidence);
            return PendingBuildResult::Match;
        }

        PendingBuildResult BuildDebugPrivilegeAccessCorrelation(
            const ObservationCorrelationPreparation& preparation,
            const std::vector<ObservationView>& views,
            PendingCorrelation& pending)
        {
            const auto tokens = SelectCandidates(
                views,
                preparation.entityScope,
                [&](const ObservationView& view)
                {
                    return IsPreparedSource(view, preparation) &&
                        IsEnabledDebugPrivilege(view);
                });
            const auto handles = SelectCandidates(
                views,
                preparation.entityScope,
                [](const ObservationView& view)
                {
                    return IsSensitiveHandleAnchor(view) &&
                        view.effective.disposition ==
                            ObservationDisposition::ReviewRelevant &&
                        CanContributeToVerdict(view.effective);
                });
            const ObservationView* token = BestCandidate(tokens);
            const ObservationView* handle = BestCandidate(handles);
            if (token == nullptr || handle == nullptr)
            {
                return PendingBuildResult::NoMatch;
            }

            pending.ruleId =
                "correlation.access.enabled-debug-privilege";
            pending.entityScope = preparation.entityScope;
            pending.correlationKey = preparation.correlationKey;
            pending.title =
                "Sensitive external access and enabled debug privilege";
            pending.rationale =
                "Typed sensitive access to a resolved external process or thread and an enabled debug privilege are present for the same source-process identity.";
            pending.significance = CorrelationSignificance::Moderate;
            pending.participants = { handle, token };
            AppendRemainingAsSupport(pending, handles);
            AppendRemainingAsSupport(pending, tokens);
            return PendingBuildResult::Match;
        }

        PendingBuildResult BuildRuntimeAccessCorrelation(
            const ObservationCorrelationPreparation& preparation,
            const std::vector<ObservationView>& views,
            PendingCorrelation& pending)
        {
            const auto runtimeRelationships = SelectCandidates(
                views,
                preparation.entityScope,
                [&](const ObservationView& view)
                {
                    return IsPreparedSource(view, preparation) &&
                        view.effective.domain == EvidenceDomain::Runtime &&
                        view.member->sourceRecord.source.
                            mappingRuleId ==
                                "native.runtime.explicit-relationship" &&
                        view.effective.disposition ==
                            ObservationDisposition::CorrelatedOnly;
                });
            const auto handles = SelectCandidates(
                views,
                preparation.entityScope,
                [](const ObservationView& view)
                {
                    return IsSensitiveHandleAnchor(view) &&
                        view.effective.disposition ==
                            ObservationDisposition::ReviewRelevant &&
                        CanContributeToVerdict(view.effective);
                });
            const ObservationView* runtime = nullptr;
            const ObservationView* handle = nullptr;
            for (const ObservationView* candidateHandle : handles)
            {
                for (const ObservationView* candidateRuntime :
                    runtimeRelationships)
                {
                    if (!RuntimeRelationshipMatchesHandleTarget(
                            *candidateRuntime,
                            *candidateHandle))
                    {
                        continue;
                    }
                    if (handle == nullptr ||
                        BetterCandidate(*candidateHandle, *handle) ||
                        (candidateHandle == handle &&
                            BetterCandidate(*candidateRuntime, *runtime)))
                    {
                        handle = candidateHandle;
                        runtime = candidateRuntime;
                    }
                }
            }
            if (runtime == nullptr || handle == nullptr)
            {
                return PendingBuildResult::NoMatch;
            }

            pending.ruleId =
                "correlation.runtime.explicit-relationship-sensitive-access";
            pending.entityScope = preparation.entityScope;
            pending.correlationKey = preparation.correlationKey;
            pending.title =
                "Explicit runtime relationship and sensitive access";
            pending.rationale =
                "A verified typed runtime source/target relationship and sensitive access to a resolved external identity are present for the selected process.";
            pending.significance = CorrelationSignificance::Moderate;
            pending.participants = { handle, runtime };
            std::vector<const ObservationView*> coherentHandles;
            for (const ObservationView* candidate : handles)
            {
                if (RuntimeRelationshipMatchesHandleTarget(
                        *runtime,
                        *candidate))
                {
                    coherentHandles.push_back(candidate);
                }
            }
            std::vector<const ObservationView*> coherentRuntimeRelationships;
            for (const ObservationView* candidate : runtimeRelationships)
            {
                if (RuntimeRelationshipMatchesHandleTarget(
                        *candidate,
                        *handle))
                {
                    coherentRuntimeRelationships.push_back(candidate);
                }
            }
            AppendRemainingAsSupport(pending, coherentHandles);
            AppendRemainingAsSupport(
                pending,
                coherentRuntimeRelationships);
            return PendingBuildResult::Match;
        }

        PendingBuildResult BuildIdentitySignatureCorrelation(
            const ObservationCorrelationPreparation& preparation,
            const std::vector<ObservationView>& views,
            PendingCorrelation& pending)
        {
            const auto identities = SelectCandidates(
                views,
                preparation.entityScope,
                [&](const ObservationView& view)
                {
                    return view.effective.domain == EvidenceDomain::ProcessIdentity &&
                        IsPreparedSource(view, preparation) &&
                        view.effective.disposition == ObservationDisposition::ReviewRelevant &&
                        CanContributeToVerdict(view.effective);
                });
            const auto signatures = SelectCandidates(
                views,
                preparation.entityScope,
                [&](const ObservationView& view)
                {
                    return IsPreparedSource(view, preparation) &&
                        IsExplicitInvalidSignature(view);
                });
            const ObservationView* identity = BestCandidate(identities);
            const ObservationView* signature = BestCandidate(signatures);
            if (identity == nullptr || signature == nullptr)
            {
                return PendingBuildResult::NoMatch;
            }

            pending.ruleId = "correlation.identity.explicit-signature-context";
            pending.entityScope = preparation.entityScope;
            pending.correlationKey = preparation.correlationKey;
            pending.title = "Process identity and signature evidence";
            pending.rationale =
                "Explicit typed process-identity evidence and an invalid-signature observation are present; no display-name or signer-name heuristic is used.";
            pending.significance = CorrelationSignificance::Moderate;
            pending.participants = { identity, signature };
            AppendRemainingAsSupport(pending, identities);
            AppendRemainingAsSupport(pending, signatures);
            return PendingBuildResult::Match;
        }

        PendingBuildResult BuildPreparedCorrelation(
            const ObservationCorrelationPreparation& preparation,
            const std::vector<ObservationView>& views,
            PendingCorrelation& pending)
        {
            if (!preparation.requirementsKnown || preparation.incomplete)
            {
                return PendingBuildResult::NoMatch;
            }
            if (preparation.correlationKey == "command-relationship-context" ||
                preparation.correlationKey == "relationship-indicator-context")
            {
                return BuildExecutionCorrelation(preparation, views, pending);
            }
            if (preparation.correlationKey == "file-path-signature-context")
            {
                return BuildPathSignatureCorrelation(preparation, views, pending);
            }
            if (preparation.correlationKey == "network-intelligence-context")
            {
                return BuildNetworkIntelligenceCorrelation(preparation, views, pending);
            }
            if (preparation.correlationKey == "local-signal-handle-context")
            {
                return BuildHandleCorrelation(preparation, views, pending);
            }
            if (preparation.correlationKey == "sensitive-handle-context")
            {
                return BuildHandleCorrelation(preparation, views, pending);
            }
            if (preparation.correlationKey ==
                "sensitive-access-debug-privilege")
            {
                return BuildDebugPrivilegeAccessCorrelation(
                    preparation,
                    views,
                    pending);
            }
            if (preparation.correlationKey ==
                "runtime-sensitive-access")
            {
                return BuildRuntimeAccessCorrelation(
                    preparation,
                    views,
                    pending);
            }
            if (preparation.correlationKey == "identity-signature-context")
            {
                return BuildIdentitySignatureCorrelation(preparation, views, pending);
            }
            return PendingBuildResult::NoMatch;
        }

        ObservationConfidence MinimumParticipantConfidence(
            const std::vector<const ObservationView*>& participants)
        {
            ObservationConfidence result = ObservationConfidence::High;
            if (participants.empty())
            {
                return ObservationConfidence::Unknown;
            }
            for (const ObservationView* participant : participants)
            {
                const int participantRank =
                    ConfidenceRank(participant->effective.confidence);
                if (participantRank == 0)
                {
                    result = ObservationConfidence::Unknown;
                }
                else if (participantRank < ConfidenceRank(result))
                {
                    result = participant->effective.confidence;
                }
            }
            return result;
        }

        bool AppendLimitation(
            std::vector<std::string>& limitations,
            const std::string& value)
        {
            if (value.size() > ObservationLimitationItemMaxCharacters)
            {
                return false;
            }
            if (std::find(limitations.begin(), limitations.end(), value) !=
                limitations.end())
            {
                return true;
            }
            if (limitations.size() >= ObservationCorrelationMaxLimitations)
            {
                return false;
            }
            limitations.push_back(value);
            return true;
        }

        bool AddViewLimitations(
            const ObservationView& view,
            std::vector<std::string>& limitations)
        {
            for (const std::string& limitation : view.effective.limitations)
            {
                if (!AppendLimitation(limitations, limitation))
                {
                    return false;
                }
            }
            for (const std::string& limitation :
                view.effective.provenance.limitations)
            {
                if (!AppendLimitation(limitations, limitation))
                {
                    return false;
                }
            }
            return true;
        }

        std::uint64_t FingerprintHash(const std::string& value)
        {
            std::uint64_t hash = 14695981039346656037ULL;
            for (const unsigned char byte : value)
            {
                hash ^= byte;
                hash *= 1099511628211ULL;
            }
            return hash;
        }

        std::string PendingIdentity(const PendingCorrelation& pending)
        {
            std::vector<std::string> ids;
            ids.reserve(pending.participants.size());
            for (const ObservationView* participant : pending.participants)
            {
                ids.push_back(participant->effective.id);
            }
            std::sort(ids.begin(), ids.end());
            ids.erase(std::unique(ids.begin(), ids.end()), ids.end());

            std::string identity = pending.entityScope + "|" + pending.ruleId;
            for (const std::string& id : ids)
            {
                identity += "|" + id;
            }
            return identity;
        }

        std::string CorrelationId(const PendingCorrelation& pending)
        {
            std::ostringstream stream;
            stream << "correlation:"
                   << std::hex
                   << std::setw(16)
                   << std::setfill('0')
                   << FingerprintHash(PendingIdentity(pending));
            return stream.str();
        }

        bool MaterializeCorrelation(
            const PendingCorrelation& pending,
            ObservationCorrelation& correlation,
            std::size_t& participantReferenceCount,
            std::size_t& supportingReferenceCount)
        {
            if (pending.participants.empty() ||
                pending.participants.size() >
                    ObservationCorrelationMaxParticipantsPerResult ||
                pending.supporting.size() >
                    ObservationCorrelationMaxSupportingPerResult)
            {
                return false;
            }
            participantReferenceCount += pending.participants.size();
            supportingReferenceCount += pending.supporting.size();
            if (participantReferenceCount >
                    ObservationCorrelationMaxParticipantReferences ||
                supportingReferenceCount >
                    ObservationCorrelationMaxSupportingReferences)
            {
                return false;
            }

            correlation.id = CorrelationId(pending);
            correlation.ruleId = pending.ruleId;
            correlation.entityScope = pending.entityScope;
            correlation.correlationKey = pending.correlationKey;
            correlation.title = pending.title;
            correlation.rationale = pending.rationale;
            correlation.significance = pending.significance;
            correlation.confidence = MinimumParticipantConfidence(
                pending.participants);
            correlation.contributesToVerdict =
                pending.significance != CorrelationSignificance::Informational;

            for (const ObservationView* participant : pending.participants)
            {
                correlation.participatingObservationIds.push_back(
                    participant->effective.id);
                correlation.participatingDomains.insert(
                    participant->effective.domain);
                if (!AddViewLimitations(*participant, correlation.limitations))
                {
                    return false;
                }
            }
            for (const ObservationView* supporting : pending.supporting)
            {
                correlation.supportingObservationIds.push_back(
                    supporting->effective.id);
                if (!AddViewLimitations(*supporting, correlation.limitations))
                {
                    return false;
                }
            }

            return correlation.id.size() <= ObservationIdMaxCharacters &&
                correlation.ruleId.size() <= ObservationRuleIdMaxCharacters &&
                correlation.entityScope.size() <= ObservationEntityScopeMaxCharacters &&
                correlation.correlationKey.size() <=
                    ObservationCorrelationKeyMaxCharacters &&
                correlation.title.size() <= ObservationTitleMaxCharacters &&
                correlation.rationale.size() <=
                    ObservationCorrelationRationaleMaxCharacters;
        }

        bool AppendUnresolved(
            ObservationCorrelationResult& result,
            const ObservationCorrelationPreparation& preparation)
        {
            if (result.unresolvedPreparations.size() >=
                ObservationCorrelationMaxUnresolvedPreparations)
            {
                return false;
            }
            result.unresolvedPreparations.push_back(preparation);
            return true;
        }
    }

    std::string CorrelationSignificanceDisplayText(
        CorrelationSignificance significance)
    {
        switch (significance)
        {
        case CorrelationSignificance::Informational:
            return "Informational";
        case CorrelationSignificance::Weak:
            return "Weak";
        case CorrelationSignificance::Moderate:
            return "Moderate";
        case CorrelationSignificance::Strong:
            return "Strong";
        default:
            return UnknownEnumText(
                "correlation significance",
                static_cast<std::uint32_t>(significance));
        }
    }

    std::string ObservationCorrelationStatusDisplayText(
        ObservationCorrelationStatus status)
    {
        switch (status)
        {
        case ObservationCorrelationStatus::NotAttempted:
            return "Not attempted";
        case ObservationCorrelationStatus::Success:
            return "Success";
        case ObservationCorrelationStatus::RefinementUnavailable:
            return "Refinement unavailable";
        case ObservationCorrelationStatus::InvalidRefinement:
            return "Invalid refinement";
        case ObservationCorrelationStatus::ResultLimitExceeded:
            return "Correlation result limit exceeded";
        case ObservationCorrelationStatus::ParticipantLimitExceeded:
            return "Correlation participant limit exceeded";
        case ObservationCorrelationStatus::SupportingLimitExceeded:
            return "Correlation supporting-reference limit exceeded";
        case ObservationCorrelationStatus::UnresolvedLimitExceeded:
            return "Unresolved correlation limit exceeded";
        case ObservationCorrelationStatus::InternalPolicyFailure:
            return "Internal correlation policy failure";
        default:
            return UnknownEnumText(
                "observation correlation status",
                static_cast<std::uint32_t>(status));
        }
    }

    bool ObservationCorrelationResult::Succeeded() const
    {
        return success && status == ObservationCorrelationStatus::Success;
    }

    ObservationCorrelationResult ActivateObservationCorrelations(
        const ObservationRefinementResult& refinement)
    {
        const CorrelationClock::time_point started = CorrelationClock::now();
        try
        {
            if (!refinement.Succeeded())
            {
                return FailureResult(
                    ObservationCorrelationStatus::RefinementUnavailable,
                    refinement.correlations.size(),
                    "Refined Observation inventory was unavailable; no partial correlations were returned.",
                    started);
            }
            if (refinement.groups.size() > ObservationRefinementMaxGroups ||
                refinement.correlations.size() >
                    ObservationRefinementMaxCorrelations)
            {
                return FailureResult(
                    ObservationCorrelationStatus::InvalidRefinement,
                    refinement.correlations.size(),
                    "Refinement metadata exceeded its bounded contract; no partial correlations were returned.",
                    started);
            }

            std::vector<ObservationView> views;
            views.reserve(std::min(
                refinement.summary.behavioralContextObservationCount,
                ObservationRefinementMaxSourceObservations));
            if (!BuildViews(refinement, views))
            {
                return FailureResult(
                    ObservationCorrelationStatus::InvalidRefinement,
                    refinement.correlations.size(),
                    "Refined observations violated their bounded Core contract; no partial correlations were returned.",
                    started);
            }
            std::size_t preparationReferenceCount = 0;
            for (const ObservationCorrelationPreparation& preparation :
                refinement.correlations)
            {
                if (!ValidatePreparation(preparation, preparationReferenceCount) ||
                    !PreparationCompletenessIsConsistent(preparation))
                {
                    return FailureResult(
                        ObservationCorrelationStatus::InvalidRefinement,
                        refinement.correlations.size(),
                        "Correlation preparation metadata violated its bounded Core contract; no partial correlations were returned.",
                        started);
                }
            }

            for (const ObservationCorrelationPreparation& preparation :
                refinement.correlations)
            {
                for (const std::string& sourceId : preparation.sourceObservationIds)
                {
                    const auto source = std::find_if(
                        views.begin(),
                        views.end(),
                        [&](const ObservationView& view)
                        {
                            return view.effective.id == sourceId &&
                                view.effective.entityScope == preparation.entityScope &&
                                view.member->sourceRecord.observation.correlationKey ==
                                    preparation.correlationKey;
                        });
                    if (source == views.end())
                    {
                        return FailureResult(
                            ObservationCorrelationStatus::InvalidRefinement,
                            refinement.correlations.size(),
                            "Correlation preparation referenced an unavailable typed source observation; no partial correlations were returned.",
                            started);
                    }
                }
            }

            ObservationCorrelationResult result;
            result.attempted = true;
            result.status = ObservationCorrelationStatus::Success;
            result.summary.preparedCorrelationCount = refinement.correlations.size();

            std::set<std::string> emittedIdentities;
            std::size_t participantReferenceCount = 0;
            std::size_t supportingReferenceCount = 0;
            for (const ObservationCorrelationPreparation& preparation :
                refinement.correlations)
            {
                PendingCorrelation pending;
                if (BuildPreparedCorrelation(preparation, views, pending) !=
                    PendingBuildResult::Match)
                {
                    if (!AppendUnresolved(result, preparation))
                    {
                        return FailureResult(
                            ObservationCorrelationStatus::UnresolvedLimitExceeded,
                            refinement.correlations.size(),
                            "Unresolved correlation metadata exceeded its cap; no partial correlations were returned.",
                            started);
                    }
                    continue;
                }

                const std::string identity = PendingIdentity(pending);
                if (!emittedIdentities.insert(identity).second)
                {
                    ++result.summary.duplicateCorrelationCount;
                    continue;
                }
                if (result.correlations.size() >= ObservationCorrelationMaxResults)
                {
                    return FailureResult(
                        ObservationCorrelationStatus::ResultLimitExceeded,
                        refinement.correlations.size(),
                        "Activated correlations exceeded the result cap; no partial correlations were returned.",
                        started);
                }
                ObservationCorrelation correlation;
                if (!MaterializeCorrelation(
                        pending,
                        correlation,
                        participantReferenceCount,
                        supportingReferenceCount))
                {
                    const ObservationCorrelationStatus failureStatus =
                        pending.supporting.size() >
                                ObservationCorrelationMaxSupportingPerResult ||
                            supportingReferenceCount >
                                ObservationCorrelationMaxSupportingReferences
                        ? ObservationCorrelationStatus::SupportingLimitExceeded
                        : ObservationCorrelationStatus::ParticipantLimitExceeded;
                    return FailureResult(
                        failureStatus,
                        refinement.correlations.size(),
                        "Correlation references or propagated limitations exceeded a bounded result cap; no partial correlations were returned.",
                        started);
                }
                result.correlations.push_back(std::move(correlation));
            }

            result.summary.activatedCorrelationCount = result.correlations.size();
            result.summary.contributingCorrelationCount =
                static_cast<std::size_t>(std::count_if(
                    result.correlations.begin(),
                    result.correlations.end(),
                    [](const ObservationCorrelation& correlation)
                    {
                        return correlation.contributesToVerdict;
                    }));
            result.summary.unresolvedCorrelationCount =
                result.unresolvedPreparations.size();
            result.summary.correlationDurationMicroseconds =
                ElapsedMicroseconds(started);
            result.success = true;
            return result;
        }
        catch (...)
        {
            return FailureResult(
                ObservationCorrelationStatus::InternalPolicyFailure,
                refinement.correlations.size(),
                "Correlation activation failed internally; no partial correlations were returned.",
                started);
        }
    }
}
