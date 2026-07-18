#include "Core/ObservationCorrelation.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace GlassPane::Tests
{
    namespace
    {
        using namespace Core;

        constexpr char FixtureEntityScope[] =
            "process:correlation-native-fixture";

        int failureCount = 0;

        void Check(bool condition, const wchar_t* testName)
        {
            if (!condition)
            {
                std::wcerr << L"FAILED: " << testName << L'\n';
                ++failureCount;
            }
        }

        template <typename Value>
        void CheckEqual(
            const Value& actual,
            const Value& expected,
            const wchar_t* testName)
        {
            Check(actual == expected, testName);
        }

        ObservationRecord MakeNativeRecord(
            std::string id,
            std::string mappingRuleId,
            EvidenceDomain domain,
            ObservationDisposition disposition,
            ObservationStrength strength,
            ObservationConfidence confidence,
            std::string groupingKey,
            std::string correlationKey = {},
            std::string entityScope = FixtureEntityScope)
        {
            ObservationRecord record;
            record.source.sourceRecordId = "native-source:" + id;
            record.source.sourceRuleId = mappingRuleId;
            record.source.mappingRuleId = std::move(mappingRuleId);
            record.source.sourceTitle = "Native typed source";
            record.source.sourceMessage = "Native typed source detail.";
            record.source.sourceCategory = "Native selected-process evidence";
            record.source.producerIdentifier = "native-correlation-fixture";

            Observation& observation = record.observation;
            observation.id = std::move(id);
            observation.ruleId = record.source.sourceRuleId;
            observation.title = "Native typed observation";
            observation.summary = "Native typed observation detail.";
            observation.domain = domain;
            observation.sourceKind = ObservationSourceKind::Direct;
            observation.disposition = disposition;
            observation.strength = strength;
            observation.confidence = confidence;
            observation.contributesToVerdict =
                disposition == ObservationDisposition::ReviewRelevant &&
                strength != ObservationStrength::None;
            observation.entityScope = std::move(entityScope);
            observation.groupingKey = std::move(groupingKey);
            observation.correlationKey = std::move(correlationKey);
            observation.rawValue = "Bounded native source value.";
            observation.normalizedValue = observation.id;
            observation.evidence = { "Bounded native evidence." };
            observation.provenance.sourceKind = observation.sourceKind;
            observation.provenance.sourceIdentifier =
                record.source.producerIdentifier;
            observation.provenance.collectionMethod = "fixed-test-input";
            observation.provenance.sourceAvailable = true;
            return record;
        }

        ObservationRecord MakeArtifactRecord(
            std::string id,
            std::string mappingRuleId,
            EvidenceDomain domain,
            ObservationDisposition disposition,
            ObservationStrength strength,
            ObservationConfidence confidence,
            ObservationArtifactKind artifactKind,
            std::string artifactKey,
            std::string artifactAttribute,
            std::string groupingKey,
            std::string correlationKey = {},
            std::string entityScope = FixtureEntityScope)
        {
            ObservationRecord record = MakeNativeRecord(
                std::move(id),
                std::move(mappingRuleId),
                domain,
                disposition,
                strength,
                confidence,
                std::move(groupingKey),
                std::move(correlationKey),
                entityScope);
            record.observation.artifactIdentity = {
                artifactKind,
                entityScope,
                std::move(artifactKey)
            };
            record.observation.artifactAttributes.push_back({
                std::move(artifactAttribute),
                "true"
            });
            return record;
        }

        ObservationRefinementResult RefineNative(
            std::vector<ObservationRecord> records)
        {
            ObservationInventory inventory;
            inventory.status = ObservationInventoryStatus::Success;
            inventory.records = std::move(records);
            return RefineObservationInventory(inventory);
        }

        const ObservationCorrelation* FindCorrelation(
            const ObservationCorrelationResult& result,
            const std::string& ruleId)
        {
            const auto found = std::find_if(
                result.correlations.begin(),
                result.correlations.end(),
                [&](const ObservationCorrelation& correlation)
                {
                    return correlation.ruleId == ruleId;
                });
            return found == result.correlations.end() ? nullptr : &*found;
        }

        bool ContainsId(
            const std::vector<std::string>& ids,
            const std::string& id)
        {
            return std::find(ids.begin(), ids.end(), id) != ids.end();
        }

        std::size_t CountRole(
            const ObservationRefinementResult& refinement,
            RefinedObservationRole role)
        {
            std::size_t count = 0;
            for (const RefinedObservationGroup& group : refinement.groups)
            {
                count += static_cast<std::size_t>(std::count_if(
                    group.members.begin(),
                    group.members.end(),
                    [&](const RefinedObservationMember& member)
                    {
                        return member.role == role;
                    }));
            }
            return count;
        }

        std::string ResultSignature(const ObservationCorrelationResult& result)
        {
            std::ostringstream signature;
            signature << result.attempted << '|'
                      << result.success << '|'
                      << static_cast<std::uint32_t>(result.status) << '|'
                      << result.summary.preparedCorrelationCount << '|'
                      << result.summary.activatedCorrelationCount << '|'
                      << result.summary.contributingCorrelationCount << '|'
                      << result.summary.unresolvedCorrelationCount << '|'
                      << result.summary.duplicateCorrelationCount;
            for (const ObservationCorrelation& correlation : result.correlations)
            {
                signature << "|c:" << correlation.id << ':'
                          << correlation.ruleId << ':'
                          << correlation.entityScope << ':'
                          << correlation.correlationKey << ':'
                          << static_cast<std::uint32_t>(correlation.significance)
                          << ':'
                          << static_cast<std::uint32_t>(correlation.confidence)
                          << ':' << correlation.contributesToVerdict;
                for (const std::string& id :
                     correlation.participatingObservationIds)
                {
                    signature << ":p" << id;
                }
                for (EvidenceDomain domain : correlation.participatingDomains)
                {
                    signature << ":d"
                              << static_cast<std::uint32_t>(domain);
                }
                for (const std::string& id :
                     correlation.supportingObservationIds)
                {
                    signature << ":s" << id;
                }
                for (const std::string& limitation : correlation.limitations)
                {
                    signature << ":l" << limitation;
                }
            }
            for (const ObservationCorrelationPreparation& unresolved :
                 result.unresolvedPreparations)
            {
                signature << "|u:" << unresolved.entityScope << ':'
                          << unresolved.correlationKey;
            }
            return signature.str();
        }

        ObservationRecord MakeEncodedCommand(
            std::string id = "encoded-command",
            ObservationStrength strength = ObservationStrength::Moderate,
            ObservationConfidence confidence = ObservationConfidence::High)
        {
            return MakeNativeRecord(
                std::move(id),
                "baseline.command.encoded-switch",
                EvidenceDomain::CommandLine,
                ObservationDisposition::ReviewRelevant,
                strength,
                confidence,
                "encoded-command-context",
                "command-relationship-context");
        }

        ObservationRecord MakeTypedRelationship(
            std::string id = "typed-relationship",
            ObservationStrength strength = ObservationStrength::Moderate,
            ObservationConfidence confidence = ObservationConfidence::High)
        {
            return MakeNativeRecord(
                std::move(id),
                "baseline.relationship.typed-context",
                EvidenceDomain::ProcessRelationship,
                ObservationDisposition::CorrelatedOnly,
                strength,
                confidence,
                "process-family-relationship",
                "command-relationship-context");
        }

        ObservationRecord MakeInvalidSignature(
            std::string id = "invalid-signature",
            ObservationStrength strength = ObservationStrength::Moderate,
            ObservationConfidence confidence = ObservationConfidence::High)
        {
            return MakeNativeRecord(
                std::move(id),
                "baseline.file.signature-invalid",
                EvidenceDomain::FileSignature,
                ObservationDisposition::ReviewRelevant,
                strength,
                confidence,
                "file-signature-status");
        }

        ObservationRecord MakeExactIndicator(
            std::string id = "exact-network-indicator",
            ObservationStrength strength = ObservationStrength::Moderate,
            ObservationConfidence confidence = ObservationConfidence::High)
        {
            return MakeNativeRecord(
                std::move(id),
                "baseline.network.indicator-exact-match",
                EvidenceDomain::Network,
                ObservationDisposition::ReviewRelevant,
                strength,
                confidence,
                "network-indicator-match",
                "network-intelligence-context");
        }

        ObservationRecord MakeSensitiveHandle(
            std::string id,
            std::string correlationKey = "sensitive-handle-context",
            std::string artifactKey = "handle:40:target:200")
        {
            return MakeArtifactRecord(
                std::move(id),
                "native.handle.external-process-sensitive-access",
                EvidenceDomain::Handle,
                ObservationDisposition::ReviewRelevant,
                ObservationStrength::Moderate,
                ObservationConfidence::High,
                ObservationArtifactKind::Handle,
                std::move(artifactKey),
                "handle.access.vm-write",
                "external-process-sensitive-access",
                std::move(correlationKey));
        }

        void TestStatusAndUnresolvedConditions()
        {
            ObservationRefinementResult unavailable;
            const ObservationCorrelationResult failed =
                ActivateObservationCorrelations(unavailable);
            Check(failed.attempted, L"unavailable refinement activation attempted");
            Check(!failed.success, L"unavailable refinement activation fails");
            CheckEqual(
                failed.status,
                ObservationCorrelationStatus::RefinementUnavailable,
                L"unavailable refinement status");
            Check(
                failed.correlations.empty(),
                L"unavailable refinement has no partial correlations");

            const ObservationCorrelationResult indicatorOnly =
                ActivateObservationCorrelations(RefineNative({
                    MakeExactIndicator()
                }));
            Check(indicatorOnly.Succeeded(), L"indicator-only activation succeeds diagnostically");
            Check(indicatorOnly.correlations.empty(), L"indicator-only evidence does not complete a correlation");
            CheckEqual(
                indicatorOnly.unresolvedPreparations.size(),
                std::size_t(1),
                L"indicator-only preparation remains unresolved");

            ObservationRecord relationship = MakeTypedRelationship();
            relationship.observation.correlationKey.clear();
            const ObservationCorrelationResult incoherent =
                ActivateObservationCorrelations(RefineNative({
                    MakeEncodedCommand(),
                    relationship
                }));
            Check(
                incoherent.correlations.empty(),
                L"independent domains without one coherent typed relationship do not correlate");
            CheckEqual(
                incoherent.unresolvedPreparations.size(),
                std::size_t(1),
                L"incoherent preparation remains visible as unresolved");
        }

        void TestCommandRelationshipCorrelation()
        {
            ObservationRecord command = MakeEncodedCommand();
            command.observation.limitations.push_back(
                "Command evidence is bounded to the captured invocation.");
            ObservationRecord relationship = MakeTypedRelationship();
            relationship.observation.provenance.limitations.push_back(
                "Relationship evidence reflects the captured process graph.");

            const ObservationCorrelationResult result =
                ActivateObservationCorrelations(RefineNative({
                    command,
                    relationship
                }));
            const ObservationCorrelation* correlation = FindCorrelation(
                result,
                "correlation.execution.encoded-command-relationship");
            Check(correlation != nullptr, L"native command and relationship activate");
            if (correlation != nullptr)
            {
                CheckEqual(
                    correlation->participatingObservationIds.size(),
                    std::size_t(2),
                    L"execution participant count");
                Check(
                    correlation->participatingDomains.count(
                        EvidenceDomain::CommandLine) == 1,
                    L"execution retains command domain");
                Check(
                    correlation->participatingDomains.count(
                        EvidenceDomain::ProcessRelationship) == 1,
                    L"execution retains relationship domain");
                CheckEqual(
                    correlation->significance,
                    CorrelationSignificance::Moderate,
                    L"default execution significance is moderate");
                CheckEqual(
                    correlation->confidence,
                    ObservationConfidence::High,
                    L"execution confidence uses participant minimum");
                Check(
                    std::find(
                        correlation->limitations.begin(),
                        correlation->limitations.end(),
                        "Command evidence is bounded to the captured invocation.") !=
                            correlation->limitations.end(),
                    L"observation limitation propagates");
                Check(
                    std::find(
                        correlation->limitations.begin(),
                        correlation->limitations.end(),
                        "Relationship evidence reflects the captured process graph.") !=
                            correlation->limitations.end(),
                    L"provenance limitation propagates");
            }

            const ObservationCorrelationResult strong =
                ActivateObservationCorrelations(RefineNative({
                    MakeEncodedCommand(
                        "strong-command",
                        ObservationStrength::Strong,
                        ObservationConfidence::High),
                    MakeTypedRelationship(
                        "strong-relationship",
                        ObservationStrength::Strong,
                        ObservationConfidence::High)
                }));
            const ObservationCorrelation* strongCorrelation = FindCorrelation(
                strong,
                "correlation.execution.encoded-command-relationship");
            Check(strongCorrelation != nullptr, L"strong native execution correlation activates");
            if (strongCorrelation != nullptr)
            {
                CheckEqual(
                    strongCorrelation->significance,
                    CorrelationSignificance::Strong,
                    L"strong direct inputs retain strong correlation significance");
            }
        }

        void TestPathAndInvalidSignatureCorrelation()
        {
            ObservationRecord path = MakeNativeRecord(
                "user-writable-path",
                "baseline.file.user-path-context",
                EvidenceDomain::FilePath,
                ObservationDisposition::Context,
                ObservationStrength::Weak,
                ObservationConfidence::High,
                "executable-path-context",
                "file-path-signature-context");

            const ObservationCorrelationResult pathOnly =
                ActivateObservationCorrelations(RefineNative({ path }));
            Check(pathOnly.correlations.empty(), L"path context alone does not correlate");
            CheckEqual(
                pathOnly.unresolvedPreparations.size(),
                std::size_t(1),
                L"path-only preparation is unresolved");

            const ObservationCorrelationResult result =
                ActivateObservationCorrelations(RefineNative({
                    path,
                    MakeInvalidSignature()
                }));
            const ObservationCorrelation* correlation = FindCorrelation(
                result,
                "correlation.file.user-path-invalid-signature");
            Check(correlation != nullptr, L"native path and invalid signature activate");
            if (correlation != nullptr)
            {
                CheckEqual(
                    correlation->significance,
                    CorrelationSignificance::Moderate,
                    L"path-signature significance is moderate");
                CheckEqual(
                    correlation->participatingDomains.size(),
                    std::size_t(2),
                    L"path-signature uses two independent domains");
                Check(
                    correlation->participatingDomains.count(
                        EvidenceDomain::FilePath) == 1 &&
                    correlation->participatingDomains.count(
                        EvidenceDomain::FileSignature) == 1,
                    L"path-signature retains exact domains");
            }
        }

        void TestExactIndicatorCeilingAndReinforcement()
        {
            ObservationRecord secondIndicator = MakeExactIndicator(
                "second-exact-network-indicator");
            secondIndicator.observation.groupingKey =
                "second-network-indicator-match";
            const ObservationCorrelationResult sameDomain =
                ActivateObservationCorrelations(RefineNative({
                    MakeExactIndicator(),
                    secondIndicator
                }));
            Check(
                sameDomain.correlations.empty(),
                L"multiple exact indicators in one domain do not reinforce each other");
            CheckEqual(
                sameDomain.unresolvedPreparations.size(),
                std::size_t(1),
                L"same-domain exact indicators retain one unresolved preparation");

            const ObservationCorrelationResult defaultReinforcement =
                ActivateObservationCorrelations(RefineNative({
                    MakeExactIndicator(),
                    MakeInvalidSignature()
                }));
            const ObservationCorrelation* moderate = FindCorrelation(
                defaultReinforcement,
                "correlation.network.exact-indicator-local-evidence");
            Check(moderate != nullptr, L"exact indicator accepts independent local evidence");
            if (moderate != nullptr)
            {
                CheckEqual(
                    moderate->significance,
                    CorrelationSignificance::Moderate,
                    L"ordinary exact-indicator correlation remains moderate");
                CheckEqual(
                    moderate->participatingDomains.size(),
                    std::size_t(2),
                    L"exact-indicator correlation retains independent domains");
            }

            ObservationRecord assessedIndicator = MakeExactIndicator(
                "assessed-exact-indicator",
                ObservationStrength::Strong,
                ObservationConfidence::High);
            assessedIndicator.source.assessmentRationale =
                "The imported exact match retained a specific bounded assessment.";
            const ObservationCorrelationResult explicitStrong =
                ActivateObservationCorrelations(RefineNative({
                    assessedIndicator,
                    MakeInvalidSignature(
                        "strong-local-signature",
                        ObservationStrength::Strong,
                        ObservationConfidence::High)
                }));
            const ObservationCorrelation* strong = FindCorrelation(
                explicitStrong,
                "correlation.network.exact-indicator-local-evidence");
            Check(strong != nullptr, L"assessed exact indicator correlation activates");
            if (strong != nullptr)
            {
                CheckEqual(
                    strong->significance,
                    CorrelationSignificance::Strong,
                    L"strong significance requires explicit assessment and reinforced confidence");
            }
        }

        void TestSensitiveHandleCorrelations()
        {
            ObservationRecord command = MakeEncodedCommand("handle-command");
            command.observation.correlationKey.clear();
            const ObservationCorrelationResult commandResult =
                ActivateObservationCorrelations(RefineNative({
                    MakeSensitiveHandle("sensitive-handle-command"),
                    command
                }));
            const ObservationCorrelation* handleCommand = FindCorrelation(
                commandResult,
                "correlation.handle.sensitive-access-local-evidence");
            Check(handleCommand != nullptr, L"sensitive handle and native command activate");
            if (handleCommand != nullptr)
            {
                CheckEqual(
                    handleCommand->participatingDomains.size(),
                    std::size_t(2),
                    L"handle-command correlation has two domains");
                CheckEqual(
                    handleCommand->significance,
                    CorrelationSignificance::Moderate,
                    L"sensitive handle correlation remains moderate");
            }

            ObservationRecord token = MakeNativeRecord(
                "debug-privilege-enabled",
                "native.token.privilege.debug-enabled",
                EvidenceDomain::Token,
                ObservationDisposition::CorrelatedOnly,
                ObservationStrength::Moderate,
                ObservationConfidence::High,
                "selected-token-privilege",
                "sensitive-access-debug-privilege");
            const ObservationCorrelationResult tokenResult =
                ActivateObservationCorrelations(RefineNative({
                    token,
                    MakeSensitiveHandle(
                        "sensitive-handle-token",
                        {},
                        "handle:44:target:204")
                }));
            const ObservationCorrelation* handleToken = FindCorrelation(
                tokenResult,
                "correlation.access.enabled-debug-privilege");
            Check(handleToken != nullptr, L"sensitive handle and enabled debug privilege activate");
            if (handleToken != nullptr)
            {
                CheckEqual(
                    handleToken->participatingDomains.size(),
                    std::size_t(2),
                    L"handle-token correlation has independent domains");
                Check(
                    ContainsId(
                        handleToken->participatingObservationIds,
                        "debug-privilege-enabled"),
                    L"handle-token correlation retains token participant");
                Check(
                    ContainsId(
                        handleToken->participatingObservationIds,
                        "sensitive-handle-token"),
                    L"handle-token correlation retains handle participant");
            }
        }

        void TestStaticMemoryAndArtifactNonReinforcement()
        {
            const std::string regionKey =
                "memory-region:1000:1000:4096";
            const ObservationRefinementResult memory = RefineNative({
                MakeArtifactRecord(
                    "memory-writable-executable",
                    "native.memory.static-region-context",
                    EvidenceDomain::MemoryMetadata,
                    ObservationDisposition::Context,
                    ObservationStrength::Weak,
                    ObservationConfidence::High,
                    ObservationArtifactKind::MemoryRegion,
                    regionKey,
                    "memory.writable-executable",
                    "memory-protection"),
                MakeArtifactRecord(
                    "memory-private-executable",
                    "native.memory.static-region-context",
                    EvidenceDomain::MemoryMetadata,
                    ObservationDisposition::Context,
                    ObservationStrength::Weak,
                    ObservationConfidence::High,
                    ObservationArtifactKind::MemoryRegion,
                    regionKey,
                    "memory.private-executable",
                    "memory-type"),
                MakeArtifactRecord(
                    "memory-unbacked-executable",
                    "native.memory.static-region-context",
                    EvidenceDomain::MemoryMetadata,
                    ObservationDisposition::Context,
                    ObservationStrength::Weak,
                    ObservationConfidence::High,
                    ObservationArtifactKind::MemoryRegion,
                    regionKey,
                    "memory.unbacked-executable",
                    "memory-backing")
            });
            Check(memory.Succeeded(), L"static memory refinement succeeds");
            CheckEqual(memory.groups.size(), std::size_t(1), L"same memory artifact forms one evidence group");
            CheckEqual(
                CountRole(memory, RefinedObservationRole::ArtifactAttribute),
                std::size_t(2),
                L"additional memory properties are artifact attributes");
            CheckEqual(
                memory.summary.contributingDomainCountAfter,
                std::size_t(0),
                L"static memory contributes no verdict domain");
            const ObservationCorrelationResult memoryResult =
                ActivateObservationCorrelations(memory);
            Check(memoryResult.Succeeded(), L"static memory correlation pass succeeds");
            Check(memoryResult.correlations.empty(), L"static memory activates no correlation");
            Check(memoryResult.unresolvedPreparations.empty(), L"static memory creates no correlation preparation");

            ObservationRecord firstHandle = MakeSensitiveHandle(
                "handle-vm-write",
                "sensitive-handle-context",
                "handle:48:target:208");
            ObservationRecord secondHandle = MakeArtifactRecord(
                "handle-vm-operation",
                "native.handle.external-process-sensitive-access",
                EvidenceDomain::Handle,
                ObservationDisposition::ReviewRelevant,
                ObservationStrength::Moderate,
                ObservationConfidence::High,
                ObservationArtifactKind::Handle,
                "handle:48:target:208",
                "handle.access.vm-operation",
                "external-process-sensitive-access",
                "sensitive-handle-context");
            ObservationRecord local = MakeInvalidSignature(
                "artifact-local-signature");
            const ObservationRefinementResult oneHandle = RefineNative({
                firstHandle,
                secondHandle,
                local
            });
            CheckEqual(oneHandle.groups.size(), std::size_t(2), L"one handle and one signature form two groups");
            CheckEqual(
                CountRole(oneHandle, RefinedObservationRole::ArtifactAttribute),
                std::size_t(1),
                L"multiple rights on one handle remain one artifact evidence unit");
            const ObservationCorrelationResult oneHandleResult =
                ActivateObservationCorrelations(oneHandle);
            const ObservationCorrelation* correlation = FindCorrelation(
                oneHandleResult,
                "correlation.handle.sensitive-access-local-evidence");
            Check(correlation != nullptr, L"one handle artifact can correlate with an independent domain");
            if (correlation != nullptr)
            {
                const std::size_t handleParticipants =
                    static_cast<std::size_t>(std::count_if(
                        correlation->participatingObservationIds.begin(),
                        correlation->participatingObservationIds.end(),
                        [](const std::string& id)
                        {
                            return id == "handle-vm-write" ||
                                id == "handle-vm-operation";
                        }));
                CheckEqual(
                    handleParticipants,
                    std::size_t(1),
                    L"one handle cannot corroborate itself through multiple rights");
                Check(
                    !ContainsId(
                        correlation->supportingObservationIds,
                        correlation->participatingObservationIds.front() ==
                                "handle-vm-write"
                            ? "handle-vm-operation"
                            : "handle-vm-write"),
                    L"artifact attribute is not retained as reinforcing support");
            }

            const ObservationCorrelationResult handlesOnly =
                ActivateObservationCorrelations(RefineNative({
                    MakeSensitiveHandle(
                        "first-distinct-handle",
                        "sensitive-handle-context",
                        "handle:52:target:212"),
                    MakeSensitiveHandle(
                        "second-distinct-handle",
                        "sensitive-handle-context",
                        "handle:56:target:216")
                }));
            Check(
                handlesOnly.correlations.empty(),
                L"multiple same-domain handle artifacts do not satisfy independent-domain gates");
            CheckEqual(
                handlesOnly.unresolvedPreparations.size(),
                std::size_t(1),
                L"same-domain handle preparation remains unresolved");
        }

        void TestDeterminismDeduplicationAndCaps()
        {
            ObservationRefinementResult repeatedPreparation = RefineNative({
                MakeEncodedCommand(),
                MakeTypedRelationship()
            });
            Check(!repeatedPreparation.correlations.empty(), L"deduplication fixture has preparation");
            if (!repeatedPreparation.correlations.empty())
            {
                repeatedPreparation.correlations.push_back(
                    repeatedPreparation.correlations.front());
            }
            const ObservationCorrelationResult deduplicated =
                ActivateObservationCorrelations(repeatedPreparation);
            CheckEqual(
                deduplicated.correlations.size(),
                std::size_t(1),
                L"duplicate native correlation output is emitted once");
            CheckEqual(
                deduplicated.summary.duplicateCorrelationCount,
                std::size_t(1),
                L"duplicate native correlation output is counted");

            ObservationRecord path = MakeNativeRecord(
                "deterministic-path",
                "baseline.file.user-path-context",
                EvidenceDomain::FilePath,
                ObservationDisposition::Context,
                ObservationStrength::Weak,
                ObservationConfidence::High,
                "deterministic-path-group",
                "file-path-signature-context");
            const ObservationRefinementResult deterministicInput = RefineNative({
                MakeEncodedCommand(),
                MakeTypedRelationship(),
                path,
                MakeInvalidSignature("deterministic-signature"),
                MakeExactIndicator("deterministic-indicator")
            });
            const ObservationCorrelationResult first =
                ActivateObservationCorrelations(deterministicInput);
            const ObservationCorrelationResult second =
                ActivateObservationCorrelations(deterministicInput);
            CheckEqual(
                ResultSignature(first),
                ResultSignature(second),
                L"native correlation ordering is deterministic across repeated runs");

            ObservationRefinementResult invalid = deterministicInput;
            invalid.groups.front().entityScope.assign(
                ObservationEntityScopeMaxCharacters + 1,
                'x');
            const ObservationCorrelationResult invalidResult =
                ActivateObservationCorrelations(invalid);
            Check(!invalidResult.success, L"invalid refinement fails correlation activation");
            CheckEqual(
                invalidResult.status,
                ObservationCorrelationStatus::InvalidRefinement,
                L"invalid refinement failure status");
            Check(
                invalidResult.correlations.empty(),
                L"invalid refinement failure is atomic");

            ObservationRefinementResult excessRequirements = RefineNative({
                MakeEncodedCommand(),
                MakeTypedRelationship()
            });
            Check(!excessRequirements.correlations.empty(), L"requirements-cap fixture has preparation");
            if (!excessRequirements.correlations.empty())
            {
                excessRequirements.correlations.front().requirements.resize(
                    ObservationCorrelationMaxRequirementsPerPreparation + 1);
                const ObservationCorrelationResult requirementsFailure =
                    ActivateObservationCorrelations(excessRequirements);
                Check(!requirementsFailure.success, L"over-cap requirements fail atomically");
                CheckEqual(
                    requirementsFailure.status,
                    ObservationCorrelationStatus::InvalidRefinement,
                    L"over-cap requirements failure status");
                Check(
                    requirementsFailure.correlations.empty(),
                    L"over-cap requirements return no partial correlations");
            }

            std::vector<ObservationRecord> overCapRecords;
            for (std::size_t index = 0;
                 index < ObservationCorrelationMaxSupportingPerResult + 2;
                 ++index)
            {
                ObservationRecord command = MakeEncodedCommand(
                    "support-command-" + std::to_string(index));
                command.observation.groupingKey =
                    "support-command-group-" + std::to_string(index);
                overCapRecords.push_back(std::move(command));
            }
            overCapRecords.push_back(MakeTypedRelationship(
                "support-relationship"));
            const ObservationCorrelationResult overCap =
                ActivateObservationCorrelations(
                    RefineNative(std::move(overCapRecords)));
            Check(!overCap.success, L"supporting reference cap fails correlation atomically");
            CheckEqual(
                overCap.status,
                ObservationCorrelationStatus::SupportingLimitExceeded,
                L"supporting reference cap status");
            Check(
                overCap.correlations.empty(),
                L"supporting reference cap returns no partial correlations");
        }
    }

    int RunObservationCorrelationTests()
    {
        TestStatusAndUnresolvedConditions();
        TestCommandRelationshipCorrelation();
        TestPathAndInvalidSignatureCorrelation();
        TestExactIndicatorCeilingAndReinforcement();
        TestSensitiveHandleCorrelations();
        TestStaticMemoryAndArtifactNonReinforcement();
        TestDeterminismDeduplicationAndCaps();

        return failureCount;
    }
}
