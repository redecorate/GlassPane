#include "Core/TriageEngine.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace GlassPane::Tests
{
    namespace
    {
        using namespace Core;

        int failureCount = 0;
        constexpr const char* EntityScope = "process:generic-entity";

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

        ObservationRecord MakeRecord(
            std::string id,
            EvidenceDomain domain,
            ObservationDisposition disposition,
            ObservationStrength strength,
            ObservationConfidence confidence = ObservationConfidence::High,
            ObservationSourceKind sourceKind = ObservationSourceKind::Direct,
            std::string entityScope = EntityScope,
            ObservationArtifactKind artifactKind =
                ObservationArtifactKind::None,
            std::string artifactKey = {},
            std::vector<ObservationArtifactAttribute> artifactAttributes = {})
        {
            ObservationRecord record;
            record.source.sourceRecordId = "source:" + id;
            record.source.sourceRuleId = "generic.source.rule";
            record.source.mappingRuleId = "generic.typed.mapping";
            record.source.sourceTitle = "Legacy source metadata";
            record.source.sourceMessage = "Legacy source message.";
            record.source.producerIdentifier = "generic-fixed-producer";

            Observation& observation = record.observation;
            observation.id = std::move(id);
            observation.ruleId = "generic.observation.rule";
            observation.title = "Generic typed observation";
            observation.summary = "Generic typed observation summary.";
            observation.domain = domain;
            observation.sourceKind = sourceKind;
            observation.disposition = disposition;
            observation.strength = strength;
            observation.confidence = confidence;
            observation.contributesToVerdict =
                disposition == ObservationDisposition::ReviewRelevant &&
                strength != ObservationStrength::None &&
                domain != EvidenceDomain::Unknown &&
                domain != EvidenceDomain::CollectionQuality &&
                domain != EvidenceDomain::EvidenceIntegrity;
            observation.entityScope = std::move(entityScope);
            observation.groupingKey = "generic-semantic-family";
            observation.provenance.sourceKind = sourceKind;
            observation.provenance.sourceIdentifier = "generic-fixed-producer";
            observation.provenance.collectionMethod = "fixed-test-input";
            observation.provenance.sourceAvailable =
                sourceKind != ObservationSourceKind::Unavailable;
            if (artifactKind != ObservationArtifactKind::None)
            {
                observation.artifactIdentity.kind = artifactKind;
                observation.artifactIdentity.entityScope =
                    observation.entityScope;
                observation.artifactIdentity.artifactKey =
                    std::move(artifactKey);
                observation.artifactAttributes =
                    std::move(artifactAttributes);
            }
            return record;
        }

        std::vector<ObservationArtifactAttribute> ExecutableMemoryAttributes()
        {
            return {
                { ObservationArtifactAttributeMemoryWritable, "true" },
                { ObservationArtifactAttributeMemoryExecutable, "true" },
                { ObservationArtifactAttributeMemoryPrivate, "true" },
                { ObservationArtifactAttributeMemoryImageBacked, "false" },
                { ObservationArtifactAttributeMemoryMappedFileBacked, "false" },
                { ObservationArtifactAttributeMemoryGuarded, "true" }
            };
        }

        ObservationRecord MakeMemoryRecord(
            std::string id,
            ObservationDisposition disposition,
            ObservationStrength strength,
            std::string artifactKey =
                "memory-region:0000000010000000:0000000010000000:0000000000004000")
        {
            return MakeRecord(
                std::move(id),
                EvidenceDomain::MemoryMetadata,
                disposition,
                strength,
                ObservationConfidence::High,
                ObservationSourceKind::Direct,
                EntityScope,
                ObservationArtifactKind::MemoryRegion,
                std::move(artifactKey),
                ExecutableMemoryAttributes());
        }

        ObservationRecord MakeContext(
            std::string id,
            EvidenceDomain domain)
        {
            return MakeRecord(
                std::move(id),
                domain,
                ObservationDisposition::Context,
                ObservationStrength::Weak);
        }

        ObservationRecord MakeCollectionNote(std::string id)
        {
            return MakeRecord(
                std::move(id),
                EvidenceDomain::CollectionQuality,
                ObservationDisposition::CollectionNote,
                ObservationStrength::None);
        }

        ObservationRecord MakeIntegrityNote(std::string id)
        {
            return MakeRecord(
                std::move(id),
                EvidenceDomain::EvidenceIntegrity,
                ObservationDisposition::EvidenceIntegrityNote,
                ObservationStrength::None);
        }

        ObservationRefinementResult MakeRefinement(
            std::vector<ObservationRecord> records,
            std::vector<ObservationRecord> collectionNotes = {},
            std::vector<ObservationRecord> integrityNotes = {})
        {
            ObservationRefinementResult result;
            result.attempted = true;
            result.success = true;
            result.status = ObservationRefinementStatus::Success;
            result.summary.rawObservationCount =
                records.size() + collectionNotes.size() + integrityNotes.size();
            result.summary.behavioralContextObservationCount = records.size();
            result.summary.collectionNoteCount = collectionNotes.size();
            result.summary.evidenceIntegrityNoteCount = integrityNotes.size();
            result.collectionNotes = std::move(collectionNotes);
            result.evidenceIntegrityNotes = std::move(integrityNotes);

            for (ObservationRecord& record : records)
            {
                if (HasObservationArtifactIdentity(record.observation))
                {
                    const auto existing = std::find_if(
                        result.groups.begin(),
                        result.groups.end(),
                        [&](const RefinedObservationGroup& group)
                        {
                            return group.domain == record.observation.domain &&
                                group.artifactIdentity.kind ==
                                    record.observation.artifactIdentity.kind &&
                                group.artifactIdentity.entityScope ==
                                    record.observation.artifactIdentity.entityScope &&
                                group.artifactIdentity.artifactKey ==
                                    record.observation.artifactIdentity.artifactKey;
                        });
                    if (existing != result.groups.end())
                    {
                        RefinedObservationMember member;
                        member.sourceRecord = std::move(record);
                        member.role = RefinedObservationRole::ArtifactAttribute;
                        member.primaryObservationId =
                            existing->members.front().sourceRecord.observation.id;
                        existing->members.push_back(std::move(member));
                        ++existing->artifactAttributeCount;
                        ++result.summary.artifactAttributeCount;
                        continue;
                    }
                }
                RefinedObservationGroup group;
                group.entityScope = record.observation.entityScope;
                group.groupingKey = record.observation.groupingKey;
                group.semanticFamily = record.observation.groupingKey;
                group.domain = record.observation.domain;
                group.artifactIdentity = record.observation.artifactIdentity;
                RefinedObservationMember member;
                member.sourceRecord = std::move(record);
                member.primaryObservationId = member.sourceRecord.observation.id;
                group.members.push_back(std::move(member));
                if (HasCompleteObservationArtifactIdentity(
                        group.artifactIdentity))
                {
                    group.artifactAttributeCount = 1;
                    ++result.summary.artifactGroupCount;
                    ++result.summary.distinctArtifactCount;
                    ++result.summary.artifactAttributeCount;
                }
                result.groups.push_back(std::move(group));
            }
            result.summary.groupCount = result.groups.size();
            return result;
        }

        ObservationCorrelationResult MakeCorrelations(
            std::vector<ObservationCorrelation> values = {},
            std::vector<ObservationCorrelationPreparation> unresolved = {})
        {
            ObservationCorrelationResult result;
            result.attempted = true;
            result.success = true;
            result.status = ObservationCorrelationStatus::Success;
            result.correlations = std::move(values);
            result.unresolvedPreparations = std::move(unresolved);
            result.summary.activatedCorrelationCount = result.correlations.size();
            result.summary.unresolvedCorrelationCount =
                result.unresolvedPreparations.size();
            return result;
        }

        ObservationCorrelation MakeCorrelation(
            std::string id,
            CorrelationSignificance significance,
            std::vector<std::string> participantIds,
            std::set<EvidenceDomain> domains,
            ObservationConfidence confidence = ObservationConfidence::High)
        {
            ObservationCorrelation correlation;
            correlation.id = std::move(id);
            correlation.ruleId = "generic.correlation.rule";
            correlation.entityScope = EntityScope;
            correlation.correlationKey = "generic-correlation-key";
            correlation.title = "Generic typed correlation";
            correlation.rationale =
                "Required typed facts are present; repetition was not used.";
            correlation.significance = significance;
            correlation.confidence = confidence;
            correlation.participatingObservationIds = std::move(participantIds);
            correlation.participatingDomains = std::move(domains);
            correlation.contributesToVerdict =
                significance != CorrelationSignificance::Informational;
            return correlation;
        }

        TriageResult Evaluate(
            ObservationRefinementResult refinement,
            ObservationCorrelationResult correlations = MakeCorrelations())
        {
            return BuildTriageResult(refinement, correlations);
        }

        std::string DeterministicSignature(const TriageResult& result)
        {
            std::ostringstream stream;
            stream << result.attempted << '|'
                   << result.success << '|'
                   << static_cast<std::uint32_t>(result.status) << '|'
                   << static_cast<std::uint32_t>(result.verdict) << '|'
                   << result.maximumContributingCorrelationDomainCount << '|'
                   << result.sameDomainContributingCorrelationCount << '|'
                   << result.sameDomainVerdictCeilingApplied << '|'
                   << result.qualifiedStandaloneStrongHighGateSatisfied << '|'
                   << result.coherentMultiDomainHighGateSatisfied << '|'
                   << result.rationaleTruncated << '|'
                   << result.previewRationaleTruncated << '|'
                   << result.limitationsTruncated << '|'
                   << result.statusMessage;
            const auto add = [&](const char* prefix, const auto& values)
            {
                for (const auto& value : values)
                {
                    stream << '|' << prefix << ':' << value;
                }
            };
            add("o", result.contributingObservationIds);
            add("c", result.contributingCorrelationIds);
            for (EvidenceDomain domain : result.contributingDomains)
            {
                stream << "|d:" << static_cast<std::uint32_t>(domain);
            }
            add("x", result.contextObservationIds);
            add("n", result.collectionNoteIds);
            add("i", result.evidenceIntegrityNoteIds);
            add("u", result.unresolvedCorrelationKeys);
            add("r", result.rationale);
            for (const TriageRationaleEntry& entry : result.rationaleEntries)
            {
                stream << "|rs:"
                       << static_cast<std::uint32_t>(entry.section)
                       << ':' << entry.text;
            }
            for (const TriageRationaleEntry& entry :
                 result.previewRationaleEntries)
            {
                stream << "|pr:"
                       << static_cast<std::uint32_t>(entry.section)
                       << ':' << entry.text;
            }
            add("l", result.limitations);
            return stream.str();
        }

        bool HasTextContaining(
            const std::vector<std::string>& values,
            const std::string& text)
        {
            return std::any_of(
                values.begin(),
                values.end(),
                [&](const std::string& value)
                {
                    return value.find(text) != std::string::npos;
                });
        }

        bool PreviewHasTextContaining(
            const TriageResult& result,
            const std::string& text)
        {
            return std::any_of(
                result.previewRationaleEntries.begin(),
                result.previewRationaleEntries.end(),
                [&](const TriageRationaleEntry& entry)
                {
                    return entry.text.find(text) != std::string::npos;
                });
        }

        void TestInformationalAndLowFixtures()
        {
            const TriageResult collectionOnly = Evaluate(MakeRefinement(
                {},
                { MakeCollectionNote("collection-token"),
                  MakeCollectionNote("collection-modules") }));
            Check(collectionOnly.Succeeded(), L"collection-only triage succeeds");
            CheckEqual(collectionOnly.verdict, TriageVerdict::Informational, L"collection notes only informational");
            Check(collectionOnly.contributingDomains.empty(), L"collection notes contribute no domains");
            CheckEqual(collectionOnly.collectionNoteIds.size(), std::size_t(2), L"collection notes retained");

            const TriageResult publicOnly = Evaluate(MakeRefinement({
                MakeContext("public-network-context", EvidenceDomain::Network)
            }));
            CheckEqual(publicOnly.verdict, TriageVerdict::Informational, L"public network context only informational");

            const TriageResult contextHeavy = Evaluate(MakeRefinement({
                MakeContext("token-handle", EvidenceDomain::Handle),
                MakeContext("runtime-count", EvidenceDomain::Runtime),
                MakeContext("single-core", EvidenceDomain::Runtime)
            }));
            CheckEqual(contextHeavy.verdict, TriageVerdict::Informational, L"generic context cluster informational");
            Check(contextHeavy.contributingObservationIds.empty(), L"context cluster has no contributing observations");

            const TriageResult unresolvedCorrelatedOnly = Evaluate(MakeRefinement({
                MakeRecord(
                    "correlated-only-handle",
                    EvidenceDomain::Handle,
                    ObservationDisposition::CorrelatedOnly,
                    ObservationStrength::Strong)
            }));
            CheckEqual(unresolvedCorrelatedOnly.verdict, TriageVerdict::Informational, L"CorrelatedOnly remains inactive without a completed correlation");
            Check(unresolvedCorrelatedOnly.contributingObservationIds.empty(), L"inactive CorrelatedOnly is never a direct contributor");

            const TriageResult oneWeak = Evaluate(MakeRefinement({
                MakeRecord(
                    "weak-path",
                    EvidenceDomain::FilePath,
                    ObservationDisposition::ReviewRelevant,
                    ObservationStrength::Weak)
            }));
            CheckEqual(oneWeak.verdict, TriageVerdict::LowAttention, L"one weak review observation low attention");

            const TriageResult sameDomain = Evaluate(MakeRefinement({
                MakeRecord("weak-path-a", EvidenceDomain::FilePath, ObservationDisposition::ReviewRelevant, ObservationStrength::Weak),
                MakeRecord("weak-path-b", EvidenceDomain::FilePath, ObservationDisposition::ReviewRelevant, ObservationStrength::Weak)
            }));
            CheckEqual(sameDomain.verdict, TriageVerdict::LowAttention, L"same-domain weak repetition remains low");
            CheckEqual(sameDomain.contributingDomains.size(), std::size_t(1), L"same-domain weak repetition counts once");
        }

        void TestMediumFixtures()
        {
            const TriageResult invalidSignature = Evaluate(MakeRefinement({
                MakeRecord("invalid-signature", EvidenceDomain::FileSignature, ObservationDisposition::ReviewRelevant, ObservationStrength::Moderate)
            }));
            CheckEqual(invalidSignature.verdict, TriageVerdict::MediumAttention, L"invalid signature alone medium at most");

            const TriageResult independentWeak = Evaluate(MakeRefinement({
                MakeRecord("weak-path", EvidenceDomain::FilePath, ObservationDisposition::ReviewRelevant, ObservationStrength::Weak),
                MakeRecord("weak-command", EvidenceDomain::CommandLine, ObservationDisposition::ReviewRelevant, ObservationStrength::Weak)
            }));
            CheckEqual(independentWeak.verdict, TriageVerdict::MediumAttention, L"independent weak domains medium");

            const TriageResult exactIndicator = Evaluate(MakeRefinement({
                MakeRecord("exact-indicator", EvidenceDomain::Network, ObservationDisposition::ReviewRelevant, ObservationStrength::Moderate)
            }));
            CheckEqual(exactIndicator.verdict, TriageVerdict::MediumAttention, L"exact indicator default ceiling medium");

            ObservationCorrelation pathSignature = MakeCorrelation(
                "correlation-path-signature",
                CorrelationSignificance::Moderate,
                { "user-path", "invalid-signature" },
                { EvidenceDomain::FilePath, EvidenceDomain::FileSignature });
            const TriageResult pathAndSignature = Evaluate(
                MakeRefinement({
                    MakeContext("user-path", EvidenceDomain::FilePath),
                    MakeRecord("invalid-signature", EvidenceDomain::FileSignature, ObservationDisposition::ReviewRelevant, ObservationStrength::Moderate)
                }),
                MakeCorrelations({ pathSignature }));
            CheckEqual(pathAndSignature.verdict, TriageVerdict::MediumAttention, L"path context and invalid signature correlation remains medium");
            CheckEqual(pathAndSignature.contributingCorrelationIds.size(), std::size_t(1), L"path signature correlation retained");

            ObservationCorrelation commandChain = MakeCorrelation(
                "correlation-command-relationship",
                CorrelationSignificance::Moderate,
                { "encoded-command", "parent-relationship" },
                { EvidenceDomain::CommandLine, EvidenceDomain::ProcessRelationship });
            const TriageResult encodedChain = Evaluate(
                MakeRefinement({
                    MakeRecord("encoded-command", EvidenceDomain::CommandLine, ObservationDisposition::ReviewRelevant, ObservationStrength::Moderate),
                    MakeRecord("parent-relationship", EvidenceDomain::ProcessRelationship, ObservationDisposition::CorrelatedOnly, ObservationStrength::Moderate)
                }),
                MakeCorrelations({ commandChain }));
            CheckEqual(encodedChain.verdict, TriageVerdict::MediumAttention, L"encoded command relationship correlation medium");

            const TriageResult writableExecutable = Evaluate(MakeRefinement({
                MakeMemoryRecord(
                    "writable-executable",
                    ObservationDisposition::ReviewRelevant,
                    ObservationStrength::Weak)
            }));
            CheckEqual(writableExecutable.verdict, TriageVerdict::Informational, L"one RWX memory artifact is informational");
            Check(writableExecutable.contributingDomains.empty(), L"static RWX memory contributes no domain");

            const TriageResult privateExecutable = Evaluate(MakeRefinement({
                MakeMemoryRecord(
                    "private-executable",
                    ObservationDisposition::Context,
                    ObservationStrength::Weak)
            }));
            CheckEqual(privateExecutable.verdict, TriageVerdict::Informational, L"one private executable-memory context is informational");

            const TriageResult unbackedExecutable = Evaluate(MakeRefinement({
                MakeMemoryRecord(
                    "unbacked-executable",
                    ObservationDisposition::Context,
                    ObservationStrength::Weak)
            }));
            CheckEqual(unbackedExecutable.verdict, TriageVerdict::Informational, L"one unbacked executable-memory context is informational");

            const TriageResult notesAndModerate = Evaluate(MakeRefinement(
                { MakeRecord("moderate-handle", EvidenceDomain::Handle, ObservationDisposition::ReviewRelevant, ObservationStrength::Moderate) },
                { MakeCollectionNote("collection-note") }));
            CheckEqual(notesAndModerate.verdict, TriageVerdict::MediumAttention, L"collection note does not elevate moderate observation");
        }

        void TestHighRestrictionsAndCorrelations()
        {
            const TriageResult twoModerateDomains = Evaluate(MakeRefinement({
                MakeRecord("exact-indicator", EvidenceDomain::Network, ObservationDisposition::ReviewRelevant, ObservationStrength::Moderate),
                MakeRecord("invalid-signature", EvidenceDomain::FileSignature, ObservationDisposition::ReviewRelevant, ObservationStrength::Moderate)
            }));
            CheckEqual(twoModerateDomains.verdict, TriageVerdict::MediumAttention, L"unrelated moderate direct domains do not establish coherent high");

            const TriageResult moderateAndWeakDomains = Evaluate(MakeRefinement({
                MakeRecord("moderate-signature", EvidenceDomain::FileSignature, ObservationDisposition::ReviewRelevant, ObservationStrength::Moderate),
                MakeRecord("weak-command", EvidenceDomain::CommandLine, ObservationDisposition::ReviewRelevant, ObservationStrength::Weak)
            }));
            CheckEqual(moderateAndWeakDomains.verdict, TriageVerdict::MediumAttention, L"unrelated moderate plus weak domains do not establish coherent high");

            ObservationCorrelation coherentLocalCorrelation = MakeCorrelation(
                "correlation-coherent-local-evidence",
                CorrelationSignificance::Moderate,
                { "coherent-indicator", "coherent-signature" },
                { EvidenceDomain::Network, EvidenceDomain::FileSignature });
            const TriageResult coherentMultiDomain = Evaluate(
                MakeRefinement({
                    MakeRecord("coherent-indicator", EvidenceDomain::Network, ObservationDisposition::ReviewRelevant, ObservationStrength::Moderate),
                    MakeRecord("coherent-signature", EvidenceDomain::FileSignature, ObservationDisposition::ReviewRelevant, ObservationStrength::Weak)
                }),
                MakeCorrelations({ coherentLocalCorrelation }));
            CheckEqual(coherentMultiDomain.verdict, TriageVerdict::MediumAttention, L"Moderate plus Weak typed domains remain medium");
            Check(!coherentMultiDomain.coherentMultiDomainHighGateSatisfied, L"Weak participant domain does not satisfy coherent High gate");
            CheckEqual(coherentMultiDomain.maximumContributingCorrelationDomainCount, std::size_t(2), L"Moderate plus Weak correlation still reports two domains");

            ObservationCorrelation qualifiedCoherentCorrelation = MakeCorrelation(
                "correlation-qualified-coherent-local-evidence",
                CorrelationSignificance::Moderate,
                { "qualified-command", "qualified-relationship" },
                { EvidenceDomain::CommandLine, EvidenceDomain::ProcessRelationship });
            const TriageResult qualifiedCoherentMultiDomain = Evaluate(
                MakeRefinement({
                    MakeRecord("qualified-command", EvidenceDomain::CommandLine, ObservationDisposition::ReviewRelevant, ObservationStrength::Moderate),
                    MakeRecord("qualified-relationship", EvidenceDomain::ProcessRelationship, ObservationDisposition::ReviewRelevant, ObservationStrength::Moderate)
                }),
                MakeCorrelations({ qualifiedCoherentCorrelation }));
            CheckEqual(qualifiedCoherentMultiDomain.verdict, TriageVerdict::HighAttention, L"two Moderate direct domains with a typed correlation may reach high");
            Check(qualifiedCoherentMultiDomain.coherentMultiDomainHighGateSatisfied, L"qualified two-Moderate relation satisfies coherent High gate");

            ObservationCorrelation lowConfidenceCorrelation = MakeCorrelation(
                "correlation-low-confidence-cross-domain",
                CorrelationSignificance::Moderate,
                { "low-confidence-indicator", "low-confidence-signature" },
                { EvidenceDomain::Network, EvidenceDomain::FileSignature },
                ObservationConfidence::Low);
            const TriageResult lowConfidenceMultiDomain = Evaluate(
                MakeRefinement({
                    MakeRecord("low-confidence-indicator", EvidenceDomain::Network, ObservationDisposition::ReviewRelevant, ObservationStrength::Moderate),
                    MakeRecord("low-confidence-signature", EvidenceDomain::FileSignature, ObservationDisposition::ReviewRelevant, ObservationStrength::Moderate)
                }),
                MakeCorrelations({ lowConfidenceCorrelation }));
            CheckEqual(lowConfidenceMultiDomain.verdict, TriageVerdict::MediumAttention, L"low-confidence cross-domain correlation does not satisfy High gate");
            Check(!lowConfidenceMultiDomain.coherentMultiDomainHighGateSatisfied, L"low-confidence correlation reports unsatisfied coherent High gate");

            ObservationCorrelation genericSameDomain = MakeCorrelation(
                "correlation-generic-same-domain",
                CorrelationSignificance::Strong,
                { "handle-a", "handle-b" },
                { EvidenceDomain::Handle });
            const TriageResult genericSameDomainResult = Evaluate(
                MakeRefinement({
                    MakeRecord("handle-a", EvidenceDomain::Handle, ObservationDisposition::ReviewRelevant, ObservationStrength::Moderate),
                    MakeRecord("handle-b", EvidenceDomain::Handle, ObservationDisposition::ReviewRelevant, ObservationStrength::Moderate)
                }),
                MakeCorrelations({ genericSameDomain }));
            CheckEqual(genericSameDomainResult.verdict, TriageVerdict::MediumAttention, L"Strong same-domain correlation in any domain has medium ceiling");
            Check(genericSameDomainResult.sameDomainVerdictCeilingApplied, L"generic same-domain ceiling is domain-independent");

            const std::string memoryArtifactKey =
                "memory-region:0000000010000000:0000000010000000:0000000000004000";
            const TriageResult oneMemoryArtifact = Evaluate(MakeRefinement({
                MakeMemoryRecord("memory-rwx", ObservationDisposition::ReviewRelevant, ObservationStrength::Weak, memoryArtifactKey),
                MakeMemoryRecord("memory-private", ObservationDisposition::Context, ObservationStrength::Weak, memoryArtifactKey),
                MakeMemoryRecord("memory-unbacked", ObservationDisposition::Context, ObservationStrength::Weak, memoryArtifactKey)
            }));
            CheckEqual(oneMemoryArtifact.verdict, TriageVerdict::Informational, L"one executable private unbacked artifact is informational");
            Check(oneMemoryArtifact.contributingObservationIds.empty(), L"one static memory artifact contributes no observations");
            Check(oneMemoryArtifact.contributingDomains.empty(), L"one static memory artifact contributes no domain");
            Check(oneMemoryArtifact.contributingCorrelationIds.empty(), L"attributes of one memory artifact do not form a correlation");
            Check(PreviewHasTextContaining(oneMemoryArtifact, "Static memory-region metadata was observed across 1 memory-region artifact."), L"compact rationale describes one memory artifact");
            Check(PreviewHasTextContaining(oneMemoryArtifact, "Writable and executable memory was observed on 1 region."), L"compact rationale aggregates writable-executable attributes");
            Check(PreviewHasTextContaining(oneMemoryArtifact, "Private executable memory was observed on 1 region."), L"compact rationale aggregates private-executable attributes");
            Check(PreviewHasTextContaining(oneMemoryArtifact, "Executable memory without image or mapped-file backing was observed on 1 region."), L"compact rationale aggregates unbacked attributes");
            Check(PreviewHasTextContaining(oneMemoryArtifact, "Guard-page protection was observed on 1 region."), L"compact rationale aggregates guarded attributes");
            Check(PreviewHasTextContaining(oneMemoryArtifact, "static point-in-time region properties"), L"compact rationale explains static memory limits");
            Check(PreviewHasTextContaining(oneMemoryArtifact, "High Attention requirements were not satisfied."), L"compact rationale states unsatisfied High gate");
            for (const TriageRationaleEntry& entry :
                 oneMemoryArtifact.previewRationaleEntries)
            {
                Check(entry.text.find("memory-rwx") == std::string::npos, L"compact rationale hides observation IDs");
                Check(entry.text.find("correlation-") == std::string::npos, L"compact rationale hides correlation IDs");
                Check(entry.text.find(memoryArtifactKey) == std::string::npos, L"compact rationale hides artifact keys and addresses");
            }
            Check(HasTextContaining(oneMemoryArtifact.rationale, "memory-rwx"), L"deep rationale retains observation identity");

            ObservationRecord staleStrongMemory = MakeMemoryRecord(
                "stale-strong-memory",
                ObservationDisposition::ReviewRelevant,
                ObservationStrength::Strong,
                memoryArtifactKey);
            staleStrongMemory.source.assessmentRationale =
                "Legacy source metadata assigned a strong assessment.";
            const TriageResult staleStrongMemoryResult = Evaluate(
                MakeRefinement({ staleStrongMemory }));
            CheckEqual(staleStrongMemoryResult.verdict, TriageVerdict::Informational, L"static memory cannot satisfy standalone Strong gate");
            Check(!staleStrongMemoryResult.qualifiedStandaloneStrongHighGateSatisfied, L"static memory leaves standalone Strong gate unsatisfied");

            ObservationCorrelation staleMemoryOnlyCorrelation = MakeCorrelation(
                "correlation-static-memory-only",
                CorrelationSignificance::Strong,
                { "stale-strong-memory" },
                { EvidenceDomain::MemoryMetadata });
            const TriageResult staleMemoryOnlyCorrelationResult = Evaluate(
                MakeRefinement({ staleStrongMemory }),
                MakeCorrelations({ staleMemoryOnlyCorrelation }));
            CheckEqual(staleMemoryOnlyCorrelationResult.verdict, TriageVerdict::Informational, L"memory-only correlation has no verdict impact");
            Check(staleMemoryOnlyCorrelationResult.contributingCorrelationIds.empty(), L"memory-only correlation is not verdict-contributing");
            Check(staleMemoryOnlyCorrelationResult.contributingDomains.empty(), L"memory-only correlation contributes no domain");

            ObservationRefinementResult memoryWithDuplicate = MakeRefinement({
                MakeMemoryRecord("memory-rwx", ObservationDisposition::ReviewRelevant, ObservationStrength::Weak, memoryArtifactKey),
                MakeMemoryRecord("memory-private", ObservationDisposition::Context, ObservationStrength::Weak, memoryArtifactKey),
                MakeMemoryRecord("memory-unbacked", ObservationDisposition::Context, ObservationStrength::Weak, memoryArtifactKey),
                MakeMemoryRecord("memory-composite-duplicate", ObservationDisposition::ReviewRelevant, ObservationStrength::Moderate, memoryArtifactKey)
            });
            RefinedObservationMember& memoryDuplicate =
                memoryWithDuplicate.groups.front().members.back();
            memoryDuplicate.role = RefinedObservationRole::Duplicate;
            memoryDuplicate.suppressed = true;
            memoryDuplicate.suppression.suppressorId =
                "structural.duplicate-source-fact";
            memoryDuplicate.suppression.reason =
                "The typed memory fact is already retained by a primary observation.";
            const TriageResult memoryDuplicateResult = Evaluate(
                std::move(memoryWithDuplicate));
            CheckEqual(memoryDuplicateResult.verdict, TriageVerdict::Informational, L"duplicate memory composite does not reinforce one artifact");

            const TriageResult memoryWithPublicContext = Evaluate(
                MakeRefinement({
                    MakeMemoryRecord("memory-rwx", ObservationDisposition::ReviewRelevant, ObservationStrength::Weak, memoryArtifactKey),
                    MakeMemoryRecord("memory-private", ObservationDisposition::Context, ObservationStrength::Weak, memoryArtifactKey),
                    MakeMemoryRecord("memory-unbacked", ObservationDisposition::Context, ObservationStrength::Weak, memoryArtifactKey),
                    MakeContext("public-network-context", EvidenceDomain::Network)
                }));
            CheckEqual(memoryWithPublicContext.verdict, TriageVerdict::Informational, L"public network Context does not reinforce memory artifact");
            Check(memoryWithPublicContext.contributingDomains.empty(), L"public network Context and memory add no contributing domain");
            Check(!memoryWithPublicContext.coherentMultiDomainHighGateSatisfied, L"public network Context cannot satisfy coherent High gate");
            CheckEqual(memoryWithPublicContext.contextObservationIds.size(), std::size_t(2), L"public network and static memory Context remain retained separately");

            const TriageResult memoryWithCollectionNote = Evaluate(
                MakeRefinement(
                    {
                        MakeMemoryRecord("memory-rwx", ObservationDisposition::ReviewRelevant, ObservationStrength::Weak, memoryArtifactKey),
                        MakeMemoryRecord("memory-private", ObservationDisposition::Context, ObservationStrength::Weak, memoryArtifactKey),
                        MakeMemoryRecord("memory-unbacked", ObservationDisposition::Context, ObservationStrength::Weak, memoryArtifactKey)
                    },
                    { MakeCollectionNote("memory-collection-note") }));
            CheckEqual(memoryWithCollectionNote.verdict, TriageVerdict::Informational, L"CollectionNote does not reinforce memory artifact");
            Check(memoryWithCollectionNote.contributingDomains.empty(), L"CollectionNote and memory add no contributing domain");
            Check(!memoryWithCollectionNote.coherentMultiDomainHighGateSatisfied, L"CollectionNote cannot satisfy coherent High gate");
            CheckEqual(memoryWithCollectionNote.collectionNoteIds.size(), std::size_t(1), L"CollectionNote remains retained separately");

            const TriageResult memoryAndUnrelatedSignature = Evaluate(
                MakeRefinement({
                    MakeMemoryRecord("memory-rwx", ObservationDisposition::ReviewRelevant, ObservationStrength::Weak, memoryArtifactKey),
                    MakeMemoryRecord("memory-private", ObservationDisposition::Context, ObservationStrength::Weak, memoryArtifactKey),
                    MakeMemoryRecord("memory-unbacked", ObservationDisposition::Context, ObservationStrength::Weak, memoryArtifactKey),
                    MakeRecord("invalid-signature", EvidenceDomain::FileSignature, ObservationDisposition::ReviewRelevant, ObservationStrength::Moderate)
                }));
            CheckEqual(memoryAndUnrelatedSignature.verdict, TriageVerdict::MediumAttention, L"unrelated invalid-signature domain does not bypass typed coherence gate");

            ObservationCorrelation typedMemorySignature = MakeCorrelation(
                "correlation-memory-signature",
                CorrelationSignificance::Moderate,
                { "memory-rwx", "invalid-signature" },
                { EvidenceDomain::MemoryMetadata, EvidenceDomain::FileSignature });
            const TriageResult memoryAndTypedSignature = Evaluate(
                MakeRefinement({
                    MakeMemoryRecord("memory-rwx", ObservationDisposition::ReviewRelevant, ObservationStrength::Weak, memoryArtifactKey),
                    MakeMemoryRecord("memory-private", ObservationDisposition::Context, ObservationStrength::Weak, memoryArtifactKey),
                    MakeMemoryRecord("memory-unbacked", ObservationDisposition::Context, ObservationStrength::Weak, memoryArtifactKey),
                    MakeRecord("invalid-signature", EvidenceDomain::FileSignature, ObservationDisposition::ReviewRelevant, ObservationStrength::Moderate)
                }),
                MakeCorrelations({ typedMemorySignature }));
            CheckEqual(memoryAndTypedSignature.verdict, TriageVerdict::MediumAttention, L"static memory plus invalid signature follows signature policy");
            CheckEqual(memoryAndTypedSignature.contributingDomains.size(), std::size_t(1), L"static memory does not add a contributing domain to signature policy");
            Check(memoryAndTypedSignature.contributingDomains.count(EvidenceDomain::FileSignature) == 1, L"signature remains the sole contributing domain");
            Check(!memoryAndTypedSignature.coherentMultiDomainHighGateSatisfied, L"static memory participant does not satisfy coherent High gate");

            ObservationCorrelation typedNetworkLocal = MakeCorrelation(
                "correlation-memory-network",
                CorrelationSignificance::Moderate,
                { "memory-rwx", "exact-indicator" },
                { EvidenceDomain::MemoryMetadata, EvidenceDomain::Network });
            const TriageResult memoryAndExactIndicator = Evaluate(
                MakeRefinement({
                    MakeMemoryRecord("memory-rwx", ObservationDisposition::ReviewRelevant, ObservationStrength::Weak, memoryArtifactKey),
                    MakeMemoryRecord("memory-private", ObservationDisposition::Context, ObservationStrength::Weak, memoryArtifactKey),
                    MakeRecord("exact-indicator", EvidenceDomain::Network, ObservationDisposition::ReviewRelevant, ObservationStrength::Moderate)
                }),
                MakeCorrelations({ typedNetworkLocal }));
            CheckEqual(memoryAndExactIndicator.verdict, TriageVerdict::MediumAttention, L"static memory plus exact indicator follows network policy");
            CheckEqual(memoryAndExactIndicator.contributingDomains.size(), std::size_t(1), L"static memory does not satisfy the local-evidence domain gate");
            Check(memoryAndExactIndicator.contributingDomains.count(EvidenceDomain::Network) == 1, L"network remains the sole contributing domain");
            Check(!memoryAndExactIndicator.coherentMultiDomainHighGateSatisfied, L"static memory evidence does not promote exact indicator to high");

            ObservationCorrelation typedExecutionChain = MakeCorrelation(
                "correlation-typed-execution-chain",
                CorrelationSignificance::Moderate,
                { "encoded-command", "process-relationship" },
                { EvidenceDomain::CommandLine, EvidenceDomain::ProcessRelationship });
            const TriageResult memoryAndExecutionChain = Evaluate(
                MakeRefinement({
                    MakeMemoryRecord("memory-rwx", ObservationDisposition::ReviewRelevant, ObservationStrength::Weak, memoryArtifactKey),
                    MakeMemoryRecord("memory-private", ObservationDisposition::Context, ObservationStrength::Weak, memoryArtifactKey),
                    MakeMemoryRecord("memory-unbacked", ObservationDisposition::Context, ObservationStrength::Weak, memoryArtifactKey),
                    MakeRecord("encoded-command", EvidenceDomain::CommandLine, ObservationDisposition::ReviewRelevant, ObservationStrength::Moderate),
                    MakeRecord("process-relationship", EvidenceDomain::ProcessRelationship, ObservationDisposition::ReviewRelevant, ObservationStrength::Moderate)
                }),
                MakeCorrelations({ typedExecutionChain }));
            CheckEqual(memoryAndExecutionChain.verdict, TriageVerdict::HighAttention, L"memory artifact plus qualified typed execution-chain relation may reach high");
            Check(memoryAndExecutionChain.coherentMultiDomainHighGateSatisfied, L"execution-chain fixture satisfies coherent multi-domain gate");
            CheckEqual(memoryAndExecutionChain.contributingDomains.size(), std::size_t(2), L"static memory does not inflate execution-chain domain count");
            Check(memoryAndExecutionChain.contributingDomains.count(EvidenceDomain::MemoryMetadata) == 0, L"static memory remains supporting context for execution chain");

            const TriageResult twoMemoryArtifacts = Evaluate(MakeRefinement({
                MakeMemoryRecord("memory-region-one", ObservationDisposition::ReviewRelevant, ObservationStrength::Weak, memoryArtifactKey),
                MakeMemoryRecord(
                    "memory-region-two",
                    ObservationDisposition::ReviewRelevant,
                    ObservationStrength::Weak,
                    "memory-region:0000000020000000:0000000020000000:0000000000004000")
            }));
            CheckEqual(twoMemoryArtifacts.verdict, TriageVerdict::Informational, L"two distinct static memory artifacts remain informational");
            Check(twoMemoryArtifacts.contributingDomains.empty(), L"distinct static memory artifacts contribute no domain");

            std::vector<ObservationRecord> manyMemoryArtifacts;
            for (std::size_t index = 0; index < 58; ++index)
            {
                manyMemoryArtifacts.push_back(MakeMemoryRecord(
                    "memory-artifact-" + std::to_string(index),
                    ObservationDisposition::ReviewRelevant,
                    ObservationStrength::Weak,
                    "memory-region:bounded-" + std::to_string(index)));
            }
            const TriageResult manyMemory = Evaluate(
                MakeRefinement(std::move(manyMemoryArtifacts)));
            CheckEqual(manyMemory.verdict, TriageVerdict::Informational, L"many distinct static memory artifacts remain informational");
            Check(manyMemory.contributingObservationIds.empty(), L"many static memory artifacts contribute no observations");
            Check(manyMemory.contributingDomains.empty(), L"many static memory artifacts contribute no domains");
            Check(PreviewHasTextContaining(manyMemory, "Static memory-region metadata was observed across 58 memory-region artifacts."), L"compact rationale aggregates total memory artifacts");
            Check(PreviewHasTextContaining(manyMemory, "Writable and executable memory was observed on 58 regions."), L"compact rationale aggregates repeated RWX memory attributes");
            Check(PreviewHasTextContaining(manyMemory, "Guard-page protection was observed on 58 regions."), L"compact rationale aggregates repeated guard attributes");

            const TriageResult memoryAndWeakPath = Evaluate(MakeRefinement({
                MakeMemoryRecord(
                    "memory-static-context",
                    ObservationDisposition::ReviewRelevant,
                    ObservationStrength::Weak,
                    memoryArtifactKey),
                MakeRecord(
                    "weak-independent-path",
                    EvidenceDomain::FilePath,
                    ObservationDisposition::ReviewRelevant,
                    ObservationStrength::Weak)
            }));
            CheckEqual(memoryAndWeakPath.verdict, TriageVerdict::LowAttention, L"static memory plus one weak independent observation follows the weak observation");
            CheckEqual(memoryAndWeakPath.contributingObservationIds.size(), std::size_t(1), L"static memory is excluded from weak independent contribution count");
            CheckEqual(memoryAndWeakPath.contributingDomains.size(), std::size_t(1), L"static memory is excluded from weak independent domain count");
            Check(memoryAndWeakPath.contributingDomains.count(EvidenceDomain::FilePath) == 1, L"weak path is the sole contributing domain");

            ObservationRecord qualified = MakeRecord(
                "qualified-strong",
                EvidenceDomain::Network,
                ObservationDisposition::ReviewRelevant,
                ObservationStrength::Strong);
            qualified.source.assessmentRationale =
                "The attributed source explicitly assessed this bounded fact as Strong.";
            const TriageResult qualifiedStrong = Evaluate(MakeRefinement({ qualified }));
            CheckEqual(qualifiedStrong.verdict, TriageVerdict::HighAttention, L"qualified strong direct observation high");
            Check(qualifiedStrong.qualifiedStandaloneStrongHighGateSatisfied, L"qualified direct Strong reports standalone High gate");

            ObservationRecord corroborated = MakeRecord(
                "qualified-corroborated-strong",
                EvidenceDomain::Network,
                ObservationDisposition::ReviewRelevant,
                ObservationStrength::Strong,
                ObservationConfidence::High,
                ObservationSourceKind::Corroborated);
            corroborated.source.assessmentRationale =
                "The attributed corroborated source explicitly assessed this bounded fact as Strong.";
            const TriageResult corroboratedStrong = Evaluate(
                MakeRefinement({ corroborated }));
            CheckEqual(corroboratedStrong.verdict, TriageVerdict::HighAttention, L"qualified corroborated Strong observation may reach high");
            Check(corroboratedStrong.qualifiedStandaloneStrongHighGateSatisfied, L"corroborated Strong reports standalone High gate");

            ObservationRecord noRationale = MakeRecord(
                "strong-without-rationale",
                EvidenceDomain::Network,
                ObservationDisposition::ReviewRelevant,
                ObservationStrength::Strong);
            const TriageResult unqualifiedStrong = Evaluate(MakeRefinement({ noRationale }));
            CheckEqual(unqualifiedStrong.verdict, TriageVerdict::MediumAttention, L"strong without explicit rationale not high");

            ObservationRecord mediumConfidenceStrong = MakeRecord(
                "medium-confidence-strong",
                EvidenceDomain::Network,
                ObservationDisposition::ReviewRelevant,
                ObservationStrength::Strong,
                ObservationConfidence::Medium);
            mediumConfidenceStrong.source.assessmentRationale =
                "The attributed source supplied a bounded Strong assessment.";
            const TriageResult mediumConfidenceStrongResult = Evaluate(
                MakeRefinement({ mediumConfidenceStrong }));
            CheckEqual(mediumConfidenceStrongResult.verdict, TriageVerdict::MediumAttention, L"standalone Strong below High confidence does not satisfy High gate");
            Check(!mediumConfidenceStrongResult.qualifiedStandaloneStrongHighGateSatisfied, L"medium-confidence Strong reports unsatisfied standalone High gate");

            ObservationRecord imported = MakeRecord(
                "imported-strong",
                EvidenceDomain::ImportedEvidence,
                ObservationDisposition::ReviewRelevant,
                ObservationStrength::Strong,
                ObservationConfidence::High,
                ObservationSourceKind::Imported);
            imported.source.assessmentRationale = "Attributed imported assessment.";
            const TriageResult importedResult = Evaluate(MakeRefinement({ imported }));
            CheckEqual(importedResult.verdict, TriageVerdict::MediumAttention, L"imported provenance does not automatically qualify standalone high");
        }

        void TestSuppressionDuplicatesAndIntegrity()
        {
            ObservationRefinementResult suppressed = MakeRefinement({
                MakeRecord("suppressed-context", EvidenceDomain::Runtime, ObservationDisposition::ReviewRelevant, ObservationStrength::Moderate)
            });
            suppressed.groups.front().members.front().suppressed = true;
            suppressed.groups.front().members.front().suppression.suppressorId =
                "context.generic-structural";
            suppressed.groups.front().members.front().suppression.reason =
                "Generic structural context explains this source observation.";
            const TriageResult suppressedResult = Evaluate(std::move(suppressed));
            CheckEqual(suppressedResult.verdict, TriageVerdict::Informational, L"suppressed observation does not elevate");

            ObservationRefinementResult duplicate = MakeRefinement({
                MakeRecord("primary-weak", EvidenceDomain::FilePath, ObservationDisposition::ReviewRelevant, ObservationStrength::Weak),
                MakeRecord("duplicate-moderate", EvidenceDomain::FilePath, ObservationDisposition::ReviewRelevant, ObservationStrength::Moderate)
            });
            RefinedObservationMember& duplicateMember =
                duplicate.groups[1].members.front();
            duplicateMember.role = RefinedObservationRole::Duplicate;
            duplicateMember.suppressed = true;
            duplicateMember.suppression.suppressorId =
                "structural.duplicate-source-fact";
            duplicateMember.suppression.reason =
                "The same typed fact is retained as supporting provenance.";
            const TriageResult duplicateResult = Evaluate(std::move(duplicate));
            CheckEqual(duplicateResult.verdict, TriageVerdict::LowAttention, L"duplicate composite does not escalate");
            CheckEqual(duplicateResult.contributingObservationIds.size(), std::size_t(1), L"duplicate is not a contributor");

            const TriageResult integrityOnly = Evaluate(MakeRefinement(
                {},
                {},
                { MakeIntegrityNote("integrity-note") }));
            CheckEqual(integrityOnly.verdict, TriageVerdict::Informational, L"integrity note only informational process verdict");
            CheckEqual(integrityOnly.evidenceIntegrityNoteIds.size(), std::size_t(1), L"integrity note retained separately");
        }

        void TestRationaleLimitationsAndUnresolved()
        {
            ObservationRecord context = MakeContext(
                "support-context",
                EvidenceDomain::Network);
            context.observation.title = "Generic public connection context";
            context.observation.limitations = { "Fixed source limitation." };
            context.observation.provenance.limitations = {
                "Fixed provenance limitation.",
                "Fixed source limitation."
            };
            ObservationRecord note = MakeCollectionNote("collection-note");
            note.observation.title = "Module metadata unavailable";
            note.observation.limitations = { "Fixed source limitation." };
            ObservationRecord integrity = MakeIntegrityNote("integrity-note");
            integrity.observation.title = "Imported evidence was truncated";

            ObservationCorrelationPreparation unresolved;
            unresolved.entityScope = EntityScope;
            unresolved.correlationKey = "generic-incomplete-correlation";
            unresolved.requirementsKnown = true;
            unresolved.incomplete = true;

            const TriageResult result = Evaluate(
                MakeRefinement({ context }, { note }, { integrity }),
                MakeCorrelations({}, { unresolved }));
            Check(result.Succeeded(), L"rationale fixture succeeds");
            Check(!result.rationale.empty(), L"rationale present");
            CheckEqual(result.rationale.front(), std::string("TriageEngine result: Informational."), L"rationale begins with verdict");
            Check(HasTextContaining(result.rationale, "Supporting context"), L"rationale contains context section");
            Check(HasTextContaining(result.rationale, "Collection limitation"), L"rationale contains collection section");
            Check(HasTextContaining(result.rationale, "Evidence-integrity context"), L"rationale contains integrity section");
            Check(HasTextContaining(result.rationale, "Unresolved correlation"), L"rationale contains unresolved section");
            CheckEqual(result.unresolvedCorrelationKeys.size(), std::size_t(1), L"unresolved key retained");
            CheckEqual(result.limitations.size(), std::size_t(2), L"limitations propagated and deduplicated");
            CheckEqual(
                std::set<std::string>(result.rationale.begin(), result.rationale.end()).size(),
                result.rationale.size(),
                L"rationale lines deduplicated");

            ObservationRecord unicodeBoundary = MakeRecord(
                "unicode-boundary",
                EvidenceDomain::Network,
                ObservationDisposition::ReviewRelevant,
                ObservationStrength::Strong);
            const std::string assessmentPrefix =
                "Attributed source assessment for 'unicode-boundary': ";
            unicodeBoundary.source.assessmentRationale.assign(
                TriageRationaleItemMaxCharacters -
                    assessmentPrefix.size() - 1,
                'a');
            unicodeBoundary.source.assessmentRationale +=
                "\xC3\xA9" "tail";
            const TriageResult unicodeResult = Evaluate(
                MakeRefinement({ unicodeBoundary }));
            const auto boundaryLine = std::find_if(
                unicodeResult.rationale.begin(),
                unicodeResult.rationale.end(),
                [&](const std::string& line)
                {
                    return line.find(assessmentPrefix) == 0;
                });
            Check(boundaryLine != unicodeResult.rationale.end(), L"Unicode-boundary rationale retained");
            if (boundaryLine != unicodeResult.rationale.end())
            {
                Check(
                    boundaryLine->size() <= TriageRationaleItemMaxCharacters,
                    L"Unicode-boundary rationale remains bounded");
                Check(
                    boundaryLine->empty() ||
                        static_cast<unsigned char>(boundaryLine->back()) != 0xC3U,
                    L"Unicode-boundary rationale never retains a dangling lead byte");
            }
        }

        void TestTypedRationalePresentationContract()
        {
            ObservationRecord basis = MakeRecord(
                "typed-basis",
                EvidenceDomain::FileSignature,
                ObservationDisposition::ReviewRelevant,
                ObservationStrength::Moderate);
            basis.observation.title = "Invalid signature evidence";

            ObservationRecord context = MakeContext(
                "typed-context",
                EvidenceDomain::Network);
            context.observation.title = "Public network context";

            ObservationRecord collection =
                MakeCollectionNote("typed-collection");
            collection.observation.title = "Module metadata unavailable";

            ObservationRecord integrity =
                MakeIntegrityNote("typed-integrity");
            integrity.observation.title = "Imported evidence truncated";

            ObservationCorrelation completed = MakeCorrelation(
                "typed-completed-correlation",
                CorrelationSignificance::Moderate,
                { "typed-basis" },
                { EvidenceDomain::FileSignature });

            ObservationCorrelationPreparation unresolved;
            unresolved.entityScope = EntityScope;
            unresolved.correlationKey = "typed-unresolved-correlation";
            unresolved.requirementsKnown = true;
            unresolved.incomplete = true;

            const TriageResult result = Evaluate(
                MakeRefinement(
                    { basis, context },
                    { collection },
                    { integrity }),
                MakeCorrelations({ completed }, { unresolved }));

            Check(result.Succeeded(), L"typed rationale fixture succeeds");
            CheckEqual(
                result.rationaleEntries.size(),
                result.rationale.size(),
                L"typed rationale is one-to-one with flattened rationale");
            Check(
                result.rationaleEntries.size() <= TriageMaxRationaleEntries,
                L"typed rationale list respects cap");

            std::set<TriageRationaleSection> presentSections;
            for (std::size_t index = 0;
                 index < result.rationaleEntries.size();
                 ++index)
            {
                const TriageRationaleEntry& entry =
                    result.rationaleEntries[index];
                CheckEqual(
                    entry.text,
                    result.rationale[index],
                    L"typed rationale preserves flattened text and order");
                Check(
                    entry.text.size() <= TriageRationaleItemMaxCharacters,
                    L"typed rationale entry respects string cap");
                presentSections.insert(entry.section);
            }

            const std::set<TriageRationaleSection> expectedSections = {
                TriageRationaleSection::VerdictBasis,
                TriageRationaleSection::CompletedCorrelations,
                TriageRationaleSection::SupportingContext,
                TriageRationaleSection::CollectionLimitations,
                TriageRationaleSection::EvidenceIntegrityContext,
                TriageRationaleSection::UnresolvedCorrelations
            };
            CheckEqual(
                presentSections,
                expectedSections,
                L"typed rationale keeps all presentation sections distinct");

            const auto completedEntry = std::find_if(
                result.rationaleEntries.begin(),
                result.rationaleEntries.end(),
                [](const TriageRationaleEntry& entry)
                {
                    return entry.section ==
                        TriageRationaleSection::CompletedCorrelations;
                });
            Check(
                completedEntry != result.rationaleEntries.end() &&
                    completedEntry->text.find("typed-completed-correlation") !=
                        std::string::npos,
                L"completed correlation rationale retains typed identity");

            CheckEqual(
                TriageRationaleSectionDisplayText(
                    TriageRationaleSection::CollectionLimitations),
                std::string("Collection limitations"),
                L"typed rationale section display text");
            CheckEqual(
                TriageRationaleSectionDisplayText(
                    TriageRationaleSection::PresentationNotes),
                std::string("Presentation notes"),
                L"presentation-note section display text");
            Check(
                TriageRationaleSectionDisplayText(
                    static_cast<TriageRationaleSection>(0xFFFFFFFFU)).find(
                        "0xFFFFFFFF") != std::string::npos,
                L"unknown rationale section remains visible");

            const TriageResult repeated = Evaluate(
                MakeRefinement(
                    { basis, context },
                    { collection },
                    { integrity }),
                MakeCorrelations({ completed }, { unresolved }));
            CheckEqual(
                DeterministicSignature(result),
                DeterministicSignature(repeated),
                L"typed rationale section ordering is deterministic");

            std::vector<ObservationRecord> overRationaleCap;
            overRationaleCap.reserve(TriageMaxRationaleItems + 1);
            for (std::size_t index = 0;
                 index < TriageMaxRationaleItems + 1;
                 ++index)
            {
                ObservationRecord boundedRecord = MakeRecord(
                    "bounded-rationale-" + std::to_string(index),
                    EvidenceDomain::FilePath,
                    ObservationDisposition::ReviewRelevant,
                    ObservationStrength::Weak);
                boundedRecord.observation.title =
                    "Bounded preview observation " +
                    std::to_string(index);
                overRationaleCap.push_back(std::move(boundedRecord));
            }
            const TriageResult bounded = Evaluate(
                MakeRefinement(std::move(overRationaleCap)));
            Check(bounded.Succeeded(), L"bounded rationale fixture succeeds");
            Check(bounded.rationaleTruncated, L"bounded rationale records truncation");
            CheckEqual(
                bounded.rationaleEntries.size(),
                bounded.rationale.size(),
                L"bounded typed rationale remains one-to-one");
            CheckEqual(
                bounded.rationale.size(),
                TriageMaxRationaleItems,
                L"bounded flattened rationale respects item cap");
            Check(bounded.previewRationaleTruncated, L"bounded compact preview records truncation");
            CheckEqual(
                bounded.previewRationaleEntries.size(),
                TriageMaxRationaleEntries,
                L"bounded compact preview respects item cap");
            for (const TriageRationaleEntry& entry :
                 bounded.previewRationaleEntries)
            {
                Check(
                    entry.text.size() <= TriageRationaleItemMaxCharacters,
                    L"bounded compact preview string respects cap");
            }
            Check(
                !bounded.rationaleEntries.empty() &&
                    bounded.rationaleEntries.back().section ==
                        TriageRationaleSection::PresentationNotes,
                L"rationale omission marker is a non-evidentiary presentation note");
            Check(
                !bounded.rationaleEntries.empty() &&
                    bounded.rationaleEntries.back().text ==
                        bounded.rationale.back(),
                L"bounded omission marker preserves flattened correspondence");
            Check(
                !bounded.rationale.empty() &&
                    bounded.rationale.back() ==
                        "Additional rationale items were omitted by the bounded triage policy.",
                L"flattened omission marker remains unchanged");
        }

        void TestAtomicValidationAndCaps()
        {
            ObservationRefinementResult overCap = MakeRefinement({});
            overCap.groups.resize(ObservationRefinementMaxGroups + 1);
            const TriageResult capFailure = Evaluate(std::move(overCap));
            Check(!capFailure.success, L"over-cap refinement fails");
            CheckEqual(capFailure.status, TriageEngineStatus::InputLimitExceeded, L"over-cap status");
            Check(capFailure.contributingObservationIds.empty(), L"over-cap failure atomic");

            ObservationCorrelation wrongDomains = MakeCorrelation(
                "wrong-domains",
                CorrelationSignificance::Moderate,
                { "typed-path", "typed-signature" },
                { EvidenceDomain::FilePath, EvidenceDomain::Token });
            const TriageResult domainFailure = Evaluate(
                MakeRefinement({
                    MakeContext("typed-path", EvidenceDomain::FilePath),
                    MakeRecord("typed-signature", EvidenceDomain::FileSignature, ObservationDisposition::ReviewRelevant, ObservationStrength::Moderate)
                }),
                MakeCorrelations({ wrongDomains }));
            Check(!domainFailure.success, L"declared correlation-domain mismatch fails");
            CheckEqual(domainFailure.status, TriageEngineStatus::InvalidInput, L"domain mismatch status");

            ObservationCorrelation unverifiedStrong = MakeCorrelation(
                "unverified-strong",
                CorrelationSignificance::Strong,
                { "unverified-memory" },
                { EvidenceDomain::MemoryMetadata });
            const TriageResult provenanceFailure = Evaluate(
                MakeRefinement({
                    MakeRecord("unverified-memory", EvidenceDomain::MemoryMetadata, ObservationDisposition::ReviewRelevant, ObservationStrength::Moderate, ObservationConfidence::High, ObservationSourceKind::Unverified)
                }),
                MakeCorrelations({ unverifiedStrong }));
            Check(!provenanceFailure.success, L"unverified participant cannot support strong correlation");
            CheckEqual(provenanceFailure.status, TriageEngineStatus::InvalidInput, L"unverified strong correlation status");

            ObservationCorrelation lowConfidenceStrong = MakeCorrelation(
                "low-confidence-strong",
                CorrelationSignificance::Strong,
                { "low-confidence-memory" },
                { EvidenceDomain::MemoryMetadata },
                ObservationConfidence::Low);
            const TriageResult confidenceFailure = Evaluate(
                MakeRefinement({
                    MakeRecord("low-confidence-memory", EvidenceDomain::MemoryMetadata, ObservationDisposition::ReviewRelevant, ObservationStrength::Moderate, ObservationConfidence::Low)
                }),
                MakeCorrelations({ lowConfidenceStrong }));
            Check(!confidenceFailure.success, L"low-confidence correlation cannot claim Strong significance");
            CheckEqual(confidenceFailure.status, TriageEngineStatus::InvalidInput, L"low-confidence strong correlation status");

            ObservationRefinementResult unavailable;
            unavailable.attempted = true;
            unavailable.success = false;
            unavailable.status = ObservationRefinementStatus::InternalPolicyFailure;
            const TriageResult unavailableResult = Evaluate(unavailable);
            CheckEqual(unavailableResult.status, TriageEngineStatus::RefinementUnavailable, L"refinement failure isolated");
            Check(unavailableResult.contributingCorrelationIds.empty(), L"refinement failure returns no partial result");
        }

        void TestDeterminismEntityAndPresentationMetadataIndependence()
        {
            ObservationRecord source = MakeRecord(
                "stable-observation",
                EvidenceDomain::FileSignature,
                ObservationDisposition::ReviewRelevant,
                ObservationStrength::Moderate);
            ObservationRefinementResult firstRefinement = MakeRefinement({ source });
            ObservationRefinementResult secondRefinement = firstRefinement;
            secondRefinement.groups.front().members.front().sourceRecord.source.
                sourceMessage = "Alternate bounded presentation metadata.";

            const TriageResult first = Evaluate(firstRefinement);
            const TriageResult repeated = Evaluate(firstRefinement);
            const TriageResult changedPresentationMetadata = Evaluate(secondRefinement);
            CheckEqual(DeterministicSignature(first), DeterministicSignature(repeated), L"triage output deterministic excluding duration");
            CheckEqual(DeterministicSignature(first), DeterministicSignature(changedPresentationMetadata), L"source presentation metadata cannot affect triage");

            ObservationRecord renamedEntity = source;
            renamedEntity.observation.entityScope = "process:other-generic-entity";
            const TriageResult otherEntity = Evaluate(MakeRefinement({ renamedEntity }));
            CheckEqual(first.verdict, otherEntity.verdict, L"generic entity name does not affect verdict");
            CheckEqual(first.rationale, otherEntity.rationale, L"generic entity name does not affect rationale structure");
        }
    }

    int RunTriageEngineTests()
    {
        failureCount = 0;
        TestInformationalAndLowFixtures();
        TestMediumFixtures();
        TestHighRestrictionsAndCorrelations();
            TestSuppressionDuplicatesAndIntegrity();
            TestRationaleLimitationsAndUnresolved();
            TestTypedRationalePresentationContract();
            TestAtomicValidationAndCaps();
        TestDeterminismEntityAndPresentationMetadataIndependence();
        return failureCount;
    }
}
