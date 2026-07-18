#include "Core/ObservationInventory.h"
#include "Core/ObservationPolicy.h"
#include "Core/ObservationRefinement.h"

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

        ObservationStrength DefaultStrength(
            ObservationDisposition disposition)
        {
            switch (disposition)
            {
            case ObservationDisposition::ReviewRelevant:
            case ObservationDisposition::CorrelatedOnly:
                return ObservationStrength::Moderate;
            case ObservationDisposition::Context:
                return ObservationStrength::Weak;
            default:
                return ObservationStrength::None;
            }
        }

        ObservationRecord MakeNativeRecord(
            std::string id,
            EvidenceDomain domain,
            ObservationDisposition disposition,
            std::string groupingKey,
            std::size_t sourceOrdinal = 0,
            std::string sourceRecordSuffix = {})
        {
            ObservationRecord record;
            record.source.sourceRecordId = "native-source:" + id +
                sourceRecordSuffix;
            record.source.sourceRuleId = "native.rule." + id;
            record.source.sourceTitle = "Native typed source";
            record.source.sourceMessage = "Native bounded source evidence.";
            record.source.sourceCategory = "Native selected-process evidence";
            record.source.producerIdentifier = "native-test-producer";
            record.source.sourceOrdinal = sourceOrdinal;

            Observation& observation = record.observation;
            observation.id = std::move(id);
            observation.ruleId = record.source.sourceRuleId;
            observation.title = "Native typed observation";
            observation.summary = "Native bounded observation summary.";
            observation.domain = domain;
            observation.sourceKind = ObservationSourceKind::Direct;
            observation.disposition = disposition;
            observation.strength = DefaultStrength(disposition);
            observation.confidence = ObservationConfidence::High;
            observation.contributesToVerdict =
                disposition == ObservationDisposition::ReviewRelevant;
            observation.entityScope = "process:4242:creation-100";
            observation.groupingKey = std::move(groupingKey);
            observation.rawValue = "native raw value";
            observation.normalizedValue = "native-normalized-value";
            observation.evidence = { "Native bounded evidence item." };
            observation.provenance.sourceKind = observation.sourceKind;
            observation.provenance.sourceIdentifier =
                record.source.producerIdentifier;
            observation.provenance.collectionMethod = "fixed-test-input";
            observation.provenance.sourceAvailable = true;
            return record;
        }

        ObservationRecord MakeCollectionNote(std::string id)
        {
            ObservationRecord record = MakeNativeRecord(
                std::move(id),
                EvidenceDomain::CollectionQuality,
                ObservationDisposition::CollectionNote,
                "collection-note");
            record.observation.sourceKind = ObservationSourceKind::Unavailable;
            record.observation.provenance.sourceKind =
                ObservationSourceKind::Unavailable;
            record.observation.provenance.sourceAvailable = false;
            record.observation.limitations = {
                "The typed source could not be collected."
            };
            return record;
        }

        ObservationRecord MakeIntegrityNote(std::string id)
        {
            ObservationRecord record = MakeNativeRecord(
                std::move(id),
                EvidenceDomain::EvidenceIntegrity,
                ObservationDisposition::EvidenceIntegrityNote,
                "integrity-note");
            record.observation.limitations = {
                "The captured evidence was truncated at its documented cap."
            };
            return record;
        }

        ObservationRecord MakeArtifactRecord(
            std::string id,
            EvidenceDomain domain,
            ObservationDisposition disposition,
            ObservationArtifactKind artifactKind,
            std::string artifactKey,
            std::string groupingKey,
            std::string attributeKey,
            std::string attributeValue = "true",
            std::size_t sourceOrdinal = 0)
        {
            ObservationRecord record = MakeNativeRecord(
                std::move(id),
                domain,
                disposition,
                std::move(groupingKey),
                sourceOrdinal);
            Observation& observation = record.observation;
            observation.artifactIdentity.kind = artifactKind;
            observation.artifactIdentity.entityScope = observation.entityScope;
            observation.artifactIdentity.artifactKey = std::move(artifactKey);
            observation.artifactAttributes.push_back({
                std::move(attributeKey),
                std::move(attributeValue)
            });
            return record;
        }

        ObservationInventory MakeInventory(
            std::vector<ObservationRecord> records)
        {
            ObservationInventory inventory;
            inventory.status = ObservationInventoryStatus::Success;
            inventory.records = std::move(records);
            return inventory;
        }

        const RefinedObservationGroup* FindGroup(
            const ObservationRefinementResult& result,
            EvidenceDomain domain,
            const std::string& groupingKey)
        {
            const auto found = std::find_if(
                result.groups.begin(),
                result.groups.end(),
                [&](const RefinedObservationGroup& group)
                {
                    return group.domain == domain &&
                        group.groupingKey == groupingKey;
                });
            return found == result.groups.end() ? nullptr : &*found;
        }

        const RefinedObservationGroup* FindArtifactGroup(
            const ObservationRefinementResult& result,
            EvidenceDomain domain,
            ObservationArtifactKind kind,
            const std::string& artifactKey)
        {
            const auto found = std::find_if(
                result.groups.begin(),
                result.groups.end(),
                [&](const RefinedObservationGroup& group)
                {
                    return group.domain == domain &&
                        group.artifactIdentity.kind == kind &&
                        group.artifactIdentity.artifactKey == artifactKey;
                });
            return found == result.groups.end() ? nullptr : &*found;
        }

        const RefinedObservationMember* FindMemberBySource(
            const ObservationRefinementResult& result,
            const std::string& sourceRecordId)
        {
            for (const RefinedObservationGroup& group : result.groups)
            {
                const auto found = std::find_if(
                    group.members.begin(),
                    group.members.end(),
                    [&](const RefinedObservationMember& member)
                    {
                        return member.sourceRecord.source.sourceRecordId ==
                            sourceRecordId;
                    });
                if (found != group.members.end())
                {
                    return &*found;
                }
            }
            return nullptr;
        }

        bool HasDomain(
            const std::vector<EvidenceDomain>& domains,
            EvidenceDomain expected)
        {
            return std::find(domains.begin(), domains.end(), expected) !=
                domains.end();
        }

        std::string RefinementSignature(
            const ObservationRefinementResult& result)
        {
            std::ostringstream signature;
            signature << result.attempted << '|'
                      << result.success << '|'
                      << static_cast<std::uint32_t>(result.status) << '|'
                      << result.summary.rawObservationCount << '|'
                      << result.summary.groupCount << '|'
                      << result.summary.artifactGroupCount << '|'
                      << result.summary.distinctArtifactCount << '|'
                      << result.summary.artifactAttributeCount << '|'
                      << result.summary.duplicateCount << '|'
                      << result.summary.suppressedCount << '|'
                      << result.summary.collectionNoteCount << '|'
                      << result.summary.evidenceIntegrityNoteCount << '|'
                      << result.summary.contributingDomainCountAfter;
            for (const RefinedObservationGroup& group : result.groups)
            {
                signature << "|g:" << group.entityScope << ':'
                          << static_cast<std::uint32_t>(group.domain) << ':'
                          << group.groupingKey << ':'
                          << static_cast<std::uint32_t>(
                                 group.artifactIdentity.kind) << ':'
                          << group.artifactIdentity.artifactKey << ':'
                          << group.artifactAttributeCount;
                for (const RefinedObservationMember& member : group.members)
                {
                    signature << "|m:"
                              << member.sourceRecord.source.sourceRecordId << ':'
                              << member.sourceRecord.observation.id << ':'
                              << static_cast<std::uint32_t>(member.role) << ':'
                              << member.primaryObservationId << ':'
                              << member.suppressed << ':'
                              << member.semanticFingerprint;
                }
            }
            for (const ObservationRecord& record : result.collectionNotes)
            {
                signature << "|collection:" << record.observation.id;
            }
            for (const ObservationRecord& record : result.evidenceIntegrityNotes)
            {
                signature << "|integrity:" << record.observation.id;
            }
            for (const ObservationCorrelationPreparation& correlation :
                 result.correlations)
            {
                signature << "|correlation:" << correlation.entityScope << ':'
                          << correlation.correlationKey << ':'
                          << correlation.requirementsKnown << ':'
                          << correlation.incomplete;
                for (EvidenceDomain domain :
                     correlation.availableSupportingDomains)
                {
                    signature << ":d"
                              << static_cast<std::uint32_t>(domain);
                }
                for (const std::string& id :
                     correlation.sourceObservationIds)
                {
                    signature << ":i" << id;
                }
            }
            return signature.str();
        }

        void TestEmptyAndUnavailableInventory()
        {
            const ObservationRefinementResult empty =
                RefineObservationInventory(ObservationInventory{});
            Check(empty.Succeeded(), L"empty native inventory succeeds");
            Check(empty.groups.empty(), L"empty native inventory has no groups");
            Check(empty.collectionNotes.empty(), L"empty native inventory has no collection notes");
            Check(empty.evidenceIntegrityNotes.empty(), L"empty native inventory has no integrity notes");

            ObservationInventory unavailable;
            unavailable.status =
                ObservationInventoryStatus::ObservationLimitExceeded;
            const ObservationRefinementResult failed =
                RefineObservationInventory(unavailable);
            Check(failed.attempted, L"unavailable inventory refinement attempted");
            Check(!failed.success, L"unavailable inventory refinement fails");
            CheckEqual(
                failed.status,
                ObservationRefinementStatus::RawInventoryUnavailable,
                L"unavailable inventory status retained");
            Check(failed.groups.empty(), L"unavailable inventory returns no groups");
            Check(failed.collectionNotes.empty(), L"unavailable inventory returns no notes");
        }

        void TestContextCollectionAndIntegritySeparation()
        {
            ObservationRecord context = MakeNativeRecord(
                "path-context",
                EvidenceDomain::FilePath,
                ObservationDisposition::Context,
                "path-context");
            ObservationRecord review = MakeNativeRecord(
                "command-review",
                EvidenceDomain::CommandLine,
                ObservationDisposition::ReviewRelevant,
                "command-review");
            const ObservationInventory inventory = MakeInventory({
                context,
                MakeCollectionNote("module-unavailable"),
                MakeIntegrityNote("handle-truncated"),
                review
            });

            const ObservationRefinementResult result =
                RefineObservationInventory(inventory);
            Check(result.Succeeded(), L"context and note separation succeeds");
            CheckEqual(result.groups.size(), std::size_t(2), L"only behavioral records are grouped");
            CheckEqual(result.collectionNotes.size(), std::size_t(1), L"collection note separated");
            CheckEqual(result.evidenceIntegrityNotes.size(), std::size_t(1), L"integrity note separated");
            Check(FindGroup(result, EvidenceDomain::FilePath, "path-context") != nullptr, L"context remains auditable in behavioral groups");
            Check(FindGroup(result, EvidenceDomain::CommandLine, "command-review") != nullptr, L"review evidence remains in behavioral groups");
            CheckEqual(result.summary.collectionNoteCount, std::size_t(1), L"collection summary exact");
            CheckEqual(result.summary.evidenceIntegrityNoteCount, std::size_t(1), L"integrity summary exact");
            CheckEqual(result.summary.contributingDomainCountAfter, std::size_t(1), L"notes and context do not contribute domains");
        }

        void TestDeterministicGroupingAndOrder()
        {
            ObservationRecord commandOne = MakeNativeRecord(
                "command-one",
                EvidenceDomain::CommandLine,
                ObservationDisposition::ReviewRelevant,
                "command-family",
                1);
            ObservationRecord commandTwo = MakeNativeRecord(
                "command-two",
                EvidenceDomain::CommandLine,
                ObservationDisposition::Context,
                "command-family",
                2);
            ObservationRecord path = MakeNativeRecord(
                "path-one",
                EvidenceDomain::FilePath,
                ObservationDisposition::Context,
                "path-family",
                3);
            ObservationRecord unkeyedOne = MakeNativeRecord(
                "unkeyed-one",
                EvidenceDomain::Runtime,
                ObservationDisposition::Context,
                {},
                4);
            ObservationRecord unkeyedTwo = MakeNativeRecord(
                "unkeyed-two",
                EvidenceDomain::Runtime,
                ObservationDisposition::Context,
                {},
                5);
            const ObservationInventory inventory = MakeInventory({
                commandOne,
                commandTwo,
                path,
                unkeyedOne,
                unkeyedTwo
            });

            const ObservationRefinementResult first =
                RefineObservationInventory(inventory);
            const ObservationRefinementResult second =
                RefineObservationInventory(inventory);
            Check(first.Succeeded() && second.Succeeded(), L"deterministic grouping runs succeed");
            CheckEqual(RefinementSignature(first), RefinementSignature(second), L"refinement result ordering is deterministic");
            CheckEqual(first.groups.size(), std::size_t(4), L"keyed records group and unkeyed records remain singletons");
            CheckEqual(first.groups[0].groupingKey, std::string("command-family"), L"first group follows first source occurrence");
            CheckEqual(first.groups[1].groupingKey, std::string("path-family"), L"second group follows source occurrence");
            CheckEqual(first.groups[0].members.size(), std::size_t(2), L"same scope domain and key group together");
            CheckEqual(first.groups[0].members[0].sourceRecord.observation.id, std::string("command-one"), L"member order remains deterministic");
            CheckEqual(first.groups[0].members[1].sourceRecord.observation.id, std::string("command-two"), L"second member order remains deterministic");
        }

        void TestExactDuplicateSuppressionPrefersNativeOrdinal()
        {
            ObservationRecord later = MakeNativeRecord(
                "native-exact-fact",
                EvidenceDomain::Handle,
                ObservationDisposition::ReviewRelevant,
                "sensitive-access",
                9,
                ":later");
            ObservationRecord earlier = MakeNativeRecord(
                "native-exact-fact",
                EvidenceDomain::Handle,
                ObservationDisposition::ReviewRelevant,
                "sensitive-access",
                2,
                ":earlier");
            const ObservationRefinementResult result =
                RefineObservationInventory(MakeInventory({ later, earlier }));

            Check(result.Succeeded(), L"native exact duplicate refinement succeeds");
            CheckEqual(result.summary.duplicateCount, std::size_t(1), L"one exact duplicate recorded");
            CheckEqual(result.summary.suppressedCount, std::size_t(1), L"exact duplicate is structurally suppressed");
            const RefinedObservationMember* primary = FindMemberBySource(
                result,
                "native-source:native-exact-fact:earlier");
            const RefinedObservationMember* duplicate = FindMemberBySource(
                result,
                "native-source:native-exact-fact:later");
            Check(primary != nullptr && duplicate != nullptr, L"both native source records remain auditable");
            if (primary != nullptr && duplicate != nullptr)
            {
                CheckEqual(primary->role, RefinedObservationRole::Primary, L"earlier native ordinal is primary");
                CheckEqual(duplicate->role, RefinedObservationRole::Duplicate, L"later native ordinal is duplicate");
                Check(duplicate->suppressed, L"duplicate carries reversible suppression");
                Check(primary->sourceRecord.observation.contributesToVerdict, L"primary source contribution remains intact");
                Check(duplicate->sourceRecord.observation.contributesToVerdict, L"duplicate source record remains unchanged for audit");
                Check(!EffectiveObservation(*duplicate).contributesToVerdict, L"effective duplicate cannot reinforce verdict");
                CheckEqual(duplicate->semanticFingerprint, primary->semanticFingerprint, L"duplicate and primary share typed fingerprint");
            }
            CheckEqual(result.summary.contributingDomainCountAfter, std::size_t(1), L"duplicate cannot create another contributing domain");
        }

        void TestArtifactIdentityAndSameArtifactAttributes()
        {
            const std::string regionOne = "memory-region:base-1000:size-4096";
            const std::string regionTwo = "memory-region:base-3000:size-4096";
            ObservationRecord writableExecutable = MakeArtifactRecord(
                "memory-rwx",
                EvidenceDomain::MemoryMetadata,
                ObservationDisposition::Context,
                ObservationArtifactKind::MemoryRegion,
                regionOne,
                "memory-writable-executable",
                ObservationArtifactAttributeMemoryWritable,
                ObservationArtifactAttributeBooleanTrue,
                1);
            writableExecutable.observation.artifactAttributes.push_back({
                ObservationArtifactAttributeMemoryExecutable,
                ObservationArtifactAttributeBooleanTrue
            });
            ObservationRecord privateExecutable = MakeArtifactRecord(
                "memory-private",
                EvidenceDomain::MemoryMetadata,
                ObservationDisposition::Context,
                ObservationArtifactKind::MemoryRegion,
                regionOne,
                "memory-private-executable",
                ObservationArtifactAttributeMemoryPrivate,
                ObservationArtifactAttributeBooleanTrue,
                2);
            ObservationRecord unbacked = MakeArtifactRecord(
                "memory-unbacked",
                EvidenceDomain::MemoryMetadata,
                ObservationDisposition::Context,
                ObservationArtifactKind::MemoryRegion,
                regionOne,
                "memory-unbacked-executable",
                ObservationArtifactAttributeMemoryImageBacked,
                ObservationArtifactAttributeBooleanFalse,
                3);
            unbacked.observation.artifactAttributes.push_back({
                ObservationArtifactAttributeMemoryMappedFileBacked,
                ObservationArtifactAttributeBooleanFalse
            });
            ObservationRecord guarded = MakeArtifactRecord(
                "memory-guarded",
                EvidenceDomain::MemoryMetadata,
                ObservationDisposition::Context,
                ObservationArtifactKind::MemoryRegion,
                regionTwo,
                "memory-guarded",
                ObservationArtifactAttributeMemoryGuarded,
                ObservationArtifactAttributeBooleanTrue,
                4);

            const ObservationRefinementResult result =
                RefineObservationInventory(MakeInventory({
                    writableExecutable,
                    privateExecutable,
                    unbacked,
                    guarded
                }));
            Check(result.Succeeded(), L"artifact-aware memory refinement succeeds");
            CheckEqual(result.groups.size(), std::size_t(2), L"two regions form two artifact evidence units");
            CheckEqual(result.summary.artifactGroupCount, std::size_t(2), L"artifact group count exact");
            CheckEqual(result.summary.distinctArtifactCount, std::size_t(2), L"distinct artifact count exact");
            CheckEqual(result.summary.artifactAttributeCount, std::size_t(4), L"artifact-level source attribute observations counted");
            const RefinedObservationGroup* firstRegion = FindArtifactGroup(
                result,
                EvidenceDomain::MemoryMetadata,
                ObservationArtifactKind::MemoryRegion,
                regionOne);
            Check(firstRegion != nullptr, L"first region artifact group retained");
            if (firstRegion != nullptr)
            {
                CheckEqual(firstRegion->members.size(), std::size_t(3), L"three properties share one artifact group");
                CheckEqual(firstRegion->artifactAttributeCount, std::size_t(3), L"same-artifact attribute count exact");
                const std::size_t attributeRoles =
                    static_cast<std::size_t>(std::count_if(
                        firstRegion->members.begin(),
                        firstRegion->members.end(),
                        [](const RefinedObservationMember& member)
                        {
                            return member.role ==
                                RefinedObservationRole::ArtifactAttribute;
                        }));
                CheckEqual(attributeRoles, std::size_t(2), L"only one region property is the artifact primary");
                for (const RefinedObservationMember& member :
                     firstRegion->members)
                {
                    Check(!EffectiveObservation(member).contributesToVerdict, L"static region property remains non-contributing context");
                }
            }
            CheckEqual(result.summary.contributingDomainCountBefore, std::size_t(0), L"static memory has no contributing domain before refinement");
            CheckEqual(result.summary.contributingDomainCountAfter, std::size_t(0), L"static memory has no contributing domain after refinement");
            Check(result.correlations.empty(), L"static memory attributes create no correlation preparation");
        }

        void TestTypedCorrelationPreparation()
        {
            ObservationRecord command = MakeNativeRecord(
                "encoded-command",
                EvidenceDomain::CommandLine,
                ObservationDisposition::ReviewRelevant,
                "encoded-command");
            command.observation.correlationKey =
                "command-relationship-context";
            ObservationRecord relationship = MakeNativeRecord(
                "verified-parent",
                EvidenceDomain::ProcessRelationship,
                ObservationDisposition::ReviewRelevant,
                "verified-parent");
            relationship.observation.correlationKey =
                "command-relationship-context";

            const ObservationRefinementResult result =
                RefineObservationInventory(MakeInventory({
                    command,
                    relationship
                }));
            Check(result.Succeeded(), L"typed correlation preparation succeeds");
            CheckEqual(result.correlations.size(), std::size_t(1), L"one correlation preparation emitted");
            if (!result.correlations.empty())
            {
                const ObservationCorrelationPreparation& correlation =
                    result.correlations.front();
                Check(correlation.requirementsKnown, L"native correlation requirements known");
                Check(!correlation.incomplete, L"independent typed domains complete correlation preparation");
                Check(HasDomain(correlation.availableSupportingDomains, EvidenceDomain::CommandLine), L"command domain retained in correlation preparation");
                Check(HasDomain(correlation.availableSupportingDomains, EvidenceDomain::ProcessRelationship), L"relationship domain retained in correlation preparation");
                CheckEqual(correlation.sourceObservationIds.size(), std::size_t(2), L"correlation participant identities retained");
            }
        }

        void TestCapsAndAtomicFailure()
        {
            ObservationRecord valid = MakeNativeRecord(
                "valid-before-invalid",
                EvidenceDomain::CommandLine,
                ObservationDisposition::ReviewRelevant,
                "valid-group");
            ObservationRecord invalid = MakeNativeRecord(
                "invalid-bounded-id",
                EvidenceDomain::FilePath,
                ObservationDisposition::Context,
                "invalid-group");
            invalid.observation.id.assign(
                ObservationIdMaxCharacters + 1,
                'x');
            const ObservationRefinementResult invalidResult =
                RefineObservationInventory(MakeInventory({ valid, invalid }));
            Check(!invalidResult.success, L"invalid bounded observation fails");
            CheckEqual(invalidResult.status, ObservationRefinementStatus::InvalidSourceObservation, L"invalid observation status exact");
            Check(invalidResult.groups.empty(), L"invalid observation returns no partial groups");
            Check(invalidResult.collectionNotes.empty(), L"invalid observation returns no partial collection notes");
            Check(invalidResult.evidenceIntegrityNotes.empty(), L"invalid observation returns no partial integrity notes");
            Check(invalidResult.correlations.empty(), L"invalid observation returns no partial correlations");

            ObservationRecord capped = MakeNativeRecord(
                "cap-record",
                EvidenceDomain::Runtime,
                ObservationDisposition::Context,
                "cap-group");
            std::vector<ObservationRecord> overCap(
                ObservationRefinementMaxSourceObservations + 1,
                capped);
            const ObservationRefinementResult capResult =
                RefineObservationInventory(MakeInventory(std::move(overCap)));
            Check(!capResult.success, L"source observation cap plus one fails");
            CheckEqual(capResult.status, ObservationRefinementStatus::SourceLimitExceeded, L"source cap failure status exact");
            CheckEqual(capResult.summary.rawObservationCount, ObservationRefinementMaxSourceObservations + 1, L"source cap diagnostic count exact");
            Check(capResult.groups.empty(), L"source cap failure is atomic");
            Check(capResult.collectionNotes.empty(), L"source cap failure emits no partial notes");
            Check(capResult.correlations.empty(), L"source cap failure emits no partial correlations");
        }

        ObservationRefinementResult RepresentativeDiagnosticResult()
        {
            ObservationRecord memory = MakeArtifactRecord(
                "diagnostic-memory",
                EvidenceDomain::MemoryMetadata,
                ObservationDisposition::Context,
                ObservationArtifactKind::MemoryRegion,
                "memory-region:diagnostic",
                "static-memory",
                ObservationArtifactAttributeMemoryExecutable);
            return RefineObservationInventory(MakeInventory({
                MakeNativeRecord(
                    "diagnostic-command",
                    EvidenceDomain::CommandLine,
                    ObservationDisposition::ReviewRelevant,
                    "command"),
                memory,
                MakeCollectionNote("diagnostic-unavailable"),
                MakeIntegrityNote("diagnostic-integrity")
            }));
        }
    }

    int RunObservationRefinementTests()
    {
        TestEmptyAndUnavailableInventory();
        TestContextCollectionAndIntegritySeparation();
        TestDeterministicGroupingAndOrder();
        TestExactDuplicateSuppressionPrefersNativeOrdinal();
        TestArtifactIdentityAndSameArtifactAttributes();
        TestTypedCorrelationPreparation();
        TestCapsAndAtomicFailure();

        const ObservationRefinementResult representative =
            RepresentativeDiagnosticResult();
        std::wcout
            << L"Observation refinement diagnostic: raw="
            << representative.summary.rawObservationCount
            << L", groups="
            << representative.summary.groupCount
            << L", artifacts="
            << representative.summary.distinctArtifactCount
            << L", domains="
            << representative.summary.contributingDomainCountAfter
            << L", duration-us="
            << representative.summary.refinementDurationMicroseconds
            << L".\n";

        return failureCount;
    }
}
