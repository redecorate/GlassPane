#include "Core/Observation.h"
#include "Core/ObservationPolicy.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <set>
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
        void CheckEqual(const Value& actual, const Value& expected, const wchar_t* testName)
        {
            Check(actual == expected, testName);
        }

        template <typename Enum>
        void CheckEnumValue(Enum actual, std::uint32_t expected, const wchar_t* testName)
        {
            CheckEqual(static_cast<std::uint32_t>(actual), expected, testName);
        }

        bool AllStringsBounded(
            const std::vector<std::string>& values,
            std::size_t maximumCharacters)
        {
            return std::all_of(
                values.begin(),
                values.end(),
                [maximumCharacters](const std::string& value)
                {
                    return value.size() <= maximumCharacters;
                });
        }

        Observation MakeObservation(
            std::string id,
            EvidenceDomain domain,
            ObservationDisposition disposition,
            ObservationStrength strength,
            bool contributesToVerdict = true)
        {
            Observation observation;
            observation.id = std::move(id);
            observation.ruleId = "generic-rule";
            observation.title = "Generic observation";
            observation.summary = "Deterministic evidence fixture";
            observation.domain = domain;
            observation.sourceKind = ObservationSourceKind::Derived;
            observation.disposition = disposition;
            observation.strength = strength;
            observation.confidence = ObservationConfidence::Medium;
            observation.contributesToVerdict = contributesToVerdict;
            observation.provenance.sourceKind = observation.sourceKind;
            observation.provenance.sourceIdentifier = "fixture-source";
            observation.provenance.collectionMethod = "fixed-input";
            observation.provenance.sourceAvailable = true;
            if (disposition == ObservationDisposition::SuppressedExpected)
            {
                observation.suppressionReason = "Expected evidence pattern";
            }
            return observation;
        }

        std::size_t CountGroupedSources(const ObservationGroupingResult& result)
        {
            std::size_t count = 0;
            for (const ObservationGroup& group : result.groups)
            {
                count += group.sourceObservations.size();
            }
            return count;
        }

        void TestDefaultsStableEnumsAndDisplayHelpers()
        {
            const Observation observation;
            Check(observation.id.empty(), L"default observation ID is empty");
            Check(observation.ruleId.empty(), L"default rule ID is empty");
            Check(observation.title.empty(), L"default title is empty");
            Check(observation.summary.empty(), L"default summary is empty");
            CheckEqual(observation.domain, EvidenceDomain::Unknown, L"default domain is unknown");
            CheckEqual(
                observation.sourceKind,
                ObservationSourceKind::Unverified,
                L"default source kind is unverified");
            CheckEqual(
                observation.disposition,
                ObservationDisposition::Informational,
                L"default disposition is informational");
            CheckEqual(observation.strength, ObservationStrength::None, L"default strength is none");
            CheckEqual(
                observation.confidence,
                ObservationConfidence::Unknown,
                L"default confidence is unknown");
            Check(!observation.contributesToVerdict, L"default observation does not contribute");
            Check(observation.entityScope.empty(), L"default entity scope is empty");
            Check(observation.groupingKey.empty(), L"default grouping key is empty");
            Check(observation.correlationKey.empty(), L"default correlation key is empty");
            Check(observation.suppressorId.empty(), L"default suppressor ID is empty");
            Check(observation.suppressionReason.empty(), L"default suppression reason is empty");
            Check(observation.rawValue.empty(), L"default raw value is empty");
            Check(observation.normalizedValue.empty(), L"default normalized value is empty");
            CheckEqual(
                observation.artifactIdentity.kind,
                ObservationArtifactKind::None,
                L"default artifact kind is none");
            Check(
                observation.artifactIdentity.entityScope.empty(),
                L"default artifact scope is empty");
            Check(
                observation.artifactIdentity.artifactKey.empty(),
                L"default artifact key is empty");
            Check(
                observation.artifactAttributes.empty(),
                L"default artifact attributes are empty");
            Check(observation.evidence.empty(), L"default evidence is empty");
            Check(observation.limitations.empty(), L"default limitations are empty");
            CheckEqual(
                observation.provenance.sourceKind,
                ObservationSourceKind::Unverified,
                L"default provenance source kind is unverified");
            Check(!observation.provenance.sourceAvailable, L"default source is unavailable");
            Check(
                observation.provenance.sourceIdentifier.empty(),
                L"default source identifier is empty");
            Check(
                observation.provenance.collectionMethod.empty(),
                L"default collection method is empty");
            Check(
                observation.provenance.collectionTimestamp.empty(),
                L"default collection timestamp is empty");
            Check(
                observation.provenance.requiredPrivilege.empty(),
                L"default required privilege is empty");
            Check(
                observation.provenance.limitations.empty(),
                L"default provenance limitations are empty");
            Check(
                observation.provenance.rawSourceReference.empty(),
                L"default raw source reference is empty");

            CheckEnumValue(EvidenceDomain::Unknown, 0, L"stable unknown domain value");
            CheckEnumValue(EvidenceDomain::ProcessIdentity, 1, L"stable process identity domain value");
            CheckEnumValue(EvidenceDomain::FilePath, 2, L"stable file path domain value");
            CheckEnumValue(EvidenceDomain::FileSignature, 3, L"stable file signature domain value");
            CheckEnumValue(EvidenceDomain::CommandLine, 4, L"stable command line domain value");
            CheckEnumValue(EvidenceDomain::ProcessRelationship, 5, L"stable relationship domain value");
            CheckEnumValue(EvidenceDomain::Network, 6, L"stable network domain value");
            CheckEnumValue(EvidenceDomain::Service, 7, L"stable service domain value");
            CheckEnumValue(EvidenceDomain::Module, 8, L"stable module domain value");
            CheckEnumValue(EvidenceDomain::Handle, 9, L"stable handle domain value");
            CheckEnumValue(EvidenceDomain::Runtime, 10, L"stable runtime domain value");
            CheckEnumValue(EvidenceDomain::MemoryMetadata, 11, L"stable memory domain value");
            CheckEnumValue(EvidenceDomain::Token, 12, L"stable token domain value");
            CheckEnumValue(EvidenceDomain::Persistence, 13, L"stable persistence domain value");
            CheckEnumValue(EvidenceDomain::CollectionQuality, 14, L"stable collection quality domain value");
            CheckEnumValue(EvidenceDomain::EvidenceIntegrity, 15, L"stable evidence integrity domain value");
            CheckEnumValue(EvidenceDomain::ImportedEvidence, 16, L"stable imported evidence domain value");

            CheckEnumValue(ObservationSourceKind::Direct, 0, L"stable direct source value");
            CheckEnumValue(ObservationSourceKind::Corroborated, 1, L"stable corroborated source value");
            CheckEnumValue(ObservationSourceKind::Derived, 2, L"stable derived source value");
            CheckEnumValue(ObservationSourceKind::Imported, 3, L"stable imported source value");
            CheckEnumValue(ObservationSourceKind::UserDefined, 4, L"stable user-defined source value");
            CheckEnumValue(ObservationSourceKind::Unverified, 5, L"stable unverified source value");
            CheckEnumValue(ObservationSourceKind::Unavailable, 6, L"stable unavailable source value");

            CheckEnumValue(ObservationDisposition::Informational, 0, L"stable informational disposition value");
            CheckEnumValue(ObservationDisposition::Context, 1, L"stable context disposition value");
            CheckEnumValue(ObservationDisposition::ReviewRelevant, 2, L"stable review disposition value");
            CheckEnumValue(ObservationDisposition::CorrelatedOnly, 3, L"stable correlated disposition value");
            CheckEnumValue(ObservationDisposition::CollectionNote, 4, L"stable collection note value");
            CheckEnumValue(ObservationDisposition::EvidenceIntegrityNote, 5, L"stable integrity note value");
            CheckEnumValue(ObservationDisposition::SuppressedExpected, 6, L"stable suppressed disposition value");

            CheckEnumValue(ObservationStrength::None, 0, L"stable none strength value");
            CheckEnumValue(ObservationStrength::Weak, 1, L"stable weak strength value");
            CheckEnumValue(ObservationStrength::Moderate, 2, L"stable moderate strength value");
            CheckEnumValue(ObservationStrength::Strong, 3, L"stable strong strength value");
            CheckEnumValue(ObservationConfidence::Unknown, 0, L"stable unknown confidence value");
            CheckEnumValue(ObservationConfidence::Low, 1, L"stable low confidence value");
            CheckEnumValue(ObservationConfidence::Medium, 2, L"stable medium confidence value");
            CheckEnumValue(ObservationConfidence::High, 3, L"stable high confidence value");
            CheckEnumValue(ObservationArtifactKind::None, 0, L"stable no-artifact value");
            CheckEnumValue(ObservationArtifactKind::Process, 1, L"stable process artifact value");
            CheckEnumValue(ObservationArtifactKind::File, 2, L"stable file artifact value");
            CheckEnumValue(ObservationArtifactKind::MemoryRegion, 3, L"stable memory-region artifact value");
            CheckEnumValue(ObservationArtifactKind::NetworkConnection, 4, L"stable network-connection artifact value");
            CheckEnumValue(ObservationArtifactKind::Service, 5, L"stable service artifact value");
            CheckEnumValue(ObservationArtifactKind::Handle, 6, L"stable handle artifact value");
            CheckEnumValue(ObservationArtifactKind::Module, 7, L"stable module artifact value");
            CheckEnumValue(ObservationArtifactKind::Token, 8, L"stable token artifact value");
            CheckEnumValue(ObservationArtifactKind::RuntimeObject, 9, L"stable runtime-object artifact value");

            CheckEqual(
                EvidenceDomainDisplayText(EvidenceDomain::ProcessRelationship),
                std::string("Process relationship"),
                L"domain display helper");
            CheckEqual(
                ObservationSourceKindDisplayText(ObservationSourceKind::UserDefined),
                std::string("User defined"),
                L"source display helper");
            CheckEqual(
                ObservationDispositionDisplayText(ObservationDisposition::CorrelatedOnly),
                std::string("Correlated only"),
                L"disposition display helper");
            CheckEqual(
                ObservationStrengthDisplayText(ObservationStrength::Moderate),
                std::string("Moderate"),
                L"strength display helper");
            CheckEqual(
                ObservationConfidenceDisplayText(ObservationConfidence::High),
                std::string("High"),
                L"confidence display helper");
            CheckEqual(
                ObservationArtifactKindDisplayText(
                    ObservationArtifactKind::MemoryRegion),
                std::string("Memory region"),
                L"artifact display helper");

            constexpr std::uint32_t unknownValue = 0xF00DBAAD;
            const std::string unknownText = "Unknown (0xF00DBAAD)";
            CheckEqual(
                EvidenceDomainDisplayText(static_cast<EvidenceDomain>(unknownValue)),
                unknownText,
                L"unknown domain remains visible");
            CheckEqual(
                ObservationSourceKindDisplayText(static_cast<ObservationSourceKind>(unknownValue)),
                unknownText,
                L"unknown source kind remains visible");
            CheckEqual(
                ObservationDispositionDisplayText(static_cast<ObservationDisposition>(unknownValue)),
                unknownText,
                L"unknown disposition remains visible");
            CheckEqual(
                ObservationStrengthDisplayText(static_cast<ObservationStrength>(unknownValue)),
                unknownText,
                L"unknown strength remains visible");
            CheckEqual(
                ObservationConfidenceDisplayText(static_cast<ObservationConfidence>(unknownValue)),
                unknownText,
                L"unknown confidence remains visible");
            CheckEqual(
                ObservationArtifactKindDisplayText(
                    static_cast<ObservationArtifactKind>(unknownValue)),
                unknownText,
                L"unknown artifact kind remains visible");
            CheckEqual(
                EvidenceDomainToString(static_cast<EvidenceDomain>(unknownValue)),
                unknownText,
                L"domain string helper preserves unknown value");
            CheckEqual(
                ObservationSourceKindToString(ObservationSourceKind::Imported),
                ObservationSourceKindDisplayText(ObservationSourceKind::Imported),
                L"source string helper matches display helper");
            CheckEqual(
                ObservationDispositionToString(ObservationDisposition::Context),
                ObservationDispositionDisplayText(ObservationDisposition::Context),
                L"disposition string helper matches display helper");
            CheckEqual(
                ObservationStrengthToString(ObservationStrength::Weak),
                ObservationStrengthDisplayText(ObservationStrength::Weak),
                L"strength string helper matches display helper");
            CheckEqual(
                ObservationConfidenceToString(ObservationConfidence::Low),
                ObservationConfidenceDisplayText(ObservationConfidence::Low),
                L"confidence string helper matches display helper");
            CheckEqual(
                ObservationArtifactKindToString(ObservationArtifactKind::Service),
                ObservationArtifactKindDisplayText(ObservationArtifactKind::Service),
                L"artifact string helper matches display helper");
            CheckEqual(
                ObservationValidationIssueDisplayText(
                    static_cast<ObservationValidationIssue>(unknownValue)),
                std::string("Unknown validation issue (0xF00DBAAD)"),
                L"unknown validation issue remains visible");
        }

        void TestCapsNormalizationAndValueCopying()
        {
            CheckEqual(ObservationIdMaxCharacters, std::size_t(128), L"observation ID cap");
            CheckEqual(ObservationRuleIdMaxCharacters, std::size_t(128), L"rule ID cap");
            CheckEqual(ObservationTitleMaxCharacters, std::size_t(256), L"title cap");
            CheckEqual(ObservationSummaryMaxCharacters, std::size_t(1024), L"summary cap");
            CheckEqual(ObservationEntityScopeMaxCharacters, std::size_t(128), L"entity scope cap");
            CheckEqual(ObservationGroupingKeyMaxCharacters, std::size_t(128), L"grouping key cap");
            CheckEqual(ObservationCorrelationKeyMaxCharacters, std::size_t(128), L"correlation key cap");
            CheckEqual(ObservationSuppressionReasonMaxCharacters, std::size_t(1024), L"suppression reason cap");
            CheckEqual(ObservationRawValueMaxCharacters, std::size_t(4096), L"raw value cap");
            CheckEqual(ObservationNormalizedValueMaxCharacters, std::size_t(4096), L"normalized value cap");
            CheckEqual(ObservationEvidenceItemMaxCharacters, std::size_t(1024), L"evidence item cap");
            CheckEqual(ObservationLimitationItemMaxCharacters, std::size_t(1024), L"limitation item cap");
            CheckEqual(ObservationMaxEvidenceItems, std::size_t(64), L"evidence count cap");
            CheckEqual(ObservationMaxLimitationItems, std::size_t(32), L"limitation count cap");
            CheckEqual(
                ObservationProvenanceSourceIdentifierMaxCharacters,
                std::size_t(512),
                L"provenance source identifier cap");
            CheckEqual(
                ObservationProvenanceCollectionMethodMaxCharacters,
                std::size_t(512),
                L"provenance collection method cap");
            CheckEqual(
                ObservationProvenanceCollectionTimestampMaxCharacters,
                std::size_t(128),
                L"provenance timestamp cap");
            CheckEqual(
                ObservationProvenanceRequiredPrivilegeMaxCharacters,
                std::size_t(512),
                L"provenance privilege cap");
            CheckEqual(
                ObservationProvenanceRawSourceReferenceMaxCharacters,
                std::size_t(1024),
                L"provenance raw reference cap");
            CheckEqual(
                ObservationProvenanceLimitationItemMaxCharacters,
                std::size_t(1024),
                L"provenance limitation item cap");
            CheckEqual(
                ObservationProvenanceMaxLimitationItems,
                std::size_t(32),
                L"provenance limitation count cap");
            CheckEqual(ObservationSuppressorIdMaxCharacters, std::size_t(128), L"suppressor ID cap");
            CheckEqual(ObservationArtifactEntityScopeMaxCharacters, std::size_t(128), L"artifact entity-scope cap");
            CheckEqual(ObservationArtifactKeyMaxCharacters, std::size_t(256), L"artifact key cap");
            CheckEqual(ObservationArtifactAttributeKeyMaxCharacters, std::size_t(128), L"artifact attribute-key cap");
            CheckEqual(ObservationArtifactAttributeValueMaxCharacters, std::size_t(1024), L"artifact attribute-value cap");
            CheckEqual(ObservationMaxArtifactAttributes, std::size_t(64), L"artifact attribute-count cap");
            CheckEqual(
                ObservationGroupingMaxSourceObservations,
                std::size_t(4096),
                L"grouping source count cap");

            Observation original = MakeObservation(
                "copy-source",
                EvidenceDomain::FilePath,
                ObservationDisposition::ReviewRelevant,
                ObservationStrength::Weak);
            original.rawValue = "raw-source-value";
            original.evidence = { "evidence-one", "evidence-two" };
            original.limitations = { "limitation-one" };
            original.provenance.limitations = { "provenance-limitation" };
            original.provenance.rawSourceReference = "raw-source-reference";
            original.entityScope = "process:artifact-copy";
            original.artifactIdentity = {
                ObservationArtifactKind::File,
                original.entityScope,
                "file:generic-copy"
            };
            original.artifactAttributes = {{ "signature.state", "invalid" }};

            Observation copied = original;
            copied.id = "copy-mutated";
            copied.evidence[0] = "mutated-evidence";
            copied.limitations[0] = "mutated-limitation";
            copied.provenance.sourceIdentifier = "mutated-source";
            copied.provenance.limitations[0] = "mutated-provenance-limitation";
            copied.artifactIdentity.artifactKey = "file:mutated";
            copied.artifactAttributes[0].value = "mutated";
            CheckEqual(original.id, std::string("copy-source"), L"copy does not alias ID");
            CheckEqual(original.evidence[0], std::string("evidence-one"), L"copy does not alias evidence");
            CheckEqual(original.limitations[0], std::string("limitation-one"), L"copy does not alias limitations");
            CheckEqual(
                original.provenance.sourceIdentifier,
                std::string("fixture-source"),
                L"copy does not alias provenance strings");
            CheckEqual(
                original.provenance.limitations[0],
                std::string("provenance-limitation"),
                L"copy does not alias provenance limitations");
            CheckEqual(
                original.artifactIdentity.artifactKey,
                std::string("file:generic-copy"),
                L"copy does not alias artifact identity");
            CheckEqual(
                original.artifactAttributes[0].value,
                std::string("invalid"),
                L"copy does not alias artifact attributes");

            Observation oversized = MakeObservation(
                std::string(ObservationIdMaxCharacters + 1, 'I'),
                EvidenceDomain::ProcessIdentity,
                ObservationDisposition::SuppressedExpected,
                ObservationStrength::Strong,
                false);
            oversized.ruleId.assign(ObservationRuleIdMaxCharacters + 1, 'R');
            oversized.title.assign(ObservationTitleMaxCharacters + 1, 'T');
            oversized.summary.assign(ObservationSummaryMaxCharacters + 1, 'S');
            oversized.entityScope.assign(ObservationEntityScopeMaxCharacters + 1, 'O');
            oversized.groupingKey.assign(ObservationGroupingKeyMaxCharacters + 1, 'G');
            oversized.correlationKey.assign(ObservationCorrelationKeyMaxCharacters + 1, 'C');
            oversized.suppressorId.assign(ObservationSuppressorIdMaxCharacters + 1, 'U');
            oversized.suppressionReason.assign(ObservationSuppressionReasonMaxCharacters + 1, 'P');
            oversized.rawValue.assign(ObservationRawValueMaxCharacters + 1, 'V');
            oversized.normalizedValue.assign(ObservationNormalizedValueMaxCharacters + 1, 'N');
            oversized.evidence.assign(
                ObservationMaxEvidenceItems + 1,
                std::string(ObservationEvidenceItemMaxCharacters + 1, 'E'));
            oversized.limitations.assign(
                ObservationMaxLimitationItems + 1,
                std::string(ObservationLimitationItemMaxCharacters + 1, 'L'));
            oversized.provenance.sourceIdentifier.assign(
                ObservationProvenanceSourceIdentifierMaxCharacters + 1,
                'A');
            oversized.provenance.collectionMethod.assign(
                ObservationProvenanceCollectionMethodMaxCharacters + 1,
                'M');
            oversized.provenance.collectionTimestamp.assign(
                ObservationProvenanceCollectionTimestampMaxCharacters + 1,
                'D');
            oversized.provenance.requiredPrivilege.assign(
                ObservationProvenanceRequiredPrivilegeMaxCharacters + 1,
                'Q');
            oversized.provenance.limitations.assign(
                ObservationMaxLimitationItems + 1,
                std::string(ObservationLimitationItemMaxCharacters + 1, 'K'));
            oversized.provenance.rawSourceReference.assign(
                ObservationProvenanceRawSourceReferenceMaxCharacters + 1,
                'F');

            const ObservationValidationResult oversizedValidation =
                ValidateObservation(oversized);
            Check(!oversizedValidation.IsValid(), L"oversized observation is rejected by validation");
            Check(
                oversizedValidation.HasIssue(ObservationValidationIssue::IdTooLong),
                L"oversized observation reports ID cap");
            Check(
                oversizedValidation.HasIssue(ObservationValidationIssue::TooManyEvidenceItems),
                L"oversized observation reports evidence count cap");
            Check(
                oversizedValidation.HasIssue(
                    ObservationValidationIssue::TooManyProvenanceLimitationItems),
                L"oversized observation reports provenance limitation count cap");

            const Observation normalized = NormalizeObservationPolicy(oversized);
            CheckEqual(normalized.id.size(), ObservationIdMaxCharacters, L"normalized ID is capped");
            CheckEqual(normalized.ruleId.size(), ObservationRuleIdMaxCharacters, L"normalized rule ID is capped");
            CheckEqual(normalized.title.size(), ObservationTitleMaxCharacters, L"normalized title is capped");
            CheckEqual(normalized.summary.size(), ObservationSummaryMaxCharacters, L"normalized summary is capped");
            CheckEqual(normalized.entityScope.size(), ObservationEntityScopeMaxCharacters, L"normalized entity scope is capped");
            CheckEqual(normalized.groupingKey.size(), ObservationGroupingKeyMaxCharacters, L"normalized grouping key is capped");
            CheckEqual(normalized.correlationKey.size(), ObservationCorrelationKeyMaxCharacters, L"normalized correlation key is capped");
            CheckEqual(normalized.suppressorId.size(), ObservationSuppressorIdMaxCharacters, L"normalized suppressor ID is capped");
            CheckEqual(normalized.suppressionReason.size(), ObservationSuppressionReasonMaxCharacters, L"normalized suppression reason is capped");
            CheckEqual(normalized.rawValue.size(), ObservationRawValueMaxCharacters, L"normalized raw value is capped");
            CheckEqual(normalized.normalizedValue.size(), ObservationNormalizedValueMaxCharacters, L"normalized value is capped");
            CheckEqual(normalized.evidence.size(), ObservationMaxEvidenceItems, L"normalized evidence count is capped");
            Check(
                AllStringsBounded(normalized.evidence, ObservationEvidenceItemMaxCharacters),
                L"normalized evidence items are capped");
            CheckEqual(normalized.limitations.size(), ObservationMaxLimitationItems, L"normalized limitation count is capped");
            Check(
                AllStringsBounded(normalized.limitations, ObservationLimitationItemMaxCharacters),
                L"normalized limitation items are capped");
            CheckEqual(
                normalized.provenance.sourceIdentifier.size(),
                ObservationProvenanceSourceIdentifierMaxCharacters,
                L"normalized provenance source identifier is capped");
            CheckEqual(
                normalized.provenance.collectionMethod.size(),
                ObservationProvenanceCollectionMethodMaxCharacters,
                L"normalized provenance method is capped");
            CheckEqual(
                normalized.provenance.collectionTimestamp.size(),
                ObservationProvenanceCollectionTimestampMaxCharacters,
                L"normalized provenance timestamp is capped");
            CheckEqual(
                normalized.provenance.requiredPrivilege.size(),
                ObservationProvenanceRequiredPrivilegeMaxCharacters,
                L"normalized provenance privilege is capped");
            CheckEqual(
                normalized.provenance.limitations.size(),
                ObservationMaxLimitationItems,
                L"normalized provenance limitation count is capped");
            Check(
                AllStringsBounded(
                    normalized.provenance.limitations,
                    ObservationLimitationItemMaxCharacters),
                L"normalized provenance limitations are capped");
            CheckEqual(
                normalized.provenance.rawSourceReference.size(),
                ObservationProvenanceRawSourceReferenceMaxCharacters,
                L"normalized provenance raw reference is capped");
            Check(ValidateObservation(normalized).IsValid(), L"normalized bounded observation validates");
        }

        void TestArtifactIdentityContract()
        {
            Observation observation = MakeObservation(
                "artifact-observation",
                EvidenceDomain::MemoryMetadata,
                ObservationDisposition::ReviewRelevant,
                ObservationStrength::Weak);
            observation.entityScope = "process:artifact-entity";
            observation.artifactIdentity = {
                ObservationArtifactKind::MemoryRegion,
                observation.entityScope,
                "base:1000/allocation:1000/size:4096"
            };
            observation.artifactAttributes = {
                { "memory.executable", "true" },
                { "memory.private", "true" }
            };
            Check(
                HasCompleteObservationArtifactIdentity(
                    observation.artifactIdentity),
                L"bounded artifact identity is complete");
            Check(
                HasObservationArtifactIdentity(observation),
                L"observation artifact scope matches containing entity");
            Check(
                ValidateObservation(observation).IsValid(),
                L"bounded artifact observation validates");

            for (const ObservationArtifactKind kind : {
                     ObservationArtifactKind::Process,
                     ObservationArtifactKind::File,
                     ObservationArtifactKind::MemoryRegion,
                     ObservationArtifactKind::NetworkConnection,
                     ObservationArtifactKind::Service,
                     ObservationArtifactKind::Handle,
                     ObservationArtifactKind::Module,
                     ObservationArtifactKind::Token,
                     ObservationArtifactKind::RuntimeObject })
            {
                ObservationArtifactIdentity identity{
                    kind,
                    "process:generic-artifact-scope",
                    "typed-artifact-key"
                };
                Check(
                    HasCompleteObservationArtifactIdentity(identity),
                    L"every modeled artifact kind supports bounded identity");
            }

            Observation mismatch = observation;
            mismatch.artifactIdentity.entityScope = "process:other-entity";
            Check(
                ValidateObservation(mismatch).HasIssue(
                    ObservationValidationIssue::ArtifactEntityScopeMismatch),
                L"cross-entity artifact identity is rejected");
            Check(
                !HasObservationArtifactIdentity(mismatch),
                L"cross-entity artifact identity is not considered present");

            Observation attributesWithoutIdentity = observation;
            attributesWithoutIdentity.artifactIdentity = {};
            Check(
                ValidateObservation(attributesWithoutIdentity).HasIssue(
                    ObservationValidationIssue::ArtifactAttributesRequireIdentity),
                L"attributes without identity are rejected");

            Observation duplicateAttribute = observation;
            duplicateAttribute.artifactAttributes.push_back(
                duplicateAttribute.artifactAttributes.front());
            Check(
                ValidateObservation(duplicateAttribute).HasIssue(
                    ObservationValidationIssue::ArtifactAttributeKeyDuplicate),
                L"duplicate artifact attribute keys are rejected");

            Observation oversizedIdentity = observation;
            oversizedIdentity.artifactIdentity.artifactKey.assign(
                ObservationArtifactKeyMaxCharacters + 1,
                'A');
            const ObservationValidationResult oversizedValidation =
                ValidateObservation(oversizedIdentity);
            Check(
                oversizedValidation.HasIssue(
                    ObservationValidationIssue::ArtifactKeyTooLong),
                L"oversized artifact key is rejected");
            const Observation normalized = NormalizeObservationPolicy(
                oversizedIdentity);
            Check(
                !HasObservationArtifactIdentity(normalized),
                L"oversized artifact identity is cleared rather than truncated");
            Check(
                normalized.artifactAttributes.empty(),
                L"attributes are cleared with invalid artifact identity");
            Check(
                std::any_of(
                    normalized.limitations.begin(),
                    normalized.limitations.end(),
                    [](const std::string& limitation)
                    {
                        return limitation.find("Artifact identity metadata") !=
                            std::string::npos;
                    }),
                L"artifact normalization records a bounded limitation");
            Check(
                ValidateObservation(normalized).IsValid(),
                L"cleared artifact metadata leaves a valid observation");

            Observation secondOversizedIdentity = observation;
            secondOversizedIdentity.artifactIdentity.artifactKey.assign(
                ObservationArtifactKeyMaxCharacters,
                'A');
            secondOversizedIdentity.artifactIdentity.artifactKey.push_back('B');
            const Observation secondNormalized = NormalizeObservationPolicy(
                secondOversizedIdentity);
            Check(
                normalized.artifactIdentity.artifactKey.empty() &&
                    secondNormalized.artifactIdentity.artifactKey.empty(),
                L"oversized keys are never truncated into a colliding identity");

            Observation tooManyAttributes = observation;
            tooManyAttributes.artifactAttributes.clear();
            for (std::size_t index = 0;
                 index <= ObservationMaxArtifactAttributes;
                 ++index)
            {
                tooManyAttributes.artifactAttributes.push_back({
                    "attribute:" + std::to_string(index),
                    "value"
                });
            }
            Check(
                ValidateObservation(tooManyAttributes).HasIssue(
                    ObservationValidationIssue::TooManyArtifactAttributes),
                L"artifact attribute count cap is enforced");
            Check(
                NormalizeObservationPolicy(tooManyAttributes).
                    artifactAttributes.empty(),
                L"over-cap artifact attributes are cleared conservatively");
        }

        void TestDispositionAndContributionPolicy()
        {
            const auto CheckCannotContribute =
                [](ObservationDisposition disposition, const wchar_t* testName)
                {
                    Observation observation = MakeObservation(
                        "non-contributing-disposition",
                        EvidenceDomain::ProcessIdentity,
                        disposition,
                        ObservationStrength::Strong,
                        true);
                    const ObservationValidationResult validation = ValidateObservation(observation);
                    Check(!validation.IsValid(), testName);
                    Check(
                        validation.HasIssue(
                            ObservationValidationIssue::VerdictContributionIncompatibleDisposition),
                        testName);
                    Check(!CanContributeToVerdict(observation), testName);
                    const Observation normalized = NormalizeObservationPolicy(observation);
                    Check(!normalized.contributesToVerdict, testName);
                    Check(ValidateObservation(normalized).IsValid(), testName);
                };

            CheckCannotContribute(
                ObservationDisposition::CollectionNote,
                L"collection notes cannot contribute");
            CheckCannotContribute(
                ObservationDisposition::SuppressedExpected,
                L"suppressed expected observations cannot contribute");
            CheckCannotContribute(
                ObservationDisposition::Informational,
                L"informational observations default to no contribution");
            CheckCannotContribute(
                ObservationDisposition::Context,
                L"context observations default to no contribution");
            CheckCannotContribute(
                ObservationDisposition::CorrelatedOnly,
                L"correlated-only observations cannot independently contribute");
            CheckCannotContribute(
                ObservationDisposition::EvidenceIntegrityNote,
                L"evidence integrity notes do not automatically contribute");

            for (const ObservationStrength strength : {
                     ObservationStrength::Weak,
                     ObservationStrength::Moderate,
                     ObservationStrength::Strong })
            {
                Observation review = MakeObservation(
                    "review-strength",
                    EvidenceDomain::FileSignature,
                    ObservationDisposition::ReviewRelevant,
                    strength,
                    true);
                Check(ValidateObservation(review).IsValid(), L"review-relevant strength validates");
                Check(CanContributeToVerdict(review), L"review-relevant strength may contribute");
                const Observation normalized = NormalizeObservationPolicy(review);
                Check(normalized.contributesToVerdict, L"normalization retains valid review contribution");
                CheckEqual(normalized.strength, strength, L"normalization retains review strength");
            }

            Observation noStrength = MakeObservation(
                "none-strength",
                EvidenceDomain::FilePath,
                ObservationDisposition::ReviewRelevant,
                ObservationStrength::None,
                true);
            Check(
                ValidateObservation(noStrength).HasIssue(
                    ObservationValidationIssue::VerdictContributionRequiresStrength),
                L"none strength contribution is rejected");
            Check(!CanContributeToVerdict(noStrength), L"none strength cannot contribute");
            Check(
                !NormalizeObservationPolicy(noStrength).contributesToVerdict,
                L"none strength contribution is normalized away");

            Observation unknownDomain = MakeObservation(
                "unknown-domain",
                EvidenceDomain::Unknown,
                ObservationDisposition::ReviewRelevant,
                ObservationStrength::Strong,
                true);
            Check(
                ValidateObservation(unknownDomain).HasIssue(
                    ObservationValidationIssue::VerdictContributionRequiresKnownDomain),
                L"unknown domain contribution is rejected");
            Check(!CanContributeToVerdict(unknownDomain), L"unknown domain cannot contribute");
            Check(
                !NormalizeObservationPolicy(unknownDomain).contributesToVerdict,
                L"unknown domain contribution is normalized away");

            Observation unmodeledDomain = unknownDomain;
            unmodeledDomain.domain = static_cast<EvidenceDomain>(0xF00DBAAD);
            Check(
                ValidateObservation(unmodeledDomain).HasIssue(
                    ObservationValidationIssue::VerdictContributionRequiresKnownDomain),
                L"unmodeled domain contribution is rejected");
            Check(!CanContributeToVerdict(unmodeledDomain), L"unmodeled domain cannot contribute");

            for (const EvidenceDomain excludedDomain : {
                     EvidenceDomain::CollectionQuality,
                     EvidenceDomain::EvidenceIntegrity })
            {
                Observation excluded = MakeObservation(
                    "excluded-domain",
                    excludedDomain,
                    ObservationDisposition::ReviewRelevant,
                    ObservationStrength::Strong,
                    true);
                Check(
                    ValidateObservation(excluded).HasIssue(
                        ObservationValidationIssue::VerdictContributionExcludedDomain),
                    L"quality domain contribution is rejected");
                Check(!CanContributeToVerdict(excluded), L"quality domain cannot contribute");
                Check(
                    !NormalizeObservationPolicy(excluded).contributesToVerdict,
                    L"quality domain contribution is normalized away");
            }

            Observation highConfidenceWeak = MakeObservation(
                "high-confidence-weak",
                EvidenceDomain::Runtime,
                ObservationDisposition::ReviewRelevant,
                ObservationStrength::Weak,
                true);
            highConfidenceWeak.confidence = ObservationConfidence::High;
            const Observation normalizedHighConfidence =
                NormalizeObservationPolicy(highConfidenceWeak);
            CheckEqual(
                normalizedHighConfidence.confidence,
                ObservationConfidence::High,
                L"normalization retains high observation confidence");
            CheckEqual(
                normalizedHighConfidence.strength,
                ObservationStrength::Weak,
                L"high confidence does not imply strong evidence");

            Observation lowConfidenceStrong = highConfidenceWeak;
            lowConfidenceStrong.confidence = ObservationConfidence::Low;
            lowConfidenceStrong.strength = ObservationStrength::Strong;
            const Observation normalizedLowConfidence =
                NormalizeObservationPolicy(lowConfidenceStrong);
            CheckEqual(
                normalizedLowConfidence.confidence,
                ObservationConfidence::Low,
                L"normalization retains low observation confidence");
            CheckEqual(
                normalizedLowConfidence.strength,
                ObservationStrength::Strong,
                L"low confidence remains independent from strong evidence");

            Observation mismatchedSource = highConfidenceWeak;
            mismatchedSource.provenance.sourceKind = ObservationSourceKind::Direct;
            Check(
                ValidateObservation(mismatchedSource).HasIssue(
                    ObservationValidationIssue::SourceKindMismatch),
                L"source kind mismatch is explicit");
            const Observation normalizedMismatch = NormalizeObservationPolicy(mismatchedSource);
            CheckEqual(
                normalizedMismatch.sourceKind,
                ObservationSourceKind::Derived,
                L"normalization does not infer source kind");
            CheckEqual(
                normalizedMismatch.provenance.sourceKind,
                ObservationSourceKind::Direct,
                L"normalization does not rewrite provenance source kind");
        }

        void TestDomainIndependenceAndQualitySeparation()
        {
            std::vector<Observation> repeatedDomain;
            for (int index = 0; index < 5; ++index)
            {
                repeatedDomain.push_back(MakeObservation(
                    "same-domain-" + std::to_string(index),
                    EvidenceDomain::Handle,
                    ObservationDisposition::ReviewRelevant,
                    ObservationStrength::Weak,
                    true));
            }
            const std::set<EvidenceDomain> oneDomain =
                CollectContributingDomains(repeatedDomain);
            CheckEqual(oneDomain.size(), std::size_t(1), L"five observations in one domain count once");
            Check(oneDomain.count(EvidenceDomain::Handle) == 1, L"repeated domain is retained once");

            std::vector<Observation> independentDomains = {
                MakeObservation(
                    "domain-one",
                    EvidenceDomain::FilePath,
                    ObservationDisposition::ReviewRelevant,
                    ObservationStrength::Moderate,
                    true),
                MakeObservation(
                    "domain-two",
                    EvidenceDomain::Network,
                    ObservationDisposition::ReviewRelevant,
                    ObservationStrength::Moderate,
                    true)
            };
            const std::set<EvidenceDomain> twoDomains =
                CollectContributingDomains(independentDomains);
            CheckEqual(twoDomains.size(), std::size_t(2), L"two independent domains count twice");
            Check(twoDomains.count(EvidenceDomain::FilePath) == 1, L"first independent domain retained");
            Check(twoDomains.count(EvidenceDomain::Network) == 1, L"second independent domain retained");

            std::vector<Observation> separatedQuality = independentDomains;
            separatedQuality.push_back(MakeObservation(
                "collection-quality",
                EvidenceDomain::CollectionQuality,
                ObservationDisposition::CollectionNote,
                ObservationStrength::Strong,
                true));
            separatedQuality.push_back(MakeObservation(
                "integrity-quality-one",
                EvidenceDomain::EvidenceIntegrity,
                ObservationDisposition::EvidenceIntegrityNote,
                ObservationStrength::Strong,
                true));
            separatedQuality.push_back(MakeObservation(
                "integrity-quality-two",
                EvidenceDomain::EvidenceIntegrity,
                ObservationDisposition::EvidenceIntegrityNote,
                ObservationStrength::None,
                false));
            const ObservationDomainSummary qualitySummary =
                SummarizeObservationDomains(separatedQuality);
            CheckEqual(
                qualitySummary.contributingDomains.size(),
                std::size_t(2),
                L"quality domains are excluded from contributing domains");
            CheckEqual(
                qualitySummary.collectionQualityObservationCount,
                std::size_t(1),
                L"collection quality is counted separately");
            CheckEqual(
                qualitySummary.evidenceIntegrityObservationCount,
                std::size_t(2),
                L"evidence integrity is counted separately");
            Check(
                qualitySummary.contributingDomains.count(EvidenceDomain::CollectionQuality) == 0,
                L"collection quality is absent from reinforcing domains");
            Check(
                qualitySummary.contributingDomains.count(EvidenceDomain::EvidenceIntegrity) == 0,
                L"evidence integrity is absent from reinforcing domains");

            std::vector<Observation> excludedDispositions = {
                MakeObservation(
                    "suppressed-domain",
                    EvidenceDomain::CommandLine,
                    ObservationDisposition::SuppressedExpected,
                    ObservationStrength::Strong,
                    true),
                MakeObservation(
                    "collection-note-domain",
                    EvidenceDomain::Service,
                    ObservationDisposition::CollectionNote,
                    ObservationStrength::Strong,
                    true),
                MakeObservation(
                    "informational-domain",
                    EvidenceDomain::Module,
                    ObservationDisposition::Informational,
                    ObservationStrength::Strong,
                    true),
                MakeObservation(
                    "context-domain",
                    EvidenceDomain::Token,
                    ObservationDisposition::Context,
                    ObservationStrength::Strong,
                    true),
                MakeObservation(
                    "correlated-domain",
                    EvidenceDomain::Persistence,
                    ObservationDisposition::CorrelatedOnly,
                    ObservationStrength::Strong,
                    true)
            };
            Check(
                CollectContributingDomains(excludedDispositions).empty(),
                L"non-independent dispositions do not reinforce domains");
        }

        void TestGroupingDeduplicationAndBounds()
        {
            std::vector<Observation> sharedGroup;
            for (int index = 0; index < 5; ++index)
            {
                Observation observation = MakeObservation(
                    "group-source-" + std::to_string(index),
                    EvidenceDomain::Handle,
                    ObservationDisposition::ReviewRelevant,
                    ObservationStrength::Weak,
                    true);
                observation.groupingKey = "shared-evidence-pattern";
                observation.entityScope = "selected-entity";
                observation.rawValue = "source-raw-" + std::to_string(index);
                observation.evidence = { "source-evidence-" + std::to_string(index) };
                observation.limitations = { "source-limitation-" + std::to_string(index) };
                observation.provenance.limitations = {
                    "provenance-limitation-" + std::to_string(index)
                };
                sharedGroup.push_back(std::move(observation));
            }

            const ObservationGroupingResult grouped = GroupObservations(sharedGroup);
            Check(grouped.Succeeded(), L"bounded grouping succeeds");
            CheckEqual(grouped.groups.size(), std::size_t(1), L"same nonempty key forms one group");
            CheckEqual(CountGroupedSources(grouped), std::size_t(5), L"grouping preserves every source");
            Check(!grouped.HasDuplicateIds(), L"unique source IDs are not duplicates");
            if (!grouped.groups.empty())
            {
                const ObservationGroup& group = grouped.groups[0];
                CheckEqual(
                    group.entityScope,
                    std::string("selected-entity"),
                    L"entity scope is retained");
                CheckEqual(
                    group.groupingKey,
                    std::string("shared-evidence-pattern"),
                    L"grouping key is retained");
                CheckEqual(group.sourceObservations.size(), std::size_t(5), L"all grouped sources remain available");
                for (std::size_t index = 0; index < group.sourceObservations.size(); ++index)
                {
                    const Observation& source = group.sourceObservations[index];
                    CheckEqual(
                        source.id,
                        "group-source-" + std::to_string(index),
                        L"source order is deterministic");
                    CheckEqual(
                        source.strength,
                        ObservationStrength::Weak,
                        L"repeated observations do not increase strength");
                    CheckEqual(source.evidence.size(), std::size_t(1), L"grouping retains source evidence");
                    CheckEqual(source.limitations.size(), std::size_t(1), L"grouping retains source limitations");
                    CheckEqual(
                        source.provenance.limitations.size(),
                        std::size_t(1),
                        L"grouping retains provenance limitations");
                }
            }

            Observation firstKey = sharedGroup[0];
            firstKey.id = "first-key";
            firstKey.groupingKey = "key-one";
            Observation secondKey = sharedGroup[1];
            secondKey.id = "second-key";
            secondKey.groupingKey = "key-two";
            Observation firstKeyAgain = sharedGroup[2];
            firstKeyAgain.id = "first-key-again";
            firstKeyAgain.groupingKey = "key-one";
            const ObservationGroupingResult distinct =
                GroupObservations({ firstKey, secondKey, firstKeyAgain });
            Check(distinct.Succeeded(), L"distinct-key grouping succeeds");
            CheckEqual(distinct.groups.size(), std::size_t(2), L"different keys remain separate");
            if (distinct.groups.size() == 2)
            {
                CheckEqual(distinct.groups[0].groupingKey, std::string("key-one"), L"first group order is stable");
                CheckEqual(distinct.groups[0].sourceObservations.size(), std::size_t(2), L"repeated first key groups together");
                CheckEqual(distinct.groups[1].groupingKey, std::string("key-two"), L"second group order is stable");
                CheckEqual(distinct.groups[1].sourceObservations.size(), std::size_t(1), L"second key remains separate");
            }

            Observation otherScope = firstKey;
            otherScope.id = "other-scope";
            otherScope.entityScope = "other-entity";
            otherScope.groupingKey = "key-one";
            const ObservationGroupingResult isolatedScopes =
                GroupObservations({ firstKey, otherScope });
            CheckEqual(
                isolatedScopes.groups.size(),
                std::size_t(2),
                L"matching keys in different entity scopes remain separate");
            if (isolatedScopes.groups.size() == 2)
            {
                CheckEqual(
                    isolatedScopes.groups[0].entityScope,
                    std::string("selected-entity"),
                    L"first entity scope remains isolated");
                CheckEqual(
                    isolatedScopes.groups[1].entityScope,
                    std::string("other-entity"),
                    L"second entity scope remains isolated");
            }

            Observation emptyScopeOne = firstKey;
            emptyScopeOne.id = "empty-scope-one";
            emptyScopeOne.entityScope.clear();
            Observation emptyScopeTwo = firstKeyAgain;
            emptyScopeTwo.id = "empty-scope-two";
            emptyScopeTwo.entityScope.clear();
            const ObservationGroupingResult emptyScopes =
                GroupObservations({ emptyScopeOne, emptyScopeTwo });
            CheckEqual(
                emptyScopes.groups.size(),
                std::size_t(2),
                L"empty entity scopes are not automatically grouped");
            CheckEqual(
                CountGroupedSources(emptyScopes),
                std::size_t(2),
                L"empty-scope sources remain available");

            Observation emptyOne = firstKey;
            emptyOne.id = "empty-key-one";
            emptyOne.groupingKey.clear();
            Observation emptyTwo = secondKey;
            emptyTwo.id = "empty-key-two";
            emptyTwo.groupingKey.clear();
            const ObservationGroupingResult emptyKeys =
                GroupObservations({ emptyOne, emptyTwo });
            CheckEqual(emptyKeys.groups.size(), std::size_t(2), L"empty keys are not automatically grouped");
            CheckEqual(CountGroupedSources(emptyKeys), std::size_t(2), L"empty-key sources remain available");
            if (emptyKeys.groups.size() == 2)
            {
                Check(emptyKeys.groups[0].groupingKey.empty(), L"first empty grouping key remains empty");
                Check(emptyKeys.groups[1].groupingKey.empty(), L"second empty grouping key remains empty");
                CheckEqual(emptyKeys.groups[0].sourceObservations.size(), std::size_t(1), L"first empty key has one source");
                CheckEqual(emptyKeys.groups[1].sourceObservations.size(), std::size_t(1), L"second empty key has one source");
            }

            std::vector<Observation> duplicates;
            for (const std::string& id : { std::string("id-z"), std::string("id-a"),
                                          std::string("id-z"), std::string("id-a"),
                                          std::string("id-z"), std::string(), std::string() })
            {
                Observation duplicate = MakeObservation(
                    id,
                    EvidenceDomain::Runtime,
                    ObservationDisposition::Context,
                    ObservationStrength::Weak,
                    false);
                duplicate.groupingKey = "duplicate-group";
                duplicate.entityScope = "duplicate-entity";
                duplicates.push_back(std::move(duplicate));
            }
            const ObservationGroupingResult duplicateResult = GroupObservations(duplicates);
            Check(duplicateResult.Succeeded(), L"duplicate detection grouping succeeds");
            Check(duplicateResult.HasDuplicateIds(), L"duplicate IDs are reported");
            CheckEqual(duplicateResult.duplicateIds.size(), std::size_t(2), L"duplicate IDs are unique");
            if (duplicateResult.duplicateIds.size() == 2)
            {
                CheckEqual(duplicateResult.duplicateIds[0], std::string("id-a"), L"duplicate IDs are sorted first");
                CheckEqual(duplicateResult.duplicateIds[1], std::string("id-z"), L"duplicate IDs are sorted second");
            }
            CheckEqual(CountGroupedSources(duplicateResult), duplicates.size(), L"duplicate sources are not discarded");

            Observation oversized = MakeObservation(
                "bounded-group-source",
                EvidenceDomain::FilePath,
                ObservationDisposition::ReviewRelevant,
                ObservationStrength::Weak,
                true);
            oversized.entityScope = "bounded-entity";
            oversized.groupingKey = "bounded-group";
            oversized.rawValue.assign(ObservationRawValueMaxCharacters + 1, 'R');
            oversized.evidence.assign(
                ObservationMaxEvidenceItems + 1,
                std::string(ObservationEvidenceItemMaxCharacters + 1, 'E'));
            oversized.limitations.assign(
                ObservationMaxLimitationItems + 1,
                std::string(ObservationLimitationItemMaxCharacters + 1, 'L'));
            const ObservationGroupingResult boundedGroup = GroupObservations({ oversized });
            Check(boundedGroup.Succeeded(), L"grouping normalizes bounded source copies");
            CheckEqual(boundedGroup.groups.size(), std::size_t(1), L"bounded source produces one group");
            if (!boundedGroup.groups.empty() && !boundedGroup.groups[0].sourceObservations.empty())
            {
                const Observation& bounded = boundedGroup.groups[0].sourceObservations[0];
                CheckEqual(
                    boundedGroup.groups[0].entityScope,
                    oversized.entityScope,
                    L"grouping retains bounded entity scope");
                CheckEqual(
                    boundedGroup.groups[0].groupingKey,
                    oversized.groupingKey,
                    L"grouping retains bounded grouping key");
                CheckEqual(bounded.rawValue.size(), ObservationRawValueMaxCharacters, L"grouped raw value is capped");
                CheckEqual(bounded.evidence.size(), ObservationMaxEvidenceItems, L"grouped evidence count is capped");
                Check(
                    AllStringsBounded(bounded.evidence, ObservationEvidenceItemMaxCharacters),
                    L"grouped evidence items are capped");
                CheckEqual(bounded.limitations.size(), ObservationMaxLimitationItems, L"grouped limitations are capped");
                Check(ValidateObservation(bounded).IsValid(), L"grouped normalized source validates");
            }

            const auto CheckIdentityFieldRejected =
                [](Observation observation, const wchar_t* testName)
                {
                    const ObservationGroupingResult rejected =
                        GroupObservations({ std::move(observation) });
                    Check(!rejected.Succeeded(), testName);
                    CheckEqual(
                        rejected.status,
                        ObservationGroupingStatus::IdentityFieldLimitExceeded,
                        testName);
                    Check(rejected.groups.empty(), testName);
                    Check(rejected.duplicateIds.empty(), testName);
                };

            Observation overId = firstKey;
            overId.id.assign(ObservationIdMaxCharacters + 1, 'I');
            CheckIdentityFieldRejected(overId, L"grouping atomically rejects over-cap observation ID");
            Observation overScope = firstKey;
            overScope.entityScope.assign(ObservationEntityScopeMaxCharacters + 1, 'S');
            CheckIdentityFieldRejected(overScope, L"grouping atomically rejects over-cap entity scope");
            Observation overGroupingKey = firstKey;
            overGroupingKey.groupingKey.assign(ObservationGroupingKeyMaxCharacters + 1, 'G');
            CheckIdentityFieldRejected(
                overGroupingKey,
                L"grouping atomically rejects over-cap grouping key");

            std::vector<Observation> overInputLimit(
                ObservationGroupingMaxSourceObservations + 1,
                MakeObservation(
                    "bounded-input",
                    EvidenceDomain::Runtime,
                    ObservationDisposition::Context,
                    ObservationStrength::Weak,
                    false));
            const ObservationGroupingResult rejectedGroup = GroupObservations(overInputLimit);
            Check(!rejectedGroup.Succeeded(), L"grouping rejects input above its source cap");
            CheckEqual(
                rejectedGroup.status,
                ObservationGroupingStatus::InputLimitExceeded,
                L"grouping reports input cap status");
            Check(rejectedGroup.groups.empty(), L"over-cap grouping returns no partial groups");
            Check(rejectedGroup.duplicateIds.empty(), L"over-cap grouping returns no partial duplicates");
        }

        void TestSuppressionContract()
        {
            Observation original = MakeObservation(
                "suppression-source",
                EvidenceDomain::CommandLine,
                ObservationDisposition::ReviewRelevant,
                ObservationStrength::Moderate,
                true);
            original.ruleId = "generic-suppression-rule";
            original.title = "Generic review observation";
            original.summary = "Review evidence retained through suppression";
            original.entityScope = "selected-entity";
            original.groupingKey = "generic-group";
            original.correlationKey = "generic-correlation";
            original.rawValue = "raw command evidence";
            original.normalizedValue = "normalized command evidence";
            original.evidence = { "evidence-one", "evidence-two" };
            original.limitations = { "observation-limitation" };
            original.sourceKind = ObservationSourceKind::Imported;
            original.provenance.sourceKind = ObservationSourceKind::Imported;
            original.provenance.sourceIdentifier = "import-source";
            original.provenance.collectionMethod = "bounded-import";
            original.provenance.collectionTimestamp = "2026-01-02T03:04:05Z";
            original.provenance.requiredPrivilege = "standard-read";
            original.provenance.sourceAvailable = true;
            original.provenance.limitations = { "provenance-limitation" };
            original.provenance.rawSourceReference = "source-reference";

            ObservationSuppression suppression;
            suppression.suppressorId = "generic-pattern-suppressor";
            suppression.reason = "Surrounding evidence plausibly explains the raw observation";
            Check(IsValidObservationSuppression(suppression), L"bounded suppression contract is valid");

            const Observation suppressed = ApplySuppression(original, suppression);
            CheckEqual(suppressed.id, original.id, L"suppression preserves observation identity");
            CheckEqual(suppressed.ruleId, original.ruleId, L"suppression preserves rule identity");
            CheckEqual(suppressed.title, original.title, L"suppression preserves title");
            CheckEqual(suppressed.summary, original.summary, L"suppression preserves summary");
            CheckEqual(suppressed.domain, original.domain, L"suppression preserves domain");
            CheckEqual(suppressed.strength, original.strength, L"suppression preserves strength field");
            CheckEqual(suppressed.confidence, original.confidence, L"suppression preserves confidence");
            CheckEqual(suppressed.entityScope, original.entityScope, L"suppression preserves entity scope");
            CheckEqual(suppressed.groupingKey, original.groupingKey, L"suppression preserves grouping key");
            CheckEqual(suppressed.correlationKey, original.correlationKey, L"suppression preserves correlation key");
            CheckEqual(suppressed.rawValue, original.rawValue, L"suppression preserves raw value");
            CheckEqual(suppressed.normalizedValue, original.normalizedValue, L"suppression preserves normalized value");
            CheckEqual(suppressed.evidence, original.evidence, L"suppression preserves evidence");
            CheckEqual(suppressed.limitations, original.limitations, L"suppression preserves limitations");
            CheckEqual(
                suppressed.provenance.sourceKind,
                original.provenance.sourceKind,
                L"suppression preserves provenance source kind");
            CheckEqual(
                suppressed.provenance.sourceIdentifier,
                original.provenance.sourceIdentifier,
                L"suppression preserves provenance source identifier");
            CheckEqual(
                suppressed.provenance.collectionMethod,
                original.provenance.collectionMethod,
                L"suppression preserves collection method");
            CheckEqual(
                suppressed.provenance.collectionTimestamp,
                original.provenance.collectionTimestamp,
                L"suppression preserves collection timestamp");
            CheckEqual(
                suppressed.provenance.requiredPrivilege,
                original.provenance.requiredPrivilege,
                L"suppression preserves required privilege");
            CheckEqual(
                suppressed.provenance.sourceAvailable,
                original.provenance.sourceAvailable,
                L"suppression preserves source availability");
            CheckEqual(
                suppressed.provenance.limitations,
                original.provenance.limitations,
                L"suppression preserves provenance limitations");
            CheckEqual(
                suppressed.provenance.rawSourceReference,
                original.provenance.rawSourceReference,
                L"suppression preserves raw source reference");
            CheckEqual(
                suppressed.disposition,
                ObservationDisposition::SuppressedExpected,
                L"suppression applies expected disposition");
            Check(!suppressed.contributesToVerdict, L"suppression disables contribution");
            CheckEqual(
                suppressed.suppressorId,
                suppression.suppressorId,
                L"suppression records its suppressor ID");
            CheckEqual(suppressed.suppressionReason, suppression.reason, L"suppression records its reason");
            CheckEqual(
                suppressed.sourceKind,
                ObservationSourceKind::Imported,
                L"suppression does not assign automatic trust");
            Check(ValidateObservation(suppressed).IsValid(), L"suppressed observation validates");

            ObservationSuppression emptyReason = suppression;
            emptyReason.reason.clear();
            Check(!IsValidObservationSuppression(emptyReason), L"empty suppression reason is invalid");
            const Observation unchangedEmpty = ApplySuppression(original, emptyReason);
            CheckEqual(unchangedEmpty.disposition, original.disposition, L"empty reason leaves disposition unchanged");
            CheckEqual(unchangedEmpty.contributesToVerdict, original.contributesToVerdict, L"empty reason leaves contribution unchanged");
            Check(unchangedEmpty.suppressionReason.empty(), L"empty reason is not recorded");

            ObservationSuppression whitespaceReason = suppression;
            whitespaceReason.reason = " \t\r\n ";
            Check(!IsValidObservationSuppression(whitespaceReason), L"whitespace suppression reason is invalid");
            const Observation unchangedWhitespace = ApplySuppression(original, whitespaceReason);
            CheckEqual(
                unchangedWhitespace.disposition,
                original.disposition,
                L"whitespace reason leaves observation unchanged");

            ObservationSuppression wrongDisposition = suppression;
            wrongDisposition.resultingDisposition = ObservationDisposition::Context;
            Check(!IsValidObservationSuppression(wrongDisposition), L"non-suppressed resulting disposition is invalid");
            const Observation unchangedDisposition = ApplySuppression(original, wrongDisposition);
            CheckEqual(
                unchangedDisposition.disposition,
                original.disposition,
                L"invalid resulting disposition leaves observation unchanged");

            ObservationSuppression overCap = suppression;
            overCap.suppressorId.assign(ObservationSuppressorIdMaxCharacters + 1, 'I');
            overCap.reason.assign(ObservationSuppressionReasonMaxCharacters + 1, 'R');
            Check(!IsValidObservationSuppression(overCap), L"over-cap suppression contract is invalid");
            const Observation unchangedOverCap = ApplySuppression(original, overCap);
            CheckEqual(unchangedOverCap.disposition, original.disposition, L"over-cap suppression is rejected");
            CheckEqual(
                unchangedOverCap.suppressorId,
                original.suppressorId,
                L"rejected suppression does not assign a suppressor ID");
            CheckEqual(unchangedOverCap.rawValue, original.rawValue, L"rejected suppression preserves raw evidence");

            const ObservationSuppression normalizedContract =
                NormalizeObservationSuppression(overCap);
            CheckEqual(
                normalizedContract.suppressorId.size(),
                ObservationSuppressorIdMaxCharacters,
                L"suppressor ID normalization enforces cap");
            CheckEqual(
                normalizedContract.reason.size(),
                ObservationSuppressionReasonMaxCharacters,
                L"suppression reason normalization enforces cap");
            Check(
                IsValidObservationSuppression(normalizedContract),
                L"explicitly normalized suppression contract validates");
        }

        void TestGenericFalseUrgencyFixtures()
        {
            std::vector<Observation> weakContext;
            for (int index = 0; index < 4; ++index)
            {
                weakContext.push_back(MakeObservation(
                    "weak-context-" + std::to_string(index),
                    EvidenceDomain::ProcessIdentity,
                    ObservationDisposition::Context,
                    ObservationStrength::Weak,
                    true));
            }
            Check(
                CollectContributingDomains(weakContext).empty(),
                L"fixture one: several weak context observations contribute no domains");

            std::vector<Observation> collectionNotes;
            for (int index = 0; index < 3; ++index)
            {
                collectionNotes.push_back(MakeObservation(
                    "collection-note-" + std::to_string(index),
                    EvidenceDomain::CollectionQuality,
                    ObservationDisposition::CollectionNote,
                    ObservationStrength::Strong,
                    true));
            }
            Check(
                std::none_of(
                    collectionNotes.begin(),
                    collectionNotes.end(),
                    CanContributeToVerdict),
                L"fixture two: collection notes never contribute");
            Check(
                CollectContributingDomains(collectionNotes).empty(),
                L"fixture two: collection notes contribute no domains");

            const std::vector<Observation> oneWeakReview = {
                MakeObservation(
                    "one-weak-review",
                    EvidenceDomain::FilePath,
                    ObservationDisposition::ReviewRelevant,
                    ObservationStrength::Weak,
                    true)
            };
            CheckEqual(
                CollectContributingDomains(oneWeakReview).size(),
                std::size_t(1),
                L"fixture three: one weak review observation contributes one domain");

            const std::vector<Observation> sameModerateDomain = {
                MakeObservation(
                    "same-moderate-one",
                    EvidenceDomain::Service,
                    ObservationDisposition::ReviewRelevant,
                    ObservationStrength::Moderate,
                    true),
                MakeObservation(
                    "same-moderate-two",
                    EvidenceDomain::Service,
                    ObservationDisposition::ReviewRelevant,
                    ObservationStrength::Moderate,
                    true)
            };
            CheckEqual(
                CollectContributingDomains(sameModerateDomain).size(),
                std::size_t(1),
                L"fixture four: two moderate observations in one domain count once");

            const std::vector<Observation> independentModerateDomains = {
                MakeObservation(
                    "independent-moderate-one",
                    EvidenceDomain::Service,
                    ObservationDisposition::ReviewRelevant,
                    ObservationStrength::Moderate,
                    true),
                MakeObservation(
                    "independent-moderate-two",
                    EvidenceDomain::Network,
                    ObservationDisposition::ReviewRelevant,
                    ObservationStrength::Moderate,
                    true)
            };
            CheckEqual(
                CollectContributingDomains(independentModerateDomains).size(),
                std::size_t(2),
                L"fixture five: moderate observations in independent domains count twice");

            Observation highConfidenceInformation = MakeObservation(
                "high-confidence-information",
                EvidenceDomain::Runtime,
                ObservationDisposition::Informational,
                ObservationStrength::Strong,
                true);
            highConfidenceInformation.confidence = ObservationConfidence::High;
            Check(!CanContributeToVerdict(highConfidenceInformation), L"fixture six: high-confidence information does not contribute");
            Check(
                CollectContributingDomains({ highConfidenceInformation }).empty(),
                L"fixture six: high-confidence information contributes no domains");

            const Observation strongCorrelatedOnly = MakeObservation(
                "strong-correlated-only",
                EvidenceDomain::Persistence,
                ObservationDisposition::CorrelatedOnly,
                ObservationStrength::Strong,
                true);
            Check(!CanContributeToVerdict(strongCorrelatedOnly), L"fixture seven: correlated-only evidence is not independently active");
            Check(
                CollectContributingDomains({ strongCorrelatedOnly }).empty(),
                L"fixture seven: correlated-only evidence contributes no independent domain");
        }
    }

    int RunObservationCoreTests()
    {
        TestDefaultsStableEnumsAndDisplayHelpers();
        TestCapsNormalizationAndValueCopying();
        TestArtifactIdentityContract();
        TestDispositionAndContributionPolicy();
        TestDomainIndependenceAndQualitySeparation();
        TestGroupingDeduplicationAndBounds();
        TestSuppressionContract();
        TestGenericFalseUrgencyFixtures();
        return failureCount;
    }
}
