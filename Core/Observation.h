#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace GlassPane::Core
{
    // Observation text and collection caps are part of the Core data contract.
    // Policy normalization applies these limits before observations are consumed.
    constexpr std::size_t ObservationIdMaxCharacters = 128;
    constexpr std::size_t ObservationRuleIdMaxCharacters = 128;
    constexpr std::size_t ObservationTitleMaxCharacters = 256;
    constexpr std::size_t ObservationSummaryMaxCharacters = 1024;
    constexpr std::size_t ObservationEntityScopeMaxCharacters = 128;
    constexpr std::size_t ObservationGroupingKeyMaxCharacters = 128;
    constexpr std::size_t ObservationCorrelationKeyMaxCharacters = 128;
    constexpr std::size_t ObservationSuppressionReasonMaxCharacters = 1024;
    constexpr std::size_t ObservationRawValueMaxCharacters = 4096;
    constexpr std::size_t ObservationNormalizedValueMaxCharacters = 4096;
    constexpr std::size_t ObservationEvidenceItemMaxCharacters = 1024;
    constexpr std::size_t ObservationLimitationItemMaxCharacters = 1024;
    constexpr std::size_t ObservationMaxEvidenceItems = 64;
    constexpr std::size_t ObservationMaxLimitationItems = 32;

    constexpr std::size_t ObservationProvenanceSourceIdentifierMaxCharacters = 512;
    constexpr std::size_t ObservationProvenanceCollectionMethodMaxCharacters = 512;
    constexpr std::size_t ObservationProvenanceCollectionTimestampMaxCharacters = 128;
    constexpr std::size_t ObservationProvenanceRequiredPrivilegeMaxCharacters = 512;
    constexpr std::size_t ObservationProvenanceRawSourceReferenceMaxCharacters = 1024;
    constexpr std::size_t ObservationProvenanceLimitationItemMaxCharacters =
        ObservationLimitationItemMaxCharacters;
    constexpr std::size_t ObservationProvenanceMaxLimitationItems =
        ObservationMaxLimitationItems;

    constexpr std::size_t ObservationSuppressorIdMaxCharacters = 128;

    constexpr std::size_t ObservationArtifactEntityScopeMaxCharacters =
        ObservationEntityScopeMaxCharacters;
    constexpr std::size_t ObservationArtifactKeyMaxCharacters = 256;
    constexpr std::size_t ObservationArtifactAttributeKeyMaxCharacters = 128;
    constexpr std::size_t ObservationArtifactAttributeValueMaxCharacters = 1024;
    constexpr std::size_t ObservationMaxArtifactAttributes = 64;

    enum class EvidenceDomain : std::uint32_t
    {
        Unknown = 0,
        ProcessIdentity = 1,
        FilePath = 2,
        FileSignature = 3,
        CommandLine = 4,
        ProcessRelationship = 5,
        Network = 6,
        Service = 7,
        Module = 8,
        Handle = 9,
        Runtime = 10,
        MemoryMetadata = 11,
        Token = 12,
        Persistence = 13,
        CollectionQuality = 14,
        EvidenceIntegrity = 15,
        ImportedEvidence = 16
    };

    enum class ObservationSourceKind : std::uint32_t
    {
        Direct = 0,
        Corroborated = 1,
        Derived = 2,
        Imported = 3,
        UserDefined = 4,
        Unverified = 5,
        Unavailable = 6
    };

    enum class ObservationDisposition : std::uint32_t
    {
        Informational = 0,
        Context = 1,
        ReviewRelevant = 2,
        CorrelatedOnly = 3,
        CollectionNote = 4,
        EvidenceIntegrityNote = 5,
        SuppressedExpected = 6
    };

    enum class ObservationStrength : std::uint32_t
    {
        None = 0,
        Weak = 1,
        Moderate = 2,
        Strong = 3
    };

    enum class ObservationConfidence : std::uint32_t
    {
        Unknown = 0,
        Low = 1,
        Medium = 2,
        High = 3
    };

    // Identifies the bounded source artifact described by one or more
    // observations. Values are stable Core data-contract values; they are not
    // UI categories or verdict policy.
    enum class ObservationArtifactKind : std::uint32_t
    {
        None = 0,
        Process = 1,
        File = 2,
        MemoryRegion = 3,
        NetworkConnection = 4,
        Service = 5,
        Handle = 6,
        Module = 7,
        Token = 8,
        RuntimeObject = 9
    };

    std::string EvidenceDomainDisplayText(EvidenceDomain domain);
    std::string ObservationSourceKindDisplayText(ObservationSourceKind sourceKind);
    std::string ObservationDispositionDisplayText(ObservationDisposition disposition);
    std::string ObservationStrengthDisplayText(ObservationStrength strength);
    std::string ObservationConfidenceDisplayText(ObservationConfidence confidence);
    std::string ObservationArtifactKindDisplayText(ObservationArtifactKind kind);

    // String aliases keep serialization and display callers on the same stable text.
    std::string EvidenceDomainToString(EvidenceDomain domain);
    std::string ObservationSourceKindToString(ObservationSourceKind sourceKind);
    std::string ObservationDispositionToString(ObservationDisposition disposition);
    std::string ObservationStrengthToString(ObservationStrength strength);
    std::string ObservationConfidenceToString(ObservationConfidence confidence);
    std::string ObservationArtifactKindToString(ObservationArtifactKind kind);

    struct ObservationArtifactIdentity
    {
        ObservationArtifactKind kind = ObservationArtifactKind::None;
        std::string entityScope;
        std::string artifactKey;
    };

    inline bool operator==(
        const ObservationArtifactIdentity& left,
        const ObservationArtifactIdentity& right)
    {
        return left.kind == right.kind &&
            left.entityScope == right.entityScope &&
            left.artifactKey == right.artifactKey;
    }

    inline bool operator!=(
        const ObservationArtifactIdentity& left,
        const ObservationArtifactIdentity& right)
    {
        return !(left == right);
    }

    struct ObservationArtifactAttribute
    {
        std::string key;
        std::string value;
    };

    inline bool operator==(
        const ObservationArtifactAttribute& left,
        const ObservationArtifactAttribute& right)
    {
        return left.key == right.key && left.value == right.value;
    }

    inline bool operator!=(
        const ObservationArtifactAttribute& left,
        const ObservationArtifactAttribute& right)
    {
        return !(left == right);
    }

    // A complete identity has a known non-None kind and bounded, nonempty
    // scope/key fields. Callers must additionally ensure its scope matches the
    // containing Observation.
    bool HasCompleteObservationArtifactIdentity(
        const ObservationArtifactIdentity& identity);

    struct ObservationProvenance
    {
        // Source class records acquisition provenance; it is not a trust verdict.
        ObservationSourceKind sourceKind = ObservationSourceKind::Unverified;
        std::string sourceIdentifier;
        std::string collectionMethod;
        std::string collectionTimestamp;
        std::string requiredPrivilege;
        bool sourceAvailable = false;
        std::vector<std::string> limitations;
        std::string rawSourceReference;
    };

    struct Observation
    {
        std::string id;
        std::string ruleId;
        std::string title;
        std::string summary;

        EvidenceDomain domain = EvidenceDomain::Unknown;
        // Policy validation reports disagreement with provenance.sourceKind.
        ObservationSourceKind sourceKind = ObservationSourceKind::Unverified;
        ObservationDisposition disposition = ObservationDisposition::Informational;
        ObservationStrength strength = ObservationStrength::None;
        ObservationConfidence confidence = ObservationConfidence::Unknown;

        bool contributesToVerdict = false;

        std::string entityScope;
        std::string groupingKey;
        std::string correlationKey;
        std::string suppressorId;
        std::string suppressionReason;

        std::string rawValue;
        std::string normalizedValue;

        ObservationArtifactIdentity artifactIdentity;
        std::vector<ObservationArtifactAttribute> artifactAttributes;

        std::vector<std::string> evidence;
        std::vector<std::string> limitations;

        ObservationProvenance provenance;
    };

    bool HasObservationArtifactIdentity(const Observation& observation);
}
