#pragma once

#include "Observation.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace GlassPane::Core
{
    constexpr std::size_t ObservationInventoryMaxObservations = 4096;
    constexpr std::size_t ObservationSourceCategoryMaxCharacters = 256;
    constexpr std::size_t ObservationSourceMessageMaxCharacters =
        ObservationSummaryMaxCharacters;

    // Stable artifact attributes are shared by native builders, refinement,
    // and triage. They describe typed memory metadata rather than display text.
    inline constexpr char ObservationArtifactAttributeMemoryWritable[] =
        "memory.writable";
    inline constexpr char ObservationArtifactAttributeMemoryExecutable[] =
        "memory.executable";
    inline constexpr char ObservationArtifactAttributeMemoryPrivate[] =
        "memory.private";
    inline constexpr char ObservationArtifactAttributeMemoryImageBacked[] =
        "memory.image-backed";
    inline constexpr char ObservationArtifactAttributeMemoryMappedFileBacked[] =
        "memory.mapped-file-backed";
    inline constexpr char ObservationArtifactAttributeMemoryGuarded[] =
        "memory.guarded";
    inline constexpr char ObservationArtifactAttributeBooleanTrue[] = "true";
    inline constexpr char ObservationArtifactAttributeBooleanFalse[] = "false";

    // Generic source metadata shared by every native producer.
    struct ObservationRecordSourceMetadata
    {
        std::string sourceRecordId;
        std::string sourceRuleId;
        std::string mappingRuleId;
        std::string sourceTitle;
        std::string sourceMessage;
        std::string sourceCategory;
        std::string producerIdentifier;
        std::string assessmentRationale;
        std::size_t sourceOrdinal = 0;

        std::size_t aggregateSourceFactCount = 0;
        std::size_t aggregateMappedFactCount = 0;
        bool rawValueExplicitlySupplied = false;
        bool normalizedValueExplicitlySupplied = false;

        bool sourceRecordIdTruncated = false;
        bool sourceRuleIdTruncated = false;
        bool mappingRuleIdTruncated = false;
        bool sourceTitleTruncated = false;
        bool sourceMessageTruncated = false;
        bool sourceCategoryTruncated = false;
        bool sourceEvidenceTruncated = false;
        bool assessmentRationaleTruncated = false;
    };

    struct ObservationRecord
    {
        Observation observation;
        ObservationRecordSourceMetadata source;
    };

    enum class ObservationInventoryStatus : std::uint32_t
    {
        Success = 0,
        SourceLimitExceeded = 1,
        ObservationLimitExceeded = 2
    };

    std::string ObservationInventoryStatusDisplayText(
        ObservationInventoryStatus status);

    struct ObservationInventory
    {
        ObservationInventoryStatus status = ObservationInventoryStatus::Success;
        std::vector<ObservationRecord> records;
        std::size_t informationalCount = 0;
        std::size_t contextCount = 0;
        std::size_t reviewRelevantCount = 0;
        std::size_t correlatedOnlyCount = 0;
        std::size_t collectionNoteCount = 0;
        std::size_t evidenceIntegrityNoteCount = 0;
        std::size_t suppressedExpectedCount = 0;
        // Native source-fact coverage is independent of legacy Finding
        // branches. Declared facts include bounded omissions supplied by a
        // producer; represented facts are the typed records retained here.
        std::size_t typedSourceFactCount = 0;
        std::size_t declaredSourceFactCount = 0;

        bool Succeeded() const;
    };

    std::vector<Observation> CollectInventoryObservations(
        const ObservationInventory& inventory);

    struct ObservationShadowSummary
    {
        std::size_t observationCount = 0;
        std::size_t contributingObservationCount = 0;
        std::size_t informationalCount = 0;
        std::size_t contextCount = 0;
        std::size_t reviewRelevantCount = 0;
        std::size_t correlatedOnlyCount = 0;
        std::size_t collectionNoteCount = 0;
        std::size_t evidenceIntegrityNoteCount = 0;
        std::size_t suppressedExpectedCount = 0;
        std::size_t contributingDomainCount = 0;
        std::size_t typedSourceFactCount = 0;
        std::size_t declaredSourceFactCount = 0;
    };

    ObservationShadowSummary SummarizeObservationShadow(
        const ObservationInventory& inventory);
}
