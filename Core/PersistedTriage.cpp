#include "PersistedTriage.h"

#include <algorithm>
#include <iomanip>
#include <sstream>
#include <string_view>
#include <utility>

namespace GlassPane::Core
{
    namespace
    {
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

        bool IsContinuationByte(unsigned char value)
        {
            return (value & 0xC0U) == 0x80U;
        }

        bool IsValidUtf8(std::string_view value)
        {
            std::size_t index = 0;
            while (index < value.size())
            {
                const unsigned char first =
                    static_cast<unsigned char>(value[index]);
                if (first <= 0x7FU)
                {
                    ++index;
                    continue;
                }

                if (first >= 0xC2U && first <= 0xDFU)
                {
                    if (index + 1 >= value.size() ||
                        !IsContinuationByte(static_cast<unsigned char>(value[index + 1])))
                    {
                        return false;
                    }
                    index += 2;
                    continue;
                }

                if (first >= 0xE0U && first <= 0xEFU)
                {
                    if (index + 2 >= value.size())
                    {
                        return false;
                    }
                    const unsigned char second =
                        static_cast<unsigned char>(value[index + 1]);
                    const unsigned char third =
                        static_cast<unsigned char>(value[index + 2]);
                    const bool validSecond = first == 0xE0U
                        ? second >= 0xA0U && second <= 0xBFU
                        : first == 0xEDU
                            ? second >= 0x80U && second <= 0x9FU
                            : IsContinuationByte(second);
                    if (!validSecond || !IsContinuationByte(third))
                    {
                        return false;
                    }
                    index += 3;
                    continue;
                }

                if (first >= 0xF0U && first <= 0xF4U)
                {
                    if (index + 3 >= value.size())
                    {
                        return false;
                    }
                    const unsigned char second =
                        static_cast<unsigned char>(value[index + 1]);
                    const unsigned char third =
                        static_cast<unsigned char>(value[index + 2]);
                    const unsigned char fourth =
                        static_cast<unsigned char>(value[index + 3]);
                    const bool validSecond = first == 0xF0U
                        ? second >= 0x90U && second <= 0xBFU
                        : first == 0xF4U
                            ? second >= 0x80U && second <= 0x8FU
                            : IsContinuationByte(second);
                    if (!validSecond ||
                        !IsContinuationByte(third) ||
                        !IsContinuationByte(fourth))
                    {
                        return false;
                    }
                    index += 4;
                    continue;
                }

                return false;
            }
            return true;
        }

        std::string TruncateValidUtf8(
            const std::string& value,
            std::size_t maximumBytes)
        {
            if (!IsValidUtf8(value) || value.size() <= maximumBytes)
            {
                return value;
            }

            std::size_t retained = maximumBytes;
            while (retained > 0 &&
                IsContinuationByte(static_cast<unsigned char>(value[retained])))
            {
                --retained;
            }
            return value.substr(0, retained);
        }

        bool HasNonWhitespace(std::string_view value)
        {
            return std::any_of(
                value.begin(),
                value.end(),
                [](char character)
                {
                    switch (character)
                    {
                    case ' ':
                    case '\t':
                    case '\r':
                    case '\n':
                    case '\f':
                    case '\v':
                        return false;
                    default:
                        return true;
                    }
                });
        }

        bool IsKnownVerdict(TriageVerdict verdict)
        {
            switch (verdict)
            {
            case TriageVerdict::Informational:
            case TriageVerdict::LowAttention:
            case TriageVerdict::MediumAttention:
            case TriageVerdict::HighAttention:
                return true;
            default:
                return false;
            }
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

        PersistedTriageValidationResult ValidResult()
        {
            PersistedTriageValidationResult result;
            result.valid = true;
            result.code = PersistedTriageValidationCode::Valid;
            return result;
        }

        PersistedTriageValidationResult Failure(
            PersistedTriageValidationCode code,
            std::string field,
            std::string message)
        {
            PersistedTriageValidationResult result;
            result.valid = false;
            result.code = code;
            result.field = TruncateValidUtf8(
                field,
                PersistedTriageValidationFieldMaxUtf8Bytes);
            result.message = TruncateValidUtf8(
                message,
                PersistedTriageValidationMessageMaxUtf8Bytes);
            return result;
        }

        PersistedTriageValidationResult ValidateString(
            const std::string& value,
            std::size_t maximumBytes,
            const std::string& field)
        {
            if (!IsValidUtf8(value))
            {
                return Failure(
                    PersistedTriageValidationCode::InvalidUtf8,
                    field,
                    "The persisted triage string is not valid UTF-8.");
            }
            if (value.size() > maximumBytes)
            {
                return Failure(
                    PersistedTriageValidationCode::StringLimitExceeded,
                    field,
                    "The persisted triage string exceeds its UTF-8 byte cap.");
            }
            return ValidResult();
        }

        PersistedTriageValidationResult ValidateStringCollection(
            const std::vector<std::string>& values,
            std::size_t maximumItems,
            const std::string& field)
        {
            if (values.size() > maximumItems)
            {
                return Failure(
                    PersistedTriageValidationCode::CollectionLimitExceeded,
                    field,
                    "The persisted triage collection exceeds its item cap.");
            }

            for (std::size_t index = 0; index < values.size(); ++index)
            {
                PersistedTriageValidationResult result = ValidateString(
                    values[index],
                    PersistedTriageLineMaxUtf8Bytes,
                    field + '[' + std::to_string(index) + ']');
                if (!result)
                {
                    return result;
                }
            }
            return ValidResult();
        }

        bool HasRationaleContent(const PersistedTriageSummary& summary)
        {
            return !summary.contributingDomains.empty() ||
                !summary.verdictBasis.empty() ||
                !summary.completedCorrelations.empty() ||
                !summary.supportingContext.empty() ||
                !summary.collectionLimitations.empty() ||
                !summary.evidenceIntegrityContext.empty() ||
                !summary.unresolvedCorrelations.empty();
        }

        PersistedTriageProjectionResult ProjectionFailure(
            PersistedTriageValidationCode code,
            const std::string& field,
            const std::string& message)
        {
            PersistedTriageProjectionResult result;
            result.validation = Failure(code, field, message);
            return result;
        }

        bool AppendRationale(
            PersistedTriageSummary& output,
            const TriageRationaleEntry& entry)
        {
            switch (entry.section)
            {
            case TriageRationaleSection::VerdictBasis:
                output.verdictBasis.push_back(entry.text);
                return true;
            case TriageRationaleSection::CompletedCorrelations:
                output.completedCorrelations.push_back(entry.text);
                return true;
            case TriageRationaleSection::SupportingContext:
                output.supportingContext.push_back(entry.text);
                return true;
            case TriageRationaleSection::CollectionLimitations:
                output.collectionLimitations.push_back(entry.text);
                return true;
            case TriageRationaleSection::EvidenceIntegrityContext:
                output.evidenceIntegrityContext.push_back(entry.text);
                return true;
            case TriageRationaleSection::UnresolvedCorrelations:
                output.unresolvedCorrelations.push_back(entry.text);
                return true;
            case TriageRationaleSection::PresentationNotes:
                // Omission diagnostics are runtime presentation metadata, not
                // capture-time evidence or verdict rationale.
                return true;
            default:
                return false;
            }
        }
    }

    std::string PersistedTriageAnalysisLevelDisplayText(
        PersistedTriageAnalysisLevel level)
    {
        switch (level)
        {
        case PersistedTriageAnalysisLevel::NotCaptured:
            return "Not captured";
        case PersistedTriageAnalysisLevel::Baseline:
            return "Baseline";
        case PersistedTriageAnalysisLevel::Enriched:
            return "Enriched";
        case PersistedTriageAnalysisLevel::LegacyFallback:
            return "Legacy fallback";
        default:
            return UnknownEnumText(
                "persisted triage analysis level",
                static_cast<std::uint32_t>(level));
        }
    }

    bool IsKnownPersistedTriageAnalysisLevel(
        PersistedTriageAnalysisLevel level)
    {
        switch (level)
        {
        case PersistedTriageAnalysisLevel::NotCaptured:
        case PersistedTriageAnalysisLevel::Baseline:
        case PersistedTriageAnalysisLevel::Enriched:
        case PersistedTriageAnalysisLevel::LegacyFallback:
            return true;
        default:
            return false;
        }
    }

    std::string PersistedTriageValidationCodeDisplayText(
        PersistedTriageValidationCode code)
    {
        switch (code)
        {
        case PersistedTriageValidationCode::Valid:
            return "Valid";
        case PersistedTriageValidationCode::UnsupportedModelVersion:
            return "Unsupported model version";
        case PersistedTriageValidationCode::InvalidProcessIdentity:
            return "Invalid process identity";
        case PersistedTriageValidationCode::UnknownAnalysisLevel:
            return "Unknown analysis level";
        case PersistedTriageValidationCode::UnknownVerdict:
            return "Unknown verdict";
        case PersistedTriageValidationCode::UnknownEvidenceDomain:
            return "Unknown evidence domain";
        case PersistedTriageValidationCode::InvalidUtf8:
            return "Invalid UTF-8";
        case PersistedTriageValidationCode::StringLimitExceeded:
            return "String limit exceeded";
        case PersistedTriageValidationCode::CollectionLimitExceeded:
            return "Collection limit exceeded";
        case PersistedTriageValidationCode::SourceEvidenceLimitExceeded:
            return "Source evidence limit exceeded";
        case PersistedTriageValidationCode::ContradictoryState:
            return "Contradictory state";
        case PersistedTriageValidationCode::NonCanonicalOrder:
            return "Non-canonical order";
        case PersistedTriageValidationCode::DuplicateProcessIdentity:
            return "Duplicate process identity";
        case PersistedTriageValidationCode::SelectedProcessMissing:
            return "Selected process missing";
        default:
            return UnknownEnumText(
                "persisted triage validation code",
                static_cast<std::uint32_t>(code));
        }
    }

    PersistedTriageValidationResult ValidatePersistedTriageSummary(
        const PersistedTriageSummary& summary)
    {
        if (!IsKnownPersistedTriageAnalysisLevel(summary.analysisLevel))
        {
            return Failure(
                PersistedTriageValidationCode::UnknownAnalysisLevel,
                "analysisLevel",
                "The persisted triage analysis level is unknown.");
        }
        if (!IsKnownVerdict(summary.authoritativeVerdict))
        {
            return Failure(
                PersistedTriageValidationCode::UnknownVerdict,
                "authoritativeVerdict",
                "The persisted authoritative verdict is unknown.");
        }
        if (!IsKnownVerdict(summary.baselineVerdict))
        {
            return Failure(
                PersistedTriageValidationCode::UnknownVerdict,
                "baselineVerdict",
                "The persisted baseline verdict is unknown.");
        }
        if (summary.sourceEvidenceCount > PersistedTriageMaxSourceEvidenceCount)
        {
            return Failure(
                PersistedTriageValidationCode::SourceEvidenceLimitExceeded,
                "sourceEvidenceCount",
                "The persisted source-evidence count exceeds its cap.");
        }
        if (summary.contributingDomains.size() >
            PersistedTriageMaxContributingDomains)
        {
            return Failure(
                PersistedTriageValidationCode::CollectionLimitExceeded,
                "contributingDomains",
                "The persisted contributing-domain collection exceeds its cap.");
        }
        for (std::size_t index = 0;
            index < summary.contributingDomains.size();
            ++index)
        {
            const EvidenceDomain domain = summary.contributingDomains[index];
            if (!IsKnownDomain(domain))
            {
                return Failure(
                    PersistedTriageValidationCode::UnknownEvidenceDomain,
                    "contributingDomains[" + std::to_string(index) + ']',
                    "The persisted contributing evidence domain is unknown.");
            }
            if (domain == EvidenceDomain::Unknown ||
                domain == EvidenceDomain::CollectionQuality ||
                domain == EvidenceDomain::EvidenceIntegrity)
            {
                return Failure(
                    PersistedTriageValidationCode::ContradictoryState,
                    "contributingDomains[" + std::to_string(index) + ']',
                    "A non-contributing evidence domain was stored as contributing.");
            }
            if (index > 0)
            {
                const std::uint32_t previous = static_cast<std::uint32_t>(
                    summary.contributingDomains[index - 1]);
                const std::uint32_t current = static_cast<std::uint32_t>(domain);
                if (current <= previous)
                {
                    return Failure(
                        PersistedTriageValidationCode::NonCanonicalOrder,
                        "contributingDomains",
                        "Contributing domains must be unique and in canonical order.");
                }
            }
        }

        const struct
        {
            const std::vector<std::string>* values;
            std::size_t maximumItems;
            const char* field;
        } collections[] = {
            { &summary.verdictBasis,
                PersistedTriageMaxVerdictBasisItems, "verdictBasis" },
            { &summary.completedCorrelations,
                PersistedTriageMaxCompletedCorrelationItems,
                "completedCorrelations" },
            { &summary.supportingContext,
                PersistedTriageMaxSupportingContextItems,
                "supportingContext" },
            { &summary.collectionLimitations,
                PersistedTriageMaxCollectionLimitationItems,
                "collectionLimitations" },
            { &summary.evidenceIntegrityContext,
                PersistedTriageMaxEvidenceIntegrityItems,
                "evidenceIntegrityContext" },
            { &summary.unresolvedCorrelations,
                PersistedTriageMaxUnresolvedCorrelationItems,
                "unresolvedCorrelations" }
        };
        for (const auto& collection : collections)
        {
            PersistedTriageValidationResult result = ValidateStringCollection(
                *collection.values,
                collection.maximumItems,
                collection.field);
            if (!result)
            {
                return result;
            }
        }

        PersistedTriageValidationResult fallbackValidation = ValidateString(
            summary.fallbackReason,
            PersistedTriageFallbackReasonMaxUtf8Bytes,
            "fallbackReason");
        if (!fallbackValidation)
        {
            return fallbackValidation;
        }
        PersistedTriageValidationResult statusValidation = ValidateString(
            summary.status,
            PersistedTriageStatusMaxUtf8Bytes,
            "status");
        if (!statusValidation)
        {
            return statusValidation;
        }

        if (!summary.captured)
        {
            if (summary.evaluationSucceeded ||
                summary.usingFallback ||
                summary.analysisLevel !=
                    PersistedTriageAnalysisLevel::NotCaptured ||
                summary.authoritativeVerdict != TriageVerdict::Informational ||
                summary.baselineVerdictAvailable ||
                summary.baselineVerdict != TriageVerdict::Informational ||
                summary.enrichedChangedVerdict ||
                summary.triageModelVersion != 0 ||
                summary.sourceEvidenceCount != 0 ||
                HasRationaleContent(summary) ||
                !summary.fallbackReason.empty() ||
                !summary.status.empty())
            {
                return Failure(
                    PersistedTriageValidationCode::ContradictoryState,
                    "captured",
                    "A not-captured triage summary must contain no captured authority data.");
            }
            return ValidResult();
        }

        if (summary.triageModelVersion != PersistedTriageModelVersion)
        {
            return Failure(
                PersistedTriageValidationCode::UnsupportedModelVersion,
                "triageModelVersion",
                "The captured triage summary uses an unsupported model version.");
        }
        if (summary.analysisLevel == PersistedTriageAnalysisLevel::NotCaptured)
        {
            return Failure(
                PersistedTriageValidationCode::ContradictoryState,
                "analysisLevel",
                "A captured triage summary cannot have a NotCaptured analysis level.");
        }

        const bool legacyFallback = summary.analysisLevel ==
            PersistedTriageAnalysisLevel::LegacyFallback;
        if (summary.usingFallback != legacyFallback)
        {
            return Failure(
                PersistedTriageValidationCode::ContradictoryState,
                "usingFallback",
                "usingFallback must be true exactly for LegacyFallback analysis.");
        }
        if (legacyFallback)
        {
            if (summary.evaluationSucceeded ||
                !HasNonWhitespace(summary.fallbackReason))
            {
                return Failure(
                    PersistedTriageValidationCode::ContradictoryState,
                    "fallbackReason",
                    "Legacy fallback must be unsuccessful and include a reason.");
            }
            if (summary.baselineVerdictAvailable ||
                summary.enrichedChangedVerdict ||
                HasRationaleContent(summary))
            {
                return Failure(
                    PersistedTriageValidationCode::ContradictoryState,
                    "analysisLevel",
                    "Legacy fallback cannot contain successful ObservationEngine rationale.");
            }
            return ValidResult();
        }

        if (!summary.evaluationSucceeded ||
            summary.usingFallback ||
            !summary.fallbackReason.empty())
        {
            return Failure(
                PersistedTriageValidationCode::ContradictoryState,
                "evaluationSucceeded",
                "Baseline and enriched authority require successful non-fallback evaluation.");
        }
        if (summary.analysisLevel == PersistedTriageAnalysisLevel::Baseline)
        {
            if (!summary.baselineVerdictAvailable)
            {
                return Failure(
                    PersistedTriageValidationCode::ContradictoryState,
                    "baselineVerdictAvailable",
                    "Baseline authority requires its captured baseline verdict.");
            }
            if (summary.enrichedChangedVerdict)
            {
                return Failure(
                    PersistedTriageValidationCode::ContradictoryState,
                    "enrichedChangedVerdict",
                    "Baseline analysis cannot report an enriched verdict change.");
            }
            if (summary.baselineVerdict != summary.authoritativeVerdict)
            {
                return Failure(
                    PersistedTriageValidationCode::ContradictoryState,
                    "baselineVerdict",
                    "Baseline authority cannot disagree with its available baseline verdict.");
            }
        }
        else
        {
            if (!summary.baselineVerdictAvailable)
            {
                return Failure(
                    PersistedTriageValidationCode::ContradictoryState,
                    "baselineVerdictAvailable",
                    "Enriched authority requires an available baseline verdict.");
            }
            const bool changed = summary.authoritativeVerdict !=
                summary.baselineVerdict;
            if (summary.enrichedChangedVerdict != changed)
            {
                return Failure(
                    PersistedTriageValidationCode::ContradictoryState,
                    "enrichedChangedVerdict",
                    "The enriched-change flag contradicts the persisted verdicts.");
            }
        }

        return ValidResult();
    }

    PersistedTriageValidationResult ValidatePersistedProcessTriageRecord(
        const PersistedProcessTriageRecord& record)
    {
        if (!record.identity.hasCreationTime &&
            record.identity.creationTimeFileTime != 0)
        {
            return Failure(
                PersistedTriageValidationCode::InvalidProcessIdentity,
                "identity.creationTimeFileTime",
                "An unavailable creation time must use a zero stored value.");
        }
        return ValidatePersistedTriageSummary(record.summary);
    }

    PersistedTriageValidationResult ValidatePersistedTriageContext(
        const PersistedTriageContext& context)
    {
        if (context.modelVersion != PersistedTriageModelVersion)
        {
            return Failure(
                PersistedTriageValidationCode::UnsupportedModelVersion,
                "modelVersion",
                "The persisted triage container uses an unsupported model version.");
        }
        if (context.processRecords.size() > PersistedTriageMaxProcessRecords)
        {
            return Failure(
                PersistedTriageValidationCode::CollectionLimitExceeded,
                "processRecords",
                "The persisted process-triage collection exceeds its cap.");
        }

        for (std::size_t index = 0; index < context.processRecords.size(); ++index)
        {
            if (index > 0)
            {
                const ProcessIdentityKey& previous =
                    context.processRecords[index - 1].identity;
                const ProcessIdentityKey& current =
                    context.processRecords[index].identity;
                if (previous == current)
                {
                    PersistedTriageValidationResult result = Failure(
                        PersistedTriageValidationCode::DuplicateProcessIdentity,
                        "processRecords",
                        "The persisted triage context contains a duplicate exact process identity.");
                    result.processRecordIndex = index;
                    return result;
                }
                if (!(previous < current))
                {
                    PersistedTriageValidationResult result = Failure(
                        PersistedTriageValidationCode::NonCanonicalOrder,
                        "processRecords",
                        "Persisted process-triage records are not in canonical identity order.");
                    result.processRecordIndex = index;
                    return result;
                }
            }

            PersistedTriageValidationResult result =
                ValidatePersistedProcessTriageRecord(context.processRecords[index]);
            if (!result)
            {
                result.processRecordIndex = index;
                result.field = "processRecords[" + std::to_string(index) + "]." +
                    result.field;
                return result;
            }
        }

        if (context.selectedRecord.has_value())
        {
            PersistedTriageValidationResult result =
                ValidatePersistedProcessTriageRecord(*context.selectedRecord);
            if (!result)
            {
                result.field = "selectedRecord." + result.field;
                return result;
            }
            if (context.FindProcess(context.selectedRecord->identity) == nullptr)
            {
                return Failure(
                    PersistedTriageValidationCode::SelectedProcessMissing,
                    "selectedRecord.identity",
                    "The selected triage identity is not present in processRecords.");
            }
        }

        return ValidResult();
    }

    const PersistedProcessTriageRecord* PersistedTriageContext::FindProcess(
        const ProcessIdentityKey& identity) const
    {
        const auto iterator = std::lower_bound(
            processRecords.begin(),
            processRecords.end(),
            identity,
            [](const PersistedProcessTriageRecord& record,
                const ProcessIdentityKey& key)
            {
                return record.identity < key;
            });
        return iterator != processRecords.end() && iterator->identity == identity
            ? &*iterator
            : nullptr;
    }

    PersistedTriageProjectionResult ProjectPersistedTriageSummary(
        const TriageResult& result,
        PersistedTriageAnalysisLevel analysisLevel,
        std::size_t sourceEvidenceCount,
        const TriageResult* baselineResult)
    {
        if (analysisLevel != PersistedTriageAnalysisLevel::Baseline &&
            analysisLevel != PersistedTriageAnalysisLevel::Enriched)
        {
            return ProjectionFailure(
                PersistedTriageValidationCode::ContradictoryState,
                "analysisLevel",
                "Successful projection requires Baseline or Enriched analysis.");
        }
        if (!result.Succeeded())
        {
            return ProjectionFailure(
                PersistedTriageValidationCode::ContradictoryState,
                "evaluationSucceeded",
                "Only a successful TriageResult can be projected as engine authority.");
        }
        if (!IsKnownVerdict(result.verdict))
        {
            return ProjectionFailure(
                PersistedTriageValidationCode::UnknownVerdict,
                "authoritativeVerdict",
                "The source TriageResult has an unknown verdict.");
        }
        if (sourceEvidenceCount > PersistedTriageMaxSourceEvidenceCount)
        {
            return ProjectionFailure(
                PersistedTriageValidationCode::SourceEvidenceLimitExceeded,
                "sourceEvidenceCount",
                "The source-evidence count exceeds the persistence cap.");
        }
        if (analysisLevel == PersistedTriageAnalysisLevel::Enriched &&
            (baselineResult == nullptr || !baselineResult->Succeeded()))
        {
            return ProjectionFailure(
                PersistedTriageValidationCode::ContradictoryState,
                "baselineVerdictAvailable",
                "Enriched projection requires a successful baseline TriageResult.");
        }

        PersistedTriageProjectionResult projection;
        PersistedTriageSummary& output = projection.summary;
        output.captured = true;
        output.evaluationSucceeded = true;
        output.usingFallback = false;
        output.analysisLevel = analysisLevel;
        output.authoritativeVerdict = result.verdict;
        output.triageModelVersion = PersistedTriageModelVersion;
        output.sourceEvidenceCount = sourceEvidenceCount;
        output.status = TruncateValidUtf8(
            result.statusMessage,
            PersistedTriageStatusMaxUtf8Bytes);
        output.contributingDomains.assign(
            result.contributingDomains.begin(),
            result.contributingDomains.end());

        if (analysisLevel == PersistedTriageAnalysisLevel::Baseline)
        {
            output.baselineVerdictAvailable = true;
            output.baselineVerdict = result.verdict;
        }
        else
        {
            output.baselineVerdictAvailable = true;
            output.baselineVerdict = baselineResult->verdict;
            output.enrichedChangedVerdict = result.verdict != baselineResult->verdict;
        }

        for (const TriageRationaleEntry& entry : result.previewRationaleEntries)
        {
            if (!AppendRationale(output, entry))
            {
                return ProjectionFailure(
                    PersistedTriageValidationCode::ContradictoryState,
                    "previewRationaleEntries",
                    "The source TriageResult contains an unknown rationale section.");
            }
        }

        projection.validation = ValidatePersistedTriageSummary(output);
        projection.success = projection.validation.valid;
        return projection;
    }

    PersistedTriageSummary MakeNotCapturedPersistedTriageSummary()
    {
        return {};
    }

    PersistedTriageContext MakePersistedTriageContext(
        std::vector<PersistedProcessTriageRecord> processRecords,
        std::optional<PersistedProcessTriageRecord> selectedRecord)
    {
        std::stable_sort(
            processRecords.begin(),
            processRecords.end(),
            [](const PersistedProcessTriageRecord& left,
                const PersistedProcessTriageRecord& right)
            {
                return left.identity < right.identity;
            });

        PersistedTriageContext context;
        context.processRecords = std::move(processRecords);
        context.selectedRecord = std::move(selectedRecord);
        return context;
    }
}
