#include "ObservationInventory.h"

#include "ObservationPolicy.h"

#include <algorithm>
#include <string>

namespace GlassPane::Core
{
    std::string ObservationInventoryStatusDisplayText(
        ObservationInventoryStatus status)
    {
        switch (status)
        {
        case ObservationInventoryStatus::Success:
            return "Success";
        case ObservationInventoryStatus::SourceLimitExceeded:
            return "Source record limit exceeded";
        case ObservationInventoryStatus::ObservationLimitExceeded:
            return "Observation limit exceeded";
        default:
            return "Unknown observation inventory status (" +
                std::to_string(static_cast<std::uint32_t>(status)) + ")";
        }
    }

    bool ObservationInventory::Succeeded() const
    {
        return status == ObservationInventoryStatus::Success;
    }

    std::vector<Observation> CollectInventoryObservations(
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

    ObservationShadowSummary SummarizeObservationShadow(
        const ObservationInventory& inventory)
    {
        ObservationShadowSummary summary;
        const std::vector<Observation> observations =
            CollectInventoryObservations(inventory);
        summary.observationCount = observations.size();
        summary.contributingObservationCount =
            static_cast<std::size_t>(std::count_if(
                observations.begin(),
                observations.end(),
                [](const Observation& observation)
                {
                    return CanContributeToVerdict(observation);
                }));
        summary.informationalCount = inventory.informationalCount;
        summary.contextCount = inventory.contextCount;
        summary.reviewRelevantCount = inventory.reviewRelevantCount;
        summary.correlatedOnlyCount = inventory.correlatedOnlyCount;
        summary.collectionNoteCount = inventory.collectionNoteCount;
        summary.evidenceIntegrityNoteCount = inventory.evidenceIntegrityNoteCount;
        summary.suppressedExpectedCount = inventory.suppressedExpectedCount;
        summary.contributingDomainCount =
            CollectContributingDomains(observations).size();
        summary.typedSourceFactCount = inventory.typedSourceFactCount;
        summary.declaredSourceFactCount = inventory.declaredSourceFactCount;
        return summary;
    }
}
