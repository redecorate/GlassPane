#include "ProcessTriageCache.h"

#include <algorithm>
#include <chrono>
#include <climits>
#include <exception>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace GlassPane::Core
{
    namespace
    {
        using Clock = std::chrono::steady_clock;

        std::uint64_t ElapsedMicroseconds(Clock::time_point started)
        {
            return static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    Clock::now() - started).count());
        }

        std::string Bounded(std::string value, std::size_t maximumCharacters)
        {
            if (value.size() > maximumCharacters)
            {
                value.resize(maximumCharacters);
            }
            return value;
        }

        void AppendUtf8CodePoint(std::string& output, std::uint32_t codePoint)
        {
            if (codePoint <= 0x7Fu)
            {
                output.push_back(static_cast<char>(codePoint));
            }
            else if (codePoint <= 0x7FFu)
            {
                output.push_back(static_cast<char>(0xC0u | (codePoint >> 6u)));
                output.push_back(static_cast<char>(0x80u | (codePoint & 0x3Fu)));
            }
            else if (codePoint <= 0xFFFFu)
            {
                output.push_back(static_cast<char>(0xE0u | (codePoint >> 12u)));
                output.push_back(static_cast<char>(0x80u | ((codePoint >> 6u) & 0x3Fu)));
                output.push_back(static_cast<char>(0x80u | (codePoint & 0x3Fu)));
            }
            else
            {
                output.push_back(static_cast<char>(0xF0u | (codePoint >> 18u)));
                output.push_back(static_cast<char>(0x80u | ((codePoint >> 12u) & 0x3Fu)));
                output.push_back(static_cast<char>(0x80u | ((codePoint >> 6u) & 0x3Fu)));
                output.push_back(static_cast<char>(0x80u | (codePoint & 0x3Fu)));
            }
        }

        std::string Utf8(std::wstring_view input)
        {
            std::string output;
            output.reserve(input.size());
            for (std::size_t index = 0; index < input.size(); ++index)
            {
                std::uint32_t codePoint = static_cast<std::uint32_t>(input[index]);
#if WCHAR_MAX <= 0xFFFF
                if (codePoint >= 0xD800u && codePoint <= 0xDBFFu)
                {
                    if (index + 1 < input.size())
                    {
                        const std::uint32_t low =
                            static_cast<std::uint32_t>(input[index + 1]);
                        if (low >= 0xDC00u && low <= 0xDFFFu)
                        {
                            codePoint = 0x10000u +
                                ((codePoint - 0xD800u) << 10u) +
                                (low - 0xDC00u);
                            ++index;
                        }
                        else
                        {
                            codePoint = 0xFFFDu;
                        }
                    }
                    else
                    {
                        codePoint = 0xFFFDu;
                    }
                }
                else if (codePoint >= 0xDC00u && codePoint <= 0xDFFFu)
                {
                    codePoint = 0xFFFDu;
                }
#else
                if (codePoint > 0x10FFFFu ||
                    (codePoint >= 0xD800u && codePoint <= 0xDFFFu))
                {
                    codePoint = 0xFFFDu;
                }
#endif
                AppendUtf8CodePoint(output, codePoint);
            }
            return output;
        }

        std::uint64_t Fnv1a64(std::string_view value)
        {
            std::uint64_t hash = 14695981039346656037ull;
            for (unsigned char character : value)
            {
                hash ^= character;
                hash *= 1099511628211ull;
            }
            return hash;
        }

        std::string BoundedArtifactKey(std::string value)
        {
            if (value.size() <= BaselineObservationFactKeyMaxCharacters)
            {
                return value;
            }

            std::ostringstream suffix;
            suffix << "#" << std::hex << std::setw(16) << std::setfill('0')
                   << Fnv1a64(value);
            const std::string suffixText = suffix.str();
            value.resize(BaselineObservationFactKeyMaxCharacters - suffixText.size());
            value += suffixText;
            return value;
        }

        std::string ConnectionArtifactKey(const NetworkConnection& connection)
        {
            std::ostringstream key;
            key << "network:"
                << Utf8(connection.protocol) << '|'
                << Utf8(connection.localAddress) << ':' << connection.localPort << '|'
                << Utf8(connection.remoteAddress) << ':' << connection.remotePort << '|'
                << Utf8(connection.state);
            return BoundedArtifactKey(key.str());
        }

        void AppendLimitation(
            BaselineObservationContext& context,
            std::string limitation)
        {
            limitation = Bounded(
                std::move(limitation),
                ObservationLimitationItemMaxCharacters);
            if (limitation.empty() ||
                std::find(
                    context.limitations.begin(),
                    context.limitations.end(),
                    limitation) != context.limitations.end())
            {
                return;
            }
            if (context.limitations.size() < BaselineObservationMaxLimitations)
            {
                context.limitations.push_back(std::move(limitation));
            }
        }

        void AppendRequiredLimitation(
            BaselineObservationContext& context,
            std::string limitation)
        {
            limitation = Bounded(
                std::move(limitation),
                ObservationLimitationItemMaxCharacters);
            if (limitation.empty() ||
                std::find(
                    context.limitations.begin(),
                    context.limitations.end(),
                    limitation) != context.limitations.end())
            {
                return;
            }
            if (context.limitations.size() >= BaselineObservationMaxLimitations)
            {
                // Internal identity limitations must survive caller-supplied
                // optional notes. Replace only the last bounded note.
                context.limitations.pop_back();
            }
            context.limitations.insert(
                context.limitations.begin(),
                std::move(limitation));
        }

        template <typename Fact>
        bool AppendBoundedFact(
            std::vector<Fact>& output,
            Fact fact,
            std::size_t cap,
            BaselineObservationContext& context,
            const char* omittedMessage)
        {
            if (output.size() >= cap)
            {
                context.preboundedSourceFactsTruncated = true;
                if (context.preboundedOmittedSourceFactCount !=
                    (std::numeric_limits<std::size_t>::max)())
                {
                    ++context.preboundedOmittedSourceFactCount;
                }
                AppendLimitation(context, omittedMessage);
                return false;
            }
            output.push_back(std::move(fact));
            return true;
        }

        std::string EntryFailureDiagnostic(
            const BaselineObservationResult& baseline,
            const ObservationRefinementResult& refinement,
            const ObservationCorrelationResult& correlations,
            const TriageResult& triage)
        {
            if (!baseline.Succeeded())
            {
                std::string message = "Baseline observation construction failed: " +
                    BaselineObservationStatusDisplayText(baseline.status);
                if (!baseline.diagnostic.empty())
                {
                    message += ". " + baseline.diagnostic;
                }
                return Bounded(
                    std::move(message),
                    ProcessTriageCacheDiagnosticMaxCharacters);
            }
            if (!refinement.Succeeded())
            {
                return Bounded(
                    "Observation refinement failed: " +
                        ObservationRefinementStatusDisplayText(refinement.status),
                    ProcessTriageCacheDiagnosticMaxCharacters);
            }
            if (!correlations.Succeeded())
            {
                return Bounded(
                    "Observation correlation failed: " +
                        ObservationCorrelationStatusDisplayText(correlations.status),
                    ProcessTriageCacheDiagnosticMaxCharacters);
            }
            if (!triage.Succeeded())
            {
                std::string message = "Triage evaluation failed: " +
                    TriageEngineStatusDisplayText(triage.status);
                if (!triage.statusMessage.empty())
                {
                    message += ". " + triage.statusMessage;
                }
                return Bounded(
                    std::move(message),
                    ProcessTriageCacheDiagnosticMaxCharacters);
            }
            return {};
        }

        void SummarizeSuccessfulEntry(
            const CachedBaselineTriage& entry,
            ProcessTriageCacheSummary& summary)
        {
            ++summary.successfulEntryCount;
            summary.observationCount += entry.baseline.inventory.records.size();
            summary.nativeFactCount += entry.baseline.nativeFactCount;
            summary.duplicateExcludedCount += entry.baseline.duplicateExcludedCount;
            if ((std::numeric_limits<std::size_t>::max)() -
                    summary.omittedFactCount <
                entry.baseline.omittedFactCount)
            {
                summary.omittedFactCount =
                    (std::numeric_limits<std::size_t>::max)();
            }
            else
            {
                summary.omittedFactCount += entry.baseline.omittedFactCount;
            }
            if (entry.baseline.truncated)
            {
                ++summary.truncatedEntryCount;
            }
            summary.contributingDomainCount += entry.triage.contributingDomains.size();
            summary.activatedCorrelationCount +=
                entry.correlations.summary.activatedCorrelationCount;

            switch (entry.triage.verdict)
            {
            case TriageVerdict::LowAttention:
                ++summary.lowAttentionCount;
                break;
            case TriageVerdict::MediumAttention:
                ++summary.mediumAttentionCount;
                break;
            case TriageVerdict::HighAttention:
                ++summary.highAttentionCount;
                break;
            case TriageVerdict::Informational:
            default:
                ++summary.informationalCount;
                break;
            }

        }

        void AppendCacheWarning(ProcessTriageCache& cache, std::string warning)
        {
            warning = Bounded(
                std::move(warning),
                ProcessTriageCacheDiagnosticMaxCharacters);
            if (warning.empty())
            {
                return;
            }
            if (cache.warnings.size() < ProcessTriageCacheMaxWarnings)
            {
                cache.warnings.push_back(std::move(warning));
            }
            else
            {
                cache.warningsTruncated = true;
            }
        }

        BaselineObservationContext DefaultContext(
            const ProcessTriageCacheBuildOptions& options)
        {
            BaselineObservationContext context;
            context.sourceKind = options.sourceStamp.loadedSnapshot
                ? ObservationSourceKind::Imported
                : options.sourceKind;
            context.collectionTimestamp = Bounded(
                options.collectionTimestamp,
                ObservationProvenanceCollectionTimestampMaxCharacters);
            context.importedEvidence = options.sourceStamp.loadedSnapshot;
            context.includeNativeProcessIdentity = options.includeNativeProcessIdentity;
            context.includeNativeExecutablePath = options.includeNativeExecutablePath;
            context.includeNativeCommandLine = options.includeNativeCommandLine;
            context.includeNativeRelationshipContext =
                options.includeNativeRelationshipContext;
            for (const std::string& limitation : options.limitations)
            {
                AppendLimitation(context, limitation);
            }
            return context;
        }

        void FinalizeSummaryDurations(
            ProcessTriageCache& cache,
            std::uint64_t totalDuration,
            std::uint64_t entryDurationSum)
        {
            cache.summary.totalBuildDurationMicroseconds = totalDuration;
            cache.summary.averageEntryBuildDurationMicroseconds =
                cache.entries.empty()
                    ? 0
                    : entryDurationSum / cache.entries.size();
        }
    }

    bool operator==(const ProcessIdentityKey& left, const ProcessIdentityKey& right)
    {
        return left.pid == right.pid &&
            left.hasCreationTime == right.hasCreationTime &&
            (!left.hasCreationTime ||
                left.creationTimeFileTime == right.creationTimeFileTime);
    }

    bool operator!=(const ProcessIdentityKey& left, const ProcessIdentityKey& right)
    {
        return !(left == right);
    }

    bool operator<(const ProcessIdentityKey& left, const ProcessIdentityKey& right)
    {
        if (left.pid != right.pid)
        {
            return left.pid < right.pid;
        }
        if (left.hasCreationTime != right.hasCreationTime)
        {
            return left.hasCreationTime < right.hasCreationTime;
        }
        if (!left.hasCreationTime)
        {
            return false;
        }
        return left.creationTimeFileTime < right.creationTimeFileTime;
    }

    ProcessIdentityKey MakeProcessIdentityKey(const ProcessInfo& process)
    {
        return {
            process.pid,
            process.hasCreationTime,
            process.hasCreationTime ? process.creationTimeFileTime : 0
        };
    }

    bool operator==(
        const ProcessTriageCacheSourceStamp& left,
        const ProcessTriageCacheSourceStamp& right)
    {
        return left.processGeneration == right.processGeneration &&
            left.evidenceGeneration == right.evidenceGeneration &&
            left.scopeGeneration == right.scopeGeneration &&
            left.loadedSnapshot == right.loadedSnapshot;
    }

    bool operator!=(
        const ProcessTriageCacheSourceStamp& left,
        const ProcessTriageCacheSourceStamp& right)
    {
        return !(left == right);
    }

    std::string ProcessTriageCacheStatusDisplayText(ProcessTriageCacheStatus status)
    {
        switch (status)
        {
        case ProcessTriageCacheStatus::NotAttempted:
            return "Not attempted";
        case ProcessTriageCacheStatus::Success:
            return "Success";
        case ProcessTriageCacheStatus::PartialSuccess:
            return "Partial success";
        case ProcessTriageCacheStatus::InvalidInput:
            return "Invalid input";
        case ProcessTriageCacheStatus::InternalFailure:
            return "Internal failure";
        default:
            return "Unknown (" +
                std::to_string(static_cast<std::uint32_t>(status)) + ")";
        }
    }

    bool ProcessTriageCache::Succeeded() const
    {
        return attempted && success &&
            (status == ProcessTriageCacheStatus::Success ||
                status == ProcessTriageCacheStatus::PartialSuccess);
    }

    bool ProcessTriageCache::MatchesStamp(
        const ProcessTriageCacheSourceStamp& expected) const
    {
        return Succeeded() && sourceStamp == expected;
    }

    const CachedBaselineTriage* ProcessTriageCache::Find(
        const ProcessIdentityKey& identity) const
    {
        const ProcessIdentityKey canonical = {
            identity.pid,
            identity.hasCreationTime,
            identity.hasCreationTime ? identity.creationTimeFileTime : 0
        };
        const auto found = std::lower_bound(
            entries.begin(),
            entries.end(),
            canonical,
            [](const CachedBaselineTriage& entry, const ProcessIdentityKey& key)
            {
                return entry.identity < key;
            });
        return found != entries.end() && found->identity == canonical
            ? &*found
            : nullptr;
    }

    const CachedBaselineTriage* ProcessTriageCache::Find(
        const ProcessInfo& process) const
    {
        return Find(MakeProcessIdentityKey(process));
    }

    ProcessTriageCache BuildProcessTriageCache(
        const ProcessSnapshot& snapshot,
        const std::vector<BaselineObservationContext>& processContexts,
        const ProcessTriageCacheBuildOptions& options) noexcept
    {
        const Clock::time_point cacheStarted = Clock::now();
        ProcessTriageCache cache;
        cache.attempted = true;
        cache.sourceStamp = options.sourceStamp;
        cache.summary.sourceProcessCount = snapshot.processes.size();

        if (!processContexts.empty() &&
            processContexts.size() != snapshot.processes.size())
        {
            cache.status = ProcessTriageCacheStatus::InvalidInput;
            cache.statusMessage =
                "Baseline process contexts must be empty or align exactly with the process snapshot.";
            cache.summary.totalBuildDurationMicroseconds =
                ElapsedMicroseconds(cacheStarted);
            return cache;
        }

        struct WorkItem
        {
            const ProcessInfo* process = nullptr;
            const BaselineObservationContext* context = nullptr;
            ProcessIdentityKey identity;
            std::size_t sourceOrdinal = 0;
        };

        try
        {
            std::vector<WorkItem> work;
            work.reserve(snapshot.processes.size());
            for (std::size_t index = 0; index < snapshot.processes.size(); ++index)
            {
                work.push_back({
                    &snapshot.processes[index],
                    processContexts.empty() ? nullptr : &processContexts[index],
                    MakeProcessIdentityKey(snapshot.processes[index]),
                    index
                });
            }
            std::stable_sort(
                work.begin(),
                work.end(),
                [](const WorkItem& left, const WorkItem& right)
                {
                    if (left.identity != right.identity)
                    {
                        return left.identity < right.identity;
                    }
                    return left.sourceOrdinal < right.sourceOrdinal;
                });

            cache.entries.reserve(
                (std::min)(work.size(), ProcessTriageCacheMaxEntries));
            std::uint64_t entryDurationSum = 0;
            for (std::size_t begin = 0; begin < work.size();)
            {
                std::size_t end = begin + 1;
                while (end < work.size() &&
                    work[end].identity == work[begin].identity)
                {
                    ++end;
                }

                if (cache.entries.size() >= ProcessTriageCacheMaxEntries)
                {
                    ++cache.summary.omittedProcessCount;
                    begin = end;
                    continue;
                }

                const WorkItem& item = work[begin];
                CachedBaselineTriage entry;
                entry.identity = item.identity;
                entry.sourceStamp = options.sourceStamp;
                entry.attempted = true;
                const Clock::time_point entryStarted = Clock::now();

                if (end - begin > 1)
                {
                    cache.summary.duplicateIdentityCount += end - begin - 1;
                    entry.diagnostic =
                        "Duplicate process identity rows prevent an unambiguous baseline result.";
                }
                else
                {
                    try
                    {
                        const BaselineObservationContext context = item.context == nullptr
                            ? DefaultContext(options)
                            : *item.context;
                        entry.baseline = BuildBaselineObservations(
                            *item.process,
                            snapshot,
                            context);
                        if (entry.baseline.Succeeded())
                        {
                            entry.refinement = RefineObservationInventory(
                                entry.baseline.inventory);
                        }
                        if (entry.refinement.Succeeded())
                        {
                            entry.correlations = ActivateObservationCorrelations(
                                entry.refinement);
                        }
                        if (entry.correlations.Succeeded())
                        {
                            entry.triage = BuildTriageResult(
                                entry.refinement,
                                entry.correlations);
                        }
                        entry.success = entry.baseline.Succeeded() &&
                            entry.refinement.Succeeded() &&
                            entry.correlations.Succeeded() &&
                            entry.triage.Succeeded();
                        entry.diagnostic = EntryFailureDiagnostic(
                            entry.baseline,
                            entry.refinement,
                            entry.correlations,
                            entry.triage);
                    }
                    catch (const std::exception& exception)
                    {
                        entry.diagnostic = Bounded(
                            std::string("Baseline pipeline exception: ") + exception.what(),
                            ProcessTriageCacheDiagnosticMaxCharacters);
                    }
                    catch (...)
                    {
                        entry.diagnostic =
                            "Baseline pipeline failed with an internal exception.";
                    }
                }

                entry.buildDurationMicroseconds = ElapsedMicroseconds(entryStarted);
                entryDurationSum += entry.buildDurationMicroseconds;
                cache.summary.maximumEntryBuildDurationMicroseconds =
                    (std::max)(
                        cache.summary.maximumEntryBuildDurationMicroseconds,
                        entry.buildDurationMicroseconds);

                if (entry.success)
                {
                    SummarizeSuccessfulEntry(entry, cache.summary);
                    if (entry.baseline.truncated ||
                        entry.baseline.omittedFactCount != 0)
                    {
                        cache.partial = true;
                        cache.truncated = true;
                    }
                }
                else
                {
                    ++cache.summary.failedEntryCount;
                    ++cache.summary.unavailableEntryCount;
                    AppendCacheWarning(
                        cache,
                        "Baseline triage unavailable for PID " +
                            std::to_string(item.identity.pid) + ": " +
                            (entry.diagnostic.empty()
                                ? std::string("unknown pipeline failure")
                                : entry.diagnostic));
                }

                cache.entries.push_back(std::move(entry));
                begin = end;
            }

            cache.summary.retainedProcessCount = cache.entries.size();
            cache.truncated = cache.truncated ||
                cache.summary.omittedProcessCount != 0;
            cache.partial = cache.partial || cache.truncated ||
                cache.summary.failedEntryCount != 0 ||
                cache.summary.duplicateIdentityCount != 0;
            cache.success = true;
            cache.status = cache.partial
                ? ProcessTriageCacheStatus::PartialSuccess
                : ProcessTriageCacheStatus::Success;

            std::ostringstream status;
            status << "Baseline triage cache built for "
                   << cache.summary.retainedProcessCount << " process identities";
            if (cache.summary.failedEntryCount != 0)
            {
                status << "; " << cache.summary.failedEntryCount
                       << " entries unavailable";
            }
            if (cache.summary.omittedProcessCount != 0)
            {
                status << "; " << cache.summary.omittedProcessCount
                       << " identities omitted by the cache cap";
            }
            if (cache.summary.omittedFactCount != 0)
            {
                status << "; " << cache.summary.omittedFactCount
                       << " baseline source facts omitted by per-process caps";
            }
            if (cache.summary.duplicateIdentityCount != 0)
            {
                status << "; " << cache.summary.duplicateIdentityCount
                       << " duplicate source rows";
            }
            status << '.';
            cache.statusMessage = Bounded(
                status.str(),
                ProcessTriageCacheStatusMessageMaxCharacters);
            FinalizeSummaryDurations(
                cache,
                ElapsedMicroseconds(cacheStarted),
                entryDurationSum);
            return cache;
        }
        catch (...)
        {
            ProcessTriageCache failed;
            failed.attempted = true;
            failed.sourceStamp = options.sourceStamp;
            failed.summary.sourceProcessCount = snapshot.processes.size();
            failed.status = ProcessTriageCacheStatus::InternalFailure;
            failed.statusMessage =
                "Baseline triage cache construction failed atomically.";
            failed.summary.totalBuildDurationMicroseconds =
                ElapsedMicroseconds(cacheStarted);
            return failed;
        }
    }

    ProcessTriageCache BuildProcessTriageCache(
        const ProcessSnapshot& snapshot,
        const NetworkCollectionResult& network,
        const std::vector<NetworkIndicatorMatch>& networkIndicatorMatches,
        const ServiceCollectionResult& services,
        const ProcessTriageCacheBuildOptions& options) noexcept
    {
        const Clock::time_point cacheStarted = Clock::now();
        try
        {
            std::vector<BaselineObservationContext> contexts;
            contexts.reserve(snapshot.processes.size());
            for (std::size_t index = 0; index < snapshot.processes.size(); ++index)
            {
                contexts.push_back(DefaultContext(options));
            }

            std::unordered_map<std::uint32_t, std::vector<std::size_t>> indexesByPid;
            indexesByPid.reserve(snapshot.processes.size());
            for (std::size_t index = 0; index < snapshot.processes.size(); ++index)
            {
                indexesByPid[snapshot.processes[index].pid].push_back(index);
            }

            std::size_t ambiguousPidEntryCount = 0;
            for (const auto& item : indexesByPid)
            {
                if (item.second.size() <= 1)
                {
                    continue;
                }
                ambiguousPidEntryCount += item.second.size();
                for (std::size_t processIndex : item.second)
                {
                    AppendRequiredLimitation(
                        contexts[processIndex],
                        "PID-only network, indicator, and service evidence was excluded because multiple process identities share this PID in the same snapshot.");
                }
            }

            const ObservationSourceKind endpointSourceKind =
                options.sourceStamp.loadedSnapshot
                    ? ObservationSourceKind::Imported
                    : options.sourceKind;

            if (options.networkContextCaptured && network.success)
            {
                for (const NetworkConnection& connection : network.connections)
                {
                    if (!connection.isPublicRemote)
                    {
                        continue;
                    }
                    const auto processIndexes = indexesByPid.find(connection.owningPid);
                    if (processIndexes == indexesByPid.end() ||
                        processIndexes->second.size() != 1)
                    {
                        continue;
                    }
                    const std::size_t processIndex =
                        processIndexes->second.front();
                    BaselineNetworkConnectionFact fact;
                    fact.artifactKey = ConnectionArtifactKey(connection);
                    fact.protocol = Utf8(connection.protocol);
                    fact.localAddress = Utf8(connection.localAddress);
                    fact.localPort = connection.localPort;
                    fact.remoteAddress = Utf8(connection.remoteAddress);
                    fact.remotePort = connection.remotePort;
                    fact.state = Utf8(connection.state);
                    fact.publicRemote = true;
                    fact.sourceKind = endpointSourceKind;
                    fact.sourceIdentifier = options.sourceStamp.loadedSnapshot
                        ? "persisted-network-context"
                        : "local-network-snapshot";
                    fact.collectionMethod = options.sourceStamp.loadedSnapshot
                        ? "loaded snapshot network record"
                        : "existing process-wide network collection";
                    AppendBoundedFact(
                        contexts[processIndex].networkConnections,
                        std::move(fact),
                        BaselineObservationMaxNetworkConnections,
                        contexts[processIndex],
                        "Additional public network connection context was omitted by the per-process baseline cap.");
                }

                for (const NetworkIndicatorMatch& match : networkIndicatorMatches)
                {
                    const auto processIndexes =
                        indexesByPid.find(match.connection.owningPid);
                    if (processIndexes == indexesByPid.end() ||
                        processIndexes->second.size() != 1)
                    {
                        continue;
                    }
                    const std::size_t processIndex =
                        processIndexes->second.front();
                    BaselineNetworkIndicatorFact fact;
                    fact.artifactKey = ConnectionArtifactKey(match.connection);
                    fact.sourceRuleId = BaselineMappingExactNetworkIndicator;
                    fact.indicatorType = Utf8(match.indicator.type);
                    fact.rawValue = Utf8(match.indicator.value);
                    fact.normalizedValue = Utf8(match.indicator.normalizedValue);
                    fact.strength = ObservationStrength::Moderate;
                    fact.confidence = ObservationConfidence::Medium;
                    fact.sourceKind = ObservationSourceKind::Imported;
                    fact.sourceIdentifier = match.indicator.source.empty()
                        ? "network-intelligence-feed"
                        : Utf8(match.indicator.source);
                    fact.collectionMethod = options.sourceStamp.loadedSnapshot
                        ? "persisted exact network-indicator match"
                        : "existing exact network-indicator match";
                    AppendBoundedFact(
                        contexts[processIndex].networkIndicatorFacts,
                        std::move(fact),
                        BaselineObservationMaxNetworkIndicatorFacts,
                        contexts[processIndex],
                        "Additional exact network-indicator matches were omitted by the per-process baseline cap.");
                }
            }
            else if (options.networkCollectionAttempted && !network.success)
            {
                const std::string status = network.statusMessage.empty()
                    ? "Network context collection was attempted but unavailable."
                    : "Network context collection was unavailable: " +
                        Utf8(network.statusMessage);
                for (BaselineObservationContext& context : contexts)
                {
                    BaselineCollectionFact fact;
                    fact.kind = BaselineCollectionFactKind::NetworkUnavailable;
                    fact.sourceRuleId = BaselineMappingNetworkCollectionUnavailable;
                    fact.statusMessage = status;
                    fact.sourceIdentifier = options.sourceStamp.loadedSnapshot
                        ? "persisted-network-context"
                        : "local-network-snapshot";
                    fact.collectionMethod = options.sourceStamp.loadedSnapshot
                        ? "loaded snapshot network availability"
                        : "existing process-wide network collection";
                    AppendBoundedFact(
                        context.collectionFacts,
                        std::move(fact),
                        BaselineObservationMaxCollectionFacts,
                        context,
                        "Additional baseline collection limitations were omitted by the per-process cap.");
                    AppendLimitation(context, status);
                }
            }

            if (options.serviceContextCaptured && services.attempted &&
                (services.success || services.partial || !services.services.empty()))
            {
                for (const ServiceInfo& service : services.services)
                {
                    if (service.scmProcessId == 0 ||
                        !service.pidReliableForState)
                    {
                        continue;
                    }
                    const auto processIndexes = indexesByPid.find(service.scmProcessId);
                    if (processIndexes == indexesByPid.end() ||
                        processIndexes->second.size() != 1)
                    {
                        continue;
                    }
                    const std::size_t processIndex =
                        processIndexes->second.front();
                    BaselineServiceAssociationFact fact;
                    fact.artifactKey = BoundedArtifactKey(
                        "service:" + Utf8(service.serviceName));
                    fact.serviceName = Utf8(service.serviceName);
                    fact.displayName = Utf8(service.displayName);
                    fact.processModel = service.processModel;
                    fact.stateRaw = service.stateRaw;
                    fact.sourceKind = endpointSourceKind;
                    fact.sourceIdentifier = options.sourceStamp.loadedSnapshot
                        ? "persisted-service-context"
                        : "local-service-control-manager";
                    fact.collectionMethod = options.sourceStamp.loadedSnapshot
                        ? "loaded snapshot SCM-reported PID association"
                        : "existing SCM-reported PID association";
                    fact.limitations.push_back(
                        "SCM-reported PID association is context, not verified process ownership.");
                    AppendBoundedFact(
                        contexts[processIndex].serviceAssociations,
                        std::move(fact),
                        BaselineObservationMaxServiceAssociations,
                        contexts[processIndex],
                        "Additional service associations were omitted by the per-process baseline cap.");
                }
                if (services.partial || services.truncated)
                {
                    for (BaselineObservationContext& context : contexts)
                    {
                        AppendLimitation(
                            context,
                            "Service context is partial or truncated; available associations remain SCM-reported context only.");
                    }
                }
            }
            else if (options.serviceContextCaptured && services.attempted &&
                !services.success)
            {
                const std::string status = services.statusMessage.empty()
                    ? "Service context collection was attempted but unavailable."
                    : "Service context collection was unavailable: " +
                        Utf8(services.statusMessage);
                for (BaselineObservationContext& context : contexts)
                {
                    BaselineCollectionFact fact;
                    fact.kind = BaselineCollectionFactKind::ServiceUnavailable;
                    fact.sourceRuleId = BaselineMappingServiceCollectionUnavailable;
                    fact.statusMessage = status;
                    fact.sourceIdentifier = options.sourceStamp.loadedSnapshot
                        ? "persisted-service-context"
                        : "local-service-control-manager";
                    fact.collectionMethod = options.sourceStamp.loadedSnapshot
                        ? "loaded snapshot service-context availability"
                        : "existing active-service snapshot collection";
                    AppendBoundedFact(
                        context.collectionFacts,
                        std::move(fact),
                        BaselineObservationMaxCollectionFacts,
                        context,
                        "Additional baseline collection limitations were omitted by the per-process cap.");
                    AppendLimitation(context, status);
                }
            }

            ProcessTriageCache cache = BuildProcessTriageCache(
                snapshot,
                contexts,
                options);
            cache.summary.ambiguousPidEntryCount =
                ambiguousPidEntryCount;
            if (ambiguousPidEntryCount != 0 && cache.success)
            {
                cache.partial = true;
                cache.status = ProcessTriageCacheStatus::PartialSuccess;
                cache.statusMessage = Bounded(
                    cache.statusMessage + " " +
                        std::to_string(ambiguousPidEntryCount) +
                        " entries excluded PID-only endpoint evidence because their PID was ambiguous.",
                    ProcessTriageCacheStatusMessageMaxCharacters);
            }
            cache.summary.totalBuildDurationMicroseconds =
                ElapsedMicroseconds(cacheStarted);
            return cache;
        }
        catch (...)
        {
            ProcessTriageCache failed;
            failed.attempted = true;
            failed.sourceStamp = options.sourceStamp;
            failed.summary.sourceProcessCount = snapshot.processes.size();
            failed.status = ProcessTriageCacheStatus::InternalFailure;
            failed.statusMessage =
                "Baseline triage endpoint context construction failed atomically.";
            failed.summary.totalBuildDurationMicroseconds =
                ElapsedMicroseconds(cacheStarted);
            return failed;
        }
    }
}
