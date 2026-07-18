#pragma once

#include "BaselineObservationBuilder.h"
#include "NetworkConnection.h"
#include "NetworkIndicator.h"
#include "ObservationCorrelation.h"
#include "ObservationRefinement.h"
#include "ProcessInfo.h"
#include "ServiceInfo.h"
#include "TriageEngine.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace GlassPane::Core
{
    constexpr std::size_t ProcessTriageCacheMaxEntries = 4096;
    constexpr std::size_t ProcessTriageCacheMaxWarnings = 128;
    constexpr std::size_t ProcessTriageCacheDiagnosticMaxCharacters = 1024;
    constexpr std::size_t ProcessTriageCacheStatusMessageMaxCharacters = 1024;

    // PID zero is a valid identity. Creation-time availability participates in
    // equality so an unavailable timestamp is never confused with a known
    // zero value, and PID reuse cannot retain a stale timestamped entry.
    struct ProcessIdentityKey
    {
        std::uint32_t pid = 0;
        bool hasCreationTime = false;
        std::uint64_t creationTimeFileTime = 0;
    };

    bool operator==(const ProcessIdentityKey& left, const ProcessIdentityKey& right);
    bool operator!=(const ProcessIdentityKey& left, const ProcessIdentityKey& right);
    bool operator<(const ProcessIdentityKey& left, const ProcessIdentityKey& right);

    ProcessIdentityKey MakeProcessIdentityKey(const ProcessInfo& process);

    // Network and endpoint evidence can change without a process refresh. All
    // three generations and the live/offline scope therefore form the cache
    // validity stamp.
    struct ProcessTriageCacheSourceStamp
    {
        std::uint64_t processGeneration = 0;
        std::uint64_t evidenceGeneration = 0;
        std::uint64_t scopeGeneration = 0;
        bool loadedSnapshot = false;
    };

    bool operator==(
        const ProcessTriageCacheSourceStamp& left,
        const ProcessTriageCacheSourceStamp& right);
    bool operator!=(
        const ProcessTriageCacheSourceStamp& left,
        const ProcessTriageCacheSourceStamp& right);

    enum class ProcessTriageCacheStatus : std::uint32_t
    {
        NotAttempted = 0,
        Success = 1,
        PartialSuccess = 2,
        InvalidInput = 3,
        InternalFailure = 4
    };

    std::string ProcessTriageCacheStatusDisplayText(ProcessTriageCacheStatus status);

    struct CachedBaselineTriage
    {
        ProcessIdentityKey identity;
        ProcessTriageCacheSourceStamp sourceStamp;

        bool attempted = false;
        bool success = false;
        BaselineObservationResult baseline;
        ObservationRefinementResult refinement;
        ObservationCorrelationResult correlations;
        TriageResult triage;

        std::string diagnostic;
        std::uint64_t buildDurationMicroseconds = 0;
    };

    struct ProcessTriageCacheSummary
    {
        std::size_t sourceProcessCount = 0;
        std::size_t retainedProcessCount = 0;
        std::size_t omittedProcessCount = 0;
        std::size_t successfulEntryCount = 0;
        std::size_t failedEntryCount = 0;
        // Native baseline authority could not be produced for this identity.
        // This is an unavailable count, not a legacy-verdict fallback count.
        std::size_t unavailableEntryCount = 0;
        std::size_t duplicateIdentityCount = 0;
        std::size_t ambiguousPidEntryCount = 0;
        std::size_t truncatedEntryCount = 0;
        std::size_t omittedFactCount = 0;

        std::size_t informationalCount = 0;
        std::size_t lowAttentionCount = 0;
        std::size_t mediumAttentionCount = 0;
        std::size_t highAttentionCount = 0;

        std::size_t observationCount = 0;
        std::size_t nativeFactCount = 0;
        std::size_t duplicateExcludedCount = 0;
        std::size_t contributingDomainCount = 0;
        std::size_t activatedCorrelationCount = 0;

        std::uint64_t totalBuildDurationMicroseconds = 0;
        std::uint64_t maximumEntryBuildDurationMicroseconds = 0;
        std::uint64_t averageEntryBuildDurationMicroseconds = 0;

    };

    struct ProcessTriageCache
    {
        bool attempted = false;
        bool success = false;
        bool partial = false;
        bool truncated = false;
        ProcessTriageCacheStatus status = ProcessTriageCacheStatus::NotAttempted;
        ProcessTriageCacheSourceStamp sourceStamp;

        std::vector<CachedBaselineTriage> entries;
        ProcessTriageCacheSummary summary;

        bool warningsTruncated = false;
        std::vector<std::string> warnings;
        std::string statusMessage;

        bool Succeeded() const;
        bool MatchesStamp(const ProcessTriageCacheSourceStamp& expected) const;
        const CachedBaselineTriage* Find(const ProcessIdentityKey& identity) const;
        const CachedBaselineTriage* Find(const ProcessInfo& process) const;
    };

    struct ProcessTriageCacheBuildOptions
    {
        ProcessTriageCacheSourceStamp sourceStamp;
        ObservationSourceKind sourceKind = ObservationSourceKind::Direct;
        std::string collectionTimestamp;
        std::vector<std::string> limitations;
        // These flags distinguish an attempted failure from intentionally
        // absent/not-captured baseline evidence. The result structs alone do
        // not carry that distinction for every live/offline source.
        bool networkContextCaptured = false;
        bool networkCollectionAttempted = false;
        bool serviceContextCaptured = false;
        bool includeNativeProcessIdentity = true;
        bool includeNativeExecutablePath = true;
        bool includeNativeCommandLine = true;
        bool includeNativeRelationshipContext = true;
    };

    // Lower-level pure build seam. Contexts must be empty (default native
    // contexts are created) or exactly aligned with snapshot.processes. The
    // returned value is a complete candidate suitable for one move assignment;
    // no existing cache is ever mutated during construction.
    ProcessTriageCache BuildProcessTriageCache(
        const ProcessSnapshot& snapshot,
        const std::vector<BaselineObservationContext>& processContexts,
        const ProcessTriageCacheBuildOptions& options) noexcept;

    // Endpoint build path. Global collections are read only during this call
    // and are pre-indexed once by PID. No pointer/reference is retained in the
    // returned cache and no collector, filesystem, network, or UI work occurs.
    ProcessTriageCache BuildProcessTriageCache(
        const ProcessSnapshot& snapshot,
        const NetworkCollectionResult& network,
        const std::vector<NetworkIndicatorMatch>& networkIndicatorMatches,
        const ServiceCollectionResult& services,
        const ProcessTriageCacheBuildOptions& options) noexcept;
}
