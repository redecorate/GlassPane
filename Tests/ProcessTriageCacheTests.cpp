#include "Core/ProcessTriageCache.h"
#include "Core/GraphModel.h"
#include "Core/TimelineModel.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iostream>
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

        ProcessInfo MakeProcess(
            std::uint32_t pid,
            std::uint64_t creationTime,
            Severity severity = Severity::None,
            std::wstring name = L"generic-cache-process.exe")
        {
            ProcessInfo process;
            process.pid = pid;
            process.parentPid = 0;
            process.name = std::move(name);
            process.executablePath =
                L"C:\\Program Files\\Generic\\generic-cache-process.exe";
            process.commandLine = L"generic-cache-process.exe --run";
            process.commandLineAccessible = true;
            process.hasCreationTime = true;
            process.creationTimeFileTime = creationTime;
            process.severity = severity;
            process.suspicious = severity == Severity::Low ||
                severity == Severity::Medium || severity == Severity::High;
            return process;
        }

        ProcessSnapshot MakeSnapshot(std::vector<ProcessInfo> processes)
        {
            ProcessSnapshot snapshot;
            snapshot.processes = std::move(processes);
            snapshot.Reindex();
            return snapshot;
        }

        ProcessTriageCacheBuildOptions MakeOptions()
        {
            ProcessTriageCacheBuildOptions options;
            options.sourceStamp = { 11, 23, 37, false };
            options.collectionTimestamp = "2026-07-16T12:00:00Z";
            return options;
        }

        const ObservationRecord* FindMapping(
            const CachedBaselineTriage& entry,
            const std::string& mappingRuleId)
        {
            const auto found = std::find_if(
                entry.baseline.inventory.records.begin(),
                entry.baseline.inventory.records.end(),
                [&](const ObservationRecord& record)
                {
                    return record.source.mappingRuleId == mappingRuleId;
                });
            return found == entry.baseline.inventory.records.end()
                ? nullptr
                : &*found;
        }

        std::size_t CountMapping(
            const CachedBaselineTriage& entry,
            const std::string& mappingRuleId)
        {
            return static_cast<std::size_t>(std::count_if(
                entry.baseline.inventory.records.begin(),
                entry.baseline.inventory.records.end(),
                [&](const ObservationRecord& record)
                {
                    return record.source.mappingRuleId == mappingRuleId;
                }));
        }

        bool HasLimitationContaining(
            const CachedBaselineTriage& entry,
            const std::string& text)
        {
            return std::any_of(
                entry.baseline.limitations.begin(),
                entry.baseline.limitations.end(),
                [&](const std::string& limitation)
                {
                    return limitation.find(text) != std::string::npos;
                });
        }

        void TestIdentityStampAndPidReuse()
        {
            ProcessInfo pidZero = MakeProcess(0, 41);
            const ProcessIdentityKey zeroKey = MakeProcessIdentityKey(pidZero);
            CheckEqual(zeroKey.pid, std::uint32_t(0), L"PID zero remains a valid cache key");
            Check(zeroKey.hasCreationTime, L"PID zero retains creation-time availability");

            ProcessInfo unavailableTime = MakeProcess(0, 99);
            unavailableTime.hasCreationTime = false;
            const ProcessIdentityKey unavailableKey =
                MakeProcessIdentityKey(unavailableTime);
            Check(!unavailableKey.hasCreationTime, L"unavailable creation time remains explicit");
            CheckEqual(unavailableKey.creationTimeFileTime, std::uint64_t(0), L"unavailable timestamp canonicalized");
            Check(unavailableKey != zeroKey, L"creation-time availability participates in identity");

            ProcessSnapshot first = MakeSnapshot({ MakeProcess(200, 1000) });
            ProcessTriageCache firstCache = BuildProcessTriageCache(
                first,
                std::vector<BaselineObservationContext>{},
                MakeOptions());
            Check(firstCache.Succeeded(), L"first PID generation cache succeeds");
            Check(firstCache.Find(first.processes.front()) != nullptr, L"first PID generation is found");

            ProcessSnapshot reused = MakeSnapshot({ MakeProcess(200, 2000) });
            ProcessTriageCache secondCache = BuildProcessTriageCache(
                reused,
                std::vector<BaselineObservationContext>{},
                MakeOptions());
            Check(secondCache.Succeeded(), L"reused PID generation cache succeeds");
            Check(secondCache.Find(first.processes.front()) == nullptr, L"old PID generation is absent after replacement candidate");
            Check(secondCache.Find(reused.processes.front()) != nullptr, L"new PID generation is present");

            ProcessTriageCacheSourceStamp stale = MakeOptions().sourceStamp;
            ++stale.evidenceGeneration;
            Check(!secondCache.MatchesStamp(stale), L"evidence-generation mismatch rejects cache");
            Check(secondCache.MatchesStamp(MakeOptions().sourceStamp), L"complete source stamp matches");
        }

        void TestEmptyDeterministicBuildAndOrdering()
        {
            const ProcessSnapshot empty;
            const ProcessTriageCache emptyCache = BuildProcessTriageCache(
                empty,
                std::vector<BaselineObservationContext>{},
                MakeOptions());
            Check(emptyCache.Succeeded(), L"empty process snapshot produces a successful empty cache");
            Check(emptyCache.entries.empty(), L"empty cache contains no entries");

            const ProcessSnapshot snapshot = MakeSnapshot({
                MakeProcess(900, 90),
                MakeProcess(10, 10),
                MakeProcess(900, 80)
            });
            const ProcessTriageCache first = BuildProcessTriageCache(
                snapshot,
                std::vector<BaselineObservationContext>{},
                MakeOptions());
            const ProcessTriageCache second = BuildProcessTriageCache(
                snapshot,
                std::vector<BaselineObservationContext>{},
                MakeOptions());
            Check(first.Succeeded() && second.Succeeded(), L"deterministic cache builds succeed");
            CheckEqual(first.entries.size(), std::size_t(3), L"one entry retained per distinct identity");
            Check(std::is_sorted(
                first.entries.begin(),
                first.entries.end(),
                [](const CachedBaselineTriage& left, const CachedBaselineTriage& right)
                {
                    return left.identity < right.identity;
                }), L"cache entries are in deterministic identity order");
            CheckEqual(first.entries.size(), second.entries.size(), L"repeated cache output size deterministic");
            for (std::size_t index = 0; index < first.entries.size(); ++index)
            {
                CheckEqual(first.entries[index].identity, second.entries[index].identity, L"repeated cache identity ordering deterministic");
                CheckEqual(first.entries[index].triage.verdict, second.entries[index].triage.verdict, L"repeated cache verdict deterministic");
                CheckEqual(first.entries[index].baseline.inventory.records.size(), second.entries[index].baseline.inventory.records.size(), L"repeated observation count deterministic");
            }
        }

        void TestPerEntryFailureIsolationAndAtomicInputFailure()
        {
            const ProcessSnapshot snapshot = MakeSnapshot({
                MakeProcess(100, 100),
                MakeProcess(200, 200)
            });
            std::vector<BaselineObservationContext> contexts(2);
            contexts[1].entityScope.assign(
                ObservationEntityScopeMaxCharacters + 1,
                'x');
            const ProcessTriageCache partial = BuildProcessTriageCache(
                snapshot,
                contexts,
                MakeOptions());
            Check(partial.Succeeded(), L"one entry failure preserves a usable cache candidate");
            Check(partial.partial, L"one entry failure marks aggregate partial");
            CheckEqual(partial.summary.successfulEntryCount, std::size_t(1), L"one entry succeeds in isolated failure fixture");
            CheckEqual(partial.summary.failedEntryCount, std::size_t(1), L"one entry fails in isolated failure fixture");
            CheckEqual(partial.summary.unavailableEntryCount, std::size_t(1), L"one native authority entry is unavailable");
            Check(partial.Find(snapshot.processes[0]) != nullptr &&
                partial.Find(snapshot.processes[0])->success,
                L"successful neighbor remains valid");
            Check(partial.Find(snapshot.processes[1]) != nullptr &&
                !partial.Find(snapshot.processes[1])->success,
                L"failed entry remains bounded and diagnosable");

            const ProcessTriageCache invalid = BuildProcessTriageCache(
                snapshot,
                std::vector<BaselineObservationContext>(1),
                MakeOptions());
            Check(!invalid.Succeeded(), L"misaligned contexts fail atomically");
            CheckEqual(invalid.status, ProcessTriageCacheStatus::InvalidInput, L"misaligned context status");
            Check(invalid.entries.empty(), L"atomic input failure exposes no partial entries");
        }

        void TestEndpointContextPreindexAndNoRetainedPointers()
        {
            const ProcessSnapshot snapshot = MakeSnapshot({
                MakeProcess(300, 300),
                MakeProcess(400, 400)
            });

            NetworkCollectionResult network;
            network.success = true;
            NetworkConnection publicConnection;
            publicConnection.owningPid = 300;
            publicConnection.protocol = L"TCP";
            publicConnection.localAddress = L"10.0.0.8";
            publicConnection.localPort = 51000;
            publicConnection.remoteAddress = L"203.0.113.15";
            publicConnection.remotePort = 443;
            publicConnection.state = L"Established";
            publicConnection.isPublicRemote = true;
            network.connections.push_back(publicConnection);
            NetworkConnection privateConnection = publicConnection;
            privateConnection.owningPid = 400;
            privateConnection.remoteAddress = L"10.0.0.9";
            privateConnection.isPublicRemote = false;
            network.connections.push_back(privateConnection);

            NetworkIndicatorMatch indicatorMatch;
            indicatorMatch.connection = publicConnection;
            indicatorMatch.indicator.type = L"ip";
            indicatorMatch.indicator.value = L"203.0.113.15";
            indicatorMatch.indicator.normalizedValue = L"203.0.113.15";
            indicatorMatch.indicator.source = L"generic-fixture-feed";

            ServiceCollectionResult services;
            services.attempted = true;
            services.success = true;
            ServiceInfo service;
            service.serviceName = L"generic-service";
            service.displayName = L"Generic Service";
            service.scmProcessId = 400;
            service.pidReliableForState = true;
            service.processModel = ServiceProcessModel::SharedProcess;
            service.stateRaw = 4;
            services.services.push_back(service);
            services.ReindexCorrelations();

            ProcessTriageCacheBuildOptions options = MakeOptions();
            options.networkContextCaptured = true;
            options.networkCollectionAttempted = true;
            options.serviceContextCaptured = true;
            ProcessTriageCache cache = BuildProcessTriageCache(
                snapshot,
                network,
                { indicatorMatch },
                services,
                options);
            Check(cache.Succeeded(), L"endpoint-context cache succeeds");
            const CachedBaselineTriage* networkEntry = cache.Find(snapshot.processes[0]);
            const CachedBaselineTriage* serviceEntry = cache.Find(snapshot.processes[1]);
            Check(networkEntry != nullptr && networkEntry->success, L"network owner baseline succeeds");
            Check(serviceEntry != nullptr && serviceEntry->success, L"service owner baseline succeeds");
            if (networkEntry != nullptr)
            {
                Check(FindMapping(*networkEntry, BaselineMappingPublicNetworkConnection) != nullptr, L"public network connection preindexed by PID");
                Check(FindMapping(*networkEntry, BaselineMappingExactNetworkIndicator) != nullptr, L"exact network match preindexed by PID");
                CheckEqual(networkEntry->triage.verdict, TriageVerdict::MediumAttention, L"exact match alone retains baseline Medium ceiling");
            }
            if (serviceEntry != nullptr)
            {
                Check(FindMapping(*serviceEntry, BaselineMappingServiceAssociation) != nullptr, L"service association preindexed by PID");
                Check(FindMapping(*serviceEntry, BaselineMappingPublicNetworkConnection) == nullptr, L"non-public connection does not create public context");
                CheckEqual(serviceEntry->triage.verdict, TriageVerdict::Informational, L"service association remains neutral context");
            }

            network.connections.clear();
            services.services.clear();
            Check(networkEntry != nullptr &&
                FindMapping(*networkEntry, BaselineMappingExactNetworkIndicator) != nullptr,
                L"cache owns observations after endpoint inputs mutate");
            Check(serviceEntry != nullptr &&
                FindMapping(*serviceEntry, BaselineMappingServiceAssociation) != nullptr,
                L"cache retains no service-buffer pointers");
        }

        void TestCapturedVersusAbsentAndImportedEvidence()
        {
            const ProcessSnapshot snapshot = MakeSnapshot({ MakeProcess(500, 500) });
            NetworkCollectionResult network;
            network.success = false;
            network.statusMessage = L"Generic network source unavailable";
            ServiceCollectionResult services;
            services.attempted = true;
            services.success = false;
            services.statusMessage = L"Generic service source unavailable";

            ProcessTriageCacheBuildOptions absent = MakeOptions();
            const ProcessTriageCache absentCache = BuildProcessTriageCache(
                snapshot,
                network,
                {},
                services,
                absent);
            const CachedBaselineTriage* absentEntry = absentCache.Find(snapshot.processes[0]);
            Check(absentEntry != nullptr && absentEntry->success, L"intentionally absent endpoint sources do not fail baseline");
            if (absentEntry != nullptr)
            {
                CheckEqual(absentEntry->baseline.inventory.collectionNoteCount, std::size_t(0), L"not-captured sources do not fabricate CollectionNotes");
            }

            ProcessTriageCacheBuildOptions attempted = MakeOptions();
            attempted.networkContextCaptured = true;
            attempted.networkCollectionAttempted = true;
            attempted.serviceContextCaptured = true;
            attempted.sourceStamp.loadedSnapshot = true;
            const ProcessTriageCache attemptedCache = BuildProcessTriageCache(
                snapshot,
                network,
                {},
                services,
                attempted);
            const CachedBaselineTriage* attemptedEntry =
                attemptedCache.Find(snapshot.processes[0]);
            Check(attemptedEntry != nullptr && attemptedEntry->success, L"attempted unavailable sources remain non-fatal");
            if (attemptedEntry != nullptr)
            {
                CheckEqual(attemptedEntry->triage.verdict, TriageVerdict::Informational, L"collection limits do not elevate baseline verdict");
                Check(attemptedEntry->baseline.inventory.collectionNoteCount >= 2, L"explicit network/service failures become CollectionNotes");
                Check(std::all_of(
                    attemptedEntry->baseline.inventory.records.begin(),
                    attemptedEntry->baseline.inventory.records.end(),
                    [](const ObservationRecord& record)
                    {
                        return record.observation.sourceKind == ObservationSourceKind::Imported ||
                            record.observation.sourceKind == ObservationSourceKind::Unavailable;
                    }), L"loaded-snapshot baseline provenance remains imported/unavailable");
            }
        }

        void TestDuplicatePidEndpointEvidenceIsolation()
        {
            const ProcessSnapshot snapshot = MakeSnapshot({
                MakeProcess(550, 1000, Severity::None, L"first-generic-identity.exe"),
                MakeProcess(550, 2000, Severity::None, L"second-generic-identity.exe")
            });

            NetworkConnection connection;
            connection.owningPid = 550;
            connection.protocol = L"TCP";
            connection.localAddress = L"10.0.0.5";
            connection.localPort = 52000;
            connection.remoteAddress = L"203.0.113.55";
            connection.remotePort = 443;
            connection.state = L"Established";
            connection.isPublicRemote = true;
            NetworkCollectionResult network;
            network.success = true;
            network.connections.push_back(connection);

            NetworkIndicatorMatch match;
            match.connection = connection;
            match.indicator.type = L"ip";
            match.indicator.value = connection.remoteAddress;
            match.indicator.normalizedValue = connection.remoteAddress;
            match.indicator.source = L"generic-loaded-fixture";

            ServiceInfo service;
            service.serviceName = L"generic-loaded-service";
            service.displayName = L"Generic Loaded Service";
            service.scmProcessId = 550;
            service.pidReliableForState = true;
            service.stateRaw = 4;
            ServiceCollectionResult services;
            services.attempted = true;
            services.success = true;
            services.services.push_back(service);
            services.ReindexCorrelations();

            ProcessTriageCacheBuildOptions options = MakeOptions();
            options.sourceStamp.loadedSnapshot = true;
            options.networkContextCaptured = true;
            options.networkCollectionAttempted = true;
            options.serviceContextCaptured = true;
            const ProcessTriageCache cache = BuildProcessTriageCache(
                snapshot,
                network,
                { match },
                services,
                options);

            Check(cache.Succeeded(), L"loaded duplicate-PID cache remains structurally usable");
            Check(cache.partial, L"ambiguous PID evidence exclusion marks cache partial");
            CheckEqual(cache.summary.ambiguousPidEntryCount, std::size_t(2), L"ambiguous PID entry count exact");
            for (const ProcessInfo& process : snapshot.processes)
            {
                const CachedBaselineTriage* entry = cache.Find(process);
                Check(entry != nullptr && entry->success, L"each creation-time identity retains a baseline entry");
                if (entry == nullptr)
                {
                    continue;
                }
                Check(FindMapping(*entry, BaselineMappingPublicNetworkConnection) == nullptr, L"ambiguous PID receives no PID-only network fact");
                Check(FindMapping(*entry, BaselineMappingExactNetworkIndicator) == nullptr, L"ambiguous PID receives no PID-only IOC fact");
                Check(FindMapping(*entry, BaselineMappingServiceAssociation) == nullptr, L"ambiguous PID receives no PID-only service fact");
                Check(HasLimitationContaining(*entry, "multiple process identities share this PID"), L"ambiguous PID exclusion remains auditable");
                Check(std::all_of(
                    entry->baseline.inventory.records.begin(),
                    entry->baseline.inventory.records.end(),
                    [](const ObservationRecord& record)
                    {
                        return record.observation.sourceKind ==
                            ObservationSourceKind::Imported;
                    }), L"loaded duplicate-PID native evidence retains imported provenance");
            }
        }

        void TestEndpointFactCapPropagation()
        {
            const ProcessSnapshot snapshot = MakeSnapshot({ MakeProcess(580, 580) });
            NetworkCollectionResult network;
            network.success = true;
            std::vector<NetworkIndicatorMatch> matches;
            ServiceCollectionResult services;
            services.attempted = true;
            services.success = true;

            constexpr std::size_t FactCount =
                BaselineObservationMaxNetworkIndicatorFacts + 1;
            for (std::size_t index = 0; index < FactCount; ++index)
            {
                NetworkConnection connection;
                connection.owningPid = 580;
                connection.protocol = L"TCP";
                connection.localAddress = L"10.0.0.8";
                connection.localPort = static_cast<std::uint16_t>(40000 + index);
                connection.remoteAddress =
                    L"203.0.113." + std::to_wstring((index % 200) + 1);
                connection.remotePort = static_cast<std::uint16_t>(1000 + index);
                connection.state = L"Established";
                connection.isPublicRemote = true;
                network.connections.push_back(connection);

                NetworkIndicatorMatch match;
                match.connection = connection;
                match.indicator.type = L"ip";
                match.indicator.value = connection.remoteAddress;
                match.indicator.normalizedValue = connection.remoteAddress;
                match.indicator.source = L"generic-cap-fixture";
                matches.push_back(std::move(match));

                ServiceInfo service;
                service.serviceName = L"generic-service-" +
                    std::to_wstring(index);
                service.displayName = service.serviceName;
                service.scmProcessId = 580;
                service.pidReliableForState = true;
                service.stateRaw = 4;
                services.services.push_back(std::move(service));
            }

            ProcessTriageCacheBuildOptions options = MakeOptions();
            options.networkContextCaptured = true;
            options.networkCollectionAttempted = true;
            options.serviceContextCaptured = true;
            const ProcessTriageCache cache = BuildProcessTriageCache(
                snapshot,
                network,
                matches,
                services,
                options);
            Check(cache.Succeeded(), L"over-cap endpoint facts retain a usable cache");
            Check(cache.partial && cache.truncated, L"pre-cap endpoint omission propagates cache truncation");
            CheckEqual(cache.summary.truncatedEntryCount, std::size_t(1), L"pre-cap truncated entry count exact");
            CheckEqual(cache.summary.omittedFactCount, std::size_t(3), L"network IOC and service pre-cap omissions counted");
            const CachedBaselineTriage* entry = cache.Find(snapshot.processes.front());
            Check(entry != nullptr && entry->success, L"over-cap process entry succeeds with bounded facts");
            if (entry != nullptr)
            {
                Check(entry->baseline.truncated, L"builder result receives external truncation state");
                CheckEqual(entry->baseline.omittedFactCount, std::size_t(3), L"builder result receives external omitted count");
                CheckEqual(CountMapping(*entry, BaselineMappingPublicNetworkConnection), BaselineObservationMaxNetworkConnections, L"public connection facts capped exactly");
                CheckEqual(CountMapping(*entry, BaselineMappingExactNetworkIndicator), BaselineObservationMaxNetworkIndicatorFacts, L"IOC facts capped exactly");
                CheckEqual(CountMapping(*entry, BaselineMappingServiceAssociation), BaselineObservationMaxServiceAssociations, L"service facts capped exactly");
            }
        }

        void TestNativeSummaryAndLegacyIndependence()
        {
            const ProcessSnapshot snapshot = MakeSnapshot({
                MakeProcess(610, 610, Severity::High, L"first-generic-name.exe"),
                MakeProcess(620, 620, Severity::Low, L"second-generic-name.exe"),
                MakeProcess(630, 630, Severity::None, L"third-generic-name.exe")
            });
            const ProcessTriageCache cache = BuildProcessTriageCache(
                snapshot,
                std::vector<BaselineObservationContext>{},
                MakeOptions());
            Check(cache.Succeeded(), L"native cache succeeds independently of legacy process metadata");
            CheckEqual(cache.summary.informationalCount, std::size_t(3), L"normal generic baseline entries informational");
            CheckEqual(cache.summary.unavailableEntryCount, std::size_t(0), L"all native authority entries are available");

            ProcessSnapshot renamed = snapshot;
            renamed.processes[0].name = L"unrelated-generic-name.exe";
            renamed.processes[0].severity = Severity::None;
            const ProcessTriageCache renamedCache = BuildProcessTriageCache(
                renamed,
                std::vector<BaselineObservationContext>{},
                MakeOptions());
            CheckEqual(
                cache.Find(snapshot.processes[0])->triage.verdict,
                renamedCache.Find(renamed.processes[0])->triage.verdict,
                L"process name and legacy severity cannot change baseline policy");
            CheckEqual(
                cache.summary.informationalCount,
                renamedCache.summary.informationalCount,
                L"legacy severity does not alter native cache summary diagnostics");
        }

        void TestDuplicateIdentityCapAndBoundedPerformance()
        {
            const ProcessSnapshot duplicateSnapshot = MakeSnapshot({
                MakeProcess(700, 700),
                MakeProcess(700, 700)
            });
            const ProcessTriageCache duplicate = BuildProcessTriageCache(
                duplicateSnapshot,
                std::vector<BaselineObservationContext>{},
                MakeOptions());
            Check(duplicate.Succeeded(), L"duplicate identity produces bounded partial cache");
            Check(duplicate.partial, L"duplicate identity marks cache partial");
            CheckEqual(duplicate.entries.size(), std::size_t(1), L"duplicate identity retains one diagnostic entry");
            CheckEqual(duplicate.summary.duplicateIdentityCount, std::size_t(1), L"duplicate source row counted");
            Check(!duplicate.entries.front().success, L"duplicate identity never selects an ambiguous source row");

            std::vector<ProcessInfo> processes;
            std::vector<BaselineObservationContext> invalidContexts;
            processes.reserve(ProcessTriageCacheMaxEntries + 1);
            invalidContexts.reserve(ProcessTriageCacheMaxEntries + 1);
            for (std::size_t index = 0; index < ProcessTriageCacheMaxEntries + 1; ++index)
            {
                processes.push_back(MakeProcess(
                    static_cast<std::uint32_t>(1000 + index),
                    100000 + index));
                BaselineObservationContext context;
                context.entityScope.assign(
                    ObservationEntityScopeMaxCharacters + 1,
                    'x');
                invalidContexts.push_back(std::move(context));
            }
            const ProcessSnapshot large = MakeSnapshot(std::move(processes));
            const ProcessTriageCache capped = BuildProcessTriageCache(
                large,
                invalidContexts,
                MakeOptions());
            Check(capped.Succeeded(), L"entry-cap candidate remains structurally usable");
            Check(capped.truncated, L"entry cap records truncation");
            CheckEqual(capped.entries.size(), ProcessTriageCacheMaxEntries, L"entry cap enforced exactly");
            CheckEqual(capped.summary.omittedProcessCount, std::size_t(1), L"entry cap omitted count exact");
            Check(capped.warnings.size() <= ProcessTriageCacheMaxWarnings, L"aggregate warnings remain bounded");
            Check(capped.warningsTruncated, L"over-cap failure warnings disclose truncation");

            std::vector<ProcessInfo> thousandProcesses;
            thousandProcesses.reserve(1000);
            NetworkCollectionResult representativeNetwork;
            representativeNetwork.success = true;
            std::vector<NetworkIndicatorMatch> representativeMatches;
            ServiceCollectionResult representativeServices;
            representativeServices.attempted = true;
            representativeServices.success = true;
            for (std::size_t index = 0; index < 1000; ++index)
            {
                thousandProcesses.push_back(MakeProcess(
                    static_cast<std::uint32_t>(10000 + index),
                    200000 + index));

                if (index % 10 == 0)
                {
                    NetworkConnection connection;
                    connection.owningPid = static_cast<std::uint32_t>(10000 + index);
                    connection.protocol = L"TCP";
                    connection.localAddress = L"10.0.0.10";
                    connection.localPort =
                        static_cast<std::uint16_t>(30000 + index);
                    connection.remoteAddress =
                        L"203.0.113." + std::to_wstring((index % 200) + 1);
                    connection.remotePort = 443;
                    connection.state = L"Established";
                    connection.isPublicRemote = true;
                    representativeNetwork.connections.push_back(connection);

                    ServiceInfo service;
                    service.serviceName = L"generic-perf-service-" +
                        std::to_wstring(index);
                    service.displayName = service.serviceName;
                    service.scmProcessId = connection.owningPid;
                    service.pidReliableForState = true;
                    service.stateRaw = 4;
                    representativeServices.services.push_back(std::move(service));

                    if (index % 100 == 0)
                    {
                        NetworkIndicatorMatch match;
                        match.connection = connection;
                        match.indicator.type = L"ip";
                        match.indicator.value = connection.remoteAddress;
                        match.indicator.normalizedValue =
                            connection.remoteAddress;
                        match.indicator.source = L"generic-performance-feed";
                        representativeMatches.push_back(std::move(match));
                    }
                }
            }
            const ProcessSnapshot thousand = MakeSnapshot(std::move(thousandProcesses));
            ProcessTriageCacheBuildOptions performanceOptions = MakeOptions();
            performanceOptions.networkContextCaptured = true;
            performanceOptions.networkCollectionAttempted = true;
            performanceOptions.serviceContextCaptured = true;
            const ProcessTriageCache lightweight = BuildProcessTriageCache(
                thousand,
                representativeNetwork,
                representativeMatches,
                representativeServices,
                performanceOptions);
            Check(lightweight.Succeeded(), L"one-thousand-process native baseline cache succeeds");
            CheckEqual(lightweight.entries.size(), std::size_t(1000), L"one-thousand-process cache retains every identity");
            Check(lightweight.summary.nativeFactCount > 1000, L"performance fixture keeps native producers and representative global evidence enabled");
            CheckEqual(lightweight.summary.failedEntryCount, std::size_t(0), L"representative endpoint cache has no failed entries");
            CheckEqual(lightweight.summary.unavailableEntryCount, std::size_t(0), L"representative endpoint cache has no unavailable native authority entries");
            Check(lightweight.summary.totalBuildDurationMicroseconds < 30000000ULL, L"bounded thousand-process fixture completes within generous limit");
            std::wcout << L"Baseline cache fixture: entries="
                       << lightweight.entries.size()
                       << L", total-us="
                       << lightweight.summary.totalBuildDurationMicroseconds
                       << L", max-entry-us="
                       << lightweight.summary.maximumEntryBuildDurationMicroseconds
                       << L", average-entry-us="
                       << lightweight.summary.averageEntryBuildDurationMicroseconds
                       << L".\n";
            const std::uint64_t originalDuration =
                lightweight.summary.totalBuildDurationMicroseconds;
            for (const ProcessInfo& process : thousand.processes)
            {
                Check(lightweight.Find(process) != nullptr, L"cache lookup returns prebuilt entry without rebuilding");
            }
            CheckEqual(lightweight.summary.totalBuildDurationMicroseconds, originalDuration, L"lookup does not mutate or rebuild cache");
        }

        void TestGraphAndTimelineRetainSourceProcessIdentity()
        {
            ProcessInfo first = MakeProcess(8800, 100, Severity::High);
            first.name = L"generic-first-identity.exe";
            ProcessInfo reused = MakeProcess(8800, 200, Severity::None);
            reused.name = L"generic-reused-identity.exe";
            const ProcessSnapshot duplicatePidSnapshot =
                MakeSnapshot({ first, reused });
            const std::vector<Severity> authoritativeSeverities = {
                Severity::None,
                Severity::Medium
            };
            const std::vector<std::uint8_t> authoritativeSuspicious = { 0, 1 };
            const std::vector<std::uint8_t> authoritativeAvailable = { 1, 1 };

            const std::vector<TimelineRow> timeline = BuildTimelineRows(
                duplicatePidSnapshot,
                TimelineFilter::All,
                authoritativeSeverities,
                authoritativeSuspicious,
                authoritativeAvailable);
            CheckEqual(timeline.size(), std::size_t(2), L"timeline retains both duplicate-PID source rows");
            CheckEqual(timeline[0].sourceProcessIndex, std::size_t(0), L"timeline first row retains exact source index");
            CheckEqual(timeline[1].sourceProcessIndex, std::size_t(1), L"timeline reused PID row retains exact source index");
            Check(timeline[0].authorityAvailable, L"timeline records current native authority availability");
            Check(timeline[1].authorityAvailable, L"timeline records reused identity native authority availability");
            CheckEqual(timeline[0].severity, Severity::None, L"timeline ignores legacy High process severity");
            CheckEqual(timeline[1].severity, Severity::Medium, L"timeline consumes exact native authority projection");
            const std::vector<TimelineRow> suspiciousTimeline = BuildTimelineRows(
                duplicatePidSnapshot,
                TimelineFilter::SuspiciousOnly,
                authoritativeSeverities,
                authoritativeSuspicious,
                authoritativeAvailable);
            CheckEqual(suspiciousTimeline.size(), std::size_t(1), L"timeline suspicious filter uses native projection only");
            if (!suspiciousTimeline.empty())
            {
                CheckEqual(suspiciousTimeline.front().sourceProcessIndex, std::size_t(1), L"timeline excludes legacy-suspicious native-informational row");
            }
            const std::vector<TimelineRow> unavailableTimeline =
                BuildTimelineRows(
                    duplicatePidSnapshot,
                    TimelineFilter::SuspiciousOnly,
                    {},
                    {},
                    {});
            Check(
                unavailableTimeline.empty(),
                L"unavailable native authority is neutral and excluded from suspicious timeline filtering");

            const FocusedGraph graph = BuildFocusedTree(
                duplicatePidSnapshot,
                reused.pid,
                authoritativeSeverities,
                authoritativeSuspicious,
                authoritativeAvailable,
                0);
            CheckEqual(graph.nodes.size(), std::size_t(1), L"focused graph retains selected duplicate-PID identity only");
            if (!graph.nodes.empty())
            {
                CheckEqual(graph.nodes.front().sourceProcessIndex, std::size_t(1), L"focused graph node retains exact current source index");
                CheckEqual(graph.nodes.front().name, reused.name, L"focused graph does not borrow stale PID identity");
                Check(graph.nodes.front().authorityAvailable, L"focused graph records current native authority availability");
                CheckEqual(graph.nodes.front().severity, Severity::Medium, L"focused graph consumes native authority severity directly");
                Check(graph.nodes.front().suspicious, L"focused graph consumes native suspicious classification directly");
            }
            const FocusedGraph unavailableGraph = BuildFocusedTree(
                duplicatePidSnapshot,
                reused.pid,
                {},
                {},
                {},
                0);
            if (!unavailableGraph.nodes.empty())
            {
                Check(!unavailableGraph.nodes.front().authorityAvailable, L"focused graph distinguishes unavailable authority from Informational");
                CheckEqual(unavailableGraph.nodes.front().severity, Severity::None, L"unavailable graph authority renders neutral");
                Check(!unavailableGraph.nodes.front().suspicious, L"unavailable graph authority is not silently suspicious or clean");
            }
        }
    }

    int RunProcessTriageCacheTests()
    {
        failureCount = 0;
        TestIdentityStampAndPidReuse();
        TestEmptyDeterministicBuildAndOrdering();
        TestPerEntryFailureIsolationAndAtomicInputFailure();
        TestEndpointContextPreindexAndNoRetainedPointers();
        TestCapturedVersusAbsentAndImportedEvidence();
        TestDuplicatePidEndpointEvidenceIsolation();
        TestEndpointFactCapPropagation();
        TestNativeSummaryAndLegacyIndependence();
        TestDuplicateIdentityCapAndBoundedPerformance();
        TestGraphAndTimelineRetainSourceProcessIdentity();
        return failureCount;
    }
}
