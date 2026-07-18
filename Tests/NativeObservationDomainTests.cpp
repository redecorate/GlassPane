#include "Core/NativeObservationBuilder.h"
#include "Core/ObservationCorrelation.h"
#include "Core/ObservationRefinement.h"
#include "Core/TriageEngine.h"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <string>

namespace GlassPane::Tests
{
    namespace
    {
        using namespace Core;

        int failureCount = 0;

        void Check(bool condition, const wchar_t* name)
        {
            if (!condition)
            {
                std::wcerr << L"FAILED: " << name << L'\n';
                ++failureCount;
            }
        }

        ProcessIdentityKey Identity()
        {
            ProcessIdentityKey identity;
            identity.pid = 9100;
            identity.hasCreationTime = true;
            identity.creationTimeFileTime = 91000;
            return identity;
        }

        NativeObservationSource Source(
            ObservationSourceKind kind = ObservationSourceKind::Direct)
        {
            NativeObservationSource source;
            source.sourceKind = kind;
            source.sourceIdentifier = "generic-typed-fixture";
            source.collectionMethod = "already-collected-fixture";
            source.rawSourceReference = "fixture-record";
            return source;
        }

        NativeSelectedProcessObservationInput EmptyInput()
        {
            NativeSelectedProcessObservationInput input;
            input.identity = Identity();
            input.entityScope =
                "selected-process/live/pid:9100/created:91000";
            return input;
        }

        const Observation* FindMapping(
            const NativeObservationBuildResult& result,
            const std::string& mapping)
        {
            const auto found = std::find_if(
                result.inventory.records.begin(),
                result.inventory.records.end(),
                [&](const ObservationRecord& record)
                {
                    return record.source.mappingRuleId == mapping;
                });
            return found == result.inventory.records.end()
                ? nullptr
                : &found->observation;
        }

        std::string Attribute(
            const Observation& observation,
            const std::string& key)
        {
            const auto found = std::find_if(
                observation.artifactAttributes.begin(),
                observation.artifactAttributes.end(),
                [&](const ObservationArtifactAttribute& attribute)
                {
                    return attribute.key == key;
                });
            return found == observation.artifactAttributes.end()
                ? std::string{}
                : found->value;
        }

        TriageResult CompleteTriage(
            const NativeObservationBuildResult& native)
        {
            if (!native.Succeeded())
            {
                return {};
            }
            const ObservationRefinementResult refined =
                RefineObservationInventory(native.inventory);
            if (!refined.Succeeded())
            {
                return {};
            }
            const ObservationCorrelationResult correlations =
                ActivateObservationCorrelations(refined);
            if (!correlations.Succeeded())
            {
                return {};
            }
            return BuildTriageResult(refined, correlations);
        }

        void TestAffinityIsNativeContext()
        {
            NativeSelectedProcessObservationInput input = EmptyInput();
            input.affinity.identity = input.identity;
            input.affinity.supplied = true;
            input.affinity.collectionAttempted = true;
            input.affinity.available = true;
            input.affinity.processAffinityMask = 0x4U;
            input.affinity.systemAffinityMask = 0xffU;
            input.affinity.source = Source();

            const NativeObservationBuildResult result =
                BuildNativeSelectedProcessObservations(input);
            Check(result.Succeeded(), L"native affinity build succeeds");
            const Observation* affinity = FindMapping(
                result,
                NativeMappingAffinityContext);
            Check(affinity != nullptr, L"native affinity observation exists");
            if (affinity != nullptr)
            {
                Check(
                    affinity->disposition == ObservationDisposition::Context &&
                        !affinity->contributesToVerdict,
                    L"single-processor affinity remains non-contributing context");
                Check(
                    Attribute(*affinity, "affinity.selected-processor-count") ==
                        "1",
                    L"affinity selected processor count is typed");
                Check(
                    Attribute(*affinity, "affinity.active-processor-count") ==
                        "8",
                    L"affinity active processor count is typed");
            }
            const TriageResult triage = CompleteTriage(result);
            Check(
                triage.Succeeded() &&
                    triage.verdict == TriageVerdict::Informational,
                L"single-processor affinity alone is Informational");
        }

        void TestNetworkFactsAreNativeAndConservative()
        {
            NativeSelectedProcessObservationInput contextInput = EmptyInput();
            contextInput.network.identity = contextInput.identity;
            contextInput.network.supplied = true;
            contextInput.network.collectionAttempted = true;
            contextInput.network.available = true;
            contextInput.network.source = Source();
            NetworkConnection connection;
            connection.owningPid = contextInput.identity.pid;
            connection.protocol = L"TCP";
            connection.localAddress = L"10.0.0.5";
            connection.localPort = 51000;
            connection.remoteAddress = L"198.51.100.10";
            connection.remotePort = 443;
            connection.isPublicRemote = true;
            contextInput.network.connections.push_back(connection);

            NativeObservationBuildResult contextResult =
                BuildNativeSelectedProcessObservations(contextInput);
            Check(contextResult.Succeeded(), L"public network context build succeeds");
            Check(
                CompleteTriage(contextResult).verdict ==
                    TriageVerdict::Informational,
                L"public network context alone is Informational");

            NetworkIndicatorMatch match;
            match.connection = connection;
            match.indicator.type = L"ip";
            match.indicator.value = connection.remoteAddress;
            match.indicator.normalizedValue = connection.remoteAddress;
            match.indicator.category = L"generic test category";
            match.indicator.severity = L"critical source label";
            match.indicator.confidence = L"source confidence label";
            match.indicator.source = L"generic imported feed";
            contextInput.network.exactIndicatorMatches.push_back(match);

            const NativeObservationBuildResult exactResult =
                BuildNativeSelectedProcessObservations(contextInput);
            Check(exactResult.Succeeded(), L"exact IOC native build succeeds");
            const Observation* exact = FindMapping(
                exactResult,
                NativeMappingExactNetworkIndicator);
            Check(exact != nullptr, L"exact IOC native observation exists");
            if (exact != nullptr)
            {
                Check(
                    exact->sourceKind == ObservationSourceKind::Imported &&
                        exact->strength == ObservationStrength::Moderate &&
                        exact->confidence == ObservationConfidence::Medium,
                    L"feed labels remain metadata and do not set OE strength or confidence");
            }
            const TriageResult exactTriage = CompleteTriage(exactResult);
            Check(
                exactTriage.Succeeded() &&
                    exactTriage.verdict == TriageVerdict::MediumAttention,
                L"exact IOC alone retains its Medium ceiling");
        }

        void TestModuleFactsAreArtifactScopedContext()
        {
            NativeSelectedProcessObservationInput input = EmptyInput();
            input.modules.identity = input.identity;
            input.modules.supplied = true;
            input.modules.collectionAttempted = true;
            input.modules.available = true;
            input.modules.collection.success = true;
            input.modules.source = Source();

            ModuleInfo module;
            module.moduleName = L"generic.dll";
            module.modulePath = L"C:\\Users\\Generic\\AppData\\generic.dll";
            module.baseAddress = L"0x100000";
            module.sizeBytes = 4096;
            module.readable = true;
            module.indicators.push_back(
                L"legacy name/path heuristic must not select native policy");
            input.modules.collection.modules = { module, module };

            const NativeObservationBuildResult result =
                BuildNativeSelectedProcessObservations(input);
            Check(result.Succeeded(), L"native module build succeeds");
            Check(
                result.inventory.records.size() == 1 &&
                    result.duplicateCount == 1,
                L"duplicate module rows are one artifact evidence unit");
            const Observation* context = FindMapping(
                result,
                NativeMappingModuleUserWritablePath);
            Check(context != nullptr, L"typed user-writable module context exists");
            if (context != nullptr)
            {
                Check(
                    context->domain == EvidenceDomain::Module &&
                        context->disposition == ObservationDisposition::Context &&
                        !context->contributesToVerdict,
                    L"module path alone remains Module context");
                Check(
                    std::find(
                        context->evidence.begin(),
                        context->evidence.end(),
                        "Module base address: 0x100000") !=
                            context->evidence.end(),
                    L"module source evidence retains typed base metadata");
            }
            Check(
                CompleteTriage(result).verdict ==
                    TriageVerdict::Informational,
                L"module path context alone is Informational");
        }

        void TestStaticMemoryAttributesRemainOneContextArtifact()
        {
            NativeSelectedProcessObservationInput input = EmptyInput();
            input.memory.identity = input.identity;
            input.memory.supplied = true;
            input.memory.collectionAttempted = true;
            input.memory.available = true;
            input.memory.collection.success = true;
            input.memory.source = Source();

            MemoryRegionInfo region;
            region.baseAddress = 0x100000U;
            region.allocationBase = 0x100000U;
            region.regionSize = 0x2000U;
            region.stateRaw = 0x1000U;
            region.typeRaw = 0x20000U;
            region.protectRaw = 0x40U;
            region.isWritable = true;
            region.isExecutable = true;
            region.isPrivate = true;
            region.isGuard = true;
            input.memory.collection.regions.push_back(region);

            const NativeObservationBuildResult result =
                BuildNativeSelectedProcessObservations(input);
            Check(result.Succeeded(), L"native static-memory build succeeds");
            Check(
                result.memoryFactCount == 1 &&
                    result.inventory.records.size() == 1,
                L"RWX private unbacked guarded attributes form one memory artifact record");
            const Observation* memory = FindMapping(
                result,
                NativeMappingStaticMemoryContext);
            Check(memory != nullptr, L"native static-memory context exists");
            if (memory != nullptr)
            {
                Check(
                    memory->domain == EvidenceDomain::MemoryMetadata &&
                        memory->disposition == ObservationDisposition::Context &&
                        !memory->contributesToVerdict,
                    L"static memory attributes remain non-contributing context");
                Check(
                    Attribute(*memory, "memory.writable") == "true" &&
                        Attribute(*memory, "memory.executable") == "true" &&
                        Attribute(*memory, "memory.private") == "true" &&
                        Attribute(*memory, "memory.guarded") == "true",
                    L"all static attributes remain auditable on one artifact");
                Check(
                    std::find(
                        memory->evidence.begin(),
                        memory->evidence.end(),
                        "Base address: 0x100000") !=
                            memory->evidence.end() &&
                    std::find(
                        memory->evidence.begin(),
                        memory->evidence.end(),
                        "Region size: 0x2000") != memory->evidence.end(),
                    L"static memory source evidence retains base and size");
            }
            Check(
                CompleteTriage(result).verdict ==
                    TriageVerdict::Informational,
                L"static memory metadata alone remains Informational");
        }

        void TestUnavailableNativeDomainsAreCollectionNotes()
        {
            NativeSelectedProcessObservationInput input = EmptyInput();
            input.modules.identity = input.identity;
            input.modules.supplied = true;
            input.modules.collectionAttempted = true;
            input.modules.available = false;
            input.modules.collection.statusMessage = L"generic module failure";
            input.modules.source = Source(ObservationSourceKind::Unavailable);
            input.memory.identity = input.identity;
            input.memory.supplied = true;
            input.memory.collectionAttempted = true;
            input.memory.available = false;
            input.memory.collection.statusMessage = L"generic memory failure";
            input.memory.source = Source(ObservationSourceKind::Unavailable);
            input.affinity.identity = input.identity;
            input.affinity.supplied = true;
            input.affinity.collectionAttempted = true;
            input.affinity.available = false;
            input.affinity.source = Source(ObservationSourceKind::Unavailable);

            const NativeObservationBuildResult result =
                BuildNativeSelectedProcessObservations(input);
            Check(result.Succeeded(), L"unavailable native-domain build succeeds");
            Check(
                result.inventory.collectionNoteCount == 3 &&
                    result.inventory.reviewRelevantCount == 0,
                L"unavailable module, memory, and affinity facts are collection notes only");
            Check(
                CompleteTriage(result).verdict ==
                    TriageVerdict::Informational,
                L"collection failures alone remain Informational");
        }
    }

    int RunNativeObservationDomainTests()
    {
        failureCount = 0;
        TestAffinityIsNativeContext();
        TestNetworkFactsAreNativeAndConservative();
        TestModuleFactsAreArtifactScopedContext();
        TestStaticMemoryAttributesRemainOneContextArtifact();
        TestUnavailableNativeDomainsAreCollectionNotes();
        return failureCount;
    }
}
