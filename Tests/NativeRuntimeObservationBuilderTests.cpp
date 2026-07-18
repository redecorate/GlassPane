#include "Core/NativeRuntimeObservationBuilder.h"

#include "Core/ObservationPolicy.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <iterator>
#include <string>
#include <utility>
#include <vector>

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

        template <typename T>
        void CheckEqual(
            const T& actual,
            const T& expected,
            const wchar_t* name)
        {
            Check(actual == expected, name);
        }

        ProcessIdentityKey Identity(
            std::uint32_t pid = 5100,
            std::uint64_t creationTime = 810000)
        {
            ProcessIdentityKey identity;
            identity.pid = pid;
            identity.hasCreationTime = true;
            identity.creationTimeFileTime = creationTime;
            return identity;
        }

        NativeRuntimeObservationSource Source(
            std::string identifier = "generic-runtime-source")
        {
            NativeRuntimeObservationSource source;
            source.sourceKind = ObservationSourceKind::Direct;
            source.sourceIdentifier = std::move(identifier);
            source.collectionMethod = "already-collected-runtime-metadata";
            source.collectionTimestamp = "2026-07-17T00:00:00Z";
            source.rawSourceReference = "typed-runtime-record";
            return source;
        }

        NativeRuntimeThreadInput Thread(
            std::uint32_t threadId,
            NativeRuntimeThreadStartKind startKind =
                NativeRuntimeThreadStartKind::ImageBacked)
        {
            NativeRuntimeThreadInput thread;
            thread.threadId = threadId;
            thread.ownerProcessId = Identity().pid;
            thread.ownerIdentityKnown = true;
            thread.ownerMatchesSelectedProcess = true;
            thread.startAddressAvailable = true;
            thread.startAddress = 0x0000000012345000ULL + threadId;
            thread.startKind = startKind;
            thread.resolvedModuleIdentity =
                startKind == NativeRuntimeThreadStartKind::ImageBacked
                    ? "module-artifact:1"
                    : std::string{};
            thread.state = NativeRuntimeThreadState::Running;
            thread.basePriorityAvailable = true;
            thread.basePriority = 8;
            thread.currentPriorityAvailable = true;
            thread.currentPriority = 1;
            thread.evidence = { "Typed thread metadata was supplied." };
            thread.source = Source("generic-thread-source");
            return thread;
        }

        NativeRuntimeObservationInput RuntimeInput()
        {
            NativeRuntimeObservationInput input;
            input.identity = Identity();
            input.supplied = true;
            input.collectionAttempted = true;
            input.available = true;
            input.declaredThreadCount = 1;
            input.declaredHandleCount = 12;
            input.processBasePriorityAvailable = true;
            input.processBasePriority = 8;
            input.source = Source();
            return input;
        }

        NativePriorityObservationInput PriorityInput(
            NativeProcessPriorityClass priorityClass)
        {
            NativePriorityObservationInput input;
            input.identity = Identity();
            input.supplied = true;
            input.collectionAttempted = true;
            input.available = true;
            input.priorityClass = priorityClass;
            input.rawPriorityClass = 0x20;
            input.basePriorityAvailable = true;
            input.basePriority = 8;
            input.source = Source("generic-priority-source");
            return input;
        }

        const NativeRuntimeObservationRecord* FindMapping(
            const NativeRuntimeObservationBuildResult& result,
            const std::string& mapping)
        {
            const auto found = std::find_if(
                result.records.begin(),
                result.records.end(),
                [&](const NativeRuntimeObservationRecord& record)
                {
                    return record.record.source.mappingRuleId == mapping;
                });
            return found == result.records.end() ? nullptr : &*found;
        }

        std::size_t CountMapping(
            const NativeRuntimeObservationBuildResult& result,
            const std::string& mapping)
        {
            return static_cast<std::size_t>(std::count_if(
                result.records.begin(),
                result.records.end(),
                [&](const NativeRuntimeObservationRecord& record)
                {
                    return record.record.source.mappingRuleId == mapping;
                }));
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

        void CheckContextOnly(
            const Observation& observation,
            const wchar_t* name)
        {
            CheckEqual(
                observation.disposition,
                ObservationDisposition::Context,
                name);
            CheckEqual(
                observation.strength,
                ObservationStrength::None,
                name);
            Check(!observation.contributesToVerdict, name);
        }

        std::vector<Observation> InventoryObservations(
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

        void TestStaticThreadAttributesAreOneContextArtifact()
        {
            NativeRuntimeObservationInput input = RuntimeInput();
            NativeRuntimeThreadInput thread = Thread(
                200,
                NativeRuntimeThreadStartKind::PrivateExecutableMetadata);
            thread.state = NativeRuntimeThreadState::Suspended;
            thread.currentPriority = 15;
            input.threads.push_back(thread);

            const NativeRuntimeObservationBuildResult result =
                BuildNativeRuntimeObservations(input);
            Check(result.Succeeded(), L"static runtime build succeeds");
            CheckEqual(
                result.representedFactCount,
                std::size_t(2),
                L"capture plus one thread artifact represented");
            const NativeRuntimeObservationRecord* record = FindMapping(
                result,
                NativeRuntimeMappingThreadContext);
            Check(record != nullptr, L"thread record exists");
            if (record != nullptr)
            {
                const Observation& observation = record->record.observation;
                CheckContextOnly(
                    observation,
                    L"thread metadata remains context only");
                CheckEqual(
                    observation.domain,
                    EvidenceDomain::Runtime,
                    L"thread metadata uses runtime domain");
                CheckEqual(
                    observation.artifactIdentity.kind,
                    ObservationArtifactKind::RuntimeObject,
                    L"thread uses runtime artifact identity");
                CheckEqual(
                    observation.artifactIdentity.artifactKey,
                    std::string("thread:200"),
                    L"thread identity uses typed thread id");
                CheckEqual(
                    Attribute(observation, "start-kind"),
                    std::string("Private executable metadata"),
                    L"private executable start remains an attribute");
                CheckEqual(
                    Attribute(observation, "state"),
                    std::string("Suspended"),
                    L"suspended state remains an attribute");
                Check(!Attribute(observation, "base-priority").empty(),
                    L"thread base priority shares thread artifact");
                Check(!Attribute(observation, "current-priority").empty(),
                    L"thread current priority shares thread artifact");
                Check(
                    observation.artifactAttributes.size() >= 10,
                    L"many thread attributes remain one observation");
            }
            Check(
                CollectContributingDomains(
                    InventoryObservations(result.inventory)).empty(),
                L"static runtime metadata contributes no domain");
        }

        void TestStartClassificationsRemainContext()
        {
            const NativeRuntimeThreadStartKind kinds[] = {
                NativeRuntimeThreadStartKind::NotEvaluated,
                NativeRuntimeThreadStartKind::ImageBacked,
                NativeRuntimeThreadStartKind::Unresolved,
                NativeRuntimeThreadStartKind::PrivateExecutableMetadata,
                NativeRuntimeThreadStartKind::OutsideKnownModule
            };
            for (std::size_t index = 0; index < std::size(kinds); ++index)
            {
                NativeRuntimeObservationInput input = RuntimeInput();
                input.threads.push_back(Thread(
                    static_cast<std::uint32_t>(300 + index),
                    kinds[index]));
                const NativeRuntimeObservationBuildResult result =
                    BuildNativeRuntimeObservations(input);
                Check(result.Succeeded(), L"start classification build succeeds");
                const NativeRuntimeObservationRecord* record = FindMapping(
                    result,
                    NativeRuntimeMappingThreadContext);
                Check(record != nullptr, L"start classification record exists");
                if (record != nullptr)
                {
                    CheckContextOnly(
                        record->record.observation,
                        L"every static start classification is context");
                    Check(
                        record->record.observation.summary.find("injection") ==
                            std::string::npos,
                        L"static summary makes no injection claim");
                }
            }
        }

        void TestDuplicateRowsDoNotReinforce()
        {
            NativeRuntimeObservationInput input = RuntimeInput();
            input.declaredThreadCount = 2;
            input.threads.push_back(Thread(400));
            input.threads.push_back(Thread(400));
            const NativeRuntimeObservationBuildResult result =
                BuildNativeRuntimeObservations(input);

            Check(result.Succeeded(), L"duplicate runtime rows build succeeds");
            CheckEqual(
                CountMapping(result, NativeRuntimeMappingThreadContext),
                std::size_t(2),
                L"duplicate source rows remain auditable");
            CheckEqual(
                result.duplicateCount,
                std::size_t(1),
                L"duplicate row designated once");
            CheckEqual(
                result.representedFactCount,
                std::size_t(2),
                L"duplicate thread is one artifact evidence unit");
            const auto duplicate = std::find_if(
                result.records.begin(),
                result.records.end(),
                [](const NativeRuntimeObservationRecord& record)
                {
                    return !record.primary;
                });
            Check(duplicate != result.records.end(),
                L"supporting duplicate is visible");
            if (duplicate != result.records.end())
            {
                Check(!duplicate->primaryObservationId.empty(),
                    L"duplicate retains primary relationship");
            }
        }

        void TestManyThreadsRemainOneNoncontributingDomain()
        {
            NativeRuntimeObservationInput input = RuntimeInput();
            input.declaredThreadCount = 32;
            for (std::uint32_t index = 0; index < 32; ++index)
            {
                input.threads.push_back(Thread(
                    500 + index,
                    NativeRuntimeThreadStartKind::OutsideKnownModule));
            }
            const NativeRuntimeObservationBuildResult result =
                BuildNativeRuntimeObservations(input);
            Check(result.Succeeded(), L"many static threads build succeeds");
            CheckEqual(
                result.representedFactCount,
                std::size_t(33),
                L"distinct thread artifacts remain distinguishable");
            Check(
                CollectContributingDomains(
                    InventoryObservations(result.inventory)).empty(),
                L"same-domain repetition does not contribute");
        }

        void TestRuntimeObjectCountsRemainContext()
        {
            NativeRuntimeObservationInput input = RuntimeInput();
            input.declaredThreadCount = 4000;
            input.declaredHandleCount = 900000;
            const NativeRuntimeObservationBuildResult result =
                BuildNativeRuntimeObservations(input);
            Check(result.Succeeded(), L"large runtime counts build succeeds");
            const NativeRuntimeObservationRecord* capture = FindMapping(
                result,
                NativeRuntimeMappingCaptureContext);
            Check(capture != nullptr, L"runtime count context retained");
            if (capture != nullptr)
            {
                CheckContextOnly(
                    capture->record.observation,
                    L"runtime counts remain context regardless of value");
                CheckEqual(
                    Attribute(
                        capture->record.observation,
                        "declared-thread-count"),
                    std::string("4000"),
                    L"declared thread count retained as metadata");
                CheckEqual(
                    Attribute(
                        capture->record.observation,
                        "declared-handle-count"),
                    std::string("900000"),
                    L"declared handle count retained as metadata");
            }
            Check(
                CollectContributingDomains(
                    InventoryObservations(result.inventory)).empty(),
                L"thread and handle counts contribute no domain");
        }

        NativeRuntimeRelationshipInput ExplicitRelationship(bool verified)
        {
            NativeRuntimeRelationshipInput relationship;
            relationship.selectedIdentity = Identity();
            relationship.sourceIdentity = Identity(5200, 820000);
            relationship.targetIdentity = Identity();
            relationship.sourceThreadId = 710;
            relationship.targetThreadId = 711;
            relationship.kind =
                NativeRuntimeRelationshipKind::CrossProcessThreadCreation;
            relationship.verified = verified;
            relationship.sourceRuleId =
                "native.runtime.relationship.cross-process-thread";
            relationship.evidence = {
                "Typed source and target identities were supplied."
            };
            relationship.source = Source("generic-runtime-relation-source");
            return relationship;
        }

        void TestOnlyExplicitVerifiedRelationshipIsCorrelatedOnly()
        {
            NativeRuntimeObservationInput input = RuntimeInput();
            input.relationships.push_back(ExplicitRelationship(true));
            const NativeRuntimeObservationBuildResult result =
                BuildNativeRuntimeObservations(input);
            Check(result.Succeeded(), L"explicit runtime relation builds");
            const NativeRuntimeObservationRecord* relation = FindMapping(
                result,
                NativeRuntimeMappingExplicitRelationship);
            Check(relation != nullptr, L"explicit relation retained");
            if (relation != nullptr)
            {
                const Observation& observation = relation->record.observation;
                CheckEqual(
                    observation.disposition,
                    ObservationDisposition::CorrelatedOnly,
                    L"verified explicit relation is correlated-only");
                Check(!observation.contributesToVerdict,
                    L"correlated-only relation never contributes directly");
                CheckEqual(
                    observation.correlationKey,
                    std::string("runtime-sensitive-access"),
                    L"explicit relation exposes typed correlation key");
                Check(relation->material,
                    L"verified explicit relation is material typed evidence");
            }

            input.relationships.clear();
            input.relationships.push_back(ExplicitRelationship(false));
            const NativeRuntimeObservationBuildResult unverified =
                BuildNativeRuntimeObservations(input);
            Check(unverified.Succeeded(), L"unverified relation builds as context");
            relation = FindMapping(
                unverified,
                NativeRuntimeMappingExplicitRelationship);
            Check(relation != nullptr, L"unverified relation retained");
            if (relation != nullptr)
            {
                CheckContextOnly(
                    relation->record.observation,
                    L"unverified relation remains context");
                Check(relation->record.observation.correlationKey.empty(),
                    L"unverified relation has no correlation key");
                Check(!relation->material,
                    L"unverified relation is not material correlation input");
            }

            input.relationships.clear();
            NativeRuntimeRelationshipInput missingThreadIdentity =
                ExplicitRelationship(true);
            missingThreadIdentity.sourceThreadId = 0;
            input.relationships.push_back(missingThreadIdentity);
            const NativeRuntimeObservationBuildResult missingThread =
                BuildNativeRuntimeObservations(input);
            Check(missingThread.Succeeded(),
                L"relationship without exact thread identity remains auditable");
            relation = FindMapping(
                missingThread,
                NativeRuntimeMappingExplicitRelationship);
            Check(relation != nullptr,
                L"relationship without thread identity remains visible");
            if (relation != nullptr)
            {
                CheckContextOnly(
                    relation->record.observation,
                    L"relationship without thread identity remains context");
                Check(relation->record.observation.correlationKey.empty(),
                    L"relationship without thread identity cannot correlate");
            }
        }

        void TestRelationshipIdentityValidationIsAtomic()
        {
            NativeRuntimeObservationInput input = RuntimeInput();
            NativeRuntimeRelationshipInput relation = ExplicitRelationship(true);
            relation.selectedIdentity = Identity(9999, 9999);
            relation.sourceIdentity = Identity(9998, 9998);
            relation.targetIdentity = Identity(9997, 9997);
            input.relationships.push_back(relation);
            const NativeRuntimeObservationBuildResult result =
                BuildNativeRuntimeObservations(input);
            Check(!result.Succeeded(), L"unrelated runtime relation rejected");
            CheckEqual(
                result.status,
                NativeRuntimeObservationBuildStatus::InvalidTypedFact,
                L"unrelated runtime relation has typed failure status");
            Check(result.records.empty(), L"runtime relation failure is atomic");
            Check(result.inventory.records.empty(),
                L"runtime relation failure leaves no partial inventory");
        }

        void TestCollectionFailureAndTruncation()
        {
            NativeRuntimeObservationInput unavailable = RuntimeInput();
            unavailable.available = false;
            unavailable.limitations = { "Runtime metadata access failed." };
            const NativeRuntimeObservationBuildResult failed =
                BuildNativeRuntimeObservations(unavailable);
            Check(failed.Succeeded(), L"runtime collection failure is represented");
            const NativeRuntimeObservationRecord* note = FindMapping(
                failed,
                NativeRuntimeMappingCollectionUnavailable);
            Check(note != nullptr, L"runtime collection note emitted");
            if (note != nullptr)
            {
                CheckEqual(
                    note->record.observation.disposition,
                    ObservationDisposition::CollectionNote,
                    L"runtime failure is a collection note");
                Check(!note->record.observation.contributesToVerdict,
                    L"runtime failure never contributes");
            }

            NativeRuntimeObservationInput truncated = RuntimeInput();
            truncated.sourceFactsTruncated = true;
            truncated.omittedMaterialFactCount = 3;
            const NativeRuntimeObservationBuildResult partial =
                BuildNativeRuntimeObservations(truncated);
            Check(partial.Succeeded(), L"runtime truncation remains bounded output");
            Check(partial.truncated, L"runtime truncation is explicit");
            CheckEqual(
                partial.omittedMaterialFactCount,
                std::size_t(3),
                L"omitted material count retained");
            note = FindMapping(
                partial,
                NativeRuntimeMappingCollectionTruncated);
            Check(note != nullptr, L"runtime truncation note retained");
            if (note != nullptr)
            {
                CheckEqual(
                    note->record.observation.disposition,
                    ObservationDisposition::CollectionNote,
                    L"runtime truncation is collection quality, not suspicion");
                Check(note->material,
                    L"omitted material runtime facts are explicit completeness input");
            }

            NativeRuntimeObservationInput contradictory = RuntimeInput();
            contradictory.omittedMaterialFactCount = 1;
            const NativeRuntimeObservationBuildResult invalid =
                BuildNativeRuntimeObservations(contradictory);
            Check(!invalid.Succeeded(),
                L"runtime omission without a truncation marker is rejected");
            CheckEqual(
                invalid.status,
                NativeRuntimeObservationBuildStatus::InvalidTypedFact,
                L"contradictory runtime omission has typed failure");

            NativeRuntimeObservationInput coverageOnly = RuntimeInput();
            coverageOnly.sourceFactsTruncated = true;
            coverageOnly.omittedMaterialFactCount = 0;
            coverageOnly.limitations = {
                "Thread enumeration did not return a stable thread identity."
            };
            const NativeRuntimeObservationBuildResult coverageResult =
                BuildNativeRuntimeObservations(coverageOnly);
            Check(coverageResult.Succeeded(),
                L"thread enumeration coverage limitation remains authoritative");
            CheckEqual(
                coverageResult.omittedMaterialFactCount,
                std::size_t(0),
                L"thread enumeration sentinel omits no material fact");
            note = FindMapping(
                coverageResult,
                NativeRuntimeMappingCollectionTruncated);
            Check(note != nullptr,
                L"thread enumeration sentinel becomes a collection note");
            if (note != nullptr)
            {
                Check(!note->material,
                    L"thread enumeration sentinel is audit-only coverage");
                CheckEqual(
                    note->record.observation.disposition,
                    ObservationDisposition::CollectionNote,
                    L"thread enumeration sentinel never becomes runtime behavior");
            }
        }

        void TestPriorityClassesAreContextOnly()
        {
            const NativeProcessPriorityClass classes[] = {
                NativeProcessPriorityClass::NotEvaluated,
                NativeProcessPriorityClass::Idle,
                NativeProcessPriorityClass::BelowNormal,
                NativeProcessPriorityClass::Normal,
                NativeProcessPriorityClass::AboveNormal,
                NativeProcessPriorityClass::High,
                NativeProcessPriorityClass::Realtime,
                NativeProcessPriorityClass::Unknown
            };
            for (const NativeProcessPriorityClass priorityClass : classes)
            {
                const NativeRuntimeObservationBuildResult result =
                    BuildNativePriorityObservations(
                        PriorityInput(priorityClass));
                Check(result.Succeeded(), L"priority class build succeeds");
                const NativeRuntimeObservationRecord* record = FindMapping(
                    result,
                    NativePriorityMappingProcessContext);
                Check(record != nullptr, L"priority class record retained");
                if (record != nullptr)
                {
                    CheckContextOnly(
                        record->record.observation,
                        L"every process priority class remains context");
                    CheckEqual(
                        record->record.observation.artifactIdentity.artifactKey,
                        std::string("process-priority"),
                        L"process priority has one artifact identity");
                }
            }
        }

        void TestPriorityRawClassifierIsExact()
        {
            struct Fixture
            {
                std::uint32_t raw;
                NativeProcessPriorityClass expected;
            };
            const Fixture fixtures[] = {
                { 0, NativeProcessPriorityClass::NotEvaluated },
                { 0x40, NativeProcessPriorityClass::Idle },
                { 0x4000, NativeProcessPriorityClass::BelowNormal },
                { 0x20, NativeProcessPriorityClass::Normal },
                { 0x8000, NativeProcessPriorityClass::AboveNormal },
                { 0x80, NativeProcessPriorityClass::High },
                { 0x100, NativeProcessPriorityClass::Realtime },
                { 0x81, NativeProcessPriorityClass::Unknown }
            };
            for (const Fixture& fixture : fixtures)
            {
                CheckEqual(
                    ClassifyNativeProcessPriorityClass(fixture.raw),
                    fixture.expected,
                    L"raw priority class has exact typed classification");
            }
        }

        void TestPriorityFailureIsCollectionNote()
        {
            NativePriorityObservationInput input = PriorityInput(
                NativeProcessPriorityClass::NotEvaluated);
            input.available = false;
            input.limitations = { "Priority metadata access failed." };
            const NativeRuntimeObservationBuildResult result =
                BuildNativePriorityObservations(input);
            Check(result.Succeeded(), L"priority failure is representable");
            const NativeRuntimeObservationRecord* note = FindMapping(
                result,
                NativePriorityMappingCollectionUnavailable);
            Check(note != nullptr, L"priority failure note emitted");
            if (note != nullptr)
            {
                CheckEqual(
                    note->record.observation.disposition,
                    ObservationDisposition::CollectionNote,
                    L"priority failure is collection quality");
                Check(!note->record.observation.contributesToVerdict,
                    L"priority failure never contributes");
            }
        }

        void TestPriorityMismatchAndTruncationRemainNoncontributing()
        {
            NativeRuntimeObservationInput runtime = RuntimeInput();
            NativeRuntimeThreadInput thread = Thread(850);
            thread.basePriority = 13;
            runtime.threads.push_back(thread);
            const NativeRuntimeObservationBuildResult runtimeResult =
                BuildNativeRuntimeObservations(runtime);
            Check(runtimeResult.Succeeded(),
                L"thread priority mismatch builds successfully");
            const NativeRuntimeObservationRecord* threadRecord = FindMapping(
                runtimeResult,
                NativeRuntimeMappingThreadContext);
            Check(threadRecord != nullptr,
                L"thread priority mismatch retained on thread artifact");
            if (threadRecord != nullptr)
            {
                CheckEqual(
                    Attribute(
                        threadRecord->record.observation,
                        "priority-differs-from-process-base"),
                    std::string("true"),
                    L"process/thread mismatch is a typed attribute");
                CheckContextOnly(
                    threadRecord->record.observation,
                    L"process/thread priority mismatch remains context");
            }

            NativePriorityObservationInput priority = PriorityInput(
                NativeProcessPriorityClass::Realtime);
            priority.rawPriorityClass = 0x100;
            priority.sourceFactsTruncated = true;
            priority.omittedMaterialFactCount = 2;
            const NativeRuntimeObservationBuildResult priorityResult =
                BuildNativePriorityObservations(priority);
            Check(priorityResult.Succeeded(),
                L"truncated priority input remains bounded and auditable");
            Check(priorityResult.truncated,
                L"priority truncation is explicit");
            CheckEqual(
                priorityResult.omittedMaterialFactCount,
                std::size_t(2),
                L"priority omitted material count retained");
            NativePriorityObservationInput contradictoryPriority =
                PriorityInput(NativeProcessPriorityClass::Normal);
            contradictoryPriority.omittedMaterialFactCount = 1;
            const NativeRuntimeObservationBuildResult invalidPriority =
                BuildNativePriorityObservations(contradictoryPriority);
            Check(!invalidPriority.Succeeded(),
                L"priority omission without a truncation marker is rejected");
            CheckEqual(
                invalidPriority.status,
                NativeRuntimeObservationBuildStatus::InvalidTypedFact,
                L"contradictory priority omission has typed failure");
            const NativeRuntimeObservationRecord* priorityRecord = FindMapping(
                priorityResult,
                NativePriorityMappingProcessContext);
            Check(priorityRecord != nullptr,
                L"realtime priority context retained");
            if (priorityRecord != nullptr)
            {
                CheckContextOnly(
                    priorityRecord->record.observation,
                    L"realtime priority remains context despite truncation");
                CheckEqual(
                    Attribute(
                        priorityRecord->record.observation,
                        "differs-from-normal-class"),
                    std::string("true"),
                    L"nondefault priority is a typed context attribute");
            }
            const NativeRuntimeObservationRecord* truncation = FindMapping(
                priorityResult,
                NativePriorityMappingCollectionTruncated);
            Check(truncation != nullptr,
                L"priority truncation collection note retained");
            if (truncation != nullptr)
            {
                CheckEqual(
                    truncation->record.observation.disposition,
                    ObservationDisposition::CollectionNote,
                    L"priority truncation is collection quality");
                Check(!truncation->record.observation.contributesToVerdict,
                    L"priority truncation does not contribute");
            }
        }

        void TestOptionalAbsenceIsSuccessfulAndSilent()
        {
            NativeRuntimeObservationInput runtime;
            runtime.identity = Identity();
            const NativeRuntimeObservationBuildResult runtimeResult =
                BuildNativeRuntimeObservations(runtime);
            Check(runtimeResult.Succeeded(),
                L"optional runtime absence is a successful empty result");
            Check(runtimeResult.records.empty(),
                L"optional runtime absence fabricates no note");

            NativePriorityObservationInput priority;
            priority.identity = Identity();
            const NativeRuntimeObservationBuildResult priorityResult =
                BuildNativePriorityObservations(priority);
            Check(priorityResult.Succeeded(),
                L"optional priority absence is a successful empty result");
            Check(priorityResult.records.empty(),
                L"optional priority absence fabricates no note");
        }

        void TestCapsAndDeterminism()
        {
            NativeRuntimeObservationInput overCap = RuntimeInput();
            overCap.threads.resize(NativeRuntimeObservationMaxThreads + 1);
            const NativeRuntimeObservationBuildResult rejected =
                BuildNativeRuntimeObservations(overCap);
            Check(!rejected.Succeeded(), L"thread cap plus one rejected");
            CheckEqual(
                rejected.status,
                NativeRuntimeObservationBuildStatus::InputLimitExceeded,
                L"thread cap rejection has exact status");
            Check(rejected.records.empty(), L"thread cap rejection is atomic");

            NativeRuntimeObservationInput input = RuntimeInput();
            input.threads.push_back(Thread(901));
            input.relationships.push_back(ExplicitRelationship(true));
            const NativeRuntimeObservationBuildResult first =
                BuildNativeRuntimeObservations(input);
            const NativeRuntimeObservationBuildResult second =
                BuildNativeRuntimeObservations(input);
            Check(first.Succeeded() && second.Succeeded(),
                L"deterministic runtime fixtures succeed");
            CheckEqual(
                first.records.size(),
                second.records.size(),
                L"deterministic runtime record count");
            for (std::size_t index = 0;
                 index < std::min(first.records.size(), second.records.size());
                 ++index)
            {
                CheckEqual(
                    first.records[index].record.observation.id,
                    second.records[index].record.observation.id,
                    L"deterministic runtime observation identity");
                CheckEqual(
                    first.records[index].semanticFactKey,
                    second.records[index].semanticFactKey,
                    L"deterministic runtime semantic identity");
                CheckEqual(
                    first.records[index].record.source.sourceCategory,
                    std::string("Native selected-process evidence"),
                    L"native source category is stable");
            }
        }
    }

    int RunNativeRuntimeObservationBuilderTests()
    {
        failureCount = 0;
        TestStaticThreadAttributesAreOneContextArtifact();
        TestStartClassificationsRemainContext();
        TestDuplicateRowsDoNotReinforce();
        TestManyThreadsRemainOneNoncontributingDomain();
        TestRuntimeObjectCountsRemainContext();
        TestOnlyExplicitVerifiedRelationshipIsCorrelatedOnly();
        TestRelationshipIdentityValidationIsAtomic();
        TestCollectionFailureAndTruncation();
        TestPriorityClassesAreContextOnly();
        TestPriorityRawClassifierIsExact();
        TestPriorityFailureIsCollectionNote();
        TestPriorityMismatchAndTruncationRemainNoncontributing();
        TestOptionalAbsenceIsSuccessfulAndSilent();
        TestCapsAndDeterminism();
        return failureCount;
    }
}
