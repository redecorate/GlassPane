#include "Core/NativeHandleObservationBuilder.h"

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
            std::uint32_t pid,
            std::uint64_t creationTime)
        {
            ProcessIdentityKey identity;
            identity.pid = pid;
            identity.hasCreationTime = true;
            identity.creationTimeFileTime = creationTime;
            return identity;
        }

        NativeHandleObservationInput EmptyInput()
        {
            NativeHandleObservationInput input;
            input.sourceIdentity = Identity(4100, 900100);
            input.supplied = true;
            input.collectionAttempted = true;
            input.collection.pid = input.sourceIdentity.pid;
            input.collection.success = true;
            input.source.sourceKind = ObservationSourceKind::Direct;
            input.source.sourceIdentifier = "generic-handle-capture";
            input.source.collectionMethod = "already-collected-handle-metadata";
            input.source.collectionTimestamp = "2026-07-17T00:00:00Z";
            input.source.rawSourceReference = "generic-handle-capture-record";
            return input;
        }

        HandleInfo Row(
            std::uint32_t ownerPid,
            std::uint64_t handleValue,
            const wchar_t* objectType,
            std::uint32_t accessMask,
            std::optional<std::uint32_t> targetPid = std::nullopt)
        {
            HandleInfo row;
            row.owningPid = ownerPid;
            row.handleValue = handleValue;
            row.objectType = objectType;
            row.typeResolved = true;
            row.grantedAccessRaw = accessMask;
            row.targetPid = targetPid;
            return row;
        }

        NativeHandleTargetIdentity Target(
            std::uint64_t handleValue,
            NativeHandleObjectKind kind,
            std::uint32_t targetPid,
            std::uint64_t creationTime)
        {
            NativeHandleTargetIdentity target;
            target.handleValue = handleValue;
            target.objectKind = kind;
            target.targetPid = targetPid;
            target.identityResolved = true;
            target.identity = Identity(targetPid, creationTime);
            return target;
        }

        const Observation* FindMapping(
            const NativeHandleObservationBuildResult& result,
            const std::string& mapping)
        {
            const auto found = std::find_if(
                result.records.begin(),
                result.records.end(),
                [&](const NativeHandleObservationRecord& record)
                {
                    return record.record.source.mappingRuleId == mapping;
                });
            return found == result.records.end()
                ? nullptr
                : &found->record.observation;
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

        void TestTypedObjectAndAccessClassification()
        {
            HandleInfo process = Row(1, 2, L"pRoCeSs", 0);
            CheckEqual(
                ClassifyNativeHandleObjectKind(process),
                NativeHandleObjectKind::Process,
                L"canonical process object type is typed case-insensitively");
            process.typeResolved = false;
            CheckEqual(
                ClassifyNativeHandleObjectKind(process),
                NativeHandleObjectKind::Unknown,
                L"unresolved object type is not inferred from display text");

            constexpr std::uint32_t mask =
                0x00000002U | 0x00000008U | 0x00000010U |
                0x00000020U | 0x00000040U | 0x00000080U |
                0x00001000U | 0x00100000U;
            const NativeHandleAccessCategories access =
                CategorizeNativeHandleAccess(
                    NativeHandleObjectKind::Process,
                    mask);
            Check(access.query, L"process query right categorized");
            Check(access.synchronize, L"synchronize right categorized");
            Check(access.vmRead, L"VM read right categorized");
            Check(access.vmWrite, L"VM write right categorized");
            Check(access.vmOperation, L"VM operation right categorized");
            Check(access.createThread, L"create-thread right categorized");
            Check(access.duplicateHandle, L"duplicate-handle right categorized");
            Check(access.createProcess, L"create-process right categorized");
            Check(access.HasSensitiveProcessAccess(),
                L"typed sensitive process access recognized");
        }

        void TestSelfAndQueryOnlyContext()
        {
            NativeHandleObservationInput input = EmptyInput();
            input.collection.handles.push_back(Row(
                input.sourceIdentity.pid,
                0x40,
                L"Process",
                0x00001000U | 0x00100000U,
                input.sourceIdentity.pid));
            const NativeHandleObservationBuildResult result =
                BuildNativeHandleObservations(input);
            Check(result.Succeeded(), L"self query handle build succeeds");
            CheckEqual(result.representedArtifactCount, std::size_t(1),
                L"self query handle is one artifact");
            const Observation* observation = FindMapping(
                result,
                NativeHandleMappingSelfAccessContext);
            Check(observation != nullptr, L"self handle uses typed context mapping");
            if (observation != nullptr)
            {
                CheckEqual(observation->disposition,
                    ObservationDisposition::Context,
                    L"self access is context");
                Check(!observation->contributesToVerdict,
                    L"self access is non-contributing");
            }

            input = EmptyInput();
            input.collection.handles.push_back(Row(
                input.sourceIdentity.pid,
                0x44,
                L"Process",
                0x00001000U | 0x00100000U,
                5100));
            input.targetIdentities.push_back(Target(
                0x44,
                NativeHandleObjectKind::Process,
                5100,
                800100));
            const NativeHandleObservationBuildResult external =
                BuildNativeHandleObservations(input);
            const Observation* externalObservation = FindMapping(
                external,
                NativeHandleMappingExternalAccessContext);
            Check(externalObservation != nullptr,
                L"external query handle uses context mapping");
            if (externalObservation != nullptr)
            {
                Check(!externalObservation->contributesToVerdict,
                    L"query-only external handle does not contribute");
            }
        }

        void TestOneHandleManyBitsIsOneArtifact()
        {
            NativeHandleObservationInput input = EmptyInput();
            constexpr std::uint32_t mask =
                0x00000002U | 0x00000008U | 0x00000010U |
                0x00000020U | 0x00000040U;
            input.collection.handles.push_back(Row(
                input.sourceIdentity.pid,
                0x88,
                L"Process",
                mask,
                5200));
            input.targetIdentities.push_back(Target(
                0x88,
                NativeHandleObjectKind::Process,
                5200,
                800200));

            const NativeHandleObservationBuildResult result =
                BuildNativeHandleObservations(input);
            Check(result.Succeeded(), L"sensitive handle build succeeds");
            CheckEqual(result.representedArtifactCount, std::size_t(1),
                L"five access bits remain one handle artifact");
            const Observation* observation = FindMapping(
                result,
                NativeHandleMappingSensitiveExternalAccess);
            Check(observation != nullptr,
                L"sensitive external process access has typed mapping");
            if (observation != nullptr)
            {
                CheckEqual(observation->disposition,
                    ObservationDisposition::ReviewRelevant,
                    L"sensitive external access is review relevant");
                CheckEqual(observation->strength,
                    ObservationStrength::Moderate,
                    L"sensitive access has a Moderate ceiling");
                Check(observation->contributesToVerdict,
                    L"resolved sensitive external access contributes");
                CheckEqual(Attribute(*observation, "access.vm-write"),
                    std::string("true"), L"VM write retained as attribute");
                CheckEqual(Attribute(*observation, "access.vm-operation"),
                    std::string("true"), L"VM operation retained as attribute");
                CheckEqual(Attribute(*observation, "access.create-thread"),
                    std::string("true"), L"create-thread retained as attribute");
                CheckEqual(Attribute(*observation, "handle.access-mask"),
                    std::string("0x0000007a"), L"raw access mask retained");
            }
        }

        void TestVmReadAndThreadAccessCeilings()
        {
            NativeHandleObservationInput input = EmptyInput();
            input.collection.handles.push_back(Row(
                input.sourceIdentity.pid,
                0x91,
                L"Process",
                0x00000010U,
                5300));
            input.targetIdentities.push_back(Target(
                0x91,
                NativeHandleObjectKind::Process,
                5300,
                800300));
            NativeHandleObservationBuildResult result =
                BuildNativeHandleObservations(input);
            const Observation* observation = FindMapping(
                result,
                NativeHandleMappingExternalVmRead);
            Check(observation != nullptr, L"external VM read is represented");
            if (observation != nullptr)
            {
                CheckEqual(observation->strength, ObservationStrength::Weak,
                    L"VM read alone is Weak");
            }

            input = EmptyInput();
            input.collection.handles.push_back(Row(
                input.sourceIdentity.pid,
                0x92,
                L"Thread",
                0x00000010U | 0x00000100U,
                5301));
            input.targetIdentities.push_back(Target(
                0x92,
                NativeHandleObjectKind::Thread,
                5301,
                800301));
            result = BuildNativeHandleObservations(input);
            observation = FindMapping(
                result,
                NativeHandleMappingSensitiveExternalThreadAccess);
            Check(observation != nullptr,
                L"external thread context-change access is represented");
            if (observation != nullptr)
            {
                CheckEqual(observation->strength,
                    ObservationStrength::Moderate,
                    L"sensitive thread access has Moderate ceiling");
            }
        }

        void TestTokenAccessIsCorrelationOnly()
        {
            NativeHandleObservationInput input = EmptyInput();
            input.collection.handles.push_back(Row(
                input.sourceIdentity.pid,
                0xA0,
                L"Token",
                0x00000001U | 0x00000002U | 0x00000008U));
            const NativeHandleObservationBuildResult result =
                BuildNativeHandleObservations(input);
            const Observation* observation = FindMapping(
                result,
                NativeHandleMappingTokenManipulationRights);
            Check(observation != nullptr,
                L"token duplication and assignment rights represented");
            if (observation != nullptr)
            {
                CheckEqual(observation->disposition,
                    ObservationDisposition::CorrelatedOnly,
                    L"token manipulation access is correlated-only");
                Check(!observation->contributesToVerdict,
                    L"token manipulation handle cannot contribute directly");
                CheckEqual(observation->correlationKey,
                    std::string("token-manipulation-access"),
                    L"token manipulation fact exposes correlation metadata");
            }
        }

        void TestDuplicateRowsAreConsolidated()
        {
            NativeHandleObservationInput input = EmptyInput();
            const HandleInfo row = Row(
                input.sourceIdentity.pid,
                0xB0,
                L"Process",
                0x00000008U | 0x00000020U,
                5400);
            input.collection.handles = { row, row, row };
            input.targetIdentities.push_back(Target(
                0xB0,
                NativeHandleObjectKind::Process,
                5400,
                800400));
            const NativeHandleObservationBuildResult result =
                BuildNativeHandleObservations(input);
            Check(result.Succeeded(), L"duplicate rows build succeeds");
            CheckEqual(result.sourceRowCount, std::size_t(3),
                L"all source rows counted");
            CheckEqual(result.representedArtifactCount, std::size_t(1),
                L"equivalent duplicate rows produce one artifact");
            CheckEqual(result.duplicateRowCount, std::size_t(2),
                L"duplicate row count is exact");
            const Observation* observation = FindMapping(
                result,
                NativeHandleMappingSensitiveExternalAccess);
            Check(observation != nullptr, L"deduplicated primary retained");
            if (observation != nullptr)
            {
                CheckEqual(Attribute(*observation, "handle.source-row-count"),
                    std::string("3"),
                    L"duplicate rows remain auditable as an attribute");
            }
        }

        void TestUnresolvedAndPidReuseRemainContext()
        {
            NativeHandleObservationInput input = EmptyInput();
            input.collection.handles.push_back(Row(
                input.sourceIdentity.pid,
                0xC0,
                L"Process",
                0x00000008U | 0x00000020U,
                5500));
            NativeHandleObservationBuildResult result =
                BuildNativeHandleObservations(input);
            CheckEqual(result.inventory.reviewRelevantCount, std::size_t(0),
                L"unresolved target sensitive mask is non-contributing context");
            CheckEqual(result.inventory.contextCount, std::size_t(1),
                L"unresolved target retained as context");

            NativeHandleTargetIdentity ambiguous = Target(
                0xC0,
                NativeHandleObjectKind::Process,
                5500,
                800500);
            ambiguous.pidReuseAmbiguous = true;
            input.targetIdentities.push_back(ambiguous);
            result = BuildNativeHandleObservations(input);
            CheckEqual(result.inventory.reviewRelevantCount, std::size_t(0),
                L"PID reuse ambiguity cannot become review-relevant access");
            CheckEqual(result.inventory.contextCount, std::size_t(1),
                L"PID reuse ambiguity remains visible context");
        }

        void TestCollectionFailureAndTruncation()
        {
            NativeHandleObservationInput input = EmptyInput();
            input.collection.success = false;
            input.collection.statusMessage = L"Generic handle metadata unavailable.";
            NativeHandleObservationBuildResult result =
                BuildNativeHandleObservations(input);
            Check(result.Succeeded(), L"collection failure is a valid native result");
            CheckEqual(result.inventory.collectionNoteCount, std::size_t(1),
                L"collection failure becomes one collection note");
            CheckEqual(result.inventory.reviewRelevantCount, std::size_t(0),
                L"collection failure is not suspicious evidence");

            input = EmptyInput();
            input.sourceTruncated = true;
            input.omittedHandleCount = 2;
            result = BuildNativeHandleObservations(input);
            Check(result.Succeeded(), L"bounded truncation result succeeds atomically");
            Check(result.materialEvidenceOmitted,
                L"omitted handle rows are an explicit material completeness flag");
            CheckEqual(result.omittedHandleCount, std::size_t(2),
                L"omitted handle count retained");
            CheckEqual(result.inventory.collectionNoteCount, std::size_t(1),
                L"truncation is visible as collection limitation");

            input = EmptyInput();
            input.sourceTruncated = true;
            result = BuildNativeHandleObservations(input);
            Check(!result.materialEvidenceOmitted,
                L"bounded source marker without omitted rows is audit-only");

            input = EmptyInput();
            input.omittedHandleCount = 1;
            result = BuildNativeHandleObservations(input);
            Check(!result.Succeeded(),
                L"omitted rows without truncation marker are rejected");
            CheckEqual(result.status,
                NativeHandleObservationBuildStatus::InvalidTypedFact,
                L"contradictory truncation metadata has typed failure status");
        }

        void TestNamesAndLegacyLabelsDoNotAffectPolicy()
        {
            NativeHandleObservationInput first = EmptyInput();
            HandleInfo row = Row(
                first.sourceIdentity.pid,
                0xD0,
                L"Process",
                0x00000008U | 0x00000020U,
                5600);
            row.targetProcessName = L"Generic Alpha";
            row.objectName = L"Display Alpha";
            row.grantedAccess = L"arbitrary display access";
            row.decodedAccess = { L"arbitrary decoded label" };
            row.indicators = { L"arbitrary legacy indicator" };
            first.collection.handles.push_back(row);
            first.targetIdentities.push_back(Target(
                0xD0,
                NativeHandleObjectKind::Process,
                5600,
                800600));

            NativeHandleObservationInput second = first;
            second.collection.handles[0].targetProcessName = L"Generic Beta";
            second.collection.handles[0].objectName = L"Display Beta";
            second.collection.handles[0].grantedAccess = L"different prose";
            second.collection.handles[0].decodedAccess = { L"different label" };
            second.collection.handles[0].indicators = { L"different indicator" };

            const NativeHandleObservationBuildResult a =
                BuildNativeHandleObservations(first);
            const NativeHandleObservationBuildResult b =
                BuildNativeHandleObservations(second);
            Check(a.Succeeded() && b.Succeeded(),
                L"name-independence fixtures build");
            CheckEqual(a.records.size(), b.records.size(),
                L"display names do not change observation count");
            if (!a.records.empty() && !b.records.empty())
            {
                CheckEqual(a.records[0].record.observation.id,
                    b.records[0].record.observation.id,
                    L"display names and legacy labels do not change identity");
                CheckEqual(a.records[0].record.observation.disposition,
                    b.records[0].record.observation.disposition,
                    L"display names and legacy labels do not change policy");
            }
        }

        void TestSameDomainArtifactsDoNotBecomeIndependentDomains()
        {
            NativeHandleObservationInput input = EmptyInput();
            for (std::uint64_t index = 0; index < 3; ++index)
            {
                const std::uint64_t handleValue = 0xE0 + index;
                const std::uint32_t targetPid =
                    static_cast<std::uint32_t>(5700 + index);
                input.collection.handles.push_back(Row(
                    input.sourceIdentity.pid,
                    handleValue,
                    L"Process",
                    0x00000008U | 0x00000020U,
                    targetPid));
                input.targetIdentities.push_back(Target(
                    handleValue,
                    NativeHandleObjectKind::Process,
                    targetPid,
                    800700 + index));
            }
            const NativeHandleObservationBuildResult result =
                BuildNativeHandleObservations(input);
            CheckEqual(result.representedArtifactCount, std::size_t(3),
                L"distinct handles remain distinct artifacts");
            const std::set<EvidenceDomain> domains =
                CollectContributingDomains([&]()
                {
                    std::vector<Observation> observations;
                    for (const NativeHandleObservationRecord& record :
                        result.records)
                    {
                        observations.push_back(record.record.observation);
                    }
                    return observations;
                }());
            CheckEqual(domains.size(), std::size_t(1),
                L"multiple handles remain one independent evidence domain");
            Check(domains.count(EvidenceDomain::Handle) == 1,
                L"one independent domain is Handle");
        }

        void TestAtomicLimitsAndIdentityValidation()
        {
            NativeHandleObservationInput input = EmptyInput();
            input.collection.handles.resize(
                NativeHandleObservationMaxRows + 1,
                Row(input.sourceIdentity.pid, 1, L"Token", 0x8));
            NativeHandleObservationBuildResult result =
                BuildNativeHandleObservations(input);
            Check(!result.Succeeded(), L"handle source cap rejects input");
            CheckEqual(result.status,
                NativeHandleObservationBuildStatus::InputLimitExceeded,
                L"handle source cap status is exact");
            Check(result.records.empty(), L"cap rejection is atomic");

            input = EmptyInput();
            input.collection.handles.push_back(Row(
                input.sourceIdentity.pid + 1,
                2,
                L"Token",
                0x8));
            result = BuildNativeHandleObservations(input);
            Check(!result.Succeeded(), L"foreign owner row rejects input");
            CheckEqual(result.status,
                NativeHandleObservationBuildStatus::InvalidIdentity,
                L"foreign owner row is identity failure");
            Check(result.records.empty(), L"identity rejection is atomic");
        }

        void TestDeterministicOrderingAndIdentity()
        {
            NativeHandleObservationInput input = EmptyInput();
            input.collection.handles.push_back(Row(
                input.sourceIdentity.pid, 0xF2, L"Token", 0x8));
            input.collection.handles.push_back(Row(
                input.sourceIdentity.pid, 0xF0, L"File", 0));
            input.collection.handles.push_back(Row(
                input.sourceIdentity.pid, 0xF1, L"Process", 0x1000, 5800));
            input.targetIdentities.push_back(Target(
                0xF1,
                NativeHandleObjectKind::Process,
                5800,
                800800));
            const NativeHandleObservationBuildResult first =
                BuildNativeHandleObservations(input);
            const NativeHandleObservationBuildResult second =
                BuildNativeHandleObservations(input);
            Check(first.Succeeded() && second.Succeeded(),
                L"deterministic fixtures build");
            CheckEqual(first.records.size(), second.records.size(),
                L"repeated output count deterministic");
            for (std::size_t index = 0;
                index < first.records.size() && index < second.records.size();
                ++index)
            {
                CheckEqual(first.records[index].semanticFactKey,
                    second.records[index].semanticFactKey,
                    L"semantic ordering deterministic");
                CheckEqual(first.records[index].record.observation.id,
                    second.records[index].record.observation.id,
                    L"observation IDs deterministic");
                Check(ValidateObservation(
                    first.records[index].record.observation).IsValid(),
                    L"native handle observation satisfies policy contract");
            }
        }
    }

    int RunNativeHandleObservationBuilderTests()
    {
        failureCount = 0;
        TestTypedObjectAndAccessClassification();
        TestSelfAndQueryOnlyContext();
        TestOneHandleManyBitsIsOneArtifact();
        TestVmReadAndThreadAccessCeilings();
        TestTokenAccessIsCorrelationOnly();
        TestDuplicateRowsAreConsolidated();
        TestUnresolvedAndPidReuseRemainContext();
        TestCollectionFailureAndTruncation();
        TestNamesAndLegacyLabelsDoNotAffectPolicy();
        TestSameDomainArtifactsDoNotBecomeIndependentDomains();
        TestAtomicLimitsAndIdentityValidation();
        TestDeterministicOrderingAndIdentity();
        return failureCount;
    }
}
