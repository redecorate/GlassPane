#include "Core/NativeTokenObservationBuilder.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <set>
#include <sstream>
#include <string>
#include <utility>

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

        ProcessIdentityKey Identity()
        {
            ProcessIdentityKey identity;
            identity.pid = 4200;
            identity.hasCreationTime = true;
            identity.creationTimeFileTime = 900000;
            return identity;
        }

        NativeTokenObservationInput AvailableInput()
        {
            NativeTokenObservationInput input;
            input.identity = Identity();
            input.supplied = true;
            input.collectionAttempted = true;
            input.token.success = true;
            input.token.userSid = L"S-1-5-21-1000";
            input.token.integrityLevelName = L"Medium";
            input.token.integrityRid = 0x2000;
            input.token.elevationType = L"Default";
            input.token.sessionId = 1;
            input.token.tokenType = L"Primary";
            input.source.sourceKind = ObservationSourceKind::Direct;
            input.source.sourceIdentifier = "core.test.native-token";
            input.source.collectionMethod = "already-collected-token-metadata";
            input.source.collectionTimestamp = "2026-07-17T00:00:00Z";
            input.source.requiredPrivilege = "process-query";
            input.source.rawSourceReference = "typed-token-capture";
            return input;
        }

        const ObservationRecord* FindMapping(
            const NativeTokenObservationBuildResult& result,
            const std::string& mapping)
        {
            const auto found = std::find_if(
                result.inventory.records.begin(),
                result.inventory.records.end(),
                [&](const ObservationRecord& record)
                {
                    return record.source.mappingRuleId == mapping;
                });
            return found == result.inventory.records.end() ? nullptr : &*found;
        }

        std::size_t CountMapping(
            const NativeTokenObservationBuildResult& result,
            const std::string& mapping)
        {
            return static_cast<std::size_t>(std::count_if(
                result.inventory.records.begin(),
                result.inventory.records.end(),
                [&](const ObservationRecord& record)
                {
                    return record.source.mappingRuleId == mapping;
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

        PrivilegeInfo Privilege(
            std::wstring name,
            bool enabled = false)
        {
            PrivilegeInfo privilege;
            privilege.name = std::move(name);
            privilege.enabled = enabled;
            return privilege;
        }

        std::string PolicyShape(
            const NativeTokenObservationBuildResult& result)
        {
            std::ostringstream stream;
            for (const ObservationRecord& record : result.inventory.records)
            {
                const Observation& observation = record.observation;
                stream << record.source.mappingRuleId << '|'
                       << static_cast<std::uint32_t>(observation.domain) << '|'
                       << static_cast<std::uint32_t>(observation.disposition) << '|'
                       << static_cast<std::uint32_t>(observation.strength) << '|'
                       << static_cast<std::uint32_t>(observation.confidence) << '|'
                       << observation.contributesToVerdict << '|'
                       << observation.normalizedValue << '\n';
            }
            return stream.str();
        }

        void TestContextOnlyToken()
        {
            const NativeTokenObservationBuildResult result =
                BuildNativeTokenObservations(AvailableInput());
            Check(result.Succeeded(), L"available token succeeds");
            Check(result.inventory.contextCount != 0,
                L"available token emits contextual facts");
            CheckEqual(result.inventory.reviewRelevantCount, std::size_t(0),
                L"ordinary token has no direct review evidence");
            CheckEqual(result.inventory.correlatedOnlyCount, std::size_t(0),
                L"ordinary token has no inactive correlation fact");
            CheckEqual(
                CountMapping(result, NativeTokenMappingAppContainer),
                std::size_t(0),
                L"false AppContainer state is not asserted without field availability");
            const ObservationRecord* elevation =
                FindMapping(result, NativeTokenMappingElevation);
            Check(elevation != nullptr, L"typed elevation type remains context");
            if (elevation != nullptr)
            {
                Check(Attribute(elevation->observation, "token.elevated").empty(),
                    L"false elevation is not asserted without field availability");
                Check(Attribute(elevation->observation, "token.admin-member").empty(),
                    L"false admin membership is not asserted without field availability");
            }
            for (const ObservationRecord& record : result.inventory.records)
            {
                Check(!record.observation.contributesToVerdict,
                    L"ordinary token fact never contributes");
                CheckEqual(
                    record.source.sourceCategory,
                    std::string("Native selected-process evidence"),
                    L"token source uses common native category");
            }
        }

        void TestOptionalTokenSourceCanBeAbsent()
        {
            NativeTokenObservationInput input;
            input.identity = Identity();
            const NativeTokenObservationBuildResult result =
                BuildNativeTokenObservations(input);
            Check(result.Succeeded(), L"omitted optional token source is valid");
            Check(result.records.empty() && result.inventory.records.empty(),
                L"omitted optional token source emits no limitation");
            CheckEqual(result.omittedFactCount, std::size_t(0),
                L"omitted optional source does not fabricate missing facts");
        }

        void TestHighIntegrityElevationAndSystemRemainContext()
        {
            NativeTokenObservationInput input = AvailableInput();
            input.token.userSid = L"S-1-5-18";
            input.token.integrityLevelName = L"System";
            input.token.integrityRid = 0x4000;
            input.token.elevationType = L"Full";
            input.token.isElevated = true;
            input.token.isAdmin = true;

            const NativeTokenObservationBuildResult result =
                BuildNativeTokenObservations(input);
            Check(result.Succeeded(), L"system high-integrity token succeeds");
            CheckEqual(result.inventory.reviewRelevantCount, std::size_t(0),
                L"system and high integrity are not review evidence");
            CheckEqual(result.inventory.correlatedOnlyCount, std::size_t(0),
                L"system and elevation do not create correlation candidates");
            const ObservationRecord* identity =
                FindMapping(result, NativeTokenMappingIdentity);
            Check(identity != nullptr, L"system SID fact retained");
            if (identity != nullptr)
            {
                CheckEqual(
                    Attribute(identity->observation, "token.user.local-system"),
                    std::string("true"),
                    L"system identity derives only from exact SID");
                CheckEqual(
                    identity->observation.disposition,
                    ObservationDisposition::Context,
                    L"system identity remains context");
            }
        }

        void TestDebugPrivilegePolicy()
        {
            NativeTokenObservationInput disabled = AvailableInput();
            disabled.token.privileges.push_back(
                Privilege(L"SeDebugPrivilege", false));
            const NativeTokenObservationBuildResult disabledResult =
                BuildNativeTokenObservations(disabled);
            Check(disabledResult.Succeeded(), L"disabled debug privilege succeeds");
            CheckEqual(
                CountMapping(
                    disabledResult,
                    NativeTokenMappingDebugPrivilegeEnabled),
                std::size_t(0),
                L"disabled debug privilege is not a correlation candidate");

            NativeTokenObservationInput enabled = AvailableInput();
            enabled.token.privileges.push_back(
                Privilege(L"SeDebugPrivilege", true));
            const NativeTokenObservationBuildResult enabledResult =
                BuildNativeTokenObservations(enabled);
            Check(enabledResult.Succeeded(), L"enabled debug privilege succeeds");
            const ObservationRecord* debug = FindMapping(
                enabledResult,
                NativeTokenMappingDebugPrivilegeEnabled);
            Check(debug != nullptr, L"enabled debug privilege typed fact exists");
            if (debug != nullptr)
            {
                CheckEqual(
                    debug->observation.disposition,
                    ObservationDisposition::CorrelatedOnly,
                    L"enabled debug privilege is inactive without access partner");
                CheckEqual(
                    debug->observation.strength,
                    ObservationStrength::Weak,
                    L"enabled debug privilege uses conservative weak strength");
                CheckEqual(
                    debug->observation.correlationKey,
                    std::string(NativeTokenSensitiveAccessCorrelationKey),
                    L"enabled debug privilege exposes typed access partner key");
                Check(!debug->observation.contributesToVerdict,
                    L"enabled debug privilege never contributes directly");
            }
        }

        void TestPrivilegeChildrenShareOneTokenArtifact()
        {
            NativeTokenObservationInput input = AvailableInput();
            for (int index = 0; index < 10; ++index)
            {
                input.token.privileges.push_back(Privilege(
                    L"SeGenericPrivilege" + std::to_wstring(index),
                    true));
            }
            const NativeTokenObservationBuildResult result =
                BuildNativeTokenObservations(input);
            Check(result.Succeeded(), L"multi-privilege token succeeds");
            std::set<std::string> tokenArtifacts;
            std::size_t privilegeCount = 0;
            for (const ObservationRecord& record : result.inventory.records)
            {
                tokenArtifacts.insert(
                    record.observation.artifactIdentity.artifactKey);
                if (record.source.mappingRuleId ==
                    NativeTokenMappingPrivilege)
                {
                    ++privilegeCount;
                    Check(!Attribute(
                        record.observation,
                        "token.privilege-child").empty(),
                        L"privilege has stable child identity attribute");
                }
            }
            CheckEqual(privilegeCount, std::size_t(10),
                L"each typed privilege remains auditable");
            CheckEqual(tokenArtifacts.size(), std::size_t(1),
                L"all token properties share one artifact identity");
            CheckEqual(result.inventory.reviewRelevantCount, std::size_t(0),
                L"privilege count does not escalate");
        }

        void TestDuplicatePrivilegeRowsDoNotReinforce()
        {
            NativeTokenObservationInput input = AvailableInput();
            input.token.privileges.push_back(
                Privilege(L"SeDebugPrivilege", false));
            input.token.privileges.push_back(
                Privilege(L"SEDEBUGPRIVILEGE", true));
            const NativeTokenObservationBuildResult result =
                BuildNativeTokenObservations(input);
            Check(result.Succeeded(), L"duplicate privilege rows succeed");
            CheckEqual(result.duplicateCount, std::size_t(1),
                L"equivalent privilege rows collapse to one primary");
            CheckEqual(
                CountMapping(result, NativeTokenMappingDebugPrivilegeEnabled),
                std::size_t(1),
                L"enabled duplicate wins deterministic primary");
            CheckEqual(result.inventory.correlatedOnlyCount, std::size_t(1),
                L"duplicate rows create one inactive candidate");
            CheckEqual(result.records.size(),
                result.inventory.records.size() + std::size_t(1),
                L"supporting duplicate remains source-auditable");
        }

        void TestAppContainerRemainsContext()
        {
            NativeTokenObservationInput input = AvailableInput();
            input.token.isAppContainer = true;
            const NativeTokenObservationBuildResult result =
                BuildNativeTokenObservations(input);
            const ObservationRecord* appContainer = FindMapping(
                result,
                NativeTokenMappingAppContainer);
            Check(appContainer != nullptr, L"AppContainer fact retained");
            if (appContainer != nullptr)
            {
                CheckEqual(
                    appContainer->observation.disposition,
                    ObservationDisposition::Context,
                    L"AppContainer remains context");
                Check(!appContainer->observation.contributesToVerdict,
                    L"AppContainer does not contribute");
            }
        }

        void TestCollectionFailureAndPartialCollection()
        {
            NativeTokenObservationInput failure;
            failure.identity = Identity();
            failure.supplied = true;
            failure.collectionAttempted = true;
            failure.token.success = false;
            failure.token.errorMessage = L"Access was unavailable.";
            failure.source.sourceIdentifier = "core.test.native-token";
            const NativeTokenObservationBuildResult failed =
                BuildNativeTokenObservations(failure);
            Check(failed.Succeeded(), L"collection failure is a valid build");
            CheckEqual(failed.inventory.collectionNoteCount, std::size_t(1),
                L"collection failure becomes one CollectionNote");
            CheckEqual(failed.inventory.reviewRelevantCount, std::size_t(0),
                L"collection failure is not review evidence");

            NativeTokenObservationInput partial = AvailableInput();
            partial.token.errorMessage =
                L"One optional token field was unavailable.";
            const NativeTokenObservationBuildResult partialResult =
                BuildNativeTokenObservations(partial);
            Check(partialResult.Succeeded(), L"partial collection remains valid");
            CheckEqual(
                CountMapping(partialResult, NativeTokenMappingCollectionPartial),
                std::size_t(1),
                L"partial source limitation remains a CollectionNote");
            CheckEqual(partialResult.inventory.reviewRelevantCount,
                std::size_t(0),
                L"partial collection does not elevate");
        }

        void TestTruncationMaterialityAndCaps()
        {
            NativeTokenObservationInput truncated = AvailableInput();
            truncated.privilegesTruncated = true;
            truncated.omittedPrivilegeCount = 3;
            const NativeTokenObservationBuildResult result =
                BuildNativeTokenObservations(truncated);
            Check(result.Succeeded(), L"bounded truncation remains auditable");
            Check(result.truncated, L"truncation flag retained");
            CheckEqual(result.omittedFactCount, std::size_t(3),
                L"material omitted fact count retained");
            CheckEqual(
                CountMapping(
                    result,
                    NativeTokenMappingPrivilegeTruncation),
                std::size_t(1),
                L"truncation produces one CollectionNote");

            NativeTokenObservationInput contradictory = AvailableInput();
            contradictory.omittedPrivilegeCount = 1;
            const NativeTokenObservationBuildResult invalid =
                BuildNativeTokenObservations(contradictory);
            Check(!invalid.Succeeded(),
                L"token omission without a truncation marker is rejected");
            CheckEqual(
                invalid.status,
                NativeTokenObservationBuildStatus::InvalidTypedFact,
                L"contradictory token omission has typed failure");

            NativeTokenObservationInput overCap = AvailableInput();
            overCap.token.privileges.resize(
                NativeTokenObservationMaxPrivileges + 1);
            for (std::size_t index = 0;
                 index < overCap.token.privileges.size();
                 ++index)
            {
                overCap.token.privileges[index].name =
                    L"SeGeneric" + std::to_wstring(index);
            }
            const NativeTokenObservationBuildResult rejected =
                BuildNativeTokenObservations(overCap);
            Check(!rejected.Succeeded(), L"privilege cap plus one is rejected");
            CheckEqual(
                rejected.status,
                NativeTokenObservationBuildStatus::InputLimitExceeded,
                L"cap rejection is typed");
            Check(rejected.records.empty() && rejected.inventory.records.empty(),
                L"cap rejection is atomic");
        }

        void TestAccountNamesNeverAffectPolicy()
        {
            NativeTokenObservationInput left = AvailableInput();
            NativeTokenObservationInput right = left;
            left.token.userName = L"Generic User A";
            left.token.domainName = L"Generic Domain A";
            right.token.userName = L"Different User B";
            right.token.domainName = L"Different Domain B";

            const NativeTokenObservationBuildResult leftResult =
                BuildNativeTokenObservations(left);
            const NativeTokenObservationBuildResult rightResult =
                BuildNativeTokenObservations(right);
            Check(leftResult.Succeeded() && rightResult.Succeeded(),
                L"name-independence fixtures succeed");
            CheckEqual(
                PolicyShape(leftResult),
                PolicyShape(rightResult),
                L"account and domain names do not affect observation policy");
        }

        void TestInvalidPrivilegeIdentityFailsAtomically()
        {
            NativeTokenObservationInput input = AvailableInput();
            input.token.privileges.push_back(Privilege(L"", true));
            const NativeTokenObservationBuildResult result =
                BuildNativeTokenObservations(input);
            Check(!result.Succeeded(), L"empty privilege identity is rejected");
            CheckEqual(
                result.status,
                NativeTokenObservationBuildStatus::InvalidTypedFact,
                L"empty privilege identity has typed status");
            Check(result.records.empty() && result.inventory.records.empty(),
                L"invalid privilege source fails atomically");
        }
    }

    int RunNativeTokenObservationBuilderTests()
    {
        failureCount = 0;
        TestContextOnlyToken();
        TestOptionalTokenSourceCanBeAbsent();
        TestHighIntegrityElevationAndSystemRemainContext();
        TestDebugPrivilegePolicy();
        TestPrivilegeChildrenShareOneTokenArtifact();
        TestDuplicatePrivilegeRowsDoNotReinforce();
        TestAppContainerRemainsContext();
        TestCollectionFailureAndPartialCollection();
        TestTruncationMaterialityAndCaps();
        TestAccountNamesNeverAffectPolicy();
        TestInvalidPrivilegeIdentityFailsAtomically();
        return failureCount;
    }
}
