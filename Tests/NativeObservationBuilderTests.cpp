#include "Core/NativeObservationBuilder.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
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
            std::uint32_t pid = 4200,
            std::uint64_t creationTime = 900000)
        {
            ProcessIdentityKey identity;
            identity.pid = pid;
            identity.hasCreationTime = true;
            identity.creationTimeFileTime = creationTime;
            return identity;
        }

        NativeObservationSource Source(
            std::string identifier = "generic-typed-source")
        {
            NativeObservationSource source;
            source.sourceKind = ObservationSourceKind::Direct;
            source.sourceIdentifier = std::move(identifier);
            source.collectionMethod = "already-collected-typed-metadata";
            source.collectionTimestamp = "2026-07-17T00:00:00Z";
            source.rawSourceReference = "typed-source-record";
            return source;
        }

        NativeSelectedProcessObservationInput EmptyInput()
        {
            NativeSelectedProcessObservationInput input;
            input.identity = Identity();
            return input;
        }

        NativeSelectedProcessObservationInput CommandInput(
            std::string commandLine)
        {
            NativeSelectedProcessObservationInput input = EmptyInput();
            input.commandLine.identity = input.identity;
            input.commandLine.supplied = true;
            input.commandLine.collectionAttempted = true;
            input.commandLine.available = true;
            input.commandLine.commandLine = std::move(commandLine);
            input.commandLine.source = Source("generic-command-line-source");
            return input;
        }

        const NativeObservationRecord* FindMapping(
            const NativeObservationBuildResult& result,
            const std::string& mapping)
        {
            const auto found = std::find_if(
                result.records.begin(),
                result.records.end(),
                [&](const NativeObservationRecord& record)
                {
                    return record.record.source.mappingRuleId == mapping;
                });
            return found == result.records.end() ? nullptr : &*found;
        }

        std::size_t CountMapping(
            const NativeObservationBuildResult& result,
            const std::string& mapping)
        {
            return static_cast<std::size_t>(std::count_if(
                result.records.begin(),
                result.records.end(),
                [&](const NativeObservationRecord& record)
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

        NativeFileIdentityInput InvalidSignatureFile(
            const ProcessIdentityKey& identity)
        {
            NativeFileIdentityInput file;
            file.identity = identity;
            file.supplied = true;
            file.artifactKey = "file-artifact:generic-selected-executable";
            file.rawPath =
                "C:\\Users\\Analyst\\AppData\\Local\\Generic\\worker.exe";
            file.normalizedPath =
                "c:\\users\\analyst\\appdata\\local\\generic\\worker.exe";
            file.pathContext = NativeFilePathContext::UserWritable;
            file.signatureState =
                NativeFileSignatureState::AuthenticatedInvalid;
            file.signerSubject = "Generic signer subject";
            file.signerIssuer = "Generic validation issuer";
            file.signerThumbprint = "0011223344556677";
            file.evidence = { "Authenticated signature state: invalid" };
            file.source = Source("generic-authenticated-file-source");
            return file;
        }

        void TestExactEncodedSwitchesAndPreviews()
        {
            struct Fixture
            {
                const char* command;
                const char* encoding;
                const char* preview;
            };
            const Fixture fixtures[] = {
                { "generic-runner.exe -EnCoDeDcOmMaNd Z2VuZXJpYw==",
                    "utf-8", "generic" },
                { "generic-runner.exe /ENCODEDCOMMAND ZwBlAG4AZQByAGkAYwA=",
                    "utf-16le", "generic" },
                { "generic-runner.exe \"--Encoded-Command\" Z2VuZXJpYw==",
                    "utf-8", "generic" }
            };

            for (const Fixture& fixture : fixtures)
            {
                const NativeObservationBuildResult result =
                    BuildNativeSelectedProcessObservations(
                        CommandInput(fixture.command));
                Check(result.Succeeded(), L"complete encoded switch build succeeds");
                CheckEqual(
                    CountMapping(result, NativeMappingEncodedCommand),
                    std::size_t(1),
                    L"complete encoded switch maps exactly once");
                const NativeObservationRecord* encoded = FindMapping(
                    result,
                    NativeMappingEncodedCommand);
                Check(encoded != nullptr, L"encoded switch record retained");
                if (encoded != nullptr)
                {
                    const Observation& observation = encoded->record.observation;
                    CheckEqual(
                        observation.domain,
                        EvidenceDomain::CommandLine,
                        L"encoded switch has command-line domain");
                    CheckEqual(
                        observation.disposition,
                        ObservationDisposition::ReviewRelevant,
                        L"encoded switch retains explicit review disposition");
                    CheckEqual(
                        observation.strength,
                        ObservationStrength::Moderate,
                        L"encoded switch retains conservative strength");
                    Check(observation.contributesToVerdict,
                        L"encoded switch can contribute under existing policy");
                    CheckEqual(
                        observation.correlationKey,
                        std::string("command-relationship-context"),
                        L"encoded switch uses existing typed correlation family");
                    CheckEqual(
                        Attribute(observation, "command.payload.encoding"),
                        std::string(fixture.encoding),
                        L"encoded payload encoding is deterministic");
                    CheckEqual(
                        Attribute(observation, "command.payload.preview"),
                        std::string(fixture.preview),
                        L"bounded decoded preview is retained");
                    Check(
                        std::any_of(
                            observation.limitations.begin(),
                            observation.limitations.end(),
                            [](const std::string& limitation)
                            {
                                return limitation.find("was not executed") !=
                                    std::string::npos;
                            }),
                        L"decoded preview explicitly states no execution");
                }
            }

            const char* nearMisses[] = {
                "generic-runner.exe -enc Z2VuZXJpYw==",
                "generic-runner.exe /enc Z2VuZXJpYw==",
                "generic-runner.exe -EncodedCommandExtra Z2VuZXJpYw==",
                "generic-runner.exe /EncodedCommand:value",
                "generic-runner.exe --encoded-command=Z2VuZXJpYw==",
                "generic-runner.exe prefix-EncodedCommand Z2VuZXJpYw=="
            };
            for (const char* command : nearMisses)
            {
                const NativeObservationBuildResult result =
                    BuildNativeSelectedProcessObservations(
                        CommandInput(command));
                Check(result.Succeeded(), L"encoded near-miss build succeeds");
                CheckEqual(
                    CountMapping(result, NativeMappingEncodedCommand),
                    std::size_t(0),
                    L"only exact complete encoded switches map");
            }
        }

        void TestBoundedDecodeAndCommandAvailability()
        {
            NativeObservationBuildResult invalid =
                BuildNativeSelectedProcessObservations(
                    CommandInput("generic-runner.exe -EncodedCommand !!!="));
            Check(invalid.Succeeded(), L"invalid base64 remains an auditable fact");
            const NativeObservationRecord* invalidRecord = FindMapping(
                invalid,
                NativeMappingEncodedCommand);
            Check(invalidRecord != nullptr, L"invalid base64 switch retained");
            if (invalidRecord != nullptr)
            {
                CheckEqual(
                    Attribute(
                        invalidRecord->record.observation,
                        "command.payload.encoding"),
                    std::string("invalid-base64"),
                    L"invalid base64 is classified without decoding");
                CheckEqual(
                    invalidRecord->completeness,
                    ObservationSourceCompleteness::Partial,
                    L"invalid base64 preview coverage is partial");
            }

            const std::string oversizedPayload(
                NativeObservationMaxEncodedPayloadCharacters + 1,
                'A');
            NativeObservationBuildResult oversized =
                BuildNativeSelectedProcessObservations(CommandInput(
                    "generic-runner.exe -EncodedCommand " + oversizedPayload));
            Check(oversized.Succeeded(), L"over-cap payload remains bounded");
            Check(oversized.truncated, L"over-cap payload marks bounded truncation");
            const NativeObservationRecord* oversizedRecord = FindMapping(
                oversized,
                NativeMappingEncodedCommand);
            Check(oversizedRecord != nullptr, L"over-cap switch remains auditable");
            if (oversizedRecord != nullptr)
            {
                CheckEqual(
                    Attribute(
                        oversizedRecord->record.observation,
                        "command.payload.encoding"),
                    std::string("limit-exceeded"),
                    L"over-cap payload is not decoded");
                Check(
                    oversizedRecord->record.observation.rawValue.size() <=
                        ObservationRawValueMaxCharacters,
                    L"over-cap payload raw value remains bounded");
            }

            NativeSelectedProcessObservationInput unavailable = EmptyInput();
            unavailable.commandLine.identity = unavailable.identity;
            unavailable.commandLine.supplied = true;
            unavailable.commandLine.collectionAttempted = true;
            unavailable.commandLine.available = false;
            unavailable.commandLine.source = Source();
            const NativeObservationBuildResult unavailableResult =
                BuildNativeSelectedProcessObservations(unavailable);
            const NativeObservationRecord* note = FindMapping(
                unavailableResult,
                NativeMappingCommandLineUnavailable);
            Check(unavailableResult.Succeeded(),
                L"unavailable command-line result succeeds as collection context");
            Check(note != nullptr, L"unavailable command-line note retained");
            if (note != nullptr)
            {
                CheckEqual(
                    note->record.observation.disposition,
                    ObservationDisposition::CollectionNote,
                    L"unavailable command line is a collection note");
                Check(!note->record.observation.contributesToVerdict,
                    L"unavailable command line cannot contribute");
            }
        }

        void TestTypedRelationshipAndAncestryIdentity()
        {
            NativeSelectedProcessObservationInput input = EmptyInput();
            NativeRelationshipFact parent;
            parent.subjectIdentity = input.identity;
            parent.relatedIdentity = Identity(4100, 800000);
            parent.kind = NativeRelationshipKind::DirectParent;
            parent.semantics =
                NativeRelationshipSemantics::ExecutionCorrelation;
            parent.semanticFactKey = "relationship:4100:4200:direct-parent";
            parent.sourceRuleId = "generic.relationship.execution-context";
            parent.normalizedValue = "pid:4100->pid:4200";
            parent.evidence = { "Typed direct-parent identity link" };
            parent.source = Source("generic-relationship-source");
            input.relationships.push_back(parent);

            NativeRelationshipFact ancestor;
            ancestor.subjectIdentity = input.identity;
            ancestor.relatedIdentity = Identity(4000, 700000);
            ancestor.kind = NativeRelationshipKind::Ancestor;
            ancestor.semantics = NativeRelationshipSemantics::Context;
            ancestor.semanticFactKey = "relationship:4000:4200:ancestor";
            ancestor.sourceRuleId = "generic.relationship.ancestry-context";
            ancestor.source = Source("generic-ancestry-source");
            input.relationships.push_back(ancestor);

            const NativeObservationBuildResult result =
                BuildNativeSelectedProcessObservations(input);
            Check(result.Succeeded(), L"typed identity relationship build succeeds");
            const NativeObservationRecord* execution = FindMapping(
                result,
                NativeMappingTypedRelationship);
            const NativeObservationRecord* context = FindMapping(
                result,
                NativeMappingRelationshipContext);
            Check(execution != nullptr, L"typed execution relationship retained");
            Check(context != nullptr, L"typed ancestry context retained");
            if (execution != nullptr)
            {
                CheckEqual(
                    execution->record.observation.disposition,
                    ObservationDisposition::CorrelatedOnly,
                    L"typed execution relationship remains correlated-only");
                Check(!execution->record.observation.contributesToVerdict,
                    L"typed relationship cannot contribute independently");
                CheckEqual(
                    execution->record.observation.correlationKey,
                    std::string("command-relationship-context"),
                    L"typed relationship uses existing correlation family");
            }
            if (context != nullptr)
            {
                CheckEqual(
                    context->record.observation.disposition,
                    ObservationDisposition::Context,
                    L"ordinary ancestry remains context");
                CheckEqual(
                    Attribute(
                        context->record.observation,
                        "relationship.kind"),
                    std::string("ancestor"),
                    L"ancestry kind is retained as typed metadata");
            }

            NativeSelectedProcessObservationInput mismatch = input;
            mismatch.relationships.front().subjectIdentity = Identity(9999, 1);
            const NativeObservationBuildResult mismatchResult =
                BuildNativeSelectedProcessObservations(mismatch);
            Check(!mismatchResult.Succeeded(),
                L"relationship with mismatched subject identity fails");
            Check(mismatchResult.records.empty(),
                L"identity mismatch fails atomically");

            NativeSelectedProcessObservationInput unavailable = EmptyInput();
            NativeRelationshipFact unverified = parent;
            unverified.subjectIdentity = unavailable.identity;
            unverified.verified = false;
            unavailable.relationships.push_back(std::move(unverified));
            const NativeObservationBuildResult unavailableResult =
                BuildNativeSelectedProcessObservations(unavailable);
            const NativeObservationRecord* unavailableRecord = FindMapping(
                unavailableResult,
                NativeMappingRelationshipUnavailable);
            Check(unavailableRecord != nullptr,
                L"unverified relationship remains a typed collection note");
            if (unavailableRecord != nullptr)
            {
                CheckEqual(
                    unavailableRecord->record.observation.domain,
                    EvidenceDomain::CollectionQuality,
                    L"unverified relationship uses collection-quality domain");
            }
        }

        void TestAuthenticatedFileIdentityPolicy()
        {
            NativeSelectedProcessObservationInput invalidInput = EmptyInput();
            invalidInput.fileIdentity = InvalidSignatureFile(invalidInput.identity);
            const NativeObservationBuildResult invalid =
                BuildNativeSelectedProcessObservations(invalidInput);
            Check(invalid.Succeeded(), L"typed invalid-signature build succeeds");
            const NativeObservationRecord* path = FindMapping(
                invalid,
                NativeMappingUserWritablePath);
            const NativeObservationRecord* signature = FindMapping(
                invalid,
                NativeMappingInvalidSignature);
            Check(path != nullptr, L"typed user-writable path context retained");
            Check(signature != nullptr, L"authenticated invalid signature retained");
            if (path != nullptr)
            {
                CheckEqual(
                    path->record.observation.disposition,
                    ObservationDisposition::Context,
                    L"user-writable path alone remains context");
                Check(!path->record.observation.contributesToVerdict,
                    L"user-writable path alone is non-contributing");
            }
            if (signature != nullptr)
            {
                CheckEqual(
                    signature->record.observation.disposition,
                    ObservationDisposition::ReviewRelevant,
                    L"authenticated invalid signature is review-relevant");
                CheckEqual(
                    signature->record.observation.strength,
                    ObservationStrength::Moderate,
                    L"invalid signature has conservative Moderate strength");
                Check(signature->record.observation.contributesToVerdict,
                    L"invalid signature may contribute");
                CheckEqual(
                    Attribute(
                        signature->record.observation,
                        "file.signer-subject"),
                    std::string("Generic signer subject"),
                    L"signer subject is retained only as metadata");
            }

            NativeSelectedProcessObservationInput renamed = invalidInput;
            renamed.fileIdentity.rawPath =
                "D:\\Different\\Generic\\renamed-binary.dat";
            renamed.fileIdentity.normalizedPath =
                "d:\\different\\generic\\renamed-binary.dat";
            renamed.fileIdentity.signerSubject = "Different generic subject";
            const NativeObservationBuildResult renamedResult =
                BuildNativeSelectedProcessObservations(renamed);
            const NativeObservationRecord* renamedSignature = FindMapping(
                renamedResult,
                NativeMappingInvalidSignature);
            Check(renamedSignature != nullptr,
                L"renamed typed invalid-signature fact remains mapped");
            if (signature != nullptr && renamedSignature != nullptr)
            {
                CheckEqual(
                    renamedSignature->record.observation.disposition,
                    signature->record.observation.disposition,
                    L"file name and signer text do not change disposition");
                CheckEqual(
                    renamedSignature->record.observation.strength,
                    signature->record.observation.strength,
                    L"file name and signer text do not change strength");
                CheckEqual(
                    renamedSignature->record.observation.contributesToVerdict,
                    signature->record.observation.contributesToVerdict,
                    L"file name and signer text do not change contribution");
            }

            NativeSelectedProcessObservationInput valid = EmptyInput();
            valid.fileIdentity = InvalidSignatureFile(valid.identity);
            valid.fileIdentity.pathContext = NativeFilePathContext::Available;
            valid.fileIdentity.signatureState =
                NativeFileSignatureState::AuthenticatedValid;
            const NativeObservationBuildResult validResult =
                BuildNativeSelectedProcessObservations(valid);
            const NativeObservationRecord* validSignature = FindMapping(
                validResult,
                NativeMappingValidSignature);
            Check(validSignature != nullptr,
                L"authenticated valid signature retained as context");
            if (validSignature != nullptr)
            {
                CheckEqual(
                    validSignature->record.observation.disposition,
                    ObservationDisposition::Informational,
                    L"valid signature metadata is informational");
                Check(!validSignature->record.observation.contributesToVerdict,
                    L"signer validity is not automatic trust or contribution");
            }

            NativeSelectedProcessObservationInput absent = valid;
            absent.fileIdentity.signatureState =
                NativeFileSignatureState::SignatureAbsent;
            const NativeObservationBuildResult absentResult =
                BuildNativeSelectedProcessObservations(absent);
            const NativeObservationRecord* absentSignature = FindMapping(
                absentResult,
                NativeMappingSignatureAbsent);
            Check(absentSignature != nullptr,
                L"signature absence remains separately represented");
            if (absentSignature != nullptr)
            {
                CheckEqual(
                    absentSignature->record.observation.disposition,
                    ObservationDisposition::Context,
                    L"signature absence is not treated as invalid signature");
            }

            NativeSelectedProcessObservationInput systemPath = valid;
            systemPath.fileIdentity.rawPath =
                "C:\\Windows\\System32\\generic-host.exe";
            systemPath.fileIdentity.normalizedPath =
                "c:\\windows\\system32\\generic-host.exe";
            systemPath.fileIdentity.signerSubject =
                "Authenticated third-party signer";
            const NativeObservationBuildResult systemPathResult =
                BuildNativeSelectedProcessObservations(systemPath);
            const NativeObservationRecord* systemPathSignature =
                FindMapping(systemPathResult, NativeMappingValidSignature);
            Check(systemPathSignature != nullptr,
                L"authenticated third-party signer is retained on a system-style path");
            if (systemPathSignature != nullptr)
            {
                Check(
                    !systemPathSignature->record.observation.contributesToVerdict,
                    L"system-like filename and third-party signer do not create suspicion");
            }

            NativeSelectedProcessObservationInput missingSubject = systemPath;
            missingSubject.fileIdentity.signerSubject.clear();
            const NativeObservationBuildResult missingSubjectResult =
                BuildNativeSelectedProcessObservations(missingSubject);
            const NativeObservationRecord* missingSubjectSignature =
                FindMapping(missingSubjectResult, NativeMappingValidSignature);
            Check(missingSubjectSignature != nullptr,
                L"missing optional signer display metadata does not erase typed validation state");
            if (missingSubjectSignature != nullptr)
            {
                CheckEqual(
                    missingSubjectSignature->record.observation.disposition,
                    ObservationDisposition::Informational,
                    L"missing signer display metadata is not a name-reputation rule");
            }

            NativeSelectedProcessObservationInput unavailable = systemPath;
            unavailable.fileIdentity.signatureState =
                NativeFileSignatureState::Unavailable;
            unavailable.fileIdentity.source.completeness =
                ObservationSourceCompleteness::Unavailable;
            const NativeObservationBuildResult unavailableResult =
                BuildNativeSelectedProcessObservations(unavailable);
            const NativeObservationRecord* unavailableSignature =
                FindMapping(
                    unavailableResult,
                    NativeMappingFileIdentityUnavailable);
            Check(unavailableSignature != nullptr,
                L"signature collection failure remains explicitly unavailable");
            if (unavailableSignature != nullptr)
            {
                CheckEqual(
                    unavailableSignature->record.observation.disposition,
                    ObservationDisposition::CollectionNote,
                    L"signature collection failure is a non-contributing collection note");
            }

            CheckEqual(
                ClassifyNativeFilePathContext(
                    "c:\\users\\generic\\downloads\\worker.exe"),
                NativeFilePathContext::UserWritable,
                L"generic user-writable path classification is structural");
            CheckEqual(
                ClassifyNativeFilePathContext(
                    "c:\\windows\\system32\\generic-host.exe"),
                NativeFilePathContext::Available,
                L"system-style path is retained as ordinary typed path context");
        }

        void TestCapsAndAtomicFailure()
        {
            NativeSelectedProcessObservationInput command = CommandInput(
                std::string(
                    NativeObservationMaxCommandLineCharacters + 1,
                    'x'));
            const NativeObservationBuildResult commandResult =
                BuildNativeSelectedProcessObservations(command);
            Check(!commandResult.Succeeded(),
                L"over-cap command line is rejected");
            CheckEqual(
                commandResult.status,
                NativeObservationBuildStatus::InputLimitExceeded,
                L"over-cap command line reports input cap");
            Check(commandResult.records.empty(),
                L"over-cap command line fails atomically");

            NativeSelectedProcessObservationInput relationships = EmptyInput();
            NativeRelationshipFact fact;
            fact.subjectIdentity = relationships.identity;
            fact.relatedIdentity = Identity(4100, 800000);
            fact.semanticFactKey = "generic.relationship.fact";
            fact.source = Source();
            relationships.relationships.assign(
                NativeObservationMaxRelationshipFacts + 1,
                fact);
            const NativeObservationBuildResult relationshipResult =
                BuildNativeSelectedProcessObservations(relationships);
            Check(!relationshipResult.Succeeded(),
                L"over-cap relationship input is rejected");
            Check(relationshipResult.records.empty(),
                L"over-cap relationship input fails atomically");

            NativeSelectedProcessObservationInput badIdentity = EmptyInput();
            badIdentity.identity.hasCreationTime = false;
            badIdentity.identity.creationTimeFileTime = 7;
            const NativeObservationBuildResult badIdentityResult =
                BuildNativeSelectedProcessObservations(badIdentity);
            CheckEqual(
                badIdentityResult.status,
                NativeObservationBuildStatus::InvalidIdentity,
                L"contradictory creation-time identity is rejected");

            NativeSelectedProcessObservationInput boundedFile = EmptyInput();
            boundedFile.fileIdentity =
                InvalidSignatureFile(boundedFile.identity);
            boundedFile.fileIdentity.signerSubject.assign(
                ObservationArtifactAttributeValueMaxCharacters + 100,
                's');
            const NativeObservationBuildResult boundedFileResult =
                BuildNativeSelectedProcessObservations(boundedFile);
            Check(boundedFileResult.Succeeded(),
                L"overlong signer metadata is bounded safely");
            Check(boundedFileResult.truncated,
                L"overlong signer metadata reports truncation");
            const NativeObservationRecord* boundedSignature = FindMapping(
                boundedFileResult,
                NativeMappingInvalidSignature);
            Check(
                boundedSignature != nullptr &&
                    Attribute(
                        boundedSignature->record.observation,
                        "file.signer-subject").size() ==
                        ObservationArtifactAttributeValueMaxCharacters,
                L"signer metadata respects artifact attribute cap");
        }

        void TestOptionalHandleMetadataTruncationIsNotMaterial()
        {
            NativeSelectedProcessObservationInput input = EmptyInput();
            input.handles.sourceIdentity = input.identity;
            input.handles.supplied = true;
            input.handles.collectionAttempted = true;
            input.handles.collection.pid = input.identity.pid;
            input.handles.collection.success = true;
            input.handles.collection.state = HandleCollectionState::Partial;
            input.handles.source.sourceKind = ObservationSourceKind::Direct;
            input.handles.source.sourceIdentifier = "generic-handle-source";
            input.handles.source.collectionMethod =
                "already-collected-handle-metadata";
            input.handles.source.collectionTimestamp =
                "2026-07-17T00:00:00Z";
            input.handles.source.rawSourceReference =
                "generic-handle-source-record";

            HandleInfo row;
            row.owningPid = input.identity.pid;
            row.handleValue = 0xA0;
            row.objectTypeIndex = 3;
            row.objectType = L"File";
            row.grantedAccessRaw = 0x00100000U;
            row.errorMessage.assign(
                ObservationLimitationItemMaxCharacters + 100,
                L'x');
            input.handles.collection.handles.push_back(std::move(row));

            const NativeObservationBuildResult result =
                BuildNativeSelectedProcessObservations(input);
            Check(result.Succeeded(),
                L"optional handle metadata limitation preserves native success");
            CheckEqual(result.omittedFactCount, std::size_t(0),
                L"optional handle metadata omission is not a missing typed fact");
            Check(!result.truncated,
                L"bounded handle display metadata does not block authority");
            CheckEqual(result.handleFactCount, std::size_t(1),
                L"raw handle fact remains represented without optional metadata");
        }

        void TestNativeMergeSuppressesSemanticDuplicates()
        {
            NativeSelectedProcessObservationInput input = EmptyInput();
            input.fileIdentity = InvalidSignatureFile(input.identity);
            const NativeObservationBuildResult native =
                BuildNativeSelectedProcessObservations(input);
            const NativeObservationRecord* nativeSignature = FindMapping(
                native,
                NativeMappingInvalidSignature);
            Check(nativeSignature != nullptr,
                L"native signature source available for merge fixture");
            if (nativeSignature == nullptr)
            {
                return;
            }

            NativeObservationRecord duplicateOne = *nativeSignature;
            duplicateOne.record.observation.id =
                "native-duplicate-one:signature";
            duplicateOne.sourceRecordId = "native-source-one:signature";
            NativeObservationRecord duplicateTwo = *nativeSignature;
            duplicateTwo.record.observation.id =
                "native-duplicate-two:signature";
            duplicateTwo.sourceRecordId = "native-source-two:signature";

            const NativeObservationMergeResult merged =
                MergeNativeObservationRecords({
                    duplicateOne,
                    duplicateTwo,
                    *nativeSignature
                });
            Check(merged.success, L"native observation merge succeeds");
            CheckEqual(merged.records.size(), std::size_t(3),
                L"native observation merge preserves every source");
            CheckEqual(merged.inventory.records.size(), std::size_t(1),
                L"duplicate semantic fact contributes one primary record");
            CheckEqual(merged.duplicateCount, std::size_t(2),
                L"equivalent native duplicates are counted");
            const std::string primaryId =
                merged.inventory.records.front().observation.id;

            std::size_t primaryCount = 0;
            std::size_t supportingCount = 0;
            for (const NativeObservationRecord& record : merged.records)
            {
                if (record.duplicateRole == ObservationDuplicateRole::Primary)
                {
                    ++primaryCount;
                }
                else
                {
                    ++supportingCount;
                    CheckEqual(
                        record.primaryObservationId,
                        primaryId,
                        L"supporting source points to native primary identity");
                }
            }
            CheckEqual(primaryCount, std::size_t(1),
                L"one primary role retained");
            CheckEqual(supportingCount, std::size_t(2),
                L"two supporting duplicate roles retained");

            NativeObservationRecord otherEntity = duplicateOne;
            otherEntity.record.observation.id =
                "native-observation:other-entity";
            otherEntity.record.observation.entityScope =
                "process:pid:4300:creation:910000";
            otherEntity.record.observation.artifactIdentity.entityScope =
                otherEntity.record.observation.entityScope;
            const NativeObservationMergeResult separateEntities =
                MergeNativeObservationRecords({ *nativeSignature, otherEntity });
            Check(separateEntities.success,
                L"cross-entity merge fixture succeeds");
            CheckEqual(
                separateEntities.inventory.records.size(),
                std::size_t(2),
                L"same semantic key in different entities does not deduplicate");
        }

        void TestGenericCombinedCorpus()
        {
            NativeSelectedProcessObservationInput input = CommandInput(
                "generic-runner.exe --encoded-command Z2VuZXJpYw==");
            NativeRelationshipFact relationship;
            relationship.subjectIdentity = input.identity;
            relationship.relatedIdentity = Identity(4100, 800000);
            relationship.kind = NativeRelationshipKind::DirectParent;
            relationship.semantics =
                NativeRelationshipSemantics::ExecutionCorrelation;
            relationship.semanticFactKey =
                "generic.execution-relationship:4100:4200";
            relationship.sourceRuleId =
                "generic.execution-relationship-rule";
            relationship.source = Source("generic-relationship-source");
            input.relationships.push_back(std::move(relationship));
            input.fileIdentity = InvalidSignatureFile(input.identity);
            input.limitations = {
                "Only already-collected selected-process metadata was evaluated."
            };

            const NativeObservationBuildResult result =
                BuildNativeSelectedProcessObservations(input);
            Check(result.Succeeded(), L"combined generic native corpus succeeds");
            CheckEqual(result.representedFactCount, std::size_t(4),
                L"combined corpus represents command, relationship, path, signature");
            CheckEqual(result.duplicateCount, std::size_t(0),
                L"distinct combined facts do not deduplicate");
            CheckEqual(result.inventory.reviewRelevantCount, std::size_t(2),
                L"combined corpus has explicit command and signature review facts");
            CheckEqual(result.inventory.correlatedOnlyCount, std::size_t(1),
                L"combined corpus has one inactive relationship partner");
            CheckEqual(result.inventory.contextCount, std::size_t(1),
                L"combined corpus has one path context fact");
            for (const NativeObservationRecord& record : result.records)
            {
                Check(
                    std::find(
                        record.record.observation.limitations.begin(),
                        record.record.observation.limitations.end(),
                        input.limitations.front()) !=
                        record.record.observation.limitations.end(),
                    L"combined builder preserves global limitations");
            }
        }

        void TestNativeBuilderAndMergePerformance()
        {
            NativeSelectedProcessObservationInput input = CommandInput(
                "generic-runner.exe --encoded-command Z2VuZXJpYw==");
            NativeRelationshipFact relationship;
            relationship.subjectIdentity = input.identity;
            relationship.relatedIdentity = Identity(4100, 800000);
            relationship.kind = NativeRelationshipKind::DirectParent;
            relationship.semantics =
                NativeRelationshipSemantics::ExecutionCorrelation;
            relationship.semanticFactKey =
                "generic.execution-relationship:4100:4200";
            relationship.sourceRuleId =
                "generic.execution-relationship-rule";
            relationship.source = Source("generic-relationship-source");
            input.relationships.push_back(std::move(relationship));
            input.fileIdentity = InvalidSignatureFile(input.identity);

            constexpr int IterationCount = 1000;
            std::size_t checksum = 0;
            NativeObservationBuildResult last;
            const auto buildStarted = std::chrono::steady_clock::now();
            for (int iteration = 0; iteration < IterationCount; ++iteration)
            {
                last = BuildNativeSelectedProcessObservations(input);
                Check(last.Succeeded(),
                    L"repeated native builder performance fixture succeeds");
                checksum += last.records.size();
            }
            const auto buildMicroseconds =
                std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now() - buildStarted).count();

            const auto mergeStarted = std::chrono::steady_clock::now();
            for (int iteration = 0; iteration < IterationCount; ++iteration)
            {
                const NativeObservationMergeResult merged =
                    MergeNativeObservationRecords(last.records);
                Check(merged.success,
                    L"repeated native observation merge performance fixture succeeds");
                checksum += merged.inventory.records.size();
            }
            const auto mergeMicroseconds =
                std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now() - mergeStarted).count();

            Check(checksum != 0,
                L"native performance fixture retains bounded output");
            std::wcout
                << L"Native selected-process fixture: "
                << IterationCount << L" builds in "
                << buildMicroseconds << L" us; "
                << IterationCount << L" native observation merges in "
                << mergeMicroseconds << L" us.\n";
        }
    }

    int RunNativeObservationBuilderTests()
    {
        failureCount = 0;
        TestExactEncodedSwitchesAndPreviews();
        TestBoundedDecodeAndCommandAvailability();
        TestTypedRelationshipAndAncestryIdentity();
        TestAuthenticatedFileIdentityPolicy();
        TestCapsAndAtomicFailure();
        TestOptionalHandleMetadataTruncationIsNotMaterial();
        TestNativeMergeSuppressesSemanticDuplicates();
        TestGenericCombinedCorpus();
        TestNativeBuilderAndMergePerformance();
        return failureCount;
    }
}
