#include "Core/BaselineObservationBuilder.h"

#include "Core/ObservationCorrelation.h"
#include "Core/ObservationPolicy.h"
#include "Core/ObservationRefinement.h"
#include "Core/TriageEngine.h"

#include <algorithm>
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
            std::uint32_t pid = 4200,
            std::wstring name = L"generic-process.exe")
        {
            ProcessInfo process;
            process.pid = pid;
            process.parentPid = 0;
            process.name = std::move(name);
            process.executablePath = L"C:\\Program Files\\Generic\\generic-process.exe";
            process.commandLine = L"\"C:\\Program Files\\Generic\\generic-process.exe\" --run";
            process.commandLineAccessible = true;
            process.hasCreationTime = true;
            process.creationTimeFileTime = 123456789ULL + pid;
            process.severity = Severity::High;
            process.suspicious = true;
            process.indicators = { L"Legacy severity metadata must not be read" };
            return process;
        }

        ProcessSnapshot MakeSnapshot(ProcessInfo process)
        {
            ProcessSnapshot snapshot;
            snapshot.processes.push_back(std::move(process));
            snapshot.Reindex();
            return snapshot;
        }

        BaselineObservationContext MakeContext()
        {
            BaselineObservationContext context;
            context.collectionTimestamp = "2026-07-16T12:00:00Z";
            return context;
        }

        const ObservationRecord* FindMapping(
            const BaselineObservationResult& result,
            const std::string& mappingRule)
        {
            const auto found = std::find_if(
                result.inventory.records.begin(),
                result.inventory.records.end(),
                [&](const ObservationRecord& record)
                {
                    return record.source.mappingRuleId == mappingRule;
                });
            return found == result.inventory.records.end() ? nullptr : &*found;
        }

        std::size_t CountMapping(
            const BaselineObservationResult& result,
            const std::string& mappingRule)
        {
            return static_cast<std::size_t>(std::count_if(
                result.inventory.records.begin(),
                result.inventory.records.end(),
                [&](const ObservationRecord& record)
                {
                    return record.source.mappingRuleId == mappingRule;
                }));
        }

        TriageResult Triage(const BaselineObservationResult& baseline)
        {
            const ObservationRefinementResult refinement =
                RefineObservationInventory(baseline.inventory);
            Check(refinement.Succeeded(), L"baseline fixture refinement succeeds");
            const ObservationCorrelationResult correlations =
                ActivateObservationCorrelations(refinement);
            Check(correlations.Succeeded(), L"baseline fixture correlation succeeds");
            const TriageResult triage = BuildTriageResult(
                refinement,
                correlations);
            Check(triage.Succeeded(), L"baseline fixture triage succeeds");
            return triage;
        }

        ObservationCorrelationResult Correlations(
            const BaselineObservationResult& baseline)
        {
            const ObservationRefinementResult refinement =
                RefineObservationInventory(baseline.inventory);
            Check(refinement.Succeeded(), L"baseline fixture refinement succeeds");
            return ActivateObservationCorrelations(refinement);
        }

        bool HasCorrelationRule(
            const ObservationCorrelationResult& correlations,
            const std::string& ruleId)
        {
            return std::any_of(
                correlations.correlations.begin(),
                correlations.correlations.end(),
                [&](const ObservationCorrelation& correlation)
                {
                    return correlation.ruleId == ruleId;
                });
        }

        void TestBaselineSafeDefaultAndLegacyIndependence()
        {
            ProcessInfo process = MakeProcess();
            const ProcessSnapshot snapshot = MakeSnapshot(process);
            const BaselineObservationResult result =
                BuildBaselineObservations(process, snapshot, MakeContext());

            Check(result.Succeeded(), L"default baseline build succeeds");
            Check(!result.inventory.records.empty(), L"default baseline retains native context");
            CheckEqual(result.inventory.reviewRelevantCount, std::size_t(0), L"normal baseline has no review evidence");
            Check(!result.limitations.empty(), L"default baseline discloses deep-evidence limitation");
            CheckEqual(Triage(result).verdict, TriageVerdict::Informational, L"normal baseline verdict informational");

            ProcessInfo renamed = process;
            renamed.name = L"different-generic-identity.exe";
            renamed.severity = Severity::None;
            renamed.suspicious = false;
            renamed.indicators.clear();
            const ProcessSnapshot renamedSnapshot = MakeSnapshot(renamed);
            const BaselineObservationResult renamedResult =
                BuildBaselineObservations(renamed, renamedSnapshot, MakeContext());
            Check(renamedResult.Succeeded(), L"renamed baseline succeeds");
            CheckEqual(renamedResult.inventory.reviewRelevantCount, result.inventory.reviewRelevantCount, L"process name does not change review evidence");
            CheckEqual(Triage(renamedResult).verdict, Triage(result).verdict, L"legacy severity and process name do not affect verdict");
        }

        void TestPathAndEncodedCommandPolicy()
        {
            ProcessInfo process = MakeProcess();
            process.executablePath = L"C:\\Users\\Analyst\\AppData\\Local\\Generic\\worker.exe";
            process.commandLine = L"worker.exe -EnCoDeDcOmMaNd Z2VuZXJpYw==";
            const ProcessSnapshot snapshot = MakeSnapshot(process);
            const BaselineObservationResult result =
                BuildBaselineObservations(process, snapshot, MakeContext());
            Check(result.Succeeded(), L"path and command baseline succeeds");

            const ObservationRecord* path = FindMapping(
                result,
                BaselineMappingUserWritablePath);
            Check(path != nullptr, L"generic user path emits typed context");
            if (path != nullptr)
            {
                CheckEqual(path->observation.domain, EvidenceDomain::FilePath, L"user path domain");
                CheckEqual(path->observation.disposition, ObservationDisposition::Context, L"user path disposition context");
                Check(!path->observation.contributesToVerdict, L"user path alone non-contributing");
            }

            const ObservationRecord* command = FindMapping(
                result,
                BaselineMappingEncodedCommand);
            Check(command != nullptr, L"generic encoded switch emits native fact");
            if (command != nullptr)
            {
                CheckEqual(command->observation.domain, EvidenceDomain::CommandLine, L"encoded command domain");
                CheckEqual(command->observation.strength, ObservationStrength::Moderate, L"encoded command explicit strength");
                Check(command->observation.contributesToVerdict, L"encoded command review evidence contributes");
                CheckEqual(command->observation.correlationKey, std::string("command-relationship-context"), L"encoded command typed correlation key");
            }
            CheckEqual(Triage(result).verdict, TriageVerdict::MediumAttention, L"encoded command alone has Medium ceiling");

            ProcessInfo falsePositive = process;
            falsePositive.commandLine = L"worker.exe --encryption enabled";
            const ProcessSnapshot falsePositiveSnapshot = MakeSnapshot(falsePositive);
            const BaselineObservationResult falsePositiveResult =
                BuildBaselineObservations(
                    falsePositive,
                    falsePositiveSnapshot,
                    MakeContext());
            CheckEqual(
                CountMapping(falsePositiveResult, BaselineMappingEncodedCommand),
                std::size_t(0),
                L"encoded switch detection uses exact command token");

            for (const std::wstring& shortAlias :
                { std::wstring(L"worker.exe -enc Z2VuZXJpYw=="),
                  std::wstring(L"worker.exe /enc Z2VuZXJpYw==") })
            {
                ProcessInfo ambiguousAlias = process;
                ambiguousAlias.commandLine = shortAlias;
                const ProcessSnapshot ambiguousSnapshot =
                    MakeSnapshot(ambiguousAlias);
                const BaselineObservationResult ambiguousResult =
                    BuildBaselineObservations(
                        ambiguousAlias,
                        ambiguousSnapshot,
                        MakeContext());
                CheckEqual(
                    CountMapping(
                        ambiguousResult,
                        BaselineMappingEncodedCommand),
                    std::size_t(0),
                    L"bare short command alias is not assigned encoded-command semantics");
            }
        }

        void TestTypedRelationshipAndSignatureFacts()
        {
            ProcessInfo process = MakeProcess();
            ProcessSnapshot snapshot = MakeSnapshot(process);
            BaselineObservationContext context = MakeContext();

            BaselineTypedProcessFact relationship;
            relationship.kind =
                BaselineTypedProcessFactKind::ReviewRelevantProcessRelationship;
            relationship.sourceRuleId = "generic.relationship.typed-rule";
            relationship.factKey = "relationship:4100:4200";
            relationship.relatedPid = 4100;
            relationship.rawValue = "4100 -> 4200";
            relationship.normalizedValue = "pid:4100->pid:4200";
            relationship.sourceIdentifier = "generic-relationship-source";
            relationship.collectionMethod = "already-collected-typed-relationship";
            context.typedProcessFacts.push_back(relationship);

            BaselineTypedProcessFact signature;
            signature.kind = BaselineTypedProcessFactKind::InvalidFileSignature;
            signature.sourceRuleId = "generic.signature.invalid";
            signature.factKey = "file:generic-executable";
            signature.rawValue = "Invalid signature validation result";
            signature.normalizedValue = "invalid";
            signature.sourceIdentifier = "generic-signature-source";
            signature.collectionMethod = "already-collected-file-signature";
            context.typedProcessFacts.push_back(signature);

            const BaselineObservationResult result =
                BuildBaselineObservations(process, snapshot, context);
            Check(result.Succeeded(), L"typed relationship/signature baseline succeeds");
            const ObservationRecord* relationshipRecord = FindMapping(
                result,
                BaselineMappingProcessRelationship);
            Check(relationshipRecord != nullptr, L"typed relationship retained");
            if (relationshipRecord != nullptr)
            {
                CheckEqual(relationshipRecord->observation.disposition, ObservationDisposition::CorrelatedOnly, L"relationship remains correlated-only");
                Check(!relationshipRecord->observation.contributesToVerdict, L"relationship cannot contribute independently");
                CheckEqual(relationshipRecord->observation.correlationKey, std::string("command-relationship-context"), L"relationship shares encoded command key");
            }
            const ObservationRecord* signatureRecord = FindMapping(
                result,
                BaselineMappingInvalidFileSignature);
            Check(signatureRecord != nullptr, L"invalid signature retained");
            if (signatureRecord != nullptr)
            {
                CheckEqual(signatureRecord->observation.domain, EvidenceDomain::FileSignature, L"signature domain");
                CheckEqual(signatureRecord->observation.strength, ObservationStrength::Moderate, L"signature conservative strength");
            }
            CheckEqual(Triage(result).verdict, TriageVerdict::MediumAttention, L"invalid signature baseline Medium at most");
        }

        void TestTypedBaselineCorrelations()
        {
            ProcessInfo executionProcess = MakeProcess();
            executionProcess.commandLine =
                L"generic-runner.exe -encodedcommand Z2VuZXJpYw==";
            const ProcessSnapshot executionSnapshot =
                MakeSnapshot(executionProcess);
            BaselineObservationContext executionContext = MakeContext();
            BaselineTypedProcessFact relationship;
            relationship.kind =
                BaselineTypedProcessFactKind::ReviewRelevantProcessRelationship;
            relationship.sourceRuleId = "generic.relationship.typed-execution";
            relationship.factKey = "relationship:4100:4200";
            relationship.relatedPid = 4100;
            relationship.normalizedValue = "pid:4100->pid:4200";
            executionContext.typedProcessFacts.push_back(relationship);
            const BaselineObservationResult execution =
                BuildBaselineObservations(
                    executionProcess,
                    executionSnapshot,
                    executionContext);
            const ObservationCorrelationResult executionCorrelations =
                Correlations(execution);
            Check(executionCorrelations.Succeeded(), L"typed execution correlation succeeds");
            Check(
                HasCorrelationRule(
                    executionCorrelations,
                    "correlation.execution.encoded-command-relationship"),
                L"encoded command and typed relationship activate explicit correlation");
            CheckEqual(
                Triage(execution).verdict,
                TriageVerdict::MediumAttention,
                L"typed execution correlation follows conservative Medium policy");

            ProcessInfo fileProcess = MakeProcess();
            fileProcess.executablePath =
                L"C:\\Users\\Analyst\\AppData\\Local\\Generic\\worker.exe";
            const ProcessSnapshot fileSnapshot = MakeSnapshot(fileProcess);
            BaselineObservationContext fileContext = MakeContext();
            BaselineTypedProcessFact invalidSignature;
            invalidSignature.kind =
                BaselineTypedProcessFactKind::InvalidFileSignature;
            invalidSignature.sourceRuleId = "generic.signature.invalid";
            invalidSignature.factKey = "file:generic-executable";
            invalidSignature.normalizedValue = "invalid";
            fileContext.typedProcessFacts.push_back(invalidSignature);
            const BaselineObservationResult file = BuildBaselineObservations(
                fileProcess,
                fileSnapshot,
                fileContext);
            const ObservationCorrelationResult fileCorrelations =
                Correlations(file);
            Check(
                HasCorrelationRule(
                    fileCorrelations,
                    "correlation.file.user-path-invalid-signature"),
                L"user path and invalid signature activate explicit correlation");
            CheckEqual(
                Triage(file).verdict,
                TriageVerdict::MediumAttention,
                L"user path and invalid signature correlation is Medium");

            ProcessInfo networkProcess = MakeProcess();
            networkProcess.commandLine =
                L"generic-runner.exe -encodedcommand Z2VuZXJpYw==";
            const ProcessSnapshot networkSnapshot = MakeSnapshot(networkProcess);
            BaselineObservationContext networkContext = MakeContext();
            BaselineNetworkIndicatorFact indicator;
            indicator.artifactKey = "network-connection:generic-exact-match";
            indicator.sourceRuleId = "generic.network.exact-indicator";
            indicator.indicatorType = "ip";
            indicator.rawValue = "198.51.100.40";
            indicator.normalizedValue = "198.51.100.40";
            indicator.sourceIdentifier = "verified-local-feed";
            indicator.confidence = ObservationConfidence::High;
            networkContext.networkIndicatorFacts.push_back(indicator);
            const BaselineObservationResult network = BuildBaselineObservations(
                networkProcess,
                networkSnapshot,
                networkContext);
            const ObservationCorrelationResult networkCorrelations =
                Correlations(network);
            Check(
                HasCorrelationRule(
                    networkCorrelations,
                    "correlation.network.exact-indicator-local-evidence"),
                L"exact indicator and independent command evidence activate typed correlation");
            CheckEqual(
                Triage(network).verdict,
                TriageVerdict::HighAttention,
                L"exact indicator plus qualified independent command evidence follows the coherent multi-domain High policy");
        }

        void TestNetworkAndServiceContext()
        {
            ProcessInfo process = MakeProcess();
            const ProcessSnapshot snapshot = MakeSnapshot(process);
            BaselineObservationContext context = MakeContext();

            BaselineNetworkConnectionFact publicConnection;
            publicConnection.artifactKey = "tcp4:local:50000:remote:443";
            publicConnection.protocol = "TCP";
            publicConnection.localAddress = "192.0.2.10";
            publicConnection.localPort = 50000;
            publicConnection.remoteAddress = "198.51.100.10";
            publicConnection.remotePort = 443;
            publicConnection.state = "Established";
            publicConnection.publicRemote = true;
            context.networkConnections.push_back(publicConnection);

            BaselineNetworkConnectionFact localConnection = publicConnection;
            localConnection.artifactKey = "tcp4:local:50001:lan:443";
            localConnection.remoteAddress = "192.168.1.10";
            localConnection.localPort = 50001;
            localConnection.publicRemote = false;
            context.networkConnections.push_back(localConnection);

            BaselineServiceAssociationFact service;
            service.artifactKey = "service:generic-shared-service";
            service.serviceName = "generic-shared-service";
            service.displayName = "Generic shared service";
            service.processModel = ServiceProcessModel::SharedProcess;
            service.stateRaw = 4;
            context.serviceAssociations.push_back(service);

            const BaselineObservationResult result =
                BuildBaselineObservations(process, snapshot, context);
            Check(result.Succeeded(), L"network/service baseline succeeds");
            CheckEqual(CountMapping(result, BaselineMappingPublicNetworkConnection), std::size_t(1), L"only public connection context emitted");
            CheckEqual(CountMapping(result, BaselineMappingServiceAssociation), std::size_t(1), L"service association emitted once");
            const ObservationRecord* network = FindMapping(
                result,
                BaselineMappingPublicNetworkConnection);
            const ObservationRecord* serviceRecord = FindMapping(
                result,
                BaselineMappingServiceAssociation);
            Check(network != nullptr && !network->observation.contributesToVerdict, L"public network context non-contributing");
            Check(serviceRecord != nullptr && !serviceRecord->observation.contributesToVerdict, L"service association context non-contributing");
            CheckEqual(Triage(result).verdict, TriageVerdict::Informational, L"network/service context verdict informational");
        }

        void TestExactIndicatorPolicyAndProvenance()
        {
            ProcessInfo process = MakeProcess();
            const ProcessSnapshot snapshot = MakeSnapshot(process);
            BaselineObservationContext context = MakeContext();
            BaselineNetworkIndicatorFact indicator;
            indicator.artifactKey = "network-connection:generic-exact-match";
            indicator.sourceRuleId = "generic.network.exact-indicator";
            indicator.indicatorType = "ip";
            indicator.rawValue = "198.51.100.30";
            indicator.normalizedValue = "198.51.100.30";
            indicator.sourceIdentifier = "verified-local-feed";
            indicator.collectionMethod = "verified-local-network-indicator-match";
            indicator.strength = ObservationStrength::Moderate;
            indicator.confidence = ObservationConfidence::High;
            context.networkIndicatorFacts.push_back(indicator);

            const BaselineObservationResult result =
                BuildBaselineObservations(process, snapshot, context);
            const ObservationRecord* exact = FindMapping(
                result,
                BaselineMappingExactNetworkIndicator);
            Check(exact != nullptr, L"exact indicator retained");
            if (exact != nullptr)
            {
                CheckEqual(exact->observation.domain, EvidenceDomain::Network, L"exact indicator network domain");
                CheckEqual(exact->observation.provenance.sourceIdentifier, std::string("verified-local-feed"), L"exact indicator provenance retained");
                CheckEqual(exact->observation.correlationKey, std::string("network-intelligence-context"), L"exact indicator correlation key");
            }
            CheckEqual(Triage(result).verdict, TriageVerdict::MediumAttention, L"exact indicator alone Medium ceiling");

            BaselineObservationContext downgradedContext = MakeContext();
            indicator.strength = ObservationStrength::Strong;
            indicator.assessmentRationale.clear();
            downgradedContext.networkIndicatorFacts.push_back(indicator);
            const BaselineObservationResult downgraded =
                BuildBaselineObservations(process, snapshot, downgradedContext);
            const ObservationRecord* downgradedRecord = FindMapping(
                downgraded,
                BaselineMappingExactNetworkIndicator);
            Check(downgradedRecord != nullptr, L"unrationalized indicator remains visible");
            if (downgradedRecord != nullptr)
            {
                CheckEqual(downgradedRecord->observation.strength, ObservationStrength::Moderate, L"Strong exact indicator requires rationale");
            }
        }

        void TestCollectionNotesParentContextAndPidZero()
        {
            ProcessInfo parent = MakeProcess(3000, L"generic-parent.exe");
            ProcessInfo child = MakeProcess(0, L"idle-like-generic-process");
            child.parentPid = parent.pid;
            child.parentRelationshipVerified = true;
            child.commandLineAccessible = false;
            child.hasCreationTime = false;

            ProcessSnapshot snapshot;
            snapshot.processes = { parent, child };
            snapshot.Reindex();
            const BaselineObservationResult result =
                BuildBaselineObservations(child, snapshot, MakeContext());
            Check(result.Succeeded(), L"PID zero baseline succeeds");
            Check(result.inventory.collectionNoteCount >= 1, L"attempted unavailable command line is collection note");
            const ObservationRecord* note = FindMapping(
                result,
                BaselineMappingCommandLineUnavailable);
            Check(note != nullptr, L"command unavailable note exists");
            if (note != nullptr)
            {
                CheckEqual(note->observation.domain, EvidenceDomain::CollectionQuality, L"unavailable command collection domain");
                Check(!note->observation.contributesToVerdict, L"unavailable command never contributes");
            }
            const ObservationRecord* relationship = FindMapping(
                result,
                BaselineMappingProcessRelationshipContext);
            Check(relationship != nullptr, L"verified parent retained as neutral context");
            if (relationship != nullptr)
            {
                CheckEqual(relationship->observation.disposition, ObservationDisposition::Context, L"ordinary parent link context only");
                Check(relationship->observation.correlationKey.empty(), L"ordinary parent link does not activate correlation");
            }
            CheckEqual(Triage(result).verdict, TriageVerdict::Informational, L"PID zero context/notes informational");
        }

        void TestCapsAtomicFailureAndDeterminism()
        {
            ProcessInfo process = MakeProcess();
            process.executablePath = L"C:\\Temp\\" +
                std::wstring(ObservationRawValueMaxCharacters + 200, L'x');
            const ProcessSnapshot snapshot = MakeSnapshot(process);
            BaselineObservationContext cappedContext = MakeContext();
            cappedContext.includeNativeProcessIdentity = false;
            cappedContext.includeNativeCommandLine = false;
            cappedContext.includeNativeRelationshipContext = false;
            cappedContext.networkConnections.resize(
                BaselineObservationMaxNetworkConnections + 3);
            for (std::size_t index = 0;
                index < cappedContext.networkConnections.size();
                ++index)
            {
                BaselineNetworkConnectionFact& fact =
                    cappedContext.networkConnections[index];
                fact.artifactKey = "connection:" + std::to_string(index);
                fact.protocol = "TCP";
                fact.localAddress = "192.0.2.10";
                fact.localPort = static_cast<std::uint16_t>(1000 + index);
                fact.remoteAddress = "198.51.100.10";
                fact.remotePort = 443;
                fact.publicRemote = true;
            }
            const BaselineObservationResult first =
                BuildBaselineObservations(process, snapshot, cappedContext);
            const BaselineObservationResult second =
                BuildBaselineObservations(process, snapshot, cappedContext);
            Check(first.Succeeded(), L"capped baseline succeeds with bounded subset");
            Check(first.truncated, L"capped baseline records truncation");
            CheckEqual(first.omittedFactCount, std::size_t(3), L"capped baseline exact omitted count");
            Check(first.inventory.records.size() <= BaselineObservationMaxSourceFacts, L"capped baseline output bounded");
            CheckEqual(first.diagnostic, second.diagnostic, L"baseline diagnostic deterministic");
            CheckEqual(first.inventory.records.size(), second.inventory.records.size(), L"baseline ordering deterministic");
            for (std::size_t index = 0; index < first.inventory.records.size(); ++index)
            {
                CheckEqual(first.inventory.records[index].observation.id, second.inventory.records[index].observation.id, L"baseline IDs deterministic");
            }

            BaselineObservationContext invalid = MakeContext();
            BaselineTypedProcessFact unknown;
            unknown.kind = BaselineTypedProcessFactKind::Unknown;
            invalid.typedProcessFacts.push_back(unknown);
            const BaselineObservationResult failed =
                BuildBaselineObservations(process, snapshot, invalid);
            Check(failed.attempted, L"invalid typed fact build attempted");
            Check(!failed.success, L"invalid typed fact fails");
            CheckEqual(failed.status, BaselineObservationStatus::InvalidTypedFact, L"invalid typed fact status");
            Check(failed.inventory.records.empty(), L"invalid typed fact failure atomic");
        }

        void TestImportedProvenanceAndNoDeepFabrication()
        {
            ProcessInfo process = MakeProcess();
            process.executablePath.clear();
            const ProcessSnapshot snapshot = MakeSnapshot(process);
            BaselineObservationContext context = MakeContext();
            context.importedEvidence = true;
            context.sourceKind = ObservationSourceKind::Direct;
            const BaselineObservationResult result =
                BuildBaselineObservations(process, snapshot, context);
            Check(result.Succeeded(), L"imported baseline succeeds");
            Check(std::all_of(
                result.inventory.records.begin(),
                result.inventory.records.end(),
                [](const ObservationRecord& record)
                {
                    return record.observation.sourceKind == ObservationSourceKind::Imported ||
                        record.observation.sourceKind == ObservationSourceKind::Unavailable;
                }), L"loaded evidence provenance is imported or unavailable");
            Check(FindMapping(result, BaselineMappingExecutablePath) == nullptr, L"missing path does not fabricate path observation");
            Check(result.inventory.records.size() < 8, L"missing deep evidence does not fabricate deep observations");
        }

        void TestExplicitEndpointCollectionFailures()
        {
            ProcessInfo process = MakeProcess();
            const ProcessSnapshot snapshot = MakeSnapshot(process);
            BaselineObservationContext noFailureContext = MakeContext();
            const BaselineObservationResult withoutFacts =
                BuildBaselineObservations(
                    process,
                    snapshot,
                    noFailureContext);
            CheckEqual(
                CountMapping(
                    withoutFacts,
                    BaselineMappingNetworkCollectionUnavailable),
                std::size_t(0),
                L"absent optional network evidence does not fabricate failure note");
            CheckEqual(
                CountMapping(
                    withoutFacts,
                    BaselineMappingServiceCollectionUnavailable),
                std::size_t(0),
                L"absent optional service evidence does not fabricate failure note");

            BaselineObservationContext explicitFailures = MakeContext();
            BaselineCollectionFact network;
            network.kind = BaselineCollectionFactKind::NetworkUnavailable;
            network.statusMessage = "Network snapshot attempt failed.";
            network.sourceIdentifier = "core.network-snapshot";
            network.collectionMethod = "normal-endpoint-network-refresh";
            explicitFailures.collectionFacts.push_back(network);

            BaselineCollectionFact service;
            service.kind = BaselineCollectionFactKind::ServiceUnavailable;
            service.statusMessage = "Service snapshot attempt failed.";
            service.sourceIdentifier = "core.service-snapshot";
            service.collectionMethod = "persisted-endpoint-context";
            explicitFailures.collectionFacts.push_back(service);

            const BaselineObservationResult result =
                BuildBaselineObservations(
                    process,
                    snapshot,
                    explicitFailures);
            Check(result.Succeeded(), L"explicit endpoint failures build succeeds");
            CheckEqual(
                CountMapping(
                    result,
                    BaselineMappingNetworkCollectionUnavailable),
                std::size_t(1),
                L"explicit network failure emits one collection note");
            CheckEqual(
                CountMapping(
                    result,
                    BaselineMappingServiceCollectionUnavailable),
                std::size_t(1),
                L"explicit service failure emits one collection note");
            const ObservationRecord* networkNote = FindMapping(
                result,
                BaselineMappingNetworkCollectionUnavailable);
            const ObservationRecord* serviceNote = FindMapping(
                result,
                BaselineMappingServiceCollectionUnavailable);
            Check(networkNote != nullptr &&
                    networkNote->observation.disposition ==
                        ObservationDisposition::CollectionNote &&
                    !networkNote->observation.contributesToVerdict,
                L"network failure is non-contributing CollectionNote");
            Check(serviceNote != nullptr &&
                    serviceNote->observation.domain ==
                        EvidenceDomain::CollectionQuality &&
                    !serviceNote->observation.contributesToVerdict,
                L"service failure is non-contributing CollectionQuality");
            CheckEqual(
                Triage(result).verdict,
                TriageVerdict::Informational,
                L"endpoint collection failures do not elevate baseline triage");
        }
    }

    int RunBaselineObservationTests()
    {
        failureCount = 0;
        TestBaselineSafeDefaultAndLegacyIndependence();
        TestPathAndEncodedCommandPolicy();
        TestTypedRelationshipAndSignatureFacts();
        TestTypedBaselineCorrelations();
        TestNetworkAndServiceContext();
        TestExactIndicatorPolicyAndProvenance();
        TestCollectionNotesParentContextAndPidZero();
        TestCapsAtomicFailureAndDeterminism();
        TestImportedProvenanceAndNoDeepFabrication();
        TestExplicitEndpointCollectionFailures();
        return failureCount;
    }
}
