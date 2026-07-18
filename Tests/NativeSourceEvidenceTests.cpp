#include "Core/NativeSourceEvidence.h"
#include "UI/InspectorPresentation.h"

#include "Core/ObservationRefinement.h"
#include "Core/TriageEngine.h"

#include <algorithm>
#include <chrono>
#include <iostream>
#include <string>

namespace GlassPane::Tests
{
    namespace
    {
        int failures = 0;

        void Check(bool condition, const wchar_t* message)
        {
            if (!condition)
            {
                ++failures;
                std::wcerr << L"FAIL: " << message << L'\n';
            }
        }

        Core::Observation MakeObservation(
            std::string id,
            std::string ruleId,
            Core::EvidenceDomain domain,
            Core::ObservationDisposition disposition)
        {
            Core::Observation observation;
            observation.id = std::move(id);
            observation.ruleId = std::move(ruleId);
            observation.title = "Typed evidence";
            observation.summary = "A bounded typed fact was observed.";
            observation.domain = domain;
            observation.sourceKind = Core::ObservationSourceKind::Direct;
            observation.disposition = disposition;
            observation.strength = disposition ==
                    Core::ObservationDisposition::ReviewRelevant
                ? Core::ObservationStrength::Moderate
                : Core::ObservationStrength::None;
            observation.confidence = Core::ObservationConfidence::High;
            observation.contributesToVerdict = disposition ==
                Core::ObservationDisposition::ReviewRelevant;
            observation.entityScope = "selected-process/pid:77/created:99";
            observation.groupingKey = observation.ruleId;
            observation.evidence = { "Second detail", "First detail", "First detail" };
            observation.limitations = { "Second limitation" };
            observation.provenance.sourceKind = observation.sourceKind;
            observation.provenance.sourceAvailable = true;
            observation.provenance.limitations = { "First limitation" };
            return observation;
        }

        Core::RefinedObservationMember MakeMember(
            Core::Observation observation,
            Core::RefinedObservationRole role =
                Core::RefinedObservationRole::Primary)
        {
            Core::RefinedObservationMember member;
            member.sourceRecord.observation = std::move(observation);
            member.role = role;
            return member;
        }

        Core::ObservationRefinementResult MakeRefinement()
        {
            Core::ObservationRefinementResult refinement;
            refinement.attempted = true;
            refinement.success = true;
            refinement.status = Core::ObservationRefinementStatus::Success;

            Core::Observation handle = MakeObservation(
                "internal-observation-id",
                "native.handle.external-sensitive-access",
                Core::EvidenceDomain::Handle,
                Core::ObservationDisposition::ReviewRelevant);
            handle.artifactIdentity.kind = Core::ObservationArtifactKind::Handle;
            handle.artifactIdentity.entityScope = handle.entityScope;
            handle.artifactIdentity.artifactKey = "internal-artifact-key";

            Core::RefinedObservationGroup group;
            group.entityScope = handle.entityScope;
            group.groupingKey = handle.groupingKey;
            group.semanticFamily = "internal-semantic-family";
            group.domain = handle.domain;
            group.artifactIdentity = handle.artifactIdentity;
            group.members.push_back(MakeMember(handle));
            refinement.groups.push_back(std::move(group));

            Core::Observation collection = MakeObservation(
                "internal-collection-id",
                "native.collection.token-unavailable",
                Core::EvidenceDomain::CollectionQuality,
                Core::ObservationDisposition::CollectionNote);
            collection.provenance.sourceKind =
                Core::ObservationSourceKind::Unavailable;
            collection.sourceKind = Core::ObservationSourceKind::Unavailable;
            collection.provenance.sourceAvailable = false;
            collection.limitations = { "Token collection failed." };
            Core::ObservationRecord collectionRecord;
            collectionRecord.observation = std::move(collection);
            refinement.collectionNotes.push_back(std::move(collectionRecord));

            return refinement;
        }

        Core::TriageResult MakeTriage()
        {
            Core::TriageResult triage;
            triage.attempted = true;
            triage.success = true;
            triage.status = Core::TriageEngineStatus::Success;
            triage.verdict = Core::TriageVerdict::MediumAttention;
            triage.contributingObservationIds = { "internal-observation-id" };
            return triage;
        }

        Core::NativeSourceEvidenceRecord MakeValidEvidenceRecord()
        {
            Core::NativeSourceEvidenceRecord record;
            record.stableRuleId = "native.fixture";
            record.title = "Typed fixture";
            record.summary = "A bounded typed fixture was observed.";
            record.domain = Core::EvidenceDomain::Runtime;
            record.disposition = Core::ObservationDisposition::ReviewRelevant;
            record.strength = Core::ObservationStrength::Moderate;
            record.confidence = Core::ObservationConfidence::High;
            record.artifactFamily = "Runtime Object";
            record.provenanceSummary = "Direct evidence";
            record.contributedToVerdict = true;
            return record;
        }

        void CheckContradictory(
            const Core::NativeSourceEvidenceRecord& record,
            const wchar_t* message)
        {
            const Core::NativeSourceEvidenceValidationResult validation =
                Core::ValidateNativeSourceEvidenceRecord(record);
            Check(
                !validation.valid &&
                    validation.code ==
                        Core::NativeSourceEvidenceValidationCode::ContradictoryState,
                message);
        }

        void TestProjectionIsBoundedAndIdFree()
        {
            const Core::ObservationRefinementResult refinement = MakeRefinement();
            const Core::TriageResult triage = MakeTriage();
            const Core::NativeSourceEvidenceProjectionResult projection =
                Core::ProjectNativeSourceEvidence(refinement, &triage);
            Check(projection.success, L"native source evidence projection succeeds");
            Check(projection.records.size() == 2, L"group member and collection note retained");
            Check(projection.contributingRecordCount == 1, L"contribution resolved without exposing ID");
            Check(projection.collectionLimitationCount == 1, L"collection limitation retained separately");

            std::string flattened;
            for (const Core::NativeSourceEvidenceRecord& record : projection.records)
            {
                flattened += record.stableRuleId + record.title + record.summary +
                    record.artifactFamily + record.provenanceSummary;
                for (const std::string& detail : record.details)
                {
                    flattened += detail;
                }
                for (const std::string& limitation : record.limitations)
                {
                    flattened += limitation;
                }
                Check(
                    std::is_sorted(record.details.begin(), record.details.end()),
                    L"details are canonical");
                Check(
                    std::adjacent_find(record.details.begin(), record.details.end()) ==
                        record.details.end(),
                    L"duplicate details are removed");
            }
            Check(
                flattened.find("internal-observation-id") == std::string::npos,
                L"internal observation ID is not projected");
            Check(
                flattened.find("internal-artifact-key") == std::string::npos,
                L"artifact key is not projected");
            Check(
                flattened.find("internal-semantic-family") == std::string::npos,
                L"internal grouping family is not projected");
            Check(
                flattened.find("legacy") == std::string::npos,
                L"legacy severity or adapter metadata is absent");
        }

        void TestDeterministicOrdering()
        {
            Core::ObservationRefinementResult first = MakeRefinement();
            Core::Observation secondObservation = MakeObservation(
                "second-internal-id",
                "native.command.encoded-switch",
                Core::EvidenceDomain::CommandLine,
                Core::ObservationDisposition::ReviewRelevant);
            Core::RefinedObservationGroup secondGroup;
            secondGroup.entityScope = secondObservation.entityScope;
            secondGroup.groupingKey = secondObservation.groupingKey;
            secondGroup.domain = secondObservation.domain;
            secondGroup.members.push_back(MakeMember(secondObservation));
            first.groups.push_back(secondGroup);

            Core::ObservationRefinementResult reordered = first;
            std::reverse(reordered.groups.begin(), reordered.groups.end());
            Core::TriageResult triage = MakeTriage();
            triage.contributingObservationIds.push_back("second-internal-id");
            const auto left = Core::ProjectNativeSourceEvidence(first, &triage);
            const auto right = Core::ProjectNativeSourceEvidence(reordered, &triage);
            Check(left.success && right.success, L"reordered projections succeed");
            Check(left.records.size() == right.records.size(), L"reordered projections retain same size");
            if (left.records.size() == right.records.size())
            {
                for (std::size_t index = 0; index < left.records.size(); ++index)
                {
                    Check(
                        left.records[index].stableRuleId == right.records[index].stableRuleId,
                        L"canonical record ordering is deterministic");
                }
            }
        }

        void TestProjectionWithoutTriageIsExplicit()
        {
            const auto projection =
                Core::ProjectNativeSourceEvidence(MakeRefinement(), nullptr);
            Check(projection.success, L"evidence can be projected without triage");
            Check(!projection.contributionEvaluationAvailable, L"missing contribution evaluation is explicit");
            Check(projection.contributingRecordCount == 0, L"no contribution is fabricated");
        }

        void TestInvalidInputFailsAtomically()
        {
            Core::ObservationRefinementResult invalid = MakeRefinement();
            invalid.groups.front().members.front().sourceRecord.observation.ruleId.clear();
            const auto projection =
                Core::ProjectNativeSourceEvidence(invalid, nullptr);
            Check(!projection.success, L"invalid observation fails projection");
            Check(projection.records.empty(), L"invalid projection returns no partial records");

            Core::NativeSourceEvidenceRecord record;
            record.stableRuleId = "native.fixture";
            record.title = std::string("bad-") + static_cast<char>(0xc0);
            record.domain = Core::EvidenceDomain::Runtime;
            record.artifactFamily = "Runtime Object";
            record.provenanceSummary = "Direct evidence";
            const auto validation = Core::ValidateNativeSourceEvidenceRecord(record);
            Check(
                !validation.valid &&
                    validation.code ==
                        Core::NativeSourceEvidenceValidationCode::InvalidUtf8,
                L"malformed UTF-8 is rejected");
        }

        void TestSuppressedDuplicateRemainsAuditable()
        {
            Core::ObservationRefinementResult refinement = MakeRefinement();
            Core::Observation duplicate =
                refinement.groups.front().members.front().sourceRecord.observation;
            duplicate.id = "duplicate-internal-id";
            Core::RefinedObservationMember duplicateMember = MakeMember(
                duplicate,
                Core::RefinedObservationRole::Duplicate);
            refinement.groups.front().members.push_back(std::move(duplicateMember));
            const auto projection =
                Core::ProjectNativeSourceEvidence(refinement, nullptr);
            Check(projection.success, L"duplicate projection succeeds");
            Check(projection.records.size() == 3, L"suppressed duplicate remains auditable");
            Check(projection.suppressedDuplicateCount == 1, L"duplicate role retained explicitly");
        }

        void TestSemanticContradictionsAreRejected()
        {
            Core::NativeSourceEvidenceRecord record = MakeValidEvidenceRecord();
            Check(
                Core::ValidateNativeSourceEvidenceRecord(record).valid,
                L"contributing review-relevant evidence is valid");

            record = MakeValidEvidenceRecord();
            record.disposition = Core::ObservationDisposition::CollectionNote;
            record.strength = Core::ObservationStrength::None;
            record.contributedToVerdict = false;
            CheckContradictory(
                record,
                L"CollectionNote without collection-limitation flag is rejected");

            record = MakeValidEvidenceRecord();
            record.collectionLimitation = true;
            record.contributedToVerdict = false;
            CheckContradictory(
                record,
                L"collection-limitation flag on non-CollectionNote is rejected");

            record = MakeValidEvidenceRecord();
            record.disposition = Core::ObservationDisposition::CollectionNote;
            record.strength = Core::ObservationStrength::None;
            record.collectionLimitation = true;
            CheckContradictory(
                record,
                L"collection limitation contributing to verdict is rejected");

            record = MakeValidEvidenceRecord();
            record.suppressedDuplicate = true;
            CheckContradictory(
                record,
                L"suppressed duplicate contributing to verdict is rejected");

            for (const Core::ObservationDisposition disposition : {
                    Core::ObservationDisposition::Informational,
                    Core::ObservationDisposition::Context,
                    Core::ObservationDisposition::EvidenceIntegrityNote,
                    Core::ObservationDisposition::SuppressedExpected })
            {
                record = MakeValidEvidenceRecord();
                record.disposition = disposition;
                CheckContradictory(
                    record,
                    L"non-verdict disposition contributing to verdict is rejected");
            }

            record = MakeValidEvidenceRecord();
            record.disposition = Core::ObservationDisposition::CorrelatedOnly;
            Check(
                Core::ValidateNativeSourceEvidenceRecord(record).valid,
                L"completed-correlation participant contribution is valid");

            record = MakeValidEvidenceRecord();
            record.strength = Core::ObservationStrength::None;
            CheckContradictory(
                record,
                L"strengthless review-relevant contribution is rejected");

            for (const Core::EvidenceDomain domain : {
                    Core::EvidenceDomain::CollectionQuality,
                    Core::EvidenceDomain::EvidenceIntegrity })
            {
                record = MakeValidEvidenceRecord();
                record.domain = domain;
                CheckContradictory(
                    record,
                    L"non-behavior domain contribution is rejected");
            }

            record = MakeValidEvidenceRecord();
            record.disposition = Core::ObservationDisposition::CorrelatedOnly;
            record.strength = Core::ObservationStrength::None;
            Check(
                Core::ValidateNativeSourceEvidenceRecord(record).valid,
                L"strengthless completed-correlation participant remains valid");

            record = MakeValidEvidenceRecord();
            record.disposition = Core::ObservationDisposition::CollectionNote;
            record.strength = Core::ObservationStrength::None;
            record.collectionLimitation = true;
            record.contributedToVerdict = false;
            Check(
                Core::ValidateNativeSourceEvidenceRecord(record).valid,
                L"non-contributing CollectionNote is valid");

            record = MakeValidEvidenceRecord();
            record.suppressedDuplicate = true;
            record.contributedToVerdict = false;
            Check(
                Core::ValidateNativeSourceEvidenceRecord(record).valid,
                L"non-contributing suppressed duplicate is valid");
        }

        void TestProjectionPerformanceIsBounded()
        {
            constexpr std::size_t Iterations = 1000;
            const Core::ObservationRefinementResult refinement = MakeRefinement();
            const Core::TriageResult triage = MakeTriage();
            std::size_t projectedRecordCount = 0;
            const auto started = std::chrono::steady_clock::now();
            for (std::size_t index = 0; index < Iterations; ++index)
            {
                const Core::NativeSourceEvidenceProjectionResult projection =
                    Core::ProjectNativeSourceEvidence(refinement, &triage);
                Check(projection.success, L"repeated native evidence projection succeeds");
                projectedRecordCount += projection.records.size();
            }
            const auto elapsedMicroseconds =
                std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now() - started).count();
            Check(
                projectedRecordCount == Iterations * 2,
                L"repeated native evidence projection retains bounded output");
            Check(
                elapsedMicroseconds < 30000000,
                L"native evidence projection remains within the generous performance cap");
            std::wcout << L"Native source-evidence projection fixture: " <<
                Iterations << L" projections in " << elapsedMicroseconds <<
                L" us.\n";
        }

        void TestZeroRecordPresentationPlanIsCompact()
        {
            constexpr UI::NativeSourceEvidenceSectionPlan plan =
                UI::PlanNativeSourceEvidenceSection(0);
            static_assert(plan.sectionCount == 1);
            static_assert(!plan.showFilters);
            static_assert(!plan.showRecordCards);
            static_assert(plan.showEmptyState);
            static_assert(!plan.copyEnabled);

            Check(plan.sectionCount == 1,
                L"zero native records retain one source-evidence section");
            Check(!plan.showFilters,
                L"zero native records hide source-evidence filters");
            Check(!plan.showRecordCards && plan.showEmptyState,
                L"zero native records render only the compact empty state");
            Check(!plan.copyEnabled,
                L"zero native records disable Copy Source Evidence");
        }

        void TestNonzeroRecordPresentationPlanShowsEvidenceControls()
        {
            constexpr UI::NativeSourceEvidenceSectionPlan plan =
                UI::PlanNativeSourceEvidenceSection(3);
            static_assert(plan.sectionCount == 1);
            static_assert(plan.showFilters);
            static_assert(plan.showRecordCards);
            static_assert(!plan.showEmptyState);
            static_assert(plan.copyEnabled);

            Check(plan.sectionCount == 1,
                L"nonzero native records retain one source-evidence section");
            Check(plan.showFilters && plan.showRecordCards,
                L"nonzero native records show filters and evidence cards");
            Check(!plan.showEmptyState,
                L"nonzero native records omit the zero-record empty state");
            Check(plan.copyEnabled,
                L"nonzero native records enable Copy Source Evidence");
        }
    }

    int RunNativeSourceEvidenceTests()
    {
        failures = 0;
        TestProjectionIsBoundedAndIdFree();
        TestDeterministicOrdering();
        TestProjectionWithoutTriageIsExplicit();
        TestInvalidInputFailsAtomically();
        TestSuppressedDuplicateRemainsAuditable();
        TestSemanticContradictionsAreRejected();
        TestZeroRecordPresentationPlanIsCompact();
        TestNonzeroRecordPresentationPlanShowsEvidenceControls();
        TestProjectionPerformanceIsBounded();
        if (failures == 0)
        {
            std::wcout << L"Native source evidence tests passed.\n";
        }
        return failures;
    }
}
