#include "Core/PersistedTriage.h"

#include <cstdint>
#include <iostream>
#include <optional>
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

        TriageResult MakeTriage(
            TriageVerdict verdict = TriageVerdict::Informational)
        {
            TriageResult result;
            result.attempted = true;
            result.success = true;
            result.status = TriageEngineStatus::Success;
            result.verdict = verdict;
            result.statusMessage = "Deterministic triage result.";
            result.previewRationaleEntries = {
                { TriageRationaleSection::VerdictBasis,
                    "A typed verdict basis was recorded." },
                { TriageRationaleSection::CompletedCorrelations,
                    "A typed correlation was completed." },
                { TriageRationaleSection::SupportingContext,
                    "Supporting context was observed." },
                { TriageRationaleSection::CollectionLimitations,
                    "A collection limitation was recorded." },
                { TriageRationaleSection::EvidenceIntegrityContext,
                    "Evidence-integrity context was recorded." },
                { TriageRationaleSection::UnresolvedCorrelations,
                    "A typed correlation remains unresolved." },
                { TriageRationaleSection::PresentationNotes,
                    "Runtime presentation was bounded." }
            };
            return result;
        }

        PersistedTriageSummary MakeBaselineSummary(
            TriageVerdict verdict = TriageVerdict::Informational)
        {
            const PersistedTriageProjectionResult projection =
                ProjectPersistedTriageSummary(
                    MakeTriage(verdict),
                    PersistedTriageAnalysisLevel::Baseline,
                    3);
            Check(projection.success, L"baseline summary fixture projects");
            return projection.summary;
        }

        PersistedTriageSummary MakeHistoricalLegacyFallbackSummary(
            TriageVerdict legacyVerdict,
            std::size_t sourceEvidenceCount,
            std::string fallbackReason,
            std::string status = {})
        {
            PersistedTriageSummary summary;
            summary.captured = true;
            summary.evaluationSucceeded = false;
            summary.usingFallback = true;
            summary.analysisLevel =
                PersistedTriageAnalysisLevel::LegacyFallback;
            summary.authoritativeVerdict = legacyVerdict;
            summary.triageModelVersion = PersistedTriageModelVersion;
            summary.sourceEvidenceCount = sourceEvidenceCount;
            summary.fallbackReason = std::move(fallbackReason);
            summary.status = std::move(status);
            return summary;
        }

        PersistedProcessTriageRecord MakeRecord(
            std::uint32_t pid,
            std::uint64_t creationTime,
            TriageVerdict verdict = TriageVerdict::Informational,
            bool hasCreationTime = true)
        {
            PersistedProcessTriageRecord record;
            record.identity.pid = pid;
            record.identity.hasCreationTime = hasCreationTime;
            record.identity.creationTimeFileTime = hasCreationTime
                ? creationTime
                : 0;
            record.summary = MakeBaselineSummary(verdict);
            return record;
        }

        void TestModelAndDisplayHelpers()
        {
            CheckEqual(PersistedTriageModelVersion, std::uint32_t(1),
                L"persisted triage model version is stable");
            CheckEqual(PersistedTriageMaxProcessRecords, std::size_t(4096),
                L"process record cap reuses process snapshot/cache cap");
            CheckEqual(PersistedTriageMaxContributingDomains, std::size_t(16),
                L"domain cap is explicit");
            CheckEqual(PersistedTriageMaxVerdictBasisItems, std::size_t(32),
                L"basis cap is explicit");
            CheckEqual(PersistedTriageMaxCompletedCorrelationItems, std::size_t(32),
                L"correlation presentation cap is explicit");
            CheckEqual(PersistedTriageMaxSupportingContextItems, std::size_t(64),
                L"context cap is explicit");
            CheckEqual(PersistedTriageMaxCollectionLimitationItems, std::size_t(32),
                L"collection cap is explicit");
            CheckEqual(PersistedTriageMaxEvidenceIntegrityItems, std::size_t(32),
                L"integrity cap is explicit");
            CheckEqual(PersistedTriageMaxUnresolvedCorrelationItems, std::size_t(32),
                L"unresolved cap is explicit");
            CheckEqual(PersistedTriageLineMaxUtf8Bytes, std::size_t(1024),
                L"line byte cap is explicit");
            CheckEqual(PersistedTriageFallbackReasonMaxUtf8Bytes, std::size_t(512),
                L"fallback byte cap is explicit");
            CheckEqual(PersistedTriageStatusMaxUtf8Bytes, std::size_t(512),
                L"status byte cap is explicit");

            CheckEqual(
                PersistedTriageAnalysisLevelDisplayText(
                    PersistedTriageAnalysisLevel::NotCaptured),
                std::string("Not captured"),
                L"not-captured display text");
            CheckEqual(
                PersistedTriageAnalysisLevelDisplayText(
                    PersistedTriageAnalysisLevel::Baseline),
                std::string("Baseline"),
                L"baseline display text");
            CheckEqual(
                PersistedTriageAnalysisLevelDisplayText(
                    PersistedTriageAnalysisLevel::Enriched),
                std::string("Enriched"),
                L"enriched display text");
            CheckEqual(
                PersistedTriageAnalysisLevelDisplayText(
                    PersistedTriageAnalysisLevel::LegacyFallback),
                std::string("Legacy fallback"),
                L"legacy fallback display text");
            Check(
                PersistedTriageAnalysisLevelDisplayText(
                    static_cast<PersistedTriageAnalysisLevel>(99)).find(
                        "Unknown") != std::string::npos,
                L"unknown analysis level stays visible");
            Check(!IsKnownPersistedTriageAnalysisLevel(
                static_cast<PersistedTriageAnalysisLevel>(99)),
                L"unknown analysis level rejected");
            CheckEqual(
                PersistedTriageValidationCodeDisplayText(
                    PersistedTriageValidationCode::InvalidUtf8),
                std::string("Invalid UTF-8"),
                L"validation display helper");
        }

        void TestNotCapturedAndStateInvariants()
        {
            const PersistedTriageSummary notCaptured =
                MakeNotCapturedPersistedTriageSummary();
            Check(ValidatePersistedTriageSummary(notCaptured).valid,
                L"empty not-captured summary valid");
            CheckEqual(notCaptured.triageModelVersion, std::uint32_t(0),
                L"not-captured model version is zero");

            PersistedTriageSummary invalid = notCaptured;
            invalid.status = "Fabricated status";
            CheckEqual(
                ValidatePersistedTriageSummary(invalid).code,
                PersistedTriageValidationCode::ContradictoryState,
                L"not-captured summary contains no content");

            invalid = MakeBaselineSummary();
            invalid.evaluationSucceeded = false;
            CheckEqual(
                ValidatePersistedTriageSummary(invalid).code,
                PersistedTriageValidationCode::ContradictoryState,
                L"baseline requires successful evaluation");

            invalid = MakeBaselineSummary();
            invalid.usingFallback = true;
            CheckEqual(
                ValidatePersistedTriageSummary(invalid).code,
                PersistedTriageValidationCode::ContradictoryState,
                L"successful evaluation cannot use fallback");

            invalid = MakeBaselineSummary();
            invalid.baselineVerdictAvailable = false;
            CheckEqual(
                ValidatePersistedTriageSummary(invalid).code,
                PersistedTriageValidationCode::ContradictoryState,
                L"baseline authority requires a captured baseline verdict");

            invalid = MakeBaselineSummary();
            invalid.analysisLevel = PersistedTriageAnalysisLevel::NotCaptured;
            CheckEqual(
                ValidatePersistedTriageSummary(invalid).code,
                PersistedTriageValidationCode::ContradictoryState,
                L"captured summary cannot be NotCaptured");

            invalid = MakeBaselineSummary();
            invalid.triageModelVersion = 2;
            CheckEqual(
                ValidatePersistedTriageSummary(invalid).code,
                PersistedTriageValidationCode::UnsupportedModelVersion,
                L"unknown triage model rejected");

            invalid = MakeBaselineSummary();
            invalid.authoritativeVerdict = static_cast<TriageVerdict>(99);
            CheckEqual(
                ValidatePersistedTriageSummary(invalid).code,
                PersistedTriageValidationCode::UnknownVerdict,
                L"unknown verdict rejected");

            invalid = MakeBaselineSummary();
            invalid.analysisLevel =
                static_cast<PersistedTriageAnalysisLevel>(99);
            CheckEqual(
                ValidatePersistedTriageSummary(invalid).code,
                PersistedTriageValidationCode::UnknownAnalysisLevel,
                L"unknown persisted level rejected");
        }

        void TestProjectionAndSections()
        {
            TriageResult baseline = MakeTriage(TriageVerdict::LowAttention);
            baseline.contributingDomains = {
                EvidenceDomain::FilePath,
                EvidenceDomain::CommandLine
            };
            baseline.contributingObservationIds = { "internal-observation-id" };
            baseline.contributingCorrelationIds = { "internal-correlation-id" };
            baseline.rationaleEntries = {
                { TriageRationaleSection::VerdictBasis,
                    "deep-only internal-observation-id" }
            };

            const PersistedTriageProjectionResult projected =
                ProjectPersistedTriageSummary(
                    baseline,
                    PersistedTriageAnalysisLevel::Baseline,
                    7);
            Check(projected.success, L"baseline projection succeeds");
            Check(projected.validation.valid, L"baseline projection validates");
            Check(projected.summary.captured, L"projected baseline captured");
            Check(projected.summary.evaluationSucceeded,
                L"projected baseline succeeds");
            Check(!projected.summary.usingFallback,
                L"projected baseline not fallback");
            Check(projected.summary.baselineVerdictAvailable,
                L"baseline verdict available");
            CheckEqual(projected.summary.authoritativeVerdict,
                TriageVerdict::LowAttention,
                L"authoritative verdict projected");
            CheckEqual(projected.summary.baselineVerdict,
                TriageVerdict::LowAttention,
                L"baseline verdict projected");
            CheckEqual(projected.summary.sourceEvidenceCount, std::size_t(7),
                L"source evidence count projected");
            CheckEqual(projected.summary.verdictBasis.size(), std::size_t(1),
                L"basis section projected");
            CheckEqual(projected.summary.completedCorrelations.size(),
                std::size_t(1), L"correlation summary projected");
            CheckEqual(projected.summary.supportingContext.size(),
                std::size_t(1), L"context section projected");
            CheckEqual(projected.summary.collectionLimitations.size(),
                std::size_t(1), L"collection section projected");
            CheckEqual(projected.summary.evidenceIntegrityContext.size(),
                std::size_t(1), L"integrity section projected");
            CheckEqual(projected.summary.unresolvedCorrelations.size(),
                std::size_t(1), L"unresolved section projected");
            Check(projected.summary.verdictBasis[0].find("internal-") ==
                std::string::npos,
                L"projection uses ID-free preview rationale only");
            Check(projected.summary.completedCorrelations[0].find("internal-") ==
                std::string::npos,
                L"completed correlations persist presentation lines not IDs");

            TriageResult enriched = MakeTriage(TriageVerdict::MediumAttention);
            const PersistedTriageProjectionResult enrichedProjection =
                ProjectPersistedTriageSummary(
                    enriched,
                    PersistedTriageAnalysisLevel::Enriched,
                    9,
                    &baseline);
            Check(enrichedProjection.success, L"enriched projection succeeds");
            CheckEqual(enrichedProjection.summary.baselineVerdict,
                TriageVerdict::LowAttention,
                L"enriched projection retains baseline verdict");
            Check(enrichedProjection.summary.enrichedChangedVerdict,
                L"enriched change derived from exact verdicts");

            const PersistedTriageProjectionResult noBaseline =
                ProjectPersistedTriageSummary(
                    enriched,
                    PersistedTriageAnalysisLevel::Enriched,
                    9);
            Check(!noBaseline.success,
                L"enriched projection without baseline rejected");

            TriageResult failed = enriched;
            failed.success = false;
            Check(!ProjectPersistedTriageSummary(
                failed,
                PersistedTriageAnalysisLevel::Baseline,
                1).success,
                L"failed TriageResult cannot project as success");

            TriageResult unknownSection = MakeTriage();
            unknownSection.previewRationaleEntries.push_back({
                static_cast<TriageRationaleSection>(99),
                "Unknown presentation section"
            });
            Check(!ProjectPersistedTriageSummary(
                unknownSection,
                PersistedTriageAnalysisLevel::Baseline,
                1).success,
                L"unknown source rationale section is not silently discarded");
        }

        void TestHistoricalFallbackValidation()
        {
            const PersistedTriageSummary fallback =
                MakeHistoricalLegacyFallbackSummary(
                    TriageVerdict::HighAttention,
                    8,
                    "Baseline evaluation was unavailable.",
                    "Legacy authority retained at capture time.");
            Check(ValidatePersistedTriageSummary(fallback).valid,
                L"schema-4 historical fallback remains valid");
            Check(fallback.captured, L"fallback capture retained");
            Check(!fallback.evaluationSucceeded,
                L"fallback not marked engine success");
            Check(fallback.usingFallback,
                L"fallback flag retained");
            CheckEqual(fallback.analysisLevel,
                PersistedTriageAnalysisLevel::LegacyFallback,
                L"fallback level retained");
            CheckEqual(fallback.authoritativeVerdict,
                TriageVerdict::HighAttention,
                L"legacy authoritative verdict retained");
            Check(fallback.verdictBasis.empty(),
                L"fallback does not fabricate engine rationale");

            PersistedTriageSummary missingReason =
                MakeHistoricalLegacyFallbackSummary(
                    TriageVerdict::LowAttention,
                    1,
                    "   ");
            Check(!ValidatePersistedTriageSummary(missingReason).valid,
                L"fallback reason is mandatory");

            PersistedTriageSummary invalid = fallback;
            invalid.evaluationSucceeded = true;
            CheckEqual(
                ValidatePersistedTriageSummary(invalid).code,
                PersistedTriageValidationCode::ContradictoryState,
                L"fallback success contradiction rejected");

            invalid = fallback;
            invalid.usingFallback = false;
            CheckEqual(
                ValidatePersistedTriageSummary(invalid).code,
                PersistedTriageValidationCode::ContradictoryState,
                L"LegacyFallback requires usingFallback");

            invalid = fallback;
            invalid.verdictBasis.push_back("Fabricated engine basis");
            CheckEqual(
                ValidatePersistedTriageSummary(invalid).code,
                PersistedTriageValidationCode::ContradictoryState,
                L"fallback cannot contain successful engine rationale");
        }

        void TestUtf8AndCaps()
        {
            const auto checkStringArrayCap = [](
                std::vector<std::string> PersistedTriageSummary::* field,
                std::size_t cap,
                const wchar_t* exactName,
                const wchar_t* overName)
            {
                PersistedTriageSummary bounded = MakeBaselineSummary();
                (bounded.*field).assign(cap, "bounded line");
                Check(ValidatePersistedTriageSummary(bounded).valid, exactName);
                (bounded.*field).push_back("over cap");
                CheckEqual(
                    ValidatePersistedTriageSummary(bounded).code,
                    PersistedTriageValidationCode::CollectionLimitExceeded,
                    overName);
            };

            PersistedTriageSummary summary = MakeBaselineSummary();
            summary.verdictBasis = {
                std::string(PersistedTriageLineMaxUtf8Bytes - 3, 'a') +
                    "\xE2\x82\xAC"
            };
            Check(ValidatePersistedTriageSummary(summary).valid,
                L"maximum UTF-8 byte line validates at code-point boundary");

            summary.verdictBasis[0].push_back('x');
            CheckEqual(
                ValidatePersistedTriageSummary(summary).code,
                PersistedTriageValidationCode::StringLimitExceeded,
                L"line byte cap enforced");

            summary = MakeBaselineSummary();
            summary.verdictBasis = { std::string("\xC0\xAF", 2) };
            CheckEqual(
                ValidatePersistedTriageSummary(summary).code,
                PersistedTriageValidationCode::InvalidUtf8,
                L"overlong UTF-8 rejected");

            summary.verdictBasis = { std::string("\xED\xA0\x80", 3) };
            CheckEqual(
                ValidatePersistedTriageSummary(summary).code,
                PersistedTriageValidationCode::InvalidUtf8,
                L"UTF-8 surrogate rejected");

            summary.verdictBasis = { std::string("\xF0\x9F\x92", 3) };
            CheckEqual(
                ValidatePersistedTriageSummary(summary).code,
                PersistedTriageValidationCode::InvalidUtf8,
                L"truncated UTF-8 rejected");

            summary = MakeBaselineSummary();
            summary.verdictBasis.assign(
                PersistedTriageMaxVerdictBasisItems + 1,
                "Bounded basis");
            CheckEqual(
                ValidatePersistedTriageSummary(summary).code,
                PersistedTriageValidationCode::CollectionLimitExceeded,
                L"basis item cap enforced");

            checkStringArrayCap(
                &PersistedTriageSummary::verdictBasis,
                PersistedTriageMaxVerdictBasisItems,
                L"basis exact item cap accepted",
                L"basis cap plus one rejected");
            checkStringArrayCap(
                &PersistedTriageSummary::completedCorrelations,
                PersistedTriageMaxCompletedCorrelationItems,
                L"correlation exact item cap accepted",
                L"correlation cap plus one rejected");
            checkStringArrayCap(
                &PersistedTriageSummary::supportingContext,
                PersistedTriageMaxSupportingContextItems,
                L"context exact item cap accepted",
                L"context cap plus one rejected");
            checkStringArrayCap(
                &PersistedTriageSummary::collectionLimitations,
                PersistedTriageMaxCollectionLimitationItems,
                L"collection exact item cap accepted",
                L"collection cap plus one rejected");
            checkStringArrayCap(
                &PersistedTriageSummary::evidenceIntegrityContext,
                PersistedTriageMaxEvidenceIntegrityItems,
                L"integrity exact item cap accepted",
                L"integrity cap plus one rejected");
            checkStringArrayCap(
                &PersistedTriageSummary::unresolvedCorrelations,
                PersistedTriageMaxUnresolvedCorrelationItems,
                L"unresolved exact item cap accepted",
                L"unresolved cap plus one rejected");

            summary = MakeBaselineSummary();
            summary.sourceEvidenceCount =
                PersistedTriageMaxSourceEvidenceCount + 1;
            CheckEqual(
                ValidatePersistedTriageSummary(summary).code,
                PersistedTriageValidationCode::SourceEvidenceLimitExceeded,
                L"source-evidence cap enforced");
            summary.sourceEvidenceCount = PersistedTriageMaxSourceEvidenceCount;
            Check(
                ValidatePersistedTriageSummary(summary).valid,
                L"source-evidence exact cap accepted");

            summary = MakeBaselineSummary();
            summary.status.assign(PersistedTriageStatusMaxUtf8Bytes, 's');
            Check(
                ValidatePersistedTriageSummary(summary).valid,
                L"status exact UTF-8 byte cap accepted");
            summary.status.push_back('x');
            CheckEqual(
                ValidatePersistedTriageSummary(summary).code,
                PersistedTriageValidationCode::StringLimitExceeded,
                L"status UTF-8 cap plus one rejected");

            PersistedTriageSummary fallbackAtCap =
                MakeHistoricalLegacyFallbackSummary(
                    TriageVerdict::LowAttention,
                    1,
                    std::string(
                        PersistedTriageFallbackReasonMaxUtf8Bytes,
                        'f'));
            Check(
                ValidatePersistedTriageSummary(fallbackAtCap).valid,
                L"fallback exact UTF-8 byte cap accepted");
            fallbackAtCap.fallbackReason.push_back('x');
            CheckEqual(
                ValidatePersistedTriageSummary(fallbackAtCap).code,
                PersistedTriageValidationCode::StringLimitExceeded,
                L"fallback UTF-8 cap plus one rejected");

            PersistedTriageSummary unicodeAtCap =
                MakeHistoricalLegacyFallbackSummary(
                    TriageVerdict::LowAttention,
                    1,
                    std::string(
                        PersistedTriageFallbackReasonMaxUtf8Bytes - 3,
                        'x') +
                    "\xE2\x82\xAC");
            Check(ValidatePersistedTriageSummary(unicodeAtCap).valid,
                L"historical fallback accepts valid UTF-8 at byte cap");

            const std::string oversizedUnicodeReason =
                std::string(PersistedTriageFallbackReasonMaxUtf8Bytes - 2, 'x') +
                "\xE2\x82\xAC";
            PersistedTriageSummary oversizedUnicode =
                MakeHistoricalLegacyFallbackSummary(
                    TriageVerdict::LowAttention,
                    1,
                    oversizedUnicodeReason);
            CheckEqual(
                ValidatePersistedTriageSummary(oversizedUnicode).code,
                PersistedTriageValidationCode::StringLimitExceeded,
                L"historical fallback rejects UTF-8 beyond byte cap");
        }

        void TestDomainValidation()
        {
            PersistedTriageSummary summary = MakeBaselineSummary();
            summary.contributingDomains = {
                EvidenceDomain::FilePath,
                EvidenceDomain::FileSignature
            };
            Check(ValidatePersistedTriageSummary(summary).valid,
                L"canonical contributing domains valid");

            summary.contributingDomains = {
                EvidenceDomain::FileSignature,
                EvidenceDomain::FilePath
            };
            CheckEqual(
                ValidatePersistedTriageSummary(summary).code,
                PersistedTriageValidationCode::NonCanonicalOrder,
                L"domain order validated");

            summary.contributingDomains = {
                EvidenceDomain::FilePath,
                EvidenceDomain::FilePath
            };
            CheckEqual(
                ValidatePersistedTriageSummary(summary).code,
                PersistedTriageValidationCode::NonCanonicalOrder,
                L"duplicate domains rejected");

            summary.contributingDomains = {
                static_cast<EvidenceDomain>(99)
            };
            CheckEqual(
                ValidatePersistedTriageSummary(summary).code,
                PersistedTriageValidationCode::UnknownEvidenceDomain,
                L"unknown contributing domain rejected");

            summary.contributingDomains = { EvidenceDomain::CollectionQuality };
            CheckEqual(
                ValidatePersistedTriageSummary(summary).code,
                PersistedTriageValidationCode::ContradictoryState,
                L"collection quality cannot be persisted as contributing");
        }

        void TestContextOrderingIdentityAndLookup()
        {
            PersistedProcessTriageRecord pidZero = MakeRecord(0, 0, TriageVerdict::Informational, false);
            PersistedProcessTriageRecord first = MakeRecord(42, 100, TriageVerdict::LowAttention);
            PersistedProcessTriageRecord reused = MakeRecord(42, 200, TriageVerdict::MediumAttention);

            PersistedTriageContext context = MakePersistedTriageContext(
                { reused, pidZero, first },
                reused);
            Check(ValidatePersistedTriageContext(context).valid,
                L"canonical context with PID zero and reused PID validates");
            CheckEqual(context.processRecords[0].identity.pid, std::uint32_t(0),
                L"context builder sorts PID zero first");
            CheckEqual(context.processRecords[1].identity.creationTimeFileTime,
                std::uint64_t(100), L"context builder sorts exact identity");
            const PersistedProcessTriageRecord* found =
                context.FindProcess(reused.identity);
            Check(found != nullptr, L"deterministic exact identity lookup succeeds");
            CheckEqual(found->summary.authoritativeVerdict,
                TriageVerdict::MediumAttention,
                L"PID reuse lookup selects matching creation identity");
            ProcessIdentityKey pidOnly = reused.identity;
            pidOnly.hasCreationTime = false;
            pidOnly.creationTimeFileTime = 0;
            Check(context.FindProcess(pidOnly) == nullptr,
                L"PID-only identity cannot match timestamped row");

            PersistedTriageContext unsorted;
            unsorted.processRecords = { reused, first };
            CheckEqual(
                ValidatePersistedTriageContext(unsorted).code,
                PersistedTriageValidationCode::NonCanonicalOrder,
                L"unsorted context rejected");

            PersistedTriageContext duplicate = MakePersistedTriageContext(
                { first, first });
            CheckEqual(
                ValidatePersistedTriageContext(duplicate).code,
                PersistedTriageValidationCode::DuplicateProcessIdentity,
                L"duplicate exact process identity rejected");

            PersistedTriageContext selectedMissing =
                MakePersistedTriageContext({ first }, reused);
            CheckEqual(
                ValidatePersistedTriageContext(selectedMissing).code,
                PersistedTriageValidationCode::SelectedProcessMissing,
                L"selected record must match a process row");

            PersistedProcessTriageRecord invalidIdentity = first;
            invalidIdentity.identity.hasCreationTime = false;
            invalidIdentity.identity.creationTimeFileTime = 123;
            CheckEqual(
                ValidatePersistedProcessTriageRecord(invalidIdentity).code,
                PersistedTriageValidationCode::InvalidProcessIdentity,
                L"unavailable creation identity canonicalized strictly");

            context.modelVersion = 2;
            CheckEqual(
                ValidatePersistedTriageContext(context).code,
                PersistedTriageValidationCode::UnsupportedModelVersion,
                L"container model version validated independently");
        }

        void TestContextCapsAndValueOwnership()
        {
            std::vector<PersistedProcessTriageRecord> records;
            records.reserve(PersistedTriageMaxProcessRecords + 1);
            for (std::size_t index = 0;
                index <= PersistedTriageMaxProcessRecords;
                ++index)
            {
                records.push_back(MakeRecord(
                    static_cast<std::uint32_t>(index),
                    static_cast<std::uint64_t>(index + 1)));
            }
            PersistedTriageContext overCap =
                MakePersistedTriageContext(std::move(records));
            CheckEqual(
                ValidatePersistedTriageContext(overCap).code,
                PersistedTriageValidationCode::CollectionLimitExceeded,
                L"process record cap enforced");
            overCap.processRecords.pop_back();
            Check(
                ValidatePersistedTriageContext(overCap).valid,
                L"process record cap accepts the exact bound");

            PersistedTriageContext original = MakePersistedTriageContext({
                MakeRecord(300, 400, TriageVerdict::MediumAttention)
            });
            PersistedTriageContext copied = original;
            copied.processRecords[0].summary.verdictBasis[0] = "Changed copy";
            Check(original.processRecords[0].summary.verdictBasis[0] !=
                copied.processRecords[0].summary.verdictBasis[0],
                L"persisted contract is value-owned and safely copied");
        }
    }

    int RunPersistedTriageTests()
    {
        failureCount = 0;
        TestModelAndDisplayHelpers();
        TestNotCapturedAndStateInvariants();
        TestProjectionAndSections();
        TestHistoricalFallbackValidation();
        TestUtf8AndCaps();
        TestDomainValidation();
        TestContextOrderingIdentityAndLookup();
        TestContextCapsAndValueOwnership();
        return failureCount;
    }
}
