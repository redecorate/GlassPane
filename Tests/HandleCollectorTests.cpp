#include "Core/HandleCollector.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <vector>

namespace GlassPane::Tests
{
    namespace
    {
        using namespace Core;

        constexpr std::uint64_t MiB = 1024ULL * 1024ULL;
        constexpr std::uint64_t GiB = 1024ULL * MiB;

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
        void CheckEqual(const T& actual, const T& expected, const wchar_t* name)
        {
            Check(actual == expected, name);
        }

        HandleTableCoreEntry Entry(
            std::uint32_t pid,
            std::uint64_t value,
            std::uint16_t type,
            std::uint32_t access)
        {
            HandleTableCoreEntry entry;
            entry.owningPid = pid;
            entry.handleValue = value;
            entry.objectTypeIndex = type;
            entry.grantedAccess = access;
            return entry;
        }

        void TestAdaptiveBudgets()
        {
            CheckEqual(
                CalculateAdaptiveHandleQueryBudget(2 * GiB, 4 * GiB),
                static_cast<std::size_t>(256 * MiB),
                L"4 GiB endpoint uses conservative 256 MiB ceiling");
            CheckEqual(
                CalculateAdaptiveHandleQueryBudget(128 * MiB, 4 * GiB),
                HandleQueryMinimumBudgetBytes,
                L"low available memory retains safe minimum budget");
            CheckEqual(
                CalculateAdaptiveHandleQueryBudget(64 * GiB, 128 * GiB),
                HandleQueryMaximumBudgetBytes,
                L"large-memory endpoint is capped at emergency ceiling");
            CheckEqual(
                CalculateAdaptiveHandleQueryBudget(0, 0),
                HandleQueryMinimumBudgetBytes,
                L"unknown memory status uses conservative minimum");

            const HandleQueryGrowthDecision aboveOldCap =
                PlanHandleQueryBufferGrowth(
                    128 * MiB,
                    160 * MiB,
                    256 * MiB);
            Check(aboveOldCap.canRetry,
                L"table above old fixed limit can grow within adaptive budget");
            Check(aboveOldCap.nextBufferBytes > 128 * MiB,
                L"adaptive growth exceeds old 128 MiB boundary");

            const HandleQueryGrowthDecision ceiling =
                PlanHandleQueryBufferGrowth(
                    HandleQueryMaximumBudgetBytes,
                    HandleQueryMaximumBudgetBytes + 1,
                    HandleQueryMaximumBudgetBytes);
            Check(!ceiling.canRetry && ceiling.budgetExceeded,
                L"emergency ceiling cannot be exceeded");
        }

        void TestQueryFailureClassification()
        {
            CheckEqual(
                HandleCollectionStateForQueryFailure(
                    HandleQueryFailureKind::BudgetExceeded),
                HandleCollectionState::Unavailable,
                L"budget exhaustion is distinguishable unavailable state");
            CheckEqual(
                HandleCollectionStateForQueryFailure(
                    HandleQueryFailureKind::ApiUnavailable),
                HandleCollectionState::Unavailable,
                L"missing native API is distinguishable unavailable state");
            CheckEqual(
                HandleCollectionStateForQueryFailure(
                    HandleQueryFailureKind::AllocationFailed),
                HandleCollectionState::Failed,
                L"query allocation failure is a failed state");
            CheckEqual(
                HandleCollectionStateForQueryFailure(
                    HandleQueryFailureKind::ApiFailed),
                HandleCollectionState::Failed,
                L"native API failure is a failed state");
            CheckEqual(
                HandleCollectionStateForQueryFailure(
                    HandleQueryFailureKind::InvalidBuffer),
                HandleCollectionState::Failed,
                L"invalid native buffer is a failed state");
        }

        void TestProjectionAndZeroMatches()
        {
            const std::vector<HandleTableCoreEntry> table = {
                Entry(10, 0x10, 2, 0x00100000),
                Entry(42, 0x20, 7, 0x00000020),
                Entry(42, 0x21, 8, 0x00000008),
                Entry(99, 0x30, 3, 0x00000001)
            };
            const HandleCoreProjectionResult selected =
                ProjectSelectedHandleCoreRecords(42, table, table.size());
            Check(selected.success, L"ordinary projection succeeds");
            CheckEqual(selected.entriesScanned, table.size(),
                L"ordinary projection scans declared table once");
            CheckEqual(selected.selectedEntriesMatched, std::size_t(2),
                L"ordinary projection identifies selected PID rows");
            CheckEqual(selected.records.size(), std::size_t(2),
                L"ordinary projection retains selected PID rows");
            CheckEqual(selected.records[0].objectTypeIndex,
                static_cast<std::uint16_t>(7),
                L"compact row preserves numeric object type index");
            CheckEqual(selected.records[0].grantedAccess,
                static_cast<std::uint32_t>(0x00000020),
                L"compact row preserves raw access mask");

            const HandleCoreProjectionResult empty =
                ProjectSelectedHandleCoreRecords(77, table, table.size());
            Check(empty.success && empty.records.empty(),
                L"successful query with zero selected rows is honest empty state");

            const HandleCoreProjectionResult pidZero =
                ProjectSelectedHandleCoreRecords(
                    0,
                    { Entry(0, 0x40, 1, 0) },
                    1);
            Check(pidZero.success && pidZero.records.size() == 1,
                L"PID 0 remains a valid projection identity");
        }

        void TestPartialProjectionPreservesRows()
        {
            const std::vector<HandleTableCoreEntry> available = {
                Entry(55, 0x50, 7, 0x00000008),
                Entry(1, 0x51, 2, 0),
                Entry(55, 0x52, 7, 0x00000020)
            };
            const HandleCoreProjectionResult truncated =
                ProjectSelectedHandleCoreRecords(55, available, 8, 16);
            Check(truncated.success && truncated.queryBufferTruncated,
                L"bounded projection identifies unscanned global tail");
            CheckEqual(truncated.records.size(), std::size_t(2),
                L"global-tail limitation preserves selected rows already scanned");

            std::vector<HandleTableCoreEntry> selectedRows;
            for (std::uint64_t index = 0; index < 7; ++index)
            {
                selectedRows.push_back(Entry(55, 0x60 + index, 7, 0x20));
            }
            const HandleCoreProjectionResult capped =
                ProjectSelectedHandleCoreRecords(55, selectedRows, 7, 3);
            Check(capped.success && capped.retentionCapReached,
                L"selected-process retention cap produces partial projection");
            CheckEqual(capped.records.size(), std::size_t(3),
                L"retention cap preserves bounded prefix");
            CheckEqual(capped.selectedEntriesMatched, std::size_t(7),
                L"projection continues scanning after retention cap");
            CheckEqual(capped.selectedEntriesOmitted, std::size_t(4),
                L"retention cap reports exact selected-row omission count");

            HandleCollectionResult partial;
            partial.success = true;
            partial.state = HandleCollectionState::Partial;
            partial.handles.resize(3);
            Check(partial.HasUsableRows() && partial.IsPartial(),
                L"typed partial state keeps retained rows usable");
        }

        void TestOptionalEnrichmentBudgets()
        {
            Check(HandleOptionalEnrichmentBudgetAvailable(
                    HandleCollectionMaxNameResolutions - 1,
                    HandleCollectionMaxNameResolutions),
                L"last object-name budget slot is available");
            Check(!HandleOptionalEnrichmentBudgetAvailable(
                    HandleCollectionMaxNameResolutions,
                    HandleCollectionMaxNameResolutions),
                L"object-name resolution cap is enforced independently");
            Check(!HandleOptionalEnrichmentBudgetAvailable(
                    HandleCollectionMaxTypeResolutions,
                    HandleCollectionMaxTypeResolutions),
                L"object-type resolution cap is enforced independently");
            CheckEqual(
                HandleCollectionMaxObjectMetadataBytes,
                static_cast<std::size_t>(64 * 1024),
                L"each optional object metadata allocation is capped at 64 KiB");

            HandleCollectionResult rawPartial;
            rawPartial.success = true;
            rawPartial.state = HandleCollectionState::Partial;
            rawPartial.nameResolutionCapReached = true;
            HandleInfo row;
            row.owningPid = 55;
            row.handleValue = 0x70;
            row.objectTypeIndex = 7;
            row.objectType = L"Type 7";
            row.grantedAccessRaw = 0x20;
            rawPartial.handles.push_back(row);
            Check(rawPartial.HasUsableRows() &&
                    rawPartial.handles[0].objectName.empty() &&
                    rawPartial.handles[0].grantedAccessRaw == 0x20,
                L"optional metadata omission preserves typed raw row");
        }

        void TestProjectionPerformanceFixtures()
        {
            std::vector<HandleTableCoreEntry> ordinary;
            ordinary.reserve(200000);
            for (std::size_t index = 0; index < 200000; ++index)
            {
                const std::uint32_t pid = index % 200 == 0 ? 700 : 701;
                ordinary.push_back(Entry(
                    pid,
                    static_cast<std::uint64_t>(index),
                    static_cast<std::uint16_t>(index % 32),
                    static_cast<std::uint32_t>(index)));
            }
            const auto ordinaryStarted = std::chrono::steady_clock::now();
            const HandleCoreProjectionResult ordinaryResult =
                ProjectSelectedHandleCoreRecords(
                    700,
                    ordinary,
                    ordinary.size());
            const auto ordinaryUs =
                std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now() - ordinaryStarted).count();
            Check(ordinaryResult.success &&
                    ordinaryResult.records.size() == 1000,
                L"ordinary performance fixture retains expected rows");

            const auto constrainedStarted =
                std::chrono::steady_clock::now();
            const HandleCoreProjectionResult constrainedResult =
                ProjectSelectedHandleCoreRecords(
                    700,
                    ordinary,
                    ordinary.size() + 50000);
            const auto constrainedUs =
                std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now() - constrainedStarted).count();
            Check(constrainedResult.success &&
                    constrainedResult.queryBufferTruncated &&
                    constrainedResult.records.size() == 1000,
                L"constrained-budget fixture preserves scanned selected rows");

            std::vector<HandleTableCoreEntry> heavy;
            heavy.reserve(20000);
            for (std::size_t index = 0; index < 20000; ++index)
            {
                heavy.push_back(Entry(
                    702,
                    static_cast<std::uint64_t>(index),
                    7,
                    0x28));
            }
            const auto heavyStarted = std::chrono::steady_clock::now();
            const HandleCoreProjectionResult heavyResult =
                ProjectSelectedHandleCoreRecords(
                    702,
                    heavy,
                    heavy.size());
            const auto heavyUs =
                std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now() - heavyStarted).count();
            Check(heavyResult.success && heavyResult.retentionCapReached,
                L"handle-heavy performance fixture remains bounded");

#ifdef _DEBUG
            const wchar_t* configuration = L"Debug";
#else
            const wchar_t* configuration = L"Release";
#endif
            std::wcout << L"Handle projection performance (" << configuration
                << L"): ordinary=" << ordinaryUs
                << L" us, constrained=" << constrainedUs
                << L" us, heavy=" << heavyUs
                << L" us, compact ordinary="
                << ordinaryResult.records.size() * sizeof(HandleTableCoreEntry)
                << L" bytes, compact heavy="
                << heavyResult.records.size() * sizeof(HandleTableCoreEntry)
                << L" bytes.\n";
        }

        void TestLiveOrdinaryProcessMeasurement()
        {
            ProcessInfo process;
            process.pid = GetCurrentProcessId();
            process.name = L"GlassPane.Core.Tests.exe";
            const HandleCollectionResult result =
                CollectProcessHandles(process, nullptr);

            Check(result.queryBufferBudgetBytes >=
                    HandleQueryMinimumBudgetBytes &&
                    result.queryBufferBudgetBytes <=
                        HandleQueryMaximumBudgetBytes,
                L"live query uses bounded adaptive budget");
            if (result.success)
            {
                Check(result.queryBufferBytes <= result.queryBufferBudgetBytes,
                    L"live successful buffer remains within adaptive budget");
                Check(result.compactCoreRecordBytes ==
                        result.selectedProcessHandlesMatched *
                            sizeof(HandleTableCoreEntry) ||
                        result.retentionCapReached,
                    L"live compact projection reports bounded retained storage");
            }

#ifdef _DEBUG
            const wchar_t* configuration = L"Debug";
#else
            const wchar_t* configuration = L"Release";
#endif
            std::wcout << L"Live handle refresh (" << configuration
                << L"): state=" << static_cast<std::uint32_t>(result.state)
                << L", query-buffer=" << result.queryBufferBytes
                << L" bytes, budget=" << result.queryBufferBudgetBytes
                << L" bytes, compact=" << result.compactCoreRecordBytes
                << L" bytes, retained=" << result.handles.size()
                << L", names=" << result.namesResolved << L"/"
                << result.namesAttempted
                << L", query=" << result.queryDurationMicroseconds
                << L" us, enrichment="
                << result.enrichmentDurationMicroseconds
                << L" us, total=" << result.totalDurationMicroseconds
                << L" us.\n";
        }
    }

    int RunHandleCollectorTests(bool runLiveHandles)
    {
        failureCount = 0;
        TestAdaptiveBudgets();
        TestQueryFailureClassification();
        TestProjectionAndZeroMatches();
        TestPartialProjectionPreservesRows();
        TestOptionalEnrichmentBudgets();
        TestProjectionPerformanceFixtures();
        if (runLiveHandles)
        {
            TestLiveOrdinaryProcessMeasurement();
        }
        return failureCount;
    }
}
