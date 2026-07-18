#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace GlassPane::Core
{
    enum class HandleCollectionState : std::uint32_t
    {
        NotAttempted = 0,
        Success = 1,
        Partial = 2,
        Unavailable = 3,
        Failed = 4
    };

    enum class HandleQueryFailureKind : std::uint32_t
    {
        None = 0,
        BudgetExceeded = 1,
        AllocationFailed = 2,
        ApiUnavailable = 3,
        ApiFailed = 4,
        InvalidBuffer = 5
    };

    constexpr HandleCollectionState HandleCollectionStateForQueryFailure(
        HandleQueryFailureKind kind) noexcept
    {
        switch (kind)
        {
        case HandleQueryFailureKind::None:
            return HandleCollectionState::Success;
        case HandleQueryFailureKind::BudgetExceeded:
        case HandleQueryFailureKind::ApiUnavailable:
            return HandleCollectionState::Unavailable;
        case HandleQueryFailureKind::AllocationFailed:
        case HandleQueryFailureKind::ApiFailed:
        case HandleQueryFailureKind::InvalidBuffer:
        default:
            return HandleCollectionState::Failed;
        }
    }

    struct HandleInfo
    {
        std::uint32_t owningPid = 0;
        std::uint64_t handleValue = 0;
        std::uint16_t objectTypeIndex = 0;
        std::wstring objectType;
        std::wstring objectName;
        std::wstring grantedAccess;
        std::uint32_t grantedAccessRaw = 0;
        std::optional<std::uint32_t> targetPid;
        std::optional<std::uint32_t> targetThreadId;
        std::wstring targetProcessName;
        bool typeResolved = false;
        bool nameResolved = false;
        std::wstring errorMessage;
        std::vector<std::wstring> decodedAccess;
        std::vector<std::wstring> indicators;
    };

    struct HandleCollectionResult
    {
        std::uint32_t pid = 0;
        HandleCollectionState state = HandleCollectionState::NotAttempted;
        HandleQueryFailureKind queryFailureKind = HandleQueryFailureKind::None;
        // Retained for schema-1 through schema-5 compatibility. Success and
        // Partial both set this flag because their retained core rows are usable.
        bool success = false;
        std::wstring statusMessage;
        std::size_t systemHandleCount = 0;
        std::size_t systemEntriesScanned = 0;
        std::size_t selectedProcessHandlesMatched = 0;
        std::size_t selectedProcessHandlesOmitted = 0;
        std::size_t namesAttempted = 0;
        std::size_t namesResolved = 0;
        std::size_t namesSkipped = 0;
        std::size_t namesFailed = 0;
        std::size_t typeResolutionsAttempted = 0;
        std::size_t typeResolutionsResolved = 0;
        std::size_t typeResolutionsSkipped = 0;
        std::size_t typeResolutionsFailed = 0;
        std::size_t targetsResolved = 0;
        std::size_t targetsUnresolved = 0;
        std::size_t queryAttemptCount = 0;
        std::size_t queryBufferBudgetBytes = 0;
        std::size_t queryBufferBytes = 0;
        std::size_t compactCoreRecordBytes = 0;
        bool queryBufferTruncated = false;
        bool retentionCapReached = false;
        bool nameResolutionCapReached = false;
        bool typeResolutionCapReached = false;
        bool typeOrTargetResolutionPartial = false;
        std::uint64_t queryDurationMicroseconds = 0;
        std::uint64_t enrichmentDurationMicroseconds = 0;
        std::uint64_t totalDurationMicroseconds = 0;
        std::vector<HandleInfo> handles;

        bool IsPartial() const noexcept
        {
            return state == HandleCollectionState::Partial;
        }

        bool HasUsableRows() const noexcept
        {
            return success &&
                (state == HandleCollectionState::Success ||
                    state == HandleCollectionState::Partial);
        }
    };
}
