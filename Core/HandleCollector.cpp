#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "HandleCollector.h"

#include <Windows.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cwctype>
#include <iomanip>
#include <limits>
#include <new>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace GlassPane::Core
{
    namespace
    {
        using NtQuerySystemInformationFn = LONG(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
        using NtQueryObjectFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

        constexpr ULONG SystemExtendedHandleInformation = 64;
        constexpr ULONG ObjectNameInformation = 1;
        constexpr ULONG ObjectTypeInformation = 2;
        constexpr LONG StatusInfoLengthMismatch = static_cast<LONG>(0xC0000004);
        constexpr LONG StatusBufferOverflow = static_cast<LONG>(0x80000005);
        constexpr LONG StatusBufferTooSmall = static_cast<LONG>(0xC0000023);

        struct NtApis
        {
            NtQuerySystemInformationFn querySystemInformation = nullptr;
            NtQueryObjectFn queryObject = nullptr;
        };

        enum class SystemHandleQueryStatus
        {
            Success,
            BudgetExceeded,
            AllocationFailed,
            ApiFailed
        };

        struct SystemHandleQueryResult
        {
            SystemHandleQueryStatus status = SystemHandleQueryStatus::ApiFailed;
            std::vector<unsigned char> buffer;
            std::size_t attemptCount = 0;
            std::size_t bufferBytes = 0;
            std::wstring diagnostic;
        };

        struct LocalUnicodeString
        {
            USHORT Length = 0;
            USHORT MaximumLength = 0;
            PWSTR Buffer = nullptr;
        };

        struct SystemHandleTableEntryInfoEx
        {
            PVOID Object = nullptr;
            ULONG_PTR UniqueProcessId = 0;
            ULONG_PTR HandleValue = 0;
            ULONG GrantedAccess = 0;
            USHORT CreatorBackTraceIndex = 0;
            USHORT ObjectTypeIndex = 0;
            ULONG HandleAttributes = 0;
            ULONG Reserved = 0;
        };

        struct SystemHandleInformationEx
        {
            ULONG_PTR NumberOfHandles = 0;
            ULONG_PTR Reserved = 0;
            SystemHandleTableEntryInfoEx Handles[1];
        };

        struct ObjectNameInformationLocal
        {
            LocalUnicodeString Name;
        };

        struct ObjectTypeInformationLocal
        {
            LocalUnicodeString TypeName;
        };

        bool NtSuccess(LONG status)
        {
            return status >= 0;
        }

        std::wstring ToLower(std::wstring value)
        {
            std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) {
                return static_cast<wchar_t>(std::towlower(ch));
            });
            return value;
        }

        bool EqualsIgnoreCase(const std::wstring& left, const std::wstring& right)
        {
            return ToLower(left) == ToLower(right);
        }

        std::wstring WindowsErrorMessage(DWORD error)
        {
            wchar_t* buffer = nullptr;
            const DWORD length = FormatMessageW(
                FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                nullptr,
                error,
                0,
                reinterpret_cast<LPWSTR>(&buffer),
                0,
                nullptr);

            if (length == 0 || buffer == nullptr)
            {
                return L"Windows error " + std::to_wstring(error);
            }

            std::wstring message(buffer, length);
            LocalFree(buffer);
            while (!message.empty() && (message.back() == L'\r' || message.back() == L'\n' || message.back() == L'.'))
            {
                message.pop_back();
            }
            return message;
        }

        std::wstring NtStatusText(LONG status)
        {
            std::wstringstream stream;
            stream << L"NTSTATUS 0x" << std::uppercase << std::hex << std::setw(8) << std::setfill(L'0')
                   << static_cast<std::uint32_t>(status);
            return stream.str();
        }

        std::wstring HexAccess(std::uint32_t access)
        {
            std::wstringstream stream;
            stream << L"0x" << std::uppercase << std::hex << std::setw(8) << std::setfill(L'0') << access;
            return stream.str();
        }

        NtApis LoadNtApis(std::wstring& errorMessage)
        {
            NtApis apis;
            HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
            if (ntdll == nullptr)
            {
                ntdll = LoadLibraryW(L"ntdll.dll");
            }

            if (ntdll == nullptr)
            {
                errorMessage = L"Could not load ntdll.dll: " + WindowsErrorMessage(GetLastError());
                return apis;
            }

            apis.querySystemInformation =
                reinterpret_cast<NtQuerySystemInformationFn>(GetProcAddress(ntdll, "NtQuerySystemInformation"));
            apis.queryObject =
                reinterpret_cast<NtQueryObjectFn>(GetProcAddress(ntdll, "NtQueryObject"));

            if (apis.querySystemInformation == nullptr)
            {
                errorMessage = L"NtQuerySystemInformation was not available.";
                apis = {};
            }

            return apis;
        }

        SystemHandleQueryResult QuerySystemHandleBuffer(
            const NtApis& apis,
            std::size_t budgetBytes)
        {
            SystemHandleQueryResult result;
            std::size_t bufferLength = (std::min)(
                HandleQueryInitialBufferBytes,
                budgetBytes);

            while (bufferLength != 0 &&
                bufferLength <= static_cast<std::size_t>(
                    (std::numeric_limits<ULONG>::max)()))
            {
                ++result.attemptCount;
                result.bufferBytes = bufferLength;
                std::vector<unsigned char> buffer;
                try
                {
                    buffer.resize(bufferLength);
                }
                catch (const std::bad_alloc&)
                {
                    result.status = SystemHandleQueryStatus::AllocationFailed;
                    result.diagnostic =
                        L"Could not allocate the temporary system handle query buffer.";
                    return result;
                }
                catch (const std::length_error&)
                {
                    result.status = SystemHandleQueryStatus::AllocationFailed;
                    result.diagnostic =
                        L"The requested system handle query buffer was not representable.";
                    return result;
                }

                ULONG returnLength = 0;
                const LONG status = apis.querySystemInformation(
                    SystemExtendedHandleInformation,
                    buffer.data(),
                    static_cast<ULONG>(bufferLength),
                    &returnLength);

                if (NtSuccess(status))
                {
                    result.status = SystemHandleQueryStatus::Success;
                    result.bufferBytes = buffer.size();
                    result.buffer = std::move(buffer);
                    return result;
                }

                if (status == StatusInfoLengthMismatch ||
                    status == StatusBufferOverflow ||
                    status == StatusBufferTooSmall ||
                    returnLength > bufferLength)
                {
                    const HandleQueryGrowthDecision growth =
                        PlanHandleQueryBufferGrowth(
                            bufferLength,
                            returnLength,
                            budgetBytes);
                    if (!growth.canRetry)
                    {
                        result.status = SystemHandleQueryStatus::BudgetExceeded;
                        result.diagnostic =
                            L"System handle table exceeded the adaptive temporary query budget.";
                        return result;
                    }
                    bufferLength = growth.nextBufferBytes;
                    continue;
                }

                result.status = SystemHandleQueryStatus::ApiFailed;
                result.diagnostic =
                    L"NtQuerySystemInformation(SystemExtendedHandleInformation) failed: " +
                    NtStatusText(status);
                return result;
            }

            result.status = SystemHandleQueryStatus::BudgetExceeded;
            result.diagnostic =
                L"System handle table exceeded the adaptive temporary query budget.";
            return result;
        }

        std::wstring UnicodeStringToWstring(const LocalUnicodeString& value)
        {
            if (value.Buffer == nullptr || value.Length == 0)
            {
                return {};
            }
            return std::wstring(value.Buffer, value.Length / sizeof(wchar_t));
        }

        std::wstring QueryObjectType(const NtApis& apis, HANDLE handle, std::wstring* errorMessage)
        {
            ULONG returnLength = 0;
            LONG status = apis.queryObject(handle, ObjectTypeInformation, nullptr, 0, &returnLength);
            if (returnLength == 0)
            {
                returnLength = 4096;
            }

            constexpr ULONG MetadataSlackBytes = 1024;
            if (returnLength >
                HandleCollectionMaxObjectMetadataBytes - MetadataSlackBytes)
            {
                if (errorMessage != nullptr)
                {
                    *errorMessage =
                        L"Object type metadata exceeded its bounded enrichment buffer.";
                }
                return {};
            }

            std::vector<unsigned char> buffer;
            try
            {
                buffer.resize(returnLength + MetadataSlackBytes);
            }
            catch (const std::bad_alloc&)
            {
                if (errorMessage != nullptr)
                {
                    *errorMessage =
                        L"Object type metadata allocation failed.";
                }
                return {};
            }
            catch (const std::length_error&)
            {
                if (errorMessage != nullptr)
                {
                    *errorMessage =
                        L"Object type metadata size was not representable.";
                }
                return {};
            }
            status = apis.queryObject(
                handle,
                ObjectTypeInformation,
                buffer.data(),
                static_cast<ULONG>(buffer.size()),
                &returnLength);

            if (!NtSuccess(status))
            {
                if (errorMessage != nullptr)
                {
                    *errorMessage = L"NtQueryObject(ObjectTypeInformation) failed: " + NtStatusText(status);
                }
                return {};
            }

            const auto* typeInfo = reinterpret_cast<const ObjectTypeInformationLocal*>(buffer.data());
            return UnicodeStringToWstring(typeInfo->TypeName);
        }

        bool ShouldQueryObjectName(const std::wstring& objectType)
        {
            const std::wstring loweredType = ToLower(objectType);
            return loweredType == L"key" ||
                loweredType == L"section" ||
                loweredType == L"mutant" ||
                loweredType == L"event" ||
                loweredType == L"semaphore" ||
                loweredType == L"symboliclink" ||
                loweredType == L"directory";
        }

        std::wstring QueryObjectName(const NtApis& apis, HANDLE handle, std::wstring* errorMessage)
        {
            ULONG returnLength = 0;
            LONG status = apis.queryObject(handle, ObjectNameInformation, nullptr, 0, &returnLength);
            if (returnLength == 0)
            {
                returnLength = 4096;
            }

            constexpr ULONG MetadataSlackBytes = 1024;
            if (returnLength >
                HandleCollectionMaxObjectMetadataBytes - MetadataSlackBytes)
            {
                if (errorMessage != nullptr)
                {
                    *errorMessage =
                        L"Object name metadata exceeded its bounded enrichment buffer.";
                }
                return {};
            }

            std::vector<unsigned char> buffer;
            try
            {
                buffer.resize(returnLength + MetadataSlackBytes);
            }
            catch (const std::bad_alloc&)
            {
                if (errorMessage != nullptr)
                {
                    *errorMessage =
                        L"Object name metadata allocation failed.";
                }
                return {};
            }
            catch (const std::length_error&)
            {
                if (errorMessage != nullptr)
                {
                    *errorMessage =
                        L"Object name metadata size was not representable.";
                }
                return {};
            }
            status = apis.queryObject(
                handle,
                ObjectNameInformation,
                buffer.data(),
                static_cast<ULONG>(buffer.size()),
                &returnLength);

            if (!NtSuccess(status))
            {
                if (errorMessage != nullptr)
                {
                    *errorMessage = L"NtQueryObject(ObjectNameInformation) failed: " + NtStatusText(status);
                }
                return {};
            }

            const auto* nameInfo = reinterpret_cast<const ObjectNameInformationLocal*>(buffer.data());
            return UnicodeStringToWstring(nameInfo->Name);
        }

        const ProcessInfo* FindProcessInSnapshot(const ProcessSnapshot* snapshot, std::uint32_t pid)
        {
            if (snapshot == nullptr)
            {
                return nullptr;
            }

            const auto found = snapshot->indexByPid.find(pid);
            if (found == snapshot->indexByPid.end() || found->second >= snapshot->processes.size())
            {
                return nullptr;
            }
            return &snapshot->processes[found->second];
        }

        std::vector<std::wstring> DecodeProcessAccess(std::uint32_t access)
        {
            std::vector<std::wstring> decoded;
            const auto addIfSet = [&](DWORD flag, const wchar_t* label) {
                if ((access & flag) != 0)
                {
                    decoded.push_back(label);
                }
            };

            addIfSet(PROCESS_VM_READ, L"PROCESS_VM_READ");
            addIfSet(PROCESS_VM_WRITE, L"PROCESS_VM_WRITE");
            addIfSet(PROCESS_VM_OPERATION, L"PROCESS_VM_OPERATION");
            addIfSet(PROCESS_CREATE_THREAD, L"PROCESS_CREATE_THREAD");
            addIfSet(PROCESS_DUP_HANDLE, L"PROCESS_DUP_HANDLE");
            addIfSet(PROCESS_QUERY_INFORMATION, L"PROCESS_QUERY_INFORMATION");
            addIfSet(PROCESS_QUERY_LIMITED_INFORMATION, L"PROCESS_QUERY_LIMITED_INFORMATION");
            addIfSet(PROCESS_TERMINATE, L"PROCESS_TERMINATE");
            return decoded;
        }

        class ScopedHandle
        {
        public:
            ScopedHandle() = default;
            explicit ScopedHandle(HANDLE value) noexcept : value_(value) {}
            ~ScopedHandle()
            {
                if (value_ != nullptr)
                {
                    CloseHandle(value_);
                }
            }

            ScopedHandle(const ScopedHandle&) = delete;
            ScopedHandle& operator=(const ScopedHandle&) = delete;

            HANDLE Get() const noexcept
            {
                return value_;
            }

            void Reset(HANDLE value = nullptr) noexcept
            {
                if (value_ != nullptr)
                {
                    CloseHandle(value_);
                }
                value_ = value;
            }

        private:
            HANDLE value_ = nullptr;
        };

        std::uint64_t ElapsedMicroseconds(
            const std::chrono::steady_clock::time_point& started) noexcept
        {
            return static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now() - started).count());
        }

        template <typename EntryReader>
        HandleCoreProjectionResult ProjectSelectedHandleCoreRecordsImpl(
            std::uint32_t selectedPid,
            std::size_t entriesAvailable,
            std::size_t systemEntriesReported,
            std::size_t retentionLimit,
            EntryReader&& readEntry) noexcept
        {
            HandleCoreProjectionResult result;
            result.systemEntriesReported = systemEntriesReported;
            const std::size_t scanCount = (std::min)(
                entriesAvailable,
                systemEntriesReported);
            result.queryBufferTruncated =
                systemEntriesReported > entriesAvailable;

            try
            {
                result.records.reserve((std::min)(retentionLimit, std::size_t(256)));
                for (std::size_t index = 0; index < scanCount; ++index)
                {
                    ++result.entriesScanned;
                    const HandleTableCoreEntry entry = readEntry(index);
                    if (entry.owningPid != selectedPid)
                    {
                        continue;
                    }

                    ++result.selectedEntriesMatched;
                    if (result.records.size() < retentionLimit)
                    {
                        result.records.push_back(entry);
                    }
                }
            }
            catch (const std::bad_alloc&)
            {
                return {};
            }
            catch (const std::length_error&)
            {
                return {};
            }

            result.selectedEntriesOmitted =
                result.selectedEntriesMatched - result.records.size();
            result.retentionCapReached = result.selectedEntriesOmitted != 0;
            result.success = true;
            return result;
        }

    }

    std::size_t CalculateAdaptiveHandleQueryBudget(
        std::uint64_t availablePhysicalBytes,
        std::uint64_t totalPhysicalBytes) noexcept
    {
        std::uint64_t desired = availablePhysicalBytes / 8U;
        if (totalPhysicalBytes != 0)
        {
            // A second total-memory guard keeps a constrained 4 GiB endpoint
            // below 256 MiB even when most memory happens to be available.
            desired = (std::min)(desired, totalPhysicalBytes / 16U);
        }
        desired = (std::max)(
            desired,
            static_cast<std::uint64_t>(HandleQueryMinimumBudgetBytes));
        desired = (std::min)(
            desired,
            static_cast<std::uint64_t>(HandleQueryMaximumBudgetBytes));
        return static_cast<std::size_t>(desired);
    }

    HandleQueryGrowthDecision PlanHandleQueryBufferGrowth(
        std::size_t currentBufferBytes,
        std::size_t requiredBufferBytes,
        std::size_t budgetBytes) noexcept
    {
        HandleQueryGrowthDecision result;
        if (currentBufferBytes == 0 ||
            budgetBytes == 0 ||
            currentBufferBytes >= budgetBytes ||
            requiredBufferBytes > budgetBytes)
        {
            result.budgetExceeded = true;
            return result;
        }

        constexpr std::size_t SlackBytes = 64ULL << 10;
        const std::size_t doubled = currentBufferBytes >
                (std::numeric_limits<std::size_t>::max)() / 2
            ? (std::numeric_limits<std::size_t>::max)()
            : currentBufferBytes * 2;
        const std::size_t requestedWithSlack = requiredBufferBytes >
                (std::numeric_limits<std::size_t>::max)() - SlackBytes
            ? (std::numeric_limits<std::size_t>::max)()
            : requiredBufferBytes + SlackBytes;
        std::size_t next = (std::max)(doubled, requestedWithSlack);
        next = (std::min)(next, budgetBytes);
        if (next <= currentBufferBytes)
        {
            result.budgetExceeded = true;
            return result;
        }

        result.canRetry = true;
        result.nextBufferBytes = next;
        return result;
    }

    HandleCoreProjectionResult ProjectSelectedHandleCoreRecords(
        std::uint32_t selectedPid,
        const std::vector<HandleTableCoreEntry>& availableEntries,
        std::size_t systemEntriesReported,
        std::size_t retentionLimit) noexcept
    {
        return ProjectSelectedHandleCoreRecordsImpl(
            selectedPid,
            availableEntries.size(),
            systemEntriesReported,
            retentionLimit,
            [&availableEntries](std::size_t index) {
                return availableEntries[index];
            });
    }

    HandleCollectionResult CollectProcessHandles(
        const ProcessInfo& process,
        const ProcessSnapshot* snapshot)
    {
        HandleCollectionResult result;
        result.pid = process.pid;
        const auto totalStarted = std::chrono::steady_clock::now();

        MEMORYSTATUSEX memoryStatus{};
        memoryStatus.dwLength = sizeof(memoryStatus);
        if (GlobalMemoryStatusEx(&memoryStatus) != FALSE)
        {
            result.queryBufferBudgetBytes = CalculateAdaptiveHandleQueryBudget(
                memoryStatus.ullAvailPhys,
                memoryStatus.ullTotalPhys);
        }
        else
        {
            result.queryBufferBudgetBytes = HandleQueryMinimumBudgetBytes;
        }

        std::wstring ntError;
        const NtApis apis = LoadNtApis(ntError);
        if (apis.querySystemInformation == nullptr)
        {
            result.queryFailureKind = HandleQueryFailureKind::ApiUnavailable;
            result.state = HandleCollectionStateForQueryFailure(
                result.queryFailureKind);
            result.statusMessage = ntError.empty() ? L"NT handle query APIs are unavailable." : ntError;
            result.totalDurationMicroseconds = ElapsedMicroseconds(totalStarted);
            return result;
        }

        HandleCoreProjectionResult projection;
        {
            const auto queryStarted = std::chrono::steady_clock::now();
            SystemHandleQueryResult query = QuerySystemHandleBuffer(
                apis,
                result.queryBufferBudgetBytes);
            result.queryDurationMicroseconds = ElapsedMicroseconds(queryStarted);
            result.queryAttemptCount = query.attemptCount;
            result.queryBufferBytes = query.bufferBytes;

            if (query.status != SystemHandleQueryStatus::Success)
            {
                result.queryFailureKind =
                    query.status == SystemHandleQueryStatus::BudgetExceeded
                    ? HandleQueryFailureKind::BudgetExceeded
                    : query.status == SystemHandleQueryStatus::AllocationFailed
                        ? HandleQueryFailureKind::AllocationFailed
                        : HandleQueryFailureKind::ApiFailed;
                result.state = HandleCollectionStateForQueryFailure(
                    result.queryFailureKind);
                result.statusMessage = query.diagnostic.empty()
                    ? L"System handle query failed."
                    : query.diagnostic;
                result.totalDurationMicroseconds = ElapsedMicroseconds(totalStarted);
                return result;
            }

            const std::size_t headerBytes =
                offsetof(SystemHandleInformationEx, Handles);
            if (query.buffer.size() < headerBytes)
            {
                result.queryFailureKind =
                    HandleQueryFailureKind::InvalidBuffer;
                result.state = HandleCollectionStateForQueryFailure(
                    result.queryFailureKind);
                result.statusMessage =
                    L"System handle query returned an invalid buffer.";
                result.totalDurationMicroseconds = ElapsedMicroseconds(totalStarted);
                return result;
            }

            const auto* systemHandles =
                reinterpret_cast<const SystemHandleInformationEx*>(
                    query.buffer.data());
            const std::size_t entriesReported = static_cast<std::size_t>(
                systemHandles->NumberOfHandles);
            const std::size_t entriesAvailable =
                (query.buffer.size() - headerBytes) /
                sizeof(SystemHandleTableEntryInfoEx);

            projection = ProjectSelectedHandleCoreRecordsImpl(
                process.pid,
                entriesAvailable,
                entriesReported,
                HandleCollectionMaxRetainedHandles,
                [systemHandles](std::size_t index) {
                    const SystemHandleTableEntryInfoEx& entry =
                        systemHandles->Handles[index];
                    HandleTableCoreEntry core;
                    core.owningPid = static_cast<std::uint32_t>(
                        entry.UniqueProcessId);
                    core.handleValue = static_cast<std::uint64_t>(
                        entry.HandleValue);
                    core.objectTypeIndex = entry.ObjectTypeIndex;
                    core.grantedAccess = entry.GrantedAccess;
                    return core;
                });

            if (!projection.success)
            {
                result.queryFailureKind =
                    HandleQueryFailureKind::AllocationFailed;
                result.state = HandleCollectionStateForQueryFailure(
                    result.queryFailureKind);
                result.statusMessage =
                    L"Could not allocate compact selected-process handle records.";
                result.totalDurationMicroseconds = ElapsedMicroseconds(totalStarted);
                return result;
            }
            // The large system-wide buffer is destroyed here, before any
            // DuplicateHandle or NtQueryObject enrichment begins.
        }

        result.systemHandleCount = projection.systemEntriesReported;
        result.systemEntriesScanned = projection.entriesScanned;
        result.selectedProcessHandlesMatched =
            projection.selectedEntriesMatched;
        result.selectedProcessHandlesOmitted =
            projection.selectedEntriesOmitted;
        result.queryBufferTruncated = projection.queryBufferTruncated;
        result.retentionCapReached = projection.retentionCapReached;
        result.compactCoreRecordBytes =
            projection.records.size() * sizeof(HandleTableCoreEntry);

        ScopedHandle sourceProcess(OpenProcess(
            PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            process.pid));
        const DWORD openProcessError = sourceProcess.Get() == nullptr
            ? GetLastError()
            : ERROR_SUCCESS;

        std::unordered_map<USHORT, std::wstring> typeNameByIndex;
        try
        {
            result.handles.reserve(projection.records.size());
            typeNameByIndex.reserve(32);
        }
        catch (const std::bad_alloc&)
        {
            result.queryFailureKind = HandleQueryFailureKind::AllocationFailed;
            result.state = HandleCollectionStateForQueryFailure(
                result.queryFailureKind);
            result.statusMessage =
                L"Could not allocate selected-process handle enrichment storage.";
            result.totalDurationMicroseconds = ElapsedMicroseconds(totalStarted);
            return result;
        }
        catch (const std::length_error&)
        {
            result.queryFailureKind = HandleQueryFailureKind::AllocationFailed;
            result.state = HandleCollectionStateForQueryFailure(
                result.queryFailureKind);
            result.statusMessage =
                L"Selected-process handle enrichment storage exceeded its bounded representation.";
            result.totalDurationMicroseconds = ElapsedMicroseconds(totalStarted);
            return result;
        }

        const auto enrichmentStarted = std::chrono::steady_clock::now();
        try
        {
            for (std::size_t index = 0; index < projection.records.size(); ++index)
            {
                const HandleTableCoreEntry& core = projection.records[index];

            HandleInfo handle;
            handle.owningPid = process.pid;
            handle.handleValue = core.handleValue;
            handle.objectTypeIndex = core.objectTypeIndex;
            handle.grantedAccessRaw = core.grantedAccess;
            try
            {
                handle.grantedAccess = HexAccess(core.grantedAccess);
            }
            catch (const std::bad_alloc&)
            {
                result.selectedProcessHandlesOmitted +=
                    projection.records.size() - index;
                result.retentionCapReached = true;
                break;
            }

            if (sourceProcess.Get() == nullptr)
            {
                handle.objectType =
                    L"Type " + std::to_wstring(core.objectTypeIndex);
                handle.errorMessage =
                    L"Could not open source process for optional handle metadata: " +
                    WindowsErrorMessage(openProcessError);
                ++result.typeResolutionsSkipped;
                result.typeOrTargetResolutionPartial = true;
                result.handles.push_back(std::move(handle));
                continue;
            }

            ScopedHandle localHandle;
            bool duplicateAttempted = false;
            const auto ensureLocalHandle = [&]() {
                if (localHandle.Get() != nullptr)
                {
                    return true;
                }
                if (duplicateAttempted)
                {
                    return false;
                }
                duplicateAttempted = true;
                HANDLE duplicated = nullptr;
                if (DuplicateHandle(
                        sourceProcess.Get(),
                        reinterpret_cast<HANDLE>(core.handleValue),
                        GetCurrentProcess(),
                        &duplicated,
                        0,
                        FALSE,
                        DUPLICATE_SAME_ACCESS) == FALSE)
                {
                    handle.errorMessage =
                        L"Could not duplicate handle for optional metadata: " +
                        WindowsErrorMessage(GetLastError());
                    return false;
                }
                localHandle.Reset(duplicated);
                return true;
            };

            const auto cachedType = typeNameByIndex.find(core.objectTypeIndex);
            if (cachedType != typeNameByIndex.end())
            {
                handle.objectType = cachedType->second;
                handle.typeResolved = !handle.objectType.empty();
            }
            else if (apis.queryObject == nullptr)
            {
                ++result.typeResolutionsSkipped;
                result.typeOrTargetResolutionPartial = true;
            }
            else if (!HandleOptionalEnrichmentBudgetAvailable(
                result.typeResolutionsAttempted,
                HandleCollectionMaxTypeResolutions))
            {
                ++result.typeResolutionsSkipped;
                result.typeResolutionCapReached = true;
                result.typeOrTargetResolutionPartial = true;
            }
            else
            {
                ++result.typeResolutionsAttempted;
                std::wstring typeError;
                if (ensureLocalHandle())
                {
                    handle.objectType = QueryObjectType(
                        apis,
                        localHandle.Get(),
                        &typeError);
                }
                handle.typeResolved = !handle.objectType.empty();
                if (handle.typeResolved)
                {
                    ++result.typeResolutionsResolved;
                    typeNameByIndex.emplace(
                        core.objectTypeIndex,
                        handle.objectType);
                }
                else
                {
                    ++result.typeResolutionsFailed;
                    result.typeOrTargetResolutionPartial = true;
                    if (handle.errorMessage.empty())
                    {
                        handle.errorMessage = typeError.empty()
                            ? L"Object type metadata was not resolved."
                            : typeError;
                    }
                }
            }

            if (handle.objectType.empty())
            {
                handle.objectType =
                    L"Type " + std::to_wstring(core.objectTypeIndex);
            }

            if (EqualsIgnoreCase(handle.objectType, L"Process"))
            {
                const DWORD targetPid = ensureLocalHandle()
                    ? GetProcessId(localHandle.Get())
                    : 0;
                if (targetPid != 0)
                {
                    ++result.targetsResolved;
                    handle.targetPid = targetPid;
                    const ProcessInfo* targetProcess = FindProcessInSnapshot(snapshot, targetPid);
                    if (targetProcess != nullptr)
                    {
                        handle.targetProcessName = targetProcess->name;
                    }
                }
                else
                {
                    ++result.targetsUnresolved;
                    result.typeOrTargetResolutionPartial = true;
                }
                handle.decodedAccess = DecodeProcessAccess(handle.grantedAccessRaw);
            }
            else if (EqualsIgnoreCase(handle.objectType, L"Thread"))
            {
                const DWORD targetPid = ensureLocalHandle()
                    ? GetProcessIdOfThread(localHandle.Get())
                    : 0;
                const DWORD targetThreadId = localHandle.Get() != nullptr
                    ? GetThreadId(localHandle.Get())
                    : 0;
                if (targetPid != 0)
                {
                    ++result.targetsResolved;
                    handle.targetPid = targetPid;
                    const ProcessInfo* targetProcess =
                        FindProcessInSnapshot(snapshot, targetPid);
                    if (targetProcess != nullptr)
                    {
                        handle.targetProcessName = targetProcess->name;
                    }
                }
                else
                {
                    ++result.targetsUnresolved;
                    result.typeOrTargetResolutionPartial = true;
                }
                if (targetThreadId != 0)
                {
                    handle.targetThreadId = targetThreadId;
                }
            }

            if (ShouldQueryObjectName(handle.objectType))
            {
                if (!HandleOptionalEnrichmentBudgetAvailable(
                    result.namesAttempted,
                    HandleCollectionMaxNameResolutions))
                {
                    ++result.namesSkipped;
                    result.nameResolutionCapReached = true;
                    if (handle.errorMessage.empty())
                    {
                        handle.errorMessage =
                            L"Object name resolution skipped by safety limit.";
                    }
                }
                else
                {
                    ++result.namesAttempted;
                    std::wstring nameError;
                    if (ensureLocalHandle())
                    {
                        handle.objectName = QueryObjectName(
                            apis,
                            localHandle.Get(),
                            &nameError);
                    }
                    handle.nameResolved = !handle.objectName.empty();
                    if (handle.nameResolved)
                    {
                        ++result.namesResolved;
                    }
                    else if (!nameError.empty() || localHandle.Get() == nullptr)
                    {
                        ++result.namesFailed;
                        if (handle.errorMessage.empty())
                        {
                            handle.errorMessage = nameError.empty()
                                ? L"Object name metadata was not resolved."
                                : nameError;
                        }
                    }
                }
            }

                result.handles.push_back(std::move(handle));
            }
        }
        catch (const std::bad_alloc&)
        {
            result.selectedProcessHandlesOmitted +=
                projection.records.size() - result.handles.size();
            result.retentionCapReached = true;
            result.typeOrTargetResolutionPartial = true;
        }
        catch (const std::length_error&)
        {
            result.selectedProcessHandlesOmitted +=
                projection.records.size() - result.handles.size();
            result.retentionCapReached = true;
            result.typeOrTargetResolutionPartial = true;
        }

        result.enrichmentDurationMicroseconds =
            ElapsedMicroseconds(enrichmentStarted);
        result.success = true;
        const bool partial = result.queryBufferTruncated ||
            result.retentionCapReached ||
            result.nameResolutionCapReached ||
            result.namesFailed != 0 ||
            result.typeResolutionCapReached ||
            result.typeResolutionsFailed != 0 ||
            result.typeOrTargetResolutionPartial;
        result.state = partial
            ? HandleCollectionState::Partial
            : HandleCollectionState::Success;
        result.statusMessage =
            std::to_wstring(result.handles.size()) + L" handles collected.";
        if (partial)
        {
            result.statusMessage +=
                L" Additional handles or metadata may not have been evaluated because safety limits or collection constraints were reached.";
        }

        result.totalDurationMicroseconds = ElapsedMicroseconds(totalStarted);
        return result;
    }
}
