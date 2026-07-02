#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "HandleCollector.h"

#include <Windows.h>

#include <algorithm>
#include <cwctype>
#include <iomanip>
#include <memory>
#include <sstream>
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

        bool Contains(const std::wstring& haystack, const std::wstring& needle)
        {
            return haystack.find(needle) != std::wstring::npos;
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

            if (apis.querySystemInformation == nullptr || apis.queryObject == nullptr)
            {
                errorMessage = L"Required ntdll exports were not available.";
                apis = {};
            }

            return apis;
        }

        std::vector<unsigned char> QuerySystemHandleBuffer(const NtApis& apis, std::wstring& errorMessage)
        {
            ULONG bufferLength = 1U << 20;
            constexpr ULONG MaxBufferLength = 128U << 20;

            for (int attempt = 0; attempt < 9; ++attempt)
            {
                std::vector<unsigned char> buffer(bufferLength);
                ULONG returnLength = 0;
                const LONG status = apis.querySystemInformation(
                    SystemExtendedHandleInformation,
                    buffer.data(),
                    bufferLength,
                    &returnLength);

                if (NtSuccess(status))
                {
                    return buffer;
                }

                if (status == StatusInfoLengthMismatch ||
                    status == StatusBufferOverflow ||
                    status == StatusBufferTooSmall ||
                    returnLength > bufferLength)
                {
                    const ULONG requestedLength = returnLength > bufferLength ? returnLength : bufferLength * 2;
                    bufferLength = std::min(MaxBufferLength, requestedLength + (64U << 10));
                    continue;
                }

                errorMessage = L"NtQuerySystemInformation(SystemExtendedHandleInformation) failed: " + NtStatusText(status);
                return {};
            }

            errorMessage = L"System handle table is too large to query within the configured limit.";
            return {};
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

            std::vector<unsigned char> buffer(returnLength + 1024);
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

            std::vector<unsigned char> buffer(returnLength + 1024);
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

        bool HasSuspiciousProcessAccess(std::uint32_t access)
        {
            constexpr DWORD SuspiciousAccess =
                PROCESS_VM_WRITE |
                PROCESS_VM_OPERATION |
                PROCESS_CREATE_THREAD |
                PROCESS_DUP_HANDLE;
            return (access & SuspiciousAccess) != 0;
        }

        bool IsSensitiveRegistryPath(const std::wstring& objectName)
        {
            const std::wstring loweredName = ToLower(objectName);
            return Contains(loweredName, L"\\registry\\machine\\sam") ||
                Contains(loweredName, L"\\registry\\machine\\security") ||
                Contains(loweredName, L"\\registry\\machine\\system\\currentcontrolset\\control\\lsa") ||
                Contains(loweredName, L"\\registry\\machine\\software\\microsoft\\windows\\currentversion\\run") ||
                (Contains(loweredName, L"\\registry\\user\\") &&
                    Contains(loweredName, L"\\software\\microsoft\\windows\\currentversion\\run"));
        }

        bool IsSuspiciousUserWritablePath(const std::wstring& objectName)
        {
            const std::wstring loweredName = ToLower(objectName);
            return Contains(loweredName, L"\\appdata\\") ||
                Contains(loweredName, L"\\temp\\") ||
                Contains(loweredName, L"\\downloads\\") ||
                Contains(loweredName, L"\\desktop\\");
        }

        void AddIndicator(HandleInfo& handle, const std::wstring& indicator)
        {
            handle.indicators.push_back(indicator);
            handle.isSensitive = true;
        }

        void AnalyzeHandle(HandleInfo& handle)
        {
            const std::wstring loweredType = ToLower(handle.objectType);
            const std::wstring loweredTargetName = ToLower(handle.targetProcessName);

            if (loweredType == L"process")
            {
                if (loweredTargetName == L"lsass.exe")
                {
                    AddIndicator(handle, L"Process handle targets lsass.exe.");
                }
                else if (loweredTargetName == L"winlogon.exe")
                {
                    AddIndicator(handle, L"Process handle targets winlogon.exe.");
                }

                if (handle.targetPid.has_value() &&
                    handle.targetPid.value() != handle.owningPid &&
                    HasSuspiciousProcessAccess(handle.grantedAccessRaw))
                {
                    AddIndicator(handle, L"Process handle has VM write, VM operation, create-thread, or duplicate-handle access.");
                }
            }
            else if (loweredType == L"token")
            {
                AddIndicator(handle, L"Token handle present.");
            }
            else if (loweredType == L"key" && !handle.objectName.empty() && IsSensitiveRegistryPath(handle.objectName))
            {
                AddIndicator(handle, L"Registry key handle references a sensitive path.");
            }
            else if (loweredType == L"file" && !handle.objectName.empty() && IsSuspiciousUserWritablePath(handle.objectName))
            {
                AddIndicator(handle, L"File handle references a user-writable path.");
            }
        }
    }

    HandleCollectionResult CollectProcessHandles(
        const ProcessInfo& process,
        const ProcessSnapshot* snapshot)
    {
        HandleCollectionResult result;
        result.pid = process.pid;

        std::wstring ntError;
        const NtApis apis = LoadNtApis(ntError);
        if (apis.querySystemInformation == nullptr || apis.queryObject == nullptr)
        {
            result.statusMessage = ntError.empty() ? L"NT handle query APIs are unavailable." : ntError;
            return result;
        }

        std::vector<unsigned char> handleBuffer = QuerySystemHandleBuffer(apis, ntError);
        if (handleBuffer.empty())
        {
            result.statusMessage = ntError.empty() ? L"System handle query returned no data." : ntError;
            return result;
        }

        const auto* systemHandles = reinterpret_cast<const SystemHandleInformationEx*>(handleBuffer.data());
        result.systemHandleCount = static_cast<std::size_t>(systemHandles->NumberOfHandles);

        HANDLE sourceProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process.pid);
        const DWORD openProcessError = sourceProcess == nullptr ? GetLastError() : ERROR_SUCCESS;

        std::unordered_map<USHORT, std::wstring> typeNameByIndex;
        result.handles.reserve(256);

        for (ULONG_PTR index = 0; index < systemHandles->NumberOfHandles; ++index)
        {
            const SystemHandleTableEntryInfoEx& entry = systemHandles->Handles[index];
            if (static_cast<std::uint32_t>(entry.UniqueProcessId) != process.pid)
            {
                continue;
            }

            HandleInfo handle;
            handle.owningPid = process.pid;
            handle.handleValue = static_cast<std::uint64_t>(entry.HandleValue);
            handle.grantedAccessRaw = entry.GrantedAccess;
            handle.grantedAccess = HexAccess(entry.GrantedAccess);

            if (sourceProcess == nullptr)
            {
                handle.objectType = L"Type " + std::to_wstring(entry.ObjectTypeIndex);
                handle.errorMessage = L"Could not open source process for handle metadata: " + WindowsErrorMessage(openProcessError);
                result.handles.push_back(std::move(handle));
                continue;
            }

            HANDLE localHandle = nullptr;
            if (DuplicateHandle(
                sourceProcess,
                reinterpret_cast<HANDLE>(entry.HandleValue),
                GetCurrentProcess(),
                &localHandle,
                0,
                FALSE,
                DUPLICATE_SAME_ACCESS) == FALSE)
            {
                handle.objectType = L"Type " + std::to_wstring(entry.ObjectTypeIndex);
                handle.errorMessage = L"Could not duplicate handle for metadata query: " + WindowsErrorMessage(GetLastError());
                result.handles.push_back(std::move(handle));
                continue;
            }

            const auto cachedType = typeNameByIndex.find(entry.ObjectTypeIndex);
            if (cachedType != typeNameByIndex.end())
            {
                handle.objectType = cachedType->second;
                handle.typeResolved = !handle.objectType.empty();
            }
            else
            {
                std::wstring typeError;
                handle.objectType = QueryObjectType(apis, localHandle, &typeError);
                handle.typeResolved = !handle.objectType.empty();
                if (handle.typeResolved)
                {
                    typeNameByIndex.emplace(entry.ObjectTypeIndex, handle.objectType);
                }
                else
                {
                    handle.objectType = L"Type " + std::to_wstring(entry.ObjectTypeIndex);
                    handle.errorMessage = typeError;
                }
            }

            if (EqualsIgnoreCase(handle.objectType, L"Process"))
            {
                const DWORD targetPid = GetProcessId(localHandle);
                if (targetPid != 0)
                {
                    handle.targetPid = targetPid;
                    const ProcessInfo* targetProcess = FindProcessInSnapshot(snapshot, targetPid);
                    if (targetProcess != nullptr)
                    {
                        handle.targetProcessName = targetProcess->name;
                    }
                }
                handle.decodedAccess = DecodeProcessAccess(handle.grantedAccessRaw);
            }

            if (ShouldQueryObjectName(handle.objectType))
            {
                std::wstring nameError;
                handle.objectName = QueryObjectName(apis, localHandle, &nameError);
                handle.nameResolved = !handle.objectName.empty();
                if (!handle.nameResolved && handle.errorMessage.empty())
                {
                    handle.errorMessage = nameError;
                }
            }

            CloseHandle(localHandle);

            AnalyzeHandle(handle);
            if (handle.isSensitive)
            {
                ++result.sensitiveCount;
            }
            result.handles.push_back(std::move(handle));
        }

        if (sourceProcess != nullptr)
        {
            CloseHandle(sourceProcess);
        }

        result.success = true;
        if (sourceProcess == nullptr)
        {
            result.statusMessage =
                L"Loaded " + std::to_wstring(result.handles.size()) +
                L" handle entries; object metadata unavailable because the process could not be opened: " +
                WindowsErrorMessage(openProcessError) + L".";
        }
        else
        {
            result.statusMessage =
                L"Loaded " + std::to_wstring(result.handles.size()) +
                L" handle entries for PID " + std::to_wstring(process.pid) + L".";
        }

        return result;
    }
}
