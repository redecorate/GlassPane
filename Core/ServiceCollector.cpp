#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "ServiceCollector.h"

#include "ServicePathParser.h"

#include <Windows.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#pragma comment(lib, "Advapi32.lib")

namespace GlassPane::Core
{
    namespace
    {
        constexpr DWORD ServiceEnumerationBufferMaxBytes = 256U * 1024U;
        constexpr DWORD ServiceQueryBufferMaxBytes = 8U * 1024U;
        constexpr std::size_t ServiceEnumerationMaxCalls = 128;

        class ScHandle
        {
        public:
            ScHandle() = default;

            explicit ScHandle(SC_HANDLE handle) noexcept
                : handle_(handle)
            {
            }

            ~ScHandle()
            {
                Reset();
            }

            ScHandle(const ScHandle&) = delete;
            ScHandle& operator=(const ScHandle&) = delete;

            ScHandle(ScHandle&& other) noexcept
                : handle_(other.handle_)
            {
                other.handle_ = nullptr;
            }

            ScHandle& operator=(ScHandle&& other) noexcept
            {
                if (this != &other)
                {
                    Reset();
                    handle_ = other.handle_;
                    other.handle_ = nullptr;
                }
                return *this;
            }

            SC_HANDLE Get() const noexcept
            {
                return handle_;
            }

            explicit operator bool() const noexcept
            {
                return handle_ != nullptr;
            }

        private:
            void Reset() noexcept
            {
                if (handle_ != nullptr)
                {
                    CloseServiceHandle(handle_);
                    handle_ = nullptr;
                }
            }

            SC_HANDLE handle_ = nullptr;
        };

        class AlignedByteBuffer
        {
        public:
            explicit AlignedByteBuffer(DWORD byteSize)
            {
                Resize(byteSize);
            }

            void Resize(DWORD byteSize)
            {
                byteSize_ = byteSize;
                const std::size_t wordSize = sizeof(std::max_align_t);
                storage_.resize((static_cast<std::size_t>(byteSize) + wordSize - 1) / wordSize);
            }

            BYTE* Data() noexcept
            {
                return reinterpret_cast<BYTE*>(storage_.data());
            }

            const BYTE* Data() const noexcept
            {
                return reinterpret_cast<const BYTE*>(storage_.data());
            }

            DWORD Size() const noexcept
            {
                return byteSize_;
            }

        private:
            std::vector<std::max_align_t> storage_;
            DWORD byteSize_ = 0;
        };

        enum class BufferStringResult
        {
            Success,
            Truncated,
            Invalid
        };

        struct EnumerationOutcome
        {
            bool completed = false;
            DWORD error = ERROR_SUCCESS;
        };

        BufferStringResult CopyStringFromBuffer(
            const wchar_t* source,
            const AlignedByteBuffer& buffer,
            std::size_t maxCharacters,
            std::wstring& destination)
        {
            destination.clear();
            if (source == nullptr)
            {
                return BufferStringResult::Success;
            }

            const std::uintptr_t bufferStart = reinterpret_cast<std::uintptr_t>(buffer.Data());
            const std::uintptr_t bufferEnd = bufferStart + static_cast<std::uintptr_t>(buffer.Size());
            const std::uintptr_t sourceAddress = reinterpret_cast<std::uintptr_t>(source);
            if (sourceAddress < bufferStart ||
                sourceAddress >= bufferEnd ||
                (sourceAddress % alignof(wchar_t)) != 0)
            {
                return BufferStringResult::Invalid;
            }

            const std::size_t availableCharacters =
                static_cast<std::size_t>(bufferEnd - sourceAddress) / sizeof(wchar_t);
            std::size_t length = 0;
            while (length < availableCharacters && source[length] != L'\0')
            {
                ++length;
            }
            if (length == availableCharacters)
            {
                return BufferStringResult::Invalid;
            }

            const bool truncated = AssignBoundedServiceText(
                destination,
                std::wstring_view(source, length),
                maxCharacters);
            return truncated ? BufferStringResult::Truncated : BufferStringResult::Success;
        }

        bool ServiceHasTruncatedFields(const ServiceInfo& service)
        {
            return service.serviceNameTruncated ||
                   service.displayNameTruncated ||
                   service.descriptionTruncated ||
                   service.serviceAccountTruncated ||
                   service.rawImagePathTruncated ||
                   service.expandedImagePathTruncated ||
                   service.svchostGroupTruncated ||
                   service.pathParseMessageTruncated ||
                   service.statusMessageTruncated;
        }

        void AppendStatusSentence(std::wstring& status, const std::wstring& sentence)
        {
            if (sentence.empty())
            {
                return;
            }
            if (!status.empty())
            {
                status += L" ";
            }
            status += sentence;
        }

        int CompareOrdinal(std::wstring_view left, std::wstring_view right, bool ignoreCase)
        {
            const int result = CompareStringOrdinal(
                left.data(),
                static_cast<int>(left.size()),
                right.data(),
                static_cast<int>(right.size()),
                ignoreCase ? TRUE : FALSE);
            if (result == CSTR_LESS_THAN)
            {
                return -1;
            }
            if (result == CSTR_GREATER_THAN)
            {
                return 1;
            }
            return 0;
        }

        void SetServiceStatus(ServiceInfo& service)
        {
            std::wstring status;
            if (!service.configurationAvailable && !service.descriptionAvailable)
            {
                status = L"Configuration and description metadata are unavailable.";
            }
            else if (!service.configurationAvailable)
            {
                status = L"Configuration metadata is unavailable.";
            }
            else if (!service.descriptionAvailable)
            {
                status = L"Description metadata is unavailable.";
            }

            if (ServiceHasTruncatedFields(service))
            {
                AppendStatusSentence(status, L"One or more fields were bounded to collection limits.");
            }
            service.statusMessageTruncated = AssignBoundedServiceText(
                service.statusMessage,
                status,
                ServiceMessageMaxCharacters);
        }

        bool PopulateConfiguration(SC_HANDLE serviceHandle, ServiceInfo& service)
        {
            DWORD requiredBytes = 0;
            if (QueryServiceConfigW(serviceHandle, nullptr, 0, &requiredBytes) != FALSE)
            {
                return false;
            }
            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER ||
                requiredBytes < sizeof(QUERY_SERVICE_CONFIGW) ||
                requiredBytes > ServiceQueryBufferMaxBytes)
            {
                return false;
            }

            AlignedByteBuffer buffer(requiredBytes);
            for (int attempt = 0; attempt < 3; ++attempt)
            {
                DWORD nextRequiredBytes = 0;
                auto* configuration = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.Data());
                if (QueryServiceConfigW(
                    serviceHandle,
                    configuration,
                    buffer.Size(),
                    &nextRequiredBytes) != FALSE)
                {
                    std::wstring account;
                    std::wstring rawImagePath;
                    const BufferStringResult accountResult = CopyStringFromBuffer(
                        configuration->lpServiceStartName,
                        buffer,
                        ServiceAccountMaxCharacters,
                        account);
                    const BufferStringResult pathResult = CopyStringFromBuffer(
                        configuration->lpBinaryPathName,
                        buffer,
                        ServiceQueryBufferMaxBytes / sizeof(wchar_t),
                        rawImagePath);
                    if (accountResult == BufferStringResult::Invalid ||
                        pathResult == BufferStringResult::Invalid)
                    {
                        return false;
                    }

                    service.startTypeRaw = configuration->dwStartType;
                    service.serviceAccount = std::move(account);
                    service.serviceAccountTruncated = accountResult == BufferStringResult::Truncated;

                    const ServiceImagePathParseResult parsed = ParseServiceImagePath(rawImagePath);
                    service.rawImagePath = parsed.rawImagePath;
                    service.expandedImagePath = parsed.expandedImagePath;
                    service.executablePath = parsed.executablePath;
                    service.pathParseStatus = parsed.status;
                    service.pathConfidence = parsed.confidence;
                    service.pathParseMessageTruncated = AssignBoundedServiceText(
                        service.pathParseMessage,
                        parsed.message,
                        ServiceMessageMaxCharacters);
                    service.svchostGroup = parsed.svchostGroup;
                    service.rawImagePathTruncated =
                        pathResult == BufferStringResult::Truncated || parsed.rawInputTruncated;
                    service.expandedImagePathTruncated = parsed.expandedInputTruncated;
                    service.svchostGroupTruncated = parsed.svchostGroupTruncated;
                    service.configurationAvailable = true;
                    return true;
                }

                const DWORD error = GetLastError();
                if (error != ERROR_INSUFFICIENT_BUFFER ||
                    nextRequiredBytes <= buffer.Size() ||
                    nextRequiredBytes > ServiceQueryBufferMaxBytes)
                {
                    return false;
                }
                buffer.Resize(nextRequiredBytes);
            }
            return false;
        }

        bool PopulateDescription(SC_HANDLE serviceHandle, ServiceInfo& service)
        {
            DWORD requiredBytes = 0;
            if (QueryServiceConfig2W(
                serviceHandle,
                SERVICE_CONFIG_DESCRIPTION,
                nullptr,
                0,
                &requiredBytes) != FALSE)
            {
                return false;
            }
            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER ||
                requiredBytes < sizeof(SERVICE_DESCRIPTIONW) ||
                requiredBytes > ServiceQueryBufferMaxBytes)
            {
                return false;
            }

            AlignedByteBuffer buffer(requiredBytes);
            for (int attempt = 0; attempt < 3; ++attempt)
            {
                DWORD nextRequiredBytes = 0;
                if (QueryServiceConfig2W(
                    serviceHandle,
                    SERVICE_CONFIG_DESCRIPTION,
                    buffer.Data(),
                    buffer.Size(),
                    &nextRequiredBytes) != FALSE)
                {
                    const auto* description =
                        reinterpret_cast<const SERVICE_DESCRIPTIONW*>(buffer.Data());
                    const BufferStringResult descriptionResult = CopyStringFromBuffer(
                        description->lpDescription,
                        buffer,
                        ServiceDescriptionMaxCharacters,
                        service.description);
                    if (descriptionResult == BufferStringResult::Invalid)
                    {
                        service.description.clear();
                        return false;
                    }

                    service.descriptionTruncated =
                        descriptionResult == BufferStringResult::Truncated;
                    service.descriptionAvailable = true;
                    return true;
                }

                const DWORD error = GetLastError();
                if (error != ERROR_INSUFFICIENT_BUFFER ||
                    nextRequiredBytes <= buffer.Size() ||
                    nextRequiredBytes > ServiceQueryBufferMaxBytes)
                {
                    return false;
                }
                buffer.Resize(nextRequiredBytes);
            }
            return false;
        }

        bool PopulateBaseService(
            const ENUM_SERVICE_STATUS_PROCESSW& source,
            const AlignedByteBuffer& enumerationBuffer,
            ServiceInfo& service)
        {
            const BufferStringResult serviceNameResult = CopyStringFromBuffer(
                source.lpServiceName,
                enumerationBuffer,
                ServiceNameMaxCharacters,
                service.serviceName);
            const BufferStringResult displayNameResult = CopyStringFromBuffer(
                source.lpDisplayName,
                enumerationBuffer,
                ServiceDisplayNameMaxCharacters,
                service.displayName);

            if (serviceNameResult == BufferStringResult::Invalid || service.serviceName.empty())
            {
                return false;
            }

            service.serviceNameTruncated = serviceNameResult == BufferStringResult::Truncated;
            service.displayNameTruncated = displayNameResult != BufferStringResult::Success;
            service.stateRaw = source.ServiceStatusProcess.dwCurrentState;
            service.serviceTypeRaw = source.ServiceStatusProcess.dwServiceType;
            service.serviceFlagsRaw = source.ServiceStatusProcess.dwServiceFlags;
            service.scmProcessId = source.ServiceStatusProcess.dwProcessId;
            service.processModel = ServiceProcessModelFromType(service.serviceTypeRaw);
            service.pidReliableForState =
                service.scmProcessId != 0 && ServiceStateHasReliableProcessId(service.stateRaw);
            return true;
        }

        bool AppendEnumerationRows(
            const AlignedByteBuffer& buffer,
            DWORD servicesReturned,
            ServiceCollectionResult& result)
        {
            const std::size_t maximumRows =
                static_cast<std::size_t>(buffer.Size()) / sizeof(ENUM_SERVICE_STATUS_PROCESSW);
            if (static_cast<std::size_t>(servicesReturned) > maximumRows)
            {
                return false;
            }

            const auto* rows =
                reinterpret_cast<const ENUM_SERVICE_STATUS_PROCESSW*>(buffer.Data());
            for (DWORD rowIndex = 0; rowIndex < servicesReturned; ++rowIndex)
            {
                if (!RegisterEnumeratedService(result))
                {
                    continue;
                }

                ServiceInfo service;
                if (!PopulateBaseService(rows[rowIndex], buffer, service))
                {
                    --result.totalEnumerated;
                    return false;
                }
                result.services.push_back(std::move(service));
            }
            return true;
        }

        EnumerationOutcome EnumerateBaseServices(
            SC_HANDLE managerHandle,
            ServiceCollectionResult& result)
        {
            DWORD bytesNeeded = 0;
            DWORD servicesReturned = 0;
            DWORD resumeHandle = 0;
            if (EnumServicesStatusExW(
                managerHandle,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_ACTIVE,
                nullptr,
                0,
                &bytesNeeded,
                &servicesReturned,
                &resumeHandle,
                nullptr) != FALSE)
            {
                return { true, ERROR_SUCCESS };
            }

            const DWORD sizingError = GetLastError();
            if (sizingError != ERROR_MORE_DATA || bytesNeeded == 0)
            {
                return { false, sizingError };
            }

            resumeHandle = 0;
            DWORD bufferBytes = (std::min)(bytesNeeded, ServiceEnumerationBufferMaxBytes);
            if (bufferBytes < sizeof(ENUM_SERVICE_STATUS_PROCESSW))
            {
                return { false, ERROR_INVALID_DATA };
            }

            AlignedByteBuffer buffer(bufferBytes);
            std::vector<DWORD> seenResumeHandles = { 0 };
            for (std::size_t callIndex = 0;
                 callIndex < ServiceEnumerationMaxCalls;
                 ++callIndex)
            {
                const DWORD previousResumeHandle = resumeHandle;
                bytesNeeded = 0;
                servicesReturned = 0;
                const BOOL pageCompleted = EnumServicesStatusExW(
                    managerHandle,
                    SC_ENUM_PROCESS_INFO,
                    SERVICE_WIN32,
                    SERVICE_ACTIVE,
                    buffer.Data(),
                    buffer.Size(),
                    &bytesNeeded,
                    &servicesReturned,
                    &resumeHandle,
                    nullptr);
                const DWORD pageError = pageCompleted != FALSE ? ERROR_SUCCESS : GetLastError();

                if (pageCompleted == FALSE && pageError != ERROR_MORE_DATA)
                {
                    return { false, pageError };
                }

                if (pageCompleted != FALSE)
                {
                    if (!AppendEnumerationRows(buffer, servicesReturned, result))
                    {
                        return { false, ERROR_INVALID_DATA };
                    }
                    return { true, ERROR_SUCCESS };
                }

                DWORD nextBufferBytes = buffer.Size();
                if (bytesNeeded > buffer.Size() && buffer.Size() < ServiceEnumerationBufferMaxBytes)
                {
                    nextBufferBytes = (std::min)(bytesNeeded, ServiceEnumerationBufferMaxBytes);
                }
                const bool bufferWillGrow = nextBufferBytes > buffer.Size();

                if (servicesReturned == 0)
                {
                    if (resumeHandle != previousResumeHandle || !bufferWillGrow)
                    {
                        return { false, ERROR_MORE_DATA };
                    }
                    buffer.Resize(nextBufferBytes);
                    continue;
                }

                if (resumeHandle == previousResumeHandle ||
                    (std::find)(
                        seenResumeHandles.begin(),
                        seenResumeHandles.end(),
                        resumeHandle) != seenResumeHandles.end())
                {
                    return { false, ERROR_MORE_DATA };
                }
                if (!AppendEnumerationRows(buffer, servicesReturned, result))
                {
                    return { false, ERROR_INVALID_DATA };
                }
                seenResumeHandles.push_back(resumeHandle);
                if (bufferWillGrow)
                {
                    buffer.Resize(nextBufferBytes);
                }
            }

            return { false, ERROR_MORE_DATA };
        }

        void EnrichServices(SC_HANDLE managerHandle, ServiceCollectionResult& result)
        {
            for (ServiceInfo& service : result.services)
            {
                if (service.serviceName.empty() || service.serviceNameTruncated)
                {
                    SetServiceStatus(service);
                    continue;
                }

                ScHandle serviceHandle(OpenServiceW(
                    managerHandle,
                    service.serviceName.c_str(),
                    SERVICE_QUERY_CONFIG));
                if (serviceHandle)
                {
                    PopulateConfiguration(serviceHandle.Get(), service);
                    PopulateDescription(serviceHandle.Get(), service);
                }
                SetServiceStatus(service);
            }
        }
    }

    bool ServiceStateHasReliableProcessId(std::uint32_t stateRaw)
    {
        return stateRaw == SERVICE_RUNNING || stateRaw == SERVICE_PAUSED;
    }

    bool AssignBoundedServiceText(
        std::wstring& destination,
        std::wstring_view source,
        std::size_t maxCharacters)
    {
        const bool truncated = source.size() > maxCharacters;
        const std::size_t retainedCharacters = truncated ? maxCharacters : source.size();
        if (retainedCharacters == 0)
        {
            destination.clear();
            return truncated;
        }
        destination.assign(source.data(), retainedCharacters);
        return truncated;
    }

    bool RegisterEnumeratedService(ServiceCollectionResult& result)
    {
        ++result.totalEnumerated;
        if (result.services.size() >= ServiceMaxRecords)
        {
            result.truncated = true;
            return false;
        }
        return true;
    }

    void SortServicesByNameCaseInsensitive(std::vector<ServiceInfo>& services)
    {
        std::stable_sort(
            services.begin(),
            services.end(),
            [](const ServiceInfo& left, const ServiceInfo& right)
            {
                const int insensitive = CompareOrdinal(left.serviceName, right.serviceName, true);
                if (insensitive != 0)
                {
                    return insensitive < 0;
                }
                return CompareOrdinal(left.serviceName, right.serviceName, false) < 0;
            });
    }

    void FinalizeServiceCollectionResult(
        ServiceCollectionResult& result,
        bool enumerationCompleted,
        std::uint32_t enumerationError)
    {
        result.attempted = true;
        if (result.totalEnumerated < result.services.size())
        {
            result.totalEnumerated = result.services.size();
        }

        result.configurationUnavailableCount = 0;
        result.descriptionUnavailableCount = 0;
        bool fieldsTruncated = false;
        for (const ServiceInfo& service : result.services)
        {
            if (!service.configurationAvailable)
            {
                ++result.configurationUnavailableCount;
            }
            if (!service.descriptionAvailable)
            {
                ++result.descriptionUnavailableCount;
            }
            fieldsTruncated = fieldsTruncated || ServiceHasTruncatedFields(service);
        }

        if (result.totalEnumerated > result.services.size())
        {
            result.truncated = true;
        }

        result.success = enumerationCompleted;
        result.partial = enumerationCompleted
            ? result.truncated ||
                result.configurationUnavailableCount != 0 ||
                result.descriptionUnavailableCount != 0 ||
                fieldsTruncated
            : !result.services.empty();

        std::wstring status;
        if (enumerationCompleted)
        {
            if (result.truncated)
            {
                const std::size_t omittedCount =
                    result.totalEnumerated > result.services.size()
                        ? result.totalEnumerated - result.services.size()
                        : 0;
                status = L"Enumerated " + std::to_wstring(result.totalEnumerated) +
                    L" SCM-visible active Win32 services; retained " +
                    std::to_wstring(result.services.size()) +
                    L" and omitted " + std::to_wstring(omittedCount) +
                    L" due to the service cap.";
            }
            else
            {
                status = L"Collected " + std::to_wstring(result.services.size()) +
                    L" SCM-visible active Win32 service(s).";
            }
        }
        else
        {
            status = L"SCM-visible active Win32 service enumeration stopped after " +
                std::to_wstring(result.totalEnumerated) +
                L" service(s) (Win32 error " +
                std::to_wstring(enumerationError) + L").";
        }

        if (result.configurationUnavailableCount != 0)
        {
            AppendStatusSentence(
                status,
                L"Configuration metadata was unavailable for " +
                    std::to_wstring(result.configurationUnavailableCount) +
                    L" retained service(s).");
        }
        if (result.descriptionUnavailableCount != 0)
        {
            AppendStatusSentence(
                status,
                L"Description metadata was unavailable for " +
                    std::to_wstring(result.descriptionUnavailableCount) +
                    L" retained service(s).");
        }
        if (fieldsTruncated)
        {
            AppendStatusSentence(
                status,
                L"One or more retained fields were bounded to collection limits.");
        }

        AssignBoundedServiceText(
            result.statusMessage,
            status,
            ServiceMessageMaxCharacters);
    }

    ServiceCollectionResult CollectServiceSnapshot()
    {
        ServiceCollectionResult result;
        result.attempted = true;

        ScHandle managerHandle(OpenSCManagerW(
            nullptr,
            nullptr,
            SC_MANAGER_ENUMERATE_SERVICE));
        if (!managerHandle)
        {
            const DWORD error = GetLastError();
            const std::wstring status =
                L"Could not open the local Service Control Manager (Win32 error " +
                std::to_wstring(error) + L").";
            AssignBoundedServiceText(
                result.statusMessage,
                status,
                ServiceMessageMaxCharacters);
            return result;
        }

        const EnumerationOutcome enumeration =
            EnumerateBaseServices(managerHandle.Get(), result);
        SortServicesByNameCaseInsensitive(result.services);
        EnrichServices(managerHandle.Get(), result);
        result.ReindexCorrelations();
        FinalizeServiceCollectionResult(
            result,
            enumeration.completed,
            enumeration.error);
        return result;
    }
}
