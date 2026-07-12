#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "Core/ServiceCollector.h"

#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
#include <unordered_map>
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
        void CheckEqual(const Value& actual, const Value& expected, const wchar_t* testName)
        {
            Check(actual == expected, testName);
        }

        bool HasTruncatedFields(const ServiceInfo& service)
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

        void MarkMetadataAvailable(ServiceInfo& service)
        {
            service.configurationAvailable = true;
            service.descriptionAvailable = true;
        }

        void TestPidReliabilityRules()
        {
            Check(!ServiceStateHasReliableProcessId(SERVICE_STOPPED), L"stopped PID is unreliable");
            Check(!ServiceStateHasReliableProcessId(SERVICE_START_PENDING), L"start-pending PID is unreliable");
            Check(!ServiceStateHasReliableProcessId(SERVICE_STOP_PENDING), L"stop-pending PID is unreliable");
            Check(ServiceStateHasReliableProcessId(SERVICE_RUNNING), L"running PID is reliable");
            Check(!ServiceStateHasReliableProcessId(SERVICE_CONTINUE_PENDING), L"continue-pending PID is conservative");
            Check(!ServiceStateHasReliableProcessId(SERVICE_PAUSE_PENDING), L"pause-pending PID is conservative");
            Check(ServiceStateHasReliableProcessId(SERVICE_PAUSED), L"paused PID is reliable");
            Check(!ServiceStateHasReliableProcessId(0xFFFFFFFF), L"unknown state PID is unreliable");
        }

        void TestBoundedText()
        {
            std::wstring destination = L"old";
            Check(!AssignBoundedServiceText(destination, L"four", 4), L"exact-cap text is not truncated");
            CheckEqual(destination, std::wstring(L"four"), L"exact-cap text preserved");

            Check(AssignBoundedServiceText(destination, L"12345", 4), L"over-cap text reports truncation");
            CheckEqual(destination, std::wstring(L"1234"), L"over-cap text bounded");

            Check(AssignBoundedServiceText(destination, L"x", 0), L"zero-cap text reports truncation");
            Check(destination.empty(), L"zero-cap text clears destination");

            Check(!AssignBoundedServiceText(destination, L"", 4), L"empty text is not truncated");
            Check(destination.empty(), L"empty text remains empty");
        }

        void TestServiceRecordRetentionCap()
        {
            ServiceCollectionResult result;
            for (std::size_t index = 0; index < ServiceMaxRecords + 2; ++index)
            {
                if (RegisterEnumeratedService(result))
                {
                    result.services.emplace_back();
                }
            }

            CheckEqual(
                result.services.size(),
                ServiceMaxRecords,
                L"service record retention cap");
            CheckEqual(
                result.totalEnumerated,
                ServiceMaxRecords + 2,
                L"service record total includes omitted rows");
            Check(result.truncated, L"service record cap marks truncation");
        }

        void TestDeterministicServiceSorting()
        {
            std::vector<ServiceInfo> services(4);
            services[0].serviceName = L"Zulu";
            services[1].serviceName = L"alpha";
            services[2].serviceName = L"BRAVO";
            services[3].serviceName = L"charlie";

            SortServicesByNameCaseInsensitive(services);
            CheckEqual(services[0].serviceName, std::wstring(L"alpha"), L"sorted alpha first");
            CheckEqual(services[1].serviceName, std::wstring(L"BRAVO"), L"sorted bravo second");
            CheckEqual(services[2].serviceName, std::wstring(L"charlie"), L"sorted charlie third");
            CheckEqual(services[3].serviceName, std::wstring(L"Zulu"), L"sorted zulu fourth");

            const std::vector<ServiceInfo> onceSorted = services;
            SortServicesByNameCaseInsensitive(services);
            for (std::size_t index = 0; index < services.size(); ++index)
            {
                CheckEqual(
                    services[index].serviceName,
                    onceSorted[index].serviceName,
                    L"service sorting is deterministic");
            }
        }

        void TestSyntheticCollectorCorrelation()
        {
            ServiceCollectionResult result;
            result.services.resize(4);

            result.services[0].stateRaw = SERVICE_RUNNING;
            result.services[0].scmProcessId = 9000;
            result.services[0].pidReliableForState =
                result.services[0].scmProcessId != 0 &&
                ServiceStateHasReliableProcessId(result.services[0].stateRaw);

            result.services[1].stateRaw = SERVICE_RUNNING;
            result.services[1].scmProcessId = 9000;
            result.services[1].pidReliableForState =
                result.services[1].scmProcessId != 0 &&
                ServiceStateHasReliableProcessId(result.services[1].stateRaw);

            result.services[2].stateRaw = SERVICE_START_PENDING;
            result.services[2].scmProcessId = 9001;
            result.services[2].pidReliableForState =
                result.services[2].scmProcessId != 0 &&
                ServiceStateHasReliableProcessId(result.services[2].stateRaw);

            result.services[3].stateRaw = SERVICE_RUNNING;
            result.services[3].scmProcessId = 0;
            result.services[3].pidReliableForState = false;

            result.ReindexCorrelations();
            CheckEqual(result.serviceIndexesByPid.size(), std::size_t(1), L"only reliable PID indexed");
            CheckEqual(result.serviceIndexesByPid.at(9000).size(), std::size_t(2), L"shared PID has two services");
            CheckEqual(result.serviceIndexesByPid.at(9000)[0], std::size_t(0), L"shared PID first service index");
            CheckEqual(result.serviceIndexesByPid.at(9000)[1], std::size_t(1), L"shared PID second service index");
            Check(result.serviceIndexesByPid.find(0) == result.serviceIndexesByPid.end(), L"synthetic PID 0 excluded");
            Check(result.serviceIndexesByPid.find(9001) == result.serviceIndexesByPid.end(), L"pending PID excluded");
        }

        void TestAggregateResultFinalization()
        {
            ServiceCollectionResult complete;
            complete.services.resize(2);
            MarkMetadataAvailable(complete.services[0]);
            MarkMetadataAvailable(complete.services[1]);
            complete.totalEnumerated = 2;
            FinalizeServiceCollectionResult(complete, true, ERROR_SUCCESS);
            Check(complete.attempted, L"complete result attempted");
            Check(complete.success, L"complete result success");
            Check(!complete.partial, L"complete result not partial");
            CheckEqual(complete.configurationUnavailableCount, std::size_t(0), L"complete config count");
            CheckEqual(complete.descriptionUnavailableCount, std::size_t(0), L"complete description count");

            ServiceCollectionResult omitted;
            omitted.services.resize(2);
            MarkMetadataAvailable(omitted.services[0]);
            MarkMetadataAvailable(omitted.services[1]);
            omitted.totalEnumerated = 5;
            FinalizeServiceCollectionResult(omitted, true, ERROR_SUCCESS);
            Check(omitted.success, L"omitted-row enumeration remains successful");
            Check(omitted.partial, L"omitted-row result is partial");
            Check(omitted.truncated, L"omitted-row result infers truncation");
            CheckEqual(omitted.configurationUnavailableCount, std::size_t(0), L"omitted-row config count");
            CheckEqual(omitted.descriptionUnavailableCount, std::size_t(0), L"omitted-row description count");
            Check(omitted.statusMessage.find(L"omitted 3") != std::wstring::npos, L"omitted-row count status");
            Check(omitted.statusMessage.size() <= ServiceMessageMaxCharacters, L"omitted-row aggregate message cap");

            ServiceCollectionResult missingDescription;
            missingDescription.services.resize(1);
            MarkMetadataAvailable(missingDescription.services[0]);
            missingDescription.services[0].descriptionAvailable = false;
            missingDescription.totalEnumerated = 1;
            FinalizeServiceCollectionResult(missingDescription, true, ERROR_SUCCESS);
            Check(missingDescription.success, L"missing-description enumeration successful");
            Check(missingDescription.partial, L"missing-description result partial");
            Check(!missingDescription.truncated, L"missing-description result not record-truncated");
            CheckEqual(
                missingDescription.descriptionUnavailableCount,
                std::size_t(1),
                L"missing-description count");

            ServiceCollectionResult boundedField;
            boundedField.services.resize(1);
            MarkMetadataAvailable(boundedField.services[0]);
            boundedField.services[0].displayNameTruncated = true;
            boundedField.totalEnumerated = 1;
            FinalizeServiceCollectionResult(boundedField, true, ERROR_SUCCESS);
            Check(boundedField.success, L"bounded-field enumeration successful");
            Check(boundedField.partial, L"bounded-field result partial");
            Check(!boundedField.truncated, L"bounded-field result not record-truncated");
            CheckEqual(boundedField.configurationUnavailableCount, std::size_t(0), L"bounded-field config count");
            CheckEqual(boundedField.descriptionUnavailableCount, std::size_t(0), L"bounded-field description count");

            ServiceCollectionResult failedEmpty;
            FinalizeServiceCollectionResult(failedEmpty, false, ERROR_ACCESS_DENIED);
            Check(failedEmpty.attempted, L"failed empty attempted");
            Check(!failedEmpty.success, L"failed empty not successful");
            Check(!failedEmpty.partial, L"failed empty not partial");
            Check(
                failedEmpty.statusMessage.find(L"Win32 error 5") != std::wstring::npos,
                L"failed empty error status");

            ServiceCollectionResult failedWithRow;
            failedWithRow.services.resize(1);
            MarkMetadataAvailable(failedWithRow.services[0]);
            failedWithRow.totalEnumerated = 1;
            FinalizeServiceCollectionResult(failedWithRow, false, ERROR_MORE_DATA);
            Check(!failedWithRow.success, L"failed row not successful");
            Check(failedWithRow.partial, L"failed row is partial");
        }

        bool ServicesHaveSameOrder(
            const std::vector<ServiceInfo>& left,
            const std::vector<ServiceInfo>& right)
        {
            if (left.size() != right.size())
            {
                return false;
            }
            for (std::size_t index = 0; index < left.size(); ++index)
            {
                if (left[index].serviceName != right[index].serviceName)
                {
                    return false;
                }
            }
            return true;
        }

        void ValidateLiveCollection(const ServiceCollectionResult& result)
        {
            Check(result.attempted, L"live collection attempted");
            Check(result.success, L"live service enumeration succeeded");
            Check(result.services.size() <= ServiceMaxRecords, L"live service count cap");
            Check(result.totalEnumerated >= result.services.size(), L"live total count covers retained rows");
            Check(result.statusMessage.size() <= ServiceMessageMaxCharacters, L"live aggregate message cap");
            Check(result.serviceIndexesByPid.find(0) == result.serviceIndexesByPid.end(), L"live PID 0 not indexed");

            std::vector<ServiceInfo> sorted = result.services;
            SortServicesByNameCaseInsensitive(sorted);
            Check(ServicesHaveSameOrder(result.services, sorted), L"live services sorted by name");

            std::size_t unavailableConfigurations = 0;
            std::size_t unavailableDescriptions = 0;
            bool anyFieldTruncated = false;
            std::vector<bool> indexed(result.services.size(), false);
            for (std::size_t index = 0; index < result.services.size(); ++index)
            {
                const ServiceInfo& service = result.services[index];
                Check(!service.serviceName.empty(), L"live service name is nonempty");
                Check(service.serviceName.size() <= ServiceNameMaxCharacters, L"live service-name cap");
                Check(service.displayName.size() <= ServiceDisplayNameMaxCharacters, L"live display-name cap");
                Check(service.description.size() <= ServiceDescriptionMaxCharacters, L"live description cap");
                Check(service.serviceAccount.size() <= ServiceAccountMaxCharacters, L"live account cap");
                Check(service.rawImagePath.size() <= ServiceImagePathMaxCharacters, L"live raw ImagePath cap");
                Check(service.expandedImagePath.size() <= ServiceImagePathMaxCharacters, L"live expanded ImagePath cap");
                Check(service.executablePath.size() <= ServiceImagePathMaxCharacters, L"live executable cap");
                Check(service.svchostGroup.size() <= ServiceSvchostGroupMaxCharacters, L"live svchost group cap");
                Check(service.pathParseMessage.size() <= ServiceMessageMaxCharacters, L"live parse message cap");
                Check(service.statusMessage.size() <= ServiceMessageMaxCharacters, L"live service status cap");
                Check((service.serviceTypeRaw & SERVICE_WIN32) != 0, L"live row is Win32 service");
                Check(service.stateRaw != SERVICE_STOPPED, L"live row was active when enumerated");
                CheckEqual(
                    service.processModel,
                    ServiceProcessModelFromType(service.serviceTypeRaw),
                    L"live process model matches service type");
                CheckEqual(
                    service.pidReliableForState,
                    service.scmProcessId != 0 && ServiceStateHasReliableProcessId(service.stateRaw),
                    L"live PID reliability rule");

                if (!service.configurationAvailable)
                {
                    ++unavailableConfigurations;
                    Check(service.rawImagePath.empty(), L"unavailable config has no raw ImagePath");
                    Check(service.expandedImagePath.empty(), L"unavailable config has no expanded ImagePath");
                    Check(service.executablePath.empty(), L"unavailable config has no executable");
                    CheckEqual(
                        service.pathParseStatus,
                        ServicePathParseStatus::NotAttempted,
                        L"unavailable config parser not attempted");
                }
                else
                {
                    Check(
                        service.pathParseStatus != ServicePathParseStatus::NotAttempted,
                        L"available config parser attempted");
                }

                if (!service.descriptionAvailable)
                {
                    ++unavailableDescriptions;
                    Check(service.description.empty(), L"unavailable description is empty");
                }
                anyFieldTruncated = anyFieldTruncated || HasTruncatedFields(service);

                if (!service.executablePath.empty())
                {
                    CheckEqual(
                        service.pathConfidence,
                        ServicePathConfidence::High,
                        L"live executable has high-confidence parse");
                    Check(
                        service.pathParseStatus == ServicePathParseStatus::ParsedQuoted ||
                            service.pathParseStatus == ServicePathParseStatus::ParsedUnquoted,
                        L"live executable has parsed status");
                }
            }

            CheckEqual(
                result.configurationUnavailableCount,
                unavailableConfigurations,
                L"live configuration unavailable count");
            CheckEqual(
                result.descriptionUnavailableCount,
                unavailableDescriptions,
                L"live description unavailable count");
            const bool expectedPartial = result.truncated ||
                unavailableConfigurations != 0 ||
                unavailableDescriptions != 0 ||
                anyFieldTruncated;
            CheckEqual(result.partial, expectedPartial, L"live partial-result semantics");

            for (const auto& entry : result.serviceIndexesByPid)
            {
                Check(entry.first != 0, L"live correlation key nonzero");
                for (std::size_t index : entry.second)
                {
                    Check(index < result.services.size(), L"live correlation index in range");
                    if (index < result.services.size())
                    {
                        Check(!indexed[index], L"live service index appears once");
                        indexed[index] = true;
                        const ServiceInfo& service = result.services[index];
                        CheckEqual(service.scmProcessId, entry.first, L"live correlation PID matches row");
                        Check(service.pidReliableForState, L"live correlated row marked reliable");
                    }
                }
            }

            ServiceCollectionResult rebuilt = result;
            rebuilt.ReindexCorrelations();
            CheckEqual(
                rebuilt.serviceIndexesByPid,
                result.serviceIndexesByPid,
                L"live correlation reindex is exact");
        }

        void TestLiveCollectionAndHandleLifetime()
        {
            const ServiceCollectionResult warmup = CollectServiceSnapshot();
            ValidateLiveCollection(warmup);
            if (!warmup.success)
            {
                return;
            }

            DWORD handlesBefore = 0;
            Check(
                GetProcessHandleCount(GetCurrentProcess(), &handlesBefore) != FALSE,
                L"live handle-count baseline");

            for (int iteration = 0; iteration < 6; ++iteration)
            {
                const ServiceCollectionResult repeated = CollectServiceSnapshot();
                Check(repeated.attempted, L"repeated live collection attempted");
                Check(repeated.success, L"repeated live enumeration succeeded");
            }

            DWORD handlesAfter = 0;
            Check(
                GetProcessHandleCount(GetCurrentProcess(), &handlesAfter) != FALSE,
                L"live handle-count final");
            Check(
                handlesAfter <= handlesBefore + 2,
                L"repeated live collection does not leak SCM handles");
        }
    }

    int RunServiceCollectorTests(bool runLiveServices)
    {
        failureCount = 0;
        TestPidReliabilityRules();
        TestBoundedText();
        TestServiceRecordRetentionCap();
        TestDeterministicServiceSorting();
        TestSyntheticCollectorCorrelation();
        TestAggregateResultFinalization();
        if (runLiveServices)
        {
            TestLiveCollectionAndHandleLifetime();
        }
        return failureCount;
    }
}
