#include "Core/ServiceInfo.h"
#include "Core/ServicePathParser.h"

#include <cstdint>
#include <iostream>
#include <string>
#include <string_view>
#include <utility>

namespace GlassPane::Tests
{
    int RunAuthoritativeTriageTests();
    int RunJsonExporterOfflineTests();
    int RunInspectorPresentationTests();
    int RunHandleCollectorTests(bool runLiveHandles);
    int RunBaselineObservationTests();
    int RunChainAnalysisTests();
    int RunNativeObservationIntegrationTests();
    int RunNativeObservationDomainTests();
    int RunNativeHandleObservationBuilderTests();
    int RunNativeObservationBuilderTests();
    int RunNativeRuntimeObservationBuilderTests();
    int RunNativeSourceEvidenceTests();
    int RunNativeTokenObservationBuilderTests();
    int RunObservationCorrelationTests();
    int RunObservationCoreTests();
    int RunObservationRefinementTests();
    int RunObservationShadowTests();
    int RunPersistedTriageTests();
    int RunProcessTriageCacheTests();
    int RunProcessIconPolicyTests();
    int RunProductVersionTests();
    int RunSelectedProcessEnrichedLifecycleTests();
    int RunSnapshotCompareTriageTests();
    int RunTriageEngineTests();
    int RunServiceCollectorTests(bool runLiveServices);
    int RunSavedSnapshotServiceTests();
    int RunSavedSnapshotNativeEvidenceTests();
    int RunSavedSnapshotTriageTests();
    int RunMarkdownServiceReportTests();
}

namespace
{
    using namespace GlassPane::Core;

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

    ServiceImagePathParseResult ParseLiteral(const std::wstring& imagePath)
    {
        const ServiceEnvironmentExpander expansionMustNotBeNeeded =
            [](std::wstring_view)
            {
                return ServiceEnvironmentExpansionResult{
                    ServiceEnvironmentExpansionStatus::Failed,
                    {}
                };
            };
        return ParseServiceImagePath(imagePath, expansionMustNotBeNeeded);
    }

    void TestEmptyAndWhitespace()
    {
        const ServiceImagePathParseResult empty = ParseLiteral(L"");
        CheckEqual(empty.status, ServicePathParseStatus::Empty, L"empty status");
        CheckEqual(empty.confidence, ServicePathConfidence::None, L"empty confidence");
        Check(empty.executablePath.empty(), L"empty has no executable");
        Check(empty.rawImagePath.empty(), L"empty raw input preserved");
        Check(empty.expandedImagePath.empty(), L"empty expanded input preserved");

        const ServiceImagePathParseResult whitespace = ParseLiteral(L" \t\r\n ");
        CheckEqual(whitespace.status, ServicePathParseStatus::Empty, L"whitespace status");
        CheckEqual(whitespace.rawImagePath, std::wstring(L" \t\r\n "), L"whitespace raw preserved");
        CheckEqual(whitespace.expandedImagePath, whitespace.rawImagePath, L"whitespace expanded preserved");
    }

    void TestQuotedPaths()
    {
        const ServiceImagePathParseResult quoted =
            ParseLiteral(L"\"C:\\Program Files\\App\\Service.exe\"");
        CheckEqual(quoted.status, ServicePathParseStatus::ParsedQuoted, L"quoted status");
        CheckEqual(quoted.confidence, ServicePathConfidence::High, L"quoted confidence");
        CheckEqual(
            quoted.executablePath,
            std::wstring(L"C:\\Program Files\\App\\Service.exe"),
            L"quoted executable");

        const ServiceImagePathParseResult withArguments =
            ParseLiteral(L"\"C:\\Program Files\\App\\Service.exe\" --service --mode test");
        CheckEqual(withArguments.status, ServicePathParseStatus::ParsedQuoted, L"quoted arguments status");
        CheckEqual(
            withArguments.executablePath,
            std::wstring(L"C:\\Program Files\\App\\Service.exe"),
            L"quoted arguments executable");

        const ServiceImagePathParseResult unmatched =
            ParseLiteral(L"\"C:\\Program Files\\App\\Service.exe --service");
        CheckEqual(unmatched.status, ServicePathParseStatus::UnmatchedQuote, L"unmatched quote status");
        CheckEqual(unmatched.confidence, ServicePathConfidence::None, L"unmatched quote confidence");
        Check(unmatched.executablePath.empty(), L"unmatched quote has no executable");

        const ServiceImagePathParseResult adjacentText =
            ParseLiteral(L"\"C:\\Program Files\\App\\Service.exe\"junk -run");
        CheckEqual(
            adjacentText.status,
            ServicePathParseStatus::UnmatchedQuote,
            L"quoted adjacent text status");
        CheckEqual(adjacentText.confidence, ServicePathConfidence::None, L"quoted adjacent text confidence");
        Check(adjacentText.executablePath.empty(), L"quoted adjacent text has no executable");
    }

    void TestUnquotedAndRelativePaths()
    {
        const ServiceImagePathParseResult unquoted =
            ParseLiteral(L"C:\\Windows\\System32\\service.exe -run");
        CheckEqual(unquoted.status, ServicePathParseStatus::ParsedUnquoted, L"unquoted status");
        CheckEqual(unquoted.confidence, ServicePathConfidence::High, L"unquoted confidence");
        CheckEqual(
            unquoted.executablePath,
            std::wstring(L"C:\\Windows\\System32\\service.exe"),
            L"unquoted executable");

        const ServiceImagePathParseResult unquotedNoArguments =
            ParseLiteral(L"C:\\Windows\\System32\\service.exe");
        CheckEqual(
            unquotedNoArguments.status,
            ServicePathParseStatus::ParsedUnquoted,
            L"unquoted no-arguments status");

        const ServiceImagePathParseResult ambiguous =
            ParseLiteral(L"C:\\Program Files\\App\\Service.exe --service");
        CheckEqual(
            ambiguous.status,
            ServicePathParseStatus::AmbiguousUnquoted,
            L"ambiguous unquoted status");
        CheckEqual(ambiguous.confidence, ServicePathConfidence::None, L"ambiguous confidence");
        Check(ambiguous.executablePath.empty(), L"ambiguous has no executable");

        const ServiceImagePathParseResult relative = ParseLiteral(L"service.exe -run");
        CheckEqual(relative.status, ServicePathParseStatus::RelativeExecutable, L"relative status");
        CheckEqual(relative.confidence, ServicePathConfidence::Low, L"relative confidence");
        Check(relative.executablePath.empty(), L"relative has no executable");

        const ServiceImagePathParseResult dotRelative = ParseLiteral(L".\\service.exe");
        CheckEqual(
            dotRelative.status,
            ServicePathParseStatus::RelativeExecutable,
            L"dot-relative status");
        Check(dotRelative.executablePath.empty(), L"dot-relative has no executable");

        const ServiceImagePathParseResult unexpectedQuote =
            ParseLiteral(L"C:\\Windows\\System32\\service.exe\"-run");
        CheckEqual(
            unexpectedQuote.status,
            ServicePathParseStatus::AmbiguousUnquoted,
            L"unexpected unquoted quote status");
        Check(unexpectedQuote.executablePath.empty(), L"unexpected unquoted quote has no executable");
    }

    void TestEnvironmentExpansion()
    {
        const ServiceEnvironmentExpander knownVariable =
            [](std::wstring_view input)
            {
                std::wstring expanded(input);
                const std::wstring variable = L"%GP_TEST_ROOT%";
                const std::size_t position = expanded.find(variable);
                if (position != std::wstring::npos)
                {
                    expanded.replace(position, variable.size(), L"C:\\FixedRoot");
                }
                return ServiceEnvironmentExpansionResult{
                    ServiceEnvironmentExpansionStatus::Success,
                    std::move(expanded)
                };
            };

        const std::wstring raw = L"%GP_TEST_ROOT%\\Service.exe -run";
        const ServiceImagePathParseResult expanded = ParseServiceImagePath(raw, knownVariable);
        CheckEqual(expanded.status, ServicePathParseStatus::ParsedUnquoted, L"environment path status");
        CheckEqual(expanded.rawImagePath, raw, L"environment raw remains separate");
        CheckEqual(
            expanded.expandedImagePath,
            std::wstring(L"C:\\FixedRoot\\Service.exe -run"),
            L"environment expanded input");
        CheckEqual(
            expanded.executablePath,
            std::wstring(L"C:\\FixedRoot\\Service.exe"),
            L"environment executable");

        const ServiceEnvironmentExpander unresolvedVariable =
            [](std::wstring_view input)
            {
                return ServiceEnvironmentExpansionResult{
                    ServiceEnvironmentExpansionStatus::Success,
                    std::wstring(input)
                };
            };
        const ServiceImagePathParseResult unresolved =
            ParseServiceImagePath(L"%GP_UNKNOWN_VARIABLE%\\Service.exe", unresolvedVariable);
        CheckEqual(
            unresolved.status,
            ServicePathParseStatus::UnresolvedEnvironment,
            L"unresolved environment status");
        Check(unresolved.executablePath.empty(), L"unresolved environment has no executable");

        const ServiceEnvironmentExpander failedExpansion =
            [](std::wstring_view)
            {
                return ServiceEnvironmentExpansionResult{
                    ServiceEnvironmentExpansionStatus::Failed,
                    {}
                };
            };
        const ServiceImagePathParseResult failed =
            ParseServiceImagePath(L"%GP_FAILURE%\\Service.exe", failedExpansion);
        CheckEqual(failed.status, ServicePathParseStatus::ExpansionFailed, L"expansion failure status");
        Check(failed.executablePath.empty(), L"expansion failure has no executable");
    }

    void TestPathFormsAndBounds()
    {
        const ServiceImagePathParseResult unc =
            ParseLiteral(L"\"\\\\server\\share\\Service.exe\" -run");
        CheckEqual(unc.status, ServicePathParseStatus::ParsedQuoted, L"UNC status");
        CheckEqual(
            unc.executablePath,
            std::wstring(L"\\\\server\\share\\Service.exe"),
            L"UNC executable");

        const ServiceImagePathParseResult extended =
            ParseLiteral(L"\"\\\\?\\C:\\Program Files\\App\\Service.exe\" -run");
        CheckEqual(extended.status, ServicePathParseStatus::ParsedQuoted, L"extended path status");
        CheckEqual(
            extended.executablePath,
            std::wstring(L"\\\\?\\C:\\Program Files\\App\\Service.exe"),
            L"extended executable");

        const std::wstring unicodeExecutable =
            L"C:\\\u041F\u0440\u043E\u0433\u0440\u0430\u043C\u043C\u044B\\\u670D\u52A1\\Service.exe";
        const ServiceImagePathParseResult unicode =
            ParseLiteral(L"\"" + unicodeExecutable + L"\" --service");
        CheckEqual(unicode.status, ServicePathParseStatus::ParsedQuoted, L"Unicode status");
        CheckEqual(unicode.executablePath, unicodeExecutable, L"Unicode executable preserved");

        const std::wstring tooLong(ServiceImagePathMaxCharacters + 1, L'A');
        const ServiceImagePathParseResult truncated = ParseLiteral(tooLong);
        CheckEqual(truncated.status, ServicePathParseStatus::InputTruncated, L"long input status");
        Check(truncated.rawInputTruncated, L"long input truncation indicator");
        CheckEqual(
            truncated.rawImagePath.size(),
            ServiceImagePathMaxCharacters,
            L"long input bounded raw length");
        Check(truncated.executablePath.empty(), L"long input has no executable");

        const ServiceEnvironmentExpander oversizedExpansion =
            [](std::wstring_view)
            {
                return ServiceEnvironmentExpansionResult{
                    ServiceEnvironmentExpansionStatus::OutputTooLong,
                    std::wstring(ServiceImagePathMaxCharacters + 10, L'X')
                };
            };
        const ServiceImagePathParseResult expandedTooLong =
            ParseServiceImagePath(L"%GP_OVERSIZED%\\Service.exe", oversizedExpansion);
        CheckEqual(
            expandedTooLong.status,
            ServicePathParseStatus::InputTruncated,
            L"oversized expansion status");
        Check(expandedTooLong.expandedInputTruncated, L"oversized expansion indicator");
        CheckEqual(
            expandedTooLong.expandedImagePath.size(),
            ServiceImagePathMaxCharacters,
            L"oversized expansion bounded length");
    }

    void TestSvchostGroupParsing()
    {
        const ServiceImagePathParseResult group =
            ParseLiteral(L"C:\\Windows\\System32\\svchost.exe -k netsvcs -p");
        CheckEqual(group.status, ServicePathParseStatus::ParsedUnquoted, L"svchost status");
        CheckEqual(group.svchostGroup, std::wstring(L"netsvcs"), L"svchost group");

        const ServiceImagePathParseResult quotedGroup =
            ParseLiteral(
                L"\"C:\\Windows\\System32\\svchost.exe\" -k \"Local Service Network Restricted\" -p");
        CheckEqual(
            quotedGroup.svchostGroup,
            std::wstring(L"Local Service Network Restricted"),
            L"quoted svchost group");

        const ServiceImagePathParseResult nonSvchost =
            ParseLiteral(L"C:\\Tools\\worker.exe -k netsvcs");
        Check(nonSvchost.svchostGroup.empty(), L"non-svchost ignores -k");

        const ServiceImagePathParseResult ambiguousSvchost =
            ParseLiteral(L"C:\\Program Files\\svchost.exe -k netsvcs");
        CheckEqual(
            ambiguousSvchost.status,
            ServicePathParseStatus::AmbiguousUnquoted,
            L"ambiguous svchost status");
        Check(ambiguousSvchost.svchostGroup.empty(), L"ambiguous svchost has no group");

        const ServiceImagePathParseResult ambiguousGroup =
            ParseLiteral(L"C:\\Windows\\System32\\svchost.exe -k one -k two");
        Check(ambiguousGroup.svchostGroup.empty(), L"multiple svchost groups rejected");

        const ServiceImagePathParseResult missingGroup =
            ParseLiteral(L"C:\\Windows\\System32\\svchost.exe -k -p");
        Check(missingGroup.svchostGroup.empty(), L"switch-shaped svchost group rejected");
    }

    void TestCorrelationReindexing()
    {
        ServiceCollectionResult collection;
        collection.services.resize(4);

        collection.services[0].scmProcessId = 0;
        collection.services[0].pidReliableForState = true;
        collection.services[1].scmProcessId = 4242;
        collection.services[1].pidReliableForState = true;
        collection.services[2].scmProcessId = 4242;
        collection.services[2].pidReliableForState = true;
        collection.services[3].scmProcessId = 7777;
        collection.services[3].pidReliableForState = false;

        collection.ReindexCorrelations();
        Check(collection.serviceIndexesByPid.find(0) == collection.serviceIndexesByPid.end(), L"PID 0 excluded");
        Check(
            collection.serviceIndexesByPid.find(7777) == collection.serviceIndexesByPid.end(),
            L"unreliable PID excluded");

        const auto sharedPid = collection.serviceIndexesByPid.find(4242);
        Check(sharedPid != collection.serviceIndexesByPid.end(), L"shared PID present");
        if (sharedPid != collection.serviceIndexesByPid.end())
        {
            CheckEqual(sharedPid->second.size(), std::size_t(2), L"shared PID service count");
            CheckEqual(sharedPid->second[0], std::size_t(1), L"shared PID first index");
            CheckEqual(sharedPid->second[1], std::size_t(2), L"shared PID second index");
        }

        collection.ReindexCorrelations();
        CheckEqual(
            collection.serviceIndexesByPid.at(4242).size(),
            std::size_t(2),
            L"reindex is idempotent");

        collection.services[1].pidReliableForState = false;
        collection.services[2].pidReliableForState = false;
        collection.ReindexCorrelations();
        Check(
            collection.serviceIndexesByPid.find(4242) == collection.serviceIndexesByPid.end(),
            L"reindex removes stale PID entries");
    }

    void TestDisplayFormatting()
    {
        CheckEqual(ServiceStateDisplayText(4), std::wstring(L"Running"), L"known state formatting");
        CheckEqual(
            ServiceStateDisplayText(0xDEADBEEF),
            std::wstring(L"Unknown (0xDEADBEEF)"),
            L"unknown state formatting");
        CheckEqual(ServiceStartTypeDisplayText(0), std::wstring(L"Boot"), L"boot start formatting");
        CheckEqual(
            ServiceStartTypeDisplayText(0x80000000),
            std::wstring(L"Unknown (0x80000000)"),
            L"unknown start formatting");
        CheckEqual(
            ServiceTypeDisplayText(0x00000050),
            std::wstring(L"User own process"),
            L"user own composite formatting");
        CheckEqual(
            ServiceTypeDisplayText(0x00000060),
            std::wstring(L"User shared process"),
            L"user shared composite formatting");
        CheckEqual(
            ServiceTypeDisplayText(0x80000010),
            std::wstring(L"Win32 own process | Unknown bits (0x80000000)"),
            L"mixed service type formatting");
        CheckEqual(
            ServiceTypeDisplayText(0x80000000),
            std::wstring(L"Unknown (0x80000000)"),
            L"unknown service type formatting");
        CheckEqual(
            ServiceProcessModelFromType(0x00000050),
            ServiceProcessModel::OwnProcess,
            L"own process model");
        CheckEqual(
            ServiceProcessModelFromType(0x00000060),
            ServiceProcessModel::SharedProcess,
            L"shared process model");
        CheckEqual(
            ServiceProcessModelFromType(0x00000030),
            ServiceProcessModel::Unknown,
            L"conflicting process model");
        CheckEqual(
            ServicePathParseStatusDisplayText(static_cast<ServicePathParseStatus>(0xABCDEF01)),
            std::wstring(L"Unknown (0xABCDEF01)"),
            L"unknown parse status formatting");
        CheckEqual(
            ServicePathConfidenceDisplayText(static_cast<ServicePathConfidence>(0xFFFFFFFF)),
            std::wstring(L"Unknown (0xFFFFFFFF)"),
            L"unknown confidence formatting");

        const ServiceInfo unavailableConfiguration;
        Check(!unavailableConfiguration.configurationAvailable, L"configuration unavailable by default");
        CheckEqual(unavailableConfiguration.startTypeRaw, std::uint32_t(0), L"raw boot value preserved separately");
    }
}

int wmain(int argumentCount, wchar_t* arguments[])
{
    bool runLiveServices = false;
    bool runLiveHandles = false;
    for (int index = 1; index < argumentCount; ++index)
    {
        if (std::wstring_view(arguments[index]) == L"--live-services")
        {
            runLiveServices = true;
        }
        else if (std::wstring_view(arguments[index]) == L"--live-handles")
        {
            runLiveHandles = true;
        }
        else
        {
            Check(false, L"unknown test argument");
        }
    }

    TestEmptyAndWhitespace();
    TestQuotedPaths();
    TestUnquotedAndRelativePaths();
    TestEnvironmentExpansion();
    TestPathFormsAndBounds();
    TestSvchostGroupParsing();
    TestCorrelationReindexing();
    TestDisplayFormatting();
    failureCount += GlassPane::Tests::RunAuthoritativeTriageTests();
    failureCount += GlassPane::Tests::RunJsonExporterOfflineTests();
    failureCount += GlassPane::Tests::RunInspectorPresentationTests();
    failureCount += GlassPane::Tests::RunHandleCollectorTests(runLiveHandles);
    failureCount += GlassPane::Tests::RunBaselineObservationTests();
    failureCount += GlassPane::Tests::RunChainAnalysisTests();
    failureCount += GlassPane::Tests::RunNativeObservationIntegrationTests();
    failureCount += GlassPane::Tests::RunNativeObservationDomainTests();
    failureCount += GlassPane::Tests::RunNativeHandleObservationBuilderTests();
    failureCount += GlassPane::Tests::RunNativeObservationBuilderTests();
    failureCount += GlassPane::Tests::RunNativeRuntimeObservationBuilderTests();
    failureCount += GlassPane::Tests::RunNativeSourceEvidenceTests();
    failureCount += GlassPane::Tests::RunNativeTokenObservationBuilderTests();
    failureCount += GlassPane::Tests::RunObservationCorrelationTests();
    failureCount += GlassPane::Tests::RunObservationCoreTests();
    failureCount += GlassPane::Tests::RunObservationRefinementTests();
    failureCount += GlassPane::Tests::RunObservationShadowTests();
    failureCount += GlassPane::Tests::RunPersistedTriageTests();
    failureCount += GlassPane::Tests::RunProcessTriageCacheTests();
    failureCount += GlassPane::Tests::RunProcessIconPolicyTests();
    failureCount += GlassPane::Tests::RunProductVersionTests();
    failureCount += GlassPane::Tests::RunSelectedProcessEnrichedLifecycleTests();
    failureCount += GlassPane::Tests::RunSnapshotCompareTriageTests();
    failureCount += GlassPane::Tests::RunTriageEngineTests();
    failureCount += GlassPane::Tests::RunServiceCollectorTests(runLiveServices);
    failureCount += GlassPane::Tests::RunSavedSnapshotServiceTests();
    failureCount += GlassPane::Tests::RunSavedSnapshotNativeEvidenceTests();
    failureCount += GlassPane::Tests::RunSavedSnapshotTriageTests();
    failureCount += GlassPane::Tests::RunMarkdownServiceReportTests();

    if (failureCount != 0)
    {
        std::wcerr << failureCount << L" Service Core test(s) failed.\n";
        return 1;
    }

    std::wcout << L"All Core tests passed.\n";
    return 0;
}
