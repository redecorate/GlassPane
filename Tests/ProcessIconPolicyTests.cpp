#include "Core/ProcessIconPolicy.h"

#include <iostream>
#include <string>
#include <unordered_map>

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

        ProcessIconRequest LiveRequest()
        {
            ProcessIconRequest request;
            request.pid = 42;
            request.hasCreationTime = true;
            request.creationTimeFileTime = 1001;
            request.executablePath =
                L"C:/Program Files/Generic/Process.exe";
            request.scope = ProcessIconScope::Live;
            request.generation = 9;
            return request;
        }

        void TestPathNormalizationAndStableKey()
        {
            ProcessIconRequest first = LiveRequest();
            ProcessIconRequest second = first;
            second.executablePath =
                L"c:\\program files\\generic\\process.EXE";

            const ProcessIconCacheKey firstKey =
                BuildProcessIconCacheKey(first);
            const ProcessIconCacheKey secondKey =
                BuildProcessIconCacheKey(second);
            CheckEqual(firstKey, secondKey, L"icon cache key normalizes Windows path case and separators");
            CheckEqual(
                ProcessIconCacheKeyHash{}(firstKey),
                ProcessIconCacheKeyHash{}(secondKey),
                L"equal icon cache keys have equal hashes");

            std::unordered_map<
                ProcessIconCacheKey,
                int,
                ProcessIconCacheKeyHash> cache;
            cache.emplace(firstKey, 7);
            CheckEqual(cache.at(secondKey), 7, L"normalized icon cache key supports deterministic lookup");
        }

        void TestIdentityPathScopeAndGenerationInvalidation()
        {
            const ProcessIconRequest original = LiveRequest();
            const ProcessIconCacheKey originalKey =
                BuildProcessIconCacheKey(original);

            ProcessIconRequest reusedPid = original;
            reusedPid.creationTimeFileTime += 1;
            Check(
                BuildProcessIconCacheKey(reusedPid) != originalKey,
                L"PID reuse changes icon cache key");

            ProcessIconRequest changedPath = original;
            changedPath.executablePath = L"C:\\Other\\Process.exe";
            Check(
                BuildProcessIconCacheKey(changedPath) != originalKey,
                L"path change changes icon cache key");

            ProcessIconRequest loadedSnapshot = original;
            loadedSnapshot.scope = ProcessIconScope::LoadedSnapshot;
            Check(
                BuildProcessIconCacheKey(loadedSnapshot) != originalKey,
                L"loaded snapshot scope changes icon cache key");

            ProcessIconRequest nextGeneration = original;
            ++nextGeneration.generation;
            Check(
                BuildProcessIconCacheKey(nextGeneration) != originalKey,
                L"source generation changes icon cache key");

            ProcessIconRequest noCreationTime = original;
            noCreationTime.hasCreationTime = false;
            noCreationTime.creationTimeFileTime = 999999;
            const ProcessIconCacheKey noCreationKey =
                BuildProcessIconCacheKey(noCreationTime);
            CheckEqual(
                noCreationKey.creationTimeFileTime,
                std::uint64_t{0},
                L"unavailable creation time cannot leak into icon identity");
        }

        void TestExtractionEligibility()
        {
            ProcessIconRequest request = LiveRequest();
            Check(
                ShouldAttemptProcessIconExtraction(request),
                L"live process with path is extraction eligible");

            request.executablePath.clear();
            Check(
                !ShouldAttemptProcessIconExtraction(request),
                L"missing path skips process icon extraction");

            request = LiveRequest();
            request.scope = ProcessIconScope::LoadedSnapshot;
            Check(
                !ShouldAttemptProcessIconExtraction(request),
                L"loaded snapshot performs zero live icon extraction");
        }

        void TestExtractedIconWinsOverFallback()
        {
            ProcessIconSelectionInput input;
            input.extractionAttempted = true;
            input.extractionSucceeded = true;
            input.extractedTextureAvailable = true;
            input.genericFallbackTextureAvailable = true;

            const ProcessIconSelection selection =
                SelectProcessIcon(LiveRequest(), input);
            CheckEqual(selection.state, ProcessIconState::Extracted, L"valid extracted icon wins over fallback");
            CheckEqual(
                selection.ownership,
                ProcessIconTextureOwnership::CacheOwnedExtracted,
                L"extracted icon is owned by process cache");
            Check(selection.useExtractedTexture, L"extracted texture selected");
            Check(!selection.useGenericFallbackTexture, L"fallback not selected when extraction succeeds");
        }

        void TestGenericFallbackForMissingOrFailedExtraction()
        {
            ProcessIconSelectionInput failedInput;
            failedInput.extractionAttempted = true;
            failedInput.genericFallbackTextureAvailable = true;
            const ProcessIconSelection failedSelection =
                SelectProcessIcon(LiveRequest(), failedInput);
            CheckEqual(
                failedSelection.state,
                ProcessIconState::GenericFallback,
                L"failed extraction uses neutral generic fallback");
            CheckEqual(
                failedSelection.ownership,
                ProcessIconTextureOwnership::SharedGenericFallback,
                L"generic fallback is shared rather than entry-owned");

            ProcessIconRequest missingPath = LiveRequest();
            missingPath.executablePath.clear();
            ProcessIconSelectionInput missingInput;
            missingInput.genericFallbackTextureAvailable = true;
            const ProcessIconSelection missingSelection =
                SelectProcessIcon(missingPath, missingInput);
            CheckEqual(
                missingSelection.state,
                ProcessIconState::GenericFallback,
                L"missing executable path uses generic fallback");
            Check(
                !missingSelection.extractionEligible,
                L"missing path fallback performs no extraction");
        }

        void TestOfflineFallbackIgnoresExtractionClaims()
        {
            ProcessIconRequest request = LiveRequest();
            request.scope = ProcessIconScope::LoadedSnapshot;
            ProcessIconSelectionInput input;
            input.extractionAttempted = true;
            input.extractionSucceeded = true;
            input.extractedTextureAvailable = true;
            input.genericFallbackTextureAvailable = true;

            const ProcessIconSelection selection =
                SelectProcessIcon(request, input);
            CheckEqual(
                selection.state,
                ProcessIconState::GenericFallback,
                L"loaded snapshot cannot borrow a live extracted icon");
            Check(!selection.extractionEligible, L"offline selection records zero extraction eligibility");
        }

        void TestUnavailableAndFailedStates()
        {
            ProcessIconSelectionInput noDevice;
            noDevice.renderingDeviceAvailable = false;
            noDevice.genericFallbackTextureAvailable = true;
            CheckEqual(
                SelectProcessIcon(LiveRequest(), noDevice).state,
                ProcessIconState::Unavailable,
                L"missing render device is unavailable");

            ProcessIconSelectionInput failed;
            failed.extractionAttempted = true;
            CheckEqual(
                SelectProcessIcon(LiveRequest(), failed).state,
                ProcessIconState::Failed,
                L"failed extraction and failed fallback creation report failed");

            ProcessIconRequest missingPath = LiveRequest();
            missingPath.executablePath.clear();
            CheckEqual(
                SelectProcessIcon(missingPath, {}).state,
                ProcessIconState::Unavailable,
                L"missing path and unavailable fallback report unavailable");
        }

        void TestRefreshAndDeviceOwnershipRules()
        {
            const ProcessIconRefreshPolicy generation =
                GetProcessIconRefreshPolicy(
                    ProcessIconRefreshKind::ProcessGenerationChanged);
            Check(generation.clearProcessEntries, L"process refresh clears icon entries");
            Check(generation.releaseOwnedExtractedTextures, L"process refresh releases owned extracted textures");
            Check(
                !generation.releaseSharedGenericFallbackTexture,
                L"process refresh reuses cached generic fallback");

            const ProcessIconRefreshPolicy scope =
                GetProcessIconRefreshPolicy(ProcessIconRefreshKind::ScopeChanged);
            Check(scope.clearProcessEntries, L"scope change clears icon entries");
            Check(
                !scope.releaseSharedGenericFallbackTexture,
                L"scope change reuses device-valid generic fallback");

            const ProcessIconRefreshPolicy device =
                GetProcessIconRefreshPolicy(
                    ProcessIconRefreshKind::RenderingDeviceRecreated);
            Check(device.clearProcessEntries, L"device recreation clears icon entries");
            Check(device.releaseOwnedExtractedTextures, L"device recreation releases extracted textures");
            Check(device.releaseSharedGenericFallbackTexture, L"device recreation rebuilds generic fallback");

            const ProcessIconRefreshPolicy shutdown =
                GetProcessIconRefreshPolicy(ProcessIconRefreshKind::Shutdown);
            Check(shutdown.releaseSharedGenericFallbackTexture, L"shutdown releases generic fallback exactly once");
        }
    }

    int RunProcessIconPolicyTests()
    {
        failureCount = 0;
        TestPathNormalizationAndStableKey();
        TestIdentityPathScopeAndGenerationInvalidation();
        TestExtractionEligibility();
        TestExtractedIconWinsOverFallback();
        TestGenericFallbackForMissingOrFailedExtraction();
        TestOfflineFallbackIgnoresExtractionClaims();
        TestUnavailableAndFailedStates();
        TestRefreshAndDeviceOwnershipRules();
        return failureCount;
    }
}
