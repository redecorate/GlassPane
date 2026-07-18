#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace GlassPane::Core
{
    // Presentation-neutral result states. Texture creation and rendering stay
    // with the UI owner; this contract only describes which source won.
    enum class ProcessIconState : std::uint32_t
    {
        Extracted = 0,
        GenericFallback = 1,
        Unavailable = 2,
        Failed = 3
    };

    enum class ProcessIconScope : std::uint32_t
    {
        Live = 0,
        LoadedSnapshot = 1
    };

    enum class ProcessIconTextureOwnership : std::uint32_t
    {
        None = 0,
        CacheOwnedExtracted = 1,
        SharedGenericFallback = 2
    };

    // A request is value-owned and identifies the exact process/scope whose
    // icon may be displayed. A generation change deliberately invalidates a
    // prior result even when PID and path happen to be unchanged.
    struct ProcessIconRequest
    {
        std::uint32_t pid = 0;
        bool hasCreationTime = false;
        std::uint64_t creationTimeFileTime = 0;
        std::wstring executablePath;
        ProcessIconScope scope = ProcessIconScope::Live;
        std::uint64_t generation = 0;
    };

    struct ProcessIconCacheKey
    {
        std::uint32_t pid = 0;
        bool hasCreationTime = false;
        std::uint64_t creationTimeFileTime = 0;
        std::wstring normalizedExecutablePath;
        ProcessIconScope scope = ProcessIconScope::Live;
        std::uint64_t generation = 0;
    };

    bool operator==(
        const ProcessIconCacheKey& left,
        const ProcessIconCacheKey& right);
    bool operator!=(
        const ProcessIconCacheKey& left,
        const ProcessIconCacheKey& right);
    bool operator<(
        const ProcessIconCacheKey& left,
        const ProcessIconCacheKey& right);

    struct ProcessIconCacheKeyHash
    {
        std::size_t operator()(const ProcessIconCacheKey& key) const noexcept;
    };

    std::wstring NormalizeProcessIconExecutablePath(
        const std::wstring& executablePath);
    ProcessIconCacheKey BuildProcessIconCacheKey(
        const ProcessIconRequest& request);
    bool ShouldAttemptProcessIconExtraction(
        const ProcessIconRequest& request);

    // Inputs describe the result of one bounded resolver attempt. An
    // extracted texture always wins; otherwise a single shared neutral
    // fallback is preferred. A loaded snapshot is never extraction-eligible.
    struct ProcessIconSelectionInput
    {
        bool renderingDeviceAvailable = true;
        bool extractionAttempted = false;
        bool extractionSucceeded = false;
        bool extractedTextureAvailable = false;
        bool genericFallbackTextureAvailable = false;
    };

    struct ProcessIconSelection
    {
        ProcessIconState state = ProcessIconState::Unavailable;
        ProcessIconTextureOwnership ownership =
            ProcessIconTextureOwnership::None;
        bool extractionEligible = false;
        bool useExtractedTexture = false;
        bool useGenericFallbackTexture = false;
    };

    ProcessIconSelection SelectProcessIcon(
        const ProcessIconRequest& request,
        const ProcessIconSelectionInput& input);

    enum class ProcessIconRefreshKind : std::uint32_t
    {
        ProcessGenerationChanged = 0,
        ScopeChanged = 1,
        RenderingDeviceRecreated = 2,
        Shutdown = 3
    };

    struct ProcessIconRefreshPolicy
    {
        bool clearProcessEntries = true;
        bool releaseOwnedExtractedTextures = true;
        bool releaseSharedGenericFallbackTexture = false;
    };

    // Snapshot/scope refreshes discard per-process results but retain the one
    // device-valid generic texture. Device recreation and shutdown release it
    // exactly once so it can be rebuilt lazily for the next device.
    ProcessIconRefreshPolicy GetProcessIconRefreshPolicy(
        ProcessIconRefreshKind kind);
}
