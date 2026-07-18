#include "ProcessIconPolicy.h"

#include <cwctype>
#include <functional>
#include <tuple>

namespace GlassPane::Core
{
    namespace
    {
        template <typename Value>
        void HashCombine(std::size_t& seed, const Value& value) noexcept
        {
            const std::size_t hashed = std::hash<Value>{}(value);
            seed ^= hashed + static_cast<std::size_t>(0x9e3779b9U) +
                (seed << 6U) + (seed >> 2U);
        }
    }

    bool operator==(
        const ProcessIconCacheKey& left,
        const ProcessIconCacheKey& right)
    {
        return left.pid == right.pid &&
            left.hasCreationTime == right.hasCreationTime &&
            (!left.hasCreationTime ||
                left.creationTimeFileTime == right.creationTimeFileTime) &&
            left.normalizedExecutablePath == right.normalizedExecutablePath &&
            left.scope == right.scope &&
            left.generation == right.generation;
    }

    bool operator!=(
        const ProcessIconCacheKey& left,
        const ProcessIconCacheKey& right)
    {
        return !(left == right);
    }

    bool operator<(
        const ProcessIconCacheKey& left,
        const ProcessIconCacheKey& right)
    {
        const std::uint64_t leftCreationTime = left.hasCreationTime
            ? left.creationTimeFileTime
            : 0;
        const std::uint64_t rightCreationTime = right.hasCreationTime
            ? right.creationTimeFileTime
            : 0;
        return std::tie(
                left.pid,
                left.hasCreationTime,
                leftCreationTime,
                left.normalizedExecutablePath,
                left.scope,
                left.generation) <
            std::tie(
                right.pid,
                right.hasCreationTime,
                rightCreationTime,
                right.normalizedExecutablePath,
                right.scope,
                right.generation);
    }

    std::size_t ProcessIconCacheKeyHash::operator()(
        const ProcessIconCacheKey& key) const noexcept
    {
        std::size_t seed = 0;
        HashCombine(seed, key.pid);
        HashCombine(seed, key.hasCreationTime);
        HashCombine(
            seed,
            key.hasCreationTime ? key.creationTimeFileTime : 0U);
        HashCombine(seed, key.normalizedExecutablePath);
        HashCombine(seed, static_cast<std::uint32_t>(key.scope));
        HashCombine(seed, key.generation);
        return seed;
    }

    std::wstring NormalizeProcessIconExecutablePath(
        const std::wstring& executablePath)
    {
        std::wstring normalized = executablePath;
        for (wchar_t& character : normalized)
        {
            if (character == L'/')
            {
                character = L'\\';
            }
            else
            {
                character =
                    static_cast<wchar_t>(std::towlower(character));
            }
        }
        return normalized;
    }

    ProcessIconCacheKey BuildProcessIconCacheKey(
        const ProcessIconRequest& request)
    {
        ProcessIconCacheKey key;
        key.pid = request.pid;
        key.hasCreationTime = request.hasCreationTime;
        key.creationTimeFileTime = request.hasCreationTime
            ? request.creationTimeFileTime
            : 0;
        key.normalizedExecutablePath =
            NormalizeProcessIconExecutablePath(request.executablePath);
        key.scope = request.scope;
        key.generation = request.generation;
        return key;
    }

    bool ShouldAttemptProcessIconExtraction(
        const ProcessIconRequest& request)
    {
        return request.scope == ProcessIconScope::Live &&
            !request.executablePath.empty();
    }

    ProcessIconSelection SelectProcessIcon(
        const ProcessIconRequest& request,
        const ProcessIconSelectionInput& input)
    {
        ProcessIconSelection selection;
        selection.extractionEligible =
            ShouldAttemptProcessIconExtraction(request);

        if (!input.renderingDeviceAvailable)
        {
            selection.state = ProcessIconState::Unavailable;
            return selection;
        }

        if (selection.extractionEligible &&
            input.extractionAttempted &&
            input.extractionSucceeded &&
            input.extractedTextureAvailable)
        {
            selection.state = ProcessIconState::Extracted;
            selection.ownership =
                ProcessIconTextureOwnership::CacheOwnedExtracted;
            selection.useExtractedTexture = true;
            return selection;
        }

        if (input.genericFallbackTextureAvailable)
        {
            selection.state = ProcessIconState::GenericFallback;
            selection.ownership =
                ProcessIconTextureOwnership::SharedGenericFallback;
            selection.useGenericFallbackTexture = true;
            return selection;
        }

        selection.state =
            selection.extractionEligible && input.extractionAttempted
                ? ProcessIconState::Failed
                : ProcessIconState::Unavailable;
        return selection;
    }

    ProcessIconRefreshPolicy GetProcessIconRefreshPolicy(
        ProcessIconRefreshKind kind)
    {
        ProcessIconRefreshPolicy policy;
        policy.releaseSharedGenericFallbackTexture =
            kind == ProcessIconRefreshKind::RenderingDeviceRecreated ||
            kind == ProcessIconRefreshKind::Shutdown;
        return policy;
    }
}
