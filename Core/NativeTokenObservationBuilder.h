#pragma once

#include "ObservationInventory.h"
#include "ProcessTriageCache.h"
#include "TokenInfo.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace GlassPane::Core
{
    constexpr std::size_t NativeTokenObservationMaxPrivileges = 512;
    constexpr std::size_t NativeTokenObservationMaxLimitations =
        ObservationMaxLimitationItems;
    constexpr std::size_t NativeTokenObservationSemanticKeyMaxCharacters = 256;
    constexpr std::size_t NativeTokenObservationDiagnosticMaxCharacters = 1024;

    inline constexpr char NativeTokenMappingIdentity[] = "native.token.identity";
    inline constexpr char NativeTokenMappingSession[] = "native.token.session";
    inline constexpr char NativeTokenMappingIntegrity[] = "native.token.integrity";
    inline constexpr char NativeTokenMappingElevation[] = "native.token.elevation";
    inline constexpr char NativeTokenMappingType[] = "native.token.type";
    inline constexpr char NativeTokenMappingAppContainer[] = "native.token.app-container";
    inline constexpr char NativeTokenMappingPrivilege[] = "native.token.privilege-state";
    inline constexpr char NativeTokenMappingDebugPrivilegeEnabled[] =
        "native.token.privilege.debug-enabled";
    inline constexpr char NativeTokenMappingCollectionFailure[] =
        "native.collection.token-unavailable";
    inline constexpr char NativeTokenMappingCollectionPartial[] =
        "native.collection.token-partial";
    inline constexpr char NativeTokenMappingPrivilegeTruncation[] =
        "native.collection.token-privileges-truncated";
    inline constexpr char NativeTokenSensitiveAccessCorrelationKey[] =
        "sensitive-access-debug-privilege";

    enum class NativeTokenObservationBuildStatus : std::uint32_t
    {
        NotAttempted = 0,
        Success = 1,
        InvalidIdentity = 2,
        InputLimitExceeded = 3,
        InvalidTypedFact = 4,
        PolicyValidationFailed = 5
    };

    enum class NativeTokenSourceCompleteness : std::uint32_t
    {
        Complete = 0,
        Partial = 1,
        Unavailable = 2
    };

    struct NativeTokenObservationSource
    {
        ObservationSourceKind sourceKind = ObservationSourceKind::Direct;
        NativeTokenSourceCompleteness completeness =
            NativeTokenSourceCompleteness::Complete;
        std::string sourceIdentifier;
        std::string collectionMethod;
        std::string collectionTimestamp;
        std::string requiredPrivilege;
        std::string rawSourceReference;
        std::vector<std::string> limitations;
    };

    // The caller supplies only an already-collected, value-owned TokenInfo.
    // An omitted optional source is not a collection failure.
    struct NativeTokenObservationInput
    {
        ProcessIdentityKey identity;
        std::string entityScope;
        bool supplied = false;
        bool collectionAttempted = false;
        TokenInfo token;

        // A nonzero omitted count identifies material native facts that were
        // not supplied. The truncation note itself remains non-contributing.
        bool privilegesTruncated = false;
        std::size_t omittedPrivilegeCount = 0;

        NativeTokenObservationSource source;
        std::vector<std::string> limitations;
    };

    struct NativeTokenObservationRecord
    {
        ObservationRecord record;
        std::string semanticFactKey;
        std::string sourceRecordId;
        NativeTokenSourceCompleteness completeness =
            NativeTokenSourceCompleteness::Complete;
        bool primary = true;
        std::string primaryObservationId;
    };

    struct NativeTokenObservationBuildResult
    {
        bool attempted = false;
        bool success = false;
        bool truncated = false;
        NativeTokenObservationBuildStatus status =
            NativeTokenObservationBuildStatus::NotAttempted;
        std::vector<NativeTokenObservationRecord> records;
        ObservationInventory inventory;
        std::size_t nativeFactCount = 0;
        std::size_t representedFactCount = 0;
        std::size_t duplicateCount = 0;
        std::size_t omittedFactCount = 0;
        std::size_t completeFactCount = 0;
        std::size_t partialFactCount = 0;
        std::size_t unavailableFactCount = 0;
        std::string diagnostic;

        bool Succeeded() const;
    };

    // Pure native selected-process token adaptation. All emitted privilege
    // facts remain children of one token artifact. It performs no collection,
    // I/O, UI work, correlation activation, or verdict calculation.
    NativeTokenObservationBuildResult BuildNativeTokenObservations(
        const NativeTokenObservationInput& input) noexcept;
}
