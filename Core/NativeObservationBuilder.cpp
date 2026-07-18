#include "NativeObservationBuilder.h"

#include "ObservationPolicy.h"

#include <algorithm>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>
#include <string_view>
#include <utility>

namespace GlassPane::Core
{
    namespace
    {
        constexpr char NativeCategory[] = "Native selected-process evidence";
        constexpr char DecodeLimitation[] =
            "The decoded payload preview is bounded and was not executed or interpreted as behavioral proof.";
        constexpr char TruncationLimitation[] =
            "One or more native source values were truncated to their bounded representation.";

        struct ObservationSpec
        {
            std::string mappingRuleId;
            std::string sourceRuleId;
            std::string semanticFactKey;
            std::string title;
            std::string summary;
            EvidenceDomain domain = EvidenceDomain::Unknown;
            ObservationDisposition disposition =
                ObservationDisposition::Informational;
            ObservationStrength strength = ObservationStrength::None;
            ObservationConfidence confidence = ObservationConfidence::Unknown;
            bool contributesToVerdict = false;
            std::string groupingKey;
            std::string correlationKey;
            std::string rawValue;
            std::string normalizedValue;
            ObservationArtifactIdentity artifactIdentity;
            std::vector<ObservationArtifactAttribute> attributes;
            std::vector<std::string> evidence;
            std::vector<std::string> limitations;
            NativeObservationSource source;
            std::size_t sourceOrdinal = 0;
        };

        struct CommandTokenization
        {
            std::vector<std::string> tokens;
            bool truncated = false;
            bool unterminatedQuote = false;
        };

        struct DecodedPayload
        {
            NativeEncodedPayloadEncoding encoding =
                NativeEncodedPayloadEncoding::None;
            std::string preview;
            bool previewTruncated = false;
        };

        bool SameIdentity(
            const ProcessIdentityKey& left,
            const ProcessIdentityKey& right)
        {
            return left.pid == right.pid &&
                left.hasCreationTime == right.hasCreationTime &&
                left.creationTimeFileTime == right.creationTimeFileTime;
        }

        bool ValidIdentity(const ProcessIdentityKey& identity)
        {
            return identity.hasCreationTime ||
                identity.creationTimeFileTime == 0;
        }

        std::string EntityScope(const ProcessIdentityKey& identity)
        {
            std::ostringstream stream;
            stream << "process:pid:" << identity.pid << ":creation:";
            if (identity.hasCreationTime)
            {
                stream << identity.creationTimeFileTime;
            }
            else
            {
                stream << "unavailable";
            }
            return stream.str();
        }

        std::string ProcessArtifactKey(const ProcessIdentityKey& identity)
        {
            std::ostringstream stream;
            stream << "pid:" << identity.pid << ":creation:";
            if (identity.hasCreationTime)
            {
                stream << identity.creationTimeFileTime;
            }
            else
            {
                stream << "unavailable";
            }
            return stream.str();
        }

        std::uint64_t Fingerprint(std::string_view value)
        {
            constexpr std::uint64_t Offset = 1469598103934665603ULL;
            constexpr std::uint64_t Prime = 1099511628211ULL;
            std::uint64_t hash = Offset;
            for (const unsigned char character : value)
            {
                hash ^= character;
                hash *= Prime;
            }
            return hash;
        }

        std::string FingerprintText(std::string_view value)
        {
            std::ostringstream stream;
            stream << std::hex << std::setw(16) << std::setfill('0')
                   << Fingerprint(value);
            return stream.str();
        }

        bool LimitString(std::string& value, std::size_t maximumCharacters)
        {
            if (value.size() <= maximumCharacters)
            {
                return false;
            }
            value.resize(maximumCharacters);
            return true;
        }

        std::string BoundedCopy(
            const std::string& value,
            std::size_t maximumCharacters,
            bool& truncated)
        {
            std::string output = value;
            truncated = LimitString(output, maximumCharacters) || truncated;
            return output;
        }

        void AppendUtf8CodePoint(
            std::uint32_t codePoint,
            std::string& output,
            std::size_t maximumBytes,
            bool& truncated)
        {
            char encoded[4]{};
            std::size_t length = 0;
            if (codePoint <= 0x7fU)
            {
                encoded[0] = static_cast<char>(codePoint);
                length = 1;
            }
            else if (codePoint <= 0x7ffU)
            {
                encoded[0] = static_cast<char>(0xc0U | (codePoint >> 6));
                encoded[1] = static_cast<char>(0x80U | (codePoint & 0x3fU));
                length = 2;
            }
            else if (codePoint <= 0xffffU)
            {
                encoded[0] = static_cast<char>(0xe0U | (codePoint >> 12));
                encoded[1] = static_cast<char>(0x80U | ((codePoint >> 6) & 0x3fU));
                encoded[2] = static_cast<char>(0x80U | (codePoint & 0x3fU));
                length = 3;
            }
            else
            {
                encoded[0] = static_cast<char>(0xf0U | (codePoint >> 18));
                encoded[1] = static_cast<char>(0x80U | ((codePoint >> 12) & 0x3fU));
                encoded[2] = static_cast<char>(0x80U | ((codePoint >> 6) & 0x3fU));
                encoded[3] = static_cast<char>(0x80U | (codePoint & 0x3fU));
                length = 4;
            }
            if (output.size() + length > maximumBytes)
            {
                truncated = true;
                return;
            }
            output.append(encoded, length);
        }

        std::string WideToUtf8Bounded(
            const std::wstring& value,
            std::size_t maximumBytes,
            bool& truncated)
        {
            std::string output;
            output.reserve((std::min)(value.size(), maximumBytes));
            for (std::size_t index = 0; index < value.size(); ++index)
            {
                std::uint32_t codePoint =
                    static_cast<std::uint32_t>(value[index]);
                if constexpr (sizeof(wchar_t) == 2)
                {
                    if (codePoint >= 0xd800U && codePoint <= 0xdbffU)
                    {
                        if (index + 1 < value.size())
                        {
                            const std::uint32_t low =
                                static_cast<std::uint32_t>(value[index + 1]);
                            if (low >= 0xdc00U && low <= 0xdfffU)
                            {
                                codePoint = 0x10000U +
                                    ((codePoint - 0xd800U) << 10) +
                                    (low - 0xdc00U);
                                ++index;
                            }
                            else
                            {
                                codePoint = 0xfffdU;
                            }
                        }
                        else
                        {
                            codePoint = 0xfffdU;
                        }
                    }
                    else if (codePoint >= 0xdc00U &&
                        codePoint <= 0xdfffU)
                    {
                        codePoint = 0xfffdU;
                    }
                }
                else if (codePoint > 0x10ffffU ||
                    (codePoint >= 0xd800U && codePoint <= 0xdfffU))
                {
                    codePoint = 0xfffdU;
                }
                const std::size_t before = output.size();
                AppendUtf8CodePoint(
                    codePoint,
                    output,
                    maximumBytes,
                    truncated);
                if (truncated && output.size() == before)
                {
                    break;
                }
            }
            return output;
        }

        std::string HexValue(std::uint64_t value)
        {
            std::ostringstream stream;
            stream << "0x" << std::hex << std::uppercase << value;
            return stream.str();
        }

        std::size_t SetBitCount(std::uint64_t value)
        {
            std::size_t count = 0;
            while (value != 0)
            {
                value &= value - 1;
                ++count;
            }
            return count;
        }

        void AddWarning(
            NativeObservationBuildResult& result,
            std::string warning)
        {
            LimitString(warning, NativeObservationWarningMaxCharacters);
            if (result.warnings.size() >= NativeObservationMaxWarnings)
            {
                result.warningsTruncated = true;
                return;
            }
            result.warnings.push_back(std::move(warning));
        }

        void CopyBoundedItems(
            const std::vector<std::string>& source,
            std::vector<std::string>& destination,
            std::size_t maximumItems,
            std::size_t maximumCharacters,
            bool& truncated)
        {
            for (const std::string& item : source)
            {
                if (destination.size() >= maximumItems)
                {
                    truncated = true;
                    return;
                }
                destination.push_back(BoundedCopy(
                    item,
                    maximumCharacters,
                    truncated));
            }
        }

        char LowerAscii(char value)
        {
            if (value >= 'A' && value <= 'Z')
            {
                return static_cast<char>(value - 'A' + 'a');
            }
            return value;
        }

        std::string LowerAscii(std::string value)
        {
            std::transform(
                value.begin(),
                value.end(),
                value.begin(),
                [](char character)
                {
                    return LowerAscii(character);
                });
            return value;
        }

        bool IsAsciiSpace(char value)
        {
            return value == ' ' || value == '\t' || value == '\r' ||
                value == '\n' || value == '\f' || value == '\v';
        }

        CommandTokenization TokenizeCommandLine(const std::string& commandLine)
        {
            CommandTokenization result;
            std::string token;
            bool quoted = false;
            for (char character : commandLine)
            {
                if (character == '"')
                {
                    quoted = !quoted;
                    continue;
                }
                if (!quoted && IsAsciiSpace(character))
                {
                    if (!token.empty())
                    {
                        if (result.tokens.size() >=
                            NativeObservationMaxCommandTokens)
                        {
                            result.truncated = true;
                            break;
                        }
                        result.tokens.push_back(std::move(token));
                        token.clear();
                    }
                    continue;
                }
                token.push_back(character);
            }
            if (!result.truncated && !token.empty())
            {
                if (result.tokens.size() >= NativeObservationMaxCommandTokens)
                {
                    result.truncated = true;
                }
                else
                {
                    result.tokens.push_back(std::move(token));
                }
            }
            result.unterminatedQuote = quoted;
            return result;
        }

        bool IsExactEncodedSwitch(std::string_view token)
        {
            std::string lowered(token);
            lowered = LowerAscii(std::move(lowered));
            return lowered == "-encodedcommand" ||
                lowered == "/encodedcommand" ||
                lowered == "--encoded-command";
        }

        int Base64Value(char character)
        {
            if (character >= 'A' && character <= 'Z')
            {
                return character - 'A';
            }
            if (character >= 'a' && character <= 'z')
            {
                return character - 'a' + 26;
            }
            if (character >= '0' && character <= '9')
            {
                return character - '0' + 52;
            }
            if (character == '+')
            {
                return 62;
            }
            if (character == '/')
            {
                return 63;
            }
            return -1;
        }

        bool DecodeBase64Strict(
            std::string_view payload,
            std::vector<unsigned char>& decoded)
        {
            if (payload.empty() || payload.size() % 4 != 0)
            {
                return false;
            }
            const std::size_t estimated = (payload.size() / 4) * 3;
            if (estimated > NativeObservationMaxDecodedPayloadBytes + 2)
            {
                return false;
            }
            decoded.clear();
            decoded.reserve(std::min(
                estimated,
                NativeObservationMaxDecodedPayloadBytes));

            for (std::size_t offset = 0; offset < payload.size(); offset += 4)
            {
                const bool last = offset + 4 == payload.size();
                const int first = Base64Value(payload[offset]);
                const int second = Base64Value(payload[offset + 1]);
                const bool thirdPadding = payload[offset + 2] == '=';
                const bool fourthPadding = payload[offset + 3] == '=';
                const int third = thirdPadding ? 0 : Base64Value(payload[offset + 2]);
                const int fourth = fourthPadding ? 0 : Base64Value(payload[offset + 3]);
                if (first < 0 || second < 0 || third < 0 || fourth < 0 ||
                    (!last && (thirdPadding || fourthPadding)) ||
                    (thirdPadding && !fourthPadding))
                {
                    return false;
                }

                const std::uint32_t value =
                    (static_cast<std::uint32_t>(first) << 18) |
                    (static_cast<std::uint32_t>(second) << 12) |
                    (static_cast<std::uint32_t>(third) << 6) |
                    static_cast<std::uint32_t>(fourth);
                decoded.push_back(static_cast<unsigned char>((value >> 16) & 0xFF));
                if (!thirdPadding)
                {
                    decoded.push_back(static_cast<unsigned char>((value >> 8) & 0xFF));
                }
                if (!fourthPadding)
                {
                    decoded.push_back(static_cast<unsigned char>(value & 0xFF));
                }
                if (decoded.size() > NativeObservationMaxDecodedPayloadBytes)
                {
                    decoded.clear();
                    return false;
                }
            }
            return true;
        }

        void AppendUtf8CodePoint(
            std::uint32_t codePoint,
            std::string& output,
            bool& truncated)
        {
            char bytes[4]{};
            std::size_t count = 0;
            if (codePoint <= 0x7F)
            {
                bytes[0] = static_cast<char>(codePoint);
                count = 1;
            }
            else if (codePoint <= 0x7FF)
            {
                bytes[0] = static_cast<char>(0xC0 | (codePoint >> 6));
                bytes[1] = static_cast<char>(0x80 | (codePoint & 0x3F));
                count = 2;
            }
            else if (codePoint <= 0xFFFF)
            {
                bytes[0] = static_cast<char>(0xE0 | (codePoint >> 12));
                bytes[1] = static_cast<char>(0x80 | ((codePoint >> 6) & 0x3F));
                bytes[2] = static_cast<char>(0x80 | (codePoint & 0x3F));
                count = 3;
            }
            else
            {
                bytes[0] = static_cast<char>(0xF0 | (codePoint >> 18));
                bytes[1] = static_cast<char>(0x80 | ((codePoint >> 12) & 0x3F));
                bytes[2] = static_cast<char>(0x80 | ((codePoint >> 6) & 0x3F));
                bytes[3] = static_cast<char>(0x80 | (codePoint & 0x3F));
                count = 4;
            }
            if (output.size() + count >
                NativeObservationMaxDecodedPreviewCharacters)
            {
                truncated = true;
                return;
            }
            output.append(bytes, count);
        }

        std::uint32_t SanitizeCodePoint(std::uint32_t codePoint)
        {
            if (codePoint == '\r' || codePoint == '\n' || codePoint == '\t')
            {
                return ' ';
            }
            if (codePoint < 0x20 || codePoint == 0x7F)
            {
                return '?';
            }
            return codePoint;
        }

        bool DecodeUtf8Preview(
            const std::vector<unsigned char>& bytes,
            std::string& preview,
            bool& truncated)
        {
            preview.clear();
            std::size_t index = 0;
            while (index < bytes.size())
            {
                const unsigned char first = bytes[index];
                std::uint32_t codePoint = 0;
                std::size_t count = 0;
                if (first <= 0x7F)
                {
                    codePoint = first;
                    count = 1;
                }
                else if (first >= 0xC2 && first <= 0xDF)
                {
                    codePoint = first & 0x1F;
                    count = 2;
                }
                else if (first >= 0xE0 && first <= 0xEF)
                {
                    codePoint = first & 0x0F;
                    count = 3;
                }
                else if (first >= 0xF0 && first <= 0xF4)
                {
                    codePoint = first & 0x07;
                    count = 4;
                }
                else
                {
                    return false;
                }
                if (index + count > bytes.size())
                {
                    return false;
                }
                for (std::size_t continuation = 1;
                    continuation < count;
                    ++continuation)
                {
                    const unsigned char next = bytes[index + continuation];
                    if ((next & 0xC0) != 0x80)
                    {
                        return false;
                    }
                    codePoint = (codePoint << 6) | (next & 0x3F);
                }
                if ((count == 2 && codePoint < 0x80) ||
                    (count == 3 && codePoint < 0x800) ||
                    (count == 4 && codePoint < 0x10000) ||
                    codePoint > 0x10FFFF ||
                    (codePoint >= 0xD800 && codePoint <= 0xDFFF))
                {
                    return false;
                }
                if (index == 0 && codePoint == 0xFEFF)
                {
                    index += count;
                    continue;
                }
                AppendUtf8CodePoint(
                    SanitizeCodePoint(codePoint),
                    preview,
                    truncated);
                if (truncated)
                {
                    return true;
                }
                index += count;
            }
            return true;
        }

        bool HasUtf16LittleEndianHint(const std::vector<unsigned char>& bytes)
        {
            if (bytes.size() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE)
            {
                return true;
            }
            std::size_t zeroHighBytes = 0;
            for (std::size_t index = 1; index < bytes.size(); index += 2)
            {
                if (bytes[index] == 0)
                {
                    ++zeroHighBytes;
                }
            }
            const std::size_t pairs = bytes.size() / 2;
            return pairs != 0 && zeroHighBytes * 2 >= pairs;
        }

        bool DecodeUtf16LittleEndianPreview(
            const std::vector<unsigned char>& bytes,
            std::string& preview,
            bool& truncated)
        {
            if (bytes.empty() || bytes.size() % 2 != 0)
            {
                return false;
            }
            preview.clear();
            std::size_t offset = 0;
            if (bytes.size() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE)
            {
                offset = 2;
            }
            while (offset < bytes.size())
            {
                std::uint32_t codePoint =
                    static_cast<std::uint32_t>(bytes[offset]) |
                    (static_cast<std::uint32_t>(bytes[offset + 1]) << 8);
                offset += 2;
                if (codePoint >= 0xD800 && codePoint <= 0xDBFF)
                {
                    if (offset + 1 >= bytes.size())
                    {
                        return false;
                    }
                    const std::uint32_t low =
                        static_cast<std::uint32_t>(bytes[offset]) |
                        (static_cast<std::uint32_t>(bytes[offset + 1]) << 8);
                    if (low < 0xDC00 || low > 0xDFFF)
                    {
                        return false;
                    }
                    offset += 2;
                    codePoint = 0x10000 +
                        ((codePoint - 0xD800) << 10) +
                        (low - 0xDC00);
                }
                else if (codePoint >= 0xDC00 && codePoint <= 0xDFFF)
                {
                    return false;
                }
                AppendUtf8CodePoint(
                    SanitizeCodePoint(codePoint),
                    preview,
                    truncated);
                if (truncated)
                {
                    return true;
                }
            }
            return true;
        }

        DecodedPayload DecodePayloadPreview(std::string_view payload)
        {
            DecodedPayload result;
            if (payload.empty())
            {
                return result;
            }
            if (payload.size() > NativeObservationMaxEncodedPayloadCharacters)
            {
                result.encoding = NativeEncodedPayloadEncoding::LimitExceeded;
                return result;
            }
            if (payload.size() >= 4 &&
                (payload.size() / 4) * 3 >
                    NativeObservationMaxDecodedPayloadBytes + 2)
            {
                result.encoding = NativeEncodedPayloadEncoding::LimitExceeded;
                return result;
            }

            std::vector<unsigned char> decoded;
            if (!DecodeBase64Strict(payload, decoded))
            {
                result.encoding = NativeEncodedPayloadEncoding::InvalidBase64;
                return result;
            }

            if (HasUtf16LittleEndianHint(decoded) &&
                DecodeUtf16LittleEndianPreview(
                    decoded,
                    result.preview,
                    result.previewTruncated))
            {
                result.encoding =
                    NativeEncodedPayloadEncoding::Utf16LittleEndian;
                return result;
            }
            if (DecodeUtf8Preview(
                    decoded,
                    result.preview,
                    result.previewTruncated))
            {
                result.encoding = NativeEncodedPayloadEncoding::Utf8;
                return result;
            }
            if (DecodeUtf16LittleEndianPreview(
                    decoded,
                    result.preview,
                    result.previewTruncated))
            {
                result.encoding =
                    NativeEncodedPayloadEncoding::Utf16LittleEndian;
                return result;
            }
            result.preview.clear();
            result.encoding = NativeEncodedPayloadEncoding::Binary;
            return result;
        }

        void CountDisposition(
            ObservationInventory& inventory,
            ObservationDisposition disposition)
        {
            switch (disposition)
            {
            case ObservationDisposition::Informational:
                ++inventory.informationalCount;
                break;
            case ObservationDisposition::Context:
                ++inventory.contextCount;
                break;
            case ObservationDisposition::ReviewRelevant:
                ++inventory.reviewRelevantCount;
                break;
            case ObservationDisposition::CorrelatedOnly:
                ++inventory.correlatedOnlyCount;
                break;
            case ObservationDisposition::CollectionNote:
                ++inventory.collectionNoteCount;
                break;
            case ObservationDisposition::EvidenceIntegrityNote:
                ++inventory.evidenceIntegrityNoteCount;
                break;
            case ObservationDisposition::SuppressedExpected:
                ++inventory.suppressedExpectedCount;
                break;
            default:
                break;
            }
        }

        int CompletenessRank(ObservationSourceCompleteness completeness)
        {
            switch (completeness)
            {
            case ObservationSourceCompleteness::Complete:
                return 3;
            case ObservationSourceCompleteness::Partial:
                return 2;
            case ObservationSourceCompleteness::Unavailable:
                return 1;
            default:
                return 0;
            }
        }

        bool BetterPrimary(
            const NativeObservationRecord& candidate,
            const NativeObservationRecord& current)
        {
            return CompletenessRank(candidate.completeness) >
                CompletenessRank(current.completeness);
        }

        bool AddObservationRecord(
            NativeObservationBuildResult& result,
            const std::string& entityScope,
            ObservationSpec spec)
        {
            if (result.records.size() >= NativeObservationMaxOutputRecords)
            {
                result.success = false;
                result.status =
                    NativeObservationBuildStatus::InputLimitExceeded;
                result.diagnostic =
                    "Native selected-process observation output exceeded its cap.";
                result.records.clear();
                return false;
            }
            if (spec.semanticFactKey.empty() ||
                spec.semanticFactKey.size() >
                    NativeObservationSemanticFactKeyMaxCharacters)
            {
                result.success = false;
                result.status = NativeObservationBuildStatus::InvalidTypedFact;
                result.diagnostic =
                    "A native typed fact has no valid bounded semantic identity.";
                result.records.clear();
                return false;
            }

            bool truncated = false;
            NativeObservationRecord output;
            output.completeness = spec.source.completeness;
            output.semanticFactKey = spec.semanticFactKey;

            const std::string identityMaterial =
                entityScope + "|" + spec.semanticFactKey + "|" +
                std::to_string(spec.sourceOrdinal) + "|" +
                spec.source.rawSourceReference;
            const std::string fingerprint = FingerprintText(identityMaterial);
            output.sourceRecordId = "native-source:" + fingerprint;

            ObservationRecord& record = output.record;
            record.source.sourceRecordId = output.sourceRecordId;
            record.source.sourceRuleId = BoundedCopy(
                spec.sourceRuleId.empty()
                    ? spec.mappingRuleId
                    : spec.sourceRuleId,
                ObservationRuleIdMaxCharacters,
                truncated);
            record.source.mappingRuleId = BoundedCopy(
                spec.mappingRuleId,
                ObservationRuleIdMaxCharacters,
                truncated);
            record.source.sourceTitle = BoundedCopy(
                spec.title,
                ObservationTitleMaxCharacters,
                truncated);
            record.source.sourceMessage = BoundedCopy(
                spec.summary,
                ObservationSourceMessageMaxCharacters,
                truncated);
            record.source.sourceCategory = NativeCategory;
            record.source.producerIdentifier = BoundedCopy(
                spec.source.sourceIdentifier.empty()
                    ? std::string("core.native-selected-process")
                    : spec.source.sourceIdentifier,
                ObservationProvenanceSourceIdentifierMaxCharacters,
                truncated);
            record.source.rawValueExplicitlySupplied = !spec.rawValue.empty();
            record.source.normalizedValueExplicitlySupplied =
                !spec.normalizedValue.empty();

            Observation& observation = record.observation;
            observation.id = "native-observation:" + fingerprint;
            observation.ruleId = record.source.sourceRuleId;
            observation.title = record.source.sourceTitle;
            observation.summary = record.source.sourceMessage;
            observation.domain = spec.domain;
            observation.sourceKind =
                spec.source.completeness ==
                    ObservationSourceCompleteness::Unavailable
                    ? ObservationSourceKind::Unavailable
                    : spec.source.sourceKind;
            observation.disposition = spec.disposition;
            observation.strength = spec.strength;
            observation.confidence = spec.confidence;
            observation.contributesToVerdict = spec.contributesToVerdict;
            observation.entityScope = entityScope;
            observation.groupingKey = BoundedCopy(
                spec.groupingKey,
                ObservationGroupingKeyMaxCharacters,
                truncated);
            observation.correlationKey = BoundedCopy(
                spec.correlationKey,
                ObservationCorrelationKeyMaxCharacters,
                truncated);
            observation.rawValue = BoundedCopy(
                spec.rawValue,
                ObservationRawValueMaxCharacters,
                truncated);
            observation.normalizedValue = BoundedCopy(
                spec.normalizedValue,
                ObservationNormalizedValueMaxCharacters,
                truncated);
            observation.artifactIdentity = std::move(spec.artifactIdentity);
            observation.artifactIdentity.entityScope = entityScope;
            observation.artifactIdentity.artifactKey = BoundedCopy(
                observation.artifactIdentity.artifactKey,
                ObservationArtifactKeyMaxCharacters,
                truncated);
            observation.artifactAttributes = std::move(spec.attributes);
            if (observation.artifactAttributes.size() >
                ObservationMaxArtifactAttributes)
            {
                observation.artifactAttributes.resize(
                    ObservationMaxArtifactAttributes);
                truncated = true;
            }
            for (ObservationArtifactAttribute& attribute :
                observation.artifactAttributes)
            {
                truncated = LimitString(
                    attribute.key,
                    ObservationArtifactAttributeKeyMaxCharacters) || truncated;
                truncated = LimitString(
                    attribute.value,
                    ObservationArtifactAttributeValueMaxCharacters) || truncated;
            }
            CopyBoundedItems(
                spec.evidence,
                observation.evidence,
                ObservationMaxEvidenceItems,
                ObservationEvidenceItemMaxCharacters,
                truncated);
            CopyBoundedItems(
                spec.limitations,
                observation.limitations,
                ObservationMaxLimitationItems,
                ObservationLimitationItemMaxCharacters,
                truncated);
            CopyBoundedItems(
                spec.source.limitations,
                observation.limitations,
                ObservationMaxLimitationItems,
                ObservationLimitationItemMaxCharacters,
                truncated);
            if (truncated && observation.limitations.size() <
                ObservationMaxLimitationItems)
            {
                observation.limitations.push_back(TruncationLimitation);
            }

            observation.provenance.sourceKind = observation.sourceKind;
            observation.provenance.sourceIdentifier =
                record.source.producerIdentifier;
            observation.provenance.collectionMethod = BoundedCopy(
                spec.source.collectionMethod,
                ObservationProvenanceCollectionMethodMaxCharacters,
                truncated);
            observation.provenance.collectionTimestamp = BoundedCopy(
                spec.source.collectionTimestamp,
                ObservationProvenanceCollectionTimestampMaxCharacters,
                truncated);
            observation.provenance.requiredPrivilege = BoundedCopy(
                spec.source.requiredPrivilege,
                ObservationProvenanceRequiredPrivilegeMaxCharacters,
                truncated);
            observation.provenance.sourceAvailable =
                observation.sourceKind != ObservationSourceKind::Unavailable;
            observation.provenance.rawSourceReference = BoundedCopy(
                spec.source.rawSourceReference.empty()
                    ? output.sourceRecordId
                    : spec.source.rawSourceReference,
                ObservationProvenanceRawSourceReferenceMaxCharacters,
                truncated);
            observation.provenance.limitations = observation.limitations;

            observation = NormalizeObservationPolicy(std::move(observation));
            if (!ValidateObservation(observation).IsValid())
            {
                result.success = false;
                result.status =
                    NativeObservationBuildStatus::PolicyValidationFailed;
                result.diagnostic =
                    "A native observation failed bounded policy validation.";
                result.records.clear();
                return false;
            }

            if (truncated && output.completeness ==
                ObservationSourceCompleteness::Complete)
            {
                output.completeness = ObservationSourceCompleteness::Partial;
            }
            result.truncated = result.truncated || truncated;
            result.records.push_back(std::move(output));
            return true;
        }

        bool ApplyGlobalLimitations(
            NativeObservationBuildResult& result,
            const std::vector<std::string>& limitations)
        {
            for (NativeObservationRecord& source : result.records)
            {
                bool truncated = false;
                CopyBoundedItems(
                    limitations,
                    source.record.observation.limitations,
                    ObservationMaxLimitationItems,
                    ObservationLimitationItemMaxCharacters,
                    truncated);
                source.record.observation.provenance.limitations =
                    source.record.observation.limitations;
                source.record.observation = NormalizeObservationPolicy(
                    std::move(source.record.observation));
                if (!ValidateObservation(
                        source.record.observation).IsValid())
                {
                    result.success = false;
                    result.status =
                        NativeObservationBuildStatus::PolicyValidationFailed;
                    result.diagnostic =
                        "A native observation failed validation after applying source limitations.";
                    result.records.clear();
                    return false;
                }
                if (truncated)
                {
                    result.truncated = true;
                    if (source.completeness ==
                        ObservationSourceCompleteness::Complete)
                    {
                        source.completeness =
                            ObservationSourceCompleteness::Partial;
                    }
                }
            }
            return true;
        }

        void BuildCommandObservations(
            NativeObservationBuildResult& result,
            const NativeSelectedProcessObservationInput& input,
            const std::string& entityScope,
            const std::string& processArtifact)
        {
            const NativeCommandLineInput& command = input.commandLine;
            if (!command.supplied)
            {
                return;
            }
            if (!SameIdentity(command.identity, input.identity))
            {
                result.success = false;
                result.status = NativeObservationBuildStatus::InvalidIdentity;
                result.diagnostic =
                    "Command-line source identity does not match the selected process identity.";
                return;
            }
            if (!command.available)
            {
                if (!command.collectionAttempted)
                {
                    return;
                }
                ObservationSpec note;
                note.mappingRuleId = NativeMappingCommandLineUnavailable;
                note.semanticFactKey =
                    std::string("collection.command-line|") + processArtifact;
                note.title = "Command-line metadata unavailable";
                note.summary =
                    "Command-line collection was attempted for the selected process but was unavailable.";
                note.domain = EvidenceDomain::CollectionQuality;
                note.disposition = ObservationDisposition::CollectionNote;
                note.strength = ObservationStrength::None;
                note.confidence = ObservationConfidence::High;
                note.groupingKey = "selected-collection-quality";
                note.artifactIdentity = {
                    ObservationArtifactKind::Process,
                    entityScope,
                    processArtifact
                };
                note.limitations.push_back(
                    "Unavailable command-line metadata does not imply benign or suspicious activity.");
                note.source = command.source;
                note.source.completeness =
                    ObservationSourceCompleteness::Unavailable;
                AddObservationRecord(result, entityScope, std::move(note));
                return;
            }

            const CommandTokenization tokenization =
                TokenizeCommandLine(command.commandLine);
            if (tokenization.truncated)
            {
                result.truncated = true;
                ++result.omittedFactCount;
                AddWarning(
                    result,
                    "Command-line tokenization reached its cap; encoded-switch coverage is partial.");
            }
            if (tokenization.unterminatedQuote)
            {
                AddWarning(
                    result,
                    "The command line contained an unterminated quote; tokenization remained bounded.");
            }

            std::size_t emitted = 0;
            for (std::size_t index = 0;
                index < tokenization.tokens.size();
                ++index)
            {
                const std::string& switchToken = tokenization.tokens[index];
                if (!IsExactEncodedSwitch(switchToken))
                {
                    continue;
                }
                if (emitted >= NativeObservationMaxEncodedSwitches)
                {
                    result.truncated = true;
                    ++result.omittedFactCount;
                    AddWarning(
                        result,
                        "Additional complete encoded-command switches were omitted by the bounded cap.");
                    continue;
                }

                std::string payload;
                if (index + 1 < tokenization.tokens.size() &&
                    !IsExactEncodedSwitch(tokenization.tokens[index + 1]))
                {
                    payload = tokenization.tokens[index + 1];
                }
                const DecodedPayload decoded = DecodePayloadPreview(payload);
                const std::string loweredSwitch = LowerAscii(switchToken);
                const std::string payloadFingerprint = FingerprintText(payload);

                ObservationSpec encoded;
                encoded.mappingRuleId = NativeMappingEncodedCommand;
                encoded.sourceRuleId = NativeMappingEncodedCommand;
                encoded.semanticFactKey =
                    std::string("command.encoded-switch|") + processArtifact +
                    "|" + payloadFingerprint;
                encoded.title = "Encoded command switch observed";
                encoded.summary =
                    "A complete generic encoded-command switch token was present in the selected process command line.";
                encoded.domain = EvidenceDomain::CommandLine;
                encoded.disposition = ObservationDisposition::ReviewRelevant;
                encoded.strength = ObservationStrength::Moderate;
                encoded.confidence = ObservationConfidence::High;
                encoded.contributesToVerdict = true;
                encoded.groupingKey = "encoded-command-context";
                encoded.correlationKey = "command-relationship-context";
                encoded.rawValue = switchToken;
                if (!payload.empty())
                {
                    encoded.rawValue += " " + payload;
                }
                // Stable semantic identity is independent of display payload
                // text so an equivalent bounded source record can be grouped.
                // The bounded payload fingerprint remains an auditable typed
                // attribute and never becomes correlation strength.
                encoded.normalizedValue = "encoded-command-switch";
                encoded.artifactIdentity = {
                    ObservationArtifactKind::Process,
                    entityScope,
                    processArtifact
                };
                encoded.attributes = {
                    { "command.switch", loweredSwitch },
                    { "command.payload.encoding",
                        NativeEncodedPayloadEncodingDisplayText(decoded.encoding) },
                    { "command.payload.characters", std::to_string(payload.size()) },
                    { "command.payload.fingerprint", payloadFingerprint }
                };
                if (!decoded.preview.empty())
                {
                    encoded.attributes.push_back({
                        "command.payload.preview",
                        decoded.preview
                    });
                }
                encoded.evidence.push_back(
                    "A complete encoded-command switch token was observed.");
                encoded.limitations.push_back(DecodeLimitation);
                if (payload.empty())
                {
                    encoded.limitations.push_back(
                        "No separate payload token followed the encoded-command switch.");
                }
                if (decoded.encoding ==
                    NativeEncodedPayloadEncoding::InvalidBase64)
                {
                    encoded.limitations.push_back(
                        "The payload token was not valid strict base64; no decoded preview was produced.");
                    encoded.source.completeness =
                        ObservationSourceCompleteness::Partial;
                }
                else if (decoded.encoding ==
                    NativeEncodedPayloadEncoding::LimitExceeded)
                {
                    encoded.limitations.push_back(
                        "The encoded payload exceeded the bounded decode cap; no decoded preview was produced.");
                    encoded.source.completeness =
                        ObservationSourceCompleteness::Partial;
                    result.truncated = true;
                }
                else if (decoded.encoding ==
                    NativeEncodedPayloadEncoding::Binary)
                {
                    encoded.limitations.push_back(
                        "The decoded bytes were neither valid UTF-8 nor valid UTF-16LE text.");
                }
                if (decoded.previewTruncated)
                {
                    encoded.limitations.push_back(
                        "The decoded text preview was truncated to its bounded cap.");
                    encoded.source.completeness =
                        ObservationSourceCompleteness::Partial;
                    result.truncated = true;
                }
                encoded.source = command.source;
                if (decoded.encoding ==
                        NativeEncodedPayloadEncoding::InvalidBase64 ||
                    decoded.encoding ==
                        NativeEncodedPayloadEncoding::LimitExceeded ||
                    decoded.previewTruncated)
                {
                    encoded.source.completeness =
                        ObservationSourceCompleteness::Partial;
                }
                encoded.sourceOrdinal = index;
                if (!AddObservationRecord(
                        result,
                        entityScope,
                        std::move(encoded)))
                {
                    return;
                }
                ++emitted;
            }
        }

        void BuildRelationshipObservations(
            NativeObservationBuildResult& result,
            const NativeSelectedProcessObservationInput& input,
            const std::string& entityScope,
            const std::string& processArtifact)
        {
            for (std::size_t index = 0;
                index < input.relationships.size();
                ++index)
            {
                const NativeRelationshipFact& fact = input.relationships[index];
                if (!SameIdentity(fact.subjectIdentity, input.identity) ||
                    !ValidIdentity(fact.relatedIdentity))
                {
                    result.success = false;
                    result.status = NativeObservationBuildStatus::InvalidIdentity;
                    result.diagnostic =
                        "A typed relationship fact has a mismatched or invalid process identity.";
                    return;
                }
                if (fact.semanticFactKey.empty() ||
                    fact.semanticFactKey.size() >
                        NativeObservationSemanticFactKeyMaxCharacters)
                {
                    result.success = false;
                    result.status =
                        NativeObservationBuildStatus::InvalidTypedFact;
                    result.diagnostic =
                        "A typed relationship fact has no valid semantic identity.";
                    return;
                }
                if ((fact.kind != NativeRelationshipKind::DirectParent &&
                        fact.kind != NativeRelationshipKind::Ancestor) ||
                    (fact.semantics !=
                            NativeRelationshipSemantics::Context &&
                        fact.semantics !=
                            NativeRelationshipSemantics::ExecutionCorrelation))
                {
                    result.success = false;
                    result.status =
                        NativeObservationBuildStatus::InvalidTypedFact;
                    result.diagnostic =
                        "A typed relationship fact contains an unknown semantic enum value.";
                    return;
                }

                ObservationSpec relationship;
                relationship.semanticFactKey = fact.semanticFactKey;
                relationship.sourceRuleId = fact.sourceRuleId;
                relationship.domain = EvidenceDomain::ProcessRelationship;
                relationship.confidence = ObservationConfidence::High;
                relationship.groupingKey = "process-family-relationship";
                relationship.rawValue = fact.rawValue;
                relationship.normalizedValue = fact.normalizedValue.empty()
                    ? "pid:" + std::to_string(fact.relatedIdentity.pid) +
                        "->pid:" + std::to_string(input.identity.pid)
                    : fact.normalizedValue;
                relationship.artifactIdentity = {
                    ObservationArtifactKind::Process,
                    entityScope,
                    processArtifact
                };
                relationship.attributes = {
                    { "relationship.kind",
                        fact.kind == NativeRelationshipKind::DirectParent
                            ? "direct-parent"
                            : "ancestor" },
                    { "relationship.related-pid",
                        std::to_string(fact.relatedIdentity.pid) },
                    { "relationship.related-creation-time",
                        fact.relatedIdentity.hasCreationTime
                            ? std::to_string(
                                fact.relatedIdentity.creationTimeFileTime)
                            : "unavailable" }
                };
                relationship.evidence = fact.evidence;
                relationship.source = fact.source;
                relationship.sourceOrdinal = index;

                if (!fact.verified ||
                    fact.source.completeness ==
                        ObservationSourceCompleteness::Unavailable)
                {
                    relationship.mappingRuleId =
                        NativeMappingRelationshipUnavailable;
                    relationship.title =
                        "Process relationship metadata unavailable";
                    relationship.summary =
                        "A typed relationship source could not verify the selected process link.";
                    relationship.domain = EvidenceDomain::CollectionQuality;
                    relationship.disposition =
                        ObservationDisposition::CollectionNote;
                    relationship.strength = ObservationStrength::None;
                    relationship.groupingKey = "selected-collection-quality";
                    relationship.limitations.push_back(
                        "An unverified relationship does not establish benign or suspicious activity.");
                    relationship.source.completeness =
                        ObservationSourceCompleteness::Unavailable;
                }
                else if (fact.semantics ==
                    NativeRelationshipSemantics::ExecutionCorrelation)
                {
                    relationship.mappingRuleId =
                        NativeMappingTypedRelationship;
                    relationship.title =
                        fact.kind == NativeRelationshipKind::DirectParent
                            ? "Typed parent relationship requires correlation"
                            : "Typed ancestry relationship requires correlation";
                    relationship.summary =
                        "A producer-authored process relationship is available for typed execution correlation.";
                    relationship.disposition =
                        ObservationDisposition::CorrelatedOnly;
                    relationship.strength = ObservationStrength::Moderate;
                    relationship.correlationKey =
                        "command-relationship-context";
                }
                else
                {
                    relationship.mappingRuleId =
                        NativeMappingRelationshipContext;
                    relationship.title =
                        fact.kind == NativeRelationshipKind::DirectParent
                            ? "Parent process relationship observed"
                            : "Process ancestry relationship observed";
                    relationship.summary =
                        "A verified typed process relationship was retained as context.";
                    relationship.disposition =
                        ObservationDisposition::Context;
                    relationship.strength = ObservationStrength::None;
                }

                if (!AddObservationRecord(
                        result,
                        entityScope,
                        std::move(relationship)))
                {
                    return;
                }
            }
        }

        void AddFilePathObservation(
            NativeObservationBuildResult& result,
            const std::string& entityScope,
            const NativeFileIdentityInput& file)
        {
            if (file.pathContext == NativeFilePathContext::NotEvaluated)
            {
                return;
            }
            ObservationSpec path;
            path.semanticFactKey =
                std::string("file.path-context|") + file.artifactKey + "|" +
                std::to_string(static_cast<std::uint32_t>(file.pathContext));
            path.sourceRuleId = file.pathContext ==
                NativeFilePathContext::UserWritable
                ? NativeMappingUserWritablePath
                : NativeMappingExecutablePath;
            path.domain = EvidenceDomain::FilePath;
            path.confidence = ObservationConfidence::High;
            path.rawValue = file.rawPath;
            path.normalizedValue = file.normalizedPath;
            path.artifactIdentity = {
                ObservationArtifactKind::File,
                entityScope,
                file.artifactKey
            };
            path.attributes = {
                { "file.path-context",
                    file.pathContext == NativeFilePathContext::UserWritable
                        ? "user-writable"
                        : file.pathContext == NativeFilePathContext::Available
                            ? "available"
                            : "unavailable" }
            };
            path.evidence = file.evidence;
            path.source = file.source;
            path.sourceOrdinal = 0;

            switch (file.pathContext)
            {
            case NativeFilePathContext::Available:
                path.mappingRuleId = NativeMappingExecutablePath;
                path.title = "Executable path observed";
                path.summary =
                    "Typed executable-path metadata was retained as identity context.";
                path.disposition = ObservationDisposition::Informational;
                path.strength = ObservationStrength::None;
                path.groupingKey = "executable-path-context";
                break;
            case NativeFilePathContext::UserWritable:
                path.mappingRuleId = NativeMappingUserWritablePath;
                path.title = "Executable path is in a user-writable location";
                path.summary =
                    "A producer-authored path-context fact identified a broadly user-writable location.";
                path.disposition = ObservationDisposition::Context;
                path.strength = ObservationStrength::Weak;
                path.groupingKey = "user-file-path-context";
                path.correlationKey = "file-path-signature-context";
                break;
            case NativeFilePathContext::Unavailable:
                path.mappingRuleId = NativeMappingFileIdentityUnavailable;
                path.title = "Executable path metadata unavailable";
                path.summary =
                    "An attempted typed file-identity source did not provide executable-path metadata.";
                path.domain = EvidenceDomain::CollectionQuality;
                path.disposition = ObservationDisposition::CollectionNote;
                path.strength = ObservationStrength::None;
                path.groupingKey = "selected-collection-quality";
                path.source.completeness =
                    ObservationSourceCompleteness::Unavailable;
                path.limitations.push_back(
                    "Unavailable path metadata does not imply benign or suspicious activity.");
                break;
            case NativeFilePathContext::NotEvaluated:
            default:
                return;
            }
            AddObservationRecord(result, entityScope, std::move(path));
        }

        void AddFileSignatureObservation(
            NativeObservationBuildResult& result,
            const std::string& entityScope,
            const NativeFileIdentityInput& file)
        {
            if (file.signatureState ==
                NativeFileSignatureState::NotEvaluated)
            {
                return;
            }
            ObservationSpec signature;
            signature.semanticFactKey =
                std::string("file.signature-state|") + file.artifactKey + "|" +
                std::to_string(static_cast<std::uint32_t>(file.signatureState));
            signature.domain = EvidenceDomain::FileSignature;
            signature.confidence = ObservationConfidence::High;
            signature.artifactIdentity = {
                ObservationArtifactKind::File,
                entityScope,
                file.artifactKey
            };
            signature.attributes.push_back({
                "file.signature-state",
                file.signatureState ==
                    NativeFileSignatureState::AuthenticatedValid
                    ? "authenticated-valid"
                    : file.signatureState ==
                        NativeFileSignatureState::AuthenticatedInvalid
                        ? "authenticated-invalid"
                        : file.signatureState ==
                            NativeFileSignatureState::SignatureAbsent
                            ? "signature-absent"
                            : "unavailable"
            });
            if (!file.signerSubject.empty())
            {
                signature.attributes.push_back({
                    "file.signer-subject",
                    file.signerSubject
                });
            }
            if (!file.signerIssuer.empty())
            {
                signature.attributes.push_back({
                    "file.signer-issuer",
                    file.signerIssuer
                });
            }
            if (!file.signerThumbprint.empty())
            {
                signature.attributes.push_back({
                    "file.signer-thumbprint",
                    file.signerThumbprint
                });
            }
            signature.evidence = file.evidence;
            signature.source = file.source;
            signature.sourceOrdinal = 1;

            switch (file.signatureState)
            {
            case NativeFileSignatureState::AuthenticatedValid:
                signature.mappingRuleId = NativeMappingValidSignature;
                signature.sourceRuleId = NativeMappingValidSignature;
                signature.title = "Executable signature validation succeeded";
                signature.summary =
                    "An authenticated signature-validation result was retained as file context.";
                signature.disposition =
                    ObservationDisposition::Informational;
                signature.strength = ObservationStrength::None;
                signature.groupingKey = "file-signature-status";
                break;
            case NativeFileSignatureState::AuthenticatedInvalid:
                signature.mappingRuleId = NativeMappingInvalidSignature;
                signature.sourceRuleId = NativeMappingInvalidSignature;
                signature.title = "Invalid executable signature observed";
                signature.summary =
                    "An authenticated typed signature-validation result reported an invalid executable signature.";
                signature.disposition =
                    ObservationDisposition::ReviewRelevant;
                signature.strength = ObservationStrength::Moderate;
                signature.contributesToVerdict = true;
                signature.groupingKey = "file-signature-status";
                signature.correlationKey = "file-path-signature-context";
                break;
            case NativeFileSignatureState::SignatureAbsent:
                signature.mappingRuleId = NativeMappingSignatureAbsent;
                signature.sourceRuleId = NativeMappingSignatureAbsent;
                signature.title = "Executable signature not present";
                signature.summary =
                    "An authenticated typed file result reported that no signature was present.";
                signature.disposition = ObservationDisposition::Context;
                signature.strength = ObservationStrength::Weak;
                signature.groupingKey = "file-signature-status";
                break;
            case NativeFileSignatureState::Unavailable:
                signature.mappingRuleId =
                    NativeMappingFileIdentityUnavailable;
                signature.sourceRuleId =
                    NativeMappingFileIdentityUnavailable;
                signature.title = "Executable signature metadata unavailable";
                signature.summary =
                    "An attempted typed file-identity source did not provide signature-validation metadata.";
                signature.domain = EvidenceDomain::CollectionQuality;
                signature.disposition =
                    ObservationDisposition::CollectionNote;
                signature.strength = ObservationStrength::None;
                signature.groupingKey = "selected-collection-quality";
                signature.source.completeness =
                    ObservationSourceCompleteness::Unavailable;
                signature.limitations.push_back(
                    "Unavailable signature metadata does not imply benign or suspicious activity.");
                break;
            case NativeFileSignatureState::NotEvaluated:
            default:
                return;
            }
            AddObservationRecord(result, entityScope, std::move(signature));
        }

        void BuildFileObservations(
            NativeObservationBuildResult& result,
            const NativeSelectedProcessObservationInput& input,
            const std::string& entityScope)
        {
            const NativeFileIdentityInput& file = input.fileIdentity;
            if (!file.supplied)
            {
                return;
            }
            if (!SameIdentity(file.identity, input.identity))
            {
                result.success = false;
                result.status = NativeObservationBuildStatus::InvalidIdentity;
                result.diagnostic =
                    "File-identity source identity does not match the selected process identity.";
                return;
            }
            if ((file.pathContext != NativeFilePathContext::NotEvaluated &&
                    file.pathContext != NativeFilePathContext::Available &&
                    file.pathContext != NativeFilePathContext::UserWritable &&
                    file.pathContext != NativeFilePathContext::Unavailable) ||
                (file.signatureState !=
                        NativeFileSignatureState::NotEvaluated &&
                    file.signatureState !=
                        NativeFileSignatureState::AuthenticatedValid &&
                    file.signatureState !=
                        NativeFileSignatureState::AuthenticatedInvalid &&
                    file.signatureState !=
                        NativeFileSignatureState::SignatureAbsent &&
                    file.signatureState !=
                        NativeFileSignatureState::Unavailable))
            {
                result.success = false;
                result.status = NativeObservationBuildStatus::InvalidTypedFact;
                result.diagnostic =
                    "Typed file identity contains an unknown semantic enum value.";
                return;
            }
            if ((file.pathContext != NativeFilePathContext::NotEvaluated ||
                    file.signatureState !=
                        NativeFileSignatureState::NotEvaluated) &&
                (file.artifactKey.empty() ||
                    file.artifactKey.size() >
                        ObservationArtifactKeyMaxCharacters))
            {
                result.success = false;
                result.status = NativeObservationBuildStatus::InvalidTypedFact;
                result.diagnostic =
                    "Typed file identity requires a bounded nonempty artifact identity.";
                return;
            }
            AddFilePathObservation(result, entityScope, file);
            if (!result.success)
            {
                return;
            }
            AddFileSignatureObservation(result, entityScope, file);
        }

        bool AddCollectionNote(
            NativeObservationBuildResult& result,
            const std::string& entityScope,
            std::string mappingRuleId,
            std::string semanticFactKey,
            std::string title,
            std::string summary,
            std::string rawValue,
            ObservationArtifactKind artifactKind,
            std::string artifactKey,
            NativeObservationSource source,
            std::vector<std::string> limitations,
            std::size_t sourceOrdinal = 0)
        {
            source.sourceKind = ObservationSourceKind::Unavailable;
            if (source.completeness == ObservationSourceCompleteness::Complete)
            {
                source.completeness =
                    ObservationSourceCompleteness::Unavailable;
            }
            ObservationSpec note;
            note.mappingRuleId = mappingRuleId;
            note.sourceRuleId = mappingRuleId;
            note.semanticFactKey = std::move(semanticFactKey);
            note.title = std::move(title);
            note.summary = std::move(summary);
            note.domain = EvidenceDomain::CollectionQuality;
            note.disposition = ObservationDisposition::CollectionNote;
            note.strength = ObservationStrength::None;
            note.confidence = ObservationConfidence::High;
            note.groupingKey = "selected-collection-quality";
            note.rawValue = std::move(rawValue);
            note.normalizedValue = note.rawValue;
            note.artifactIdentity = {
                artifactKind,
                entityScope,
                std::move(artifactKey)
            };
            note.limitations = std::move(limitations);
            note.source = std::move(source);
            note.sourceOrdinal = sourceOrdinal;
            return AddObservationRecord(result, entityScope, std::move(note));
        }

        std::string NetworkConnectionIdentity(
            const NetworkConnection& connection,
            bool& truncated)
        {
            return WideToUtf8Bounded(
                    connection.protocol,
                    64,
                    truncated) + "|" +
                WideToUtf8Bounded(
                    connection.localAddress,
                    256,
                    truncated) + "|" +
                std::to_string(connection.localPort) + "|" +
                WideToUtf8Bounded(
                    connection.remoteAddress,
                    256,
                    truncated) + "|" +
                std::to_string(connection.remotePort);
        }

        void BuildNetworkObservations(
            NativeObservationBuildResult& result,
            const NativeSelectedProcessObservationInput& input,
            const std::string& entityScope,
            const std::string& processArtifact)
        {
            const NativeNetworkObservationInput& network = input.network;
            if (!network.supplied && !network.collectionAttempted)
            {
                return;
            }
            if (!SameIdentity(network.identity, input.identity))
            {
                result.success = false;
                result.status = NativeObservationBuildStatus::InvalidIdentity;
                result.diagnostic =
                    "Network source identity does not match the selected process identity.";
                return;
            }
            if (!network.available)
            {
                std::vector<std::string> limitations = network.source.limitations;
                limitations.push_back(
                    "Unavailable network evidence does not establish benign or suspicious activity.");
                AddCollectionNote(
                    result,
                    entityScope,
                    NativeMappingNetworkUnavailable,
                    "network.collection-unavailable",
                    "Network evidence unavailable",
                    "Selected-process network collection was attempted but unavailable.",
                    network.source.rawSourceReference,
                    ObservationArtifactKind::Process,
                    processArtifact,
                    network.source,
                    std::move(limitations));
                return;
            }
            if (network.omittedMaterialFactCount != 0)
            {
                result.omittedFactCount +=
                    network.omittedMaterialFactCount;
                result.truncated = true;
            }

            const std::size_t connectionCount = (std::min)(
                network.connections.size(),
                NativeObservationMaxNetworkConnections);
            for (std::size_t index = 0; index < connectionCount; ++index)
            {
                const NetworkConnection& connection =
                    network.connections[index];
                if (connection.owningPid != input.identity.pid)
                {
                    result.success = false;
                    result.status = NativeObservationBuildStatus::InvalidIdentity;
                    result.diagnostic =
                        "A network connection belongs to a different process identity.";
                    return;
                }
                if (!connection.isPublicRemote)
                {
                    continue;
                }
                bool truncated = false;
                const std::string identity =
                    NetworkConnectionIdentity(connection, truncated);
                const std::string artifactKey =
                    "network-connection:" + FingerprintText(identity);
                ObservationSpec context;
                context.mappingRuleId = NativeMappingPublicNetworkContext;
                context.sourceRuleId = NativeMappingPublicNetworkContext;
                context.semanticFactKey =
                    "network.public-context|" + artifactKey;
                context.title = "Public network connection observed";
                context.summary =
                    "A public network connection was observed; public connectivity alone is supporting context.";
                context.domain = EvidenceDomain::Network;
                context.disposition = ObservationDisposition::Context;
                context.strength = ObservationStrength::Weak;
                context.confidence = ObservationConfidence::High;
                context.groupingKey = "public-network-activity";
                context.rawValue = identity;
                context.normalizedValue = LowerAscii(identity);
                context.artifactIdentity = {
                    ObservationArtifactKind::NetworkConnection,
                    entityScope,
                    artifactKey
                };
                context.attributes = {
                    { "network.protocol", WideToUtf8Bounded(
                        connection.protocol, 64, truncated) },
                    { "network.remote-port",
                        std::to_string(connection.remotePort) },
                    { "network.public-remote", "true" }
                };
                context.source = network.source;
                context.sourceOrdinal = index;
                if (truncated)
                {
                    context.limitations.push_back(
                        "A network endpoint field was truncated to its bounded representation.");
                    result.truncated = true;
                }
                if (!AddObservationRecord(
                        result,
                        entityScope,
                        std::move(context)))
                {
                    return;
                }
            }

            const std::size_t indicatorCount = (std::min)(
                network.exactIndicatorMatches.size(),
                NativeObservationMaxNetworkIndicators);
            if (indicatorCount < network.exactIndicatorMatches.size())
            {
                result.omittedFactCount +=
                    network.exactIndicatorMatches.size() - indicatorCount;
                result.truncated = true;
            }
            for (std::size_t index = 0; index < indicatorCount; ++index)
            {
                const NetworkIndicatorMatch& match =
                    network.exactIndicatorMatches[index];
                if (match.connection.owningPid != input.identity.pid)
                {
                    result.success = false;
                    result.status = NativeObservationBuildStatus::InvalidIdentity;
                    result.diagnostic =
                        "An exact network-indicator match belongs to a different process identity.";
                    return;
                }
                bool truncated = false;
                const std::string connectionIdentity =
                    NetworkConnectionIdentity(match.connection, truncated);
                const std::string artifactKey =
                    "network-connection:" +
                    FingerprintText(connectionIdentity);
                const std::string type = WideToUtf8Bounded(
                    match.indicator.type,
                    128,
                    truncated);
                const std::string rawValue = WideToUtf8Bounded(
                    match.indicator.value,
                    ObservationRawValueMaxCharacters,
                    truncated);
                const std::string normalizedValue = WideToUtf8Bounded(
                    match.indicator.normalizedValue,
                    ObservationNormalizedValueMaxCharacters,
                    truncated);
                const std::string indicatorIdentity = type + "|" +
                    normalizedValue + "|" + connectionIdentity;

                ObservationSpec indicator;
                indicator.mappingRuleId =
                    NativeMappingExactNetworkIndicator;
                indicator.sourceRuleId =
                    NativeMappingExactNetworkIndicator;
                indicator.semanticFactKey =
                    "network.exact-indicator|" +
                    FingerprintText(indicatorIdentity);
                indicator.title = "Exact network indicator match observed";
                indicator.summary =
                    "An exact attributed Network Intelligence match was retained from already-collected evidence.";
                indicator.domain = EvidenceDomain::Network;
                indicator.disposition =
                    ObservationDisposition::ReviewRelevant;
                indicator.strength = ObservationStrength::Moderate;
                indicator.confidence = ObservationConfidence::Medium;
                indicator.contributesToVerdict = true;
                indicator.groupingKey = "network-indicator-match";
                indicator.correlationKey = "network-intelligence-context";
                indicator.rawValue = rawValue;
                indicator.normalizedValue = normalizedValue;
                indicator.artifactIdentity = {
                    ObservationArtifactKind::NetworkConnection,
                    entityScope,
                    artifactKey
                };
                indicator.attributes = {
                    { "network-indicator.type", type },
                    { "network-indicator.exact-match", "true" }
                };
                if (!type.empty())
                {
                    indicator.evidence.push_back(BoundedCopy(
                        "Indicator type: " + type,
                        ObservationEvidenceItemMaxCharacters,
                        truncated));
                }
                if (!rawValue.empty() &&
                    indicator.evidence.size() < ObservationMaxEvidenceItems)
                {
                    indicator.evidence.push_back(BoundedCopy(
                        "Matched value: " + rawValue,
                        ObservationEvidenceItemMaxCharacters,
                        truncated));
                }
                const auto appendSourceMetadata = [&](
                    const char* label,
                    const std::wstring& value)
                {
                    if (!value.empty() &&
                        indicator.evidence.size() <
                            ObservationMaxEvidenceItems)
                    {
                        indicator.evidence.push_back(
                            std::string(label) + WideToUtf8Bounded(
                                value,
                                ObservationEvidenceItemMaxCharacters,
                                truncated));
                    }
                };
                appendSourceMetadata(
                    "Feed category: ",
                    match.indicator.category);
                appendSourceMetadata(
                    "Feed severity metadata: ",
                    match.indicator.severity);
                appendSourceMetadata(
                    "Feed confidence metadata: ",
                    match.indicator.confidence);
                appendSourceMetadata(
                    "Feed description: ",
                    match.indicator.description);
                indicator.source = network.source;
                indicator.source.sourceKind = ObservationSourceKind::Imported;
                if (!match.indicator.source.empty())
                {
                    indicator.source.sourceIdentifier = WideToUtf8Bounded(
                        match.indicator.source,
                        ObservationProvenanceSourceIdentifierMaxCharacters,
                        truncated);
                    indicator.source.rawSourceReference =
                        indicator.source.sourceIdentifier;
                }
                indicator.sourceOrdinal = index;
                if (truncated)
                {
                    indicator.limitations.push_back(
                        "Network Intelligence source metadata was truncated to its bounded representation.");
                    result.truncated = true;
                }
                if (!AddObservationRecord(
                        result,
                        entityScope,
                        std::move(indicator)))
                {
                    return;
                }
            }

            if (network.truncated ||
                network.connections.size() > connectionCount)
            {
                AddCollectionNote(
                    result,
                    entityScope,
                    NativeMappingNetworkTruncated,
                    "network.collection-truncated",
                    "Network evidence was truncated",
                    "Additional selected-process network context was omitted by a bounded capture cap.",
                    std::to_string(network.omittedContextFactCount),
                    ObservationArtifactKind::Process,
                    processArtifact,
                    network.source,
                    { "Omitted public-connection context does not independently determine the verdict." },
                    connectionCount + indicatorCount);
            }
        }

        void BuildModuleObservations(
            NativeObservationBuildResult& result,
            const NativeSelectedProcessObservationInput& input,
            const std::string& entityScope,
            const std::string& processArtifact)
        {
            const NativeModuleObservationInput& modules = input.modules;
            if (!modules.supplied && !modules.collectionAttempted)
            {
                return;
            }
            if (!SameIdentity(modules.identity, input.identity))
            {
                result.success = false;
                result.status = NativeObservationBuildStatus::InvalidIdentity;
                result.diagnostic =
                    "Module source identity does not match the selected process identity.";
                return;
            }
            if (!modules.available || !modules.collection.success)
            {
                bool truncated = false;
                const std::string status = WideToUtf8Bounded(
                    modules.collection.statusMessage,
                    ObservationLimitationItemMaxCharacters,
                    truncated);
                AddCollectionNote(
                    result,
                    entityScope,
                    NativeMappingModulesUnavailable,
                    "modules.collection-unavailable",
                    "Module metadata unavailable",
                    "Module enumeration was attempted but unavailable.",
                    status,
                    ObservationArtifactKind::Process,
                    processArtifact,
                    modules.source,
                    { status.empty()
                        ? "Module enumeration did not return details."
                        : status });
                result.truncated = result.truncated || truncated;
                return;
            }

            const std::size_t count = (std::min)(
                modules.collection.modules.size(),
                NativeObservationMaxModules);
            for (std::size_t index = 0; index < count; ++index)
            {
                const ModuleInfo& module = modules.collection.modules[index];
                bool truncated = false;
                const std::string rawPath = WideToUtf8Bounded(
                    module.modulePath,
                    ObservationRawValueMaxCharacters,
                    truncated);
                const std::string normalizedPath =
                    LowerAscii(rawPath);
                const std::string baseAddress = WideToUtf8Bounded(
                    module.baseAddress,
                    128,
                    truncated);
                std::string identityMaterial = normalizedPath + "|" +
                    baseAddress + "|" + std::to_string(module.sizeBytes);
                if (normalizedPath.empty() && baseAddress.empty() &&
                    module.sizeBytes == 0)
                {
                    identityMaterial += "|ordinal:" +
                        std::to_string(index);
                }
                const std::string artifactKey =
                    "module:" + FingerprintText(identityMaterial);
                if (rawPath.empty())
                {
                    NativeObservationSource source = modules.source;
                    source.completeness =
                        ObservationSourceCompleteness::Unavailable;
                    AddCollectionNote(
                        result,
                        entityScope,
                        NativeMappingModulePathUnavailable,
                        "module.path-unavailable|" + artifactKey,
                        "Module path unavailable",
                        "A captured module record did not include a resolved path.",
                        baseAddress,
                        ObservationArtifactKind::Module,
                        artifactKey,
                        std::move(source),
                        { "An unavailable module path does not establish benign or suspicious behavior." },
                        index);
                    if (!result.success)
                    {
                        return;
                    }
                    continue;
                }

                const NativeFilePathContext pathContext =
                    ClassifyNativeFilePathContext(normalizedPath);
                ObservationSpec context;
                context.mappingRuleId = pathContext ==
                        NativeFilePathContext::UserWritable
                    ? NativeMappingModuleUserWritablePath
                    : NativeMappingModuleContext;
                context.sourceRuleId = context.mappingRuleId;
                context.semanticFactKey =
                    "module.path-context|" + artifactKey;
                context.title = pathContext ==
                        NativeFilePathContext::UserWritable
                    ? "Module path is in a user-writable location"
                    : "Loaded module metadata observed";
                context.summary = pathContext ==
                        NativeFilePathContext::UserWritable
                    ? "A loaded module path was classified in a broadly user-writable location; path context alone is non-contributing."
                    : "Loaded-image identity and path metadata were retained as context.";
                context.domain = EvidenceDomain::Module;
                context.disposition = ObservationDisposition::Context;
                context.strength = pathContext ==
                        NativeFilePathContext::UserWritable
                    ? ObservationStrength::Weak
                    : ObservationStrength::None;
                context.confidence = ObservationConfidence::High;
                context.groupingKey = "loaded-module-context";
                context.rawValue = rawPath;
                context.normalizedValue = normalizedPath;
                context.artifactIdentity = {
                    ObservationArtifactKind::Module,
                    entityScope,
                    artifactKey
                };
                context.attributes = {
                    { "module.base-address", baseAddress },
                    { "module.size-bytes",
                        std::to_string(module.sizeBytes) },
                    { "module.readable",
                        module.readable ? "true" : "false" },
                    { "module.path-context",
                        pathContext == NativeFilePathContext::UserWritable
                            ? "user-writable"
                            : "available" }
                };
                context.evidence.push_back(BoundedCopy(
                    "Module path: " + rawPath,
                    ObservationEvidenceItemMaxCharacters,
                    truncated));
                if (!baseAddress.empty())
                {
                    context.evidence.push_back(
                        "Module base address: " + baseAddress);
                }
                context.evidence.push_back(
                    "Module size: " + std::to_string(module.sizeBytes) +
                    " bytes");
                context.source = modules.source;
                context.sourceOrdinal = index;
                if (truncated)
                {
                    context.limitations.push_back(
                        "A module metadata field was truncated to its bounded representation.");
                    result.truncated = true;
                }
                if (!AddObservationRecord(
                        result,
                        entityScope,
                        std::move(context)))
                {
                    return;
                }
            }

            if (modules.truncated ||
                modules.collection.modules.size() > count)
            {
                AddCollectionNote(
                    result,
                    entityScope,
                    NativeMappingModulesTruncated,
                    "modules.collection-truncated",
                    "Module evidence was truncated",
                    "Additional module context was omitted by a bounded capture cap.",
                    std::to_string(modules.omittedContextFactCount),
                    ObservationArtifactKind::Process,
                    processArtifact,
                    modules.source,
                    { "Omitted module path context does not independently determine the verdict." },
                    count);
            }
        }

        void BuildMemoryObservations(
            NativeObservationBuildResult& result,
            const NativeSelectedProcessObservationInput& input,
            const std::string& entityScope,
            const std::string& processArtifact)
        {
            const NativeMemoryObservationInput& memory = input.memory;
            if (!memory.supplied && !memory.collectionAttempted)
            {
                return;
            }
            if (!SameIdentity(memory.identity, input.identity))
            {
                result.success = false;
                result.status = NativeObservationBuildStatus::InvalidIdentity;
                result.diagnostic =
                    "Memory source identity does not match the selected process identity.";
                return;
            }
            if (!memory.available || !memory.collection.success)
            {
                bool truncated = false;
                const std::string status = WideToUtf8Bounded(
                    memory.collection.statusMessage,
                    ObservationLimitationItemMaxCharacters,
                    truncated);
                AddCollectionNote(
                    result,
                    entityScope,
                    NativeMappingMemoryUnavailable,
                    "memory.collection-unavailable",
                    "Memory-region metadata unavailable",
                    "Memory-region metadata collection was attempted but unavailable.",
                    status,
                    ObservationArtifactKind::Process,
                    processArtifact,
                    memory.source,
                    { status.empty()
                        ? "Memory-region collection did not return details."
                        : status });
                result.truncated = result.truncated || truncated;
                return;
            }

            const std::size_t count = (std::min)(
                memory.collection.regions.size(),
                NativeObservationMaxMemoryRegions);
            for (std::size_t index = 0; index < count; ++index)
            {
                const MemoryRegionInfo& region =
                    memory.collection.regions[index];
                const bool writableExecutable =
                    region.isWritable && region.isExecutable;
                const bool privateExecutable =
                    region.isPrivate && region.isExecutable;
                const bool executableUnbacked = region.isExecutable &&
                    !region.isImage && !region.isMapped &&
                    region.mappedFilePath.empty();
                if (!writableExecutable && !privateExecutable &&
                    !executableUnbacked && !region.isGuard)
                {
                    continue;
                }
                if (region.regionSize == 0)
                {
                    continue;
                }
                const std::string artifactKey =
                    "memory-region:" + HexValue(region.baseAddress) + ":" +
                    HexValue(region.allocationBase) + ":" +
                    HexValue(region.regionSize);
                ObservationSpec context;
                context.mappingRuleId = NativeMappingStaticMemoryContext;
                context.sourceRuleId = NativeMappingStaticMemoryContext;
                context.semanticFactKey =
                    "memory.static-region-context|" + artifactKey;
                context.title = region.isExecutable
                    ? "Static executable-memory metadata observed"
                    : "Static guard-page metadata observed";
                context.summary =
                    "Point-in-time memory-region properties were retained as context and do not establish injection, payload execution, or malicious activity.";
                context.domain = EvidenceDomain::MemoryMetadata;
                context.disposition = ObservationDisposition::Context;
                context.strength = ObservationStrength::Weak;
                context.confidence = ObservationConfidence::High;
                context.groupingKey = "static-memory-region-context";
                context.rawValue = HexValue(region.baseAddress) + "|" +
                    HexValue(region.regionSize);
                context.normalizedValue = context.rawValue;
                context.artifactIdentity = {
                    ObservationArtifactKind::MemoryRegion,
                    entityScope,
                    artifactKey
                };
                context.attributes = {
                    { "memory.base-address",
                        HexValue(region.baseAddress) },
                    { "memory.allocation-base",
                        HexValue(region.allocationBase) },
                    { "memory.region-size",
                        HexValue(region.regionSize) },
                    { "memory.state-raw",
                        HexValue(region.stateRaw) },
                    { "memory.type-raw",
                        HexValue(region.typeRaw) },
                    { "memory.protection-raw",
                        HexValue(region.protectRaw) },
                    { "memory.writable",
                        region.isWritable ? "true" : "false" },
                    { "memory.executable",
                        region.isExecutable ? "true" : "false" },
                    { "memory.private",
                        region.isPrivate ? "true" : "false" },
                    { "memory.image-backed",
                        region.isImage ? "true" : "false" },
                    { "memory.mapped-file-backed",
                        (region.isMapped || !region.mappedFilePath.empty())
                            ? "true"
                            : "false" },
                    { "memory.guarded",
                        region.isGuard ? "true" : "false" }
                };
                context.evidence = {
                    "Base address: " + HexValue(region.baseAddress),
                    "Region size: " + HexValue(region.regionSize),
                    "Protection value: " + HexValue(region.protectRaw),
                    std::string("Region properties: ") +
                        (region.isWritable ? "writable, " : "") +
                        (region.isExecutable ? "executable, " : "") +
                        (region.isPrivate ? "private, " : "") +
                        (region.isImage ? "image-backed, " : "") +
                        (region.isMapped || !region.mappedFilePath.empty()
                            ? "mapped-file-backed, "
                            : "unbacked, ") +
                        (region.isGuard ? "guarded" : "not guarded")
                };
                context.source = memory.source;
                context.sourceOrdinal = index;
                if (!AddObservationRecord(
                        result,
                        entityScope,
                        std::move(context)))
                {
                    return;
                }
            }

            if (memory.truncated ||
                memory.collection.regions.size() > count)
            {
                AddCollectionNote(
                    result,
                    entityScope,
                    NativeMappingMemoryTruncated,
                    "memory.collection-truncated",
                    "Memory-region evidence was truncated",
                    "Additional static memory-region context was omitted by a bounded capture cap.",
                    std::to_string(memory.omittedContextFactCount),
                    ObservationArtifactKind::Process,
                    processArtifact,
                    memory.source,
                    { "Omitted static region metadata does not independently determine the verdict." },
                    count);
            }
        }

        void BuildAffinityObservation(
            NativeObservationBuildResult& result,
            const NativeSelectedProcessObservationInput& input,
            const std::string& entityScope,
            const std::string& processArtifact)
        {
            const NativeAffinityObservationInput& affinity = input.affinity;
            if (!affinity.supplied && !affinity.collectionAttempted)
            {
                return;
            }
            if (!SameIdentity(affinity.identity, input.identity))
            {
                result.success = false;
                result.status = NativeObservationBuildStatus::InvalidIdentity;
                result.diagnostic =
                    "Affinity source identity does not match the selected process identity.";
                return;
            }
            if (!affinity.available || affinity.processAffinityMask == 0 ||
                affinity.systemAffinityMask == 0)
            {
                AddCollectionNote(
                    result,
                    entityScope,
                    NativeMappingAffinityUnavailable,
                    "runtime.affinity-unavailable",
                    "Process affinity metadata unavailable",
                    "Process affinity collection was attempted but unavailable.",
                    affinity.source.rawSourceReference,
                    ObservationArtifactKind::Process,
                    processArtifact,
                    affinity.source,
                    { "Affinity availability does not establish benign or suspicious activity." });
                return;
            }

            const std::size_t selectedProcessorCount =
                SetBitCount(affinity.processAffinityMask);
            const std::size_t activeProcessorCount =
                SetBitCount(affinity.systemAffinityMask);
            const bool constrained =
                affinity.processAffinityMask != affinity.systemAffinityMask;
            ObservationSpec context;
            context.mappingRuleId = NativeMappingAffinityContext;
            context.sourceRuleId = NativeMappingAffinityContext;
            context.semanticFactKey = "runtime.affinity-context";
            context.title = selectedProcessorCount == 1
                ? "Single-processor affinity observed"
                : constrained
                    ? "Constrained process affinity observed"
                    : "Process affinity metadata observed";
            context.summary =
                "Process affinity is execution context only and does not independently affect attention.";
            context.domain = EvidenceDomain::Runtime;
            context.disposition = ObservationDisposition::Context;
            context.strength = ObservationStrength::None;
            context.confidence = ObservationConfidence::High;
            context.groupingKey = "process-affinity-context";
            context.rawValue = HexValue(affinity.processAffinityMask);
            context.normalizedValue = context.rawValue;
            context.artifactIdentity = {
                ObservationArtifactKind::RuntimeObject,
                entityScope,
                processArtifact + "|affinity"
            };
            context.attributes = {
                { "affinity.process-mask",
                    HexValue(affinity.processAffinityMask) },
                { "affinity.system-mask",
                    HexValue(affinity.systemAffinityMask) },
                { "affinity.selected-processor-count",
                    std::to_string(selectedProcessorCount) },
                { "affinity.active-processor-count",
                    std::to_string(activeProcessorCount) },
                { "affinity.single-processor",
                    selectedProcessorCount == 1 ? "true" : "false" },
                { "affinity.constrained",
                    constrained ? "true" : "false" }
            };
            context.evidence = {
                "Selected processors: " +
                    std::to_string(selectedProcessorCount) + " of " +
                    std::to_string(activeProcessorCount) + " active processors",
                "Process affinity mask: " +
                    HexValue(affinity.processAffinityMask)
            };
            context.source = affinity.source;
            AddObservationRecord(result, entityScope, std::move(context));
        }
    }

    std::string ObservationSourceCompletenessDisplayText(
        ObservationSourceCompleteness completeness)
    {
        switch (completeness)
        {
        case ObservationSourceCompleteness::Complete:
            return "Complete";
        case ObservationSourceCompleteness::Partial:
            return "Partial";
        case ObservationSourceCompleteness::Unavailable:
            return "Unavailable";
        default:
            return "Unknown source completeness";
        }
    }

    std::string NativeEncodedPayloadEncodingDisplayText(
        NativeEncodedPayloadEncoding encoding)
    {
        switch (encoding)
        {
        case NativeEncodedPayloadEncoding::None:
            return "none";
        case NativeEncodedPayloadEncoding::Utf8:
            return "utf-8";
        case NativeEncodedPayloadEncoding::Utf16LittleEndian:
            return "utf-16le";
        case NativeEncodedPayloadEncoding::Binary:
            return "binary";
        case NativeEncodedPayloadEncoding::InvalidBase64:
            return "invalid-base64";
        case NativeEncodedPayloadEncoding::LimitExceeded:
            return "limit-exceeded";
        default:
            return "unknown";
        }
    }

    std::string NativeObservationBuildStatusDisplayText(
        NativeObservationBuildStatus status)
    {
        switch (status)
        {
        case NativeObservationBuildStatus::NotAttempted:
            return "Not attempted";
        case NativeObservationBuildStatus::Success:
            return "Success";
        case NativeObservationBuildStatus::InvalidIdentity:
            return "Invalid identity";
        case NativeObservationBuildStatus::InputLimitExceeded:
            return "Input limit exceeded";
        case NativeObservationBuildStatus::InvalidTypedFact:
            return "Invalid typed fact";
        case NativeObservationBuildStatus::PolicyValidationFailed:
            return "Policy validation failed";
        default:
            return "Unknown native observation status";
        }
    }

    NativeFilePathContext ClassifyNativeFilePathContext(
        std::string_view normalizedExecutablePath)
    {
        if (normalizedExecutablePath.empty())
        {
            return NativeFilePathContext::Unavailable;
        }
        const std::string lowered = LowerAscii(
            std::string(normalizedExecutablePath));
        const auto contains = [&](std::string_view segment)
        {
            return lowered.find(segment) != std::string::npos;
        };
        return contains("\\users\\") ||
            contains("\\appdata\\") ||
            contains("\\temp\\") ||
            contains("\\downloads\\") ||
            contains("\\desktop\\")
                ? NativeFilePathContext::UserWritable
                : NativeFilePathContext::Available;
    }


    NativeObservationMergeResult MergeNativeObservationRecords(
        const std::vector<NativeObservationRecord>& records)
    {
        NativeObservationMergeResult result;
        if (records.size() > NativeObservationMaxMergeRecords)
        {
            result.diagnostic =
                "Native observation merge input exceeded its bounded cap.";
            return result;
        }

        result.records = records;
        struct Group
        {
            std::vector<std::size_t> indexes;
            std::size_t winner = 0;
        };
        std::vector<Group> groups;
        std::map<std::string, std::size_t> groupByKey;

        for (std::size_t index = 0; index < result.records.size(); ++index)
        {
            NativeObservationRecord& source = result.records[index];
            if (source.semanticFactKey.size() >
                    NativeObservationSemanticFactKeyMaxCharacters ||
                source.record.observation.entityScope.size() >
                    ObservationEntityScopeMaxCharacters ||
                !ValidateObservation(source.record.observation).IsValid())
            {
                result.records.clear();
                result.diagnostic =
                    "Native observation merge received an invalid bounded record.";
                return result;
            }
            switch (source.completeness)
            {
            case ObservationSourceCompleteness::Complete:
                ++result.completeSourceCount;
                break;
            case ObservationSourceCompleteness::Partial:
                ++result.partialSourceCount;
                break;
            case ObservationSourceCompleteness::Unavailable:
                ++result.unavailableSourceCount;
                break;
            default:
                result.records.clear();
                result.diagnostic =
                    "Native observation merge received unknown completeness.";
                return result;
            }

            std::string groupKey;
            if (source.semanticFactKey.empty())
            {
                groupKey = "unique:" + std::to_string(index);
            }
            else
            {
                groupKey = source.record.observation.entityScope + "\x1f" +
                    source.semanticFactKey;
            }
            const auto found = groupByKey.find(groupKey);
            if (found == groupByKey.end())
            {
                Group group;
                group.indexes.push_back(index);
                group.winner = index;
                groupByKey.emplace(groupKey, groups.size());
                groups.push_back(std::move(group));
            }
            else
            {
                Group& group = groups[found->second];
                group.indexes.push_back(index);
                if (BetterPrimary(source, result.records[group.winner]))
                {
                    group.winner = index;
                }
            }
        }

        result.inventory.status = ObservationInventoryStatus::Success;
        result.inventory.declaredSourceFactCount = result.records.size();
        for (const Group& group : groups)
        {
            const NativeObservationRecord& winner =
                result.records[group.winner];
            for (const std::size_t index : group.indexes)
            {
                NativeObservationRecord& record = result.records[index];
                record.primaryObservationId =
                    winner.record.observation.id;
                record.duplicateRole = index == group.winner
                    ? ObservationDuplicateRole::Primary
                    : ObservationDuplicateRole::SupportingDuplicate;
                if (index != group.winner)
                {
                    ++result.duplicateCount;
                }
            }
            result.inventory.records.push_back(winner.record);
            CountDisposition(
                result.inventory,
                winner.record.observation.disposition);
        }
        result.inventory.typedSourceFactCount =
            result.inventory.records.size();
        result.primaryCount = result.inventory.records.size();
        result.success = true;
        result.diagnostic =
            "Native observation merge completed: " +
            std::to_string(result.primaryCount) + " primary records, " +
            std::to_string(result.duplicateCount) + " supporting duplicates.";
        LimitString(result.diagnostic, NativeObservationDiagnosticMaxCharacters);
        return result;
    }

    bool NativeObservationBuildResult::Succeeded() const
    {
        return attempted && success &&
            status == NativeObservationBuildStatus::Success &&
            inventory.Succeeded();
    }

    NativeObservationBuildResult BuildNativeSelectedProcessObservations(
        const NativeSelectedProcessObservationInput& input) noexcept
    {
        NativeObservationBuildResult result;
        result.attempted = true;
        try
        {
            if (!ValidIdentity(input.identity))
            {
                result.status = NativeObservationBuildStatus::InvalidIdentity;
                result.diagnostic =
                    "The selected process identity is contradictory.";
                return result;
            }
            const std::string entityScope = input.entityScope.empty()
                ? EntityScope(input.identity)
                : input.entityScope;
            if (entityScope.empty() ||
                entityScope.size() > ObservationEntityScopeMaxCharacters)
            {
                result.status = NativeObservationBuildStatus::InvalidIdentity;
                result.diagnostic =
                    "The selected process entity scope is missing or exceeds its cap.";
                return result;
            }
            if (input.commandLine.commandLine.size() >
                    NativeObservationMaxCommandLineCharacters ||
                input.relationships.size() >
                    NativeObservationMaxRelationshipFacts ||
                input.limitations.size() > ObservationMaxLimitationItems)
            {
                result.status =
                    NativeObservationBuildStatus::InputLimitExceeded;
                result.diagnostic =
                    "Native selected-process typed input exceeded a bounded cap.";
                return result;
            }

            result.success = true;
            const std::string processArtifact =
                ProcessArtifactKey(input.identity);
            BuildCommandObservations(
                result,
                input,
                entityScope,
                processArtifact);
            if (!result.success)
            {
                result.records.clear();
                return result;
            }
            BuildRelationshipObservations(
                result,
                input,
                entityScope,
                processArtifact);
            if (!result.success)
            {
                result.records.clear();
                return result;
            }
            BuildFileObservations(result, input, entityScope);
            if (!result.success)
            {
                result.records.clear();
                return result;
            }
            result.commandRelationshipFileFactCount = result.records.size();

            const std::size_t beforeNetwork = result.records.size();
            BuildNetworkObservations(
                result,
                input,
                entityScope,
                processArtifact);
            if (!result.success)
            {
                result.records.clear();
                return result;
            }
            result.networkFactCount = result.records.size() - beforeNetwork;

            const std::size_t beforeModules = result.records.size();
            BuildModuleObservations(
                result,
                input,
                entityScope,
                processArtifact);
            if (!result.success)
            {
                result.records.clear();
                return result;
            }
            result.moduleFactCount = result.records.size() - beforeModules;

            const std::size_t beforeMemory = result.records.size();
            BuildMemoryObservations(
                result,
                input,
                entityScope,
                processArtifact);
            if (!result.success)
            {
                result.records.clear();
                return result;
            }
            result.memoryFactCount = result.records.size() - beforeMemory;

            const std::size_t beforeAffinity = result.records.size();
            BuildAffinityObservation(
                result,
                input,
                entityScope,
                processArtifact);
            if (!result.success)
            {
                result.records.clear();
                return result;
            }
            result.affinityFactCount = result.records.size() - beforeAffinity;

            const auto appendNativeRecord = [&result](
                ObservationRecord record,
                std::string semanticFactKey,
                ObservationSourceCompleteness completeness)
            {
                if (result.records.size() >=
                    NativeObservationMaxOutputRecords)
                {
                    result.success = false;
                    result.status =
                        NativeObservationBuildStatus::InputLimitExceeded;
                    result.diagnostic =
                        "Combined native selected-process observations exceeded their bounded cap.";
                    return false;
                }
                NativeObservationRecord nativeRecord;
                nativeRecord.record = std::move(record);
                nativeRecord.completeness = completeness;
                nativeRecord.semanticFactKey = std::move(semanticFactKey);
                nativeRecord.sourceRecordId =
                    nativeRecord.record.source.sourceRecordId;
                nativeRecord.primaryObservationId =
                    nativeRecord.record.observation.id;
                result.records.push_back(std::move(nativeRecord));
                return true;
            };

            if (input.token.supplied || input.token.collectionAttempted)
            {
                NativeTokenObservationBuildResult token =
                    BuildNativeTokenObservations(input.token);
                result.tokenProducerAttempted = token.attempted;
                result.tokenProducerSucceeded = token.Succeeded();
                if (!result.tokenProducerSucceeded)
                {
                    result.success = false;
                    result.status =
                        token.status ==
                            NativeTokenObservationBuildStatus::InputLimitExceeded
                            ? NativeObservationBuildStatus::InputLimitExceeded
                            : NativeObservationBuildStatus::PolicyValidationFailed;
                    result.diagnostic = token.diagnostic.empty()
                        ? "Native token observation production failed."
                        : token.diagnostic;
                    result.records.clear();
                    return result;
                }
                result.tokenFactCount = token.inventory.records.size();
                result.omittedFactCount += token.omittedFactCount;
                result.truncated = result.truncated || token.truncated;
                for (NativeTokenObservationRecord& source : token.records)
                {
                    ObservationSourceCompleteness completeness =
                        ObservationSourceCompleteness::Complete;
                    if (source.completeness ==
                        NativeTokenSourceCompleteness::Partial)
                    {
                        completeness = ObservationSourceCompleteness::Partial;
                    }
                    else if (source.completeness ==
                        NativeTokenSourceCompleteness::Unavailable)
                    {
                        completeness =
                            ObservationSourceCompleteness::Unavailable;
                    }
                    if (!appendNativeRecord(
                            std::move(source.record),
                            std::move(source.semanticFactKey),
                            completeness))
                    {
                        result.records.clear();
                        return result;
                    }
                }
            }

            if (input.handles.supplied || input.handles.collectionAttempted)
            {
                NativeHandleObservationBuildResult handles =
                    BuildNativeHandleObservations(input.handles);
                result.handleProducerAttempted = handles.attempted;
                result.handleProducerSucceeded = handles.Succeeded();
                if (!result.handleProducerSucceeded)
                {
                    result.success = false;
                    result.status =
                        handles.status ==
                            NativeHandleObservationBuildStatus::InputLimitExceeded
                            ? NativeObservationBuildStatus::InputLimitExceeded
                            : NativeObservationBuildStatus::PolicyValidationFailed;
                    result.diagnostic = handles.diagnostic.empty()
                        ? "Native handle observation production failed."
                        : handles.diagnostic;
                    result.records.clear();
                    return result;
                }
                result.handleFactCount = handles.inventory.records.size();
                result.handleDuplicateRowCount =
                    handles.duplicateRowCount;
                if (handles.materialEvidenceOmitted)
                {
                    result.omittedFactCount += handles.omittedHandleCount;
                }
                // Handle presentation/enrichment fields may be bounded without
                // omitting a typed access fact. Only omitted core handle rows
                // make the aggregate native input materially incomplete.
                result.truncated = result.truncated ||
                    handles.materialEvidenceOmitted;
                for (NativeHandleObservationRecord& source :
                    handles.records)
                {
                    if (!appendNativeRecord(
                            std::move(source.record),
                            std::move(source.semanticFactKey),
                            ObservationSourceCompleteness::Complete))
                    {
                        result.records.clear();
                        return result;
                    }
                }
            }

            if (input.runtime.supplied || input.runtime.collectionAttempted)
            {
                NativeRuntimeObservationBuildResult runtime =
                    BuildNativeRuntimeObservations(input.runtime);
                result.runtimeProducerAttempted = runtime.attempted;
                result.runtimeProducerSucceeded = runtime.Succeeded();
                if (!result.runtimeProducerSucceeded)
                {
                    result.success = false;
                    result.status =
                        runtime.status ==
                            NativeRuntimeObservationBuildStatus::InputLimitExceeded
                            ? NativeObservationBuildStatus::InputLimitExceeded
                            : NativeObservationBuildStatus::PolicyValidationFailed;
                    result.diagnostic = runtime.diagnostic.empty()
                        ? "Native runtime observation production failed."
                        : runtime.diagnostic;
                    result.records.clear();
                    return result;
                }
                result.runtimeFactCount = runtime.inventory.records.size();
                result.omittedFactCount +=
                    runtime.omittedMaterialFactCount;
                result.truncated = result.truncated || runtime.truncated;
                for (NativeRuntimeObservationRecord& source :
                    runtime.records)
                {
                    ObservationSourceCompleteness completeness =
                        ObservationSourceCompleteness::Complete;
                    if (source.completeness ==
                        NativeRuntimeSourceCompleteness::Partial)
                    {
                        completeness = ObservationSourceCompleteness::Partial;
                    }
                    else if (source.completeness ==
                        NativeRuntimeSourceCompleteness::Unavailable)
                    {
                        completeness =
                            ObservationSourceCompleteness::Unavailable;
                    }
                    if (!appendNativeRecord(
                            std::move(source.record),
                            std::move(source.semanticFactKey),
                            completeness))
                    {
                        result.records.clear();
                        return result;
                    }
                }
            }

            if (input.priority.supplied || input.priority.collectionAttempted)
            {
                NativeRuntimeObservationBuildResult priority =
                    BuildNativePriorityObservations(input.priority);
                result.priorityProducerAttempted = priority.attempted;
                result.priorityProducerSucceeded = priority.Succeeded();
                if (!result.priorityProducerSucceeded)
                {
                    result.success = false;
                    result.status =
                        priority.status ==
                            NativeRuntimeObservationBuildStatus::InputLimitExceeded
                            ? NativeObservationBuildStatus::InputLimitExceeded
                            : NativeObservationBuildStatus::PolicyValidationFailed;
                    result.diagnostic = priority.diagnostic.empty()
                        ? "Native priority observation production failed."
                        : priority.diagnostic;
                    result.records.clear();
                    return result;
                }
                result.priorityFactCount = priority.inventory.records.size();
                result.omittedFactCount +=
                    priority.omittedMaterialFactCount;
                result.truncated = result.truncated || priority.truncated;
                for (NativeRuntimeObservationRecord& source :
                    priority.records)
                {
                    ObservationSourceCompleteness completeness =
                        ObservationSourceCompleteness::Complete;
                    if (source.completeness ==
                        NativeRuntimeSourceCompleteness::Partial)
                    {
                        completeness = ObservationSourceCompleteness::Partial;
                    }
                    else if (source.completeness ==
                        NativeRuntimeSourceCompleteness::Unavailable)
                    {
                        completeness =
                            ObservationSourceCompleteness::Unavailable;
                    }
                    if (!appendNativeRecord(
                            std::move(source.record),
                            std::move(source.semanticFactKey),
                            completeness))
                    {
                        result.records.clear();
                        return result;
                    }
                }
            }
            if (!ApplyGlobalLimitations(result, input.limitations))
            {
                return result;
            }

            const NativeObservationMergeResult merged =
                MergeNativeObservationRecords(result.records);
            if (!merged.success)
            {
                result.success = false;
                result.status =
                    NativeObservationBuildStatus::PolicyValidationFailed;
                result.diagnostic = merged.diagnostic;
                result.records.clear();
                return result;
            }
            result.records = merged.records;
            result.inventory = merged.inventory;
            result.nativeFactCount = result.records.size();
            result.representedFactCount = result.inventory.records.size();
            result.duplicateCount = merged.duplicateCount;
            result.completeFactCount = merged.completeSourceCount;
            result.partialFactCount = merged.partialSourceCount;
            result.unavailableFactCount = merged.unavailableSourceCount;
            result.status = NativeObservationBuildStatus::Success;
            result.diagnostic =
                "Native selected-process observations built: " +
                std::to_string(result.representedFactCount) +
                " typed facts represented";
            if (result.duplicateCount != 0)
            {
                result.diagnostic += ", " +
                    std::to_string(result.duplicateCount) +
                    " duplicates retained as supporting sources";
            }
            result.diagnostic += '.';
            LimitString(
                result.diagnostic,
                NativeObservationDiagnosticMaxCharacters);
            return result;
        }
        catch (...)
        {
            result.success = false;
            result.status =
                NativeObservationBuildStatus::PolicyValidationFailed;
            result.records.clear();
            result.inventory = {};
            result.diagnostic =
                "Native selected-process observation construction failed internally.";
            return result;
        }
    }
}
