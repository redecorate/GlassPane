#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "SavedSnapshot.h"

#include "../Core/ProcessTree.h"

#include <Windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

namespace GlassPane::Export
{
    namespace
    {
        struct JsonValue
        {
            enum class Type
            {
                Null,
                Object,
                Array,
                String,
                Number,
                Boolean
            };

            Type type = Type::Null;
            std::map<std::wstring, JsonValue> objectValue;
            std::vector<JsonValue> arrayValue;
            std::wstring stringValue;
            double numberValue = 0.0;
            bool boolValue = false;
        };

        std::string WideToUtf8(const std::wstring& value)
        {
            if (value.empty())
            {
                return {};
            }

            const int required = WideCharToMultiByte(
                CP_UTF8,
                0,
                value.data(),
                static_cast<int>(value.size()),
                nullptr,
                0,
                nullptr,
                nullptr);
            if (required <= 0)
            {
                return {};
            }

            std::string result(static_cast<std::size_t>(required), '\0');
            WideCharToMultiByte(
                CP_UTF8,
                0,
                value.data(),
                static_cast<int>(value.size()),
                result.data(),
                required,
                nullptr,
                nullptr);
            return result;
        }

        bool TryUtf8ToWide(
            const char* value,
            std::size_t length,
            std::wstring& result)
        {
            if (value == nullptr || length == 0)
            {
                result.clear();
                return value != nullptr || length == 0;
            }

            const int required = MultiByteToWideChar(
                CP_UTF8,
                MB_ERR_INVALID_CHARS,
                value,
                static_cast<int>(length),
                nullptr,
                0);
            if (required <= 0)
            {
                result.clear();
                return false;
            }

            result.assign(static_cast<std::size_t>(required), L'\0');
            return MultiByteToWideChar(
                CP_UTF8,
                MB_ERR_INVALID_CHARS,
                value,
                static_cast<int>(length),
                result.data(),
                required) == required;
        }

        std::wstring Utf8ToWide(const char* value, std::size_t length)
        {
            std::wstring result;
            TryUtf8ToWide(value, length, result);
            return result;
        }

        std::string EscapeJson(const std::string& value)
        {
            std::string escaped;
            escaped.reserve(value.size() + 8);
            for (const unsigned char ch : value)
            {
                switch (ch)
                {
                case '\\':
                    escaped += "\\\\";
                    break;
                case '"':
                    escaped += "\\\"";
                    break;
                case '\b':
                    escaped += "\\b";
                    break;
                case '\f':
                    escaped += "\\f";
                    break;
                case '\n':
                    escaped += "\\n";
                    break;
                case '\r':
                    escaped += "\\r";
                    break;
                case '\t':
                    escaped += "\\t";
                    break;
                default:
                    if (ch < 0x20)
                    {
                        constexpr char Hex[] = "0123456789abcdef";
                        escaped += "\\u00";
                        escaped += Hex[(ch >> 4) & 0x0f];
                        escaped += Hex[ch & 0x0f];
                    }
                    else
                    {
                        escaped.push_back(static_cast<char>(ch));
                    }
                    break;
                }
            }
            return escaped;
        }

        void WriteJsonString(std::ostream& output, const std::wstring& value)
        {
            if (value.size() <= SnapshotMaxStringLength)
            {
                output << '"' << EscapeJson(WideToUtf8(value)) << '"';
                return;
            }

            constexpr std::wstring_view Suffix = L"...[truncated]";
            const std::size_t prefixLength = SnapshotMaxStringLength > Suffix.size()
                ? SnapshotMaxStringLength - Suffix.size()
                : SnapshotMaxStringLength;
            std::wstring truncated = value.substr(0, prefixLength);
            if (SnapshotMaxStringLength > Suffix.size())
            {
                truncated += Suffix;
            }
            output << '"' << EscapeJson(WideToUtf8(truncated)) << '"';
        }

        void WriteJsonStringArray(std::ostream& output, const std::vector<std::wstring>& values)
        {
            output << '[';
            for (std::size_t index = 0; index < values.size(); ++index)
            {
                if (index > 0)
                {
                    output << ", ";
                }
                WriteJsonString(output, values[index]);
            }
            output << ']';
        }

        void AppendCodepointUtf8(std::string& bytes, unsigned int codepoint)
        {
            if (codepoint <= 0x7f)
            {
                bytes.push_back(static_cast<char>(codepoint));
            }
            else if (codepoint <= 0x7ff)
            {
                bytes.push_back(static_cast<char>(0xc0 | ((codepoint >> 6) & 0x1f)));
                bytes.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
            }
            else if (codepoint <= 0xffff)
            {
                bytes.push_back(static_cast<char>(0xe0 | ((codepoint >> 12) & 0x0f)));
                bytes.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f)));
                bytes.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
            }
            else
            {
                bytes.push_back(static_cast<char>(0xf0 | ((codepoint >> 18) & 0x07)));
                bytes.push_back(static_cast<char>(0x80 | ((codepoint >> 12) & 0x3f)));
                bytes.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f)));
                bytes.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
            }
        }

        const wchar_t* SeverityName(Core::Severity severity)
        {
            return Core::SeverityToString(severity);
        }

        Core::Severity ParseSeverity(const std::wstring& value)
        {
            if (value == L"High")
            {
                return Core::Severity::High;
            }
            if (value == L"Medium")
            {
                return Core::Severity::Medium;
            }
            if (value == L"Low")
            {
                return Core::Severity::Low;
            }
            if (value == L"Info")
            {
                return Core::Severity::Info;
            }
            return Core::Severity::None;
        }

        bool TryParseSeverity(
            const std::wstring& value,
            Core::Severity& severity)
        {
            if (value == L"High")
            {
                severity = Core::Severity::High;
                return true;
            }
            if (value == L"Medium")
            {
                severity = Core::Severity::Medium;
                return true;
            }
            if (value == L"Low")
            {
                severity = Core::Severity::Low;
                return true;
            }
            if (value == L"Info")
            {
                severity = Core::Severity::Info;
                return true;
            }
            if (value == L"None")
            {
                severity = Core::Severity::None;
                return true;
            }
            return false;
        }

        std::wstring UInt64String(std::uint64_t value)
        {
            return std::to_wstring(value);
        }

        std::uint64_t ParseUInt64String(const std::wstring& value)
        {
            if (value.empty())
            {
                return 0;
            }
            try
            {
                return static_cast<std::uint64_t>(std::stoull(value));
            }
            catch (...)
            {
                return 0;
            }
        }

        class JsonParser
        {
        public:
            explicit JsonParser(const std::string& text)
                : text_(text)
            {
            }

            bool Parse(JsonValue& value, std::wstring& error)
            {
                SkipWhitespace();
                if (!ParseValue(value, error))
                {
                    return false;
                }
                SkipWhitespace();
                if (position_ != text_.size())
                {
                    error = L"Unexpected trailing content in saved snapshot.";
                    return false;
                }
                return true;
            }

        private:
            void SkipWhitespace()
            {
                while (position_ < text_.size() &&
                    std::isspace(static_cast<unsigned char>(text_[position_])) != 0)
                {
                    ++position_;
                }
            }

            bool ConsumeLiteral(const char* literal)
            {
                const std::size_t length = std::strlen(literal);
                if (position_ + length > text_.size())
                {
                    return false;
                }
                if (text_.compare(position_, length, literal) != 0)
                {
                    return false;
                }
                position_ += length;
                return true;
            }

            bool RemainingTextIsLiteralPrefix(const char* literal) const
            {
                const std::size_t literalLength = std::strlen(literal);
                const std::size_t remainingLength = text_.size() - position_;
                return remainingLength < literalLength &&
                    text_.compare(position_, remainingLength, literal, remainingLength) == 0;
            }

            bool ParseValue(JsonValue& value, std::wstring& error)
            {
                SkipWhitespace();
                if (position_ >= text_.size())
                {
                    error = L"Unexpected end of file in saved snapshot at byte " + std::to_wstring(position_) + L".";
                    return false;
                }

                const char ch = text_[position_];
                if (ch == '{')
                {
                    return ParseObject(value, error);
                }
                if (ch == '[')
                {
                    return ParseArray(value, error);
                }
                if (ch == '"')
                {
                    value.type = JsonValue::Type::String;
                    return ParseString(value.stringValue, error);
                }
                if (ch == '-' || std::isdigit(static_cast<unsigned char>(ch)) != 0)
                {
                    value.type = JsonValue::Type::Number;
                    return ParseNumber(value.numberValue, error);
                }
                if (ConsumeLiteral("true"))
                {
                    value.type = JsonValue::Type::Boolean;
                    value.boolValue = true;
                    return true;
                }
                if (ConsumeLiteral("false"))
                {
                    value.type = JsonValue::Type::Boolean;
                    value.boolValue = false;
                    return true;
                }
                if (ConsumeLiteral("null"))
                {
                    value.type = JsonValue::Type::Null;
                    return true;
                }

                if (RemainingTextIsLiteralPrefix("true") ||
                    RemainingTextIsLiteralPrefix("false") ||
                    RemainingTextIsLiteralPrefix("null"))
                {
                    error = L"Unexpected end of file while reading a saved snapshot value.";
                    return false;
                }

                error = L"Unsupported JSON value in saved snapshot.";
                return false;
            }

            bool ParseObject(JsonValue& value, std::wstring& error)
            {
                value.type = JsonValue::Type::Object;
                ++position_;
                SkipWhitespace();
                if (position_ < text_.size() && text_[position_] == '}')
                {
                    ++position_;
                    return true;
                }

                while (position_ < text_.size())
                {
                    std::wstring key;
                    if (!ParseString(key, error))
                    {
                        return false;
                    }
                    SkipWhitespace();
                    if (position_ >= text_.size())
                    {
                        error = L"Unexpected end of file while reading saved snapshot object.";
                        return false;
                    }
                    if (text_[position_] != ':')
                    {
                        error = L"Expected ':' in saved snapshot object.";
                        return false;
                    }
                    ++position_;

                    JsonValue member;
                    if (!ParseValue(member, error))
                    {
                        return false;
                    }
                    const auto inserted = value.objectValue.emplace(
                        std::move(key),
                        std::move(member));
                    if (!inserted.second)
                    {
                        error = L"Duplicate key in saved snapshot object.";
                        return false;
                    }

                    SkipWhitespace();
                    if (position_ >= text_.size())
                    {
                        error = L"Unexpected end of file while reading saved snapshot object.";
                        return false;
                    }
                    if (text_[position_] == ',')
                    {
                        ++position_;
                        SkipWhitespace();
                        continue;
                    }
                    if (text_[position_] == '}')
                    {
                        ++position_;
                        return true;
                    }
                    error = L"Expected ',' or '}' in saved snapshot object.";
                    return false;
                }

                error = L"Unexpected end of file while reading saved snapshot object.";
                return false;
            }

            bool ParseArray(JsonValue& value, std::wstring& error)
            {
                value.type = JsonValue::Type::Array;
                ++position_;
                SkipWhitespace();
                if (position_ < text_.size() && text_[position_] == ']')
                {
                    ++position_;
                    return true;
                }

                while (position_ < text_.size())
                {
                    JsonValue item;
                    if (!ParseValue(item, error))
                    {
                        return false;
                    }
                    value.arrayValue.push_back(std::move(item));

                    SkipWhitespace();
                    if (position_ >= text_.size())
                    {
                        error = L"Unexpected end of file while reading saved snapshot array.";
                        return false;
                    }
                    if (text_[position_] == ',')
                    {
                        ++position_;
                        SkipWhitespace();
                        continue;
                    }
                    if (text_[position_] == ']')
                    {
                        ++position_;
                        return true;
                    }
                    error = L"Expected ',' or ']' in saved snapshot array.";
                    return false;
                }

                error = L"Unexpected end of file while reading saved snapshot array.";
                return false;
            }

            bool ParseString(std::wstring& value, std::wstring& error)
            {
                if (position_ >= text_.size() || text_[position_] != '"')
                {
                    error = L"Expected saved snapshot string.";
                    return false;
                }
                ++position_;

                std::string bytes;
                while (position_ < text_.size())
                {
                    const char ch = text_[position_++];
                    if (ch == '"')
                    {
                        if (!TryUtf8ToWide(bytes.data(), bytes.size(), value))
                        {
                            error = L"Invalid UTF-8 in saved snapshot string.";
                            return false;
                        }
                        return true;
                    }
                    if (ch != '\\')
                    {
                        if (static_cast<unsigned char>(ch) < 0x20)
                        {
                            error = L"Unescaped control character in saved snapshot string.";
                            return false;
                        }
                        bytes.push_back(ch);
                        continue;
                    }
                    if (position_ >= text_.size())
                    {
                        error = L"Unexpected end of file while reading saved snapshot string escape.";
                        return false;
                    }
                    const char escaped = text_[position_++];
                    switch (escaped)
                    {
                    case '"':
                    case '\\':
                    case '/':
                        bytes.push_back(escaped);
                        break;
                    case 'b':
                        bytes.push_back('\b');
                        break;
                    case 'f':
                        bytes.push_back('\f');
                        break;
                    case 'n':
                        bytes.push_back('\n');
                        break;
                    case 'r':
                        bytes.push_back('\r');
                        break;
                    case 't':
                        bytes.push_back('\t');
                        break;
                    case 'u':
                    {
                        const auto parseHexQuad = [this](
                            unsigned int& codeUnit,
                            std::wstring& parseError)
                        {
                            if (position_ + 4 > text_.size())
                            {
                                parseError = L"Unexpected end of file while reading saved snapshot unicode escape.";
                                return false;
                            }
                            codeUnit = 0;
                            for (int index = 0; index < 4; ++index)
                            {
                                const char hex = text_[position_++];
                                codeUnit <<= 4;
                                if (hex >= '0' && hex <= '9')
                                {
                                    codeUnit += static_cast<unsigned int>(hex - '0');
                                }
                                else if (hex >= 'a' && hex <= 'f')
                                {
                                    codeUnit += static_cast<unsigned int>(hex - 'a' + 10);
                                }
                                else if (hex >= 'A' && hex <= 'F')
                                {
                                    codeUnit += static_cast<unsigned int>(hex - 'A' + 10);
                                }
                                else
                                {
                                    parseError = L"Invalid unicode escape in saved snapshot.";
                                    return false;
                                }
                            }
                            return true;
                        };

                        unsigned int codepoint = 0;
                        if (!parseHexQuad(codepoint, error))
                        {
                            return false;
                        }
                        if (codepoint >= 0xd800 && codepoint <= 0xdbff)
                        {
                            if (position_ + 2 > text_.size() ||
                                text_[position_] != '\\' ||
                                text_[position_ + 1] != 'u')
                            {
                                error = L"High surrogate in saved snapshot string is not followed by a low surrogate.";
                                return false;
                            }
                            position_ += 2;
                            unsigned int low = 0;
                            if (!parseHexQuad(low, error))
                            {
                                return false;
                            }
                            if (low < 0xdc00 || low > 0xdfff)
                            {
                                error = L"Invalid low surrogate in saved snapshot string.";
                                return false;
                            }
                            codepoint = 0x10000 +
                                ((codepoint - 0xd800) << 10) +
                                (low - 0xdc00);
                        }
                        else if (codepoint >= 0xdc00 && codepoint <= 0xdfff)
                        {
                            error = L"Unexpected low surrogate in saved snapshot string.";
                            return false;
                        }
                        AppendCodepointUtf8(bytes, codepoint);
                        break;
                    }
                    default:
                        error = L"Unsupported string escape in saved snapshot.";
                        return false;
                    }
                }

                error = L"Unexpected end of file while reading saved snapshot string.";
                return false;
            }

            bool ParseNumber(double& value, std::wstring& error)
            {
                const std::size_t start = position_;
                if (position_ < text_.size() && text_[position_] == '-')
                {
                    ++position_;
                }
                const std::size_t integerStart = position_;
                while (position_ < text_.size() &&
                    std::isdigit(static_cast<unsigned char>(text_[position_])) != 0)
                {
                    ++position_;
                }
                if (integerStart == position_)
                {
                    error = position_ >= text_.size()
                        ? L"Unexpected end of file while reading saved snapshot number."
                        : L"Invalid number in saved snapshot.";
                    return false;
                }
                if (position_ < text_.size() && text_[position_] == '.')
                {
                    ++position_;
                    const std::size_t fractionStart = position_;
                    while (position_ < text_.size() &&
                        std::isdigit(static_cast<unsigned char>(text_[position_])) != 0)
                    {
                        ++position_;
                    }
                    if (fractionStart == position_)
                    {
                        error = position_ >= text_.size()
                            ? L"Unexpected end of file while reading saved snapshot number."
                            : L"Invalid number in saved snapshot.";
                        return false;
                    }
                }
                if (position_ < text_.size() && (text_[position_] == 'e' || text_[position_] == 'E'))
                {
                    ++position_;
                    if (position_ < text_.size() && (text_[position_] == '+' || text_[position_] == '-'))
                    {
                        ++position_;
                    }
                    const std::size_t exponentStart = position_;
                    while (position_ < text_.size() &&
                        std::isdigit(static_cast<unsigned char>(text_[position_])) != 0)
                    {
                        ++position_;
                    }
                    if (exponentStart == position_)
                    {
                        error = position_ >= text_.size()
                            ? L"Unexpected end of file while reading saved snapshot number."
                            : L"Invalid number in saved snapshot.";
                        return false;
                    }
                }

                try
                {
                    value = std::stod(text_.substr(start, position_ - start));
                }
                catch (...)
                {
                    error = L"Invalid number in saved snapshot.";
                    return false;
                }
                return true;
            }

            const std::string& text_;
            std::size_t position_ = 0;
        };

        const JsonValue* ObjectMember(const JsonValue& value, const wchar_t* name)
        {
            if (value.type != JsonValue::Type::Object)
            {
                return nullptr;
            }
            const auto found = value.objectValue.find(name);
            return found == value.objectValue.end() ? nullptr : &found->second;
        }

        std::wstring StringMember(const JsonValue& value, const wchar_t* name)
        {
            const JsonValue* member = ObjectMember(value, name);
            return member != nullptr && member->type == JsonValue::Type::String ? member->stringValue : std::wstring{};
        }

        int IntMember(const JsonValue& value, const wchar_t* name)
        {
            const JsonValue* member = ObjectMember(value, name);
            return member != nullptr && member->type == JsonValue::Type::Number
                ? static_cast<int>(member->numberValue)
                : 0;
        }

        std::uint32_t UInt32Member(const JsonValue& value, const wchar_t* name)
        {
            const JsonValue* member = ObjectMember(value, name);
            return member != nullptr && member->type == JsonValue::Type::Number
                ? static_cast<std::uint32_t>(member->numberValue)
                : 0;
        }

        std::uint64_t UInt64Member(const JsonValue& value, const wchar_t* name)
        {
            const JsonValue* member = ObjectMember(value, name);
            if (member == nullptr)
            {
                return 0;
            }
            if (member->type == JsonValue::Type::String)
            {
                return ParseUInt64String(member->stringValue);
            }
            if (member->type == JsonValue::Type::Number)
            {
                return static_cast<std::uint64_t>(member->numberValue);
            }
            return 0;
        }

        std::size_t SizeMember(const JsonValue& value, const wchar_t* name)
        {
            return static_cast<std::size_t>(UInt64Member(value, name));
        }

        bool BoolMember(const JsonValue& value, const wchar_t* name)
        {
            const JsonValue* member = ObjectMember(value, name);
            return member != nullptr && member->type == JsonValue::Type::Boolean && member->boolValue;
        }

        std::vector<std::wstring> StringArrayMember(const JsonValue& value, const wchar_t* name)
        {
            std::vector<std::wstring> values;
            const JsonValue* member = ObjectMember(value, name);
            if (member == nullptr || member->type != JsonValue::Type::Array)
            {
                return values;
            }
            for (const JsonValue& item : member->arrayValue)
            {
                if (item.type == JsonValue::Type::String)
                {
                    values.push_back(item.stringValue);
                }
            }
            return values;
        }

        const char* PersistedAnalysisLevelToken(
            Core::PersistedTriageAnalysisLevel level)
        {
            switch (level)
            {
            case Core::PersistedTriageAnalysisLevel::NotCaptured:
                return "not_captured";
            case Core::PersistedTriageAnalysisLevel::Baseline:
                return "baseline";
            case Core::PersistedTriageAnalysisLevel::Enriched:
                return "enriched";
            case Core::PersistedTriageAnalysisLevel::LegacyFallback:
                return "legacy_fallback";
            default:
                return "unknown";
            }
        }

        bool ParsePersistedAnalysisLevelToken(
            const std::wstring& token,
            Core::PersistedTriageAnalysisLevel& level)
        {
            if (token == L"not_captured")
            {
                level = Core::PersistedTriageAnalysisLevel::NotCaptured;
                return true;
            }
            if (token == L"baseline")
            {
                level = Core::PersistedTriageAnalysisLevel::Baseline;
                return true;
            }
            if (token == L"enriched")
            {
                level = Core::PersistedTriageAnalysisLevel::Enriched;
                return true;
            }
            if (token == L"legacy_fallback")
            {
                level = Core::PersistedTriageAnalysisLevel::LegacyFallback;
                return true;
            }
            return false;
        }

        const char* TriageVerdictToken(Core::TriageVerdict verdict)
        {
            switch (verdict)
            {
            case Core::TriageVerdict::Informational:
                return "informational";
            case Core::TriageVerdict::LowAttention:
                return "low_attention";
            case Core::TriageVerdict::MediumAttention:
                return "medium_attention";
            case Core::TriageVerdict::HighAttention:
                return "high_attention";
            default:
                return "unknown";
            }
        }

        bool ParseTriageVerdictToken(
            const std::wstring& token,
            Core::TriageVerdict& verdict)
        {
            if (token == L"informational")
            {
                verdict = Core::TriageVerdict::Informational;
                return true;
            }
            if (token == L"low_attention")
            {
                verdict = Core::TriageVerdict::LowAttention;
                return true;
            }
            if (token == L"medium_attention")
            {
                verdict = Core::TriageVerdict::MediumAttention;
                return true;
            }
            if (token == L"high_attention")
            {
                verdict = Core::TriageVerdict::HighAttention;
                return true;
            }
            return false;
        }

        const char* EvidenceDomainToken(Core::EvidenceDomain domain)
        {
            switch (domain)
            {
            case Core::EvidenceDomain::Unknown: return "unknown";
            case Core::EvidenceDomain::ProcessIdentity: return "process_identity";
            case Core::EvidenceDomain::FilePath: return "file_path";
            case Core::EvidenceDomain::FileSignature: return "file_signature";
            case Core::EvidenceDomain::CommandLine: return "command_line";
            case Core::EvidenceDomain::ProcessRelationship: return "process_relationship";
            case Core::EvidenceDomain::Network: return "network";
            case Core::EvidenceDomain::Service: return "service";
            case Core::EvidenceDomain::Module: return "module";
            case Core::EvidenceDomain::Handle: return "handle";
            case Core::EvidenceDomain::Runtime: return "runtime";
            case Core::EvidenceDomain::MemoryMetadata: return "memory_metadata";
            case Core::EvidenceDomain::Token: return "token";
            case Core::EvidenceDomain::Persistence: return "persistence";
            case Core::EvidenceDomain::CollectionQuality: return "collection_quality";
            case Core::EvidenceDomain::EvidenceIntegrity: return "evidence_integrity";
            case Core::EvidenceDomain::ImportedEvidence: return "imported_evidence";
            default: return "unknown_enum";
            }
        }

        bool ParseEvidenceDomainToken(
            const std::wstring& token,
            Core::EvidenceDomain& domain)
        {
            static constexpr std::array<std::pair<const wchar_t*, Core::EvidenceDomain>, 17> Values = {{
                {L"unknown", Core::EvidenceDomain::Unknown},
                {L"process_identity", Core::EvidenceDomain::ProcessIdentity},
                {L"file_path", Core::EvidenceDomain::FilePath},
                {L"file_signature", Core::EvidenceDomain::FileSignature},
                {L"command_line", Core::EvidenceDomain::CommandLine},
                {L"process_relationship", Core::EvidenceDomain::ProcessRelationship},
                {L"network", Core::EvidenceDomain::Network},
                {L"service", Core::EvidenceDomain::Service},
                {L"module", Core::EvidenceDomain::Module},
                {L"handle", Core::EvidenceDomain::Handle},
                {L"runtime", Core::EvidenceDomain::Runtime},
                {L"memory_metadata", Core::EvidenceDomain::MemoryMetadata},
                {L"token", Core::EvidenceDomain::Token},
                {L"persistence", Core::EvidenceDomain::Persistence},
                {L"collection_quality", Core::EvidenceDomain::CollectionQuality},
                {L"evidence_integrity", Core::EvidenceDomain::EvidenceIntegrity},
                {L"imported_evidence", Core::EvidenceDomain::ImportedEvidence}
            }};
            for (const auto& value : Values)
            {
                if (token == value.first)
                {
                    domain = value.second;
                    return true;
                }
            }
            return false;
        }

        const char* ObservationDispositionToken(
            Core::ObservationDisposition disposition)
        {
            switch (disposition)
            {
            case Core::ObservationDisposition::Informational: return "informational";
            case Core::ObservationDisposition::Context: return "context";
            case Core::ObservationDisposition::ReviewRelevant: return "review_relevant";
            case Core::ObservationDisposition::CorrelatedOnly: return "correlated_only";
            case Core::ObservationDisposition::CollectionNote: return "collection_note";
            case Core::ObservationDisposition::EvidenceIntegrityNote: return "evidence_integrity_note";
            case Core::ObservationDisposition::SuppressedExpected: return "suppressed_expected";
            default: return "unknown_enum";
            }
        }

        bool ParseObservationDispositionToken(
            const std::wstring& token,
            Core::ObservationDisposition& disposition)
        {
            static constexpr std::array<std::pair<
                const wchar_t*, Core::ObservationDisposition>, 7> Values = {{
                { L"informational", Core::ObservationDisposition::Informational },
                { L"context", Core::ObservationDisposition::Context },
                { L"review_relevant", Core::ObservationDisposition::ReviewRelevant },
                { L"correlated_only", Core::ObservationDisposition::CorrelatedOnly },
                { L"collection_note", Core::ObservationDisposition::CollectionNote },
                { L"evidence_integrity_note", Core::ObservationDisposition::EvidenceIntegrityNote },
                { L"suppressed_expected", Core::ObservationDisposition::SuppressedExpected }
            }};
            for (const auto& value : Values)
            {
                if (token == value.first)
                {
                    disposition = value.second;
                    return true;
                }
            }
            return false;
        }

        const char* ObservationStrengthToken(Core::ObservationStrength strength)
        {
            switch (strength)
            {
            case Core::ObservationStrength::None: return "none";
            case Core::ObservationStrength::Weak: return "weak";
            case Core::ObservationStrength::Moderate: return "moderate";
            case Core::ObservationStrength::Strong: return "strong";
            default: return "unknown_enum";
            }
        }

        bool ParseObservationStrengthToken(
            const std::wstring& token,
            Core::ObservationStrength& strength)
        {
            if (token == L"none")
            {
                strength = Core::ObservationStrength::None;
                return true;
            }
            if (token == L"weak")
            {
                strength = Core::ObservationStrength::Weak;
                return true;
            }
            if (token == L"moderate")
            {
                strength = Core::ObservationStrength::Moderate;
                return true;
            }
            if (token == L"strong")
            {
                strength = Core::ObservationStrength::Strong;
                return true;
            }
            return false;
        }

        const char* ObservationConfidenceToken(
            Core::ObservationConfidence confidence)
        {
            switch (confidence)
            {
            case Core::ObservationConfidence::Unknown: return "unknown";
            case Core::ObservationConfidence::Low: return "low";
            case Core::ObservationConfidence::Medium: return "medium";
            case Core::ObservationConfidence::High: return "high";
            default: return "unknown_enum";
            }
        }

        bool ParseObservationConfidenceToken(
            const std::wstring& token,
            Core::ObservationConfidence& confidence)
        {
            if (token == L"unknown")
            {
                confidence = Core::ObservationConfidence::Unknown;
                return true;
            }
            if (token == L"low")
            {
                confidence = Core::ObservationConfidence::Low;
                return true;
            }
            if (token == L"medium")
            {
                confidence = Core::ObservationConfidence::Medium;
                return true;
            }
            if (token == L"high")
            {
                confidence = Core::ObservationConfidence::High;
                return true;
            }
            return false;
        }

        void WriteUtf8JsonString(std::ostream& output, const std::string& value)
        {
            WriteJsonString(output, Utf8ToWide(value.data(), value.size()));
        }

        void WritePersistedStringArray(
            std::ostream& output,
            const std::vector<std::string>& values)
        {
            output << '[';
            for (std::size_t index = 0; index < values.size(); ++index)
            {
                if (index != 0)
                {
                    output << ", ";
                }
                WriteUtf8JsonString(output, values[index]);
            }
            output << ']';
        }

        const JsonValue* ArrayMember(const JsonValue& value, const wchar_t* name)
        {
            const JsonValue* member = ObjectMember(value, name);
            return member != nullptr && member->type == JsonValue::Type::Array ? member : nullptr;
        }

        std::wstring ServiceFieldPath(const std::wstring& scope, const wchar_t* name)
        {
            return scope + L"." + name;
        }

        bool ReadRequiredServiceString(
            const JsonValue& value,
            const wchar_t* name,
            std::size_t maxCharacters,
            const std::wstring& scope,
            std::wstring& destination,
            std::wstring& error)
        {
            const JsonValue* member = ObjectMember(value, name);
            const std::wstring path = ServiceFieldPath(scope, name);
            if (member == nullptr || member->type != JsonValue::Type::String)
            {
                error = path + L" must be a string.";
                return false;
            }

            const std::size_t effectiveCap = (std::min)(maxCharacters, SnapshotMaxStringLength);
            if (member->stringValue.size() > effectiveCap)
            {
                error = path + L" exceeds its saved-snapshot string cap.";
                return false;
            }
            destination = member->stringValue;
            return true;
        }

        bool ReadRequiredServiceBool(
            const JsonValue& value,
            const wchar_t* name,
            const std::wstring& scope,
            bool& destination,
            std::wstring& error)
        {
            const JsonValue* member = ObjectMember(value, name);
            const std::wstring path = ServiceFieldPath(scope, name);
            if (member == nullptr || member->type != JsonValue::Type::Boolean)
            {
                error = path + L" must be a boolean.";
                return false;
            }
            destination = member->boolValue;
            return true;
        }

        bool ReadRequiredServiceUInt32(
            const JsonValue& value,
            const wchar_t* name,
            const std::wstring& scope,
            std::uint32_t& destination,
            std::wstring& error)
        {
            const JsonValue* member = ObjectMember(value, name);
            const std::wstring path = ServiceFieldPath(scope, name);
            if (member == nullptr ||
                member->type != JsonValue::Type::Number ||
                !std::isfinite(member->numberValue) ||
                member->numberValue < 0.0 ||
                member->numberValue > static_cast<double>((std::numeric_limits<std::uint32_t>::max)()) ||
                std::floor(member->numberValue) != member->numberValue)
            {
                error = path + L" must be an unsigned 32-bit integer.";
                return false;
            }
            destination = static_cast<std::uint32_t>(member->numberValue);
            return true;
        }

        bool ReadRequiredServiceSize(
            const JsonValue& value,
            const wchar_t* name,
            const std::wstring& scope,
            std::size_t& destination,
            std::wstring& error)
        {
            std::uint32_t parsed = 0;
            if (!ReadRequiredServiceUInt32(value, name, scope, parsed, error))
            {
                return false;
            }
            destination = static_cast<std::size_t>(parsed);
            return true;
        }

        bool ServiceHasPersistedTruncation(const Core::ServiceInfo& service)
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

        bool ValidateServiceStringForSnapshot(
            const std::wstring& value,
            std::size_t maxCharacters,
            const std::wstring& path,
            std::wstring& error)
        {
            if (value.size() > (std::min)(maxCharacters, SnapshotMaxStringLength))
            {
                error = path + L" exceeds its saved-snapshot string cap.";
                return false;
            }
            return true;
        }

        bool ValidateServiceInfoForSnapshot(
            const Core::ServiceInfo& service,
            std::size_t index,
            std::wstring& error)
        {
            const std::wstring scope =
                L"service_context.services[" + std::to_wstring(index) + L"]";
            if (!ValidateServiceStringForSnapshot(
                    service.serviceName,
                    Core::ServiceNameMaxCharacters,
                    ServiceFieldPath(scope, L"service_name"),
                    error) ||
                !ValidateServiceStringForSnapshot(
                    service.displayName,
                    Core::ServiceDisplayNameMaxCharacters,
                    ServiceFieldPath(scope, L"display_name"),
                    error) ||
                !ValidateServiceStringForSnapshot(
                    service.description,
                    Core::ServiceDescriptionMaxCharacters,
                    ServiceFieldPath(scope, L"description"),
                    error) ||
                !ValidateServiceStringForSnapshot(
                    service.serviceAccount,
                    Core::ServiceAccountMaxCharacters,
                    ServiceFieldPath(scope, L"service_account"),
                    error) ||
                !ValidateServiceStringForSnapshot(
                    service.rawImagePath,
                    Core::ServiceImagePathMaxCharacters,
                    ServiceFieldPath(scope, L"raw_image_path"),
                    error) ||
                !ValidateServiceStringForSnapshot(
                    service.expandedImagePath,
                    Core::ServiceImagePathMaxCharacters,
                    ServiceFieldPath(scope, L"expanded_image_path"),
                    error) ||
                !ValidateServiceStringForSnapshot(
                    service.executablePath,
                    Core::ServiceImagePathMaxCharacters,
                    ServiceFieldPath(scope, L"executable_path"),
                    error) ||
                !ValidateServiceStringForSnapshot(
                    service.pathParseMessage,
                    Core::ServiceMessageMaxCharacters,
                    ServiceFieldPath(scope, L"parse_message"),
                    error) ||
                !ValidateServiceStringForSnapshot(
                    service.svchostGroup,
                    Core::ServiceSvchostGroupMaxCharacters,
                    ServiceFieldPath(scope, L"svchost_group"),
                    error) ||
                !ValidateServiceStringForSnapshot(
                    service.statusMessage,
                    Core::ServiceMessageMaxCharacters,
                    ServiceFieldPath(scope, L"status_message"),
                    error))
            {
                return false;
            }
            if (service.serviceName.empty())
            {
                error = ServiceFieldPath(scope, L"service_name") + L" must not be empty.";
                return false;
            }

            if (static_cast<std::uint32_t>(service.pathParseStatus) >
                static_cast<std::uint32_t>(Core::ServicePathParseStatus::InputTruncated))
            {
                error = ServiceFieldPath(scope, L"path_parse_status") + L" is invalid.";
                return false;
            }
            if (static_cast<std::uint32_t>(service.pathConfidence) >
                static_cast<std::uint32_t>(Core::ServicePathConfidence::High))
            {
                error = ServiceFieldPath(scope, L"path_confidence") + L" is invalid.";
                return false;
            }
            if (static_cast<std::uint32_t>(service.processModel) >
                static_cast<std::uint32_t>(Core::ServiceProcessModel::SharedProcess))
            {
                error = ServiceFieldPath(scope, L"process_model") + L" is invalid.";
                return false;
            }
            if (service.processModel != Core::ServiceProcessModelFromType(service.serviceTypeRaw))
            {
                error = ServiceFieldPath(scope, L"process_model") +
                    L" contradicts service_type_raw.";
                return false;
            }

            constexpr std::uint32_t ServiceRunning = 0x00000004;
            constexpr std::uint32_t ServicePaused = 0x00000007;
            const bool expectedReliablePid =
                service.scmProcessId != 0 &&
                (service.stateRaw == ServiceRunning || service.stateRaw == ServicePaused);
            if (service.pidReliableForState != expectedReliablePid)
            {
                error = ServiceFieldPath(scope, L"pid_reliable_for_state") +
                    L" contradicts state_raw or scm_pid.";
                return false;
            }
            return true;
        }

        bool ValidateServiceContextForSnapshot(
            const Core::ServiceCollectionResult& serviceContext,
            std::wstring& error)
        {
            if (serviceContext.services.size() > Core::ServiceMaxRecords)
            {
                error = L"service_context.services exceeds the retained service cap.";
                return false;
            }
            if (serviceContext.totalEnumerated > (std::numeric_limits<std::uint32_t>::max)() ||
                serviceContext.configurationUnavailableCount > (std::numeric_limits<std::uint32_t>::max)() ||
                serviceContext.descriptionUnavailableCount > (std::numeric_limits<std::uint32_t>::max)())
            {
                error = L"service_context collection counts exceed the supported range.";
                return false;
            }
            if (!ValidateServiceStringForSnapshot(
                    serviceContext.statusMessage,
                    Core::ServiceMessageMaxCharacters,
                    L"service_context.status_message",
                    error))
            {
                return false;
            }

            std::size_t unavailableConfigurations = 0;
            std::size_t unavailableDescriptions = 0;
            bool hasTruncatedFields = false;
            for (std::size_t index = 0; index < serviceContext.services.size(); ++index)
            {
                const Core::ServiceInfo& service = serviceContext.services[index];
                if (!ValidateServiceInfoForSnapshot(service, index, error))
                {
                    return false;
                }
                if (!service.configurationAvailable)
                {
                    ++unavailableConfigurations;
                }
                if (!service.descriptionAvailable)
                {
                    ++unavailableDescriptions;
                }
                hasTruncatedFields = hasTruncatedFields || ServiceHasPersistedTruncation(service);
            }

            if (!serviceContext.attempted &&
                (serviceContext.success ||
                 serviceContext.partial ||
                 serviceContext.truncated ||
                 serviceContext.totalEnumerated != 0 ||
                 serviceContext.configurationUnavailableCount != 0 ||
                 serviceContext.descriptionUnavailableCount != 0 ||
                 !serviceContext.services.empty()))
            {
                error = L"service_context contains collection results although attempted is false.";
                return false;
            }
            if (serviceContext.totalEnumerated < serviceContext.services.size())
            {
                error = L"service_context.total_enumerated is smaller than the retained service count.";
                return false;
            }
            const bool expectedTruncated =
                serviceContext.totalEnumerated > serviceContext.services.size();
            if (serviceContext.truncated != expectedTruncated)
            {
                error = L"service_context.truncated contradicts the enumerated and retained counts.";
                return false;
            }
            if (serviceContext.configurationUnavailableCount != unavailableConfigurations)
            {
                error = L"service_context.configuration_unavailable_count contradicts retained service rows.";
                return false;
            }
            if (serviceContext.descriptionUnavailableCount != unavailableDescriptions)
            {
                error = L"service_context.description_unavailable_count contradicts retained service rows.";
                return false;
            }
            const bool expectedPartial = serviceContext.success
                ? serviceContext.truncated ||
                    serviceContext.configurationUnavailableCount != 0 ||
                    serviceContext.descriptionUnavailableCount != 0 ||
                    hasTruncatedFields
                : !serviceContext.services.empty();
            if (serviceContext.partial != expectedPartial)
            {
                error = L"service_context.partial contradicts the persisted collection result.";
                return false;
            }
            return true;
        }

        void WriteServiceStringField(
            std::ostream& output,
            const std::string& indent,
            const char* name,
            const std::wstring& value,
            bool trailingComma = true)
        {
            output << indent << '"' << name << "\": ";
            WriteJsonString(output, value);
            output << (trailingComma ? ",\n" : "\n");
        }

        void WriteServiceBoolField(
            std::ostream& output,
            const std::string& indent,
            const char* name,
            bool value,
            bool trailingComma = true)
        {
            output << indent << '"' << name << "\": " << (value ? "true" : "false")
                   << (trailingComma ? ",\n" : "\n");
        }

        template <typename Value>
        void WriteServiceNumberField(
            std::ostream& output,
            const std::string& indent,
            const char* name,
            Value value,
            bool trailingComma = true)
        {
            output << indent << '"' << name << "\": " << value
                   << (trailingComma ? ",\n" : "\n");
        }

        void WriteServiceInfo(
            std::ostream& output,
            const Core::ServiceInfo& service,
            const std::string& indent,
            bool trailingComma)
        {
            output << indent << "{\n";
            const std::string fieldIndent = indent + "  ";
            WriteServiceStringField(output, fieldIndent, "service_name", service.serviceName);
            WriteServiceStringField(output, fieldIndent, "display_name", service.displayName);
            WriteServiceStringField(output, fieldIndent, "description", service.description);
            WriteServiceNumberField(output, fieldIndent, "state_raw", service.stateRaw);
            WriteServiceNumberField(output, fieldIndent, "start_type_raw", service.startTypeRaw);
            WriteServiceNumberField(output, fieldIndent, "service_type_raw", service.serviceTypeRaw);
            WriteServiceNumberField(output, fieldIndent, "service_flags_raw", service.serviceFlagsRaw);
            WriteServiceStringField(output, fieldIndent, "service_account", service.serviceAccount);
            WriteServiceStringField(output, fieldIndent, "raw_image_path", service.rawImagePath);
            WriteServiceStringField(output, fieldIndent, "expanded_image_path", service.expandedImagePath);
            WriteServiceStringField(output, fieldIndent, "executable_path", service.executablePath);
            WriteServiceNumberField(
                output,
                fieldIndent,
                "path_parse_status",
                static_cast<std::uint32_t>(service.pathParseStatus));
            WriteServiceNumberField(
                output,
                fieldIndent,
                "path_confidence",
                static_cast<std::uint32_t>(service.pathConfidence));
            WriteServiceStringField(output, fieldIndent, "parse_message", service.pathParseMessage);
            WriteServiceNumberField(output, fieldIndent, "scm_pid", service.scmProcessId);
            WriteServiceBoolField(
                output,
                fieldIndent,
                "pid_reliable_for_state",
                service.pidReliableForState);
            WriteServiceNumberField(
                output,
                fieldIndent,
                "process_model",
                static_cast<std::uint32_t>(service.processModel));
            WriteServiceStringField(output, fieldIndent, "svchost_group", service.svchostGroup);
            WriteServiceBoolField(
                output,
                fieldIndent,
                "configuration_available",
                service.configurationAvailable);
            WriteServiceBoolField(
                output,
                fieldIndent,
                "description_available",
                service.descriptionAvailable);
            WriteServiceBoolField(
                output,
                fieldIndent,
                "service_name_truncated",
                service.serviceNameTruncated);
            WriteServiceBoolField(
                output,
                fieldIndent,
                "display_name_truncated",
                service.displayNameTruncated);
            WriteServiceBoolField(
                output,
                fieldIndent,
                "description_truncated",
                service.descriptionTruncated);
            WriteServiceBoolField(
                output,
                fieldIndent,
                "service_account_truncated",
                service.serviceAccountTruncated);
            WriteServiceBoolField(
                output,
                fieldIndent,
                "raw_image_path_truncated",
                service.rawImagePathTruncated);
            WriteServiceBoolField(
                output,
                fieldIndent,
                "expanded_image_path_truncated",
                service.expandedImagePathTruncated);
            WriteServiceBoolField(
                output,
                fieldIndent,
                "svchost_group_truncated",
                service.svchostGroupTruncated);
            WriteServiceBoolField(
                output,
                fieldIndent,
                "parse_message_truncated",
                service.pathParseMessageTruncated);
            WriteServiceBoolField(
                output,
                fieldIndent,
                "status_message_truncated",
                service.statusMessageTruncated);
            WriteServiceStringField(
                output,
                fieldIndent,
                "status_message",
                service.statusMessage,
                false);
            output << indent << '}' << (trailingComma ? ",\n" : "\n");
        }

        void WriteServiceContext(
            std::ostream& output,
            const Core::ServiceCollectionResult& serviceContext,
            const std::string& indent)
        {
            output << indent << "\"service_context\": {\n";
            const std::string fieldIndent = indent + "  ";
            WriteServiceBoolField(output, fieldIndent, "attempted", serviceContext.attempted);
            WriteServiceBoolField(output, fieldIndent, "success", serviceContext.success);
            WriteServiceBoolField(output, fieldIndent, "partial", serviceContext.partial);
            WriteServiceBoolField(output, fieldIndent, "truncated", serviceContext.truncated);
            WriteServiceNumberField(
                output,
                fieldIndent,
                "total_enumerated",
                serviceContext.totalEnumerated);
            WriteServiceNumberField(
                output,
                fieldIndent,
                "configuration_unavailable_count",
                serviceContext.configurationUnavailableCount);
            WriteServiceNumberField(
                output,
                fieldIndent,
                "description_unavailable_count",
                serviceContext.descriptionUnavailableCount);
            WriteServiceStringField(
                output,
                fieldIndent,
                "status_message",
                serviceContext.statusMessage);
            output << fieldIndent << "\"services\": [\n";
            for (std::size_t index = 0; index < serviceContext.services.size(); ++index)
            {
                WriteServiceInfo(
                    output,
                    serviceContext.services[index],
                    fieldIndent + "  ",
                    index + 1 < serviceContext.services.size());
            }
            output << fieldIndent << "]\n";
            output << indent << "},\n";
        }

        bool ParseServiceInfo(
            const JsonValue& value,
            std::size_t index,
            Core::ServiceInfo& service,
            std::wstring& error)
        {
            const std::wstring scope =
                L"service_context.services[" + std::to_wstring(index) + L"]";
            if (value.type != JsonValue::Type::Object)
            {
                error = scope + L" must be an object.";
                return false;
            }

            if (!ReadRequiredServiceString(
                    value,
                    L"service_name",
                    Core::ServiceNameMaxCharacters,
                    scope,
                    service.serviceName,
                    error) ||
                !ReadRequiredServiceString(
                    value,
                    L"display_name",
                    Core::ServiceDisplayNameMaxCharacters,
                    scope,
                    service.displayName,
                    error) ||
                !ReadRequiredServiceString(
                    value,
                    L"description",
                    Core::ServiceDescriptionMaxCharacters,
                    scope,
                    service.description,
                    error) ||
                !ReadRequiredServiceUInt32(
                    value,
                    L"state_raw",
                    scope,
                    service.stateRaw,
                    error) ||
                !ReadRequiredServiceUInt32(
                    value,
                    L"start_type_raw",
                    scope,
                    service.startTypeRaw,
                    error) ||
                !ReadRequiredServiceUInt32(
                    value,
                    L"service_type_raw",
                    scope,
                    service.serviceTypeRaw,
                    error) ||
                !ReadRequiredServiceUInt32(
                    value,
                    L"service_flags_raw",
                    scope,
                    service.serviceFlagsRaw,
                    error) ||
                !ReadRequiredServiceString(
                    value,
                    L"service_account",
                    Core::ServiceAccountMaxCharacters,
                    scope,
                    service.serviceAccount,
                    error) ||
                !ReadRequiredServiceString(
                    value,
                    L"raw_image_path",
                    Core::ServiceImagePathMaxCharacters,
                    scope,
                    service.rawImagePath,
                    error) ||
                !ReadRequiredServiceString(
                    value,
                    L"expanded_image_path",
                    Core::ServiceImagePathMaxCharacters,
                    scope,
                    service.expandedImagePath,
                    error) ||
                !ReadRequiredServiceString(
                    value,
                    L"executable_path",
                    Core::ServiceImagePathMaxCharacters,
                    scope,
                    service.executablePath,
                    error))
            {
                return false;
            }

            std::uint32_t pathParseStatus = 0;
            std::uint32_t pathConfidence = 0;
            std::uint32_t processModel = 0;
            if (!ReadRequiredServiceUInt32(
                    value,
                    L"path_parse_status",
                    scope,
                    pathParseStatus,
                    error) ||
                !ReadRequiredServiceUInt32(
                    value,
                    L"path_confidence",
                    scope,
                    pathConfidence,
                    error) ||
                !ReadRequiredServiceString(
                    value,
                    L"parse_message",
                    Core::ServiceMessageMaxCharacters,
                    scope,
                    service.pathParseMessage,
                    error) ||
                !ReadRequiredServiceUInt32(
                    value,
                    L"scm_pid",
                    scope,
                    service.scmProcessId,
                    error) ||
                !ReadRequiredServiceBool(
                    value,
                    L"pid_reliable_for_state",
                    scope,
                    service.pidReliableForState,
                    error) ||
                !ReadRequiredServiceUInt32(
                    value,
                    L"process_model",
                    scope,
                    processModel,
                    error) ||
                !ReadRequiredServiceString(
                    value,
                    L"svchost_group",
                    Core::ServiceSvchostGroupMaxCharacters,
                    scope,
                    service.svchostGroup,
                    error) ||
                !ReadRequiredServiceBool(
                    value,
                    L"configuration_available",
                    scope,
                    service.configurationAvailable,
                    error) ||
                !ReadRequiredServiceBool(
                    value,
                    L"description_available",
                    scope,
                    service.descriptionAvailable,
                    error) ||
                !ReadRequiredServiceBool(
                    value,
                    L"service_name_truncated",
                    scope,
                    service.serviceNameTruncated,
                    error) ||
                !ReadRequiredServiceBool(
                    value,
                    L"display_name_truncated",
                    scope,
                    service.displayNameTruncated,
                    error) ||
                !ReadRequiredServiceBool(
                    value,
                    L"description_truncated",
                    scope,
                    service.descriptionTruncated,
                    error) ||
                !ReadRequiredServiceBool(
                    value,
                    L"service_account_truncated",
                    scope,
                    service.serviceAccountTruncated,
                    error) ||
                !ReadRequiredServiceBool(
                    value,
                    L"raw_image_path_truncated",
                    scope,
                    service.rawImagePathTruncated,
                    error) ||
                !ReadRequiredServiceBool(
                    value,
                    L"expanded_image_path_truncated",
                    scope,
                    service.expandedImagePathTruncated,
                    error) ||
                !ReadRequiredServiceBool(
                    value,
                    L"svchost_group_truncated",
                    scope,
                    service.svchostGroupTruncated,
                    error) ||
                !ReadRequiredServiceBool(
                    value,
                    L"parse_message_truncated",
                    scope,
                    service.pathParseMessageTruncated,
                    error) ||
                !ReadRequiredServiceBool(
                    value,
                    L"status_message_truncated",
                    scope,
                    service.statusMessageTruncated,
                    error) ||
                !ReadRequiredServiceString(
                    value,
                    L"status_message",
                    Core::ServiceMessageMaxCharacters,
                    scope,
                    service.statusMessage,
                    error))
            {
                return false;
            }

            if (pathParseStatus >
                static_cast<std::uint32_t>(Core::ServicePathParseStatus::InputTruncated))
            {
                error = ServiceFieldPath(scope, L"path_parse_status") + L" is invalid.";
                return false;
            }
            if (pathConfidence >
                static_cast<std::uint32_t>(Core::ServicePathConfidence::High))
            {
                error = ServiceFieldPath(scope, L"path_confidence") + L" is invalid.";
                return false;
            }
            if (processModel >
                static_cast<std::uint32_t>(Core::ServiceProcessModel::SharedProcess))
            {
                error = ServiceFieldPath(scope, L"process_model") + L" is invalid.";
                return false;
            }

            service.pathParseStatus = static_cast<Core::ServicePathParseStatus>(pathParseStatus);
            service.pathConfidence = static_cast<Core::ServicePathConfidence>(pathConfidence);
            service.processModel = static_cast<Core::ServiceProcessModel>(processModel);
            return true;
        }

        bool ParseServiceContext(
            const JsonValue& value,
            Core::ServiceCollectionResult& serviceContext,
            std::wstring& error)
        {
            constexpr const wchar_t* Scope = L"service_context";
            if (value.type != JsonValue::Type::Object)
            {
                error = L"service_context must be an object.";
                return false;
            }

            if (!ReadRequiredServiceBool(
                    value,
                    L"attempted",
                    Scope,
                    serviceContext.attempted,
                    error) ||
                !ReadRequiredServiceBool(
                    value,
                    L"success",
                    Scope,
                    serviceContext.success,
                    error) ||
                !ReadRequiredServiceBool(
                    value,
                    L"partial",
                    Scope,
                    serviceContext.partial,
                    error) ||
                !ReadRequiredServiceBool(
                    value,
                    L"truncated",
                    Scope,
                    serviceContext.truncated,
                    error) ||
                !ReadRequiredServiceSize(
                    value,
                    L"total_enumerated",
                    Scope,
                    serviceContext.totalEnumerated,
                    error) ||
                !ReadRequiredServiceSize(
                    value,
                    L"configuration_unavailable_count",
                    Scope,
                    serviceContext.configurationUnavailableCount,
                    error) ||
                !ReadRequiredServiceSize(
                    value,
                    L"description_unavailable_count",
                    Scope,
                    serviceContext.descriptionUnavailableCount,
                    error) ||
                !ReadRequiredServiceString(
                    value,
                    L"status_message",
                    Core::ServiceMessageMaxCharacters,
                    Scope,
                    serviceContext.statusMessage,
                    error))
            {
                return false;
            }

            const JsonValue* services = ObjectMember(value, L"services");
            if (services == nullptr || services->type != JsonValue::Type::Array)
            {
                error = L"service_context.services must be an array.";
                return false;
            }
            if (services->arrayValue.size() > Core::ServiceMaxRecords)
            {
                error = L"service_context.services exceeds the retained service cap.";
                return false;
            }

            serviceContext.services.reserve(services->arrayValue.size());
            for (std::size_t index = 0; index < services->arrayValue.size(); ++index)
            {
                Core::ServiceInfo service;
                if (!ParseServiceInfo(services->arrayValue[index], index, service, error))
                {
                    return false;
                }
                serviceContext.services.push_back(std::move(service));
            }

            if (!ValidateServiceContextForSnapshot(serviceContext, error))
            {
                return false;
            }
            serviceContext.ReindexCorrelations();
            return true;
        }

        void WriteStatus(std::ostream& output, const EvidenceCollectionStatus& status, const std::string& indent)
        {
            output << "{\n";
            output << indent << "  \"status\": ";
            WriteJsonString(output, status.status);
            output << ",\n";
            output << indent << "  \"message\": ";
            WriteJsonString(output, status.message);
            output << ",\n";
            output << indent << "  \"truncated\": " << (status.truncated ? "true" : "false") << ",\n";
            output << indent << "  \"original_count\": " << status.originalCount << ",\n";
            output << indent << "  \"saved_count\": " << status.savedCount << "\n";
            output << indent << "}";
        }

        EvidenceCollectionStatus ParseStatus(const JsonValue& value)
        {
            EvidenceCollectionStatus status;
            status.status = StringMember(value, L"status");
            if (status.status.empty())
            {
                status.status = L"not_attempted";
            }
            status.message = StringMember(value, L"message");
            status.truncated = BoolMember(value, L"truncated");
            status.originalCount = SizeMember(value, L"original_count");
            status.savedCount = SizeMember(value, L"saved_count");
            return status;
        }

        void WriteThread(std::ostream& output, const Core::ThreadInfo& thread, const std::string& indent, bool trailingComma)
        {
            output << indent << "{\n";
            output << indent << "  \"thread_id\": " << thread.threadId << ",\n";
            output << indent << "  \"owner_process_id\": " << thread.ownerProcessId << ",\n";
            output << indent << "  \"base_priority\": " << thread.basePriority << ",\n";
            output << indent << "  \"current_priority\": " << thread.currentPriority << ",\n";
            output << indent << "  \"has_current_priority\": " << (thread.hasCurrentPriority ? "true" : "false") << ",\n";
            output << indent << "  \"start_address\": ";
            WriteJsonString(output, thread.startAddress);
            output << ",\n";
            output << indent << "  \"start_address_resolved_module\": ";
            WriteJsonString(output, thread.startAddressResolvedModule);
            output << ",\n";
            output << indent << "  \"state\": ";
            WriteJsonString(output, thread.state);
            output << ",\n";
            output << indent << "  \"error_message\": ";
            WriteJsonString(output, thread.errorMessage);
            output << "\n" << indent << "}";
            if (trailingComma)
            {
                output << ',';
            }
            output << '\n';
        }

        Core::ThreadInfo ParseThread(const JsonValue& value)
        {
            Core::ThreadInfo thread;
            thread.threadId = UInt32Member(value, L"thread_id");
            thread.ownerProcessId = UInt32Member(value, L"owner_process_id");
            thread.basePriority = IntMember(value, L"base_priority");
            thread.currentPriority = IntMember(value, L"current_priority");
            thread.hasCurrentPriority = BoolMember(value, L"has_current_priority");
            thread.startAddress = StringMember(value, L"start_address");
            thread.startAddressResolvedModule = StringMember(value, L"start_address_resolved_module");
            thread.state = StringMember(value, L"state");
            thread.errorMessage = StringMember(value, L"error_message");
            return thread;
        }

        void WriteRuntime(std::ostream& output, const Core::RuntimeInfo& runtime, const std::string& indent)
        {
            output << "{\n";
            output << indent << "  \"success\": " << (runtime.success ? "true" : "false") << ",\n";
            output << indent << "  \"error_message\": ";
            WriteJsonString(output, runtime.errorMessage);
            output << ",\n";
            output << indent << "  \"process_id\": " << runtime.processId << ",\n";
            output << indent << "  \"priority_class_raw\": " << runtime.priorityClassRaw << ",\n";
            output << indent << "  \"priority_class_name\": ";
            WriteJsonString(output, runtime.priorityClassName);
            output << ",\n";
            output << indent << "  \"base_priority\": " << runtime.basePriority << ",\n";
            output << indent << "  \"process_affinity_mask\": ";
            WriteJsonString(output, UInt64String(runtime.processAffinityMask));
            output << ",\n";
            output << indent << "  \"system_affinity_mask\": ";
            WriteJsonString(output, UInt64String(runtime.systemAffinityMask));
            output << ",\n";
            output << indent << "  \"affinity_mask_string\": ";
            WriteJsonString(output, runtime.affinityMaskString);
            output << ",\n";
            output << indent << "  \"processor_group\": ";
            WriteJsonString(output, runtime.processorGroup);
            output << ",\n";
            output << indent << "  \"thread_count\": " << runtime.threadCount << ",\n";
            output << indent << "  \"handle_count\": " << runtime.handleCount << ",\n";
            output << indent << "  \"working_set_size\": ";
            WriteJsonString(output, UInt64String(runtime.workingSetSize));
            output << ",\n";
            output << indent << "  \"peak_working_set_size\": ";
            WriteJsonString(output, UInt64String(runtime.peakWorkingSetSize));
            output << ",\n";
            output << indent << "  \"private_bytes\": ";
            WriteJsonString(output, UInt64String(runtime.privateBytes));
            output << ",\n";
            output << indent << "  \"pagefile_usage\": ";
            WriteJsonString(output, UInt64String(runtime.pagefileUsage));
            output << ",\n";
            output << indent << "  \"peak_pagefile_usage\": ";
            WriteJsonString(output, UInt64String(runtime.peakPagefileUsage));
            output << ",\n";
            output << indent << "  \"user_cpu_time\": ";
            WriteJsonString(output, runtime.userCpuTime);
            output << ",\n";
            output << indent << "  \"kernel_cpu_time\": ";
            WriteJsonString(output, runtime.kernelCpuTime);
            output << ",\n";
            output << indent << "  \"total_cpu_time\": ";
            WriteJsonString(output, runtime.totalCpuTime);
            output << ",\n";
            output << indent << "  \"user_cpu_time_100ns\": ";
            WriteJsonString(output, UInt64String(runtime.userCpuTime100ns));
            output << ",\n";
            output << indent << "  \"kernel_cpu_time_100ns\": ";
            WriteJsonString(output, UInt64String(runtime.kernelCpuTime100ns));
            output << ",\n";
            output << indent << "  \"total_cpu_time_100ns\": ";
            WriteJsonString(output, UInt64String(runtime.totalCpuTime100ns));
            output << ",\n";
            output << indent << "  \"architecture\": ";
            WriteJsonString(output, runtime.architecture);
            output << ",\n";
            output << indent << "  \"is_wow64\": " << (runtime.isWow64 ? "true" : "false") << ",\n";
            output << indent << "  \"context_notes\": ";
            WriteJsonStringArray(output, runtime.contextNotes);
            output << ",\n";
            output << indent << "  \"threads\": [\n";
            for (std::size_t index = 0; index < runtime.threads.size(); ++index)
            {
                WriteThread(output, runtime.threads[index], indent + "    ", index + 1 < runtime.threads.size());
            }
            output << indent << "  ]\n";
            output << indent << "}";
        }

        Core::RuntimeInfo ParseRuntime(const JsonValue& value)
        {
            Core::RuntimeInfo runtime;
            runtime.success = BoolMember(value, L"success");
            runtime.errorMessage = StringMember(value, L"error_message");
            runtime.processId = UInt32Member(value, L"process_id");
            runtime.priorityClassRaw = UInt32Member(value, L"priority_class_raw");
            runtime.priorityClassName = StringMember(value, L"priority_class_name");
            runtime.basePriority = IntMember(value, L"base_priority");
            runtime.processAffinityMask = UInt64Member(value, L"process_affinity_mask");
            runtime.systemAffinityMask = UInt64Member(value, L"system_affinity_mask");
            runtime.affinityMaskString = StringMember(value, L"affinity_mask_string");
            runtime.processorGroup = StringMember(value, L"processor_group");
            runtime.threadCount = UInt32Member(value, L"thread_count");
            runtime.handleCount = UInt32Member(value, L"handle_count");
            runtime.workingSetSize = UInt64Member(value, L"working_set_size");
            runtime.peakWorkingSetSize = UInt64Member(value, L"peak_working_set_size");
            runtime.privateBytes = UInt64Member(value, L"private_bytes");
            runtime.pagefileUsage = UInt64Member(value, L"pagefile_usage");
            runtime.peakPagefileUsage = UInt64Member(value, L"peak_pagefile_usage");
            runtime.userCpuTime = StringMember(value, L"user_cpu_time");
            runtime.kernelCpuTime = StringMember(value, L"kernel_cpu_time");
            runtime.totalCpuTime = StringMember(value, L"total_cpu_time");
            runtime.userCpuTime100ns = UInt64Member(value, L"user_cpu_time_100ns");
            runtime.kernelCpuTime100ns = UInt64Member(value, L"kernel_cpu_time_100ns");
            runtime.totalCpuTime100ns = UInt64Member(value, L"total_cpu_time_100ns");
            runtime.architecture = StringMember(value, L"architecture");
            runtime.isWow64 = BoolMember(value, L"is_wow64");
            runtime.contextNotes = StringArrayMember(value, L"context_notes");
            if (const JsonValue* threads = ArrayMember(value, L"threads"))
            {
                runtime.threads.reserve(threads->arrayValue.size());
                for (const JsonValue& item : threads->arrayValue)
                {
                    if (item.type == JsonValue::Type::Object)
                    {
                        runtime.threads.push_back(ParseThread(item));
                    }
                }
            }
            return runtime;
        }

        void WritePrivilege(std::ostream& output, const Core::PrivilegeInfo& privilege, const std::string& indent, bool trailingComma)
        {
            output << indent << "{\n";
            output << indent << "  \"name\": ";
            WriteJsonString(output, privilege.name);
            output << ",\n";
            output << indent << "  \"display_name\": ";
            WriteJsonString(output, privilege.displayName);
            output << ",\n";
            output << indent << "  \"enabled\": " << (privilege.enabled ? "true" : "false") << ",\n";
            output << indent << "  \"enabled_by_default\": " << (privilege.enabledByDefault ? "true" : "false") << ",\n";
            output << indent << "  \"removed\": " << (privilege.removed ? "true" : "false") << ",\n";
            output << indent << "  \"used_for_access\": " << (privilege.usedForAccess ? "true" : "false") << "\n";
            output << indent << "}";
            if (trailingComma)
            {
                output << ',';
            }
            output << '\n';
        }

        Core::PrivilegeInfo ParsePrivilege(const JsonValue& value)
        {
            Core::PrivilegeInfo privilege;
            privilege.name = StringMember(value, L"name");
            privilege.displayName = StringMember(value, L"display_name");
            privilege.enabled = BoolMember(value, L"enabled");
            privilege.enabledByDefault = BoolMember(value, L"enabled_by_default");
            privilege.removed = BoolMember(value, L"removed");
            privilege.usedForAccess = BoolMember(value, L"used_for_access");
            return privilege;
        }

        void WriteToken(std::ostream& output, const Core::TokenInfo& token, const std::string& indent)
        {
            output << "{\n";
            output << indent << "  \"success\": " << (token.success ? "true" : "false") << ",\n";
            output << indent << "  \"error_message\": ";
            WriteJsonString(output, token.errorMessage);
            output << ",\n";
            output << indent << "  \"user_name\": ";
            WriteJsonString(output, token.userName);
            output << ",\n";
            output << indent << "  \"domain_name\": ";
            WriteJsonString(output, token.domainName);
            output << ",\n";
            output << indent << "  \"user_sid\": ";
            WriteJsonString(output, token.userSid);
            output << ",\n";
            output << indent << "  \"integrity_level_name\": ";
            WriteJsonString(output, token.integrityLevelName);
            output << ",\n";
            output << indent << "  \"integrity_rid\": " << token.integrityRid << ",\n";
            output << indent << "  \"elevation_type\": ";
            WriteJsonString(output, token.elevationType);
            output << ",\n";
            output << indent << "  \"is_elevated\": " << (token.isElevated ? "true" : "false") << ",\n";
            output << indent << "  \"is_admin\": " << (token.isAdmin ? "true" : "false") << ",\n";
            output << indent << "  \"is_app_container\": " << (token.isAppContainer ? "true" : "false") << ",\n";
            output << indent << "  \"session_id\": ";
            if (token.sessionId.has_value())
            {
                output << token.sessionId.value();
            }
            else
            {
                output << "null";
            }
            output << ",\n";
            output << indent << "  \"token_type\": ";
            WriteJsonString(output, token.tokenType);
            output << ",\n";
            output << indent << "  \"impersonation_level\": ";
            WriteJsonString(output, token.impersonationLevel);
            output << ",\n";
            output << indent << "  \"privileges\": [\n";
            for (std::size_t index = 0; index < token.privileges.size(); ++index)
            {
                WritePrivilege(output, token.privileges[index], indent + "    ", index + 1 < token.privileges.size());
            }
            output << indent << "  ]\n";
            output << indent << "}";
        }

        Core::TokenInfo ParseToken(const JsonValue& value)
        {
            Core::TokenInfo token;
            token.success = BoolMember(value, L"success");
            token.errorMessage = StringMember(value, L"error_message");
            token.userName = StringMember(value, L"user_name");
            token.domainName = StringMember(value, L"domain_name");
            token.userSid = StringMember(value, L"user_sid");
            token.integrityLevelName = StringMember(value, L"integrity_level_name");
            token.integrityRid = UInt32Member(value, L"integrity_rid");
            token.elevationType = StringMember(value, L"elevation_type");
            token.isElevated = BoolMember(value, L"is_elevated");
            token.isAdmin = BoolMember(value, L"is_admin");
            token.isAppContainer = BoolMember(value, L"is_app_container");
            if (const JsonValue* session = ObjectMember(value, L"session_id");
                session != nullptr && session->type == JsonValue::Type::Number)
            {
                token.sessionId = static_cast<std::uint32_t>(session->numberValue);
            }
            token.tokenType = StringMember(value, L"token_type");
            token.impersonationLevel = StringMember(value, L"impersonation_level");
            if (const JsonValue* privileges = ArrayMember(value, L"privileges"))
            {
                token.privileges.reserve(privileges->arrayValue.size());
                for (const JsonValue& item : privileges->arrayValue)
                {
                    if (item.type == JsonValue::Type::Object)
                    {
                        token.privileges.push_back(ParsePrivilege(item));
                    }
                }
            }
            return token;
        }

        void WriteModule(std::ostream& output, const Core::ModuleInfo& module, const std::string& indent, bool trailingComma)
        {
            output << indent << "{\n";
            output << indent << "  \"module_name\": ";
            WriteJsonString(output, module.moduleName);
            output << ",\n";
            output << indent << "  \"module_path\": ";
            WriteJsonString(output, module.modulePath);
            output << ",\n";
            output << indent << "  \"base_address\": ";
            WriteJsonString(output, module.baseAddress);
            output << ",\n";
            output << indent << "  \"size_bytes\": " << module.sizeBytes << ",\n";
            output << indent << "  \"readable\": " << (module.readable ? "true" : "false") << "\n";
            output << indent << "}";
            if (trailingComma)
            {
                output << ',';
            }
            output << '\n';
        }

        Core::ModuleInfo ParseModule(const JsonValue& value)
        {
            Core::ModuleInfo module;
            module.moduleName = StringMember(value, L"module_name");
            module.modulePath = StringMember(value, L"module_path");
            module.baseAddress = StringMember(value, L"base_address");
            module.sizeBytes = UInt32Member(value, L"size_bytes");
            module.readable = BoolMember(value, L"readable");
            module.indicators = StringArrayMember(value, L"indicators");
            return module;
        }

        void WriteModules(std::ostream& output, const Core::ModuleCollectionResult& modules, const std::string& indent)
        {
            output << "{\n";
            output << indent << "  \"pid\": " << modules.pid << ",\n";
            output << indent << "  \"success\": " << (modules.success ? "true" : "false") << ",\n";
            output << indent << "  \"status_message\": ";
            WriteJsonString(output, modules.statusMessage);
            output << ",\n";
            output << indent << "  \"modules\": [\n";
            for (std::size_t index = 0; index < modules.modules.size(); ++index)
            {
                WriteModule(output, modules.modules[index], indent + "    ", index + 1 < modules.modules.size());
            }
            output << indent << "  ]\n";
            output << indent << "}";
        }

        Core::ModuleCollectionResult ParseModules(const JsonValue& value)
        {
            Core::ModuleCollectionResult modules;
            modules.pid = UInt32Member(value, L"pid");
            modules.success = BoolMember(value, L"success");
            modules.statusMessage = StringMember(value, L"status_message");
            modules.indicators = StringArrayMember(value, L"indicators");
            if (const JsonValue* array = ArrayMember(value, L"modules"))
            {
                modules.modules.reserve(array->arrayValue.size());
                for (const JsonValue& item : array->arrayValue)
                {
                    if (item.type == JsonValue::Type::Object)
                    {
                        modules.modules.push_back(ParseModule(item));
                    }
                }
            }
            return modules;
        }

        void WriteHandle(std::ostream& output, const Core::HandleInfo& handle, const std::string& indent, bool trailingComma)
        {
            output << indent << "{\n";
            output << indent << "  \"owning_pid\": " << handle.owningPid << ",\n";
            output << indent << "  \"handle_value\": ";
            WriteJsonString(output, UInt64String(handle.handleValue));
            output << ",\n";
            output << indent << "  \"object_type_index\": " << handle.objectTypeIndex << ",\n";
            output << indent << "  \"object_type\": ";
            WriteJsonString(output, handle.objectType);
            output << ",\n";
            output << indent << "  \"object_name\": ";
            WriteJsonString(output, handle.objectName);
            output << ",\n";
            output << indent << "  \"granted_access\": ";
            WriteJsonString(output, handle.grantedAccess);
            output << ",\n";
            output << indent << "  \"granted_access_raw\": " << handle.grantedAccessRaw << ",\n";
            output << indent << "  \"target_pid\": ";
            if (handle.targetPid.has_value())
            {
                output << handle.targetPid.value();
            }
            else
            {
                output << "null";
            }
            output << ",\n";
            output << indent << "  \"target_thread_id\": ";
            if (handle.targetThreadId.has_value())
            {
                output << handle.targetThreadId.value();
            }
            else
            {
                output << "null";
            }
            output << ",\n";
            output << indent << "  \"target_process_name\": ";
            WriteJsonString(output, handle.targetProcessName);
            output << ",\n";
            output << indent << "  \"type_resolved\": " << (handle.typeResolved ? "true" : "false") << ",\n";
            output << indent << "  \"name_resolved\": " << (handle.nameResolved ? "true" : "false") << ",\n";
            output << indent << "  \"error_message\": ";
            WriteJsonString(output, handle.errorMessage);
            output << ",\n";
            output << indent << "  \"decoded_access\": ";
            WriteJsonStringArray(output, handle.decodedAccess);
            output << "\n" << indent << "}";
            if (trailingComma)
            {
                output << ',';
            }
            output << '\n';
        }

        Core::HandleInfo ParseHandle(const JsonValue& value)
        {
            Core::HandleInfo handle;
            handle.owningPid = UInt32Member(value, L"owning_pid");
            handle.handleValue = UInt64Member(value, L"handle_value");
            handle.objectTypeIndex = static_cast<std::uint16_t>(
                UInt32Member(value, L"object_type_index"));
            handle.objectType = StringMember(value, L"object_type");
            handle.objectName = StringMember(value, L"object_name");
            handle.grantedAccess = StringMember(value, L"granted_access");
            handle.grantedAccessRaw = UInt32Member(value, L"granted_access_raw");
            if (const JsonValue* targetPid = ObjectMember(value, L"target_pid");
                targetPid != nullptr && targetPid->type == JsonValue::Type::Number)
            {
                handle.targetPid = static_cast<std::uint32_t>(targetPid->numberValue);
            }
            if (const JsonValue* targetThreadId = ObjectMember(value, L"target_thread_id");
                targetThreadId != nullptr && targetThreadId->type == JsonValue::Type::Number)
            {
                handle.targetThreadId = static_cast<std::uint32_t>(
                    targetThreadId->numberValue);
            }
            handle.targetProcessName = StringMember(value, L"target_process_name");
            handle.typeResolved = BoolMember(value, L"type_resolved");
            handle.nameResolved = BoolMember(value, L"name_resolved");
            handle.errorMessage = StringMember(value, L"error_message");
            handle.decodedAccess = StringArrayMember(value, L"decoded_access");
            handle.indicators = StringArrayMember(value, L"indicators");
            return handle;
        }

        const char* HandleCollectionStateText(
            Core::HandleCollectionState state)
        {
            switch (state)
            {
            case Core::HandleCollectionState::NotAttempted:
                return "not_attempted";
            case Core::HandleCollectionState::Success:
                return "success";
            case Core::HandleCollectionState::Partial:
                return "partial";
            case Core::HandleCollectionState::Unavailable:
                return "unavailable";
            case Core::HandleCollectionState::Failed:
                return "failed";
            default:
                return "failed";
            }
        }

        Core::HandleCollectionState ParseHandleCollectionState(
            const std::wstring& value,
            bool legacySuccess)
        {
            if (value == L"success")
            {
                return Core::HandleCollectionState::Success;
            }
            if (value == L"partial")
            {
                return Core::HandleCollectionState::Partial;
            }
            if (value == L"unavailable")
            {
                return Core::HandleCollectionState::Unavailable;
            }
            if (value == L"failed")
            {
                return Core::HandleCollectionState::Failed;
            }
            if (value == L"not_attempted")
            {
                return Core::HandleCollectionState::NotAttempted;
            }

            // Schema-5 files written before typed partial-state capture retain
            // only the compatibility success flag. The outer collection status
            // further refines this value after the process evidence is parsed.
            return legacySuccess
                ? Core::HandleCollectionState::Success
                : Core::HandleCollectionState::NotAttempted;
        }

        const char* HandleQueryFailureKindText(
            Core::HandleQueryFailureKind kind)
        {
            switch (kind)
            {
            case Core::HandleQueryFailureKind::None:
                return "none";
            case Core::HandleQueryFailureKind::BudgetExceeded:
                return "budget_exceeded";
            case Core::HandleQueryFailureKind::AllocationFailed:
                return "allocation_failed";
            case Core::HandleQueryFailureKind::ApiUnavailable:
                return "api_unavailable";
            case Core::HandleQueryFailureKind::ApiFailed:
                return "api_failed";
            case Core::HandleQueryFailureKind::InvalidBuffer:
                return "invalid_buffer";
            default:
                return "none";
            }
        }

        Core::HandleQueryFailureKind ParseHandleQueryFailureKind(
            const std::wstring& value)
        {
            if (value == L"budget_exceeded")
            {
                return Core::HandleQueryFailureKind::BudgetExceeded;
            }
            if (value == L"allocation_failed")
            {
                return Core::HandleQueryFailureKind::AllocationFailed;
            }
            if (value == L"api_unavailable")
            {
                return Core::HandleQueryFailureKind::ApiUnavailable;
            }
            if (value == L"api_failed")
            {
                return Core::HandleQueryFailureKind::ApiFailed;
            }
            if (value == L"invalid_buffer")
            {
                return Core::HandleQueryFailureKind::InvalidBuffer;
            }
            return Core::HandleQueryFailureKind::None;
        }

        void WriteHandles(std::ostream& output, const Core::HandleCollectionResult& handles, const std::string& indent)
        {
            output << "{\n";
            output << indent << "  \"pid\": " << handles.pid << ",\n";
            output << indent << "  \"collection_state\": \""
                   << HandleCollectionStateText(handles.state) << "\",\n";
            output << indent << "  \"query_failure_kind\": \""
                   << HandleQueryFailureKindText(handles.queryFailureKind)
                   << "\",\n";
            output << indent << "  \"success\": " << (handles.success ? "true" : "false") << ",\n";
            output << indent << "  \"status_message\": ";
            WriteJsonString(output, handles.statusMessage);
            output << ",\n";
            output << indent << "  \"system_handle_count\": " << handles.systemHandleCount << ",\n";
            output << indent << "  \"system_entries_scanned\": " << handles.systemEntriesScanned << ",\n";
            output << indent << "  \"selected_process_handles_matched\": " << handles.selectedProcessHandlesMatched << ",\n";
            output << indent << "  \"selected_process_handles_omitted\": " << handles.selectedProcessHandlesOmitted << ",\n";
            output << indent << "  \"names_attempted\": " << handles.namesAttempted << ",\n";
            output << indent << "  \"names_resolved\": " << handles.namesResolved << ",\n";
            output << indent << "  \"names_skipped\": " << handles.namesSkipped << ",\n";
            output << indent << "  \"names_failed\": " << handles.namesFailed << ",\n";
            output << indent << "  \"type_resolutions_attempted\": " << handles.typeResolutionsAttempted << ",\n";
            output << indent << "  \"type_resolutions_resolved\": " << handles.typeResolutionsResolved << ",\n";
            output << indent << "  \"type_resolutions_skipped\": " << handles.typeResolutionsSkipped << ",\n";
            output << indent << "  \"type_resolutions_failed\": " << handles.typeResolutionsFailed << ",\n";
            output << indent << "  \"targets_resolved\": " << handles.targetsResolved << ",\n";
            output << indent << "  \"targets_unresolved\": " << handles.targetsUnresolved << ",\n";
            output << indent << "  \"query_buffer_truncated\": " << (handles.queryBufferTruncated ? "true" : "false") << ",\n";
            output << indent << "  \"retention_cap_reached\": " << (handles.retentionCapReached ? "true" : "false") << ",\n";
            output << indent << "  \"name_resolution_cap_reached\": " << (handles.nameResolutionCapReached ? "true" : "false") << ",\n";
            output << indent << "  \"type_resolution_cap_reached\": " << (handles.typeResolutionCapReached ? "true" : "false") << ",\n";
            output << indent << "  \"type_or_target_resolution_partial\": " << (handles.typeOrTargetResolutionPartial ? "true" : "false") << ",\n";
            output << indent << "  \"handles\": [\n";
            for (std::size_t index = 0; index < handles.handles.size(); ++index)
            {
                WriteHandle(output, handles.handles[index], indent + "    ", index + 1 < handles.handles.size());
            }
            output << indent << "  ]\n";
            output << indent << "}";
        }

        Core::HandleCollectionResult ParseHandles(const JsonValue& value)
        {
            Core::HandleCollectionResult handles;
            handles.pid = UInt32Member(value, L"pid");
            handles.success = BoolMember(value, L"success");
            handles.state = ParseHandleCollectionState(
                StringMember(value, L"collection_state"),
                handles.success);
            handles.queryFailureKind = ParseHandleQueryFailureKind(
                StringMember(value, L"query_failure_kind"));
            handles.statusMessage = StringMember(value, L"status_message");
            handles.systemHandleCount = SizeMember(value, L"system_handle_count");
            handles.systemEntriesScanned = SizeMember(value, L"system_entries_scanned");
            handles.selectedProcessHandlesMatched = SizeMember(
                value,
                L"selected_process_handles_matched");
            handles.selectedProcessHandlesOmitted = SizeMember(
                value,
                L"selected_process_handles_omitted");
            handles.namesAttempted = SizeMember(value, L"names_attempted");
            handles.namesResolved = SizeMember(value, L"names_resolved");
            handles.namesSkipped = SizeMember(value, L"names_skipped");
            handles.namesFailed = SizeMember(value, L"names_failed");
            handles.typeResolutionsAttempted = SizeMember(
                value,
                L"type_resolutions_attempted");
            handles.typeResolutionsResolved = SizeMember(
                value,
                L"type_resolutions_resolved");
            handles.typeResolutionsSkipped = SizeMember(
                value,
                L"type_resolutions_skipped");
            handles.typeResolutionsFailed = SizeMember(
                value,
                L"type_resolutions_failed");
            handles.targetsResolved = SizeMember(value, L"targets_resolved");
            handles.targetsUnresolved = SizeMember(value, L"targets_unresolved");
            handles.queryBufferTruncated = BoolMember(
                value,
                L"query_buffer_truncated");
            handles.retentionCapReached = BoolMember(
                value,
                L"retention_cap_reached");
            handles.nameResolutionCapReached = BoolMember(
                value,
                L"name_resolution_cap_reached");
            handles.typeResolutionCapReached = BoolMember(
                value,
                L"type_resolution_cap_reached");
            handles.typeOrTargetResolutionPartial = BoolMember(
                value,
                L"type_or_target_resolution_partial");
            if (const JsonValue* array = ArrayMember(value, L"handles"))
            {
                handles.handles.reserve(array->arrayValue.size());
                for (const JsonValue& item : array->arrayValue)
                {
                    if (item.type == JsonValue::Type::Object)
                    {
                        handles.handles.push_back(ParseHandle(item));
                    }
                }
            }
            return handles;
        }

        void WriteMemoryRegion(std::ostream& output, const Core::MemoryRegionInfo& region, const std::string& indent, bool trailingComma)
        {
            output << indent << "{\n";
            output << indent << "  \"base_address\": ";
            WriteJsonString(output, UInt64String(region.baseAddress));
            output << ",\n";
            output << indent << "  \"base_address_string\": ";
            WriteJsonString(output, region.baseAddressString);
            output << ",\n";
            output << indent << "  \"allocation_base\": ";
            WriteJsonString(output, UInt64String(region.allocationBase));
            output << ",\n";
            output << indent << "  \"allocation_base_string\": ";
            WriteJsonString(output, region.allocationBaseString);
            output << ",\n";
            output << indent << "  \"region_size\": ";
            WriteJsonString(output, UInt64String(region.regionSize));
            output << ",\n";
            output << indent << "  \"region_size_string\": ";
            WriteJsonString(output, region.regionSizeString);
            output << ",\n";
            output << indent << "  \"state_raw\": " << region.stateRaw << ",\n";
            output << indent << "  \"state_name\": ";
            WriteJsonString(output, region.stateName);
            output << ",\n";
            output << indent << "  \"type_raw\": " << region.typeRaw << ",\n";
            output << indent << "  \"type_name\": ";
            WriteJsonString(output, region.typeName);
            output << ",\n";
            output << indent << "  \"protect_raw\": " << region.protectRaw << ",\n";
            output << indent << "  \"protect_name\": ";
            WriteJsonString(output, region.protectName);
            output << ",\n";
            output << indent << "  \"allocation_protect_raw\": " << region.allocationProtectRaw << ",\n";
            output << indent << "  \"allocation_protect_name\": ";
            WriteJsonString(output, region.allocationProtectName);
            output << ",\n";
            output << indent << "  \"mapped_file_path\": ";
            WriteJsonString(output, region.mappedFilePath);
            output << ",\n";
            output << indent << "  \"is_readable\": " << (region.isReadable ? "true" : "false") << ",\n";
            output << indent << "  \"is_writable\": " << (region.isWritable ? "true" : "false") << ",\n";
            output << indent << "  \"is_executable\": " << (region.isExecutable ? "true" : "false") << ",\n";
            output << indent << "  \"is_copy_on_write\": " << (region.isCopyOnWrite ? "true" : "false") << ",\n";
            output << indent << "  \"is_guard\": " << (region.isGuard ? "true" : "false") << ",\n";
            output << indent << "  \"is_private\": " << (region.isPrivate ? "true" : "false") << ",\n";
            output << indent << "  \"is_image\": " << (region.isImage ? "true" : "false") << ",\n";
            output << indent << "  \"is_mapped\": " << (region.isMapped ? "true" : "false") << "\n";
            output << indent << "}";
            if (trailingComma)
            {
                output << ',';
            }
            output << '\n';
        }

        Core::MemoryRegionInfo ParseMemoryRegion(const JsonValue& value)
        {
            Core::MemoryRegionInfo region;
            region.baseAddress = UInt64Member(value, L"base_address");
            region.baseAddressString = StringMember(value, L"base_address_string");
            region.allocationBase = UInt64Member(value, L"allocation_base");
            region.allocationBaseString = StringMember(value, L"allocation_base_string");
            region.regionSize = UInt64Member(value, L"region_size");
            region.regionSizeString = StringMember(value, L"region_size_string");
            region.stateRaw = UInt32Member(value, L"state_raw");
            region.stateName = StringMember(value, L"state_name");
            region.typeRaw = UInt32Member(value, L"type_raw");
            region.typeName = StringMember(value, L"type_name");
            region.protectRaw = UInt32Member(value, L"protect_raw");
            region.protectName = StringMember(value, L"protect_name");
            region.allocationProtectRaw = UInt32Member(value, L"allocation_protect_raw");
            region.allocationProtectName = StringMember(value, L"allocation_protect_name");
            region.mappedFilePath = StringMember(value, L"mapped_file_path");
            region.isReadable = BoolMember(value, L"is_readable");
            region.isWritable = BoolMember(value, L"is_writable");
            region.isExecutable = BoolMember(value, L"is_executable");
            region.isCopyOnWrite = BoolMember(value, L"is_copy_on_write");
            region.isGuard = BoolMember(value, L"is_guard");
            region.isPrivate = BoolMember(value, L"is_private");
            region.isImage = BoolMember(value, L"is_image");
            region.isMapped = BoolMember(value, L"is_mapped");
            region.indicators = StringArrayMember(value, L"indicators");
            return region;
        }

        void WriteMemory(std::ostream& output, const Core::MemoryCollectionResult& memory, const std::string& indent)
        {
            output << "{\n";
            output << indent << "  \"pid\": " << memory.pid << ",\n";
            output << indent << "  \"success\": " << (memory.success ? "true" : "false") << ",\n";
            output << indent << "  \"status_message\": ";
            WriteJsonString(output, memory.statusMessage);
            output << ",\n";
            output << indent << "  \"total_regions\": " << memory.totalRegions << ",\n";
            output << indent << "  \"executable_regions\": " << memory.executableRegions << ",\n";
            output << indent << "  \"private_executable_regions\": " << memory.privateExecutableRegions << ",\n";
            output << indent << "  \"rwx_regions\": " << memory.rwxRegions << ",\n";
            output << indent << "  \"guard_regions\": " << memory.guardRegions << ",\n";
            output << indent << "  \"regions\": [\n";
            for (std::size_t index = 0; index < memory.regions.size(); ++index)
            {
                WriteMemoryRegion(output, memory.regions[index], indent + "    ", index + 1 < memory.regions.size());
            }
            output << indent << "  ]\n";
            output << indent << "}";
        }

        Core::MemoryCollectionResult ParseMemory(const JsonValue& value)
        {
            Core::MemoryCollectionResult memory;
            memory.pid = UInt32Member(value, L"pid");
            memory.success = BoolMember(value, L"success");
            memory.statusMessage = StringMember(value, L"status_message");
            memory.totalRegions = SizeMember(value, L"total_regions");
            memory.executableRegions = SizeMember(value, L"executable_regions");
            memory.privateExecutableRegions = SizeMember(value, L"private_executable_regions");
            memory.rwxRegions = SizeMember(value, L"rwx_regions");
            memory.guardRegions = SizeMember(value, L"guard_regions");
            if (const JsonValue* array = ArrayMember(value, L"regions"))
            {
                memory.regions.reserve(array->arrayValue.size());
                for (const JsonValue& item : array->arrayValue)
                {
                    if (item.type == JsonValue::Type::Object)
                    {
                        memory.regions.push_back(ParseMemoryRegion(item));
                    }
                }
            }
            return memory;
        }

        void WriteProcessEvidence(
            std::ostream& output,
            const ProcessEvidenceSnapshot& evidence,
            const std::string& indent,
            bool trailingComma)
        {
            output << indent << "{\n";
            output << indent << "  \"pid\": " << evidence.pid << ",\n";
            output << indent << "  \"process_name\": ";
            WriteJsonString(output, evidence.processName);
            output << ",\n";
            output << indent << "  \"collection_status\": {\n";
            output << indent << "    \"runtime\": ";
            WriteStatus(output, evidence.runtimeStatus, indent + "    ");
            output << ",\n";
            output << indent << "    \"token\": ";
            WriteStatus(output, evidence.tokenStatus, indent + "    ");
            output << ",\n";
            output << indent << "    \"modules\": ";
            WriteStatus(output, evidence.modulesStatus, indent + "    ");
            output << ",\n";
            output << indent << "    \"handles\": ";
            WriteStatus(output, evidence.handlesStatus, indent + "    ");
            output << ",\n";
            output << indent << "    \"memory\": ";
            WriteStatus(output, evidence.memoryStatus, indent + "    ");
            output << "\n";
            output << indent << "  },\n";
            output << indent << "  \"runtime\": ";
            WriteRuntime(output, evidence.runtime, indent + "  ");
            output << ",\n";
            output << indent << "  \"token\": ";
            WriteToken(output, evidence.token, indent + "  ");
            output << ",\n";
            output << indent << "  \"modules\": ";
            WriteModules(output, evidence.modules, indent + "  ");
            output << ",\n";
            output << indent << "  \"handles\": ";
            WriteHandles(output, evidence.handles, indent + "  ");
            output << ",\n";
            output << indent << "  \"memory\": ";
            WriteMemory(output, evidence.memory, indent + "  ");
            output << "\n" << indent << "}";
            if (trailingComma)
            {
                output << ',';
            }
            output << '\n';
        }

        ProcessEvidenceSnapshot ParseProcessEvidence(const JsonValue& value)
        {
            ProcessEvidenceSnapshot evidence;
            evidence.pid = UInt32Member(value, L"pid");
            evidence.processName = StringMember(value, L"process_name");

            if (const JsonValue* statuses = ObjectMember(value, L"collection_status");
                statuses != nullptr && statuses->type == JsonValue::Type::Object)
            {
                if (const JsonValue* runtime = ObjectMember(*statuses, L"runtime"))
                {
                    evidence.runtimeStatus = ParseStatus(*runtime);
                }
                if (const JsonValue* token = ObjectMember(*statuses, L"token"))
                {
                    evidence.tokenStatus = ParseStatus(*token);
                }
                if (const JsonValue* modules = ObjectMember(*statuses, L"modules"))
                {
                    evidence.modulesStatus = ParseStatus(*modules);
                }
                if (const JsonValue* handles = ObjectMember(*statuses, L"handles"))
                {
                    evidence.handlesStatus = ParseStatus(*handles);
                }
                if (const JsonValue* memory = ObjectMember(*statuses, L"memory"))
                {
                    evidence.memoryStatus = ParseStatus(*memory);
                }
            }

            if (const JsonValue* runtime = ObjectMember(value, L"runtime");
                runtime != nullptr && runtime->type == JsonValue::Type::Object)
            {
                evidence.runtime = ParseRuntime(*runtime);
            }
            if (const JsonValue* token = ObjectMember(value, L"token");
                token != nullptr && token->type == JsonValue::Type::Object)
            {
                evidence.token = ParseToken(*token);
            }
            if (const JsonValue* modules = ObjectMember(value, L"modules");
                modules != nullptr && modules->type == JsonValue::Type::Object)
            {
                evidence.modules = ParseModules(*modules);
            }
            if (const JsonValue* handles = ObjectMember(value, L"handles");
                handles != nullptr && handles->type == JsonValue::Type::Object)
            {
                evidence.handles = ParseHandles(*handles);
                // Older schema-5 files did not carry collection_state. Their
                // existing outer status remains authoritative for whether a
                // successful retained-row capture was partial.
                if (evidence.handlesStatus.status == L"partial" &&
                    (evidence.handles.success ||
                        !evidence.handles.handles.empty()))
                {
                    evidence.handles.state =
                        Core::HandleCollectionState::Partial;
                    evidence.handles.success = true;
                }
                else if (evidence.handles.state ==
                    Core::HandleCollectionState::NotAttempted)
                {
                    if (evidence.handlesStatus.status == L"ok")
                    {
                        evidence.handles.state =
                            Core::HandleCollectionState::Success;
                        evidence.handles.success = true;
                    }
                    else if (evidence.handlesStatus.status == L"unavailable" ||
                        evidence.handlesStatus.status == L"access_denied" ||
                        evidence.handlesStatus.status == L"process_exited")
                    {
                        evidence.handles.state =
                            Core::HandleCollectionState::Unavailable;
                    }
                    else if (evidence.handlesStatus.status == L"failed")
                    {
                        evidence.handles.state =
                            Core::HandleCollectionState::Failed;
                    }
                }
            }
            if (const JsonValue* memory = ObjectMember(value, L"memory");
                memory != nullptr && memory->type == JsonValue::Type::Object)
            {
                evidence.memory = ParseMemory(*memory);
            }
            return evidence;
        }

        void WriteProcessEvidenceMap(
            std::ostream& output,
            const std::vector<ProcessEvidenceSnapshot>* processEvidence)
        {
            output << "  \"process_evidence\": {\n";
            if (processEvidence != nullptr)
            {
                for (std::size_t index = 0; index < processEvidence->size(); ++index)
                {
                    const ProcessEvidenceSnapshot& evidence = (*processEvidence)[index];
                    output << "    ";
                    WriteJsonString(output, std::to_wstring(evidence.pid));
                    output << ": ";
                    WriteProcessEvidence(output, evidence, "    ", index + 1 < processEvidence->size());
                }
            }
            output << "  }\n";
        }

        void WritePersistedTriageSummary(
            std::ostream& output,
            const Core::PersistedTriageSummary& summary,
            const std::string& indent)
        {
            output << "{\n";
            output << indent << "  \"captured\": " << (summary.captured ? "true" : "false") << ",\n";
            output << indent << "  \"evaluation_succeeded\": " << (summary.evaluationSucceeded ? "true" : "false") << ",\n";
            output << indent << "  \"analysis_level\": \"" << PersistedAnalysisLevelToken(summary.analysisLevel) << "\",\n";
            output << indent << "  \"authoritative_verdict\": \"" << TriageVerdictToken(summary.authoritativeVerdict) << "\",\n";
            output << indent << "  \"baseline_verdict_available\": " << (summary.baselineVerdictAvailable ? "true" : "false") << ",\n";
            output << indent << "  \"baseline_verdict\": \"" << TriageVerdictToken(summary.baselineVerdict) << "\",\n";
            output << indent << "  \"enriched_changed_verdict\": " << (summary.enrichedChangedVerdict ? "true" : "false") << ",\n";
            output << indent << "  \"triage_model_version\": " << summary.triageModelVersion << ",\n";
            output << indent << "  \"source_evidence_count\": " << summary.sourceEvidenceCount << ",\n";
            output << indent << "  \"contributing_domains\": [";
            for (std::size_t index = 0; index < summary.contributingDomains.size(); ++index)
            {
                if (index != 0)
                {
                    output << ", ";
                }
                output << '"' << EvidenceDomainToken(summary.contributingDomains[index]) << '"';
            }
            output << "],\n";
            output << indent << "  \"verdict_basis\": ";
            WritePersistedStringArray(output, summary.verdictBasis);
            output << ",\n";
            output << indent << "  \"completed_correlations\": ";
            WritePersistedStringArray(output, summary.completedCorrelations);
            output << ",\n";
            output << indent << "  \"supporting_context\": ";
            WritePersistedStringArray(output, summary.supportingContext);
            output << ",\n";
            output << indent << "  \"collection_limitations\": ";
            WritePersistedStringArray(output, summary.collectionLimitations);
            output << ",\n";
            output << indent << "  \"evidence_integrity_context\": ";
            WritePersistedStringArray(output, summary.evidenceIntegrityContext);
            output << ",\n";
            output << indent << "  \"unresolved_correlations\": ";
            WritePersistedStringArray(output, summary.unresolvedCorrelations);
            output << ",\n";
            output << indent << "  \"status\": ";
            WriteUtf8JsonString(output, summary.status);
            output << "\n" << indent << '}';
        }

        void WritePersistedTriageRecord(
            std::ostream& output,
            const Core::PersistedProcessTriageRecord& record,
            const std::string& indent)
        {
            output << indent << "{\n";
            output << indent << "  \"pid\": " << record.identity.pid << ",\n";
            output << indent << "  \"creation_time_available\": " << (record.identity.hasCreationTime ? "true" : "false") << ",\n";
            output << indent << "  \"creation_time\": ";
            WriteJsonString(output, UInt64String(record.identity.creationTimeFileTime));
            output << ",\n";
            output << indent << "  \"captured_triage\": ";
            WritePersistedTriageSummary(output, record.summary, indent + "  ");
            output << "\n" << indent << '}';
        }

        void WritePersistedTriageContext(
            std::ostream& output,
            const Core::PersistedTriageContext& context)
        {
            output << "  \"triage_context\": {\n";
            output << "    \"process_records\": [\n";
            for (std::size_t index = 0; index < context.processRecords.size(); ++index)
            {
                WritePersistedTriageRecord(output, context.processRecords[index], "      ");
                if (index + 1 < context.processRecords.size())
                {
                    output << ',';
                }
                output << '\n';
            }
            output << "    ],\n";
            output << "    \"selected_process_triage\": ";
            if (context.selectedRecord.has_value())
            {
                output << '\n';
                WritePersistedTriageRecord(output, context.selectedRecord.value(), "    ");
                output << '\n';
            }
            else
            {
                output << "null\n";
            }
            output << "  },\n";
        }

        void WriteNativeSourceEvidenceRecord(
            std::ostream& output,
            const Core::NativeSourceEvidenceRecord& record,
            const std::string& indent)
        {
            output << indent << "{\n";
            output << indent << "  \"stable_rule_id\": ";
            WriteUtf8JsonString(output, record.stableRuleId);
            output << ",\n";
            output << indent << "  \"title\": ";
            WriteUtf8JsonString(output, record.title);
            output << ",\n";
            output << indent << "  \"summary\": ";
            WriteUtf8JsonString(output, record.summary);
            output << ",\n";
            output << indent << "  \"details\": ";
            WritePersistedStringArray(output, record.details);
            output << ",\n";
            output << indent << "  \"limitations\": ";
            WritePersistedStringArray(output, record.limitations);
            output << ",\n";
            output << indent << "  \"domain\": ";
            WriteJsonString(output, Utf8ToWide(
                EvidenceDomainToken(record.domain),
                std::strlen(EvidenceDomainToken(record.domain))));
            output << ",\n";
            output << indent << "  \"disposition\": ";
            WriteJsonString(output, Utf8ToWide(
                ObservationDispositionToken(record.disposition),
                std::strlen(ObservationDispositionToken(record.disposition))));
            output << ",\n";
            output << indent << "  \"strength\": ";
            WriteJsonString(output, Utf8ToWide(
                ObservationStrengthToken(record.strength),
                std::strlen(ObservationStrengthToken(record.strength))));
            output << ",\n";
            output << indent << "  \"confidence\": ";
            WriteJsonString(output, Utf8ToWide(
                ObservationConfidenceToken(record.confidence),
                std::strlen(ObservationConfidenceToken(record.confidence))));
            output << ",\n";
            output << indent << "  \"artifact_family\": ";
            WriteUtf8JsonString(output, record.artifactFamily);
            output << ",\n";
            output << indent << "  \"provenance_summary\": ";
            WriteUtf8JsonString(output, record.provenanceSummary);
            output << ",\n";
            output << indent << "  \"contributed_to_verdict\": "
                << (record.contributedToVerdict ? "true" : "false") << ",\n";
            output << indent << "  \"suppressed_duplicate\": "
                << (record.suppressedDuplicate ? "true" : "false") << ",\n";
            output << indent << "  \"collection_limitation\": "
                << (record.collectionLimitation ? "true" : "false") << "\n";
            output << indent << '}';
        }

        void WriteNativeSourceEvidenceContext(
            std::ostream& output,
            const SavedNativeSourceEvidenceContext& context)
        {
            output << "  \"native_source_evidence\": {\n";
            output << "    \"model_version\": " << context.modelVersion << ",\n";
            output << "    \"selected_process\": ";
            if (!context.selectedRecord.has_value())
            {
                output << "null\n";
            }
            else
            {
                const SavedNativeSourceEvidenceRecord& selected =
                    *context.selectedRecord;
                output << "{\n";
                output << "      \"pid\": " << selected.identity.pid << ",\n";
                output << "      \"creation_time_available\": "
                    << (selected.identity.hasCreationTime ? "true" : "false")
                    << ",\n";
                output << "      \"creation_time\": ";
                WriteJsonString(
                    output,
                    UInt64String(selected.identity.creationTimeFileTime));
                output << ",\n";
                output << "      \"records\": [\n";
                for (std::size_t index = 0;
                    index < selected.records.size();
                    ++index)
                {
                    WriteNativeSourceEvidenceRecord(
                        output,
                        selected.records[index],
                        "        ");
                    if (index + 1 < selected.records.size())
                    {
                        output << ',';
                    }
                    output << '\n';
                }
                output << "      ]\n";
                output << "    }\n";
            }
            output << "  },\n";
        }

        bool HasHistoricalLegacyEvidence(const Core::ProcessInfo& process)
        {
            return process.historicalSeverityCaptured ||
                process.historicalSuspiciousCaptured ||
                !process.indicators.empty() ||
                !process.contextNotes.empty();
        }

        bool ValidateHistoricalLegacyEvidenceForSave(
            const Core::ProcessSnapshot& snapshot,
            std::wstring& error)
        {
            for (const Core::ProcessInfo& process : snapshot.processes)
            {
                const bool knownSeverity =
                    process.severity == Core::Severity::None ||
                    process.severity == Core::Severity::Info ||
                    process.severity == Core::Severity::Low ||
                    process.severity == Core::Severity::Medium ||
                    process.severity == Core::Severity::High;
                if (!knownSeverity ||
                    (!process.historicalSeverityCaptured &&
                        process.severity != Core::Severity::None) ||
                    (!process.historicalSuspiciousCaptured &&
                        process.suspicious) ||
                    (!process.hasCreationTime &&
                        process.creationTimeFileTime != 0))
                {
                    error = L"Historical legacy process metadata has a contradictory capture state.";
                    return false;
                }
                const std::size_t recordCount =
                    process.indicators.size() + process.contextNotes.size();
                if (recordCount > SnapshotHistoricalMaxRecordsPerProcess)
                {
                    error = L"Historical legacy source evidence exceeds the per-process record cap.";
                    return false;
                }
                const auto validStrings = [](const std::vector<std::wstring>& values) {
                    return std::all_of(
                        values.begin(),
                        values.end(),
                        [](const std::wstring& value) {
                            return value.size() <= SnapshotMaxStringLength;
                        });
                };
                if (!validStrings(process.indicators) ||
                    !validStrings(process.contextNotes))
                {
                    error = L"Historical legacy source evidence contains an oversized string.";
                    return false;
                }
            }
            return true;
        }

        void WriteHistoricalLegacyEvidenceContext(
            std::ostream& output,
            const Core::ProcessSnapshot& snapshot)
        {
            std::vector<const Core::ProcessInfo*> records;
            records.reserve(snapshot.processes.size());
            for (const Core::ProcessInfo& process : snapshot.processes)
            {
                if (HasHistoricalLegacyEvidence(process))
                {
                    records.push_back(&process);
                }
            }
            if (records.empty())
            {
                return;
            }

            output << "  \"historical_legacy_evidence\": {\n";
            output << "    \"model_version\": " <<
                SnapshotHistoricalEvidenceModelVersion << ",\n";
            output << "    \"process_records\": [\n";
            for (std::size_t index = 0; index < records.size(); ++index)
            {
                const Core::ProcessInfo& process = *records[index];
                output << "      {\n";
                output << "        \"pid\": " << process.pid << ",\n";
                output << "        \"creation_time_available\": " <<
                    (process.hasCreationTime ? "true" : "false") << ",\n";
                output << "        \"creation_time\": ";
                WriteJsonString(output, UInt64String(process.creationTimeFileTime));
                output << ",\n";
                output << "        \"process_severity_captured\": " <<
                    (process.historicalSeverityCaptured ? "true" : "false") << ",\n";
                output << "        \"process_severity\": ";
                if (!process.historicalSeverityCaptured)
                {
                    output << "null";
                }
                else
                {
                    WriteJsonString(output, SeverityName(process.severity));
                }
                output << ",\n";
                // Historical schemas captured this as process metadata, not
                // as a severity or suspicious flag on each source row.
                output << "        \"process_suspicious_captured\": " <<
                    (process.historicalSuspiciousCaptured ? "true" : "false") << ",\n";
                output << "        \"process_suspicious_metadata\": ";
                if (process.historicalSuspiciousCaptured)
                {
                    output << (process.suspicious ? "true" : "false");
                }
                else
                {
                    output << "null";
                }
                output << ",\n";
                output << "        \"indicators\": ";
                WriteJsonStringArray(output, process.indicators);
                output << ",\n";
                output << "        \"context_notes\": ";
                WriteJsonStringArray(output, process.contextNotes);
                output << "\n      }";
                if (index + 1 < records.size())
                {
                    output << ',';
                }
                output << '\n';
            }
            output << "    ]\n";
            output << "  },\n";
        }

        void WriteProcess(std::ostream& output, const Core::ProcessInfo& process, const std::string& indent, bool trailingComma)
        {
            output << indent << "{\n";
            output << indent << "  \"pid\": " << process.pid << ",\n";
            output << indent << "  \"parent_pid\": " << process.parentPid << ",\n";
            output << indent << "  \"name\": ";
            WriteJsonString(output, process.name);
            output << ",\n";
            output << indent << "  \"path\": ";
            WriteJsonString(output, process.executablePath);
            output << ",\n";
            output << indent << "  \"command_line\": ";
            WriteJsonString(output, process.commandLine);
            output << ",\n";
            output << indent << "  \"command_line_accessible\": " << (process.commandLineAccessible ? "true" : "false") << ",\n";
            output << indent << "  \"session_id\": ";
            if (process.sessionId.has_value())
            {
                output << process.sessionId.value();
            }
            else
            {
                output << "null";
            }
            output << ",\n";
            output << indent << "  \"architecture\": ";
            WriteJsonString(output, process.architecture);
            output << ",\n";
            output << indent << "  \"creation_time_local\": ";
            WriteJsonString(output, process.creationTimeLocal);
            output << ",\n";
            output << indent << "  \"has_creation_time\": " << (process.hasCreationTime ? "true" : "false") << ",\n";
            output << indent << "  \"creation_time_filetime\": ";
            WriteJsonString(output, UInt64String(process.creationTimeFileTime));
            output << "\n" << indent << "}";
            if (trailingComma)
            {
                output << ',';
            }
            output << '\n';
        }

        void WriteNetworkConnection(std::ostream& output, const Core::NetworkConnection& connection, const std::string& indent, bool trailingComma)
        {
            output << indent << "{\n";
            output << indent << "  \"owning_pid\": " << connection.owningPid << ",\n";
            output << indent << "  \"process_name\": ";
            WriteJsonString(output, connection.processName);
            output << ",\n";
            output << indent << "  \"protocol\": ";
            WriteJsonString(output, connection.protocol);
            output << ",\n";
            output << indent << "  \"local_address\": ";
            WriteJsonString(output, connection.localAddress);
            output << ",\n";
            output << indent << "  \"local_port\": " << connection.localPort << ",\n";
            output << indent << "  \"remote_address\": ";
            WriteJsonString(output, connection.remoteAddress);
            output << ",\n";
            output << indent << "  \"remote_port\": " << connection.remotePort << ",\n";
            output << indent << "  \"state\": ";
            WriteJsonString(output, connection.state);
            output << ",\n";
            output << indent << "  \"address_family\": ";
            WriteJsonString(output, connection.addressFamily);
            output << ",\n";
            output << indent << "  \"is_listening\": " << (connection.isListening ? "true" : "false") << ",\n";
            output << indent << "  \"is_loopback\": " << (connection.isLoopback ? "true" : "false") << ",\n";
            output << indent << "  \"is_lan\": " << (connection.isLan ? "true" : "false") << ",\n";
            output << indent << "  \"is_public_remote\": " << (connection.isPublicRemote ? "true" : "false") << "\n";
            output << indent << "}";
            if (trailingComma)
            {
                output << ',';
            }
            output << '\n';
        }

        Core::ProcessInfo ParseProcess(const JsonValue& value, int schemaVersion)
        {
            Core::ProcessInfo process;
            process.pid = UInt32Member(value, L"pid");
            process.parentPid = UInt32Member(value, L"parent_pid");
            process.name = StringMember(value, L"name");
            process.executablePath = StringMember(value, L"path");
            process.commandLine = StringMember(value, L"command_line");
            process.commandLineAccessible = BoolMember(value, L"command_line_accessible");
            if (const JsonValue* session = ObjectMember(value, L"session_id");
                session != nullptr && session->type == JsonValue::Type::Number)
            {
                process.sessionId = static_cast<std::uint32_t>(session->numberValue);
            }
            process.architecture = StringMember(value, L"architecture");
            process.creationTimeLocal = StringMember(value, L"creation_time_local");
            process.hasCreationTime = BoolMember(value, L"has_creation_time");
            process.creationTimeFileTime = ParseUInt64String(StringMember(value, L"creation_time_filetime"));
            if (schemaVersion < GlassPaneSnapshotTriageSchemaVersion)
            {
                const JsonValue* suspicious = ObjectMember(value, L"suspicious");
                process.historicalSuspiciousCaptured =
                    suspicious != nullptr && suspicious->type == JsonValue::Type::Boolean;
                process.suspicious = process.historicalSuspiciousCaptured &&
                    suspicious->boolValue;
                const JsonValue* severity = ObjectMember(value, L"severity");
                process.historicalSeverityCaptured =
                    severity != nullptr && severity->type == JsonValue::Type::String &&
                    TryParseSeverity(severity->stringValue, process.severity);
                process.indicators = StringArrayMember(value, L"indicators");
            }
            else if (schemaVersion <
                GlassPaneSnapshotNativeEvidenceSchemaVersion)
            {
                const JsonValue* suspicious =
                    ObjectMember(value, L"legacy_source_suspicious");
                process.historicalSuspiciousCaptured =
                    suspicious != nullptr && suspicious->type == JsonValue::Type::Boolean;
                process.suspicious = process.historicalSuspiciousCaptured &&
                    suspicious->boolValue;
                const JsonValue* severity =
                    ObjectMember(value, L"legacy_source_severity");
                process.historicalSeverityCaptured =
                    severity != nullptr && severity->type == JsonValue::Type::String &&
                    TryParseSeverity(severity->stringValue, process.severity);
                process.indicators = StringArrayMember(value, L"indicators");
            }
            // Schema 5 has no live Finding-derived process severity or
            // indicator fields. ProcessInfo defaults remain neutral even if an
            // unrecognized compatibility field is injected into the object.
            if (schemaVersion < GlassPaneSnapshotNativeEvidenceSchemaVersion)
            {
                process.contextNotes = StringArrayMember(value, L"context_notes");
            }
            return process;
        }

        bool ReadHistoricalStringArray(
            const JsonValue& object,
            const wchar_t* name,
            std::vector<std::wstring>& values,
            std::wstring& error)
        {
            const JsonValue* array = ObjectMember(object, name);
            if (array == nullptr || array->type != JsonValue::Type::Array)
            {
                error = L"historical_legacy_evidence." +
                    std::wstring(name) + L" must be an array.";
                return false;
            }
            if (array->arrayValue.size() >
                SnapshotHistoricalMaxRecordsPerProcess)
            {
                error = L"historical_legacy_evidence." +
                    std::wstring(name) + L" exceeds its per-process cap.";
                return false;
            }
            values.clear();
            values.reserve(array->arrayValue.size());
            for (const JsonValue& item : array->arrayValue)
            {
                if (item.type != JsonValue::Type::String ||
                    item.stringValue.size() > SnapshotMaxStringLength)
                {
                    error = L"historical_legacy_evidence." +
                        std::wstring(name) +
                        L" contains an invalid or oversized string.";
                    return false;
                }
                values.push_back(item.stringValue);
            }
            return true;
        }

        bool ParseHistoricalLegacyEvidenceContext(
            const JsonValue& value,
            Core::ProcessSnapshot& snapshot,
            std::wstring& error)
        {
            if (value.type != JsonValue::Type::Object)
            {
                error = L"historical_legacy_evidence must be an object.";
                return false;
            }
            const JsonValue* modelVersion = ObjectMember(value, L"model_version");
            if (modelVersion == nullptr ||
                modelVersion->type != JsonValue::Type::Number ||
                modelVersion->numberValue !=
                    static_cast<double>(SnapshotHistoricalEvidenceModelVersion))
            {
                error = L"historical_legacy_evidence has an unsupported model_version.";
                return false;
            }
            const JsonValue* records = ObjectMember(value, L"process_records");
            if (records == nullptr || records->type != JsonValue::Type::Array ||
                records->arrayValue.size() > SnapshotMaxProcesses)
            {
                error = L"historical_legacy_evidence.process_records is missing or exceeds its cap.";
                return false;
            }

            std::map<std::wstring, bool> seen;
            for (const JsonValue& item : records->arrayValue)
            {
                if (item.type != JsonValue::Type::Object)
                {
                    error = L"historical_legacy_evidence process record must be an object.";
                    return false;
                }
                const JsonValue* pidValue = ObjectMember(item, L"pid");
                const JsonValue* creationAvailableValue =
                    ObjectMember(item, L"creation_time_available");
                const JsonValue* creationValue = ObjectMember(item, L"creation_time");
                const JsonValue* severityCapturedValue =
                    ObjectMember(item, L"process_severity_captured");
                const JsonValue* suspiciousCapturedValue =
                    ObjectMember(item, L"process_suspicious_captured");
                const JsonValue* suspiciousValue =
                    ObjectMember(item, L"process_suspicious_metadata");
                if (pidValue == nullptr || pidValue->type != JsonValue::Type::Number ||
                    pidValue->numberValue < 0.0 ||
                    std::floor(pidValue->numberValue) != pidValue->numberValue ||
                    pidValue->numberValue >
                        static_cast<double>((std::numeric_limits<std::uint32_t>::max)()) ||
                    creationAvailableValue == nullptr ||
                    creationAvailableValue->type != JsonValue::Type::Boolean ||
                    creationValue == nullptr || creationValue->type != JsonValue::Type::String ||
                    severityCapturedValue == nullptr ||
                    severityCapturedValue->type != JsonValue::Type::Boolean ||
                    suspiciousCapturedValue == nullptr ||
                    suspiciousCapturedValue->type != JsonValue::Type::Boolean ||
                    suspiciousValue == nullptr ||
                    (suspiciousValue->type != JsonValue::Type::Boolean &&
                        suspiciousValue->type != JsonValue::Type::Null))
                {
                    error = L"historical_legacy_evidence process identity or metadata is invalid.";
                    return false;
                }
                const std::uint32_t pid =
                    static_cast<std::uint32_t>(pidValue->numberValue);
                const bool hasCreationTime = creationAvailableValue->boolValue;
                std::uint64_t creationTime = 0;
                if (creationValue->stringValue.empty())
                {
                    error = L"historical_legacy_evidence creation_time must be a decimal uint64 string.";
                    return false;
                }
                for (const wchar_t digit : creationValue->stringValue)
                {
                    if (digit < L'0' || digit > L'9')
                    {
                        error = L"historical_legacy_evidence creation_time must be a decimal uint64 string.";
                        return false;
                    }
                    const std::uint64_t value =
                        static_cast<std::uint64_t>(digit - L'0');
                    if (creationTime >
                        ((std::numeric_limits<std::uint64_t>::max)() - value) / 10)
                    {
                        error = L"historical_legacy_evidence creation_time exceeds uint64.";
                        return false;
                    }
                    creationTime = creationTime * 10 + value;
                }
                if (!hasCreationTime && creationTime != 0)
                {
                    error = L"historical_legacy_evidence has contradictory creation-time identity.";
                    return false;
                }
                const std::wstring identity = std::to_wstring(pid) + L"|" +
                    (hasCreationTime ? std::to_wstring(creationTime) : L"-");
                if (!seen.emplace(identity, true).second)
                {
                    error = L"historical_legacy_evidence contains a duplicate process identity.";
                    return false;
                }

                Core::ProcessInfo* matched = nullptr;
                for (Core::ProcessInfo& process : snapshot.processes)
                {
                    if (process.pid == pid &&
                        process.hasCreationTime == hasCreationTime &&
                        (!hasCreationTime ||
                            process.creationTimeFileTime == creationTime))
                    {
                        matched = &process;
                        break;
                    }
                }
                if (matched == nullptr)
                {
                    error = L"historical_legacy_evidence identity does not match a saved process.";
                    return false;
                }

                Core::Severity severity = Core::Severity::None;
                const bool severityCaptured = severityCapturedValue->boolValue;
                const JsonValue* severityValue = ObjectMember(item, L"process_severity");
                if (severityCaptured)
                {
                    if (severityValue == nullptr ||
                        severityValue->type != JsonValue::Type::String ||
                        !TryParseSeverity(severityValue->stringValue, severity))
                    {
                        error = L"historical_legacy_evidence has an invalid captured process severity.";
                        return false;
                    }
                }
                else if (severityValue == nullptr ||
                    severityValue->type != JsonValue::Type::Null)
                {
                    error = L"historical_legacy_evidence uncaptured process severity must be null.";
                    return false;
                }

                const bool suspiciousCaptured =
                    suspiciousCapturedValue->boolValue;
                if ((suspiciousCaptured &&
                        suspiciousValue->type != JsonValue::Type::Boolean) ||
                    (!suspiciousCaptured &&
                        suspiciousValue->type != JsonValue::Type::Null))
                {
                    error = L"historical_legacy_evidence has contradictory process suspicious metadata.";
                    return false;
                }

                std::vector<std::wstring> indicators;
                std::vector<std::wstring> contextNotes;
                if (!ReadHistoricalStringArray(
                        item,
                        L"indicators",
                        indicators,
                        error) ||
                    !ReadHistoricalStringArray(
                        item,
                        L"context_notes",
                        contextNotes,
                        error) ||
                    indicators.size() + contextNotes.size() >
                        SnapshotHistoricalMaxRecordsPerProcess)
                {
                    if (error.empty())
                    {
                        error = L"historical_legacy_evidence exceeds the combined per-process record cap.";
                    }
                    return false;
                }

                matched->severity = severity;
                matched->historicalSeverityCaptured = severityCaptured;
                matched->suspicious = suspiciousCaptured &&
                    suspiciousValue->boolValue;
                matched->historicalSuspiciousCaptured = suspiciousCaptured;
                matched->indicators = std::move(indicators);
                matched->contextNotes = std::move(contextNotes);
            }
            return true;
        }

        bool ReadRequiredTriageBool(
            const JsonValue& object,
            const wchar_t* name,
            bool& destination,
            std::wstring& error)
        {
            const JsonValue* value = ObjectMember(object, name);
            if (value == nullptr || value->type != JsonValue::Type::Boolean)
            {
                error = L"triage_context." + std::wstring(name) + L" must be a boolean.";
                return false;
            }
            destination = value->boolValue;
            return true;
        }

        bool ReadRequiredTriageUInt32(
            const JsonValue& object,
            const wchar_t* name,
            std::uint32_t& destination,
            std::wstring& error)
        {
            const JsonValue* value = ObjectMember(object, name);
            if (value == nullptr || value->type != JsonValue::Type::Number ||
                !std::isfinite(value->numberValue) ||
                value->numberValue < 0.0 ||
                value->numberValue >
                    static_cast<double>((std::numeric_limits<std::uint32_t>::max)()) ||
                std::floor(value->numberValue) != value->numberValue)
            {
                error = L"triage_context." + std::wstring(name) +
                    L" must be an unsigned 32-bit integer.";
                return false;
            }
            destination = static_cast<std::uint32_t>(value->numberValue);
            return true;
        }

        bool ReadRequiredTriageSize(
            const JsonValue& object,
            const wchar_t* name,
            std::size_t maximum,
            std::size_t& destination,
            std::wstring& error)
        {
            std::uint32_t parsed = 0;
            if (!ReadRequiredTriageUInt32(object, name, parsed, error))
            {
                return false;
            }
            if (static_cast<std::size_t>(parsed) > maximum)
            {
                error = L"triage_context." + std::wstring(name) +
                    L" exceeds its retained-count cap.";
                return false;
            }
            destination = static_cast<std::size_t>(parsed);
            return true;
        }

        bool ReadRequiredTriageUtf8String(
            const JsonValue& object,
            const wchar_t* name,
            std::size_t maximumBytes,
            std::string& destination,
            std::wstring& error)
        {
            const JsonValue* value = ObjectMember(object, name);
            if (value == nullptr || value->type != JsonValue::Type::String)
            {
                error = L"triage_context." + std::wstring(name) + L" must be a string.";
                return false;
            }
            destination = WideToUtf8(value->stringValue);
            if (destination.size() > maximumBytes)
            {
                error = L"triage_context." + std::wstring(name) +
                    L" exceeds its UTF-8 byte cap.";
                return false;
            }
            return true;
        }

        bool ReadRequiredTriageStringArray(
            const JsonValue& object,
            const wchar_t* name,
            std::size_t maximumItems,
            std::vector<std::string>& destination,
            std::wstring& error)
        {
            const JsonValue* value = ObjectMember(object, name);
            if (value == nullptr || value->type != JsonValue::Type::Array)
            {
                error = L"triage_context." + std::wstring(name) + L" must be an array.";
                return false;
            }
            if (value->arrayValue.size() > maximumItems)
            {
                error = L"triage_context." + std::wstring(name) +
                    L" exceeds its retained-item cap.";
                return false;
            }
            destination.clear();
            destination.reserve(value->arrayValue.size());
            for (const JsonValue& item : value->arrayValue)
            {
                if (item.type != JsonValue::Type::String)
                {
                    error = L"triage_context." + std::wstring(name) +
                        L" entries must be strings.";
                    return false;
                }
                std::string text = WideToUtf8(item.stringValue);
                if (text.size() > Core::PersistedTriageLineMaxUtf8Bytes)
                {
                    error = L"triage_context." + std::wstring(name) +
                        L" contains a line exceeding its UTF-8 byte cap.";
                    return false;
                }
                destination.push_back(std::move(text));
            }
            return true;
        }

        bool ParsePersistedTriageSummary(
            const JsonValue& value,
            Core::PersistedTriageSummary& summary,
            bool allowHistoricalLegacyFallback,
            std::wstring& error)
        {
            if (value.type != JsonValue::Type::Object)
            {
                error = L"triage_context captured_triage must be an object.";
                return false;
            }

            std::string status;
            if (!ReadRequiredTriageBool(value, L"captured", summary.captured, error) ||
                !ReadRequiredTriageBool(value, L"evaluation_succeeded", summary.evaluationSucceeded, error) ||
                !ReadRequiredTriageBool(value, L"baseline_verdict_available", summary.baselineVerdictAvailable, error) ||
                !ReadRequiredTriageBool(value, L"enriched_changed_verdict", summary.enrichedChangedVerdict, error) ||
                !ReadRequiredTriageUInt32(value, L"triage_model_version", summary.triageModelVersion, error) ||
                !ReadRequiredTriageSize(
                    value,
                    L"source_evidence_count",
                    Core::PersistedTriageMaxSourceEvidenceCount,
                    summary.sourceEvidenceCount,
                    error) ||
                !ReadRequiredTriageUtf8String(
                    value,
                    L"status",
                    Core::PersistedTriageStatusMaxUtf8Bytes,
                    status,
                    error))
            {
                return false;
            }
            summary.status = std::move(status);

            const JsonValue* usingFallback =
                ObjectMember(value, L"using_fallback");
            const JsonValue* fallbackReason =
                ObjectMember(value, L"fallback_reason");
            if (allowHistoricalLegacyFallback)
            {
                std::string reason;
                if (!ReadRequiredTriageBool(
                        value,
                        L"using_fallback",
                        summary.usingFallback,
                        error) ||
                    !ReadRequiredTriageUtf8String(
                        value,
                        L"fallback_reason",
                        Core::PersistedTriageFallbackReasonMaxUtf8Bytes,
                        reason,
                        error))
                {
                    return false;
                }
                summary.fallbackReason = std::move(reason);
            }
            else if (usingFallback != nullptr || fallbackReason != nullptr)
            {
                bool historicalFlag = false;
                std::string historicalReason;
                if (usingFallback == nullptr || fallbackReason == nullptr ||
                    !ReadRequiredTriageBool(
                        value,
                        L"using_fallback",
                        historicalFlag,
                        error) ||
                    !ReadRequiredTriageUtf8String(
                        value,
                        L"fallback_reason",
                        Core::PersistedTriageFallbackReasonMaxUtf8Bytes,
                        historicalReason,
                        error) ||
                    historicalFlag || !historicalReason.empty())
                {
                    error = L"Schema 5 triage records cannot contain a legacy fallback state.";
                    return false;
                }
            }

            const JsonValue* analysis = ObjectMember(value, L"analysis_level");
            if (analysis == nullptr || analysis->type != JsonValue::Type::String ||
                !ParsePersistedAnalysisLevelToken(
                    analysis->stringValue,
                    summary.analysisLevel))
            {
                error = L"triage_context.analysis_level is unknown.";
                return false;
            }
            const JsonValue* verdict = ObjectMember(value, L"authoritative_verdict");
            if (verdict == nullptr || verdict->type != JsonValue::Type::String ||
                !ParseTriageVerdictToken(
                    verdict->stringValue,
                    summary.authoritativeVerdict))
            {
                error = L"triage_context.authoritative_verdict is unknown.";
                return false;
            }
            const JsonValue* baselineVerdict = ObjectMember(value, L"baseline_verdict");
            if (baselineVerdict == nullptr ||
                baselineVerdict->type != JsonValue::Type::String ||
                !ParseTriageVerdictToken(
                    baselineVerdict->stringValue,
                    summary.baselineVerdict))
            {
                error = L"triage_context.baseline_verdict is unknown.";
                return false;
            }

            const JsonValue* domains = ObjectMember(value, L"contributing_domains");
            if (domains == nullptr || domains->type != JsonValue::Type::Array ||
                domains->arrayValue.size() >
                    Core::PersistedTriageMaxContributingDomains)
            {
                error = L"triage_context.contributing_domains is missing or exceeds its cap.";
                return false;
            }
            summary.contributingDomains.clear();
            summary.contributingDomains.reserve(domains->arrayValue.size());
            for (const JsonValue& item : domains->arrayValue)
            {
                Core::EvidenceDomain domain = Core::EvidenceDomain::Unknown;
                if (item.type != JsonValue::Type::String ||
                    !ParseEvidenceDomainToken(item.stringValue, domain))
                {
                    error = L"triage_context.contributing_domains contains an unknown domain.";
                    return false;
                }
                summary.contributingDomains.push_back(domain);
            }

            if (!ReadRequiredTriageStringArray(
                    value, L"verdict_basis",
                    Core::PersistedTriageMaxVerdictBasisItems,
                    summary.verdictBasis, error) ||
                !ReadRequiredTriageStringArray(
                    value, L"completed_correlations",
                    Core::PersistedTriageMaxCompletedCorrelationItems,
                    summary.completedCorrelations, error) ||
                !ReadRequiredTriageStringArray(
                    value, L"supporting_context",
                    Core::PersistedTriageMaxSupportingContextItems,
                    summary.supportingContext, error) ||
                !ReadRequiredTriageStringArray(
                    value, L"collection_limitations",
                    Core::PersistedTriageMaxCollectionLimitationItems,
                    summary.collectionLimitations, error) ||
                !ReadRequiredTriageStringArray(
                    value, L"evidence_integrity_context",
                    Core::PersistedTriageMaxEvidenceIntegrityItems,
                    summary.evidenceIntegrityContext, error) ||
                !ReadRequiredTriageStringArray(
                    value, L"unresolved_correlations",
                    Core::PersistedTriageMaxUnresolvedCorrelationItems,
                    summary.unresolvedCorrelations, error))
            {
                return false;
            }

            const Core::PersistedTriageValidationResult validation =
                Core::ValidatePersistedTriageSummary(summary);
            if (!validation.valid)
            {
                error = L"triage_context captured_triage is invalid: " +
                    Utf8ToWide(validation.message.data(), validation.message.size());
                return false;
            }
            return true;
        }

        bool ParseUInt64Decimal(
            const std::wstring& value,
            std::uint64_t& destination)
        {
            if (value.empty() ||
                std::any_of(value.begin(), value.end(), [](wchar_t character)
                {
                    return character < L'0' || character > L'9';
                }))
            {
                return false;
            }
            try
            {
                std::size_t parsed = 0;
                const unsigned long long result = std::stoull(value, &parsed, 10);
                if (parsed != value.size())
                {
                    return false;
                }
                destination = static_cast<std::uint64_t>(result);
                return true;
            }
            catch (...)
            {
                return false;
            }
        }

        bool ParsePersistedTriageRecord(
            const JsonValue& value,
            Core::PersistedProcessTriageRecord& record,
            bool allowHistoricalLegacyFallback,
            std::wstring& error)
        {
            if (value.type != JsonValue::Type::Object ||
                !ReadRequiredTriageUInt32(value, L"pid", record.identity.pid, error) ||
                !ReadRequiredTriageBool(
                    value,
                    L"creation_time_available",
                    record.identity.hasCreationTime,
                    error))
            {
                return false;
            }
            const JsonValue* creation = ObjectMember(value, L"creation_time");
            if (creation == nullptr || creation->type != JsonValue::Type::String ||
                !ParseUInt64Decimal(
                    creation->stringValue,
                    record.identity.creationTimeFileTime))
            {
                error = L"triage_context.creation_time must be a decimal uint64 string.";
                return false;
            }
            const JsonValue* summary = ObjectMember(value, L"captured_triage");
            if (summary == nullptr ||
                !ParsePersistedTriageSummary(
                    *summary,
                    record.summary,
                    allowHistoricalLegacyFallback,
                    error))
            {
                if (summary == nullptr)
                {
                    error = L"triage_context record is missing captured_triage.";
                }
                return false;
            }
            return true;
        }

        bool ParsePersistedTriageContext(
            const JsonValue& value,
            std::uint32_t modelVersion,
            bool allowHistoricalLegacyFallback,
            Core::PersistedTriageContext& context,
            std::wstring& error)
        {
            if (value.type != JsonValue::Type::Object)
            {
                error = L"triage_context must be an object.";
                return false;
            }
            context = {};
            context.modelVersion = modelVersion;
            const JsonValue* records = ObjectMember(value, L"process_records");
            if (records == nullptr || records->type != JsonValue::Type::Array ||
                records->arrayValue.size() >
                    Core::PersistedTriageMaxProcessRecords)
            {
                error = L"triage_context.process_records is missing or exceeds its cap.";
                return false;
            }
            context.processRecords.reserve(records->arrayValue.size());
            for (const JsonValue& valueRecord : records->arrayValue)
            {
                Core::PersistedProcessTriageRecord record;
                if (!ParsePersistedTriageRecord(
                        valueRecord,
                        record,
                        allowHistoricalLegacyFallback,
                        error))
                {
                    return false;
                }
                context.processRecords.push_back(std::move(record));
            }

            const JsonValue* selected = ObjectMember(value, L"selected_process_triage");
            if (selected == nullptr)
            {
                error = L"triage_context is missing selected_process_triage.";
                return false;
            }
            if (selected->type == JsonValue::Type::Object)
            {
                Core::PersistedProcessTriageRecord selectedRecord;
                if (!ParsePersistedTriageRecord(
                        *selected,
                        selectedRecord,
                        allowHistoricalLegacyFallback,
                        error))
                {
                    return false;
                }
                context.selectedRecord = std::move(selectedRecord);
            }
            else if (selected->type != JsonValue::Type::Null)
            {
                error = L"triage_context.selected_process_triage must be an object or null.";
                return false;
            }

            const Core::PersistedTriageValidationResult validation =
                Core::ValidatePersistedTriageContext(context);
            if (!validation.valid)
            {
                error = L"triage_context is invalid: " +
                    Utf8ToWide(validation.message.data(), validation.message.size());
                return false;
            }
            return true;
        }

        bool ReadRequiredNativeEvidenceUtf8String(
            const JsonValue& object,
            const wchar_t* name,
            std::size_t maximumBytes,
            std::string& destination,
            std::wstring& error)
        {
            const JsonValue* value = ObjectMember(object, name);
            if (value == nullptr || value->type != JsonValue::Type::String)
            {
                error = L"native_source_evidence." + std::wstring(name) +
                    L" must be a string.";
                return false;
            }
            destination = WideToUtf8(value->stringValue);
            if (destination.size() > maximumBytes)
            {
                error = L"native_source_evidence." + std::wstring(name) +
                    L" exceeds its UTF-8 byte cap.";
                return false;
            }
            return true;
        }

        bool ReadRequiredNativeEvidenceStringArray(
            const JsonValue& object,
            const wchar_t* name,
            std::size_t maximumItems,
            std::size_t maximumBytes,
            std::vector<std::string>& destination,
            std::wstring& error)
        {
            const JsonValue* value = ObjectMember(object, name);
            if (value == nullptr || value->type != JsonValue::Type::Array ||
                value->arrayValue.size() > maximumItems)
            {
                error = L"native_source_evidence." + std::wstring(name) +
                    L" is missing or exceeds its item cap.";
                return false;
            }
            destination.clear();
            destination.reserve(value->arrayValue.size());
            for (const JsonValue& item : value->arrayValue)
            {
                if (item.type != JsonValue::Type::String)
                {
                    error = L"native_source_evidence." + std::wstring(name) +
                        L" must contain only strings.";
                    return false;
                }
                std::string text = WideToUtf8(item.stringValue);
                if (text.size() > maximumBytes)
                {
                    error = L"native_source_evidence." + std::wstring(name) +
                        L" contains an item exceeding its UTF-8 byte cap.";
                    return false;
                }
                destination.push_back(std::move(text));
            }
            return true;
        }

        bool ReadRequiredNativeEvidenceBool(
            const JsonValue& object,
            const wchar_t* name,
            bool& destination,
            std::wstring& error)
        {
            const JsonValue* value = ObjectMember(object, name);
            if (value == nullptr || value->type != JsonValue::Type::Boolean)
            {
                error = L"native_source_evidence." + std::wstring(name) +
                    L" must be a boolean.";
                return false;
            }
            destination = value->boolValue;
            return true;
        }

        bool ParseNativeSourceEvidenceRecord(
            const JsonValue& value,
            Core::NativeSourceEvidenceRecord& record,
            std::wstring& error)
        {
            if (value.type != JsonValue::Type::Object ||
                !ReadRequiredNativeEvidenceUtf8String(
                    value,
                    L"stable_rule_id",
                    Core::NativeSourceEvidenceStableRuleIdMaxUtf8Bytes,
                    record.stableRuleId,
                    error) ||
                !ReadRequiredNativeEvidenceUtf8String(
                    value,
                    L"title",
                    Core::NativeSourceEvidenceTitleMaxUtf8Bytes,
                    record.title,
                    error) ||
                !ReadRequiredNativeEvidenceUtf8String(
                    value,
                    L"summary",
                    Core::NativeSourceEvidenceSummaryMaxUtf8Bytes,
                    record.summary,
                    error) ||
                !ReadRequiredNativeEvidenceStringArray(
                    value,
                    L"details",
                    Core::NativeSourceEvidenceMaxDetailItems,
                    Core::NativeSourceEvidenceDetailMaxUtf8Bytes,
                    record.details,
                    error) ||
                !ReadRequiredNativeEvidenceStringArray(
                    value,
                    L"limitations",
                    Core::NativeSourceEvidenceMaxLimitationItems,
                    Core::NativeSourceEvidenceLimitationMaxUtf8Bytes,
                    record.limitations,
                    error) ||
                !ReadRequiredNativeEvidenceUtf8String(
                    value,
                    L"artifact_family",
                    Core::NativeSourceEvidenceArtifactFamilyMaxUtf8Bytes,
                    record.artifactFamily,
                    error) ||
                !ReadRequiredNativeEvidenceUtf8String(
                    value,
                    L"provenance_summary",
                    Core::NativeSourceEvidenceProvenanceSummaryMaxUtf8Bytes,
                    record.provenanceSummary,
                    error) ||
                !ReadRequiredNativeEvidenceBool(
                    value,
                    L"contributed_to_verdict",
                    record.contributedToVerdict,
                    error) ||
                !ReadRequiredNativeEvidenceBool(
                    value,
                    L"suppressed_duplicate",
                    record.suppressedDuplicate,
                    error) ||
                !ReadRequiredNativeEvidenceBool(
                    value,
                    L"collection_limitation",
                    record.collectionLimitation,
                    error))
            {
                if (error.empty())
                {
                    error = L"native_source_evidence record must be an object.";
                }
                return false;
            }

            const JsonValue* domain = ObjectMember(value, L"domain");
            const JsonValue* disposition = ObjectMember(value, L"disposition");
            const JsonValue* strength = ObjectMember(value, L"strength");
            const JsonValue* confidence = ObjectMember(value, L"confidence");
            if (domain == nullptr || domain->type != JsonValue::Type::String ||
                !ParseEvidenceDomainToken(domain->stringValue, record.domain) ||
                disposition == nullptr ||
                disposition->type != JsonValue::Type::String ||
                !ParseObservationDispositionToken(
                    disposition->stringValue,
                    record.disposition) ||
                strength == nullptr || strength->type != JsonValue::Type::String ||
                !ParseObservationStrengthToken(strength->stringValue, record.strength) ||
                confidence == nullptr ||
                confidence->type != JsonValue::Type::String ||
                !ParseObservationConfidenceToken(
                    confidence->stringValue,
                    record.confidence))
            {
                error = L"native_source_evidence contains an unknown typed enum token.";
                return false;
            }

            const Core::NativeSourceEvidenceValidationResult validation =
                Core::ValidateNativeSourceEvidenceRecord(record);
            if (!validation.valid)
            {
                error = L"native_source_evidence record is invalid: " +
                    Utf8ToWide(
                        validation.diagnostic.data(),
                        validation.diagnostic.size());
                return false;
            }
            return true;
        }

        bool ParseNativeSourceEvidenceContext(
            const JsonValue& value,
            SavedNativeSourceEvidenceContext& context,
            std::wstring& error)
        {
            if (value.type != JsonValue::Type::Object)
            {
                error = L"native_source_evidence must be an object.";
                return false;
            }
            std::uint32_t modelVersion = 0;
            std::wstring ignoredTriageError;
            if (!ReadRequiredTriageUInt32(
                    value,
                    L"model_version",
                    modelVersion,
                    ignoredTriageError) ||
                modelVersion != Core::NativeSourceEvidenceModelVersion)
            {
                error = L"native_source_evidence has an unsupported model_version.";
                return false;
            }

            SavedNativeSourceEvidenceContext parsed;
            parsed.modelVersion = modelVersion;
            const JsonValue* selected = ObjectMember(value, L"selected_process");
            if (selected == nullptr)
            {
                error = L"native_source_evidence is missing selected_process.";
                return false;
            }
            if (selected->type == JsonValue::Type::Null)
            {
                context = std::move(parsed);
                return true;
            }
            if (selected->type != JsonValue::Type::Object)
            {
                error = L"native_source_evidence.selected_process must be an object or null.";
                return false;
            }

            SavedNativeSourceEvidenceRecord record;
            std::wstring ignoredIdentityError;
            if (!ReadRequiredTriageUInt32(
                    *selected,
                    L"pid",
                    record.identity.pid,
                    ignoredIdentityError) ||
                !ReadRequiredTriageBool(
                    *selected,
                    L"creation_time_available",
                    record.identity.hasCreationTime,
                    ignoredIdentityError))
            {
                error = L"native_source_evidence selected identity is invalid.";
                return false;
            }
            const JsonValue* creation = ObjectMember(*selected, L"creation_time");
            if (creation == nullptr || creation->type != JsonValue::Type::String ||
                !ParseUInt64Decimal(
                    creation->stringValue,
                    record.identity.creationTimeFileTime))
            {
                error = L"native_source_evidence.creation_time must be a decimal uint64 string.";
                return false;
            }
            const JsonValue* records = ObjectMember(*selected, L"records");
            if (records == nullptr || records->type != JsonValue::Type::Array ||
                records->arrayValue.size() > Core::NativeSourceEvidenceMaxRecords)
            {
                error = L"native_source_evidence.records is missing or exceeds its cap.";
                return false;
            }
            record.records.reserve(records->arrayValue.size());
            for (const JsonValue& valueRecord : records->arrayValue)
            {
                Core::NativeSourceEvidenceRecord nativeRecord;
                if (!ParseNativeSourceEvidenceRecord(
                        valueRecord,
                        nativeRecord,
                        error))
                {
                    return false;
                }
                record.records.push_back(std::move(nativeRecord));
            }
            const Core::NativeSourceEvidenceValidationResult validation =
                Core::ValidateNativeSourceEvidenceRecords(record.records);
            if (!validation.valid)
            {
                error = L"native_source_evidence records are invalid: " +
                    Utf8ToWide(
                        validation.diagnostic.data(),
                        validation.diagnostic.size());
                return false;
            }
            parsed.selectedRecord = std::move(record);
            context = std::move(parsed);
            return true;
        }

        Core::NetworkConnection ParseNetworkConnection(const JsonValue& value)
        {
            Core::NetworkConnection connection;
            connection.owningPid = UInt32Member(value, L"owning_pid");
            connection.processName = StringMember(value, L"process_name");
            connection.protocol = StringMember(value, L"protocol");
            connection.localAddress = StringMember(value, L"local_address");
            connection.localPort = static_cast<std::uint16_t>(UInt32Member(value, L"local_port"));
            connection.remoteAddress = StringMember(value, L"remote_address");
            connection.remotePort = static_cast<std::uint16_t>(UInt32Member(value, L"remote_port"));
            connection.state = StringMember(value, L"state");
            connection.addressFamily = StringMember(value, L"address_family");
            connection.isListening = BoolMember(value, L"is_listening");
            connection.isLoopback = BoolMember(value, L"is_loopback");
            connection.isLan = BoolMember(value, L"is_lan");
            connection.isPublicRemote = BoolMember(value, L"is_public_remote");
            return connection;
        }

        void WriteNetworkIndicator(std::ostream& output, const Core::NetworkIndicator& indicator, const std::string& indent)
        {
            output << "{\n";
            output << indent << "  \"type\": ";
            WriteJsonString(output, indicator.type);
            output << ",\n";
            output << indent << "  \"value\": ";
            WriteJsonString(output, indicator.value);
            output << ",\n";
            output << indent << "  \"normalized_value\": ";
            WriteJsonString(output, indicator.normalizedValue);
            output << ",\n";
            output << indent << "  \"category\": ";
            WriteJsonString(output, indicator.category);
            output << ",\n";
            output << indent << "  \"severity\": ";
            WriteJsonString(output, indicator.severity);
            output << ",\n";
            output << indent << "  \"confidence\": ";
            WriteJsonString(output, indicator.confidence);
            output << ",\n";
            output << indent << "  \"source\": ";
            WriteJsonString(output, indicator.source);
            output << ",\n";
            output << indent << "  \"description\": ";
            WriteJsonString(output, indicator.description);
            output << ",\n";
            output << indent << "  \"first_seen\": ";
            WriteJsonString(output, indicator.firstSeen);
            output << ",\n";
            output << indent << "  \"last_seen\": ";
            WriteJsonString(output, indicator.lastSeen);
            output << "\n" << indent << "}";
        }

        Core::NetworkIndicator ParseNetworkIndicator(const JsonValue& value)
        {
            Core::NetworkIndicator indicator;
            indicator.type = StringMember(value, L"type");
            indicator.value = StringMember(value, L"value");
            indicator.normalizedValue = StringMember(value, L"normalized_value");
            indicator.category = StringMember(value, L"category");
            indicator.severity = StringMember(value, L"severity");
            indicator.confidence = StringMember(value, L"confidence");
            indicator.source = StringMember(value, L"source");
            indicator.description = StringMember(value, L"description");
            indicator.firstSeen = StringMember(value, L"first_seen");
            indicator.lastSeen = StringMember(value, L"last_seen");
            return indicator;
        }

        void WriteNetworkIndicatorMatch(
            std::ostream& output,
            const Core::NetworkIndicatorMatch& match,
            const std::string& indent,
            bool trailingComma)
        {
            output << indent << "{\n";
            output << indent << "  \"connection\": ";
            WriteNetworkConnection(output, match.connection, indent + "  ", false);
            output << ",\n";
            output << indent << "  \"indicator\": ";
            WriteNetworkIndicator(output, match.indicator, indent + "  ");
            output << "\n" << indent << "}";
            if (trailingComma)
            {
                output << ',';
            }
            output << '\n';
        }

        Core::NetworkIndicatorMatch ParseNetworkIndicatorMatch(const JsonValue& value)
        {
            Core::NetworkIndicatorMatch match;
            if (const JsonValue* connection = ObjectMember(value, L"connection");
                connection != nullptr && connection->type == JsonValue::Type::Object)
            {
                match.connection = ParseNetworkConnection(*connection);
            }
            if (const JsonValue* indicator = ObjectMember(value, L"indicator");
                indicator != nullptr && indicator->type == JsonValue::Type::Object)
            {
                match.indicator = ParseNetworkIndicator(*indicator);
            }
            return match;
        }

        Core::PersistedTriageContext MakeNotCapturedTriageContext(
            const Core::ProcessSnapshot& snapshot,
            std::uint32_t /*selectedPid*/)
        {
            std::vector<Core::PersistedProcessTriageRecord> records;
            records.reserve((std::min)(
                snapshot.processes.size(),
                Core::PersistedTriageMaxProcessRecords));
            for (const Core::ProcessInfo& process : snapshot.processes)
            {
                Core::PersistedProcessTriageRecord record;
                record.identity = Core::MakeProcessIdentityKey(process);
                record.summary = Core::MakeNotCapturedPersistedTriageSummary();
                records.push_back(std::move(record));
            }
            return Core::MakePersistedTriageContext(
                std::move(records),
                std::nullopt);
        }

        bool ValidateTriageContextForSnapshot(
            const Core::PersistedTriageContext& context,
            const Core::ProcessSnapshot& snapshot,
            std::uint32_t selectedPid,
            bool allowHistoricalLegacyFallback,
            std::wstring& error)
        {
            const Core::PersistedTriageValidationResult validation =
                Core::ValidatePersistedTriageContext(context);
            if (!validation.valid)
            {
                error = L"triage_context is invalid: " +
                    Utf8ToWide(validation.message.data(), validation.message.size());
                return false;
            }
            if (context.processRecords.size() != snapshot.processes.size())
            {
                error = L"triage_context.process_records must contain exactly one record for every saved process identity.";
                return false;
            }

            std::vector<Core::ProcessIdentityKey> snapshotIdentities;
            snapshotIdentities.reserve(snapshot.processes.size());
            for (const Core::ProcessInfo& process : snapshot.processes)
            {
                const Core::ProcessIdentityKey identity =
                    Core::MakeProcessIdentityKey(process);
                snapshotIdentities.push_back(identity);
            }
            std::sort(snapshotIdentities.begin(), snapshotIdentities.end());
            if (std::adjacent_find(
                    snapshotIdentities.begin(),
                    snapshotIdentities.end()) != snapshotIdentities.end())
            {
                error = L"Saved process rows contain a duplicate PID and creation-time identity.";
                return false;
            }
            if (std::adjacent_find(
                    snapshotIdentities.begin(),
                    snapshotIdentities.end(),
                    [](const Core::ProcessIdentityKey& left,
                       const Core::ProcessIdentityKey& right)
                    {
                        return left.pid == right.pid;
                    }) != snapshotIdentities.end())
            {
                error = L"Saved process rows contain an ambiguous duplicate PID.";
                return false;
            }
            for (std::size_t index = 0;
                index < snapshotIdentities.size();
                ++index)
            {
                if (context.processRecords[index].identity !=
                    snapshotIdentities[index])
                {
                    error = L"triage_context identities do not exactly match the saved process identities.";
                    return false;
                }
                const Core::PersistedProcessTriageRecord& record =
                    context.processRecords[index];
                if (!allowHistoricalLegacyFallback &&
                    record.summary.analysisLevel ==
                        Core::PersistedTriageAnalysisLevel::LegacyFallback)
                {
                    error = L"Native-evidence snapshots cannot contain a legacy-fallback process triage record.";
                    return false;
                }
                if (record.summary.analysisLevel ==
                    Core::PersistedTriageAnalysisLevel::Enriched)
                {
                    error = L"triage_context process-wide records cannot use the enriched analysis level.";
                    return false;
                }
            }

            const Core::ProcessInfo* selectedProcess = nullptr;
            std::size_t selectedMatchCount = 0;
            for (const Core::ProcessInfo& process : snapshot.processes)
            {
                if (process.pid == selectedPid)
                {
                    selectedProcess = &process;
                    ++selectedMatchCount;
                }
            }
            if (selectedMatchCount > 1)
            {
                error = L"Saved selected PID is ambiguous across multiple process identities.";
                return false;
            }
            if (selectedProcess == nullptr)
            {
                if (context.selectedRecord.has_value())
                {
                    error = L"triage_context selected_process_triage exists without a selected saved process.";
                    return false;
                }
                return true;
            }
            if (context.selectedRecord.has_value() &&
                context.selectedRecord->identity !=
                    Core::MakeProcessIdentityKey(*selectedProcess))
            {
                error = L"triage_context selected_process_triage does not match the saved selected process identity.";
                return false;
            }
            if (!allowHistoricalLegacyFallback &&
                context.selectedRecord.has_value() &&
                context.selectedRecord->summary.analysisLevel ==
                    Core::PersistedTriageAnalysisLevel::LegacyFallback)
            {
                error = L"Native-evidence snapshots cannot contain a legacy-fallback selected triage record.";
                return false;
            }
            return true;
        }

        bool ValidateNativeSourceEvidenceForSnapshot(
            const SavedNativeSourceEvidenceContext& context,
            const Core::ProcessSnapshot& snapshot,
            std::uint32_t selectedPid,
            const Core::PersistedTriageContext& triageContext,
            std::wstring& error)
        {
            if (context.modelVersion !=
                Core::NativeSourceEvidenceModelVersion)
            {
                error = L"native_source_evidence has an unsupported model version.";
                return false;
            }
            if (!context.selectedRecord.has_value())
            {
                return true;
            }

            const SavedNativeSourceEvidenceRecord& selected =
                *context.selectedRecord;
            const Core::NativeSourceEvidenceValidationResult validation =
                Core::ValidateNativeSourceEvidenceRecords(selected.records);
            if (!validation.valid)
            {
                error = L"native_source_evidence is invalid: " +
                    Utf8ToWide(
                        validation.diagnostic.data(),
                        validation.diagnostic.size());
                return false;
            }

            const Core::ProcessInfo* matchingProcess = nullptr;
            std::size_t matchingPidCount = 0;
            for (const Core::ProcessInfo& process : snapshot.processes)
            {
                if (process.pid == selected.identity.pid)
                {
                    matchingProcess = &process;
                    ++matchingPidCount;
                }
            }
            if (matchingPidCount != 1 || matchingProcess == nullptr ||
                selected.identity !=
                    Core::MakeProcessIdentityKey(*matchingProcess))
            {
                error = L"native_source_evidence selected identity does not exactly match one saved process.";
                return false;
            }
            if (selected.identity.pid != selectedPid)
            {
                error = L"native_source_evidence selected identity does not match selected_pid.";
                return false;
            }
            if (triageContext.selectedRecord.has_value() &&
                triageContext.selectedRecord->identity != selected.identity)
            {
                error = L"native_source_evidence and selected triage identities do not match.";
                return false;
            }
            return true;
        }

        bool WriteAllText(const std::wstring& filePath, const std::string& text, std::wstring* errorMessage)
        {
            std::ofstream output(std::filesystem::path(filePath), std::ios::binary | std::ios::trunc);
            if (!output)
            {
                if (errorMessage != nullptr)
                {
                    *errorMessage = L"Could not open output file for writing.";
                }
                return false;
            }
            output << text;
            if (!output)
            {
                if (errorMessage != nullptr)
                {
                    *errorMessage = L"Could not write output file.";
                }
                return false;
            }
            return true;
        }
    }

    bool SaveGlassPaneSnapshot(
        const SavedSnapshotExportContext& context,
        const std::wstring& filePath,
        std::wstring* errorMessage)
    {
        if (context.snapshot == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = L"No process snapshot is available to save.";
            }
            return false;
        }
        if (context.snapshot->processes.size() > SnapshotMaxProcesses)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = L"Process snapshot exceeds the saved-snapshot process cap.";
            }
            return false;
        }
        if (context.serviceContext == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = L"No service context is available to save.";
            }
            return false;
        }

        std::wstring serviceValidationError;
        if (!ValidateServiceContextForSnapshot(*context.serviceContext, serviceValidationError))
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = L"Service context is invalid: " + serviceValidationError;
            }
            return false;
        }

        Core::PersistedTriageContext notCapturedTriage;
        const Core::PersistedTriageContext* triageContext = context.triageContext;
        if (triageContext == nullptr)
        {
            notCapturedTriage = MakeNotCapturedTriageContext(
                *context.snapshot,
                context.selectedPid);
            triageContext = &notCapturedTriage;
        }
        std::wstring triageValidationError;
        if (!ValidateTriageContextForSnapshot(
                *triageContext,
                *context.snapshot,
                context.selectedPid,
                false,
                triageValidationError))
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = L"Captured triage context is invalid: " +
                    triageValidationError;
            }
            return false;
        }
        std::wstring nativeEvidenceValidationError;
        if (!ValidateNativeSourceEvidenceForSnapshot(
                context.nativeSourceEvidence,
                *context.snapshot,
                context.selectedPid,
                *triageContext,
                nativeEvidenceValidationError))
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = L"Captured native source evidence is invalid: " +
                    nativeEvidenceValidationError;
            }
            return false;
        }
        std::wstring historicalEvidenceValidationError;
        if (context.preserveHistoricalLegacyEvidence &&
            !ValidateHistoricalLegacyEvidenceForSave(
                *context.snapshot,
                historicalEvidenceValidationError))
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = L"Historical compatibility evidence is invalid: " +
                    historicalEvidenceValidationError;
            }
            return false;
        }

        {
            std::ofstream output(std::filesystem::path(filePath), std::ios::binary | std::ios::trunc);
            if (!output)
            {
                if (errorMessage != nullptr)
                {
                    *errorMessage = L"Could not open snapshot file for writing.";
                }
                return false;
            }

            const std::vector<Core::NetworkConnection>* connections =
                context.networkLoaded && context.network != nullptr ? &context.network->connections : nullptr;

            output << "{\n";
            output << "  \"format\": ";
            WriteJsonString(output, GlassPaneSnapshotFormat);
            output << ",\n";
            output << "  \"schema_version\": " << GlassPaneSnapshotSchemaVersion << ",\n";
            output << "  \"triage_model_version\": " << triageContext->modelVersion << ",\n";
            output << "  \"glasspane_version\": ";
            WriteJsonString(output, context.glassPaneVersion);
            output << ",\n";
            output << "  \"captured_at\": ";
            WriteJsonString(output, context.capturedAt);
            output << ",\n";
            output << "  \"hostname\": ";
            WriteJsonString(output, context.hostname);
            output << ",\n";
            output << "  \"current_user\": ";
            WriteJsonString(output, context.currentUser);
            output << ",\n";
            output << "  \"os_build\": ";
            WriteJsonString(output, context.osBuild);
            output << ",\n";
            output << "  \"evidence_mode\": ";
            WriteJsonString(output, context.evidenceMode.empty() ? std::wstring(L"default") : context.evidenceMode);
            output << ",\n";
            output << "  \"selected_pid\": " << context.selectedPid << ",\n";
            output << "  \"process_count\": " << context.snapshot->processes.size() << ",\n";
            output << "  \"network_loaded\": " << (context.networkLoaded ? "true" : "false") << ",\n";
            output << "  \"network_status_message\": ";
            WriteJsonString(output, context.network != nullptr ? context.network->statusMessage : std::wstring{});
            output << ",\n";
            output << "  \"network_row_count\": " << (connections != nullptr ? connections->size() : 0) << ",\n";
            output << "  \"network_intelligence\": {\n";
            output << "    \"loaded\": " << (context.networkIntel.loaded ? "true" : "false") << ",\n";
            output << "    \"feed_name\": ";
            WriteJsonString(output, context.networkIntel.feedName);
            output << ",\n";
            output << "    \"schema_version\": " << context.networkIntel.schemaVersion << ",\n";
            output << "    \"generated_at\": ";
            WriteJsonString(output, context.networkIntel.generatedAt);
            output << ",\n";
            output << "    \"expires_at\": ";
            WriteJsonString(output, context.networkIntel.expiresAt);
            output << ",\n";
            output << "    \"indicator_count\": " << context.networkIntel.indicatorCount << ",\n";
            output << "    \"source\": ";
            WriteJsonString(output, context.networkIntel.source);
            output << ",\n";
            output << "    \"status\": ";
            WriteJsonString(output, context.networkIntel.status);
            output << ",\n";
            output << "    \"local_feed_sha256\": ";
            WriteJsonString(output, context.networkIntel.localFeedSha256);
            output << "\n";
            output << "  },\n";
            WriteServiceContext(output, *context.serviceContext, "  ");
            WritePersistedTriageContext(output, *triageContext);
            WriteNativeSourceEvidenceContext(
                output,
                context.nativeSourceEvidence);
            if (context.preserveHistoricalLegacyEvidence)
            {
                WriteHistoricalLegacyEvidenceContext(
                    output,
                    *context.snapshot);
            }
            output << "  \"processes\": [\n";
            for (std::size_t index = 0; index < context.snapshot->processes.size(); ++index)
            {
                WriteProcess(output, context.snapshot->processes[index], "    ", index + 1 < context.snapshot->processes.size());
            }
            output << "  ],\n";
            output << "  \"network_connections\": [\n";
            if (connections != nullptr)
            {
                for (std::size_t index = 0; index < connections->size(); ++index)
                {
                    WriteNetworkConnection(output, (*connections)[index], "    ", index + 1 < connections->size());
                }
            }
            output << "  ],\n";
            output << "  \"network_intelligence_matches\": [\n";
            if (context.networkIndicatorMatches != nullptr)
            {
                for (std::size_t index = 0; index < context.networkIndicatorMatches->size(); ++index)
                {
                    WriteNetworkIndicatorMatch(
                        output,
                        (*context.networkIndicatorMatches)[index],
                        "    ",
                        index + 1 < context.networkIndicatorMatches->size());
                }
            }
            output << "  ],\n";
            WriteProcessEvidenceMap(output, context.processEvidence);
            output << "}\n";

            if (!output)
            {
                if (errorMessage != nullptr)
                {
                    *errorMessage = L"Could not finish writing snapshot file.";
                }
                return false;
            }
            output.flush();
            if (!output)
            {
                if (errorMessage != nullptr)
                {
                    *errorMessage = L"Could not flush snapshot file.";
                }
                return false;
            }
            output.close();
            if (!output)
            {
                if (errorMessage != nullptr)
                {
                    *errorMessage = L"Could not close snapshot file after writing.";
                }
                return false;
            }
        }

        SavedSnapshotDocument validation;
        std::wstring validationError;
        if (!LoadGlassPaneSnapshot(filePath, validation, &validationError))
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = L"Snapshot save validation failed: " +
                    (validationError.empty() ? std::wstring(L"malformed JSON") : validationError);
            }
            return false;
        }
        return true;
    }

    bool LoadGlassPaneSnapshot(
        const std::wstring& filePath,
        SavedSnapshotDocument& document,
        std::wstring* errorMessage)
    {
        std::ifstream input(std::filesystem::path(filePath), std::ios::binary);
        if (!input)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = L"Could not open snapshot file.";
            }
            return false;
        }

        input.seekg(0, std::ios::end);
        const std::streamoff length = input.tellg();
        if (length < 0)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = L"Could not determine snapshot file size.";
            }
            return false;
        }
        input.seekg(0, std::ios::beg);

        std::string text(static_cast<std::size_t>(length), '\0');
        if (!text.empty())
        {
            input.read(text.data(), static_cast<std::streamsize>(text.size()));
            if (input.gcount() != static_cast<std::streamsize>(text.size()))
            {
                if (errorMessage != nullptr)
                {
                    *errorMessage = L"Could not read the complete snapshot file.";
                }
                return false;
            }
        }

        JsonValue root;
        std::wstring parseError;
        JsonParser parser(text);
        if (!parser.Parse(root, parseError) || root.type != JsonValue::Type::Object)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = parseError.empty() ? L"Malformed saved snapshot." : parseError;
            }
            return false;
        }

        const std::wstring format = StringMember(root, L"format");
        if (format != GlassPaneSnapshotFormat)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = L"Unsupported snapshot format.";
            }
            return false;
        }

        const JsonValue* schemaVersionValue = ObjectMember(root, L"schema_version");
        if (schemaVersionValue == nullptr ||
            schemaVersionValue->type != JsonValue::Type::Number ||
            !std::isfinite(schemaVersionValue->numberValue) ||
            std::floor(schemaVersionValue->numberValue) != schemaVersionValue->numberValue ||
            schemaVersionValue->numberValue < 0.0 ||
            schemaVersionValue->numberValue > static_cast<double>((std::numeric_limits<int>::max)()))
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = L"Snapshot schema version must be a non-negative integer.";
            }
            return false;
        }
        const int schemaVersion = static_cast<int>(schemaVersionValue->numberValue);
        if (schemaVersion < GlassPaneSnapshotLegacySchemaVersion ||
            schemaVersion > GlassPaneSnapshotSchemaVersion)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = L"Unsupported snapshot schema version.";
            }
            return false;
        }

        std::uint32_t persistedTriageModelVersion = 0;
        if (schemaVersion >= GlassPaneSnapshotTriageSchemaVersion)
        {
            std::wstring triageVersionError;
            if (!ReadRequiredTriageUInt32(
                    root,
                    L"triage_model_version",
                    persistedTriageModelVersion,
                    triageVersionError) ||
                persistedTriageModelVersion !=
                    Core::PersistedTriageModelVersion)
            {
                if (errorMessage != nullptr)
                {
                    *errorMessage =
                        persistedTriageModelVersion == 0
                            ? (triageVersionError.empty()
                                ? L"Saved snapshot has an invalid triage_model_version."
                                : triageVersionError)
                            : L"Unsupported persisted triage model version.";
                }
                return false;
            }
        }

        SavedSnapshotDocument loaded;
        loaded.metadata.schemaVersion = schemaVersion;
        loaded.metadata.format = format;
        loaded.metadata.glassPaneVersion = StringMember(root, L"glasspane_version");
        loaded.metadata.capturedAt = StringMember(root, L"captured_at");
        loaded.metadata.hostname = StringMember(root, L"hostname");
        loaded.metadata.currentUser = StringMember(root, L"current_user");
        loaded.metadata.osBuild = StringMember(root, L"os_build");
        loaded.metadata.evidenceMode = StringMember(root, L"evidence_mode");
        if (loaded.metadata.evidenceMode.empty())
        {
            loaded.metadata.evidenceMode = schemaVersion == GlassPaneSnapshotLegacySchemaVersion
                ? L"legacy"
                : L"default";
        }
        loaded.metadata.sourcePath = filePath;
        loaded.metadata.selectedPid = UInt32Member(root, L"selected_pid");
        loaded.networkLoaded = BoolMember(root, L"network_loaded");
        loaded.network.success = loaded.networkLoaded;
        loaded.network.statusMessage = StringMember(root, L"network_status_message");

        if (const JsonValue* intel = ObjectMember(root, L"network_intelligence");
            intel != nullptr && intel->type == JsonValue::Type::Object)
        {
            loaded.networkIntel.loaded = BoolMember(*intel, L"loaded");
            loaded.networkIntel.feedName = StringMember(*intel, L"feed_name");
            loaded.networkIntel.schemaVersion = IntMember(*intel, L"schema_version");
            loaded.networkIntel.generatedAt = StringMember(*intel, L"generated_at");
            loaded.networkIntel.expiresAt = StringMember(*intel, L"expires_at");
            loaded.networkIntel.indicatorCount = static_cast<std::size_t>(UInt32Member(*intel, L"indicator_count"));
            loaded.networkIntel.source = StringMember(*intel, L"source");
            loaded.networkIntel.status = StringMember(*intel, L"status");
            loaded.networkIntel.localFeedSha256 = StringMember(*intel, L"local_feed_sha256");
        }

        if (schemaVersion >= GlassPaneSnapshotServiceContextSchemaVersion)
        {
            const JsonValue* serviceContext = ObjectMember(root, L"service_context");
            if (serviceContext == nullptr)
            {
                if (errorMessage != nullptr)
                {
                    *errorMessage = L"Snapshot schema 3 or newer is missing service_context.";
                }
                return false;
            }

            std::wstring serviceError;
            if (!ParseServiceContext(*serviceContext, loaded.serviceContext, serviceError))
            {
                if (errorMessage != nullptr)
                {
                    *errorMessage = serviceError.empty()
                        ? L"Malformed service_context in saved snapshot."
                        : serviceError;
                }
                return false;
            }
        }

        const JsonValue* processes = ObjectMember(root, L"processes");
        if (processes == nullptr || processes->type != JsonValue::Type::Array)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = L"Saved snapshot is missing the process array.";
            }
            return false;
        }
        if (schemaVersion >= GlassPaneSnapshotTriageSchemaVersion &&
            processes->arrayValue.size() > SnapshotMaxProcesses)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = L"Saved-snapshot process array exceeds its retained-record cap.";
            }
            return false;
        }

        loaded.snapshot.processes.reserve(processes->arrayValue.size());
        for (const JsonValue& process : processes->arrayValue)
        {
            if (process.type != JsonValue::Type::Object)
            {
                if (schemaVersion >= GlassPaneSnapshotTriageSchemaVersion)
                {
                    if (errorMessage != nullptr)
                    {
                        *errorMessage = L"Saved-snapshot process entries must be objects.";
                    }
                    return false;
                }
                continue;
            }
            loaded.snapshot.processes.push_back(ParseProcess(process, schemaVersion));
        }
        if (schemaVersion >= GlassPaneSnapshotNativeEvidenceSchemaVersion)
        {
            if (const JsonValue* historicalEvidence =
                    ObjectMember(root, L"historical_legacy_evidence");
                historicalEvidence != nullptr)
            {
                std::wstring historicalEvidenceError;
                if (!ParseHistoricalLegacyEvidenceContext(
                        *historicalEvidence,
                        loaded.snapshot,
                        historicalEvidenceError))
                {
                    if (errorMessage != nullptr)
                    {
                        *errorMessage = historicalEvidenceError.empty()
                            ? L"Malformed historical_legacy_evidence in saved snapshot."
                            : historicalEvidenceError;
                    }
                    return false;
                }
            }
        }
        Core::BuildProcessTree(loaded.snapshot);

        if (schemaVersion >= GlassPaneSnapshotTriageSchemaVersion)
        {
            const JsonValue* triageContext =
                ObjectMember(root, L"triage_context");
            std::wstring triageError;
            if (triageContext == nullptr ||
                !ParsePersistedTriageContext(
                    *triageContext,
                    persistedTriageModelVersion,
                    schemaVersion < GlassPaneSnapshotNativeEvidenceSchemaVersion,
                    loaded.triageContext,
                    triageError) ||
                !ValidateTriageContextForSnapshot(
                    loaded.triageContext,
                    loaded.snapshot,
                    loaded.metadata.selectedPid,
                    schemaVersion < GlassPaneSnapshotNativeEvidenceSchemaVersion,
                    triageError))
            {
                if (errorMessage != nullptr)
                {
                    *errorMessage = triageError.empty()
                        ? L"Saved snapshot is missing triage_context."
                        : triageError;
                }
                return false;
            }
        }

        if (schemaVersion >= GlassPaneSnapshotNativeEvidenceSchemaVersion)
        {
            const JsonValue* nativeEvidence =
                ObjectMember(root, L"native_source_evidence");
            std::wstring nativeEvidenceError;
            if (nativeEvidence == nullptr ||
                !ParseNativeSourceEvidenceContext(
                    *nativeEvidence,
                    loaded.nativeSourceEvidence,
                    nativeEvidenceError) ||
                !ValidateNativeSourceEvidenceForSnapshot(
                    loaded.nativeSourceEvidence,
                    loaded.snapshot,
                    loaded.metadata.selectedPid,
                    loaded.triageContext,
                    nativeEvidenceError))
            {
                if (errorMessage != nullptr)
                {
                    *errorMessage = nativeEvidenceError.empty()
                        ? L"Schema 5 snapshot is missing native_source_evidence."
                        : nativeEvidenceError;
                }
                return false;
            }
            loaded.nativeSourceEvidenceCaptured = true;
        }

        const JsonValue* networkConnections = ObjectMember(root, L"network_connections");
        if (networkConnections != nullptr && networkConnections->type == JsonValue::Type::Array)
        {
            loaded.network.connections.reserve(networkConnections->arrayValue.size());
            for (const JsonValue& connection : networkConnections->arrayValue)
            {
                if (connection.type == JsonValue::Type::Object)
                {
                    loaded.network.connections.push_back(ParseNetworkConnection(connection));
                }
            }
        }

        const JsonValue* networkIntelMatches = ObjectMember(root, L"network_intelligence_matches");
        if (networkIntelMatches != nullptr && networkIntelMatches->type == JsonValue::Type::Array)
        {
            loaded.networkIndicatorMatches.reserve(networkIntelMatches->arrayValue.size());
            for (const JsonValue& match : networkIntelMatches->arrayValue)
            {
                if (match.type == JsonValue::Type::Object)
                {
                    loaded.networkIndicatorMatches.push_back(ParseNetworkIndicatorMatch(match));
                }
            }
        }

        if (const JsonValue* processEvidence = ObjectMember(root, L"process_evidence");
            processEvidence != nullptr && processEvidence->type == JsonValue::Type::Object)
        {
            loaded.processEvidence.reserve(processEvidence->objectValue.size());
            for (const auto& [pidText, evidenceValue] : processEvidence->objectValue)
            {
                if (evidenceValue.type != JsonValue::Type::Object)
                {
                    continue;
                }

                ProcessEvidenceSnapshot evidence = ParseProcessEvidence(evidenceValue);
                if (evidence.pid == 0)
                {
                    evidence.pid = static_cast<std::uint32_t>(ParseUInt64String(pidText));
                }
                loaded.processEvidence.push_back(std::move(evidence));
            }
        }

        document = std::move(loaded);
        return true;
    }

    bool ExportNetworkIntelligenceMetadataJson(
        const NetworkIntelligenceSnapshotMetadata& metadata,
        const std::wstring& filePath,
        std::wstring* errorMessage)
    {
        std::ostringstream output;
        output << "{\n";
        output << "  \"loaded\": " << (metadata.loaded ? "true" : "false") << ",\n";
        output << "  \"feed_name\": ";
        WriteJsonString(output, metadata.feedName);
        output << ",\n";
        output << "  \"schema_version\": " << metadata.schemaVersion << ",\n";
        output << "  \"generated_at\": ";
        WriteJsonString(output, metadata.generatedAt);
        output << ",\n";
        output << "  \"expires_at\": ";
        WriteJsonString(output, metadata.expiresAt);
        output << ",\n";
        output << "  \"indicator_count\": " << metadata.indicatorCount << ",\n";
        output << "  \"loaded_from\": ";
        WriteJsonString(output, metadata.source);
        output << ",\n";
        output << "  \"status\": ";
        WriteJsonString(output, metadata.status);
        output << ",\n";
        output << "  \"local_feed_sha256\": ";
        WriteJsonString(output, metadata.localFeedSha256);
        output << "\n}\n";
        return WriteAllText(filePath, output.str(), errorMessage);
    }

    bool WriteEvidencePackageReadme(
        const std::wstring& filePath,
        const std::wstring& generatedAt,
        const std::wstring& glassPaneVersion,
        bool generatedFromLoadedSnapshot,
        const std::vector<std::wstring>& packageFiles,
        std::wstring* errorMessage)
    {
        std::ostringstream output;
        output << "GlassPane Evidence Package\n";
        output << "==========================\n\n";
        output << "Generated by GlassPane " << WideToUtf8(glassPaneVersion) << "\n";
        output << "Generated at: " << WideToUtf8(generatedAt) << "\n\n";
        output << "Authoritative triage model: "
            << Core::PersistedTriageModelVersion << "\n\n";
        output << "Package source: " <<
            (generatedFromLoadedSnapshot ? "loaded saved snapshot / offline viewer" : "live endpoint view") << "\n\n";
        output << "This package contains local evidence preserved by GlassPane for review or escalation.\n";
        output << "The schema-5 saved snapshot contains captured authoritative triage summaries, native source evidence for the captured selected process, process relationships, available network and service context, and bounded process metadata where collection was possible.\n";
        output << "Default evidence packages use the portable bounded snapshot mode. Deep lists such as handles, memory regions, module rows, and thread rows are summarized or capped.\n";
        output << "Collection status is recorded per process and evidence type, so access denied, process exited, partial, not-attempted, and failed states are expected on some endpoints.\n";
        output << "Memory region metadata does not include memory contents. Packet contents are not captured.\n";
        output << "GlassPane is read-only and non-remediating. It does not kill, inject into, tamper with, or modify processes.\n";
        output << "Network Intelligence matches are context from a local indicator feed, not proof of compromise.\n\n";
        output << "Package contents:\n";
        for (const std::wstring& file : packageFiles)
        {
            output << "- " << WideToUtf8(file) << "\n";
        }
        output << "\nNotes:\n";
        output << "- Snapshot differences and source-evidence records are evidence worth reviewing, not proof of malicious activity.\n";
        output << "- No endpoint data was uploaded by this export action.\n";
        return WriteAllText(filePath, output.str(), errorMessage);
    }

    bool ComputeFileSha256Hex(
        const std::wstring& filePath,
        std::string& sha256,
        std::wstring* errorMessage)
    {
        std::ifstream input(std::filesystem::path(filePath), std::ios::binary);
        if (!input)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = L"Could not open file for hashing.";
            }
            return false;
        }

        BCRYPT_ALG_HANDLE algorithm = nullptr;
        BCRYPT_HASH_HANDLE hash = nullptr;
        std::vector<unsigned char> hashObject;
        std::array<unsigned char, 32> digest = {};
        bool success = false;

        do
        {
            if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
            {
                break;
            }
            DWORD objectLength = 0;
            DWORD dataLength = 0;
            if (BCryptGetProperty(
                    algorithm,
                    BCRYPT_OBJECT_LENGTH,
                    reinterpret_cast<PUCHAR>(&objectLength),
                    sizeof(objectLength),
                    &dataLength,
                    0) != 0)
            {
                break;
            }
            hashObject.resize(objectLength);
            if (BCryptCreateHash(
                    algorithm,
                    &hash,
                    hashObject.data(),
                    static_cast<ULONG>(hashObject.size()),
                    nullptr,
                    0,
                    0) != 0)
            {
                break;
            }

            std::array<char, 64 * 1024> buffer = {};
            bool hashDataOk = true;
            while (input)
            {
                input.read(buffer.data(), buffer.size());
                const std::streamsize read = input.gcount();
                if (read <= 0)
                {
                    break;
                }
                if (BCryptHashData(hash, reinterpret_cast<PUCHAR>(buffer.data()), static_cast<ULONG>(read), 0) != 0)
                {
                    hashDataOk = false;
                    break;
                }
            }
            if (!hashDataOk || input.bad())
            {
                break;
            }
            if (BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) != 0)
            {
                break;
            }

            static constexpr char Hex[] = "0123456789abcdef";
            sha256.clear();
            sha256.reserve(digest.size() * 2);
            for (unsigned char byte : digest)
            {
                sha256.push_back(Hex[(byte >> 4) & 0x0f]);
                sha256.push_back(Hex[byte & 0x0f]);
            }
            success = true;
        } while (false);

        if (hash != nullptr)
        {
            BCryptDestroyHash(hash);
        }
        if (algorithm != nullptr)
        {
            BCryptCloseAlgorithmProvider(algorithm, 0);
        }

        if (!success && errorMessage != nullptr)
        {
            *errorMessage = L"Could not compute SHA256 hash.";
        }
        return success;
    }

    bool WriteSha256Manifest(
        const std::wstring& packageDirectory,
        const std::vector<std::wstring>& relativeFiles,
        const std::wstring& manifestFileName,
        std::wstring* errorMessage)
    {
        const std::filesystem::path base(packageDirectory);
        std::ostringstream output;
        for (const std::wstring& relativeFile : relativeFiles)
        {
            if (relativeFile == manifestFileName)
            {
                continue;
            }
            std::string hash;
            if (!ComputeFileSha256Hex((base / relativeFile).wstring(), hash, errorMessage))
            {
                return false;
            }
            output << hash << "  " << WideToUtf8(relativeFile) << "\n";
        }
        return WriteAllText((base / manifestFileName).wstring(), output.str(), errorMessage);
    }
}
