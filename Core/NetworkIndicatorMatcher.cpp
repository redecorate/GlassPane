#include "NetworkIndicatorMatcher.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <ctime>
#include <cwctype>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <unordered_map>

namespace GlassPane::Core
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

        std::wstring ToLower(std::wstring value)
        {
            std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) {
                return static_cast<wchar_t>(std::towlower(ch));
            });
            return value;
        }

        std::wstring Trim(const std::wstring& value)
        {
            const auto first = std::find_if_not(value.begin(), value.end(), [](wchar_t ch) {
                return std::iswspace(ch) != 0;
            });
            const auto last = std::find_if_not(value.rbegin(), value.rend(), [](wchar_t ch) {
                return std::iswspace(ch) != 0;
            }).base();
            if (first >= last)
            {
                return {};
            }
            return std::wstring(first, last);
        }

        std::wstring CurrentTimestampUtc()
        {
            const std::time_t now = std::time(nullptr);
            std::tm utc = {};
            gmtime_s(&utc, &now);
            wchar_t buffer[32] = {};
            swprintf_s(
                buffer,
                L"%04d-%02d-%02dT%02d:%02d:%02dZ",
                utc.tm_year + 1900,
                utc.tm_mon + 1,
                utc.tm_mday,
                utc.tm_hour,
                utc.tm_min,
                utc.tm_sec);
            return buffer;
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
                    error = L"Unexpected trailing content in JSON feed.";
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

            bool ParseValue(JsonValue& value, std::wstring& error)
            {
                SkipWhitespace();
                if (position_ >= text_.size())
                {
                    error = L"Unexpected end of JSON feed.";
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

                error = L"Unsupported JSON value in feed.";
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
                    if (position_ >= text_.size() || text_[position_] != ':')
                    {
                        error = L"Expected ':' in JSON object.";
                        return false;
                    }
                    ++position_;

                    JsonValue member;
                    if (!ParseValue(member, error))
                    {
                        return false;
                    }
                    value.objectValue[std::move(key)] = std::move(member);

                    SkipWhitespace();
                    if (position_ < text_.size() && text_[position_] == ',')
                    {
                        ++position_;
                        SkipWhitespace();
                        continue;
                    }
                    if (position_ < text_.size() && text_[position_] == '}')
                    {
                        ++position_;
                        return true;
                    }

                    error = L"Expected ',' or '}' in JSON object.";
                    return false;
                }

                error = L"Unterminated JSON object.";
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
                    if (position_ < text_.size() && text_[position_] == ',')
                    {
                        ++position_;
                        SkipWhitespace();
                        continue;
                    }
                    if (position_ < text_.size() && text_[position_] == ']')
                    {
                        ++position_;
                        return true;
                    }

                    error = L"Expected ',' or ']' in JSON array.";
                    return false;
                }

                error = L"Unterminated JSON array.";
                return false;
            }

            bool ParseString(std::wstring& value, std::wstring& error)
            {
                if (position_ >= text_.size() || text_[position_] != '"')
                {
                    error = L"Expected JSON string.";
                    return false;
                }
                ++position_;

                value.clear();
                while (position_ < text_.size())
                {
                    const char ch = text_[position_++];
                    if (ch == '"')
                    {
                        return true;
                    }
                    if (ch != '\\')
                    {
                        value.push_back(static_cast<wchar_t>(static_cast<unsigned char>(ch)));
                        continue;
                    }

                    if (position_ >= text_.size())
                    {
                        error = L"Unterminated JSON string escape.";
                        return false;
                    }
                    const char escaped = text_[position_++];
                    switch (escaped)
                    {
                    case '"':
                    case '\\':
                    case '/':
                        value.push_back(static_cast<wchar_t>(escaped));
                        break;
                    case 'b':
                        value.push_back(L'\b');
                        break;
                    case 'f':
                        value.push_back(L'\f');
                        break;
                    case 'n':
                        value.push_back(L'\n');
                        break;
                    case 'r':
                        value.push_back(L'\r');
                        break;
                    case 't':
                        value.push_back(L'\t');
                        break;
                    case 'u':
                    {
                        if (position_ + 4 > text_.size())
                        {
                            error = L"Invalid JSON unicode escape.";
                            return false;
                        }
                        unsigned int codepoint = 0;
                        for (int index = 0; index < 4; ++index)
                        {
                            const char hex = text_[position_++];
                            codepoint <<= 4;
                            if (hex >= '0' && hex <= '9')
                            {
                                codepoint += static_cast<unsigned int>(hex - '0');
                            }
                            else if (hex >= 'a' && hex <= 'f')
                            {
                                codepoint += static_cast<unsigned int>(hex - 'a' + 10);
                            }
                            else if (hex >= 'A' && hex <= 'F')
                            {
                                codepoint += static_cast<unsigned int>(hex - 'A' + 10);
                            }
                            else
                            {
                                error = L"Invalid JSON unicode escape.";
                                return false;
                            }
                        }
                        value.push_back(static_cast<wchar_t>(codepoint));
                        break;
                    }
                    default:
                        error = L"Unsupported JSON string escape.";
                        return false;
                    }
                }

                error = L"Unterminated JSON string.";
                return false;
            }

            bool ParseNumber(double& value, std::wstring& error)
            {
                const std::size_t start = position_;
                if (position_ < text_.size() && text_[position_] == '-')
                {
                    ++position_;
                }
                while (position_ < text_.size() &&
                    std::isdigit(static_cast<unsigned char>(text_[position_])) != 0)
                {
                    ++position_;
                }
                if (position_ < text_.size() && text_[position_] == '.')
                {
                    ++position_;
                    while (position_ < text_.size() &&
                        std::isdigit(static_cast<unsigned char>(text_[position_])) != 0)
                    {
                        ++position_;
                    }
                }

                try
                {
                    value = std::stod(text_.substr(start, position_ - start));
                }
                catch (...)
                {
                    error = L"Invalid JSON number.";
                    return false;
                }
                return true;
            }

            bool ConsumeLiteral(const char* literal)
            {
                const std::size_t length = std::strlen(literal);
                if (text_.compare(position_, length, literal) != 0)
                {
                    return false;
                }
                position_ += length;
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
            if (member == nullptr || member->type != JsonValue::Type::String)
            {
                return {};
            }
            return Trim(member->stringValue);
        }

        int NumberMember(const JsonValue& value, const wchar_t* name)
        {
            const JsonValue* member = ObjectMember(value, name);
            if (member == nullptr || member->type != JsonValue::Type::Number)
            {
                return 0;
            }
            return static_cast<int>(member->numberValue);
        }

        bool IsSupportedIpIndicator(const NetworkIndicator& indicator)
        {
            return ToLower(indicator.type) == L"ip" && !indicator.normalizedValue.empty();
        }
    }

    std::wstring NormalizeIpIndicatorValue(const std::wstring& value)
    {
        const std::wstring trimmed = Trim(value);
        if (trimmed.empty())
        {
            return {};
        }

        std::wistringstream stream(trimmed);
        std::wstring part;
        std::vector<int> octets;
        while (std::getline(stream, part, L'.'))
        {
            if (part.empty() || part.size() > 3)
            {
                return {};
            }
            int number = 0;
            for (wchar_t ch : part)
            {
                if (ch < L'0' || ch > L'9')
                {
                    return {};
                }
                number = number * 10 + static_cast<int>(ch - L'0');
            }
            if (number < 0 || number > 255)
            {
                return {};
            }
            octets.push_back(number);
        }

        if (octets.size() != 4)
        {
            return {};
        }

        return std::to_wstring(octets[0]) + L"." +
            std::to_wstring(octets[1]) + L"." +
            std::to_wstring(octets[2]) + L"." +
            std::to_wstring(octets[3]);
    }

    NetworkIndicatorLoadResult LoadNetworkIndicatorFeedFromFile(const std::wstring& filePath)
    {
        NetworkIndicatorLoadResult result;
        result.feed.metadata.sourcePath = filePath;
        result.feed.metadata.loadedAt = CurrentTimestampUtc();

        std::ifstream input(filePath, std::ios::binary);
        if (!input)
        {
            result.missing = true;
            result.statusMessage = L"Intel feed missing.";
            result.feed.metadata.loadError = result.statusMessage;
            return result;
        }

        std::ostringstream buffer;
        buffer << input.rdbuf();
        const std::string text = buffer.str();

        JsonValue root;
        std::wstring parseError;
        JsonParser parser(text);
        if (!parser.Parse(root, parseError) || root.type != JsonValue::Type::Object)
        {
            result.malformed = true;
            result.statusMessage = parseError.empty() ? L"Malformed network indicator feed." : parseError;
            result.feed.metadata.loadError = result.statusMessage;
            return result;
        }

        result.feed.metadata.feedName = StringMember(root, L"feed_name");
        result.feed.metadata.schemaVersion = NumberMember(root, L"schema_version");
        result.feed.metadata.generatedAt = StringMember(root, L"generated_at");
        result.feed.metadata.expiresAt = StringMember(root, L"expires_at");

        if (result.feed.metadata.schemaVersion != 1)
        {
            result.malformed = true;
            result.statusMessage = L"Unsupported network indicator feed schema version.";
            result.feed.metadata.loadError = result.statusMessage;
            return result;
        }

        const JsonValue* indicators = ObjectMember(root, L"indicators");
        if (indicators == nullptr || indicators->type != JsonValue::Type::Array)
        {
            result.malformed = true;
            result.statusMessage = L"Network indicator feed is missing an indicators array.";
            result.feed.metadata.loadError = result.statusMessage;
            return result;
        }

        for (const JsonValue& item : indicators->arrayValue)
        {
            if (item.type != JsonValue::Type::Object)
            {
                continue;
            }

            NetworkIndicator indicator;
            indicator.type = ToLower(StringMember(item, L"type"));
            indicator.value = StringMember(item, L"value");
            indicator.normalizedValue = NormalizeIpIndicatorValue(indicator.value);
            indicator.category = StringMember(item, L"category");
            indicator.severity = ToLower(StringMember(item, L"severity"));
            indicator.confidence = ToLower(StringMember(item, L"confidence"));
            indicator.source = StringMember(item, L"source");
            indicator.description = StringMember(item, L"description");
            indicator.firstSeen = StringMember(item, L"first_seen");
            indicator.lastSeen = StringMember(item, L"last_seen");

            if (indicator.severity.empty())
            {
                indicator.severity = L"info";
            }
            if (indicator.confidence.empty())
            {
                indicator.confidence = L"unknown";
            }
            if (IsSupportedIpIndicator(indicator))
            {
                result.feed.indicators.push_back(std::move(indicator));
            }
        }

        result.feed.loaded = true;
        result.feed.metadata.indicatorCount = result.feed.indicators.size();
        result.success = true;
        result.statusMessage = L"Network indicator feed loaded.";
        return result;
    }

    std::vector<NetworkIndicatorMatch> MatchNetworkIndicators(
        const std::vector<NetworkConnection>& connections,
        const NetworkIndicatorFeed& feed)
    {
        std::vector<NetworkIndicatorMatch> matches;
        if (!feed.loaded || feed.indicators.empty())
        {
            return matches;
        }

        std::unordered_map<std::wstring, std::vector<const NetworkIndicator*>> indicatorsByIp;
        for (const NetworkIndicator& indicator : feed.indicators)
        {
            if (IsSupportedIpIndicator(indicator))
            {
                indicatorsByIp[indicator.normalizedValue].push_back(&indicator);
            }
        }

        for (const NetworkConnection& connection : connections)
        {
            const std::wstring normalizedRemote = NormalizeIpIndicatorValue(connection.remoteAddress);
            if (normalizedRemote.empty())
            {
                continue;
            }

            const auto found = indicatorsByIp.find(normalizedRemote);
            if (found == indicatorsByIp.end())
            {
                continue;
            }

            for (const NetworkIndicator* indicator : found->second)
            {
                if (indicator == nullptr)
                {
                    continue;
                }
                matches.push_back({ connection, *indicator });
            }
        }

        return matches;
    }

    std::vector<NetworkIndicatorMatch> MatchNetworkIndicatorsForPid(
        const std::vector<NetworkConnection>& connections,
        const NetworkIndicatorFeed& feed,
        std::uint32_t pid)
    {
        std::vector<NetworkConnection> selectedConnections;
        selectedConnections.reserve(connections.size());
        for (const NetworkConnection& connection : connections)
        {
            if (connection.owningPid == pid)
            {
                selectedConnections.push_back(connection);
            }
        }
        return MatchNetworkIndicators(selectedConnections, feed);
    }
}
