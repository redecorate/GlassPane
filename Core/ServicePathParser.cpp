#include "ServicePathParser.h"

#include <Windows.h>

#include <string_view>
#include <utility>
#include <vector>

namespace GlassPane::Core
{
    namespace
    {
        constexpr std::size_t MaxArgumentTokensForGroupParsing = 128;

        bool IsWhitespace(wchar_t character)
        {
            switch (character)
            {
            case L' ':
            case L'\t':
            case L'\r':
            case L'\n':
            case L'\v':
            case L'\f':
                return true;
            default:
                return false;
            }
        }

        std::wstring_view Trim(std::wstring_view text)
        {
            std::size_t first = 0;
            while (first < text.size() && IsWhitespace(text[first]))
            {
                ++first;
            }

            std::size_t last = text.size();
            while (last > first && IsWhitespace(text[last - 1]))
            {
                --last;
            }
            return text.substr(first, last - first);
        }

        bool ContainsEnvironmentReference(std::wstring_view text)
        {
            std::size_t searchFrom = 0;
            while (searchFrom < text.size())
            {
                const std::size_t opening = text.find(L'%', searchFrom);
                if (opening == std::wstring_view::npos)
                {
                    return false;
                }

                const std::size_t closing = text.find(L'%', opening + 1);
                if (closing == std::wstring_view::npos)
                {
                    return false;
                }
                if (closing > opening + 1)
                {
                    return true;
                }
                searchFrom = closing + 1;
            }
            return false;
        }

        bool IsAsciiLetter(wchar_t character)
        {
            return (character >= L'A' && character <= L'Z') ||
                   (character >= L'a' && character <= L'z');
        }

        bool IsDirectorySeparator(wchar_t character)
        {
            return character == L'\\' || character == L'/';
        }

        bool IsAbsolutePath(std::wstring_view path)
        {
            if (path.size() >= 3 &&
                IsAsciiLetter(path[0]) &&
                path[1] == L':' &&
                IsDirectorySeparator(path[2]))
            {
                return path.size() > 3 && !IsDirectorySeparator(path.back());
            }

            if (path.size() < 2 ||
                !IsDirectorySeparator(path[0]) ||
                !IsDirectorySeparator(path[1]))
            {
                return false;
            }

            const std::size_t firstComponentEnd = path.find_first_of(L"\\/", 2);
            if (firstComponentEnd == std::wstring_view::npos || firstComponentEnd == 2)
            {
                return false;
            }

            const std::size_t secondComponentStart = firstComponentEnd + 1;
            const std::size_t secondComponentEnd = path.find_first_of(L"\\/", secondComponentStart);
            return secondComponentEnd != std::wstring_view::npos &&
                   secondComponentEnd > secondComponentStart &&
                   secondComponentEnd + 1 < path.size() &&
                   !IsDirectorySeparator(path.back());
        }

        wchar_t ToLowerAscii(wchar_t character)
        {
            if (character >= L'A' && character <= L'Z')
            {
                return static_cast<wchar_t>(character - L'A' + L'a');
            }
            return character;
        }

        bool EqualsAsciiInsensitive(std::wstring_view left, std::wstring_view right)
        {
            if (left.size() != right.size())
            {
                return false;
            }

            for (std::size_t index = 0; index < left.size(); ++index)
            {
                if (ToLowerAscii(left[index]) != ToLowerAscii(right[index]))
                {
                    return false;
                }
            }
            return true;
        }

        bool EndsWithAsciiInsensitive(std::wstring_view value, std::wstring_view suffix)
        {
            if (value.size() < suffix.size())
            {
                return false;
            }
            return EqualsAsciiInsensitive(value.substr(value.size() - suffix.size()), suffix);
        }

        bool HasDefensibleUnquotedBoundary(std::wstring_view token)
        {
            return EndsWithAsciiInsensitive(token, L".exe") ||
                   EndsWithAsciiInsensitive(token, L".com") ||
                   EndsWithAsciiInsensitive(token, L".sys");
        }

        bool TokenizeArguments(std::wstring_view arguments, std::vector<std::wstring>& tokens)
        {
            std::size_t position = 0;
            while (position < arguments.size())
            {
                while (position < arguments.size() && IsWhitespace(arguments[position]))
                {
                    ++position;
                }
                if (position == arguments.size())
                {
                    break;
                }
                if (tokens.size() == MaxArgumentTokensForGroupParsing)
                {
                    return false;
                }

                if (arguments[position] == L'"')
                {
                    const std::size_t closing = arguments.find(L'"', position + 1);
                    if (closing == std::wstring_view::npos)
                    {
                        return false;
                    }

                    tokens.emplace_back(arguments.substr(position + 1, closing - position - 1));
                    position = closing + 1;
                    if (position < arguments.size() && !IsWhitespace(arguments[position]))
                    {
                        return false;
                    }
                }
                else
                {
                    const std::size_t start = position;
                    while (position < arguments.size() && !IsWhitespace(arguments[position]))
                    {
                        if (arguments[position] == L'"')
                        {
                            return false;
                        }
                        ++position;
                    }
                    tokens.emplace_back(arguments.substr(start, position - start));
                }
            }
            return true;
        }

        bool IsSvchostExecutable(std::wstring_view executablePath)
        {
            const std::size_t separator = executablePath.find_last_of(L"\\/");
            const std::wstring_view basename = separator == std::wstring_view::npos
                ? executablePath
                : executablePath.substr(separator + 1);
            return EqualsAsciiInsensitive(basename, L"svchost.exe");
        }

        void ExtractSvchostGroup(
            ServiceImagePathParseResult& result,
            std::wstring_view argumentText)
        {
            if (result.confidence != ServicePathConfidence::High ||
                !IsSvchostExecutable(result.executablePath))
            {
                return;
            }

            std::vector<std::wstring> tokens;
            if (!TokenizeArguments(argumentText, tokens))
            {
                return;
            }

            const std::wstring* group = nullptr;
            for (std::size_t index = 0; index < tokens.size(); ++index)
            {
                if (!EqualsAsciiInsensitive(tokens[index], L"-k"))
                {
                    continue;
                }
                if (group != nullptr || index + 1 >= tokens.size() || tokens[index + 1].empty())
                {
                    return;
                }
                if (tokens[index + 1].front() == L'-' || tokens[index + 1].front() == L'/')
                {
                    return;
                }
                group = &tokens[index + 1];
            }

            if (group == nullptr)
            {
                return;
            }
            if (group->size() > ServiceSvchostGroupMaxCharacters)
            {
                result.svchostGroupTruncated = true;
                return;
            }
            result.svchostGroup = *group;
        }

        ServiceEnvironmentExpansionResult ExpandCurrentProcessEnvironment(std::wstring_view input)
        {
            const std::wstring nullTerminatedInput(input);
            const DWORD requiredSize = ExpandEnvironmentStringsW(
                nullTerminatedInput.c_str(),
                nullptr,
                0);
            if (requiredSize == 0)
            {
                return { ServiceEnvironmentExpansionStatus::Failed, {} };
            }
            if (static_cast<std::size_t>(requiredSize) >
                ServiceEnvironmentExpansionHardLimitCharacters + 1)
            {
                return { ServiceEnvironmentExpansionStatus::OutputTooLong, {} };
            }

            std::wstring buffer(static_cast<std::size_t>(requiredSize), L'\0');
            const DWORD writtenSize = ExpandEnvironmentStringsW(
                nullTerminatedInput.c_str(),
                buffer.data(),
                requiredSize);
            if (writtenSize == 0)
            {
                return { ServiceEnvironmentExpansionStatus::Failed, {} };
            }
            if (writtenSize > requiredSize ||
                static_cast<std::size_t>(writtenSize) >
                    ServiceEnvironmentExpansionHardLimitCharacters + 1)
            {
                return { ServiceEnvironmentExpansionStatus::OutputTooLong, {} };
            }

            buffer.resize(static_cast<std::size_t>(writtenSize - 1));
            return { ServiceEnvironmentExpansionStatus::Success, std::move(buffer) };
        }

        void SetRelativeResult(ServiceImagePathParseResult& result)
        {
            result.status = ServicePathParseStatus::RelativeExecutable;
            result.confidence = ServicePathConfidence::Low;
            result.message = L"ImagePath does not identify a defensible absolute executable path.";
        }
    }

    ServiceImagePathParseResult ParseServiceImagePath(const std::wstring& imagePath)
    {
        return ParseServiceImagePath(imagePath, ExpandCurrentProcessEnvironment);
    }

    ServiceImagePathParseResult ParseServiceImagePath(
        const std::wstring& imagePath,
        const ServiceEnvironmentExpander& environmentExpander)
    {
        ServiceImagePathParseResult result;
        if (imagePath.size() > ServiceImagePathMaxCharacters)
        {
            result.rawImagePath.assign(imagePath.data(), ServiceImagePathMaxCharacters);
            result.rawInputTruncated = true;
            result.status = ServicePathParseStatus::InputTruncated;
            result.message = L"ImagePath exceeded the 4096-character input cap; parsing was not attempted.";
            return result;
        }

        result.rawImagePath = imagePath;
        if (ContainsEnvironmentReference(result.rawImagePath))
        {
            if (!environmentExpander)
            {
                result.status = ServicePathParseStatus::ExpansionFailed;
                result.message = L"Environment expansion failed; parsing was not attempted.";
                return result;
            }

            ServiceEnvironmentExpansionResult expansion = environmentExpander(result.rawImagePath);
            if (expansion.status == ServiceEnvironmentExpansionStatus::Failed)
            {
                result.status = ServicePathParseStatus::ExpansionFailed;
                result.message = L"Environment expansion failed; parsing was not attempted.";
                return result;
            }
            if (expansion.status == ServiceEnvironmentExpansionStatus::OutputTooLong ||
                expansion.expandedValue.size() > ServiceImagePathMaxCharacters)
            {
                result.expandedImagePath.assign(
                    expansion.expandedValue.data(),
                    expansion.expandedValue.size() < ServiceImagePathMaxCharacters
                        ? expansion.expandedValue.size()
                        : ServiceImagePathMaxCharacters);
                result.expandedInputTruncated = true;
                result.status = ServicePathParseStatus::InputTruncated;
                result.message = L"Expanded ImagePath exceeded the 4096-character cap; parsing was not attempted.";
                return result;
            }
            result.expandedImagePath = std::move(expansion.expandedValue);
        }
        else
        {
            result.expandedImagePath = result.rawImagePath;
        }

        if (ContainsEnvironmentReference(result.expandedImagePath))
        {
            result.status = ServicePathParseStatus::UnresolvedEnvironment;
            result.message = L"ImagePath contains an unresolved environment-variable reference.";
            return result;
        }

        const std::wstring_view working = Trim(result.expandedImagePath);
        if (working.empty())
        {
            result.status = ServicePathParseStatus::Empty;
            result.message = L"ImagePath is empty.";
            return result;
        }

        std::wstring_view executable;
        std::wstring_view argumentText;
        if (working.front() == L'"')
        {
            const std::size_t closingQuote = working.find(L'"', 1);
            if (closingQuote == std::wstring_view::npos)
            {
                result.status = ServicePathParseStatus::UnmatchedQuote;
                result.message = L"ImagePath begins with an unmatched quote.";
                return result;
            }

            executable = working.substr(1, closingQuote - 1);
            argumentText = working.substr(closingQuote + 1);
            if (!argumentText.empty() && !IsWhitespace(argumentText.front()))
            {
                result.status = ServicePathParseStatus::UnmatchedQuote;
                result.message = L"Quoted executable text is not followed by whitespace or end of input.";
                return result;
            }
            if (!IsAbsolutePath(executable))
            {
                SetRelativeResult(result);
                return result;
            }

            result.executablePath = executable;
            result.status = ServicePathParseStatus::ParsedQuoted;
            result.confidence = ServicePathConfidence::High;
            result.message = L"Parsed an absolute executable path from quoted ImagePath text.";
        }
        else
        {
            std::size_t firstWhitespace = 0;
            while (firstWhitespace < working.size() && !IsWhitespace(working[firstWhitespace]))
            {
                ++firstWhitespace;
            }

            executable = working.substr(0, firstWhitespace);
            argumentText = working.substr(firstWhitespace);
            if (executable.find(L'"') != std::wstring_view::npos)
            {
                result.status = ServicePathParseStatus::AmbiguousUnquoted;
                result.message = L"Unquoted ImagePath contains an unexpected quote before its argument boundary.";
                return result;
            }
            if (!IsAbsolutePath(executable))
            {
                SetRelativeResult(result);
                return result;
            }
            if (firstWhitespace != working.size() && !HasDefensibleUnquotedBoundary(executable))
            {
                result.status = ServicePathParseStatus::AmbiguousUnquoted;
                result.message = L"Unquoted ImagePath has no defensible executable boundary before whitespace.";
                return result;
            }

            result.executablePath = executable;
            result.status = ServicePathParseStatus::ParsedUnquoted;
            result.confidence = ServicePathConfidence::High;
            result.message = L"Parsed an absolute executable path with an unambiguous boundary.";
        }

        ExtractSvchostGroup(result, argumentText);
        return result;
    }
}
