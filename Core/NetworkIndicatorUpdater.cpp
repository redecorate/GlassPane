#include "NetworkIndicatorUpdater.h"

#include "NetworkIndicatorMatcher.h"

#include <Windows.h>
#include <bcrypt.h>
#include <winhttp.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <filesystem>
#include <functional>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace GlassPane::Core
{
    namespace
    {
        constexpr const wchar_t* NetworkIndicatorsJsonUrl =
            L"https://raw.githubusercontent.com/redecorate/GlassPane-NetworkIntelligence/refs/heads/main/feeds/network-indicators.json";
        constexpr const wchar_t* NetworkIndicatorsShaUrl =
            L"https://raw.githubusercontent.com/redecorate/GlassPane-NetworkIntelligence/refs/heads/main/feeds/network-indicators.sha256";
        constexpr const wchar_t* FeedJsonFileName = L"network-indicators.json";
        constexpr const wchar_t* FeedShaFileName = L"network-indicators.sha256";
        constexpr const wchar_t* FeedJsonTempFileName = L"network-indicators.json.tmp";
        constexpr const wchar_t* FeedShaTempFileName = L"network-indicators.sha256.tmp";
        constexpr std::size_t MaxDownloadBytes = 64 * 1024 * 1024;

        std::wstring LastErrorText(const wchar_t* prefix)
        {
            return std::wstring(prefix) + L" (Win32 error " + std::to_wstring(GetLastError()) + L")";
        }

        bool DeleteFileIfExists(const std::filesystem::path& path)
        {
            std::error_code error;
            if (!std::filesystem::exists(path, error))
            {
                return true;
            }
            std::filesystem::remove(path, error);
            return !error;
        }

        bool DownloadFileToPath(
            const wchar_t* url,
            const std::filesystem::path& destinationPath,
            std::size_t& bytesWritten,
            std::wstring& error)
        {
            bytesWritten = 0;

            URL_COMPONENTSW components = {};
            components.dwStructSize = sizeof(components);
            components.dwSchemeLength = static_cast<DWORD>(-1);
            components.dwHostNameLength = static_cast<DWORD>(-1);
            components.dwUrlPathLength = static_cast<DWORD>(-1);
            components.dwExtraInfoLength = static_cast<DWORD>(-1);

            if (!WinHttpCrackUrl(url, 0, 0, &components))
            {
                error = LastErrorText(L"Could not parse official feed URL");
                return false;
            }

            if (components.nScheme != INTERNET_SCHEME_HTTPS)
            {
                error = L"Official feed URL must use HTTPS.";
                return false;
            }

            std::wstring host(components.lpszHostName, components.dwHostNameLength);
            std::wstring path(components.lpszUrlPath, components.dwUrlPathLength);
            if (components.dwExtraInfoLength > 0)
            {
                path.append(components.lpszExtraInfo, components.dwExtraInfoLength);
            }

            HINTERNET session = WinHttpOpen(
                L"GlassPane Network Intelligence Updater/1.0",
                WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                WINHTTP_NO_PROXY_NAME,
                WINHTTP_NO_PROXY_BYPASS,
                0);
            if (session == nullptr)
            {
                error = LastErrorText(L"Could not initialize WinHTTP");
                return false;
            }

            bool success = false;
            HINTERNET connect = nullptr;
            HINTERNET request = nullptr;
            HANDLE output = INVALID_HANDLE_VALUE;

            do
            {
                connect = WinHttpConnect(session, host.c_str(), components.nPort, 0);
                if (connect == nullptr)
                {
                    error = LastErrorText(L"Could not connect to feed host");
                    break;
                }

                request = WinHttpOpenRequest(
                    connect,
                    L"GET",
                    path.c_str(),
                    nullptr,
                    WINHTTP_NO_REFERER,
                    WINHTTP_DEFAULT_ACCEPT_TYPES,
                    WINHTTP_FLAG_SECURE);
                if (request == nullptr)
                {
                    error = LastErrorText(L"Could not create feed request");
                    break;
                }

                if (!WinHttpSendRequest(
                        request,
                        WINHTTP_NO_ADDITIONAL_HEADERS,
                        0,
                        WINHTTP_NO_REQUEST_DATA,
                        0,
                        0,
                        0) ||
                    !WinHttpReceiveResponse(request, nullptr))
                {
                    error = LastErrorText(L"Feed download request failed");
                    break;
                }

                DWORD statusCode = 0;
                DWORD statusCodeSize = sizeof(statusCode);
                if (!WinHttpQueryHeaders(
                        request,
                        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX,
                        &statusCode,
                        &statusCodeSize,
                        WINHTTP_NO_HEADER_INDEX) ||
                    statusCode != HTTP_STATUS_OK)
                {
                    error = L"Feed download returned HTTP status " + std::to_wstring(statusCode) + L".";
                    break;
                }

                output = CreateFileW(
                    destinationPath.c_str(),
                    GENERIC_WRITE,
                    0,
                    nullptr,
                    CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL,
                    nullptr);
                if (output == INVALID_HANDLE_VALUE)
                {
                    error = LastErrorText(L"Could not create temporary feed file");
                    break;
                }

                for (;;)
                {
                    DWORD available = 0;
                    if (!WinHttpQueryDataAvailable(request, &available))
                    {
                        error = LastErrorText(L"Could not query feed download data");
                        break;
                    }
                    if (available == 0)
                    {
                        success = true;
                        break;
                    }

                    if (bytesWritten + available > MaxDownloadBytes)
                    {
                        error = L"Downloaded feed exceeded maximum supported size.";
                        break;
                    }

                    std::vector<char> buffer(available);
                    DWORD read = 0;
                    if (!WinHttpReadData(request, buffer.data(), available, &read))
                    {
                        error = LastErrorText(L"Could not read feed download data");
                        break;
                    }
                    if (read == 0)
                    {
                        success = true;
                        break;
                    }

                    DWORD written = 0;
                    if (!WriteFile(output, buffer.data(), read, &written, nullptr) || written != read)
                    {
                        error = LastErrorText(L"Could not write temporary feed file");
                        break;
                    }
                    bytesWritten += read;
                }
            } while (false);

            if (output != INVALID_HANDLE_VALUE)
            {
                CloseHandle(output);
            }
            if (request != nullptr)
            {
                WinHttpCloseHandle(request);
            }
            if (connect != nullptr)
            {
                WinHttpCloseHandle(connect);
            }
            WinHttpCloseHandle(session);

            if (!success)
            {
                DeleteFileIfExists(destinationPath);
            }
            return success;
        }

        bool IsHexHash(const std::string& value)
        {
            return value.size() == 64 &&
                std::all_of(value.begin(), value.end(), [](unsigned char ch) {
                    return std::isxdigit(ch) != 0;
                });
        }

        bool ParseSha256File(
            const std::filesystem::path& path,
            std::string& expectedHash,
            std::wstring& error)
        {
            std::ifstream input(path, std::ios::binary);
            if (!input)
            {
                error = L"Update failed: checksum file unavailable";
                return false;
            }

            std::ostringstream buffer;
            buffer << input.rdbuf();
            std::string text = buffer.str();
            if (text.size() >= 3 &&
                static_cast<unsigned char>(text[0]) == 0xEF &&
                static_cast<unsigned char>(text[1]) == 0xBB &&
                static_cast<unsigned char>(text[2]) == 0xBF)
            {
                text.erase(0, 3);
            }

            std::istringstream stream(text);
            std::string hash;
            std::string fileName;
            std::string extra;
            if (!(stream >> hash >> fileName))
            {
                error = L"Update failed: checksum file malformed";
                return false;
            }
            if (stream >> extra)
            {
                error = L"Update failed: checksum file malformed";
                return false;
            }

            std::transform(hash.begin(), hash.end(), hash.begin(), [](unsigned char ch) {
                return static_cast<char>(std::tolower(ch));
            });
            if (!IsHexHash(hash))
            {
                error = L"Update failed: checksum file malformed";
                return false;
            }
            if (fileName != "network-indicators.json")
            {
                error = L"Update failed: checksum filename mismatch";
                return false;
            }

            expectedHash = hash;
            return true;
        }

        bool ComputeFileSha256(
            const std::filesystem::path& path,
            std::string& computedHash,
            std::wstring& error)
        {
            std::ifstream input(path, std::ios::binary);
            if (!input)
            {
                error = L"Update failed: SHA256 verification failed";
                return false;
            }

            BCRYPT_ALG_HANDLE algorithm = nullptr;
            BCRYPT_HASH_HANDLE hash = nullptr;
            bool success = false;
            std::vector<unsigned char> hashObject;
            std::array<unsigned char, 32> digest = {};

            do
            {
                if (BCryptOpenAlgorithmProvider(
                        &algorithm,
                        BCRYPT_SHA256_ALGORITHM,
                        nullptr,
                        0) != 0)
                {
                    error = L"Update failed: SHA256 verification failed";
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
                    error = L"Update failed: SHA256 verification failed";
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
                    error = L"Update failed: SHA256 verification failed";
                    break;
                }

                std::array<char, 64 * 1024> buffer = {};
                while (input)
                {
                    input.read(buffer.data(), buffer.size());
                    const std::streamsize read = input.gcount();
                    if (read <= 0)
                    {
                        break;
                    }
                    if (BCryptHashData(
                            hash,
                            reinterpret_cast<PUCHAR>(buffer.data()),
                            static_cast<ULONG>(read),
                            0) != 0)
                    {
                        error = L"Update failed: SHA256 verification failed";
                        break;
                    }
                }
                if (!error.empty())
                {
                    break;
                }

                if (BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) != 0)
                {
                    error = L"Update failed: SHA256 verification failed";
                    break;
                }

                static constexpr char Hex[] = "0123456789abcdef";
                computedHash.clear();
                computedHash.reserve(digest.size() * 2);
                for (unsigned char byte : digest)
                {
                    computedHash.push_back(Hex[(byte >> 4) & 0x0F]);
                    computedHash.push_back(Hex[byte & 0x0F]);
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
            return success;
        }

        bool PathExists(const std::filesystem::path& path)
        {
            std::error_code error;
            return std::filesystem::exists(path, error);
        }

        bool ReplaceOneFile(
            const std::filesystem::path& tempPath,
            const std::filesystem::path& finalPath,
            const std::filesystem::path& backupPath,
            bool& hadExisting,
            std::wstring& error)
        {
            hadExisting = PathExists(finalPath);
            DeleteFileIfExists(backupPath);

            if (hadExisting)
            {
                if (!ReplaceFileW(
                        finalPath.c_str(),
                        tempPath.c_str(),
                        backupPath.c_str(),
                        REPLACEFILE_IGNORE_MERGE_ERRORS,
                        nullptr,
                        nullptr))
                {
                    error = L"Update failed: could not replace local feed";
                    return false;
                }
                return true;
            }

            if (!MoveFileExW(
                    tempPath.c_str(),
                    finalPath.c_str(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
            {
                error = L"Update failed: could not replace local feed";
                return false;
            }
            return true;
        }

        void RollBackOneFile(
            const std::filesystem::path& finalPath,
            const std::filesystem::path& backupPath,
            bool hadExisting)
        {
            if (hadExisting)
            {
                if (PathExists(backupPath))
                {
                    MoveFileExW(
                        backupPath.c_str(),
                        finalPath.c_str(),
                        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
                }
            }
            else
            {
                DeleteFileIfExists(finalPath);
            }
        }
    }

    NetworkIndicatorUpdateResult UpdateNetworkIndicatorFeed(
        const std::wstring& indicatorsDirectory)
    {
        return UpdateNetworkIndicatorFeed(indicatorsDirectory, {});
    }

    NetworkIndicatorUpdateResult UpdateNetworkIndicatorFeed(
        const std::wstring& indicatorsDirectory,
        const std::function<void(const std::wstring&, float)>& progress)
    {
        const auto reportProgress = [&progress](const std::wstring& message, float value) {
            if (progress)
            {
                progress(message, value);
            }
        };

        NetworkIndicatorUpdateResult result;
        const std::filesystem::path directory(indicatorsDirectory);
        const std::filesystem::path finalJsonPath = directory / FeedJsonFileName;
        const std::filesystem::path finalShaPath = directory / FeedShaFileName;
        const std::filesystem::path jsonTempPath = directory / FeedJsonTempFileName;
        const std::filesystem::path shaTempPath = directory / FeedShaTempFileName;
        const std::filesystem::path jsonBackupPath = directory / L"network-indicators.json.bak";
        const std::filesystem::path shaBackupPath = directory / L"network-indicators.sha256.bak";

        result.finalJsonPath = finalJsonPath.wstring();
        result.finalShaPath = finalShaPath.wstring();
        result.jsonTempPath = jsonTempPath.wstring();
        result.shaTempPath = shaTempPath.wstring();

        std::error_code fsError;
        reportProgress(L"Preparing portable Indicators folder...", 0.05f);
        std::filesystem::create_directories(directory, fsError);
        if (fsError)
        {
            result.statusMessage = L"Update failed: could not create Indicators folder";
            const std::string message = fsError.message();
            result.detail = std::wstring(message.begin(), message.end());
            return result;
        }

        DeleteFileIfExists(jsonTempPath);
        DeleteFileIfExists(shaTempPath);

        std::wstring error;
        reportProgress(L"Downloading network-indicators.json...", 0.18f);
        if (!DownloadFileToPath(
                NetworkIndicatorsJsonUrl,
                jsonTempPath,
                result.downloadedJsonBytes,
                error))
        {
            result.statusMessage = L"Update failed: network feed download failed";
            result.detail = error;
            DeleteFileIfExists(jsonTempPath);
            DeleteFileIfExists(shaTempPath);
            return result;
        }
        result.jsonDownloaded = true;

        reportProgress(L"Downloading network-indicators.sha256...", 0.32f);
        if (!DownloadFileToPath(
                NetworkIndicatorsShaUrl,
                shaTempPath,
                result.downloadedShaBytes,
                error))
        {
            result.statusMessage = L"Update failed: checksum file unavailable";
            result.detail = error;
            DeleteFileIfExists(jsonTempPath);
            DeleteFileIfExists(shaTempPath);
            return result;
        }
        result.shaDownloaded = true;

        reportProgress(L"Parsing checksum file...", 0.46f);
        if (!ParseSha256File(shaTempPath, result.expectedSha256, error))
        {
            result.statusMessage = error;
            DeleteFileIfExists(jsonTempPath);
            DeleteFileIfExists(shaTempPath);
            return result;
        }
        result.checksumParsed = true;

        reportProgress(L"Verifying SHA256...", 0.58f);
        if (!ComputeFileSha256(jsonTempPath, result.computedSha256, error))
        {
            result.statusMessage = error.empty()
                ? std::wstring(L"Update failed: SHA256 verification failed")
                : error;
            DeleteFileIfExists(jsonTempPath);
            DeleteFileIfExists(shaTempPath);
            return result;
        }
        result.shaVerified = result.computedSha256 == result.expectedSha256;
        if (!result.shaVerified)
        {
            result.statusMessage = L"Update failed: downloaded feed hash mismatch";
            DeleteFileIfExists(jsonTempPath);
            DeleteFileIfExists(shaTempPath);
            return result;
        }

        reportProgress(L"Validating feed JSON...", 0.70f);
        const NetworkIndicatorLoadResult validation = LoadNetworkIndicatorFeedFromFile(jsonTempPath.wstring());
        if (!validation.success)
        {
            if (validation.statusMessage.find(L"Unsupported network indicator feed schema version") != std::wstring::npos)
            {
                result.statusMessage = L"Update failed: unsupported feed schema";
            }
            else
            {
                result.statusMessage = L"Update failed: downloaded feed JSON is invalid";
            }
            result.detail = validation.statusMessage;
            DeleteFileIfExists(jsonTempPath);
            DeleteFileIfExists(shaTempPath);
            return result;
        }
        result.jsonValidated = true;

        reportProgress(L"Replacing local feed files...", 0.82f);
        bool hadJson = false;
        bool hadSha = false;
        if (!ReplaceOneFile(jsonTempPath, finalJsonPath, jsonBackupPath, hadJson, error))
        {
            result.statusMessage = error;
            DeleteFileIfExists(jsonTempPath);
            DeleteFileIfExists(shaTempPath);
            return result;
        }

        if (!ReplaceOneFile(shaTempPath, finalShaPath, shaBackupPath, hadSha, error))
        {
            RollBackOneFile(finalJsonPath, jsonBackupPath, hadJson);
            result.statusMessage = error;
            DeleteFileIfExists(jsonTempPath);
            DeleteFileIfExists(shaTempPath);
            DeleteFileIfExists(jsonBackupPath);
            DeleteFileIfExists(shaBackupPath);
            return result;
        }
        result.filesReplaced = true;

        reportProgress(L"Reloading verified feed...", 0.92f);
        result.loadResult = LoadNetworkIndicatorFeedFromFile(finalJsonPath.wstring());
        if (!result.loadResult.success)
        {
            RollBackOneFile(finalShaPath, shaBackupPath, hadSha);
            RollBackOneFile(finalJsonPath, jsonBackupPath, hadJson);
            result.statusMessage = L"Update failed: downloaded feed JSON is invalid";
            result.detail = result.loadResult.statusMessage;
            DeleteFileIfExists(jsonTempPath);
            DeleteFileIfExists(shaTempPath);
            DeleteFileIfExists(jsonBackupPath);
            DeleteFileIfExists(shaBackupPath);
            return result;
        }

        result.cleanupWarning =
            !DeleteFileIfExists(jsonBackupPath) ||
            !DeleteFileIfExists(shaBackupPath) ||
            !DeleteFileIfExists(jsonTempPath) ||
            !DeleteFileIfExists(shaTempPath);

        result.success = true;
        result.statusMessage =
            L"Intel feed updated and verified: " +
            std::to_wstring(result.loadResult.feed.indicators.size()) +
            L" indicator";
        if (result.loadResult.feed.indicators.size() != 1)
        {
            result.statusMessage += L"s";
        }
        return result;
    }
}
