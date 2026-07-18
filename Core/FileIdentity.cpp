#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "FileIdentity.h"

#include <Windows.h>
#include <bcrypt.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>

#include <array>
#include <cstdio>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Version.lib")
#pragma comment(lib, "Wintrust.lib")

namespace GlassPane::Core
{
    namespace
    {
        struct Translation
        {
            WORD language = 0;
            WORD codePage = 0;
        };

        void AppendError(FileIdentity& identity, const std::wstring& message)
        {
            if (message.empty())
            {
                return;
            }

            if (!identity.errorMessage.empty())
            {
                identity.errorMessage += L" ";
            }
            identity.errorMessage += message;
        }

        std::wstring WindowsErrorMessage(DWORD error)
        {
            wchar_t* buffer = nullptr;
            const DWORD length = FormatMessageW(
                FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                nullptr,
                error,
                0,
                reinterpret_cast<LPWSTR>(&buffer),
                0,
                nullptr);

            if (length == 0 || buffer == nullptr)
            {
                return L"Windows error " + std::to_wstring(error);
            }

            std::wstring message(buffer, length);
            LocalFree(buffer);
            while (!message.empty() && (message.back() == L'\r' || message.back() == L'\n' || message.back() == L'.'))
            {
                message.pop_back();
            }
            return message;
        }

        std::wstring HexStatus(LONG status)
        {
            std::wstringstream stream;
            stream << L"0x" << std::uppercase << std::hex << static_cast<unsigned long>(status);
            return stream.str();
        }

        std::wstring TrustStatusText(LONG status)
        {
            switch (static_cast<DWORD>(status))
            {
            case ERROR_SUCCESS:
                return L"Signature is valid";
            case TRUST_E_NOSIGNATURE:
                return L"No embedded or catalog signature was found";
            case TRUST_E_BAD_DIGEST:
                return L"Signature digest does not match the file";
            case TRUST_E_EXPLICIT_DISTRUST:
                return L"Signature is explicitly distrusted";
            case TRUST_E_SUBJECT_NOT_TRUSTED:
                return L"Signature subject is not trusted";
            case TRUST_E_SUBJECT_FORM_UNKNOWN:
                return L"Signature subject form is unknown";
            case TRUST_E_PROVIDER_UNKNOWN:
                return L"Signature trust provider is unknown";
            case CERT_E_EXPIRED:
                return L"Signing certificate is expired";
            case CERT_E_REVOKED:
                return L"Signing certificate is revoked";
            case CERT_E_UNTRUSTEDROOT:
                return L"Signing certificate chains to an untrusted root";
            case CRYPT_E_SECURITY_SETTINGS:
                return L"Local policy prevents signature verification";
            default:
                return L"WinVerifyTrust returned " + HexStatus(status);
            }
        }

        bool IsNoSignatureStatus(LONG status)
        {
            return status == TRUST_E_NOSIGNATURE ||
                status == TRUST_E_SUBJECT_FORM_UNKNOWN ||
                status == TRUST_E_PROVIDER_UNKNOWN;
        }

        std::wstring BytesToHex(const std::vector<unsigned char>& bytes)
        {
            std::wstringstream stream;
            stream << std::hex << std::setfill(L'0');
            for (const unsigned char byte : bytes)
            {
                stream << std::setw(2) << static_cast<unsigned int>(byte);
            }
            return stream.str();
        }

        std::wstring NtStatusText(NTSTATUS status)
        {
            std::wstringstream stream;
            stream << L"BCrypt status 0x" << std::uppercase << std::hex << static_cast<unsigned long>(status);
            return stream.str();
        }

        bool ComputeSha256(FileIdentity& identity)
        {
            HANDLE file = CreateFileW(
                identity.path.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                nullptr);

            if (file == INVALID_HANDLE_VALUE)
            {
                AppendError(identity, L"Could not open file for hashing: " + WindowsErrorMessage(GetLastError()) + L".");
                return false;
            }

            LARGE_INTEGER fileSize = {};
            if (GetFileSizeEx(file, &fileSize) != FALSE && fileSize.QuadPart >= 0)
            {
                identity.fileSize = static_cast<std::uint64_t>(fileSize.QuadPart);
            }
            else
            {
                AppendError(identity, L"Could not read file size: " + WindowsErrorMessage(GetLastError()) + L".");
            }

            BCRYPT_ALG_HANDLE algorithm = nullptr;
            BCRYPT_HASH_HANDLE hash = nullptr;
            DWORD objectLength = 0;
            DWORD hashLength = 0;
            DWORD bytesReturned = 0;
            std::vector<unsigned char> hashObject;
            std::vector<unsigned char> hashValue;
            bool ok = false;

            NTSTATUS status = BCryptOpenAlgorithmProvider(
                &algorithm,
                BCRYPT_SHA256_ALGORITHM,
                nullptr,
                0);
            if (status < 0)
            {
                AppendError(identity, L"Could not open SHA256 provider: " + NtStatusText(status) + L".");
                CloseHandle(file);
                return false;
            }

            status = BCryptGetProperty(
                algorithm,
                BCRYPT_OBJECT_LENGTH,
                reinterpret_cast<PUCHAR>(&objectLength),
                sizeof(objectLength),
                &bytesReturned,
                0);
            if (status >= 0)
            {
                status = BCryptGetProperty(
                    algorithm,
                    BCRYPT_HASH_LENGTH,
                    reinterpret_cast<PUCHAR>(&hashLength),
                    sizeof(hashLength),
                    &bytesReturned,
                    0);
            }

            if (status >= 0)
            {
                hashObject.resize(objectLength);
                hashValue.resize(hashLength);
                status = BCryptCreateHash(
                    algorithm,
                    &hash,
                    hashObject.data(),
                    objectLength,
                    nullptr,
                    0,
                    0);
            }

            if (status < 0)
            {
                AppendError(identity, L"Could not initialize SHA256 hash: " + NtStatusText(status) + L".");
            }
            else
            {
                std::array<unsigned char, 64 * 1024> buffer = {};
                DWORD bytesRead = 0;
                while (ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, nullptr) != FALSE)
                {
                    if (bytesRead == 0)
                    {
                        ok = true;
                        break;
                    }

                    status = BCryptHashData(hash, buffer.data(), bytesRead, 0);
                    if (status < 0)
                    {
                        AppendError(identity, L"Could not update SHA256 hash: " + NtStatusText(status) + L".");
                        break;
                    }
                }

                if (!ok && status >= 0)
                {
                    AppendError(identity, L"Could not read file for hashing: " + WindowsErrorMessage(GetLastError()) + L".");
                }

                if (ok)
                {
                    status = BCryptFinishHash(hash, hashValue.data(), hashLength, 0);
                    if (status >= 0)
                    {
                        identity.sha256 = BytesToHex(hashValue);
                    }
                    else
                    {
                        ok = false;
                        AppendError(identity, L"Could not finalize SHA256 hash: " + NtStatusText(status) + L".");
                    }
                }
            }

            if (hash != nullptr)
            {
                BCryptDestroyHash(hash);
            }
            if (algorithm != nullptr)
            {
                BCryptCloseAlgorithmProvider(algorithm, 0);
            }
            CloseHandle(file);
            return ok;
        }

        std::wstring ReadVersionString(
            const std::vector<unsigned char>& versionData,
            WORD language,
            WORD codePage,
            const wchar_t* name)
        {
            wchar_t block[128] = {};
            swprintf_s(
                block,
                L"\\StringFileInfo\\%04x%04x\\%s",
                static_cast<unsigned int>(language),
                static_cast<unsigned int>(codePage),
                name);

            LPVOID value = nullptr;
            UINT valueLength = 0;
            if (VerQueryValueW(
                const_cast<unsigned char*>(versionData.data()),
                block,
                &value,
                &valueLength) == FALSE ||
                value == nullptr ||
                valueLength == 0)
            {
                return {};
            }

            std::wstring result(static_cast<const wchar_t*>(value), valueLength);
            while (!result.empty() && result.back() == L'\0')
            {
                result.pop_back();
            }
            return result;
        }

        std::vector<Translation> ReadVersionTranslations(const std::vector<unsigned char>& versionData)
        {
            LPVOID translationsRaw = nullptr;
            UINT translationBytes = 0;
            std::vector<Translation> translations;
            if (VerQueryValueW(
                const_cast<unsigned char*>(versionData.data()),
                L"\\VarFileInfo\\Translation",
                &translationsRaw,
                &translationBytes) != FALSE &&
                translationsRaw != nullptr &&
                translationBytes >= sizeof(Translation))
            {
                const auto* translationValues = static_cast<const Translation*>(translationsRaw);
                const std::size_t count = translationBytes / sizeof(Translation);
                translations.assign(translationValues, translationValues + count);
            }

            if (translations.empty())
            {
                translations.push_back({ 0x0409, 0x04b0 });
                translations.push_back({ 0x0409, 0x04e4 });
            }
            return translations;
        }

        std::wstring ReadFirstVersionString(
            const std::vector<unsigned char>& versionData,
            const std::vector<Translation>& translations,
            const wchar_t* name)
        {
            for (const Translation& translation : translations)
            {
                std::wstring value = ReadVersionString(
                    versionData,
                    translation.language,
                    translation.codePage,
                    name);
                if (!value.empty())
                {
                    return value;
                }
            }
            return {};
        }

        std::wstring FixedFileVersion(const std::vector<unsigned char>& versionData)
        {
            LPVOID fixedInfoRaw = nullptr;
            UINT fixedInfoLength = 0;
            if (VerQueryValueW(
                const_cast<unsigned char*>(versionData.data()),
                L"\\",
                &fixedInfoRaw,
                &fixedInfoLength) == FALSE ||
                fixedInfoRaw == nullptr ||
                fixedInfoLength < sizeof(VS_FIXEDFILEINFO))
            {
                return {};
            }

            const auto* fixedInfo = static_cast<const VS_FIXEDFILEINFO*>(fixedInfoRaw);
            if (fixedInfo->dwSignature != VS_FFI_SIGNATURE)
            {
                return {};
            }

            std::wstringstream version;
            version
                << HIWORD(fixedInfo->dwFileVersionMS) << L'.'
                << LOWORD(fixedInfo->dwFileVersionMS) << L'.'
                << HIWORD(fixedInfo->dwFileVersionLS) << L'.'
                << LOWORD(fixedInfo->dwFileVersionLS);
            return version.str();
        }

        void ReadVersionInfo(FileIdentity& identity)
        {
            DWORD handle = 0;
            const DWORD versionSize = GetFileVersionInfoSizeW(identity.path.c_str(), &handle);
            if (versionSize == 0)
            {
                return;
            }

            std::vector<unsigned char> versionData(versionSize);
            if (GetFileVersionInfoW(
                identity.path.c_str(),
                0,
                versionSize,
                versionData.data()) == FALSE)
            {
                AppendError(identity, L"Could not read version info: " + WindowsErrorMessage(GetLastError()) + L".");
                return;
            }

            const std::vector<Translation> translations = ReadVersionTranslations(versionData);
            identity.companyName = ReadFirstVersionString(versionData, translations, L"CompanyName");
            identity.productName = ReadFirstVersionString(versionData, translations, L"ProductName");
            identity.fileDescription = ReadFirstVersionString(versionData, translations, L"FileDescription");
            identity.originalFilename = ReadFirstVersionString(versionData, translations, L"OriginalFilename");
            identity.versionString = ReadFirstVersionString(versionData, translations, L"FileVersion");
            if (identity.versionString.empty())
            {
                identity.versionString = ReadFirstVersionString(versionData, translations, L"ProductVersion");
            }
            if (identity.versionString.empty())
            {
                identity.versionString = FixedFileVersion(versionData);
            }
        }

        std::wstring CertificateDisplayName(PCCERT_CONTEXT certificate)
        {
            if (certificate == nullptr)
            {
                return {};
            }

            DWORD nameType = CERT_NAME_SIMPLE_DISPLAY_TYPE;
            DWORD length = CertGetNameStringW(
                certificate,
                nameType,
                0,
                nullptr,
                nullptr,
                0);
            if (length <= 1)
            {
                nameType = CERT_NAME_FRIENDLY_DISPLAY_TYPE;
                length = CertGetNameStringW(
                    certificate,
                    nameType,
                    0,
                    nullptr,
                    nullptr,
                    0);
            }
            if (length <= 1)
            {
                return {};
            }

            std::wstring name(length - 1, L'\0');
            CertGetNameStringW(
                certificate,
                nameType,
                0,
                nullptr,
                name.data(),
                length);
            return name;
        }

        std::wstring EmbeddedSignerName(const std::wstring& path)
        {
            HCERTSTORE store = nullptr;
            HCRYPTMSG message = nullptr;
            DWORD encoding = 0;
            DWORD contentType = 0;
            DWORD formatType = 0;

            if (CryptQueryObject(
                CERT_QUERY_OBJECT_FILE,
                path.c_str(),
                CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                CERT_QUERY_FORMAT_FLAG_BINARY,
                0,
                &encoding,
                &contentType,
                &formatType,
                &store,
                &message,
                nullptr) == FALSE)
            {
                return {};
            }

            DWORD signerInfoSize = 0;
            if (CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerInfoSize) == FALSE ||
                signerInfoSize == 0)
            {
                if (message != nullptr)
                {
                    CryptMsgClose(message);
                }
                if (store != nullptr)
                {
                    CertCloseStore(store, 0);
                }
                return {};
            }

            std::vector<unsigned char> signerInfoBuffer(signerInfoSize);
            if (CryptMsgGetParam(
                message,
                CMSG_SIGNER_INFO_PARAM,
                0,
                signerInfoBuffer.data(),
                &signerInfoSize) == FALSE)
            {
                CryptMsgClose(message);
                CertCloseStore(store, 0);
                return {};
            }

            const auto* signerInfo = reinterpret_cast<const CMSG_SIGNER_INFO*>(signerInfoBuffer.data());
            CERT_INFO certificateInfo = {};
            certificateInfo.Issuer = signerInfo->Issuer;
            certificateInfo.SerialNumber = signerInfo->SerialNumber;

            PCCERT_CONTEXT certificate = CertFindCertificateInStore(
                store,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                0,
                CERT_FIND_SUBJECT_CERT,
                &certificateInfo,
                nullptr);

            std::wstring name = CertificateDisplayName(certificate);

            if (certificate != nullptr)
            {
                CertFreeCertificateContext(certificate);
            }
            CryptMsgClose(message);
            CertCloseStore(store, 0);
            return name;
        }

        void ReadSignerFromTrustState(HANDLE trustState, FileIdentity& identity)
        {
            if (trustState == nullptr)
            {
                return;
            }

            CRYPT_PROVIDER_DATA* providerData = WTHelperProvDataFromStateData(trustState);
            if (providerData == nullptr)
            {
                return;
            }

            CRYPT_PROVIDER_SGNR* signer = WTHelperGetProvSignerFromChain(providerData, 0, FALSE, 0);
            if (signer == nullptr || signer->csCertChain == 0 || signer->pasCertChain == nullptr)
            {
                return;
            }

            const std::wstring name = CertificateDisplayName(signer->pasCertChain[0].pCert);
            if (!name.empty())
            {
                identity.signerName = name;
            }
        }

        void VerifySignature(FileIdentity& identity)
        {
            WINTRUST_FILE_INFO fileInfo = {};
            fileInfo.cbStruct = sizeof(fileInfo);
            fileInfo.pcwszFilePath = identity.path.c_str();

            WINTRUST_DATA trustData = {};
            trustData.cbStruct = sizeof(trustData);
            trustData.dwUIChoice = WTD_UI_NONE;
            trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
            trustData.dwUnionChoice = WTD_CHOICE_FILE;
            trustData.pFile = &fileInfo;
            trustData.dwStateAction = WTD_STATEACTION_VERIFY;
            trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

            GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            const LONG status = WinVerifyTrust(nullptr, &action, &trustData);
            if (status == ERROR_SUCCESS)
            {
                identity.signaturePresent = true;
                identity.signatureValid = true;
            }
            else if (IsNoSignatureStatus(status))
            {
                identity.signaturePresent = false;
                identity.signatureValid = false;
            }
            else
            {
                identity.signaturePresent = true;
                identity.signatureValid = false;
                AppendError(identity, L"Authenticode signature verification failed: " + TrustStatusText(status) + L".");
            }

            ReadSignerFromTrustState(trustData.hWVTStateData, identity);
            if (identity.signerName.empty())
            {
                identity.signerName = EmbeddedSignerName(identity.path);
            }
            if (!identity.signerName.empty())
            {
                identity.signaturePresent = true;
            }

            if (trustData.hWVTStateData != nullptr)
            {
                trustData.dwStateAction = WTD_STATEACTION_CLOSE;
                WinVerifyTrust(nullptr, &action, &trustData);
            }
        }

    }

    FileIdentity CollectFileIdentity(const std::wstring& path)
    {
        FileIdentity identity;
        identity.path = path;

        if (path.empty())
        {
            identity.errorMessage = L"File path is empty.";
            return identity;
        }

        const DWORD attributes = GetFileAttributesW(path.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
        {
            identity.exists = false;
            identity.errorMessage = L"File does not exist or is not a regular file.";
            return identity;
        }

        identity.exists = true;
        ComputeSha256(identity);
        ReadVersionInfo(identity);
        VerifySignature(identity);
        return identity;
    }

}
