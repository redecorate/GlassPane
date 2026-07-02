#pragma once

#include "ProcessInfo.h"

#include <cstdint>
#include <string>
#include <vector>

namespace GlassPane::Core
{
    struct FileIdentity
    {
        std::wstring path;
        bool exists = false;
        std::wstring sha256;
        std::uint64_t fileSize = 0;
        std::wstring signerName;
        bool signaturePresent = false;
        bool signatureValid = false;
        std::wstring companyName;
        std::wstring productName;
        std::wstring fileDescription;
        std::wstring originalFilename;
        std::wstring versionString;
        std::wstring errorMessage;
    };

    struct FileIdentityIndicator
    {
        Severity severity = Severity::Info;
        std::wstring message;
    };

    FileIdentity CollectFileIdentity(const std::wstring& path);

    std::vector<FileIdentityIndicator> BuildFileIdentityIndicators(
        const FileIdentity& identity,
        const std::wstring& imageName,
        bool executableContext);
}
