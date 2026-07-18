#pragma once

#include <cstdint>
#include <string>

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

    FileIdentity CollectFileIdentity(const std::wstring& path);
}
