#pragma once

#include "../Core/FileIdentity.h"
#include "../Core/Finding.h"
#include "../Core/HandleInfo.h"
#include "../Core/MemoryRegionInfo.h"
#include "../Core/ModuleInfo.h"
#include "../Core/NetworkConnection.h"
#include "../Core/ProcessInfo.h"
#include "../Core/RuntimeInfo.h"
#include "../Core/TokenInfo.h"

#include <cstdint>
#include <string>
#include <vector>

namespace GlassPane::Export
{
    struct SelectedProcessMarkdownReportContext
    {
        const Core::ProcessSnapshot* snapshot = nullptr;
        std::uint32_t pid = 0;
        std::wstring appVersion;
        std::wstring buildConfiguration;
        std::vector<Core::Finding> findings;

        const Core::FileIdentity* fileIdentity = nullptr;
        std::vector<Core::FileIdentityIndicator> fileIdentityIndicators;

        bool modulesLoaded = false;
        const Core::ModuleCollectionResult* modules = nullptr;

        bool networkLoaded = false;
        bool networkSuccess = false;
        std::wstring networkStatusMessage;
        const std::vector<Core::NetworkConnection>* networkConnections = nullptr;

        bool tokenLoaded = false;
        const Core::TokenInfo* token = nullptr;

        bool runtimeLoaded = false;
        const Core::RuntimeInfo* runtime = nullptr;

        bool memoryLoaded = false;
        const Core::MemoryCollectionResult* memory = nullptr;

        bool handlesLoaded = false;
        const Core::HandleCollectionResult* handles = nullptr;
    };

    bool ExportSelectedProcessMarkdownReport(
        const SelectedProcessMarkdownReportContext& context,
        const std::wstring& filePath,
        std::wstring* errorMessage = nullptr);
}
