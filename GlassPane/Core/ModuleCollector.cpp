#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "ModuleCollector.h"

#include <Windows.h>
#include <Psapi.h>

#include <algorithm>
#include <cwctype>
#include <sstream>
#include <string>
#include <vector>

namespace GlassPane::Core
{
    namespace
    {
        std::wstring ToLower(std::wstring value)
        {
            std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) {
                return static_cast<wchar_t>(std::towlower(ch));
            });
            return value;
        }

        bool Contains(const std::wstring& haystack, const std::wstring& needle)
        {
            return haystack.find(needle) != std::wstring::npos;
        }

        std::wstring LastPathPart(const std::wstring& path)
        {
            const std::size_t slash = path.find_last_of(L"\\/");
            if (slash == std::wstring::npos || slash + 1 >= path.size())
            {
                return path;
            }
            return path.substr(slash + 1);
        }

        std::wstring FormatBaseAddress(void* address)
        {
            std::wstringstream stream;
            stream << L"0x" << std::uppercase << std::hex << reinterpret_cast<std::uintptr_t>(address);
            return stream.str();
        }

        std::wstring ErrorMessage(DWORD error)
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

        bool IsSystemProcess(const ProcessInfo& process)
        {
            const std::wstring loweredPath = ToLower(process.executablePath);
            const std::wstring loweredName = ToLower(process.name);
            if (process.sessionId.has_value() && process.sessionId.value() == 0)
            {
                return true;
            }

            if (Contains(loweredPath, L"\\windows\\system32\\") ||
                Contains(loweredPath, L"\\windows\\syswow64\\"))
            {
                return true;
            }

            return loweredName == L"services.exe" ||
                loweredName == L"lsass.exe" ||
                loweredName == L"winlogon.exe" ||
                loweredName == L"svchost.exe" ||
                loweredName == L"csrss.exe" ||
                loweredName == L"smss.exe";
        }

        bool IsCommonInstallPath(const std::wstring& loweredPath)
        {
            return Contains(loweredPath, L"\\windows\\") ||
                Contains(loweredPath, L"\\program files\\") ||
                Contains(loweredPath, L"\\program files (x86)\\");
        }

        void AddIndicator(ModuleCollectionResult& result, ModuleInfo& module, const std::wstring& indicator)
        {
            module.indicators.push_back(indicator);
            result.indicators.push_back(module.moduleName.empty()
                ? indicator
                : module.moduleName + L": " + indicator);
        }

        void AnalyzeModule(ModuleCollectionResult& result, ModuleInfo& module, const ProcessInfo& process)
        {
            const std::wstring loweredPath = ToLower(module.modulePath);
            if (module.modulePath.empty())
            {
                AddIndicator(result, module, L"Module path missing");
                return;
            }

            if (Contains(loweredPath, L"\\temp\\"))
            {
                AddIndicator(result, module, L"Module loaded from Temp");
            }

            if (Contains(loweredPath, L"\\appdata\\"))
            {
                AddIndicator(result, module, L"Module loaded from AppData");
            }

            if (IsSystemProcess(process) && !IsCommonInstallPath(loweredPath))
            {
                AddIndicator(result, module, L"System process loaded module outside Windows or Program Files");
            }
        }
    }

    ModuleCollectionResult CollectProcessModules(const ProcessInfo& process)
    {
        ModuleCollectionResult result;
        result.pid = process.pid;

        HANDLE processHandle = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            FALSE,
            process.pid);

        if (processHandle == nullptr)
        {
            result.statusMessage = L"Could not open process for module inspection: " + ErrorMessage(GetLastError());
            return result;
        }

        DWORD neededBytes = 0;
        std::vector<HMODULE> modules(256);
        if (EnumProcessModulesEx(
            processHandle,
            modules.data(),
            static_cast<DWORD>(modules.size() * sizeof(HMODULE)),
            &neededBytes,
            LIST_MODULES_ALL) == FALSE)
        {
            result.statusMessage = L"Could not enumerate modules: " + ErrorMessage(GetLastError());
            CloseHandle(processHandle);
            return result;
        }

        if (neededBytes > modules.size() * sizeof(HMODULE))
        {
            modules.resize(neededBytes / sizeof(HMODULE));
            if (EnumProcessModulesEx(
                processHandle,
                modules.data(),
                static_cast<DWORD>(modules.size() * sizeof(HMODULE)),
                &neededBytes,
                LIST_MODULES_ALL) == FALSE)
            {
                result.statusMessage = L"Could not enumerate all modules: " + ErrorMessage(GetLastError());
                CloseHandle(processHandle);
                return result;
            }
        }

        const std::size_t moduleCount = neededBytes / sizeof(HMODULE);
        modules.resize(moduleCount);

        for (HMODULE moduleHandle : modules)
        {
            ModuleInfo module;
            MODULEINFO moduleInfo = {};
            if (GetModuleInformation(processHandle, moduleHandle, &moduleInfo, sizeof(moduleInfo)) != FALSE)
            {
                module.baseAddress = FormatBaseAddress(moduleInfo.lpBaseOfDll);
                module.sizeBytes = moduleInfo.SizeOfImage;
                module.readable = true;
            }
            else
            {
                module.baseAddress = FormatBaseAddress(moduleHandle);
            }

            std::vector<wchar_t> pathBuffer(32768);
            const DWORD pathLength = GetModuleFileNameExW(
                processHandle,
                moduleHandle,
                pathBuffer.data(),
                static_cast<DWORD>(pathBuffer.size()));

            if (pathLength > 0)
            {
                module.modulePath.assign(pathBuffer.data(), pathLength);
                module.moduleName = LastPathPart(module.modulePath);
            }
            else
            {
                std::vector<wchar_t> nameBuffer(MAX_PATH);
                const DWORD nameLength = GetModuleBaseNameW(
                    processHandle,
                    moduleHandle,
                    nameBuffer.data(),
                    static_cast<DWORD>(nameBuffer.size()));
                module.moduleName = nameLength > 0
                    ? std::wstring(nameBuffer.data(), nameLength)
                    : L"(unknown)";
            }

            AnalyzeModule(result, module, process);
            result.modules.push_back(std::move(module));
        }

        CloseHandle(processHandle);
        result.success = true;
        result.statusMessage = L"Loaded " + std::to_wstring(result.modules.size()) + L" modules.";
        return result;
    }
}
