#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "ModuleCollector.h"

#include <Windows.h>
#include <Psapi.h>

#include <sstream>
#include <string>
#include <vector>

namespace GlassPane::Core
{
    namespace
    {
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

            result.modules.push_back(std::move(module));
        }

        CloseHandle(processHandle);
        result.success = true;
        result.statusMessage = L"Loaded " + std::to_wstring(result.modules.size()) + L" modules.";
        return result;
    }
}
