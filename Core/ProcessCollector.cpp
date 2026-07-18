#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "ProcessCollector.h"

#include "ProcessTree.h"

#include <Windows.h>
#include <TlHelp32.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace GlassPane::Core
{
    namespace
    {
        using NtQueryInformationProcessFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

        struct UnicodeStringRemote
        {
            USHORT Length = 0;
            USHORT MaximumLength = 0;
            PWSTR Buffer = nullptr;
        };

        struct ProcessBasicInformation
        {
            PVOID Reserved1 = nullptr;
            PVOID PebBaseAddress = nullptr;
            PVOID Reserved2[2] = {};
            ULONG_PTR UniqueProcessId = 0;
            PVOID Reserved3 = nullptr;
        };

        struct PebPartial
        {
            BYTE Reserved1[2] = {};
            BYTE BeingDebugged = 0;
            BYTE Reserved2[1] = {};
            PVOID Reserved3[2] = {};
            PVOID Ldr = nullptr;
            PVOID ProcessParameters = nullptr;
        };

        struct RtlUserProcessParametersPartial
        {
            BYTE Reserved1[16] = {};
            PVOID Reserved2[10] = {};
            UnicodeStringRemote ImagePathName;
            UnicodeStringRemote CommandLine;
        };

        std::wstring QueryExecutablePath(HANDLE process)
        {
            std::vector<wchar_t> buffer(32768);
            DWORD length = static_cast<DWORD>(buffer.size());
            if (QueryFullProcessImageNameW(process, 0, buffer.data(), &length) == FALSE)
            {
                return {};
            }

            return std::wstring(buffer.data(), length);
        }

        std::wstring FormatLocalTimestamp(const FILETIME& fileTime)
        {
            FILETIME localFileTime = {};
            SYSTEMTIME localSystemTime = {};
            if (FileTimeToLocalFileTime(&fileTime, &localFileTime) == FALSE ||
                FileTimeToSystemTime(&localFileTime, &localSystemTime) == FALSE)
            {
                return {};
            }

            wchar_t buffer[32] = {};
            swprintf_s(
                buffer,
                L"%04u-%02u-%02u %02u:%02u:%02u",
                localSystemTime.wYear,
                localSystemTime.wMonth,
                localSystemTime.wDay,
                localSystemTime.wHour,
                localSystemTime.wMinute,
                localSystemTime.wSecond);
            return buffer;
        }

        void QueryCreationTime(HANDLE process, ProcessInfo& info)
        {
            FILETIME creationTime = {};
            FILETIME exitTime = {};
            FILETIME kernelTime = {};
            FILETIME userTime = {};

            if (GetProcessTimes(process, &creationTime, &exitTime, &kernelTime, &userTime) == FALSE)
            {
                return;
            }

            ULARGE_INTEGER creation = {};
            creation.LowPart = creationTime.dwLowDateTime;
            creation.HighPart = creationTime.dwHighDateTime;
            info.creationTimeFileTime = creation.QuadPart;
            info.hasCreationTime = true;

            const std::wstring formatted = FormatLocalTimestamp(creationTime);
            if (!formatted.empty())
            {
                info.creationTimeLocal = formatted;
            }
        }

        std::wstring MachineToArchitecture(USHORT machine)
        {
            switch (machine)
            {
            case IMAGE_FILE_MACHINE_I386:
                return L"x86";
            case IMAGE_FILE_MACHINE_AMD64:
                return L"x64";
            case IMAGE_FILE_MACHINE_ARM:
            case IMAGE_FILE_MACHINE_ARMNT:
                return L"ARM";
            case IMAGE_FILE_MACHINE_ARM64:
                return L"ARM64";
            case IMAGE_FILE_MACHINE_UNKNOWN:
                return L"Native";
            default:
                return L"Unknown";
            }
        }

        std::wstring QueryArchitecture(HANDLE process)
        {
            HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
            if (kernel32 != nullptr)
            {
                using IsWow64Process2Fn = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
                const auto isWow64Process2 = reinterpret_cast<IsWow64Process2Fn>(
                    GetProcAddress(kernel32, "IsWow64Process2"));

                if (isWow64Process2 != nullptr)
                {
                    USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
                    USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
                    if (isWow64Process2(process, &processMachine, &nativeMachine) != FALSE)
                    {
                        if (processMachine == IMAGE_FILE_MACHINE_UNKNOWN)
                        {
                            return MachineToArchitecture(nativeMachine);
                        }
                        return MachineToArchitecture(processMachine);
                    }
                }
            }

            BOOL isWow64 = FALSE;
            if (IsWow64Process(process, &isWow64) != FALSE && isWow64 != FALSE)
            {
                return L"x86";
            }

#if defined(_M_X64) || defined(_M_AMD64)
            return L"x64";
#elif defined(_M_ARM64)
            return L"ARM64";
#elif defined(_M_IX86)
            return L"x86";
#else
            return L"Unknown";
#endif
        }

        std::optional<std::wstring> QueryCommandLine(HANDLE process)
        {
            HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
            if (ntdll == nullptr)
            {
                return std::nullopt;
            }

            const auto ntQueryInformationProcess = reinterpret_cast<NtQueryInformationProcessFn>(
                GetProcAddress(ntdll, "NtQueryInformationProcess"));
            if (ntQueryInformationProcess == nullptr)
            {
                return std::nullopt;
            }

            ProcessBasicInformation processInfo = {};
            const LONG status = ntQueryInformationProcess(
                process,
                0,
                &processInfo,
                sizeof(processInfo),
                nullptr);

            if (status < 0 || processInfo.PebBaseAddress == nullptr)
            {
                return std::nullopt;
            }

            SIZE_T bytesRead = 0;
            PebPartial peb = {};
            if (ReadProcessMemory(process, processInfo.PebBaseAddress, &peb, sizeof(peb), &bytesRead) == FALSE ||
                peb.ProcessParameters == nullptr)
            {
                return std::nullopt;
            }

            RtlUserProcessParametersPartial parameters = {};
            if (ReadProcessMemory(process, peb.ProcessParameters, &parameters, sizeof(parameters), &bytesRead) == FALSE)
            {
                return std::nullopt;
            }

            const UnicodeStringRemote& commandLine = parameters.CommandLine;
            if (commandLine.Length == 0)
            {
                return std::wstring();
            }

            constexpr USHORT maxCommandLineBytes = 64 * 1024 - sizeof(wchar_t);
            if (commandLine.Buffer == nullptr || commandLine.Length > maxCommandLineBytes)
            {
                return std::nullopt;
            }

            std::vector<wchar_t> buffer((commandLine.Length / sizeof(wchar_t)) + 1);
            if (ReadProcessMemory(process, commandLine.Buffer, buffer.data(), commandLine.Length, &bytesRead) == FALSE)
            {
                return std::nullopt;
            }

            buffer[commandLine.Length / sizeof(wchar_t)] = L'\0';
            return std::wstring(buffer.data(), commandLine.Length / sizeof(wchar_t));
        }

        void PopulateProcessDetails(ProcessInfo& info)
        {
            DWORD sessionId = 0;
            if (ProcessIdToSessionId(info.pid, &sessionId) != FALSE)
            {
                info.sessionId = static_cast<std::uint32_t>(sessionId);
            }

            HANDLE queryHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, info.pid);
            if (queryHandle != nullptr)
            {
                info.executablePath = QueryExecutablePath(queryHandle);
                info.architecture = QueryArchitecture(queryHandle);
                QueryCreationTime(queryHandle, info);
                CloseHandle(queryHandle);
            }

            HANDLE readHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, info.pid);
            if (readHandle != nullptr)
            {
                const std::optional<std::wstring> commandLine = QueryCommandLine(readHandle);
                if (commandLine.has_value())
                {
                    info.commandLine = commandLine.value();
                    info.commandLineAccessible = true;
                }
                CloseHandle(readHandle);
            }
        }
    }

    ProcessSnapshot CollectProcessSnapshot()
    {
        ProcessSnapshot snapshot;

        HANDLE toolhelp = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (toolhelp == INVALID_HANDLE_VALUE)
        {
            return snapshot;
        }

        PROCESSENTRY32W entry = {};
        entry.dwSize = sizeof(entry);

        if (Process32FirstW(toolhelp, &entry) != FALSE)
        {
            do
            {
                ProcessInfo info;
                info.pid = static_cast<std::uint32_t>(entry.th32ProcessID);
                info.parentPid = static_cast<std::uint32_t>(entry.th32ParentProcessID);
                info.name = entry.szExeFile;
                PopulateProcessDetails(info);
                snapshot.processes.push_back(std::move(info));
            } while (Process32NextW(toolhelp, &entry) != FALSE);
        }

        CloseHandle(toolhelp);

        snapshot.Reindex();
        BuildProcessTree(snapshot);
        return snapshot;
    }
}
