#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "RuntimeCollector.h"

#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <winternl.h>

#include <algorithm>
#include <iomanip>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#pragma comment(lib, "Psapi.lib")

namespace GlassPane::Core
{
    namespace
    {
        using NtQueryInformationThreadFn = NTSTATUS (NTAPI*)(
            HANDLE,
            THREADINFOCLASS,
            PVOID,
            ULONG,
            PULONG);

        struct ModuleRange
        {
            std::uintptr_t base = 0;
            std::uintptr_t end = 0;
            std::wstring name;
        };

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

        std::uint64_t FileTimeToUInt64(const FILETIME& fileTime)
        {
            ULARGE_INTEGER value = {};
            value.LowPart = fileTime.dwLowDateTime;
            value.HighPart = fileTime.dwHighDateTime;
            return value.QuadPart;
        }

        std::wstring DurationText(std::uint64_t fileTime100ns)
        {
            const std::uint64_t totalMilliseconds = fileTime100ns / 10000ULL;
            const std::uint64_t milliseconds = totalMilliseconds % 1000ULL;
            const std::uint64_t totalSeconds = totalMilliseconds / 1000ULL;
            const std::uint64_t seconds = totalSeconds % 60ULL;
            const std::uint64_t totalMinutes = totalSeconds / 60ULL;
            const std::uint64_t minutes = totalMinutes % 60ULL;
            const std::uint64_t hours = totalMinutes / 60ULL;

            std::wstringstream stream;
            stream << hours << L":"
                   << std::setw(2) << std::setfill(L'0') << minutes << L":"
                   << std::setw(2) << std::setfill(L'0') << seconds << L"."
                   << std::setw(3) << std::setfill(L'0') << milliseconds;
            return stream.str();
        }

        std::wstring HexMask(std::uint64_t value)
        {
            std::wstringstream stream;
            stream << L"0x" << std::uppercase << std::hex << value;
            return stream.str();
        }

        std::wstring PointerHex(std::uintptr_t value)
        {
            if (value == 0)
            {
                return L"Unavailable";
            }

            std::wstringstream stream;
            stream << L"0x" << std::uppercase << std::hex << value;
            return stream.str();
        }

        std::wstring PriorityClassName(DWORD priorityClass)
        {
            switch (priorityClass)
            {
            case IDLE_PRIORITY_CLASS:
                return L"Idle";
            case BELOW_NORMAL_PRIORITY_CLASS:
                return L"Below Normal";
            case NORMAL_PRIORITY_CLASS:
                return L"Normal";
            case ABOVE_NORMAL_PRIORITY_CLASS:
                return L"Above Normal";
            case HIGH_PRIORITY_CLASS:
                return L"High";
            case REALTIME_PRIORITY_CLASS:
                return L"Realtime";
            default:
                return priorityClass == 0 ? L"Unavailable" : L"Unknown";
            }
        }

        std::wstring MachineArchitecture(USHORT machine)
        {
            switch (machine)
            {
            case IMAGE_FILE_MACHINE_AMD64:
                return L"x64";
            case IMAGE_FILE_MACHINE_I386:
                return L"x86";
            case IMAGE_FILE_MACHINE_ARM64:
                return L"ARM64";
            case IMAGE_FILE_MACHINE_ARMNT:
                return L"ARM";
            case IMAGE_FILE_MACHINE_UNKNOWN:
                return L"Native";
            default:
                return L"Unknown";
            }
        }

        void AppendError(RuntimeInfo& runtime, const std::wstring& message)
        {
            if (message.empty())
            {
                return;
            }

            if (!runtime.errorMessage.empty())
            {
                runtime.errorMessage += L" ";
            }
            runtime.errorMessage += message;
        }

        void PopulateBasePriority(RuntimeInfo& runtime)
        {
            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snapshot == INVALID_HANDLE_VALUE)
            {
                AppendError(runtime, L"Could not inspect process base priority: " + WindowsErrorMessage(GetLastError()) + L".");
                return;
            }

            PROCESSENTRY32W entry = {};
            entry.dwSize = sizeof(entry);
            if (Process32FirstW(snapshot, &entry) != FALSE)
            {
                do
                {
                    if (entry.th32ProcessID == runtime.processId)
                    {
                        runtime.basePriority = entry.pcPriClassBase;
                        CloseHandle(snapshot);
                        return;
                    }
                } while (Process32NextW(snapshot, &entry) != FALSE);
            }

            CloseHandle(snapshot);
        }

        std::vector<ModuleRange> CollectModuleRanges(std::uint32_t pid)
        {
            std::vector<ModuleRange> ranges;
            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
            if (snapshot == INVALID_HANDLE_VALUE)
            {
                return ranges;
            }

            MODULEENTRY32W module = {};
            module.dwSize = sizeof(module);
            if (Module32FirstW(snapshot, &module) != FALSE)
            {
                do
                {
                    const std::uintptr_t base = reinterpret_cast<std::uintptr_t>(module.modBaseAddr);
                    ModuleRange range;
                    range.base = base;
                    range.end = base + static_cast<std::uintptr_t>(module.modBaseSize);
                    range.name = module.szModule;
                    ranges.push_back(std::move(range));
                } while (Module32NextW(snapshot, &module) != FALSE);
            }

            CloseHandle(snapshot);
            return ranges;
        }

        std::wstring ResolveModuleForAddress(
            const std::vector<ModuleRange>& modules,
            std::uintptr_t address)
        {
            if (address == 0)
            {
                return {};
            }

            for (const ModuleRange& module : modules)
            {
                if (address >= module.base && address < module.end)
                {
                    return module.name;
                }
            }

            return {};
        }

        NtQueryInformationThreadFn ResolveNtQueryInformationThread()
        {
            HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
            if (ntdll == nullptr)
            {
                return nullptr;
            }

            return reinterpret_cast<NtQueryInformationThreadFn>(
                GetProcAddress(ntdll, "NtQueryInformationThread"));
        }

        HANDLE OpenThreadForQuery(std::uint32_t threadId)
        {
            HANDLE threadHandle = OpenThread(
                THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION,
                FALSE,
                threadId);
            if (threadHandle != nullptr)
            {
                return threadHandle;
            }

            return OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, threadId);
        }

        std::vector<ThreadInfo> CollectThreads(std::uint32_t pid)
        {
            std::vector<ThreadInfo> threads;
            const std::vector<ModuleRange> modules = CollectModuleRanges(pid);
            NtQueryInformationThreadFn queryThread = ResolveNtQueryInformationThread();

            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (snapshot == INVALID_HANDLE_VALUE)
            {
                ThreadInfo errorThread;
                errorThread.ownerProcessId = pid;
                errorThread.errorMessage = L"Could not create thread snapshot: " + WindowsErrorMessage(GetLastError()) + L".";
                threads.push_back(std::move(errorThread));
                return threads;
            }

            THREADENTRY32 entry = {};
            entry.dwSize = sizeof(entry);
            if (Thread32First(snapshot, &entry) == FALSE)
            {
                CloseHandle(snapshot);
                return threads;
            }

            do
            {
                if (entry.th32OwnerProcessID != pid)
                {
                    continue;
                }

                ThreadInfo thread;
                thread.threadId = entry.th32ThreadID;
                thread.ownerProcessId = entry.th32OwnerProcessID;
                thread.basePriority = entry.tpBasePri;
                thread.state = L"Unavailable";

                HANDLE threadHandle = OpenThreadForQuery(thread.threadId);
                if (threadHandle == nullptr)
                {
                    thread.errorMessage = L"Thread metadata unavailable: " + WindowsErrorMessage(GetLastError()) + L".";
                    threads.push_back(std::move(thread));
                    continue;
                }

                const int currentPriority = GetThreadPriority(threadHandle);
                if (currentPriority != THREAD_PRIORITY_ERROR_RETURN)
                {
                    thread.currentPriority = currentPriority;
                    thread.hasCurrentPriority = true;
                }

                if (queryThread != nullptr)
                {
                    PVOID startAddress = nullptr;
                    const NTSTATUS status = queryThread(
                        threadHandle,
                        static_cast<THREADINFOCLASS>(9),
                        &startAddress,
                        sizeof(startAddress),
                        nullptr);
                    if (status >= 0 && startAddress != nullptr)
                    {
                        const std::uintptr_t address = reinterpret_cast<std::uintptr_t>(startAddress);
                        thread.startAddress = PointerHex(address);
                        thread.startAddressResolvedModule = ResolveModuleForAddress(modules, address);
                    }
                    else
                    {
                        thread.startAddress = L"Unavailable";
                    }
                }
                else
                {
                    thread.startAddress = L"Unavailable";
                }

                if (thread.errorMessage.empty() && !thread.hasCurrentPriority && thread.startAddress == L"Unavailable")
                {
                    thread.errorMessage = L"Thread metadata partially unavailable.";
                }

                CloseHandle(threadHandle);
                threads.push_back(std::move(thread));
            } while (Thread32Next(snapshot, &entry) != FALSE);

            CloseHandle(snapshot);
            return threads;
        }

        void PopulateProcessorGroup(HANDLE processHandle, RuntimeInfo& runtime)
        {
            using GetProcessGroupAffinityFn = BOOL (WINAPI*)(HANDLE, PUSHORT, PUSHORT);
            HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
            const auto getProcessGroupAffinity = kernel32 == nullptr
                ? nullptr
                : reinterpret_cast<GetProcessGroupAffinityFn>(GetProcAddress(kernel32, "GetProcessGroupAffinity"));
            if (getProcessGroupAffinity == nullptr)
            {
                runtime.processorGroup = L"Unavailable";
                return;
            }

            USHORT groupCount = 0;
            if (getProcessGroupAffinity(processHandle, &groupCount, nullptr) != FALSE || groupCount == 0)
            {
                runtime.processorGroup = L"Default";
                return;
            }

            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            {
                runtime.processorGroup = L"Unavailable";
                return;
            }

            std::vector<USHORT> groups(groupCount);
            if (getProcessGroupAffinity(processHandle, &groupCount, groups.data()) == FALSE)
            {
                runtime.processorGroup = L"Unavailable";
                return;
            }

            if (groupCount == 1)
            {
                runtime.processorGroup = L"Group " + std::to_wstring(groups.front());
            }
            else
            {
                runtime.processorGroup = L"Multiple groups (" + std::to_wstring(groupCount) + L")";
            }
        }

        void PopulateArchitecture(HANDLE processHandle, const ProcessInfo& process, RuntimeInfo& runtime)
        {
            using IsWow64Process2Fn = BOOL (WINAPI*)(HANDLE, USHORT*, USHORT*);
            HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
            const auto isWow64Process2 = kernel32 == nullptr
                ? nullptr
                : reinterpret_cast<IsWow64Process2Fn>(GetProcAddress(kernel32, "IsWow64Process2"));

            if (isWow64Process2 != nullptr)
            {
                USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
                USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
                if (isWow64Process2(processHandle, &processMachine, &nativeMachine) != FALSE)
                {
                    runtime.isWow64 = processMachine != IMAGE_FILE_MACHINE_UNKNOWN;
                    runtime.architecture = runtime.isWow64
                        ? MachineArchitecture(processMachine) + L" on " + MachineArchitecture(nativeMachine)
                        : MachineArchitecture(nativeMachine);
                    return;
                }
            }

            BOOL wow64 = FALSE;
            if (IsWow64Process(processHandle, &wow64) != FALSE)
            {
                runtime.isWow64 = wow64 != FALSE;
                if (runtime.isWow64)
                {
                    runtime.architecture = L"x86 on native Windows";
                    return;
                }
            }

            runtime.architecture = process.architecture.empty() ? L"Unknown" : process.architecture;
        }

    }

    RuntimeInfo CollectProcessRuntimeInfo(const ProcessInfo& process)
    {
        RuntimeInfo runtime;
        runtime.processId = process.pid;
        runtime.architecture = process.architecture.empty() ? L"Unknown" : process.architecture;

        HANDLE processHandle = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_QUERY_INFORMATION,
            FALSE,
            process.pid);
        if (processHandle == nullptr)
        {
            runtime.errorMessage = L"Could not open process for runtime inspection: " + WindowsErrorMessage(GetLastError()) + L".";
            runtime.threads = CollectThreads(process.pid);
            runtime.threadCount = static_cast<std::uint32_t>(runtime.threads.size());
            return runtime;
        }

        runtime.success = true;

        const DWORD priorityClass = GetPriorityClass(processHandle);
        runtime.priorityClassRaw = priorityClass;
        runtime.priorityClassName = PriorityClassName(priorityClass);
        if (priorityClass == 0)
        {
            AppendError(runtime, L"Could not read priority class: " + WindowsErrorMessage(GetLastError()) + L".");
        }

        PopulateBasePriority(runtime);

        DWORD_PTR processAffinity = 0;
        DWORD_PTR systemAffinity = 0;
        if (GetProcessAffinityMask(processHandle, &processAffinity, &systemAffinity) != FALSE)
        {
            runtime.processAffinityMask = static_cast<std::uint64_t>(processAffinity);
            runtime.systemAffinityMask = static_cast<std::uint64_t>(systemAffinity);
            runtime.affinityMaskString =
                HexMask(runtime.processAffinityMask) + L" / system " + HexMask(runtime.systemAffinityMask);
        }
        else
        {
            runtime.affinityMaskString = L"Unavailable";
            AppendError(runtime, L"Could not read process affinity: " + WindowsErrorMessage(GetLastError()) + L".");
        }

        PopulateProcessorGroup(processHandle, runtime);

        FILETIME createTime = {};
        FILETIME exitTime = {};
        FILETIME kernelTime = {};
        FILETIME userTime = {};
        if (GetProcessTimes(processHandle, &createTime, &exitTime, &kernelTime, &userTime) != FALSE)
        {
            runtime.userCpuTime100ns = FileTimeToUInt64(userTime);
            runtime.kernelCpuTime100ns = FileTimeToUInt64(kernelTime);
            runtime.totalCpuTime100ns = runtime.userCpuTime100ns + runtime.kernelCpuTime100ns;
            runtime.userCpuTime = DurationText(runtime.userCpuTime100ns);
            runtime.kernelCpuTime = DurationText(runtime.kernelCpuTime100ns);
            runtime.totalCpuTime = DurationText(runtime.totalCpuTime100ns);
        }
        else
        {
            AppendError(runtime, L"Could not read process CPU time: " + WindowsErrorMessage(GetLastError()) + L".");
        }

        DWORD handleCount = 0;
        if (GetProcessHandleCount(processHandle, &handleCount) != FALSE)
        {
            runtime.handleCount = handleCount;
        }
        else
        {
            AppendError(runtime, L"Could not read process handle count: " + WindowsErrorMessage(GetLastError()) + L".");
        }

        PROCESS_MEMORY_COUNTERS_EX memory = {};
        memory.cb = sizeof(memory);
        if (GetProcessMemoryInfo(processHandle, reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&memory), sizeof(memory)) != FALSE)
        {
            runtime.workingSetSize = static_cast<std::uint64_t>(memory.WorkingSetSize);
            runtime.peakWorkingSetSize = static_cast<std::uint64_t>(memory.PeakWorkingSetSize);
            runtime.privateBytes = static_cast<std::uint64_t>(memory.PrivateUsage);
            runtime.pagefileUsage = static_cast<std::uint64_t>(memory.PagefileUsage);
            runtime.peakPagefileUsage = static_cast<std::uint64_t>(memory.PeakPagefileUsage);
        }
        else
        {
            AppendError(runtime, L"Could not read process memory counters: " + WindowsErrorMessage(GetLastError()) + L".");
        }

        PopulateArchitecture(processHandle, process, runtime);
        runtime.threads = CollectThreads(process.pid);
        runtime.threadCount = static_cast<std::uint32_t>(runtime.threads.size());

        CloseHandle(processHandle);
        return runtime;
    }
}
