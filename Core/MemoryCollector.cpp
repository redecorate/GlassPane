#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "MemoryCollector.h"

#include <Windows.h>
#include <Psapi.h>

#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>

#pragma comment(lib, "Psapi.lib")

namespace GlassPane::Core
{
    namespace
    {
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

        std::wstring HexAddress(std::uint64_t value)
        {
            std::wstringstream stream;
            stream << L"0x" << std::uppercase << std::hex << value;
            return stream.str();
        }

        std::wstring SizeText(std::uint64_t bytes)
        {
            constexpr std::uint64_t KiB = 1024ULL;
            constexpr std::uint64_t MiB = KiB * 1024ULL;
            constexpr std::uint64_t GiB = MiB * 1024ULL;

            std::wstringstream stream;
            stream << std::fixed << std::setprecision(1);
            if (bytes >= GiB)
            {
                stream << (static_cast<double>(bytes) / static_cast<double>(GiB)) << L" GiB";
            }
            else if (bytes >= MiB)
            {
                stream << (static_cast<double>(bytes) / static_cast<double>(MiB)) << L" MiB";
            }
            else if (bytes >= KiB)
            {
                stream << (static_cast<double>(bytes) / static_cast<double>(KiB)) << L" KiB";
            }
            else
            {
                stream.str(L"");
                stream.clear();
                stream << bytes << L" B";
            }
            return stream.str();
        }

        std::wstring StateName(DWORD state)
        {
            switch (state)
            {
            case MEM_COMMIT:
                return L"Commit";
            case MEM_RESERVE:
                return L"Reserve";
            case MEM_FREE:
                return L"Free";
            default:
                return state == 0 ? L"(none)" : L"Unknown";
            }
        }

        std::wstring TypeName(DWORD type)
        {
            switch (type)
            {
            case MEM_IMAGE:
                return L"Image";
            case MEM_MAPPED:
                return L"Mapped";
            case MEM_PRIVATE:
                return L"Private";
            default:
                return type == 0 ? L"(none)" : L"Unknown";
            }
        }

        std::wstring BaseProtectionName(DWORD protect)
        {
            switch (protect & 0xffU)
            {
            case PAGE_NOACCESS:
                return L"NoAccess";
            case PAGE_READONLY:
                return L"R";
            case PAGE_READWRITE:
                return L"RW";
            case PAGE_WRITECOPY:
                return L"WC";
            case PAGE_EXECUTE:
                return L"X";
            case PAGE_EXECUTE_READ:
                return L"RX";
            case PAGE_EXECUTE_READWRITE:
                return L"RWX";
            case PAGE_EXECUTE_WRITECOPY:
                return L"XWC";
            default:
                return protect == 0 ? L"(none)" : L"Unknown";
            }
        }

        std::wstring ProtectionName(DWORD protect)
        {
            std::wstring text = BaseProtectionName(protect);
            if ((protect & PAGE_GUARD) != 0)
            {
                text += L" | Guard";
            }
            if ((protect & PAGE_NOCACHE) != 0)
            {
                text += L" | NoCache";
            }
            if ((protect & PAGE_WRITECOMBINE) != 0)
            {
                text += L" | WriteCombine";
            }
            return text;
        }

        bool IsReadableProtection(DWORD protect)
        {
            switch (protect & 0xffU)
            {
            case PAGE_READONLY:
            case PAGE_READWRITE:
            case PAGE_WRITECOPY:
            case PAGE_EXECUTE_READ:
            case PAGE_EXECUTE_READWRITE:
            case PAGE_EXECUTE_WRITECOPY:
                return true;
            default:
                return false;
            }
        }

        bool IsWritableProtection(DWORD protect)
        {
            switch (protect & 0xffU)
            {
            case PAGE_READWRITE:
            case PAGE_EXECUTE_READWRITE:
                return true;
            default:
                return false;
            }
        }

        bool IsExecutableProtection(DWORD protect)
        {
            switch (protect & 0xffU)
            {
            case PAGE_EXECUTE:
            case PAGE_EXECUTE_READ:
            case PAGE_EXECUTE_READWRITE:
            case PAGE_EXECUTE_WRITECOPY:
                return true;
            default:
                return false;
            }
        }

        bool IsCopyOnWriteProtection(DWORD protect)
        {
            switch (protect & 0xffU)
            {
            case PAGE_WRITECOPY:
            case PAGE_EXECUTE_WRITECOPY:
                return true;
            default:
                return false;
            }
        }

        std::wstring QueryMappedFilePath(HANDLE process, void* baseAddress)
        {
            wchar_t buffer[MAX_PATH * 4] = {};
            const DWORD length = GetMappedFileNameW(
                process,
                baseAddress,
                buffer,
                static_cast<DWORD>(sizeof(buffer) / sizeof(buffer[0])));
            if (length == 0)
            {
                return {};
            }
            return std::wstring(buffer, length);
        }

        void AddRegionIndicators(MemoryRegionInfo& region)
        {
            if (region.stateRaw != MEM_COMMIT)
            {
                return;
            }

            if (region.isGuard)
            {
                region.indicators.push_back(L"Guard page.");
            }

            if (region.isExecutable && region.isWritable)
            {
                region.indicators.push_back(L"RWX memory region.");
            }

            if (region.isPrivate && region.isExecutable)
            {
                region.indicators.push_back(L"Private executable memory region.");
                constexpr std::uint64_t LargeExecutableRegion = 16ULL * 1024ULL * 1024ULL;
                if (region.regionSize >= LargeExecutableRegion)
                {
                    region.indicators.push_back(L"Large private executable memory region.");
                }
            }

            if (region.isExecutable && !region.isImage && !region.isMapped && region.mappedFilePath.empty())
            {
                region.indicators.push_back(L"Executable region is not backed by an image or mapped file.");
            }

            region.isSuspicious = region.isExecutable &&
                (region.isWritable || region.isPrivate || (!region.isImage && !region.isMapped && region.mappedFilePath.empty()));
        }
    }

    MemoryCollectionResult CollectMemoryRegionsForPid(std::uint32_t pid)
    {
        MemoryCollectionResult result;
        result.pid = pid;

        HANDLE process = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE,
            pid);
        if (process == nullptr)
        {
            result.statusMessage = L"Could not open process for memory metadata: " + WindowsErrorMessage(GetLastError()) + L".";
            return result;
        }

        SYSTEM_INFO systemInfo = {};
        GetNativeSystemInfo(&systemInfo);

        std::uintptr_t address = reinterpret_cast<std::uintptr_t>(systemInfo.lpMinimumApplicationAddress);
        const std::uintptr_t maxAddress = reinterpret_cast<std::uintptr_t>(systemInfo.lpMaximumApplicationAddress);

        while (address < maxAddress)
        {
            MEMORY_BASIC_INFORMATION info = {};
            const SIZE_T bytesReturned = VirtualQueryEx(
                process,
                reinterpret_cast<LPCVOID>(address),
                &info,
                sizeof(info));
            if (bytesReturned == 0)
            {
                const DWORD error = GetLastError();
                if (result.regions.empty())
                {
                    result.statusMessage = L"VirtualQueryEx failed: " + WindowsErrorMessage(error) + L".";
                }
                else
                {
                    result.statusMessage = L"Memory enumeration stopped early: " + WindowsErrorMessage(error) + L".";
                }
                break;
            }

            MemoryRegionInfo region;
            region.baseAddress = reinterpret_cast<std::uint64_t>(info.BaseAddress);
            region.baseAddressString = HexAddress(region.baseAddress);
            region.allocationBase = reinterpret_cast<std::uint64_t>(info.AllocationBase);
            region.allocationBaseString = HexAddress(region.allocationBase);
            region.regionSize = static_cast<std::uint64_t>(info.RegionSize);
            region.regionSizeString = SizeText(region.regionSize);
            region.stateRaw = info.State;
            region.stateName = StateName(info.State);
            region.typeRaw = info.Type;
            region.typeName = TypeName(info.Type);
            region.protectRaw = info.Protect;
            region.protectName = ProtectionName(info.Protect);
            region.allocationProtectRaw = info.AllocationProtect;
            region.allocationProtectName = ProtectionName(info.AllocationProtect);
            region.isReadable = IsReadableProtection(info.Protect);
            region.isWritable = IsWritableProtection(info.Protect);
            region.isExecutable = IsExecutableProtection(info.Protect);
            region.isCopyOnWrite = IsCopyOnWriteProtection(info.Protect);
            region.isGuard = (info.Protect & PAGE_GUARD) != 0;
            region.isPrivate = info.Type == MEM_PRIVATE;
            region.isImage = info.Type == MEM_IMAGE;
            region.isMapped = info.Type == MEM_MAPPED;
            if (info.State == MEM_COMMIT && (region.isImage || region.isMapped))
            {
                region.mappedFilePath = QueryMappedFilePath(process, info.BaseAddress);
            }
            AddRegionIndicators(region);

            result.regions.push_back(std::move(region));

            const std::uintptr_t nextAddress =
                reinterpret_cast<std::uintptr_t>(info.BaseAddress) + info.RegionSize;
            if (nextAddress <= address)
            {
                break;
            }
            address = nextAddress;
        }

        CloseHandle(process);

        result.totalRegions = result.regions.size();
        for (const MemoryRegionInfo& region : result.regions)
        {
            if (region.isExecutable)
            {
                ++result.executableRegions;
            }
            if (region.isPrivate && region.isExecutable)
            {
                ++result.privateExecutableRegions;
            }
            if (region.isExecutable && region.isWritable)
            {
                ++result.rwxRegions;
            }
            if (region.isSuspicious)
            {
                ++result.suspiciousRegions;
            }
            if (region.isGuard)
            {
                ++result.guardRegions;
            }
        }

        result.success = !result.regions.empty() || result.statusMessage.empty();
        if (result.statusMessage.empty())
        {
            result.statusMessage =
                L"Loaded " + std::to_wstring(result.regions.size()) + L" memory region(s).";
        }
        return result;
    }
}
