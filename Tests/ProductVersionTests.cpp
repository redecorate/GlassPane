#include "Core/ProductVersion.h"

#include <iostream>
#include <string_view>

namespace GlassPane::Tests
{
    namespace
    {
        int failures = 0;

        void Check(bool condition, const wchar_t* message)
        {
            if (!condition)
            {
                ++failures;
                std::wcerr << L"FAIL: " << message << L'\n';
            }
        }

        void TestProductVersionNumbersAndStrings()
        {
            using namespace Core::ProductVersion;
            static_assert(Major == 0);
            static_assert(Minor == 8);
            static_assert(Patch == 0);
            static_assert(Revision == 0);
            static_assert(std::string_view(FileVersionString) == "0.8.0.0");
            static_assert(
                std::string_view(ProductVersionString) == "0.8.0.0");
            static_assert(std::string_view(BaseVersion) == "V0.8.0");

            Check(Major == 0 && Minor == 8 && Patch == 0 && Revision == 0,
                L"product version numeric components are 0.8.0.0");
            Check(std::string_view(BaseVersion) == "V0.8.0",
                L"product base display version is V0.8.0");
        }

        void TestConfigurationDisplayVersions()
        {
            using namespace Core::ProductVersion;
            static_assert(
                std::string_view(DebugDisplayVersion) == "V0.8.0-Debug");
            static_assert(
                std::string_view(ReleaseDisplayVersion) == "V0.8.0-Release");

            Check(std::string_view(DebugDisplayVersion) == "V0.8.0-Debug",
                L"Debug display version follows the release convention");
            Check(std::string_view(ReleaseDisplayVersion) == "V0.8.0-Release",
                L"Release display version follows the release convention");
#ifdef _DEBUG
            Check(std::string_view(CurrentDisplayVersion) == DebugDisplayVersion,
                L"Debug binary selects the Debug display version");
#else
            Check(std::string_view(CurrentDisplayVersion) == ReleaseDisplayVersion,
                L"Release binary selects the Release display version");
#endif
        }
    }

    int RunProductVersionTests()
    {
        failures = 0;
        TestProductVersionNumbersAndStrings();
        TestConfigurationDisplayVersions();
        if (failures == 0)
        {
            std::wcout << L"Product version tests passed.\n";
        }
        return failures;
    }
}
