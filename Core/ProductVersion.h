#pragma once

// Keep these macros C/resource-compiler compatible. GlassPane.rc and the C++
// presentation/export paths intentionally share this single version source.
#define GLASSPANE_VERSION_MAJOR 0
#define GLASSPANE_VERSION_MINOR 8
#define GLASSPANE_VERSION_PATCH 0
#define GLASSPANE_VERSION_REVISION 0
#define GLASSPANE_VERSION_NUMERIC 0,8,0,0

#define GLASSPANE_FILE_VERSION_STRING "0.8.0.0"
#define GLASSPANE_PRODUCT_VERSION_STRING "0.8.0.0"
#define GLASSPANE_BASE_VERSION_STRING "V0.8.0"
#define GLASSPANE_DEBUG_DISPLAY_VERSION_STRING "V0.8.0-Debug"
#define GLASSPANE_RELEASE_DISPLAY_VERSION_STRING "V0.8.0-Release"

#ifdef __cplusplus

#include <cstdint>

namespace GlassPane::Core::ProductVersion
{
    inline constexpr std::uint32_t Major = GLASSPANE_VERSION_MAJOR;
    inline constexpr std::uint32_t Minor = GLASSPANE_VERSION_MINOR;
    inline constexpr std::uint32_t Patch = GLASSPANE_VERSION_PATCH;
    inline constexpr std::uint32_t Revision = GLASSPANE_VERSION_REVISION;

    inline constexpr char FileVersionString[] = GLASSPANE_FILE_VERSION_STRING;
    inline constexpr char ProductVersionString[] =
        GLASSPANE_PRODUCT_VERSION_STRING;
    inline constexpr char BaseVersion[] = GLASSPANE_BASE_VERSION_STRING;
    inline constexpr char DebugDisplayVersion[] =
        GLASSPANE_DEBUG_DISPLAY_VERSION_STRING;
    inline constexpr char ReleaseDisplayVersion[] =
        GLASSPANE_RELEASE_DISPLAY_VERSION_STRING;

#ifdef _DEBUG
    inline constexpr char CurrentDisplayVersion[] =
        GLASSPANE_DEBUG_DISPLAY_VERSION_STRING;
#else
    inline constexpr char CurrentDisplayVersion[] =
        GLASSPANE_RELEASE_DISPLAY_VERSION_STRING;
#endif
}

#endif
