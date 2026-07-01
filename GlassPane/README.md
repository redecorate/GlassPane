# GlassPane

GlassPane v0.1 is a Windows-first, read-only process relationship visualizer for security research.

## Features

- Native Win32 desktop UI with a process table and details pane
- Optional Dear ImGui + DirectX 11 UI shell, enabled only when Dear ImGui is added locally
- Focused Graph View panel with selected-process ancestry, children, and grandchildren
- Timeline View sorted by process start time
- Chain Summary details with root-to-process ancestry and chain indicators
- Copy Chain button for the selected process ancestry
- Selected-process module/DLL inspection with module indicators
- Selected-process details export with modules
- Refreshable process snapshot
- Search/filter box
- Suspicious-only view with Low, Medium, and High severity filters
- Parent-child process tree ordering
- JSON export of the current snapshot
- Read-only Windows API process inspection

## Collected Fields

- PID
- Parent PID
- Process name
- Executable path, when accessible
- Command line, when accessible
- Session ID
- Process architecture
- Process start time, when accessible
- Placeholder suspicious-rule reasons
- Severity, indicators, and context notes
- Parent chain, chain severity, and chain indicators
- Selected process modules: name, path, base address, image size, readability, and module indicators

The Graph View uses a simple hierarchical GDI layout. Click a process node to select it and update the details pane. Use `Focus selected` to rebuild and recenter the graph around the currently selected process. The selected process ancestry is emphasized with thicker blue edges.

The Timeline View is available in the bottom tab panel. It lists processes by start time and supports `All`, `Suspicious only`, and `High severity only` filters. Clicking a timeline row selects that process in the table, details panel, and graph.

Module inspection is scoped to the selected process. Click `Refresh Modules` in the details header to enumerate DLLs for the selected process, then use `Export Selected` to write selected process details plus the current module list. Full snapshot export does not enumerate modules for every process.

## Build

Requirements:

- Visual Studio with the Desktop development with C++ workload
- Windows 10 SDK or newer
- C++17-capable MSVC toolset

Steps:

1. Open `GlassPane.slnx` or `GlassPane.vcxproj` in Visual Studio.
2. Select `x64` and `Debug` or `Release`.
3. Build and run `GlassPane`.

Command-line build example:

```powershell
& "C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\amd64\MSBuild.exe" GlassPane.vcxproj /p:Configuration=Release /p:Platform=x64
```

The x64 build is recommended for best command-line collection coverage on 64-bit Windows. The application runs as the current user and does not enable debug privileges; protected processes and higher-integrity processes may hide paths or command lines.

## Optional Dear ImGui UI

The project includes a guarded ImGui + DirectX 11 UI layer in `UI/ImGuiApp.*`, `UI/ImGuiMain.cpp`, and `UI/Theme.*`. Dear ImGui is not vendored in this repository. The existing Win32 UI remains the default build when `GLASSPANE_ENABLE_IMGUI` is not defined.

To enable the ImGui UI:

1. Add Dear ImGui under `third_party/imgui`. The docking branch enables dockable panels; the UI falls back to ordinary ImGui windows when docking symbols are not available.
2. Ensure these files exist:
   - `third_party/imgui/imgui.h`
   - `third_party/imgui/imconfig.h`
   - `third_party/imgui/imgui_internal.h`
   - `third_party/imgui/imstb_rectpack.h`
   - `third_party/imgui/imstb_textedit.h`
   - `third_party/imgui/imstb_truetype.h`
   - `third_party/imgui/imgui.cpp`
   - `third_party/imgui/imgui_draw.cpp`
   - `third_party/imgui/imgui_tables.cpp`
   - `third_party/imgui/imgui_widgets.cpp`
   - `third_party/imgui/imgui_internal.h`
   - `third_party/imgui/backends/imgui_impl_win32.h`
   - `third_party/imgui/backends/imgui_impl_win32.cpp`
   - `third_party/imgui/backends/imgui_impl_dx11.h`
   - `third_party/imgui/backends/imgui_impl_dx11.cpp`
3. Add the six ImGui `.cpp` files above to the Visual Studio project.
4. Add `GLASSPANE_ENABLE_IMGUI` to the active configuration's preprocessor definitions.
5. Build `x64 Debug`.

Leave `GLASSPANE_ENABLE_IMGUI` undefined to build and run the existing native Win32 UI.

## Suspicious Placeholder Rules

- Office process spawning `cmd.exe` or `powershell.exe`
- Script host spawning `cmd.exe` or `powershell.exe`
- Executable path under `Temp` or `AppData`
- PowerShell command line containing `-enc` or `-encodedcommand`

PowerShell encoded-command severity is context aware:

- `Medium` by default
- `Low` when launched by `codex.exe`, with a developer-tooling context note
- `High` when launched by Office, browsers, script hosts, or `rundll32.exe`

Chain severity is the maximum severity seen in the root-to-selected-process ancestry, with chain-specific escalation for patterns such as Office spawning a shell, browser spawning a script interpreter, script host launching a LOLBin, and encoded PowerShell appearing in ancestry.
