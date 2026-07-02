#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "../Core/ProcessInfo.h"
#include "../Core/ModuleInfo.h"
#include "../Core/TimelineModel.h"
#include "TreeViewPanel.h"

#include <Windows.h>

#include <cstddef>
#include <string>
#include <vector>

namespace GlassPane::UI
{
    int RunApp(HINSTANCE instance, int showCommand);

    class MainWindow
    {
    public:
        MainWindow() = default;

        bool Create(HINSTANCE instance, int showCommand);
        int MessageLoop();

    private:
        struct VisibleProcess
        {
            std::size_t processIndex = 0;
            std::size_t depth = 0;
        };

        static LRESULT CALLBACK WindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
        LRESULT HandleMessage(UINT message, WPARAM wParam, LPARAM lParam);

        void OnCreate();
        void OnCommand(WPARAM wParam, LPARAM lParam);
        void OnNotify(LPARAM lParam);
        void OnSize(int width, int height);
        void RefreshSnapshot();
        void RebuildProcessList();
        void RebuildTimelineList();
        void UpdateDetails();
        void UpdateGraphView(bool focusSelected);
        void UpdateBottomPanelVisibility();
        void ExportSnapshot();
        void ExportSelectedDetails();
        void CopySelectedChainToClipboard();
        void RefreshSelectedModules();
        void SelectProcess(std::uint32_t pid, bool selectInList, bool focusGraph);
        bool SelectListItemByPid(std::uint32_t pid);
        bool SelectTimelineItemByPid(std::uint32_t pid);

        std::wstring GetSearchText() const;
        bool SeverityAllowed(Core::Severity severity) const;
        Core::TimelineFilter CurrentTimelineFilter() const;
        bool MatchesCurrentFilter(const Core::ProcessInfo& process, const std::wstring& filter) const;
        std::wstring BuildDetailsText(const Core::ProcessInfo& process) const;
        const Core::ProcessInfo* FindProcess(std::uint32_t pid) const;

        HINSTANCE instance_ = nullptr;
        HWND hwnd_ = nullptr;
        HWND refreshButton_ = nullptr;
        HWND exportButton_ = nullptr;
        HWND focusGraphButton_ = nullptr;
        HWND copyChainButton_ = nullptr;
        HWND refreshModulesButton_ = nullptr;
        HWND exportSelectedButton_ = nullptr;
        HWND searchLabel_ = nullptr;
        HWND bottomTab_ = nullptr;
        HWND searchEdit_ = nullptr;
        HWND suspiciousOnlyCheck_ = nullptr;
        HWND lowSeverityCheck_ = nullptr;
        HWND mediumSeverityCheck_ = nullptr;
        HWND highSeverityCheck_ = nullptr;
        HWND timelineAllRadio_ = nullptr;
        HWND timelineSuspiciousRadio_ = nullptr;
        HWND timelineHighRadio_ = nullptr;
        HWND timelineListView_ = nullptr;
        HWND listView_ = nullptr;
        HWND detailsEdit_ = nullptr;
        HWND statusText_ = nullptr;
        HFONT uiFont_ = nullptr;
        TreeViewPanel treeViewPanel_;

        Core::ProcessSnapshot snapshot_;
        std::vector<VisibleProcess> visibleProcesses_;
        Core::ModuleCollectionResult selectedModules_;
        std::uint32_t selectedModulesPid_ = 0;
        bool selectedModulesLoaded_ = false;
        std::uint32_t selectedPid_ = 0;
        bool suppressListSelectionEvents_ = false;
        bool suppressTimelineSelectionEvents_ = false;
    };
}
