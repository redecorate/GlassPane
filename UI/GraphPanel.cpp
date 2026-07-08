#include "GraphPanel.h"

// This implementation file is included from ImGuiApp.cpp inside the private ImGuiApp class definition.
// Graph state and orchestration remain owned by ImGuiApp.

        void RequestGraphFit()
        {
            graphFitRequested_ = true;
            graphFitPid_ = focusedGraph_.focusPid;
        }

        void RebuildFocusedGraph(const char*)
        {
            const ULONGLONG started = GetTickCount64();
            focusedGraph_ = Core::BuildFocusedTree(snapshot_, selectedPid_, 2);
            timings_.graphLayoutMs = ElapsedMs(started);
            graphLayoutDirty_ = true;
        }

        void RebuildGraphWorldLayoutIfNeeded()
        {
            if (!graphLayoutDirty_ &&
                graphLayoutFocusPid_ == focusedGraph_.focusPid &&
                graphLayoutNodeCount_ == focusedGraph_.nodes.size() &&
                graphLayoutEdgeCount_ == focusedGraph_.edges.size() &&
                graphLayoutCachedMode_ == graphLayoutMode_)
            {
                return;
            }

            const ULONGLONG started = GetTickCount64();
            graphLayoutNodes_.clear();
            graphLayoutNodeIndexByPid_.clear();
            graphLayoutHasWorldBounds_ = false;
            graphLayoutSingleNode_ = focusedGraph_.nodes.size() == 1;
            graphLayoutSmallGraph_ = focusedGraph_.nodes.size() >= 2 && focusedGraph_.nodes.size() <= 5;
            graphLayoutBaseNodeSize_ = graphLayoutSingleNode_
                ? ImVec2(342.0f, 126.0f)
                : (graphLayoutSmallGraph_ ? ImVec2(318.0f, 112.0f) : ImVec2(302.0f, 106.0f));

            std::unordered_map<std::size_t, std::vector<std::size_t>> levels;
            std::size_t maxDepth = 0;
            for (std::size_t nodeIndex = 0; nodeIndex < focusedGraph_.nodes.size(); ++nodeIndex)
            {
                const Core::FocusedGraphNode& node = focusedGraph_.nodes[nodeIndex];
                levels[node.depth].push_back(nodeIndex);
                maxDepth = std::max(maxDepth, node.depth);
            }

            graphLayoutNodes_.resize(focusedGraph_.nodes.size());
            const float siblingSpacing = graphLayoutSingleNode_ ? 0.0f : (graphLayoutSmallGraph_ ? 170.0f : 190.0f);
            const float levelSpacing = graphLayoutMode_ == GraphLayoutMode::LeftToRight ? 166.0f : 132.0f;
            for (std::size_t depth = 0; depth <= maxDepth; ++depth)
            {
                auto level = levels.find(depth);
                if (level == levels.end())
                {
                    continue;
                }

                std::vector<std::size_t>& nodeIndexes = level->second;
                std::sort(nodeIndexes.begin(), nodeIndexes.end(), [this](std::size_t leftIndex, std::size_t rightIndex) {
                    if (leftIndex >= focusedGraph_.nodes.size() || rightIndex >= focusedGraph_.nodes.size())
                    {
                        return leftIndex < rightIndex;
                    }
                    return focusedGraph_.nodes[leftIndex].pid < focusedGraph_.nodes[rightIndex].pid;
                });

                const float count = static_cast<float>(nodeIndexes.size());
                if (graphLayoutMode_ == GraphLayoutMode::LeftToRight)
                {
                    const float totalHeight =
                        count * graphLayoutBaseNodeSize_.y + std::max(0.0f, count - 1.0f) * siblingSpacing;
                    const float startY = -totalHeight * 0.5f + graphLayoutBaseNodeSize_.y * 0.5f;
                    const float x = static_cast<float>(depth) * (graphLayoutBaseNodeSize_.x + levelSpacing);
                    for (std::size_t index = 0; index < nodeIndexes.size(); ++index)
                    {
                        const std::size_t nodeIndex = nodeIndexes[index];
                        if (nodeIndex >= graphLayoutNodes_.size())
                        {
                            continue;
                        }
                        graphLayoutNodes_[nodeIndex].nodeIndex = nodeIndex;
                        graphLayoutNodes_[nodeIndex].worldCenter = ImVec2(
                            x,
                            startY + static_cast<float>(index) * (graphLayoutBaseNodeSize_.y + siblingSpacing));
                    }
                }
                else
                {
                    const float totalWidth =
                        count * graphLayoutBaseNodeSize_.x + std::max(0.0f, count - 1.0f) * siblingSpacing;
                    const float startX = -totalWidth * 0.5f + graphLayoutBaseNodeSize_.x * 0.5f;
                    const float y = static_cast<float>(depth) * (graphLayoutBaseNodeSize_.y + levelSpacing);
                    for (std::size_t index = 0; index < nodeIndexes.size(); ++index)
                    {
                        const std::size_t nodeIndex = nodeIndexes[index];
                        if (nodeIndex >= graphLayoutNodes_.size())
                        {
                            continue;
                        }
                        graphLayoutNodes_[nodeIndex].nodeIndex = nodeIndex;
                        graphLayoutNodes_[nodeIndex].worldCenter = ImVec2(
                            startX + static_cast<float>(index) * (graphLayoutBaseNodeSize_.x + siblingSpacing),
                            y);
                    }
                }
            }

            for (std::size_t layoutIndex = 0; layoutIndex < graphLayoutNodes_.size(); ++layoutIndex)
            {
                const GraphLayoutNode& visual = graphLayoutNodes_[layoutIndex];
                if (visual.nodeIndex >= focusedGraph_.nodes.size())
                {
                    continue;
                }

                graphLayoutNodeIndexByPid_[focusedGraph_.nodes[visual.nodeIndex].pid] = layoutIndex;
                const ImVec2 min(
                    visual.worldCenter.x - graphLayoutBaseNodeSize_.x * 0.5f,
                    visual.worldCenter.y - graphLayoutBaseNodeSize_.y * 0.5f);
                const ImVec2 max(
                    visual.worldCenter.x + graphLayoutBaseNodeSize_.x * 0.5f,
                    visual.worldCenter.y + graphLayoutBaseNodeSize_.y * 0.5f);
                if (!graphLayoutHasWorldBounds_)
                {
                    graphLayoutWorldMin_ = min;
                    graphLayoutWorldMax_ = max;
                    graphLayoutHasWorldBounds_ = true;
                }
                else
                {
                    graphLayoutWorldMin_.x = std::min(graphLayoutWorldMin_.x, min.x);
                    graphLayoutWorldMin_.y = std::min(graphLayoutWorldMin_.y, min.y);
                    graphLayoutWorldMax_.x = std::max(graphLayoutWorldMax_.x, max.x);
                    graphLayoutWorldMax_.y = std::max(graphLayoutWorldMax_.y, max.y);
                }
            }

            graphLayoutFocusPid_ = focusedGraph_.focusPid;
            graphLayoutNodeCount_ = focusedGraph_.nodes.size();
            graphLayoutEdgeCount_ = focusedGraph_.edges.size();
            graphLayoutCachedMode_ = graphLayoutMode_;
            graphLayoutDirty_ = false;
            timings_.graphLayoutMs = ElapsedMs(started);
        }

        void ResetGraphView()
        {
            graphZoom_ = 1.0f;
            graphPan_ = ImVec2(0.0f, 0.0f);
            RequestGraphFit();
        }

        void RenderGraphView()
        {
            const auto clampZoom = [](float zoom) {
                return std::clamp(zoom, 0.4f, 2.5f);
            };
            const auto layoutLabel = [](GraphLayoutMode mode) {
                return mode == GraphLayoutMode::LeftToRight ? "Left To Right" : "Top Down";
            };

            const bool pushedHeadingFont = PushFontIfAvailable(fonts_.bold);
            ImGui::TextColored(AccentBlue(), "Process Graph");
            PopFontIfPushed(pushedHeadingFont);
            ImGui::SameLine();
            ImGui::TextColored(MutedText(), "focused process relationships");

            const float toolbarWidth = 612.0f;
            const float toolbarX = ImGui::GetCursorPosX() + std::max(0.0f, ImGui::GetContentRegionAvail().x - toolbarWidth);
            if (ImGui::GetContentRegionAvail().x > toolbarWidth + 12.0f)
            {
                ImGui::SameLine(toolbarX);
            }
            else
            {
                ImGui::Spacing();
            }

            if (ImGui::Button("Focus"))
            {
                RebuildFocusedGraph("graph-focus-button");
                RequestGraphFit();
                AddLog(LogLevel::Info, "Graph focused on selected process.");
            }
            ImGui::SameLine();
            if (ImGui::Button("Fit"))
            {
                RequestGraphFit();
                AddLog(LogLevel::Info, "Graph fit requested.");
            }
            ImGui::SameLine();
            if (ImGui::Button("Refresh"))
            {
                RebuildFocusedGraph("graph-refresh-button");
                RequestGraphFit();
                AddLog(LogLevel::Info, "Graph refreshed.");
            }
            ImGui::SameLine();
            ImGui::TextDisabled("Layout");
            ImGui::SameLine();
            ImGui::SetNextItemWidth(124.0f);
            if (ImGui::BeginCombo("##graph_layout", layoutLabel(graphLayoutMode_)))
            {
                const bool topDownSelected = graphLayoutMode_ == GraphLayoutMode::TopDown;
                if (ImGui::Selectable("Top Down", topDownSelected))
                {
                    graphLayoutMode_ = GraphLayoutMode::TopDown;
                    RequestGraphFit();
                }
                if (topDownSelected)
                {
                    ImGui::SetItemDefaultFocus();
                }

                const bool leftToRightSelected = graphLayoutMode_ == GraphLayoutMode::LeftToRight;
                if (ImGui::Selectable("Left To Right", leftToRightSelected))
                {
                    graphLayoutMode_ = GraphLayoutMode::LeftToRight;
                    RequestGraphFit();
                }
                if (leftToRightSelected)
                {
                    ImGui::SetItemDefaultFocus();
                }
                ImGui::EndCombo();
            }
            ImGui::SameLine();
            if (ImGui::Button("Zoom -"))
            {
                graphZoom_ = clampZoom(graphZoom_ * 0.86f);
            }
            ImGui::SameLine();
            if (ImGui::Button("Zoom +"))
            {
                graphZoom_ = clampZoom(graphZoom_ * 1.16f);
            }
            ImGui::SameLine();
            if (ImGui::Button("Reset"))
            {
                ResetGraphView();
            }
            ImGui::SameLine();
            ImGui::TextDisabled("%.0f%%", graphZoom_ * 100.0f);

            const Core::ProcessInfo* selectedGraphProcess = Core::FindProcessByPid(snapshot_, selectedPid_);
            const bool selectedHiddenByFilters = selectedGraphProcess != nullptr && !ProcessMatchesFilters(*selectedGraphProcess);

            ImGui::Spacing();
            const ImVec2 available = ImGui::GetContentRegionAvail();
            const ImVec2 childSize(std::max(available.x, 320.0f), std::max(available.y, 260.0f));
            ImGui::PushStyleColor(ImGuiCol_ChildBg, GraphCanvasBg());
            ImGui::BeginChild(
                "graph_canvas",
                childSize,
                false,
                ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
            ImGui::PopStyleColor();

            const ImVec2 canvasOrigin = ImGui::GetWindowPos();
            const ImVec2 canvasSize = ImGui::GetWindowSize();
            const ImVec2 canvasMax(canvasOrigin.x + canvasSize.x, canvasOrigin.y + canvasSize.y);
            ImDrawList* drawList = ImGui::GetWindowDrawList();
            const bool selectedHasHighTriageFinding = SelectedProcessHasHighTriageFinding();

            drawList->PushClipRect(canvasOrigin, canvasMax, true);
            drawList->AddRectFilledMultiColor(
                canvasOrigin,
                canvasMax,
                IM_COL32(6, 10, 16, 255),
                IM_COL32(9, 15, 23, 255),
                IM_COL32(12, 18, 27, 255),
                ColorU32(GraphCanvasBg()));
            drawList->AddRectFilled(
                canvasOrigin,
                canvasMax,
                ColorU32(ImVec4(GraphCanvasBg().x, GraphCanvasBg().y, GraphCanvasBg().z, 0.58f)),
                8.0f);
            drawList->AddRect(canvasOrigin, canvasMax, ColorU32(PanelBorder()), 8.0f, 0, 1.2f);

            if (!std::isfinite(graphZoom_))
            {
                graphZoom_ = 1.0f;
            }
            graphZoom_ = clampZoom(graphZoom_);

            const float gridStep = std::max(42.0f, 80.0f * graphZoom_);
            float firstGridX = canvasOrigin.x + std::fmod(graphPan_.x, gridStep);
            if (firstGridX > canvasOrigin.x)
            {
                firstGridX -= gridStep;
            }
            for (float x = firstGridX; x < canvasMax.x; x += gridStep)
            {
                drawList->AddLine(
                    ImVec2(x, canvasOrigin.y + 12.0f),
                    ImVec2(x, canvasMax.y - 12.0f),
                    ColorU32(GraphGridLine()),
                    1.0f);
            }

            float firstGridY = canvasOrigin.y + std::fmod(graphPan_.y, gridStep);
            if (firstGridY > canvasOrigin.y)
            {
                firstGridY -= gridStep;
            }
            for (float y = firstGridY; y < canvasMax.y; y += gridStep)
            {
                drawList->AddLine(
                    ImVec2(canvasOrigin.x + 12.0f, y),
                    ImVec2(canvasMax.x - 12.0f, y),
                    ColorU32(GraphGridLine()),
                    1.0f);
            }

            if (focusedGraph_.nodes.empty())
            {
                drawList->AddText(
                    ImVec2(canvasOrigin.x + 16.0f, canvasOrigin.y + 16.0f),
                    ColorU32(MutedText()),
                    "No focused graph available.");
                drawList->PopClipRect();
                ImGui::EndChild();
                return;
            }

            RebuildGraphWorldLayoutIfNeeded();

            struct GraphVisualNode
            {
                std::size_t nodeIndex = 0;
                ImVec2 worldCenter = ImVec2(0.0f, 0.0f);
                ImVec2 min = ImVec2(0.0f, 0.0f);
                ImVec2 max = ImVec2(0.0f, 0.0f);
                Core::Severity displaySeverity = Core::Severity::None;
            };

            const bool singleNodeGraph = graphLayoutSingleNode_;
            const bool smallGraph = graphLayoutSmallGraph_;
            const ImVec2 baseNodeSize = graphLayoutBaseNodeSize_;
            std::vector<GraphVisualNode> visualNodes(graphLayoutNodes_.size());
            for (std::size_t layoutIndex = 0; layoutIndex < graphLayoutNodes_.size(); ++layoutIndex)
            {
                visualNodes[layoutIndex].nodeIndex = graphLayoutNodes_[layoutIndex].nodeIndex;
                visualNodes[layoutIndex].worldCenter = graphLayoutNodes_[layoutIndex].worldCenter;
            }

            if (graphLayoutHasWorldBounds_ &&
                (graphFitRequested_ ||
                    graphFitPid_ != focusedGraph_.focusPid ||
                    graphFitNodeCount_ != focusedGraph_.nodes.size() ||
                    graphFitLayoutMode_ != graphLayoutMode_))
            {
                const float padding = singleNodeGraph ? 120.0f : 74.0f;
                const float worldWidth = std::max(1.0f, graphLayoutWorldMax_.x - graphLayoutWorldMin_.x);
                const float worldHeight = std::max(1.0f, graphLayoutWorldMax_.y - graphLayoutWorldMin_.y);
                const float fitX = std::max(1.0f, canvasSize.x - padding * 2.0f) / worldWidth;
                const float fitY = std::max(1.0f, canvasSize.y - padding * 2.0f) / worldHeight;
                const float maxFitZoom = singleNodeGraph ? 1.28f : (smallGraph ? 1.16f : 1.0f);
                graphZoom_ = clampZoom(std::min(std::min(fitX, fitY), maxFitZoom));
                if (singleNodeGraph)
                {
                    graphPan_ = ImVec2(canvasSize.x * 0.5f, canvasSize.y * 0.5f);
                }
                else
                {
                    const ImVec2 worldCenter(
                        (graphLayoutWorldMin_.x + graphLayoutWorldMax_.x) * 0.5f,
                        (graphLayoutWorldMin_.y + graphLayoutWorldMax_.y) * 0.5f);
                    graphPan_ = ImVec2(
                        canvasSize.x * 0.5f - worldCenter.x * graphZoom_,
                        canvasSize.y * 0.5f - worldCenter.y * graphZoom_);
                }
                graphFitRequested_ = false;
                graphFitPid_ = focusedGraph_.focusPid;
                graphFitNodeCount_ = focusedGraph_.nodes.size();
                graphFitLayoutMode_ = graphLayoutMode_;
            }

            const bool canvasHovered = ImGui::IsWindowHovered(ImGuiHoveredFlags_AllowWhenBlockedByActiveItem);
            ImGuiIO& io = ImGui::GetIO();
            if (canvasHovered && io.MouseWheel != 0.0f)
            {
                const float previousZoom = graphZoom_;
                const ImVec2 mouseCanvas(
                    io.MousePos.x - canvasOrigin.x,
                    io.MousePos.y - canvasOrigin.y);
                const ImVec2 worldUnderMouse(
                    (mouseCanvas.x - graphPan_.x) / previousZoom,
                    (mouseCanvas.y - graphPan_.y) / previousZoom);
                const float zoomFactor = io.MouseWheel > 0.0f ? 1.13f : 0.88f;
                graphZoom_ = clampZoom(graphZoom_ * zoomFactor);
                graphPan_ = ImVec2(
                    mouseCanvas.x - worldUnderMouse.x * graphZoom_,
                    mouseCanvas.y - worldUnderMouse.y * graphZoom_);
            }

            const float nodeDrawScale = std::clamp(graphZoom_, 0.62f, 1.18f);
            const ImVec2 nodeSize(baseNodeSize.x * nodeDrawScale, baseNodeSize.y * nodeDrawScale);

            auto updateVisualRects = [&]() {
                for (GraphVisualNode& visual : visualNodes)
                {
                    const ImVec2 screenCenter(
                        canvasOrigin.x + graphPan_.x + visual.worldCenter.x * graphZoom_,
                        canvasOrigin.y + graphPan_.y + visual.worldCenter.y * graphZoom_);
                    visual.min = ImVec2(screenCenter.x - nodeSize.x * 0.5f, screenCenter.y - nodeSize.y * 0.5f);
                    visual.max = ImVec2(screenCenter.x + nodeSize.x * 0.5f, screenCenter.y + nodeSize.y * 0.5f);
                    if (visual.nodeIndex < focusedGraph_.nodes.size())
                    {
                        const Core::FocusedGraphNode& node = focusedGraph_.nodes[visual.nodeIndex];
                        visual.displaySeverity =
                            node.pid == selectedPid_ && selectedHasHighTriageFinding
                                ? Core::Severity::High
                                : node.severity;
                    }
                }
            };
            updateVisualRects();

            bool mouseOverNode = false;
            if (canvasHovered)
            {
                for (const GraphVisualNode& visual : visualNodes)
                {
                    if (ImGui::IsMouseHoveringRect(visual.min, visual.max))
                    {
                        mouseOverNode = true;
                        break;
                    }
                }
            }

            if (canvasHovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
            {
                graphLeftMouseDownStartedOnNode_ = mouseOverNode;
                graphLeftCanvasPanActive_ = !mouseOverNode;
            }

            const bool leftCanvasDrag =
                graphLeftCanvasPanActive_ &&
                ImGui::IsMouseDown(ImGuiMouseButton_Left) &&
                ImGui::IsMouseDragging(ImGuiMouseButton_Left, 0.0f);
            const bool alternateCanvasDrag =
                canvasHovered &&
                (ImGui::IsMouseDragging(ImGuiMouseButton_Middle, 0.0f) ||
                    ImGui::IsMouseDragging(ImGuiMouseButton_Right, 0.0f));
            if (leftCanvasDrag || alternateCanvasDrag)
            {
                graphPan_.x += io.MouseDelta.x;
                graphPan_.y += io.MouseDelta.y;
                ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
                updateVisualRects();
            }

            auto edgeAnchor = [&](std::uint32_t pid, bool parentSide) -> ImVec2 {
                const auto nodeIndex = graphLayoutNodeIndexByPid_.find(pid);
                if (nodeIndex == graphLayoutNodeIndexByPid_.end() || nodeIndex->second >= visualNodes.size())
                {
                    return ImVec2(0.0f, 0.0f);
                }

                const GraphVisualNode& visual = visualNodes[nodeIndex->second];
                if (graphLayoutMode_ == GraphLayoutMode::LeftToRight)
                {
                    return parentSide
                        ? ImVec2(visual.max.x, (visual.min.y + visual.max.y) * 0.5f)
                        : ImVec2(visual.min.x, (visual.min.y + visual.max.y) * 0.5f);
                }

                return parentSide
                    ? ImVec2((visual.min.x + visual.max.x) * 0.5f, visual.max.y)
                    : ImVec2((visual.min.x + visual.max.x) * 0.5f, visual.min.y);
            };

            for (const Core::FocusedGraphEdge& edge : focusedGraph_.edges)
            {
                if (graphLayoutNodeIndexByPid_.find(edge.parentPid) == graphLayoutNodeIndexByPid_.end() ||
                    graphLayoutNodeIndexByPid_.find(edge.childPid) == graphLayoutNodeIndexByPid_.end())
                {
                    continue;
                }

                const ImVec2 start = edgeAnchor(edge.parentPid, true);
                const ImVec2 end = edgeAnchor(edge.childPid, false);
                const ImU32 color = edge.inSelectedChain
                    ? ColorU32(ImVec4(AccentBlue().x, AccentBlue().y, AccentBlue().z, 0.92f))
                    : IM_COL32(94, 108, 130, 210);
                if (graphLayoutMode_ == GraphLayoutMode::LeftToRight)
                {
                    const float midpoint = (start.x + end.x) * 0.5f;
                    if (edge.inSelectedChain)
                    {
                        drawList->AddBezierCubic(
                            start,
                            ImVec2(midpoint, start.y),
                            ImVec2(midpoint, end.y),
                            end,
                            ColorU32(ImVec4(AccentBlue().x, AccentBlue().y, AccentBlue().z, 0.18f)),
                            7.0f);
                    }
                    drawList->AddBezierCubic(
                        start,
                        ImVec2(midpoint, start.y),
                        ImVec2(midpoint, end.y),
                        end,
                        color,
                        edge.inSelectedChain ? 4.6f : 2.4f);
                }
                else
                {
                    const float midpoint = (start.y + end.y) * 0.5f;
                    if (edge.inSelectedChain)
                    {
                        drawList->AddBezierCubic(
                            start,
                            ImVec2(start.x, midpoint),
                            ImVec2(end.x, midpoint),
                            end,
                            ColorU32(ImVec4(AccentBlue().x, AccentBlue().y, AccentBlue().z, 0.18f)),
                            7.0f);
                    }
                    drawList->AddBezierCubic(
                        start,
                        ImVec2(start.x, midpoint),
                        ImVec2(end.x, midpoint),
                        end,
                        color,
                        edge.inSelectedChain ? 4.6f : 2.4f);
                }
            }

            std::uint32_t pendingSelectedPid = InvalidPid;
            ImVec2 singleNodeMin;
            ImVec2 singleNodeMax;
            bool hasSingleNodeBounds = false;
            for (const GraphVisualNode& visual : visualNodes)
            {
                if (visual.nodeIndex >= focusedGraph_.nodes.size())
                {
                    continue;
                }

                const Core::FocusedGraphNode& node = focusedGraph_.nodes[visual.nodeIndex];
                if (singleNodeGraph)
                {
                    singleNodeMin = visual.min;
                    singleNodeMax = visual.max;
                    hasSingleNodeBounds = true;
                }

                const bool hovered = ImGui::IsMouseHoveringRect(visual.min, visual.max);
                const ImVec2 leftDragDelta = ImGui::GetMouseDragDelta(ImGuiMouseButton_Left);
                const bool leftClickWithoutDrag =
                    (leftDragDelta.x * leftDragDelta.x + leftDragDelta.y * leftDragDelta.y) < 36.0f;
                if (hovered &&
                    graphLeftMouseDownStartedOnNode_ &&
                    leftClickWithoutDrag &&
                    ImGui::IsMouseReleased(ImGuiMouseButton_Left))
                {
                    pendingSelectedPid = node.pid;
                }

                ImU32 fill = node.focus ? ColorU32(ImVec4(0.090f, 0.165f, 0.245f, 1.0f)) : ColorU32(CardBg());
                if (Core::SeverityRank(visual.displaySeverity) >= Core::SeverityRank(Core::Severity::High))
                {
                    fill = node.focus ? IM_COL32(58, 38, 46, 255) : IM_COL32(46, 22, 28, 255);
                }
                else if (Core::SeverityRank(visual.displaySeverity) >= Core::SeverityRank(Core::Severity::Low))
                {
                    fill = node.focus ? IM_COL32(58, 49, 36, 255) : IM_COL32(42, 33, 25, 255);
                }

                const ImU32 border = Core::SeverityRank(visual.displaySeverity) >= Core::SeverityRank(Core::Severity::Low)
                    ? SeverityU32(visual.displaySeverity)
                    : (node.inSelectedChain ? ColorU32(AccentBlue()) : ColorU32(PanelBorder()));
                if (node.focus)
                {
                    drawList->AddRect(
                        ImVec2(visual.min.x - 4.0f, visual.min.y - 4.0f),
                        ImVec2(visual.max.x + 4.0f, visual.max.y + 4.0f),
                        ColorU32(ImVec4(AccentBlue().x, AccentBlue().y, AccentBlue().z, 0.68f)),
                        9.0f,
                        0,
                        2.0f);
                }
                drawList->AddRectFilled(
                    ImVec2(visual.min.x + 3.0f, visual.min.y + 4.0f),
                    ImVec2(visual.max.x + 3.0f, visual.max.y + 4.0f),
                    IM_COL32(0, 0, 0, 72),
                    9.0f);
                drawList->AddRectFilled(visual.min, visual.max, fill, 9.0f);
                drawList->AddRect(visual.min, visual.max, border, 9.0f, 0, node.focus ? 3.2f : 1.8f);
                drawList->AddRectFilled(
                    ImVec2(visual.min.x, visual.min.y),
                    ImVec2(visual.min.x + 5.0f, visual.max.y),
                    border,
                    9.0f,
                    ImDrawFlags_RoundCornersLeft);

                const std::string title = Shorten(DisplayName(node.name), nodeDrawScale < 0.78f ? 22 : 30);
                const std::string pidText = "PID " + std::to_string(node.pid);
                const float leftPadding = std::max(12.0f, 18.0f * nodeDrawScale);
                drawList->AddText(
                    ImVec2(visual.min.x + leftPadding, visual.min.y + 15.0f * nodeDrawScale),
                    ColorU32(PrimaryText()),
                    title.c_str());
                drawList->AddText(
                    ImVec2(visual.min.x + leftPadding, visual.min.y + 48.0f * nodeDrawScale),
                    ColorU32(MutedText()),
                    pidText.c_str());

                if (Core::SeverityRank(visual.displaySeverity) >= Core::SeverityRank(Core::Severity::Low))
                {
                    const std::string severityLabel = WideToUtf8(Core::SeverityToString(visual.displaySeverity));
                    const ImVec2 badgeTextSize = ImGui::CalcTextSize(severityLabel.c_str());
                    const ImVec2 badgeMin(
                        visual.max.x - badgeTextSize.x - 28.0f,
                        visual.min.y + 15.0f * nodeDrawScale);
                    const ImVec2 badgeMax(
                        visual.max.x - 12.0f,
                        badgeMin.y + 24.0f);
                    if (badgeMin.x > visual.min.x + leftPadding + 90.0f)
                    {
                        drawList->AddRectFilled(badgeMin, badgeMax, IM_COL32(20, 22, 26, 180), 4.0f);
                        drawList->AddRect(badgeMin, badgeMax, SeverityU32(visual.displaySeverity), 4.0f, 0, 1.0f);
                        drawList->AddText(
                            ImVec2(badgeMin.x + 8.0f, badgeMin.y + 4.0f),
                            SeverityU32(visual.displaySeverity),
                            severityLabel.c_str());
                    }
                }
                else if (node.inSelectedChain)
                {
                    drawList->AddText(
                        ImVec2(visual.min.x + leftPadding, visual.min.y + 76.0f * nodeDrawScale),
                        ColorU32(AccentBlue()),
                        "chain");
                }

                if (hovered)
                {
                    drawList->AddRect(
                        visual.min,
                        visual.max,
                        ColorU32(ImVec4(AccentBlue().x, AccentBlue().y, AccentBlue().z, 0.82f)),
                        9.0f,
                        0,
                        1.5f);
                    ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
                }
            }

            if (hasSingleNodeBounds)
            {
                const Core::ProcessInfo* summaryProcess = selectedGraphProcess != nullptr
                    ? selectedGraphProcess
                    : Core::FindProcessByPid(snapshot_, focusedGraph_.nodes.front().pid);

                const char* relationshipMessage = "No visible parent or child relationships for this process.";
                const ImVec2 messageSize = ImGui::CalcTextSize(relationshipMessage);
                const float clusterCenterX = (singleNodeMin.x + singleNodeMax.x) * 0.5f;
                const auto centeredClusterX = [&](float width) {
                    const float minX = canvasOrigin.x + 18.0f;
                    const float maxX = std::max(minX, canvasMax.x - width - 18.0f);
                    return std::clamp(clusterCenterX - width * 0.5f, minX, maxX);
                };
                const float messageY = std::min(
                    singleNodeMax.y + 22.0f,
                    canvasOrigin.y + canvasSize.y - 72.0f);
                drawList->AddText(
                    ImVec2(centeredClusterX(messageSize.x), messageY),
                    ColorU32(MutedText()),
                    relationshipMessage);

                if (summaryProcess != nullptr)
                {
                    struct GraphSummaryBadge
                    {
                        std::string label;
                        std::string value;
                        ImVec4 color;
                        float width = 0.0f;
                    };

                    std::vector<GraphSummaryBadge> badges;
                    const Core::ChainAnalysisResult& chain = CachedChainAnalysis(*summaryProcess);
                    const Core::FileIdentity& fileIdentity = CachedFileIdentity(summaryProcess->executablePath);
                    const std::vector<Core::Finding>& findings =
                        FindingsForSelectedProcess(*summaryProcess, chain, fileIdentity);

                    Core::Severity triageSeverity = Core::Severity::None;
                    std::string triageValue = "Clean";
                    if (!findings.empty())
                    {
                        triageSeverity = FindingSeverityAsCoreSeverity(Core::HighestFindingSeverity(findings));
                        triageValue = WideToUtf8(Core::SeverityToString(triageSeverity));
                    }
                    else if (!summaryProcess->indicators.empty() || !summaryProcess->contextNotes.empty())
                    {
                        triageSeverity = Core::Severity::Info;
                        triageValue = "Info";
                    }

                    badges.push_back({ "Triage", triageValue, SeverityColor(triageSeverity), 0.0f });
                    if (networkLoaded_)
                    {
                        const NetworkSummary networkSummary = GetNetworkSummary(summaryProcess->pid);
                        badges.push_back({
                            "Network",
                            std::to_string(networkSummary.connectionCount) +
                                (networkSummary.connectionCount == 1 ? " connection" : " connections"),
                            networkSummary.publicRemoteCount > 0 ? SeverityColor(Core::Severity::Low) : AccentBlue(),
                            0.0f });
                    }
                    if (ModulesLoadedForProcess(*summaryProcess))
                    {
                        badges.push_back({
                            "Modules",
                            std::to_string(selectedModules_.modules.size()) + " loaded",
                            AccentBlue(),
                            0.0f });
                    }

                    float badgeRowWidth = 0.0f;
                    for (GraphSummaryBadge& badge : badges)
                    {
                        badge.width =
                            ImGui::CalcTextSize(badge.label.c_str()).x +
                            ImGui::CalcTextSize(badge.value.c_str()).x +
                            34.0f;
                        badgeRowWidth += badge.width;
                    }
                    badgeRowWidth += std::max<std::size_t>(badges.size(), 1) > 1
                        ? static_cast<float>(badges.size() - 1) * 8.0f
                        : 0.0f;

                    float badgeX = centeredClusterX(badgeRowWidth);
                    const float badgeY = messageY + 30.0f;
                    for (const GraphSummaryBadge& badge : badges)
                    {
                        const ImVec2 badgeMin(badgeX, badgeY);
                        const ImVec2 badgeMax(badgeX + badge.width, badgeY + 28.0f);
                        drawList->AddRectFilled(badgeMin, badgeMax, ColorU32(CardBg()), 6.0f);
                        drawList->AddRect(badgeMin, badgeMax, ColorU32(ImVec4(badge.color.x, badge.color.y, badge.color.z, 0.48f)), 6.0f);
                        drawList->AddText(ImVec2(badgeMin.x + 10.0f, badgeMin.y + 6.0f), ColorU32(MutedText()), badge.label.c_str());
                        drawList->AddText(
                            ImVec2(badgeMin.x + ImGui::CalcTextSize(badge.label.c_str()).x + 18.0f, badgeMin.y + 6.0f),
                            ColorU32(badge.color),
                            badge.value.c_str());
                        badgeX = badgeMax.x + 8.0f;
                    }
                }
            }

            if (selectedHiddenByFilters)
            {
                const ImVec2 overlayMin(canvasOrigin.x + 18.0f, canvasOrigin.y + 18.0f);
                const ImVec2 overlayMax(
                    std::min(canvasOrigin.x + canvasSize.x - 18.0f, overlayMin.x + 420.0f),
                    overlayMin.y + 76.0f);
                drawList->AddRectFilled(overlayMin, overlayMax, ColorU32(ImVec4(CardBg().x, CardBg().y, CardBg().z, 0.96f)), 8.0f);
                drawList->AddRect(overlayMin, overlayMax, ColorU32(ImVec4(SeverityColor(Core::Severity::Medium).x, SeverityColor(Core::Severity::Medium).y, SeverityColor(Core::Severity::Medium).z, 0.52f)), 8.0f);
                drawList->AddText(
                    ImVec2(overlayMin.x + 14.0f, overlayMin.y + 13.0f),
                    ColorU32(PrimaryText()),
                    "Selected process is hidden by filters.");
                drawList->AddText(
                    ImVec2(overlayMin.x + 14.0f, overlayMin.y + 38.0f),
                    ColorU32(MutedText()),
                    "Clear search and switch to All to reveal it.");

                const ImVec2 buttonMin(overlayMax.x - 128.0f, overlayMin.y + 24.0f);
                const ImVec2 buttonMax(buttonMin.x + 110.0f, buttonMin.y + 30.0f);
                const bool buttonHovered = ImGui::IsMouseHoveringRect(buttonMin, buttonMax);
                drawList->AddRectFilled(
                    buttonMin,
                    buttonMax,
                    buttonHovered ? ColorU32(PanelHover()) : ColorU32(CardBg()),
                    6.0f);
                drawList->AddRect(
                    buttonMin,
                    buttonMax,
                    ColorU32(ImVec4(AccentBlue().x, AccentBlue().y, AccentBlue().z, buttonHovered ? 0.92f : 0.58f)),
                    6.0f,
                    0,
                    1.2f);
                const char* showSelectedLabel = "Show selected";
                const ImVec2 labelSize = ImGui::CalcTextSize(showSelectedLabel);
                drawList->AddText(
                    ImVec2(
                        buttonMin.x + (buttonMax.x - buttonMin.x - labelSize.x) * 0.5f,
                        buttonMin.y + (buttonMax.y - buttonMin.y - labelSize.y) * 0.5f),
                    ColorU32(PrimaryText()),
                    showSelectedLabel);

                if (buttonHovered)
                {
                    ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
                }
                if (buttonHovered && ImGui::IsMouseReleased(ImGuiMouseButton_Left))
                {
                    ShowSelectedProcessInFilters();
                }
            }

            drawList->PopClipRect();
            ImGui::EndChild();

            if (pendingSelectedPid != InvalidPid)
            {
                SelectGraphNode(pendingSelectedPid);
            }

            if (!ImGui::IsMouseDown(ImGuiMouseButton_Left))
            {
                graphLeftCanvasPanActive_ = false;
                graphLeftMouseDownStartedOnNode_ = false;
            }
        }
