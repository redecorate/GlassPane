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
                ? ImVec2(246.0f, 88.0f)
                : (graphLayoutSmallGraph_ ? ImVec2(218.0f, 76.0f) : ImVec2(194.0f, 66.0f));

            std::unordered_map<std::size_t, std::vector<std::size_t>> levels;
            std::size_t maxDepth = 0;
            for (std::size_t nodeIndex = 0; nodeIndex < focusedGraph_.nodes.size(); ++nodeIndex)
            {
                const Core::FocusedGraphNode& node = focusedGraph_.nodes[nodeIndex];
                levels[node.depth].push_back(nodeIndex);
                maxDepth = std::max(maxDepth, node.depth);
            }

            graphLayoutNodes_.resize(focusedGraph_.nodes.size());
            const float siblingSpacing = graphLayoutSingleNode_ ? 0.0f : (graphLayoutSmallGraph_ ? 96.0f : 112.0f);
            const float levelSpacing = graphLayoutMode_ == GraphLayoutMode::LeftToRight ? 118.0f : 92.0f;
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
            const auto graphToolbarButton = [](const char* label) {
                PushGlassButtonStyle();
                const bool clicked = ImGui::Button(label);
                PopGlassButtonStyle();
                return clicked;
            };

            const ImGuiStyle& style = ImGui::GetStyle();
            const float headerStartX = ImGui::GetCursorPosX();
            const bool pushedHeadingFont = PushFontIfAvailable(fonts_.bold);
            ImGui::AlignTextToFramePadding();
            ImGui::TextColored(AccentBlue(), "Process Graph");
            PopFontIfPushed(pushedHeadingFont);

            const float refreshWidth = ImGui::CalcTextSize("Refresh").x + style.FramePadding.x * 2.0f;
            const float layoutLabelWidth = ImGui::CalcTextSize("Layout").x;
            const float layoutComboWidth = 124.0f;
            const float toolbarWidth =
                refreshWidth +
                layoutLabelWidth +
                layoutComboWidth +
                style.ItemSpacing.x * 2.0f;
            const float toolbarX =
                ImGui::GetCursorPosX() +
                std::max(0.0f, ImGui::GetContentRegionAvail().x - toolbarWidth);
            if (ImGui::GetContentRegionAvail().x > toolbarWidth + 12.0f)
            {
                ImGui::SameLine(toolbarX);
            }
            else
            {
                ImGui::SameLine();
            }

            if (graphToolbarButton("Refresh"))
            {
                RebuildFocusedGraph("graph-refresh-button");
                RequestGraphFit();
                AddLog(LogLevel::Info, "Graph refreshed.");
            }
            ImGui::SameLine();
            ImGui::TextDisabled("Layout");
            ImGui::SameLine();
            ImGui::SetNextItemWidth(124.0f);
            const bool layoutComboOpen = ImGui::BeginCombo("##graph_layout", layoutLabel(graphLayoutMode_));
            const bool layoutComboHovered = ImGui::IsItemHovered();
            if (layoutComboOpen)
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
            if (layoutComboHovered)
            {
                RenderWrappedTooltip("Choose the direction used to arrange process relationships.", 360.0f);
            }

            ImGui::SetCursorPosX(headerStartX);
            const ImVec2 separatorStart = ImGui::GetCursorScreenPos();
            const float separatorWidth = ImGui::GetContentRegionAvail().x;
            if (separatorWidth > 1.0f)
            {
                ImGui::GetWindowDrawList()->AddLine(
                    separatorStart,
                    ImVec2(separatorStart.x + separatorWidth, separatorStart.y),
                    ColorU32(ImVec4(AccentBlue().x, AccentBlue().y, AccentBlue().z, 0.24f)),
                    1.0f);
            }
            ImGui::Dummy(ImVec2(0.0f, 4.0f));

            const Core::ProcessInfo* selectedGraphProcess = Core::FindProcessByPid(snapshot_, selectedPid_);
            const bool selectedHiddenByFilters = selectedGraphProcess != nullptr && !ProcessMatchesFilters(*selectedGraphProcess);

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
                IM_COL32(4, 8, 13, 255),
                IM_COL32(8, 14, 22, 255),
                IM_COL32(10, 16, 25, 255),
                IM_COL32(5, 9, 15, 255));
            drawList->AddRectFilled(
                canvasOrigin,
                canvasMax,
                ColorU32(ImVec4(GraphCanvasBg().x, GraphCanvasBg().y, GraphCanvasBg().z, 0.44f)),
                8.0f);

            const ImVec2 canvasCenter(
                (canvasOrigin.x + canvasMax.x) * 0.5f,
                (canvasOrigin.y + canvasMax.y) * 0.5f);
            drawList->AddRect(canvasOrigin, canvasMax, ColorU32(ImVec4(PanelBorder().x, PanelBorder().y, PanelBorder().z, 0.72f)), 8.0f, 0, 1.1f);

            if (!std::isfinite(graphZoom_))
            {
                graphZoom_ = 1.0f;
            }
            graphZoom_ = clampZoom(graphZoom_);

            const float gridStep = std::max(42.0f, 80.0f * graphZoom_);
            const ImU32 gridColor = ColorU32(ImVec4(GraphGridLine().x, GraphGridLine().y, GraphGridLine().z, 0.135f));
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
                    gridColor,
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
                    gridColor,
                    1.0f);
            }

            if (focusedGraph_.nodes.empty())
            {
                drawList->AddText(
                    ImVec2(canvasOrigin.x + 16.0f, canvasOrigin.y + 16.0f),
                    ColorU32(PrimaryText()),
                    "No process graph is available.");
                drawList->AddText(
                    ImVec2(canvasOrigin.x + 16.0f, canvasOrigin.y + 40.0f),
                    ColorU32(MutedText()),
                    "Select a process to review its parent and child relationships.");
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

            struct GraphRailButtonSpec
            {
                const char* label;
                const char* tooltip;
                float width;
            };

            const GraphRailButtonSpec railButtons[] = {
                { "Focus", "Focus graph on the selected process", 58.0f },
                { "Fit", "Fit the focused graph in view", 44.0f },
                { "-", "Zoom out", 34.0f },
                { "+", "Zoom in", 34.0f },
                { "Reset", "Reset graph zoom and pan", 58.0f },
            };
            const std::string railZoomLabel =
                std::to_string(static_cast<int>(std::round(graphZoom_ * 100.0f))) + "%";
            constexpr float RailPaddingX = 10.0f;
            constexpr float RailPaddingY = 8.0f;
            constexpr float RailGap = 6.0f;
            constexpr float RailButtonHeight = 30.0f;
            const float railZoomWidth = std::max(48.0f, ImGui::CalcTextSize(railZoomLabel.c_str()).x + 20.0f);
            float railButtonWidth = 0.0f;
            for (const GraphRailButtonSpec& button : railButtons)
            {
                railButtonWidth += button.width;
            }
            constexpr std::size_t RailButtonCount = sizeof(railButtons) / sizeof(railButtons[0]);
            railButtonWidth += railZoomWidth + RailGap * static_cast<float>(RailButtonCount);
            const ImVec2 railSize(
                railButtonWidth + RailPaddingX * 2.0f,
                RailButtonHeight + RailPaddingY * 2.0f);
            const float railXMin = canvasOrigin.x + 16.0f;
            const float railXMax = std::max(railXMin, canvasMax.x - railSize.x - 16.0f);
            ImVec2 railMin(
                std::clamp(canvasCenter.x - railSize.x * 0.5f, railXMin, railXMax),
                canvasMax.y - railSize.y - 18.0f);
            railMin.y = std::max(canvasOrigin.y + 18.0f, railMin.y);
            const ImVec2 railMax(railMin.x + railSize.x, railMin.y + railSize.y);

            const bool canvasHovered = ImGui::IsWindowHovered(ImGuiHoveredFlags_AllowWhenBlockedByActiveItem);
            const bool railHovered = canvasHovered && ImGui::IsMouseHoveringRect(railMin, railMax);
            const bool canvasInputHovered = canvasHovered && !railHovered;
            ImGuiIO& io = ImGui::GetIO();
            if (canvasInputHovered && io.MouseWheel != 0.0f)
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

            const float nodeDrawScale = std::clamp(graphZoom_, 0.78f, 1.16f);
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
            if (canvasInputHovered)
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

            if (canvasInputHovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
            {
                graphLeftMouseDownStartedOnNode_ = mouseOverNode;
                graphLeftCanvasPanActive_ = !mouseOverNode;
            }

            const bool leftCanvasDrag =
                graphLeftCanvasPanActive_ &&
                ImGui::IsMouseDown(ImGuiMouseButton_Left) &&
                ImGui::IsMouseDragging(ImGuiMouseButton_Left, 0.0f);
            const bool alternateCanvasDrag =
                canvasInputHovered &&
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

            auto edgeEndpointSeverity = [&](const Core::FocusedGraphEdge& edge) {
                Core::Severity severity = Core::Severity::None;
                const auto parentIndex = graphLayoutNodeIndexByPid_.find(edge.parentPid);
                if (parentIndex != graphLayoutNodeIndexByPid_.end() && parentIndex->second < visualNodes.size())
                {
                    severity = visualNodes[parentIndex->second].displaySeverity;
                }
                const auto childIndex = graphLayoutNodeIndexByPid_.find(edge.childPid);
                if (childIndex != graphLayoutNodeIndexByPid_.end() && childIndex->second < visualNodes.size())
                {
                    const Core::Severity childSeverity = visualNodes[childIndex->second].displaySeverity;
                    if (Core::SeverityRank(childSeverity) > Core::SeverityRank(severity))
                    {
                        severity = childSeverity;
                    }
                }
                return severity;
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
                const Core::Severity edgeSeverity = edgeEndpointSeverity(edge);
                const bool severityEdge =
                    edge.inSelectedChain &&
                    Core::SeverityRank(edgeSeverity) >= Core::SeverityRank(Core::Severity::Low);
                const ImVec4 edgeAccent = severityEdge ? SeverityColor(edgeSeverity) : AccentBlue();
                const ImU32 color = edge.inSelectedChain
                    ? ColorU32(ImVec4(edgeAccent.x, edgeAccent.y, edgeAccent.z, 0.90f))
                    : IM_COL32(86, 103, 126, 176);
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
                            ColorU32(ImVec4(edgeAccent.x, edgeAccent.y, edgeAccent.z, 0.16f)),
                            severityEdge ? 7.8f : 7.0f);
                    }
                    drawList->AddBezierCubic(
                        start,
                        ImVec2(midpoint, start.y),
                        ImVec2(midpoint, end.y),
                        end,
                        color,
                        edge.inSelectedChain ? 4.0f : 2.0f);
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
                            ColorU32(ImVec4(edgeAccent.x, edgeAccent.y, edgeAccent.z, 0.16f)),
                            severityEdge ? 7.8f : 7.0f);
                    }
                    drawList->AddBezierCubic(
                        start,
                        ImVec2(start.x, midpoint),
                        ImVec2(end.x, midpoint),
                        end,
                        color,
                        edge.inSelectedChain ? 4.0f : 2.0f);
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

                const bool hovered = !railHovered && ImGui::IsMouseHoveringRect(visual.min, visual.max);
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

                Core::Severity cardSeverity = visual.displaySeverity;
                if (node.suspicious && Core::SeverityRank(cardSeverity) < Core::SeverityRank(Core::Severity::Medium))
                {
                    cardSeverity = Core::Severity::Medium;
                }
                const bool severityNode = Core::SeverityRank(cardSeverity) >= Core::SeverityRank(Core::Severity::Low);
                const ImVec4 accent = severityNode
                    ? SeverityColor(cardSeverity)
                    : (node.inSelectedChain ? AccentBlue() : ImVec4(0.40f, 0.58f, 0.76f, 1.0f));
                const ImVec4 selectedGlow = severityNode ? accent : AccentBlue();

                ImVec4 fill = node.focus
                    ? ImVec4(0.055f, 0.105f, 0.158f, 1.0f)
                    : ImVec4(0.034f, 0.049f, 0.071f, 1.0f);
                if (severityNode)
                {
                    if (Core::SeverityRank(cardSeverity) >= Core::SeverityRank(Core::Severity::High))
                    {
                        fill = node.focus ? ImVec4(0.156f, 0.045f, 0.055f, 1.0f) : ImVec4(0.096f, 0.030f, 0.040f, 1.0f);
                    }
                    else if (Core::SeverityRank(cardSeverity) >= Core::SeverityRank(Core::Severity::Medium))
                    {
                        fill = node.focus ? ImVec4(0.132f, 0.062f, 0.044f, 1.0f) : ImVec4(0.086f, 0.046f, 0.036f, 1.0f);
                    }
                    else
                    {
                        fill = node.focus ? ImVec4(0.105f, 0.095f, 0.050f, 1.0f) : ImVec4(0.065f, 0.062f, 0.038f, 1.0f);
                    }
                }

                const ImU32 border = ColorU32(ImVec4(accent.x, accent.y, accent.z, node.focus ? 0.94f : 0.62f));
                const float rounding = std::clamp(9.0f * nodeDrawScale, 7.0f, 10.0f);
                if (node.focus)
                {
                    drawList->AddRect(
                        ImVec2(visual.min.x - 7.0f, visual.min.y - 7.0f),
                        ImVec2(visual.max.x + 7.0f, visual.max.y + 7.0f),
                        ColorU32(ImVec4(selectedGlow.x, selectedGlow.y, selectedGlow.z, 0.18f)),
                        rounding + 4.0f,
                        0,
                        7.0f);
                    drawList->AddRect(
                        ImVec2(visual.min.x - 3.0f, visual.min.y - 3.0f),
                        ImVec2(visual.max.x + 3.0f, visual.max.y + 3.0f),
                        ColorU32(ImVec4(selectedGlow.x, selectedGlow.y, selectedGlow.z, 0.72f)),
                        rounding + 2.0f,
                        0,
                        2.0f);
                }
                else if (severityNode)
                {
                    drawList->AddRect(
                        ImVec2(visual.min.x - 3.0f, visual.min.y - 3.0f),
                        ImVec2(visual.max.x + 3.0f, visual.max.y + 3.0f),
                        ColorU32(ImVec4(accent.x, accent.y, accent.z, 0.14f)),
                        rounding + 2.0f,
                        0,
                        4.0f);
                }

                drawList->AddRectFilled(
                    ImVec2(visual.min.x + 4.0f, visual.min.y + 6.0f),
                    ImVec2(visual.max.x + 4.0f, visual.max.y + 6.0f),
                    IM_COL32(0, 0, 0, 82),
                    rounding);
                drawList->AddRectFilled(visual.min, visual.max, ColorU32(fill), rounding);
                drawList->AddRectFilledMultiColor(
                    visual.min,
                    ImVec2(visual.max.x, visual.min.y + std::min(20.0f, (visual.max.y - visual.min.y) * 0.45f)),
                    ColorU32(ImVec4(1.0f, 1.0f, 1.0f, 0.055f)),
                    ColorU32(ImVec4(1.0f, 1.0f, 1.0f, 0.028f)),
                    ColorU32(ImVec4(1.0f, 1.0f, 1.0f, 0.0f)),
                    ColorU32(ImVec4(1.0f, 1.0f, 1.0f, 0.0f)));
                drawList->AddRect(visual.min, visual.max, border, rounding, 0, node.focus ? 2.4f : 1.35f);
                drawList->AddRectFilled(
                    ImVec2(visual.min.x, visual.min.y),
                    ImVec2(visual.min.x + std::max(4.0f, 5.0f * nodeDrawScale), visual.max.y),
                    ColorU32(ImVec4(accent.x, accent.y, accent.z, severityNode ? 0.88f : 0.62f)),
                    rounding,
                    ImDrawFlags_RoundCornersLeft);

                const float iconSize = std::clamp(32.0f * nodeDrawScale, 24.0f, 34.0f);
                const ImVec2 iconMin(
                    visual.min.x + std::clamp(14.0f * nodeDrawScale, 10.0f, 15.0f),
                    visual.min.y + ((visual.max.y - visual.min.y) - iconSize) * 0.5f);
                const ImVec2 iconMax(iconMin.x + iconSize, iconMin.y + iconSize);
                drawList->AddRectFilled(iconMin, iconMax, ColorU32(ImVec4(0.020f, 0.030f, 0.045f, 0.92f)), 6.0f);
                drawList->AddRect(iconMin, iconMax, ColorU32(ImVec4(accent.x, accent.y, accent.z, 0.42f)), 6.0f, 0, 1.0f);

                const Core::ProcessInfo* nodeProcess = Core::FindProcessByPid(snapshot_, node.pid);
                ID3D11ShaderResourceView* processIcon = nodeProcess != nullptr ? GetProcessIconTexture(*nodeProcess) : nullptr;
                if (processIcon != nullptr)
                {
                    drawList->AddImage(
                        reinterpret_cast<ImTextureID>(processIcon),
                        ImVec2(iconMin.x + 4.0f, iconMin.y + 4.0f),
                        ImVec2(iconMax.x - 4.0f, iconMax.y - 4.0f));
                }
                else
                {
                    const char* glyph = node.pid == 0 ? "S" : "P";
                    const ImVec2 glyphSize = ImGui::CalcTextSize(glyph);
                    drawList->AddText(
                        ImVec2(
                            iconMin.x + (iconSize - glyphSize.x) * 0.5f,
                            iconMin.y + (iconSize - glyphSize.y) * 0.5f),
                        ColorU32(ImVec4(accent.x, accent.y, accent.z, 0.96f)),
                        glyph);
                }

                const std::string displayTitle = DisplayName(node.name);
                const std::string pidText = "PID " + std::to_string(node.pid);
                const float textX = iconMax.x + std::clamp(10.0f * nodeDrawScale, 8.0f, 12.0f);
                const float titleY = visual.min.y + std::clamp(13.0f * nodeDrawScale, 10.0f, 14.0f);
                const float pidY = titleY + std::clamp(22.0f * nodeDrawScale, 17.0f, 22.0f);
                const float rightReserve = severityNode ? std::clamp(58.0f * nodeDrawScale, 44.0f, 68.0f) : 14.0f;
                const float titleMaxWidth = std::max(24.0f, visual.max.x - rightReserve - textX);
                const std::string title = EllipsizeToWidth(displayTitle, titleMaxWidth);
                drawList->PushClipRect(
                    ImVec2(textX, visual.min.y + 6.0f),
                    ImVec2(visual.max.x - rightReserve, visual.max.y - 6.0f),
                    true);
                drawList->AddText(
                    ImVec2(textX, titleY),
                    ColorU32(PrimaryText()),
                    title.c_str());
                drawList->AddText(
                    ImVec2(textX, pidY),
                    ColorU32(ImVec4(MutedText().x + 0.08f, MutedText().y + 0.08f, MutedText().z + 0.08f, 1.0f)),
                    pidText.c_str());
                drawList->PopClipRect();

                if (severityNode)
                {
                    const std::string severityLabel = WideToUtf8(Core::SeverityToString(cardSeverity));
                    const ImVec2 badgeTextSize = ImGui::CalcTextSize(severityLabel.c_str());
                    const float badgeWidth = badgeTextSize.x + 20.0f;
                    const ImVec2 badgeMin(
                        visual.max.x - badgeWidth - 12.0f,
                        visual.max.y - std::clamp(26.0f * nodeDrawScale, 22.0f, 26.0f));
                    const ImVec2 badgeMax(
                        visual.max.x - 12.0f,
                        badgeMin.y + 21.0f);
                    drawList->AddRectFilled(
                        badgeMin,
                        badgeMax,
                        ColorU32(ImVec4(0.020f, 0.025f, 0.034f, 0.86f)),
                        5.0f);
                    drawList->AddRect(
                        badgeMin,
                        badgeMax,
                        ColorU32(ImVec4(accent.x, accent.y, accent.z, 0.68f)),
                        5.0f,
                        0,
                        1.0f);
                    drawList->AddText(
                        ImVec2(badgeMin.x + 10.0f, badgeMin.y + 3.0f),
                        ColorU32(ImVec4(accent.x, accent.y, accent.z, 0.96f)),
                        severityLabel.c_str());

                    if (Core::SeverityRank(cardSeverity) >= Core::SeverityRank(Core::Severity::Medium))
                    {
                        const ImVec2 alertCenter(visual.max.x - 12.0f, visual.min.y + 12.0f);
                        drawList->AddCircleFilled(alertCenter, 8.0f, ColorU32(ImVec4(accent.x, accent.y, accent.z, 0.96f)), 16);
                        drawList->AddText(ImVec2(alertCenter.x - 2.5f, alertCenter.y - 7.5f), IM_COL32(255, 255, 255, 245), "!");
                    }
                }
                else if (node.inSelectedChain)
                {
                    const char* chainLabel = "chain";
                    const ImVec2 chainSize = ImGui::CalcTextSize(chainLabel);
                    drawList->AddText(
                        ImVec2(visual.max.x - chainSize.x - 13.0f, visual.max.y - chainSize.y - 11.0f),
                        ColorU32(ImVec4(AccentBlue().x, AccentBlue().y, AccentBlue().z, 0.84f)),
                        chainLabel);
                }

                if (hovered)
                {
                    drawList->AddRect(
                        visual.min,
                        visual.max,
                        ColorU32(ImVec4(AccentBlue().x, AccentBlue().y, AccentBlue().z, 0.82f)),
                        rounding,
                        0,
                        1.4f);
                    ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
                    if (title != displayTitle)
                    {
                        RenderWrappedTooltip(displayTitle, 420.0f);
                    }
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
                    const Core::FileIdentity& fileIdentity = CachedFileIdentity(*summaryProcess);
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

            auto drawRailButton = [&](const GraphRailButtonSpec& button, const ImVec2& buttonMin) {
                const ImVec2 buttonMax(buttonMin.x + button.width, buttonMin.y + RailButtonHeight);
                const bool hovered = canvasHovered && ImGui::IsMouseHoveringRect(buttonMin, buttonMax);
                const bool clicked = hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left);
                const ImVec4 fill = hovered
                    ? GlassHoverColor()
                    : ImVec4(0.036f, 0.049f, 0.070f, 0.96f);
                const ImVec4 border = hovered
                    ? ImVec4(AccentBlue().x, AccentBlue().y, AccentBlue().z, 0.78f)
                    : ImVec4(GlassBorderColor().x, GlassBorderColor().y, GlassBorderColor().z, 0.80f);
                drawList->AddRectFilled(buttonMin, buttonMax, ColorU32(fill), 7.0f);
                drawList->AddRect(buttonMin, buttonMax, ColorU32(border), 7.0f, 0, hovered ? 1.4f : 1.0f);

                const ImVec2 labelSize = ImGui::CalcTextSize(button.label);
                drawList->AddText(
                    ImVec2(
                        buttonMin.x + (button.width - labelSize.x) * 0.5f,
                        buttonMin.y + (RailButtonHeight - labelSize.y) * 0.5f),
                    ColorU32(hovered ? GlassPrimaryTextColor() : GlassMutedTextColor()),
                    button.label);

                if (hovered)
                {
                    ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
                    ImGui::SetTooltip("%s", button.tooltip);
                }

                return clicked;
            };

            drawList->AddRectFilled(
                ImVec2(railMin.x + 3.0f, railMin.y + 5.0f),
                ImVec2(railMax.x + 3.0f, railMax.y + 5.0f),
                IM_COL32(0, 0, 0, 92),
                11.0f);
            drawList->AddRectFilled(
                railMin,
                railMax,
                ColorU32(ImVec4(GlassRaisedPanelBackground().x, GlassRaisedPanelBackground().y, GlassRaisedPanelBackground().z, 0.94f)),
                11.0f);
            drawList->AddRect(
                railMin,
                railMax,
                ColorU32(ImVec4(GlassBorderColor().x, GlassBorderColor().y, GlassBorderColor().z, 0.92f)),
                11.0f,
                0,
                1.1f);

            ImVec2 railButtonMin(railMin.x + RailPaddingX, railMin.y + RailPaddingY);
            const bool focusClicked = drawRailButton(railButtons[0], railButtonMin);
            railButtonMin.x += railButtons[0].width + RailGap;
            const bool fitClicked = drawRailButton(railButtons[1], railButtonMin);
            railButtonMin.x += railButtons[1].width + RailGap;
            const bool zoomOutClicked = drawRailButton(railButtons[2], railButtonMin);
            railButtonMin.x += railButtons[2].width + RailGap;
            const bool zoomInClicked = drawRailButton(railButtons[3], railButtonMin);
            railButtonMin.x += railButtons[3].width + RailGap;
            const bool resetClicked = drawRailButton(railButtons[4], railButtonMin);
            railButtonMin.x += railButtons[4].width + RailGap;
            const ImVec2 zoomMin(railButtonMin.x, railButtonMin.y);
            const ImVec2 zoomMax(zoomMin.x + railZoomWidth, zoomMin.y + RailButtonHeight);
            drawList->AddRectFilled(
                zoomMin,
                zoomMax,
                ColorU32(ImVec4(0.024f, 0.034f, 0.050f, 0.92f)),
                7.0f);
            drawList->AddRect(
                zoomMin,
                zoomMax,
                ColorU32(ImVec4(GlassBorderColor().x, GlassBorderColor().y, GlassBorderColor().z, 0.58f)),
                7.0f,
                0,
                1.0f);
            const ImVec2 zoomTextSize = ImGui::CalcTextSize(railZoomLabel.c_str());
            drawList->AddText(
                ImVec2(
                    zoomMin.x + (railZoomWidth - zoomTextSize.x) * 0.5f,
                    zoomMin.y + (RailButtonHeight - zoomTextSize.y) * 0.5f),
                ColorU32(GlassMutedTextColor()),
                railZoomLabel.c_str());

            if (focusClicked)
            {
                RebuildFocusedGraph("graph-focus-rail");
                RequestGraphFit();
                AddLog(LogLevel::Info, "Graph focused on selected process.");
            }
            if (fitClicked)
            {
                RequestGraphFit();
                AddLog(LogLevel::Info, "Graph fit requested.");
            }
            if (zoomOutClicked)
            {
                graphZoom_ = clampZoom(graphZoom_ * 0.86f);
            }
            if (zoomInClicked)
            {
                graphZoom_ = clampZoom(graphZoom_ * 1.16f);
            }
            if (resetClicked)
            {
                ResetGraphView();
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
