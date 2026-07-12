// ImGuiApp inspector subview render implementations.
// This file is intentionally included inside the ImGuiApp class definition so
// inspector rendering can move out of ImGuiApp.cpp without moving state ownership.

        Core::Severity TriageSeverityForFindings(const std::vector<Core::Finding>& findings)
        {
            return findings.empty()
                ? Core::Severity::None
                : FindingSeverityAsCoreSeverity(Core::HighestFindingSeverity(findings));
        }

        std::wstring InspectorProcessName(const Core::ProcessInfo& process)
        {
            return process.name.empty() ? L"(unknown process)" : process.name;
        }

        std::wstring InspectorFindingCountText(std::size_t findingCount)
        {
            return std::to_wstring(findingCount) + (findingCount == 1 ? L" finding" : L" findings");
        }

        static int CompareInspectorTextCaseInsensitive(const std::wstring& left, const std::wstring& right)
        {
            const int result = CompareStringOrdinal(
                left.c_str(),
                static_cast<int>(left.size()),
                right.c_str(),
                static_cast<int>(right.size()),
                TRUE);
            if (result == CSTR_LESS_THAN)
            {
                return -1;
            }
            if (result == CSTR_GREATER_THAN)
            {
                return 1;
            }
            if (result == CSTR_EQUAL)
            {
                return 0;
            }
            return left.compare(right);
        }

        static int CompareInspectorUnsigned(std::uint64_t left, std::uint64_t right)
        {
            return left < right ? -1 : (left > right ? 1 : 0);
        }

        static int CompareInspectorSigned(std::int64_t left, std::int64_t right)
        {
            return left < right ? -1 : (left > right ? 1 : 0);
        }

        static std::uint64_t InspectorNumericAddress(const std::wstring& value)
        {
            if (value.empty())
            {
                return 0;
            }

            wchar_t* end = nullptr;
            const std::uint64_t parsed = std::wcstoull(value.c_str(), &end, 0);
            if (end != value.c_str())
            {
                return parsed;
            }
            return std::wcstoull(value.c_str(), nullptr, 16);
        }

        static std::vector<std::size_t> NaturalInspectorIndexView(std::size_t count)
        {
            std::vector<std::size_t> indexes;
            indexes.reserve(count);
            for (std::size_t index = 0; index < count; ++index)
            {
                indexes.push_back(index);
            }
            return indexes;
        }

        template <typename Comparator>
        static void SortInspectorIndexView(
            std::vector<std::size_t>& indexes,
            ImGuiTableSortSpecs* sortSpecs,
            Comparator compare)
        {
            if (sortSpecs == nullptr || sortSpecs->SpecsCount == 0)
            {
                return;
            }

            const ImGuiTableColumnSortSpecs& spec = sortSpecs->Specs[0];
            const bool descending = spec.SortDirection == ImGuiSortDirection_Descending;
            std::stable_sort(indexes.begin(), indexes.end(), [&](std::size_t left, std::size_t right) {
                const int result = compare(left, right, spec.ColumnIndex);
                if (result == 0)
                {
                    return false;
                }
                return descending ? result > 0 : result < 0;
            });
            sortSpecs->SpecsDirty = false;
        }

        static bool IsExistingInspectorPath(const std::wstring& value, bool& isDirectory)
        {
            isDirectory = false;
            if (value.empty() || value.find(L'\"') != std::wstring::npos)
            {
                return false;
            }
            for (wchar_t character : value)
            {
                if (character < 32)
                {
                    return false;
                }
            }

            const std::filesystem::path path(value);
            if (!path.is_absolute())
            {
                return false;
            }

            std::error_code error;
            const std::filesystem::file_status status = std::filesystem::status(path, error);
            if (error || !std::filesystem::exists(status))
            {
                return false;
            }
            isDirectory = std::filesystem::is_directory(status);
            return true;
        }

        bool OpenInspectorPathLocation(const std::wstring& path, bool isDirectory)
        {
            HINSTANCE result = nullptr;
            if (isDirectory)
            {
                result = ShellExecuteW(hwnd_, L"open", path.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            }
            else
            {
                const std::wstring parameters = L"/select,\"" + path + L"\"";
                result = ShellExecuteW(hwnd_, L"open", L"explorer.exe", parameters.c_str(), nullptr, SW_SHOWNORMAL);
            }
            return reinterpret_cast<INT_PTR>(result) > 32;
        }

        void RenderInspectorValueContextMenu(
            const char* popupId,
            const std::wstring& copyValue,
            bool openRequested,
            const std::wstring* fileSystemPath = nullptr)
        {
            if (openRequested)
            {
                ImGui::OpenPopup(popupId);
            }
            if (!ImGui::BeginPopup(popupId))
            {
                return;
            }

            const bool pushedMenuFont = PushFontIfAvailable(fonts_.ui);
            if (ImGui::MenuItem("Copy value"))
            {
                CopyTextToClipboard(copyValue);
            }

            bool isDirectory = false;
            if (fileSystemPath != nullptr && IsExistingInspectorPath(*fileSystemPath, isDirectory))
            {
                ImGui::Separator();
                if (ImGui::MenuItem("Open file location"))
                {
                    if (OpenInspectorPathLocation(*fileSystemPath, isDirectory))
                    {
                        AddLog(LogLevel::Info, "Opened file location in Windows Explorer.");
                    }
                    else
                    {
                        AddLog(LogLevel::Warning, "Could not open file location in Windows Explorer.");
                    }
                }
            }

            PopFontIfPushed(pushedMenuFont);
            ImGui::EndPopup();
        }

        void RenderInspectorClippedValue(
            const char* popupId,
            const std::wstring& displayValue,
            const std::wstring* fileSystemPath = nullptr,
            float tooltipWidth = 600.0f)
        {
            ImGui::TextUnformatted(WideToUtf8(displayValue).c_str());
            const bool hovered = ImGui::IsItemHovered();
            if (hovered)
            {
                RenderWrappedTooltip(displayValue, tooltipWidth);
            }
            RenderInspectorValueContextMenu(
                popupId,
                displayValue,
                hovered && ImGui::IsMouseReleased(ImGuiMouseButton_Right),
                fileSystemPath);
        }

        void RenderServiceInspectorField(
            const char* id,
            const char* label,
            const std::wstring& value,
            ImFont* valueFont = nullptr,
            const std::wstring* fileSystemPath = nullptr,
            const wchar_t* emptyText = L"(unavailable)")
        {
            ImGui::PushID(id);
            const float availableWidth = ImGui::GetContentRegionAvail().x;
            const bool useVerticalLayout = availableWidth < 300.0f;
            const auto renderValue = [&]() {
                if (value.empty())
                {
                    ImGui::TextDisabled("%s", WideToUtf8(emptyText).c_str());
                    return;
                }
                const bool pushedValueFont = PushFontIfAvailable(valueFont);
                RenderInspectorClippedValue("ServiceValueContext", value, fileSystemPath);
                PopFontIfPushed(pushedValueFont);
            };

            if (useVerticalLayout)
            {
                ImGui::TextDisabled("%s", label);
                renderValue();
            }
            else
            {
                const ImGuiTableFlags flags =
                    ImGuiTableFlags_SizingStretchProp |
                    ImGuiTableFlags_NoSavedSettings |
                    ImGuiTableFlags_PadOuterX;
                if (ImGui::BeginTable("ServiceFieldTable", 2, flags))
                {
                    const float labelWidth = std::clamp(availableWidth * 0.31f, 104.0f, 142.0f);
                    ImGui::TableSetupColumn("Label", ImGuiTableColumnFlags_WidthFixed, labelWidth);
                    ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    ImGui::TextDisabled("%s", label);
                    ImGui::TableSetColumnIndex(1);
                    renderValue();
                    ImGui::EndTable();
                }
            }
            ImGui::PopID();
        }

        void RenderServiceInspectorWrappedField(
            const char* id,
            const char* label,
            const std::wstring& value,
            ImFont* valueFont = nullptr,
            const wchar_t* emptyText = L"(unavailable)")
        {
            ImGui::PushID(id);
            ImGui::TextDisabled("%s", label);
            if (value.empty())
            {
                WrappedTextDisabled(emptyText);
            }
            else
            {
                const bool pushedValueFont = PushFontIfAvailable(valueFont);
                WrappedTextWide(value);
                const bool openRequested =
                    ImGui::IsItemHovered() &&
                    ImGui::IsMouseReleased(ImGuiMouseButton_Right);
                RenderInspectorValueContextMenu(
                    "ServiceWrappedValueContext",
                    value,
                    openRequested);
                PopFontIfPushed(pushedValueFont);
            }
            ImGui::PopID();
        }

        std::wstring ServiceTruncationSummary(const Core::ServiceInfo& service)
        {
            std::wstring summary;
            const auto append = [&](bool truncated, const wchar_t* label) {
                if (!truncated)
                {
                    return;
                }
                if (!summary.empty())
                {
                    summary += L", ";
                }
                summary += label;
            };
            append(service.serviceNameTruncated, L"service name");
            append(service.displayNameTruncated, L"display name");
            append(service.descriptionTruncated, L"description");
            append(service.serviceAccountTruncated, L"service account");
            append(service.rawImagePathTruncated, L"raw ImagePath");
            append(service.expandedImagePathTruncated, L"expanded ImagePath");
            append(service.svchostGroupTruncated, L"svchost group");
            append(service.pathParseMessageTruncated, L"parse message");
            append(service.statusMessageTruncated, L"status message");
            return summary.empty() ? L"None observed" : summary;
        }

        static bool ServiceExecutablePathCanOpen(const Core::ServiceInfo& service)
        {
            return !service.executablePath.empty() &&
                service.pathConfidence == Core::ServicePathConfidence::High &&
                (service.pathParseStatus == Core::ServicePathParseStatus::ParsedQuoted ||
                 service.pathParseStatus == Core::ServicePathParseStatus::ParsedUnquoted);
        }

        float InspectorSummaryChipWidth(const char* label, const std::wstring& value)
        {
            const std::string chipText = std::string(label) + ": " + WideToUtf8(value);
            return ImGui::CalcTextSize(chipText.c_str()).x + 20.0f;
        }

        void InspectorSummaryChip(const char* id, const char* label, const std::wstring& value, const ImVec4& accent)
        {
            ImGui::PushID(id);
            const std::string chipText = std::string(label) + ": " + WideToUtf8(value);
            const ImVec2 textSize = ImGui::CalcTextSize(chipText.c_str());
            const ImVec2 min = ImGui::GetCursorScreenPos();
            const ImVec2 max(min.x + textSize.x + 20.0f, min.y + textSize.y + 10.0f);
            ImDrawList* drawList = ImGui::GetWindowDrawList();
            const ImVec4 base = GlassRaisedPanelBackground();
            drawList->AddRectFilled(min, max, ColorU32(base), 5.0f);
            drawList->AddRect(min, max, ColorU32(ImVec4(accent.x, accent.y, accent.z, 0.58f)), 5.0f, 0, 1.2f);
            drawList->AddText(ImVec2(min.x + 10.0f, min.y + 5.0f), ColorU32(ImVec4(accent.x, accent.y, accent.z, 0.96f)), chipText.c_str());
            ImGui::Dummy(ImVec2(textSize.x + 20.0f, textSize.y + 10.0f));
            ImGui::PopID();
        }

        void RenderInspectorProcessIcon(const Core::ProcessInfo& process, float size)
        {
            ID3D11ShaderResourceView* processIcon = GetProcessIconTexture(process);
            if (processIcon != nullptr)
            {
                ImGui::Image(reinterpret_cast<ImTextureID>(processIcon), ImVec2(size, size));
                return;
            }

            const ImVec2 iconMin = ImGui::GetCursorScreenPos();
            const ImVec2 iconMax(iconMin.x + size, iconMin.y + size);
            ImGui::GetWindowDrawList()->AddRectFilled(iconMin, iconMax, ColorU32(PanelBgRaised()), 6.0f);
            ImGui::GetWindowDrawList()->AddRect(iconMin, iconMax, ColorU32(AccentBlue()), 6.0f, 0, 1.1f);
            ImGui::Dummy(ImVec2(size, size));
        }

        void RenderTriagePanel()
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                RenderEmptyState("No process is selected.", "Select a process to review triage findings.");
                return;
            }

            const Core::ChainAnalysisResult& chain = CachedChainAnalysis(*process);
            Core::FileIdentity loadedSnapshotFileIdentity;
            const Core::FileIdentity& fileIdentity = loadedSnapshotActive_
                ? loadedSnapshotFileIdentity
                : CachedFileIdentity(*process);
            const std::vector<Core::Finding>& findings =
                FindingsForSelectedProcess(*process, chain, fileIdentity);
            const std::wstring triageSummary = Core::TriageSummary(findings);
            const Core::Severity verdictColorSeverity = TriageSeverityForFindings(findings);

            BeginInspectorCard("triage_summary", "Triage Summary", fonts_.bold);

            RenderInspectorProcessIcon(*process, 42.0f);
            ImGui::SameLine(0.0f, 12.0f);
            ImGui::BeginGroup();
            const bool pushedSummaryTitleFont = PushFontIfAvailable(fonts_.title);
            ClippedTextWithTooltip(InspectorProcessName(*process));
            PopFontIfPushed(pushedSummaryTitleFont);

            const bool pushedSummaryPidFont = PushFontIfAvailable(fonts_.monospace);
            ImGui::TextDisabled("PID %u  |  PPID %u", process->pid, process->parentPid);
            PopFontIfPushed(pushedSummaryPidFont);
            ImGui::EndGroup();

            ImGui::Spacing();
            InspectorSummaryChip("triage_verdict_chip", "Triage", triageSummary, SeverityColor(verdictColorSeverity));
            SameLineIfFits(InspectorSummaryChipWidth("Findings", InspectorFindingCountText(findings.size())), 6.0f);
            InspectorSummaryChip(
                "triage_finding_count_chip",
                "Findings",
                InspectorFindingCountText(findings.size()),
                findings.empty() ? MutedText() : SeverityColor(verdictColorSeverity));

            ImGui::Spacing();
            if (!process->executablePath.empty())
            {
                const bool pushedSummaryPathFont = PushFontIfAvailable(fonts_.monospace);
                RenderInspectorClippedValue(
                    "TriageExecutablePathValueContext",
                    process->executablePath,
                    &process->executablePath);
                PopFontIfPushed(pushedSummaryPathFont);
            }
            else if (process->pid == 0)
            {
                WrappedTextDisabled("System process entry has no executable path.");
            }
            else
            {
                WrappedTextDisabled("Executable path unavailable.");
            }

            ImGui::Spacing();
            if (ImGui::SmallButton("Copy Triage Summary"))
            {
                CopyTextToClipboard(FormatTriageSummaryForClipboard(*process, findings));
                AddLog(LogLevel::Info, "Copied triage summary to clipboard.");
            }
            SameLineIfFits(StandardButtonWidth("Copy All Findings"), 6.0f);
            if (findings.empty())
            {
                ImGui::BeginDisabled();
            }
            if (ImGui::SmallButton("Copy All Findings"))
            {
                CopyTextToClipboard(FormatFindingsForClipboard(*process, findings));
                AddLog(LogLevel::Info, "Copied all triage findings to clipboard.");
            }
            if (findings.empty())
            {
                ImGui::EndDisabled();
                RenderDisabledReasonTooltip("No findings are available to copy for this process.");
            }
            SameLineIfFits(StandardButtonWidth("Export Report"), 6.0f);
            if (ImGui::SmallButton("Export Report"))
            {
                ExportSelectedMarkdownReport();
            }
            EndInspectorCard();

            ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(6.0f, 6.0f));
            if (ChipButton("All##TriageFilter", triageFilter_ == TriageFilter::All, AccentBlue()))
            {
                triageFilter_ = TriageFilter::All;
            }
            SameLineIfChipFits("Info");
            if (ChipButton("Info##TriageFilter", triageFilter_ == TriageFilter::Info, FindingSeverityColor(Core::FindingSeverity::Info)))
            {
                triageFilter_ = TriageFilter::Info;
            }
            SameLineIfChipFits("Low");
            if (ChipButton("Low##TriageFilter", triageFilter_ == TriageFilter::Low, FindingSeverityColor(Core::FindingSeverity::Low)))
            {
                triageFilter_ = TriageFilter::Low;
            }
            SameLineIfChipFits("Medium");
            if (ChipButton("Medium##TriageFilter", triageFilter_ == TriageFilter::Medium, FindingSeverityColor(Core::FindingSeverity::Medium)))
            {
                triageFilter_ = TriageFilter::Medium;
            }
            SameLineIfChipFits("High");
            if (ChipButton("High##TriageFilter", triageFilter_ == TriageFilter::High, FindingSeverityColor(Core::FindingSeverity::High)))
            {
                triageFilter_ = TriageFilter::High;
            }
            ImGui::PopStyleVar();
            ImGui::Spacing();

            if (findings.empty())
            {
                BeginInspectorCard("triage_clean", "Findings", fonts_.bold);
                RenderEmptyState(
                    "No findings are available for the selected process.",
                    "Review process, module, network, and chain context as needed.");
                EndInspectorCard();
                return;
            }

            std::size_t visibleFindings = 0;
            for (std::size_t index = 0; index < findings.size(); ++index)
            {
                const Core::Finding& finding = findings[index];
                if (!FindingMatchesFilter(finding, triageFilter_))
                {
                    continue;
                }

                ++visibleFindings;
                const std::string cardId = "triage_finding_" + std::to_string(index);
                const ImVec4 accent = FindingSeverityColor(finding.severity);
                ImGui::PushStyleColor(ImGuiCol_ChildBg, FindingCardBg(finding.severity));
                ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(accent.x, accent.y, accent.z, 0.55f));
                ImGui::BeginChild(
                    cardId.c_str(),
                    ImVec2(0.0f, 0.0f),
                    ImGuiChildFlags_Borders | ImGuiChildFlags_AlwaysUseWindowPadding | ImGuiChildFlags_AutoResizeY);

                SeverityBadge(FindingSeverityAsCoreSeverity(finding.severity));
                ImGui::SameLine();
                const bool pushedFindingTitleFont = PushFontIfAvailable(fonts_.bold);
                ImGui::TextColored(ImVec4(0.88f, 0.93f, 0.98f, 1.0f), "%s", WideToUtf8(finding.title.empty() ? L"(untitled finding)" : finding.title).c_str());
                PopFontIfPushed(pushedFindingTitleFont);
                ImGui::SameLine();
                if (ImGui::SmallButton("Copy Finding"))
                {
                    CopyTextToClipboard(FormatFindingForClipboard(finding));
                    AddLog(LogLevel::Info, "Copied triage finding to clipboard.");
                }

                ImGui::TextDisabled("Category");
                ImGui::SameLine(145.0f);
                TextWide(finding.category.empty() ? L"(none)" : finding.category);
                WrappedTextWide(finding.description);

                if (!finding.evidence.empty())
                {
                    ImGui::SeparatorText("Evidence");
                    for (const std::wstring& evidence : finding.evidence)
                    {
                        ImGui::TextColored(ImVec4(accent.x, accent.y, accent.z, 0.80f), "-");
                        ImGui::SameLine();
                        WrappedTextDisabled(evidence);
                    }
                }
                ImGui::EndChild();
                ImGui::PopStyleColor(2);
                ImGui::Spacing();
            }

            if (visibleFindings == 0)
            {
                BeginInspectorCard("triage_filter_empty", "Findings", fonts_.bold);
                const std::string filterDetail =
                    "Current filter: " + WideToUtf8(TriageFilterLabel(triageFilter_));
                RenderEmptyState("No findings match the current filter.", filterDetail.c_str());
                EndInspectorCard();
            }
        }

        void RenderDetailsPanel()
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                RenderEmptyState("No process is selected.", "Select a process to review its details.");
                return;
            }

            const Core::ParentRelationshipStatus parentRelationshipStatus =
                Core::GetParentRelationshipStatus(snapshot_, *process);
            const Core::ProcessInfo* parent =
                Core::IsUsableParentRelationship(parentRelationshipStatus)
                    ? Core::FindProcessByPid(snapshot_, process->parentPid)
                    : nullptr;
            const Core::ChainAnalysisResult& chain = CachedChainAnalysis(*process);
            const NetworkSummary networkSummary = GetNetworkSummary(process->pid);
            Core::FileIdentity loadedSnapshotFileIdentity;
            const Core::FileIdentity& fileIdentity = loadedSnapshotActive_
                ? loadedSnapshotFileIdentity
                : CachedFileIdentity(*process);
            const std::vector<Core::FileIdentityIndicator> fileIdentityIndicators =
                loadedSnapshotActive_
                    ? std::vector<Core::FileIdentityIndicator>{}
                    : BuildProcessFileIdentityIndicators(*process, fileIdentity);
            const std::vector<Core::Finding>& findings =
                FindingsForSelectedProcess(*process, chain, fileIdentity);
            if (!ProcessMatchesFilters(*process))
            {
                ImGui::TextColored(
                    ImVec4(0.96f, 0.52f, 0.20f, 1.0f),
                    "Selected process hidden by filters.");
                ImGui::Spacing();
            }

            ImGui::PushStyleColor(ImGuiCol_ChildBg, CardBg());
            ImGui::PushStyleColor(ImGuiCol_Border, PanelBorder());
            ImGui::BeginChild(
                "details_header",
                ImVec2(0.0f, 0.0f),
                ImGuiChildFlags_Borders | ImGuiChildFlags_AlwaysUseWindowPadding | ImGuiChildFlags_AutoResizeY);

            ID3D11ShaderResourceView* processIcon = GetProcessIconTexture(*process);
            if (processIcon != nullptr)
            {
                ImGui::Image(reinterpret_cast<ImTextureID>(processIcon), ImVec2(40.0f, 40.0f));
                ImGui::SameLine();
            }
            else
            {
                const ImVec2 iconMin = ImGui::GetCursorScreenPos();
                const ImVec2 iconMax(iconMin.x + 40.0f, iconMin.y + 40.0f);
                ImGui::GetWindowDrawList()->AddRectFilled(iconMin, iconMax, IM_COL32(44, 58, 78, 255), 5.0f);
                ImGui::GetWindowDrawList()->AddRect(iconMin, iconMax, ColorU32(AccentBlue()), 5.0f, 0, 1.0f);
                ImGui::Dummy(ImVec2(40.0f, 40.0f));
                ImGui::SameLine();
            }

            ImGui::BeginGroup();
            const bool pushedProcessTitleFont = PushFontIfAvailable(fonts_.title);
            ClippedTextWithTooltip(InspectorProcessName(*process));
            PopFontIfPushed(pushedProcessTitleFont);
            ImGui::TextDisabled("Triage");
            ImGui::SameLine(82.0f);
            ImGui::TextColored(SeverityColor(findings.empty()
                ? Core::Severity::None
                : FindingSeverityAsCoreSeverity(Core::HighestFindingSeverity(findings))),
                "%s",
                WideToUtf8(Core::TriageSummary(findings)).c_str());
            ImGui::TextDisabled("Process severity");
            ImGui::SameLine(118.0f);
            SeverityBadge(process->severity);
            if (!findings.empty())
            {
                const Core::Severity triageSeverity = FindingSeverityAsCoreSeverity(Core::HighestFindingSeverity(findings));
                if (triageSeverity != process->severity)
                {
                    ImGui::SameLine();
                    ImGui::TextDisabled("Triage severity");
                    ImGui::SameLine();
                    SeverityBadge(triageSeverity);
                }
            }
            const bool pushedHeaderPidFont = PushFontIfAvailable(fonts_.monospace);
            ImGui::TextDisabled("PID %u  |  PPID %u", process->pid, process->parentPid);
            PopFontIfPushed(pushedHeaderPidFont);
            ImGui::EndGroup();

            if (!process->executablePath.empty())
            {
                ImGui::Spacing();
                const bool pushedPathFont = PushFontIfAvailable(fonts_.monospace);
                WrappedTextDisabled(process->executablePath);
                RenderInspectorValueContextMenu(
                    "DetailsHeaderExecutablePathValueContext",
                    process->executablePath,
                    ImGui::IsItemHovered() && ImGui::IsMouseReleased(ImGuiMouseButton_Right),
                    &process->executablePath);
                PopFontIfPushed(pushedPathFont);
            }
            ImGui::EndChild();
            ImGui::PopStyleColor(2);
            ImGui::Spacing();

            BeginInspectorCard("details_identity", "Identity", fonts_.bold);
            LabelValue("PID", std::to_wstring(process->pid));
            ImGui::SameLine();
            if (ImGui::SmallButton("Copy PID"))
            {
                CopyTextToClipboard(std::to_wstring(process->pid));
                AddLog(LogLevel::Info, "Copied selected PID to clipboard.");
            }
            LabelValue("Parent PID", parent == nullptr
                ? std::to_wstring(process->parentPid)
                : std::to_wstring(process->parentPid) + L" (" + parent->name + L")");
            LabelValue("Parent Link", ParentRelationshipStatusText(parentRelationshipStatus));
            LabelValue("Session", OptionalSessionId(process->sessionId));
            LabelValue("Architecture", process->architecture);
            EndInspectorCard();

            BeginInspectorCard("details_execution", "Execution", fonts_.bold);
            LabelValue("Start Time", process->hasCreationTime ? process->creationTimeLocal : L"(not accessible)");
            ImGui::TextDisabled("Executable Path");
            ImGui::SameLine();
            const bool executablePathAvailable = !process->executablePath.empty();
            if (!executablePathAvailable)
            {
                ImGui::BeginDisabled();
            }
            if (ImGui::SmallButton("Copy Path"))
            {
                CopyTextToClipboard(process->executablePath);
                AddLog(LogLevel::Info, "Copied executable path to clipboard.");
            }
            if (!executablePathAvailable)
            {
                ImGui::EndDisabled();
                RenderDisabledReasonTooltip("The executable path is unavailable for this process.");
            }
            const bool pushedExecutionPathFont = PushFontIfAvailable(fonts_.monospace);
            const std::wstring executablePath =
                process->executablePath.empty() ? L"(not accessible)" : process->executablePath;
            WrappedTextWide(executablePath);
            RenderInspectorValueContextMenu(
                "DetailsExecutablePathValueContext",
                executablePath,
                ImGui::IsItemHovered() && ImGui::IsMouseReleased(ImGuiMouseButton_Right),
                process->executablePath.empty() ? nullptr : &process->executablePath);
            PopFontIfPushed(pushedExecutionPathFont);
            ImGui::TextDisabled("Command Line");
            ImGui::SameLine();
            const bool commandLineAvailable = process->commandLineAccessible && !process->commandLine.empty();
            if (!commandLineAvailable)
            {
                ImGui::BeginDisabled();
            }
            if (ImGui::SmallButton("Copy Command"))
            {
                CopyTextToClipboard(process->commandLine);
                AddLog(LogLevel::Info, "Copied command line to clipboard.");
            }
            if (!commandLineAvailable)
            {
                ImGui::EndDisabled();
                RenderDisabledReasonTooltip("The command line is unavailable for this process.");
            }
            if (!process->commandLineAccessible)
            {
                TextWide(L"(not accessible)");
            }
            else
            {
                const bool pushedCommandFont = PushFontIfAvailable(fonts_.monospace);
                WrappedTextWide(process->commandLine.empty() ? L"(empty)" : process->commandLine);
                PopFontIfPushed(pushedCommandFont);
            }
            EndInspectorCard();

            BeginInspectorCard("details_file_identity", "File Identity", fonts_.bold);
            RenderFileIdentityFields(
                "process_file_identity",
                fileIdentity,
                fileIdentityIndicators,
                "process executable");
            EndInspectorCard();

            BeginInspectorCard("details_security", "Security", fonts_.bold);
            LabelValue("Triage", Core::TriageSummary(findings));
            LabelValue("Suspicious", process->IsSuspicious() ? "Yes" : "No");
            ImGui::TextDisabled("Severity");
            ImGui::SameLine(145.0f);
            SeverityText(process->severity);
            ImGui::TextDisabled("Chain Severity");
            ImGui::SameLine(145.0f);
            SeverityText(chain.chainSeverity);
            LabelValue("Network Connections", std::to_wstring(networkSummary.connectionCount));
            LabelValue("Listening Sockets", std::to_wstring(networkSummary.listeningCount));
            LabelValue("Public Remote", std::to_wstring(networkSummary.publicRemoteCount));
            LabelValue("Intel Matches", std::to_wstring(networkSummary.intelMatchCount));
            EndInspectorCard();

            BeginInspectorCard("details_indicators", "Indicators", fonts_.bold);
            const std::vector<std::wstring> networkIndicators = BuildNetworkIndicators(*process, networkSummary);
            if (process->indicators.empty() && networkIndicators.empty() && fileIdentityIndicators.empty())
            {
                RenderEmptyState("No process indicators are available.");
            }
            else
            {
                for (const std::wstring& indicator : process->indicators)
                {
                    ImGui::Bullet();
                    ImGui::SameLine();
                    WrappedTextWide(indicator);
                }
                for (const Core::FileIdentityIndicator& indicator : fileIdentityIndicators)
                {
                    ImGui::Bullet();
                    ImGui::SameLine();
                    SeverityText(indicator.severity);
                    ImGui::SameLine();
                    WrappedTextWide(indicator.message);
                }
                for (const std::wstring& indicator : networkIndicators)
                {
                    ImGui::Bullet();
                    ImGui::SameLine();
                    WrappedTextWide(indicator);
                }
            }
            EndInspectorCard();

            BeginInspectorCard("details_context", "Context Notes", fonts_.bold);
            const std::vector<std::wstring> networkContextNotes = BuildNetworkContextNotes(*process, chain, networkSummary);
            if (process->contextNotes.empty() && networkContextNotes.empty())
            {
                RenderEmptyState("No context notes are available.");
            }
            else
            {
                for (const std::wstring& note : process->contextNotes)
                {
                    ImGui::Bullet();
                    ImGui::SameLine();
                    WrappedTextWide(note);
                }
                for (const std::wstring& note : networkContextNotes)
                {
                    ImGui::Bullet();
                    ImGui::SameLine();
                    WrappedTextWide(note);
                }
            }
            EndInspectorCard();
        }

        void RenderServiceContextSummaryCard(
            std::uint32_t pid,
            std::size_t correlatedCount,
            std::size_t activeRecordCount,
            const std::wstring& collectionStatus,
            bool inventoryAvailable)
        {
            const std::string title = "Services for PID " + std::to_string(pid);
            BeginInspectorCard("services_summary", title.c_str(), fonts_.bold);
            RenderServiceInspectorField(
                "summary_pid",
                "Selected PID",
                std::to_wstring(pid),
                fonts_.monospace);
            RenderServiceInspectorField(
                "summary_status",
                "Collection status",
                collectionStatus);
            RenderServiceInspectorField(
                "summary_source",
                "Association source",
                L"SCM-reported PID association");
            if (inventoryAvailable)
            {
                RenderServiceInspectorField(
                    "summary_correlated",
                    "Correlated services",
                    std::to_wstring(correlatedCount) + L" service record(s)");
                RenderServiceInspectorField(
                    "summary_active_records",
                    "Active records visible",
                    std::to_wstring(activeRecordCount) +
                        L" to the current security context");
            }
            EndInspectorCard();
        }

        void RenderServiceInspectorCard(
            const Core::ServiceInfo& service,
            std::size_t serviceIndex)
        {
            ImGui::PushID(static_cast<int>(serviceIndex));
            BeginInspectorCard("service_card", "Associated Service", fonts_.bold);

            const std::wstring primaryName = service.displayName.empty()
                ? service.serviceName
                : service.displayName;
            const bool pushedPrimaryFont = PushFontIfAvailable(fonts_.bold);
            RenderInspectorClippedValue("ServicePrimaryNameContext", primaryName);
            PopFontIfPushed(pushedPrimaryFont);
            ImGui::Spacing();

            ImGui::SeparatorText("Identity");
            RenderServiceInspectorField(
                "service_name",
                "Service name",
                service.serviceName);
            RenderServiceInspectorField(
                "display_name",
                "Display name",
                service.displayName,
                nullptr,
                nullptr,
                L"(empty)");
            if (service.descriptionAvailable)
            {
                RenderServiceInspectorWrappedField(
                    "description",
                    "Description",
                    service.description,
                    nullptr,
                    L"(empty)");
            }

            ImGui::SeparatorText("Runtime");
            RenderServiceInspectorField(
                "state",
                "State",
                Core::ServiceStateDisplayText(service.stateRaw));
            RenderServiceInspectorField(
                "scm_pid",
                "SCM-reported PID",
                std::to_wstring(service.scmProcessId),
                fonts_.monospace);
            RenderServiceInspectorField(
                "process_model",
                "Process model",
                Core::ServiceProcessModelDisplayText(service.processModel));
            RenderServiceInspectorField(
                "service_type",
                "Service type",
                Core::ServiceTypeDisplayText(service.serviceTypeRaw));
            if (!service.svchostGroup.empty())
            {
                RenderServiceInspectorField(
                    "svchost_group",
                    "svchost group",
                    service.svchostGroup);
            }

            ImGui::SeparatorText("Configured Context");
            if (service.configurationAvailable)
            {
                RenderServiceInspectorField(
                    "start_type",
                    "Start type",
                    Core::ServiceStartTypeDisplayText(service.startTypeRaw));
                RenderServiceInspectorField(
                    "service_account",
                    "Service account",
                    service.serviceAccount,
                    nullptr,
                    nullptr,
                    L"(empty)");
                RenderServiceInspectorField(
                    "raw_image_path",
                    "Raw ImagePath",
                    service.rawImagePath,
                    fonts_.monospace,
                    nullptr,
                    L"(empty)");
                if (!service.expandedImagePath.empty() &&
                    service.expandedImagePath != service.rawImagePath)
                {
                    RenderServiceInspectorField(
                        "expanded_image_path",
                        "Expanded ImagePath",
                        service.expandedImagePath,
                        fonts_.monospace);
                }

                const std::wstring* openableExecutablePath =
                    ServiceExecutablePathCanOpen(service)
                        ? &service.executablePath
                        : nullptr;
                if (!service.executablePath.empty())
                {
                    RenderServiceInspectorField(
                        "executable_path",
                        "Parsed executable",
                        service.executablePath,
                        fonts_.monospace,
                        openableExecutablePath);
                }
                RenderServiceInspectorField(
                    "path_parse_status",
                    "Path parse status",
                    Core::ServicePathParseStatusDisplayText(service.pathParseStatus));
                RenderServiceInspectorField(
                    "path_confidence",
                    "Path confidence",
                    Core::ServicePathConfidenceDisplayText(service.pathConfidence));
                if (!service.pathParseMessage.empty())
                {
                    RenderServiceInspectorWrappedField(
                        "path_parse_message",
                        "Parse detail",
                        service.pathParseMessage);
                }
            }
            else
            {
                WrappedTextDisabled(
                    "Configuration metadata is unavailable in this service context. "
                    "Configured start type, account, and ImagePath values are not shown.");
            }

            ImGui::SeparatorText("Availability");
            RenderServiceInspectorField(
                "configuration_availability",
                "Configuration",
                service.configurationAvailable ? L"Available" : L"Unavailable");
            RenderServiceInspectorField(
                "description_availability",
                "Description",
                service.descriptionAvailable ? L"Available" : L"Unavailable");
            RenderServiceInspectorField(
                "truncation",
                "Bounded fields",
                ServiceTruncationSummary(service));
            if (!service.statusMessage.empty())
            {
                RenderServiceInspectorWrappedField(
                    "service_status_message",
                    "Service status",
                    service.statusMessage);
            }

            EndInspectorCard();
            ImGui::PopID();
        }

        void RenderServicesPanel()
        {
            constexpr std::size_t MaxRenderedServicesPerPid = 64;

            const Core::ProcessInfo* process =
                Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                RenderEmptyState(
                    "Select a process to review associated service context.");
                return;
            }

            if (!serviceSnapshot_.attempted)
            {
                RenderServiceContextSummaryCard(
                    process->pid,
                    0,
                    0,
                    loadedSnapshotActive_ ? L"Not captured" : L"Unavailable",
                    false);
                RenderEmptyState(
                    loadedSnapshotActive_
                        ? "Service context was not captured in this snapshot."
                        : "Service context has not been collected. Refresh the live endpoint to collect it.");
                return;
            }

            const auto correlation =
                serviceSnapshot_.serviceIndexesByPid.find(process->pid);
            const std::vector<std::size_t>* correlatedServiceIndexes =
                correlation == serviceSnapshot_.serviceIndexesByPid.end()
                    ? nullptr
                    : &correlation->second;
            const std::size_t correlatedCount =
                correlatedServiceIndexes == nullptr
                    ? 0
                    : correlatedServiceIndexes->size();
            const std::size_t activeRecordCount = (std::max)(
                serviceSnapshot_.services.size(),
                serviceSnapshot_.totalEnumerated);
            const bool renderablePartial =
                serviceSnapshot_.partial &&
                !serviceSnapshot_.services.empty();
            const bool unavailable =
                !serviceSnapshot_.success &&
                !renderablePartial;
            const bool partial =
                !unavailable &&
                (serviceSnapshot_.partial ||
                 serviceSnapshot_.truncated ||
                 !serviceSnapshot_.success);

            RenderServiceContextSummaryCard(
                process->pid,
                correlatedCount,
                activeRecordCount,
                unavailable ? L"Unavailable" : (partial ? L"Partial" : L"Complete"),
                !unavailable);

            if (unavailable)
            {
                const std::string detail = WideToUtf8(serviceSnapshot_.statusMessage);
                RenderEmptyState(
                    "Service context could not be collected.",
                    detail.empty() ? nullptr : detail.c_str());
                return;
            }

            if (partial)
            {
                BeginInspectorCard(
                    "services_partial_context",
                    "Partial Service Context",
                    fonts_.bold);
                WrappedTextColored(
                    ImVec4(0.95f, 0.72f, 0.25f, 1.0f),
                    "Service context is partial. Some configuration details may be unavailable.");

                const std::size_t omittedCount =
                    activeRecordCount > serviceSnapshot_.services.size()
                        ? activeRecordCount - serviceSnapshot_.services.size()
                        : 0;
                if (omittedCount != 0)
                {
                    WrappedTextDisabled(
                        std::to_wstring(omittedCount) +
                        L" active service record(s) were omitted by the service cap.");
                }
                if (serviceSnapshot_.configurationUnavailableCount != 0 ||
                    serviceSnapshot_.descriptionUnavailableCount != 0)
                {
                    WrappedTextDisabled(
                        std::to_wstring(serviceSnapshot_.configurationUnavailableCount) +
                        L" configuration record(s) and " +
                        std::to_wstring(serviceSnapshot_.descriptionUnavailableCount) +
                        L" description record(s) are unavailable in the retained service context.");
                }
                if (!serviceSnapshot_.statusMessage.empty())
                {
                    WrappedTextDisabled(serviceSnapshot_.statusMessage);
                }
                EndInspectorCard();
            }

            if (correlatedCount == 0)
            {
                RenderEmptyState(
                    "No active Windows services were correlated to this process by SCM-reported PID.");
                return;
            }

            const std::size_t renderCount =
                (std::min)(correlatedCount, MaxRenderedServicesPerPid);
            for (std::size_t viewIndex = 0; viewIndex < renderCount; ++viewIndex)
            {
                const std::size_t serviceIndex =
                    (*correlatedServiceIndexes)[viewIndex];
                if (serviceIndex >= serviceSnapshot_.services.size())
                {
                    continue;
                }
                RenderServiceInspectorCard(
                    serviceSnapshot_.services[serviceIndex],
                    serviceIndex);
            }

            if (correlatedCount > renderCount)
            {
                WrappedTextDisabled(
                    std::to_wstring(correlatedCount - renderCount) +
                    L" additional services omitted from this view.");
            }
        }

        void RenderChainPanel()
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                RenderEmptyState("No process is selected.", "Select a process to review its process chain.");
                return;
            }

            const Core::ChainAnalysisResult& chain = CachedChainAnalysis(*process);
            ImGui::TextDisabled("Chain Severity");
            ImGui::SameLine(145.0f);
            SeverityText(chain.chainSeverity);

            if (ImGui::Button("Copy Chain"))
            {
                const std::string chainText = WideToUtf8(chain.formattedParentChain);
                ImGui::SetClipboardText(chainText.c_str());
                AddLog(LogLevel::Info, "Copied selected process chain to clipboard.");
            }
            ImGui::SameLine();
            if (ImGui::Button("Export Selected"))
            {
                ExportSelectedDetails();
            }

            ImGui::SeparatorText("Parent Chain");
            WrappedTextWide(chain.formattedParentChain.empty() ? L"(unavailable)" : chain.formattedParentChain);

            ImGui::SeparatorText("Processes");
            for (const Core::ChainProcessSummary& item : chain.parentChain)
            {
                ImGui::PushID(static_cast<int>(item.pid));
                if (ImGui::Selectable(DisplayName(item.name).c_str(), item.pid == selectedPid_))
                {
                    SelectProcess(item.pid, true);
                }
                ImGui::SameLine();
                const bool pushedChainPidFont = PushFontIfAvailable(fonts_.monospace);
                ImGui::TextDisabled("PID %u", item.pid);
                PopFontIfPushed(pushedChainPidFont);
                ImGui::SameLine();
                SeverityText(item.severity);
                ImGui::PopID();
            }

            ImGui::SeparatorText("Chain Indicators");
            if (chain.chainIndicators.empty())
            {
                RenderEmptyState("No chain indicators are available.");
            }
            else
            {
                for (const std::wstring& indicator : chain.chainIndicators)
                {
                    ImGui::Bullet();
                    ImGui::SameLine();
                    WrappedTextWide(indicator);
                }
            }
        }

        void RenderModulesPanel()
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                RenderEmptyState("No process is selected.", "Select a process to review module information.");
                return;
            }

            const bool pushedModuleTitleFont = PushFontIfAvailable(fonts_.bold);
            ImGui::TextColored(ImVec4(0.72f, 0.84f, 0.96f, 1.0f), "%s", DisplayName(process->name).c_str());
            PopFontIfPushed(pushedModuleTitleFont);
            ImGui::SameLine();
            const bool pushedModulePidFont = PushFontIfAvailable(fonts_.monospace);
            ImGui::TextDisabled("PID %u", process->pid);
            PopFontIfPushed(pushedModulePidFont);

            ImGui::Separator();
            if (LoadedSnapshotLiveActionButton("Refresh Modules"))
            {
                RefreshModules();
            }
            ImGui::SameLine();
            if (ImGui::Button("Export Selected"))
            {
                ExportSelectedDetails();
            }

            if (!ModulesLoadedForProcess(*process))
            {
                ImGui::Spacing();
                if (loadedSnapshotActive_)
                {
                    RenderEmptyState(
                        "Module information was not collected in this saved snapshot.",
                        "Return to Live View to collect live module information.");
                }
                else
                {
                    RenderEmptyState(
                        "Module information has not been collected for this process.",
                        "Use Refresh Modules to collect read-only module metadata.");
                }
                return;
            }

            if (loadedSnapshotActive_)
            {
                WrappedTextDisabled("Showing metadata preserved in saved snapshot.");
            }

            if (selectedModules_.success)
            {
                WrappedTextColored(
                    ImVec4(0.55f, 0.72f, 0.92f, 1.0f),
                    WideToUtf8(selectedModules_.statusMessage));
            }
            else
            {
                WrappedTextColored(
                    ImVec4(0.96f, 0.52f, 0.20f, 1.0f),
                    "Module information is unavailable: " + WideToUtf8(selectedModules_.statusMessage));
                WrappedTextDisabled("Protected, exited, or cross-architecture processes may not expose module details.");
            }

            if (!selectedModules_.indicators.empty())
            {
                ImGui::SeparatorText("Module Indicators");
                for (const std::wstring& indicator : selectedModules_.indicators)
                {
                    ImGui::Bullet();
                    ImGui::SameLine();
                    WrappedTextWide(indicator);
                }
            }

            if (selectedModules_.modules.empty())
            {
                ImGui::Spacing();
                RenderEmptyState("No module information was returned for this process.");
                return;
            }

            const ImGuiTableFlags flags =
                ImGuiTableFlags_BordersInnerV |
                ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Resizable |
                ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_SizingStretchProp |
                ImGuiTableFlags_NoSavedSettings |
                ImGuiTableFlags_Sortable |
                ImGuiTableFlags_SortTristate;
            AcknowledgeTableAutoSizeRequest(modulesTableNeedsAutoSize_);
            if (ImGui::BeginTable("ModulesTable##ModulesPanel", 4, flags))
            {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn(
                    "Module",
                    ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_PreferSortAscending,
                    155.0f);
                ImGui::TableSetupColumn(
                    "Base",
                    ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_PreferSortAscending,
                    112.0f);
                ImGui::TableSetupColumn(
                    "Size",
                    ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_PreferSortAscending,
                    76.0f);
                ImGui::TableSetupColumn(
                    "Path",
                    ImGuiTableColumnFlags_WidthStretch | ImGuiTableColumnFlags_PreferSortAscending);
                ImGui::TableHeadersRow();

                std::vector<std::size_t> moduleView = NaturalInspectorIndexView(selectedModules_.modules.size());
                SortInspectorIndexView(
                    moduleView,
                    ImGui::TableGetSortSpecs(),
                    [this](std::size_t leftIndex, std::size_t rightIndex, int columnIndex) {
                        const Core::ModuleInfo& left = selectedModules_.modules[leftIndex];
                        const Core::ModuleInfo& right = selectedModules_.modules[rightIndex];
                        switch (columnIndex)
                        {
                        case 0:
                            return CompareInspectorTextCaseInsensitive(left.moduleName, right.moduleName);
                        case 1:
                            return CompareInspectorUnsigned(
                                InspectorNumericAddress(left.baseAddress),
                                InspectorNumericAddress(right.baseAddress));
                        case 2:
                            return CompareInspectorUnsigned(left.sizeBytes, right.sizeBytes);
                        case 3:
                            return CompareInspectorTextCaseInsensitive(left.modulePath, right.modulePath);
                        default:
                            return 0;
                        }
                    });

                ImGuiListClipper clipper;
                clipper.Begin(static_cast<int>(moduleView.size()));
                while (clipper.Step())
                {
                    for (int rowIndex = clipper.DisplayStart; rowIndex < clipper.DisplayEnd; ++rowIndex)
                    {
                        const std::size_t moduleIndex = moduleView[static_cast<std::size_t>(rowIndex)];
                        const Core::ModuleInfo& module = selectedModules_.modules[moduleIndex];
                        const bool moduleSelected =
                            selectedModulePid_ == selectedPid_ &&
                            selectedModuleIndex_ == moduleIndex;

                        ImGui::TableNextRow();
                        if (moduleSelected)
                        {
                            const ImU32 selectedRow = ColorU32(TableSelectedRow());
                            ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, selectedRow);
                            ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1, selectedRow);
                        }
                        ImGui::PushID(static_cast<int>(moduleIndex));

                        ImGui::TableSetColumnIndex(0);
                        const std::wstring moduleName = module.moduleName.empty() ? L"(unknown)" : module.moduleName;
                        const ImVec2 moduleCellStart = ImGui::GetCursorScreenPos();
                        if (ImGui::Selectable(
                            WideToUtf8(moduleName).c_str(),
                            moduleSelected,
                            ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap,
                            ImVec2(0.0f, 24.0f)))
                        {
                            selectedModulePid_ = selectedPid_;
                            selectedModuleIndex_ = moduleIndex;
                        }
                        const ImVec2 moduleRowMin = ImGui::GetItemRectMin();
                        const ImVec2 moduleRowMax = ImGui::GetItemRectMax();
                        const float moduleTextWidth =
                            ImGui::CalcTextSize(WideToUtf8(moduleName).c_str()).x +
                            ImGui::GetStyle().FramePadding.x * 2.0f;
                        ImGui::SetCursorScreenPos(ImVec2(moduleCellStart.x, moduleRowMin.y));
                        ImGui::InvisibleButton(
                            "##ModuleNameContextHit",
                            ImVec2(moduleTextWidth, moduleRowMax.y - moduleRowMin.y),
                            ImGuiButtonFlags_MouseButtonRight);
                        const bool moduleContextRequested = ImGui::IsItemClicked(ImGuiMouseButton_Right);
                        RenderInspectorValueContextMenu(
                            "ModuleNameValueContext",
                            moduleName,
                            moduleContextRequested);

                        ImGui::TableSetColumnIndex(1);
                        const bool pushedBaseFont = PushFontIfAvailable(fonts_.monospace);
                        TextWide(module.baseAddress);
                        const bool baseContextRequested =
                            ImGui::IsItemHovered() && ImGui::IsMouseReleased(ImGuiMouseButton_Right);
                        PopFontIfPushed(pushedBaseFont);
                        RenderInspectorValueContextMenu(
                            "ModuleBaseValueContext",
                            module.baseAddress,
                            baseContextRequested);

                        ImGui::TableSetColumnIndex(2);
                        ImGui::Text("%u", module.sizeBytes);
                        const bool sizeContextRequested =
                            ImGui::IsItemHovered() && ImGui::IsMouseReleased(ImGuiMouseButton_Right);
                        RenderInspectorValueContextMenu(
                            "ModuleSizeValueContext",
                            std::to_wstring(module.sizeBytes),
                            sizeContextRequested);

                        ImGui::TableSetColumnIndex(3);
                        const std::wstring modulePath =
                            module.modulePath.empty() ? L"(path unavailable)" : module.modulePath;
                        const bool pushedPathFont = PushFontIfAvailable(fonts_.monospace);
                        RenderInspectorClippedValue(
                            "ModulePathValueContext",
                            modulePath,
                            module.modulePath.empty() ? nullptr : &module.modulePath);
                        PopFontIfPushed(pushedPathFont);
                        ImGui::PopID();
                    }
                }
                ImGui::EndTable();
            }

            if (selectedModulePid_ == selectedPid_ && selectedModuleIndex_ < selectedModules_.modules.size())
            {
                const Core::ModuleInfo& module = selectedModules_.modules[selectedModuleIndex_];
                ImGui::SeparatorText("Selected Module");
                ImGui::TextDisabled("Module");
                ImGui::SameLine(92.0f);
                const std::wstring selectedModuleName =
                    module.moduleName.empty() ? L"(unknown)" : module.moduleName;
                TextWide(selectedModuleName);
                RenderInspectorValueContextMenu(
                    "SelectedModuleNameValueContext",
                    selectedModuleName,
                    ImGui::IsItemHovered() && ImGui::IsMouseReleased(ImGuiMouseButton_Right));

                const bool pushedSelectedModuleFont = PushFontIfAvailable(fonts_.monospace);
                ImGui::TextDisabled("Base");
                ImGui::SameLine(92.0f);
                TextWide(module.baseAddress);
                RenderInspectorValueContextMenu(
                    "SelectedModuleBaseValueContext",
                    module.baseAddress,
                    ImGui::IsItemHovered() && ImGui::IsMouseReleased(ImGuiMouseButton_Right));
                ImGui::TextDisabled("Size");
                ImGui::SameLine(92.0f);
                ImGui::Text("%u", module.sizeBytes);
                RenderInspectorValueContextMenu(
                    "SelectedModuleSizeValueContext",
                    std::to_wstring(module.sizeBytes),
                    ImGui::IsItemHovered() && ImGui::IsMouseReleased(ImGuiMouseButton_Right));
                ImGui::TextDisabled("Path");
                const std::wstring selectedModulePath =
                    module.modulePath.empty() ? L"(path unavailable)" : module.modulePath;
                WrappedTextWide(selectedModulePath);
                RenderInspectorValueContextMenu(
                    "SelectedModulePathValueContext",
                    selectedModulePath,
                    ImGui::IsItemHovered() && ImGui::IsMouseReleased(ImGuiMouseButton_Right),
                    module.modulePath.empty() ? nullptr : &module.modulePath);
                PopFontIfPushed(pushedSelectedModuleFont);

                if (loadedSnapshotActive_)
                {
                    ImGui::SeparatorText("File Identity");
                    WrappedTextDisabled("File identity metadata is live-only and was not collected for this saved module row.");
                }
                else
                {
                    const Core::FileIdentity& moduleFileIdentity = CachedFileIdentity(module.modulePath);
                    const std::vector<Core::FileIdentityIndicator> moduleFileIdentityIndicators =
                        Core::BuildFileIdentityIndicators(moduleFileIdentity, module.moduleName, false);
                    ImGui::SeparatorText("File Identity");
                    RenderFileIdentityFields(
                        "selected_module_file_identity",
                        moduleFileIdentity,
                        moduleFileIdentityIndicators,
                        "selected module");
                }
            }
        }

        void RenderTokenPanel()
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                RenderEmptyState("No process is selected.", "Select a process to review token information.");
                return;
            }

            const bool pushedTokenTitleFont = PushFontIfAvailable(fonts_.bold);
            ImGui::TextColored(ImVec4(0.72f, 0.84f, 0.96f, 1.0f), "%s", DisplayName(process->name).c_str());
            PopFontIfPushed(pushedTokenTitleFont);
            ImGui::SameLine();
            const bool pushedTokenPidFont = PushFontIfAvailable(fonts_.monospace);
            ImGui::TextDisabled("PID %u", process->pid);
            PopFontIfPushed(pushedTokenPidFont);

            ImGui::Separator();
            if (LoadedSnapshotLiveActionButton("Refresh Token"))
            {
                RefreshToken(true);
            }

            if (!TokenLoadedForProcess(*process))
            {
                ImGui::Spacing();
                BeginInspectorCard("token_empty_state", "Token", fonts_.bold);
                if (loadedSnapshotActive_)
                {
                    RenderEmptyState(
                        "Token information was not collected in this saved snapshot.",
                        "Return to Live View to collect live token information.");
                }
                else
                {
                    RenderEmptyState(
                        "Token information has not been collected for this process.",
                        "Use Refresh Token to collect read-only token metadata.");
                }
                EndInspectorCard();
                return;
            }

            if (loadedSnapshotActive_)
            {
                WrappedTextDisabled("Showing metadata preserved in saved snapshot.");
            }

            const Core::TokenInfo& token = selectedToken_;
            const std::wstring tokenUser = TokenUserText(token);
            const std::wstring integritySummary = token.integrityLevelName.empty()
                ? L"(unavailable)"
                : token.integrityLevelName + L" (" + std::to_wstring(token.integrityRid) + L")";

            if (!token.success)
            {
                BeginInspectorCard("token_unavailable", "Token", fonts_.bold);
                const std::string tokenDetail = WideToUtf8(
                    token.errorMessage.empty() ? std::wstring(L"Access was denied or the process exited.") : token.errorMessage);
                RenderEmptyState("Token information is unavailable.", tokenDetail.c_str());
                EndInspectorCard();
                return;
            }

            BeginInspectorCard("token_summary", "Token Summary", fonts_.bold);
            if (ImGui::BeginTable(
                "TokenSummaryGrid##TokenPanel",
                2,
                ImGuiTableFlags_SizingStretchSame | ImGuiTableFlags_NoSavedSettings | ImGuiTableFlags_PadOuterX))
            {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                TokenSummaryCell("User", tokenUser, ImGui::GetStyleColorVec4(ImGuiCol_Text), fonts_.bold);
                ImGui::TableSetColumnIndex(1);
                TokenSummaryCell("Integrity", integritySummary, ImGui::GetStyleColorVec4(ImGuiCol_Text), fonts_.bold);
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                TokenSummaryCell(
                    "Elevated",
                    YesNo(token.isElevated),
                    token.isElevated ? SeverityColor(Core::Severity::Medium) : ImGui::GetStyleColorVec4(ImGuiCol_Text),
                    fonts_.bold);
                ImGui::TableSetColumnIndex(1);
                TokenSummaryCell(
                    "Admin",
                    YesNo(token.isAdmin),
                    token.isAdmin ? SeverityColor(Core::Severity::Low) : ImGui::GetStyleColorVec4(ImGuiCol_Text),
                    fonts_.bold);
                ImGui::EndTable();
            }
            EndInspectorCard();

            BeginInspectorCard("token_identity", "Identity", fonts_.bold);
            InspectorFieldRow("token_user", "User", tokenUser);
            InspectorFieldRow(
                "token_session",
                "Session",
                token.sessionId.has_value() ? std::to_wstring(token.sessionId.value()) : L"(unavailable)");
            ImGui::Spacing();
            ImGui::TextDisabled("SID");
            if (!token.userSid.empty())
            {
                ImGui::SameLine();
                if (ImGui::SmallButton("Copy SID"))
                {
                    CopyTextToClipboard(token.userSid);
                }
            }
            const bool pushedSidFont = PushFontIfAvailable(fonts_.monospace);
            WrappedTextDisabled(token.userSid.empty() ? L"(unavailable)" : token.userSid);
            PopFontIfPushed(pushedSidFont);
            EndInspectorCard();

            BeginInspectorCard("token_security", "Token Security", fonts_.bold);
            InspectorFieldRow("token_integrity", "Integrity", integritySummary);
            InspectorFieldRow("token_elevated", "Elevated", YesNo(token.isElevated));
            InspectorFieldRow("token_admin", "Admin", YesNo(token.isAdmin));
            InspectorFieldRow("token_elevation_type", "Elevation Type", token.elevationType.empty() ? L"(unavailable)" : token.elevationType);
            InspectorFieldRow("token_type", "Token Type", token.tokenType.empty() ? L"(unavailable)" : token.tokenType);
            if (!token.impersonationLevel.empty())
            {
                InspectorFieldRow("token_impersonation", "Impersonation", token.impersonationLevel);
            }
            InspectorFieldRow("token_appcontainer", "AppContainer", YesNo(token.isAppContainer));
            if (!token.errorMessage.empty())
            {
                ImGui::SeparatorText("Context");
                WrappedTextDisabled(token.errorMessage);
            }
            EndInspectorCard();

            const Core::ChainAnalysisResult& chain = CachedChainAnalysis(*process);
            Core::FileIdentity loadedSnapshotFileIdentity;
            const Core::FileIdentity& fileIdentity = loadedSnapshotActive_
                ? loadedSnapshotFileIdentity
                : CachedFileIdentity(*process);
            const std::vector<Core::Finding>& findings =
                FindingsForSelectedProcess(*process, chain, fileIdentity);
            bool hasTokenFindings = false;
            for (const Core::Finding& finding : findings)
            {
                if (finding.category == L"Token")
                {
                    if (!hasTokenFindings)
                    {
                        BeginInspectorCard("token_context", "Token Context", fonts_.bold);
                        hasTokenFindings = true;
                    }
                    SeverityText(FindingSeverityAsCoreSeverity(finding.severity));
                    ImGui::SameLine();
                    WrappedTextWide(finding.title);
                    for (const std::wstring& evidence : finding.evidence)
                    {
                        ImGui::Bullet();
                        ImGui::SameLine();
                        WrappedTextDisabled(evidence);
                    }
                    ImGui::Spacing();
                }
            }
            if (hasTokenFindings)
            {
                EndInspectorCard();
            }

            BeginInspectorCard("token_privileges", "Privileges", fonts_.bold);
            if (token.privileges.empty())
            {
                RenderEmptyState("No privilege information was returned for this token.");
            }
            else
            {
                if (ImGui::Checkbox("Show enabled only", &tokenShowEnabledOnly_))
                {
                    tokenTableNeedsAutoSize_ = true;
                }
                ImGui::Spacing();

                std::vector<const Core::PrivilegeInfo*> visiblePrivileges;
                visiblePrivileges.reserve(token.privileges.size());
                for (const Core::PrivilegeInfo& privilege : token.privileges)
                {
                    if (tokenShowEnabledOnly_ && (!privilege.enabled || privilege.removed))
                    {
                        continue;
                    }
                    visiblePrivileges.push_back(&privilege);
                }

                if (visiblePrivileges.empty())
                {
                    RenderEmptyState("No privileges match the current filter.");
                }
                else
                {
                const ImGuiTableFlags flags =
                    ImGuiTableFlags_BordersInnerV |
                    ImGuiTableFlags_RowBg |
                    ImGuiTableFlags_Resizable |
                    ImGuiTableFlags_SizingStretchProp |
                    ImGuiTableFlags_NoSavedSettings;
                    AcknowledgeTableAutoSizeRequest(tokenTableNeedsAutoSize_);
                if (ImGui::BeginTable("TokenPrivilegesTable##TokenPanel", 3, flags))
                {
                    ImGui::TableSetupColumn("Privilege", ImGuiTableColumnFlags_WidthFixed, 172.0f);
                    ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 104.0f);
                    ImGui::TableSetupColumn("Description", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableHeadersRow();

                    ImGuiListClipper clipper;
                    clipper.Begin(static_cast<int>(visiblePrivileges.size()));
                    while (clipper.Step())
                    {
                        for (int rowIndex = clipper.DisplayStart; rowIndex < clipper.DisplayEnd; ++rowIndex)
                        {
                            const Core::PrivilegeInfo& privilege = *visiblePrivileges[static_cast<std::size_t>(rowIndex)];
                            ImGui::TableNextRow();
                            if (privilege.enabled && !privilege.removed)
                            {
                                ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, ColorU32(ImVec4(0.18f, 0.15f, 0.07f, 0.55f)));
                            }

                            ImGui::TableSetColumnIndex(0);
                            const bool pushedPrivilegeFont = PushFontIfAvailable(fonts_.monospace);
                            ClippedTextWithTooltip(privilege.name.empty() ? L"(unknown)" : privilege.name);
                            PopFontIfPushed(pushedPrivilegeFont);

                            ImGui::TableSetColumnIndex(1);
                            const std::wstring state = PrivilegeStateText(privilege);
                            if (privilege.enabled && !privilege.removed)
                            {
                                ImGui::TextColored(SeverityColor(Core::Severity::Low), "%s", WideToUtf8(state).c_str());
                            }
                            else
                            {
                                TextWide(state);
                            }

                            ImGui::TableSetColumnIndex(2);
                            ClippedTextWithTooltip(privilege.displayName.empty() ? L"(description unavailable)" : privilege.displayName);
                        }
                    }
                    ImGui::EndTable();
                }
                }
            }
            EndInspectorCard();
        }

        void RenderHandlesPanel()
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                RenderEmptyState("No process is selected.", "Select a process to review handle information.");
                return;
            }

            const bool pushedHandleTitleFont = PushFontIfAvailable(fonts_.bold);
            ImGui::TextColored(ImVec4(0.72f, 0.84f, 0.96f, 1.0f), "%s", DisplayName(process->name).c_str());
            PopFontIfPushed(pushedHandleTitleFont);
            ImGui::SameLine();
            const bool pushedHandlePidFont = PushFontIfAvailable(fonts_.monospace);
            ImGui::TextDisabled("PID %u", process->pid);
            PopFontIfPushed(pushedHandlePidFont);

            ImGui::Separator();
            if (LoadedSnapshotLiveActionButton("Refresh Handles"))
            {
                RefreshHandles(true);
            }
            ImGui::SameLine();
            if (ImGui::Button("Export Selected"))
            {
                ExportSelectedDetails();
            }

            if (!HandlesLoadedForProcess(*process))
            {
                ImGui::Spacing();
                BeginInspectorCard("handles_empty_state", "Handles", fonts_.bold);
                if (loadedSnapshotActive_)
                {
                    RenderEmptyState(
                        "Handle information was not collected in this saved snapshot.",
                        "Return to Live View to collect live handle information.");
                }
                else
                {
                    RenderEmptyState(
                        "Handle information has not been collected for this process.",
                        "Use Refresh Handles to collect read-only handle metadata.");
                }
                EndInspectorCard();
                return;
            }

            if (loadedSnapshotActive_)
            {
                WrappedTextDisabled("Showing metadata preserved in saved snapshot.");
            }

            if (!selectedHandles_.success)
            {
                BeginInspectorCard("handles_unavailable", "Handles", fonts_.bold);
                const std::string handleDetail = WideToUtf8(selectedHandles_.statusMessage.empty()
                    ? L"Collection did not complete."
                    : selectedHandles_.statusMessage);
                RenderEmptyState("Handle information is unavailable.", handleDetail.c_str());
                EndInspectorCard();
                return;
            }

            if (selectedHandles_.handles.empty())
            {
                BeginInspectorCard("handles_none", "Handles", fonts_.bold);
                RenderEmptyState("No handle information was returned for this process.");
                EndInspectorCard();
                return;
            }

            BeginInspectorCard("handles_filters", "Filters", fonts_.bold);
            ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x);
            if (ImGui::InputTextWithHint(
                "##HandlesPanelSearch",
                "Search handle, type, target, access, indicator",
                handleSearchBuffer_.data(),
                handleSearchBuffer_.size()))
            {
                const std::wstring loweredSearch = ToLower(Utf8ToWide(handleSearchBuffer_.data()));
                if (handleSearchText_ != loweredSearch)
                {
                    handleSearchText_ = loweredSearch;
                    visibleHandlesDirty_ = true;
                    handlesTableNeedsAutoSize_ = true;
                }
            }

            if (ChipButton("All##HandleFilter", handleFilter_ == HandleFilter::All, AccentBlue()))
            {
                if (handleFilter_ != HandleFilter::All)
                {
                    handleFilter_ = HandleFilter::All;
                    visibleHandlesDirty_ = true;
                    handlesTableNeedsAutoSize_ = true;
                }
            }
            SameLineIfChipFits("Sensitive");
            if (ChipButton("Sensitive##HandleFilter", handleFilter_ == HandleFilter::Sensitive, SeverityColor(Core::Severity::Medium)))
            {
                if (handleFilter_ != HandleFilter::Sensitive)
                {
                    handleFilter_ = HandleFilter::Sensitive;
                    visibleHandlesDirty_ = true;
                    handlesTableNeedsAutoSize_ = true;
                }
            }
            SameLineIfChipFits("Process");
            if (ChipButton("Process##HandleFilter", handleFilter_ == HandleFilter::Process, AccentBlue()))
            {
                if (handleFilter_ != HandleFilter::Process)
                {
                    handleFilter_ = HandleFilter::Process;
                    visibleHandlesDirty_ = true;
                    handlesTableNeedsAutoSize_ = true;
                }
            }
            SameLineIfChipFits("Token");
            if (ChipButton("Token##HandleFilter", handleFilter_ == HandleFilter::Token, AccentBlue()))
            {
                if (handleFilter_ != HandleFilter::Token)
                {
                    handleFilter_ = HandleFilter::Token;
                    visibleHandlesDirty_ = true;
                    handlesTableNeedsAutoSize_ = true;
                }
            }
            SameLineIfChipFits("File");
            if (ChipButton("File##HandleFilter", handleFilter_ == HandleFilter::File, AccentBlue()))
            {
                if (handleFilter_ != HandleFilter::File)
                {
                    handleFilter_ = HandleFilter::File;
                    visibleHandlesDirty_ = true;
                    handlesTableNeedsAutoSize_ = true;
                }
            }
            SameLineIfChipFits("Registry");
            if (ChipButton("Registry##HandleFilter", handleFilter_ == HandleFilter::Registry, AccentBlue()))
            {
                if (handleFilter_ != HandleFilter::Registry)
                {
                    handleFilter_ = HandleFilter::Registry;
                    visibleHandlesDirty_ = true;
                    handlesTableNeedsAutoSize_ = true;
                }
            }
            SameLineIfChipFits("Named Objects");
            if (ChipButton("Named Objects##HandleFilter", handleFilter_ == HandleFilter::NamedObjects, AccentBlue()))
            {
                if (handleFilter_ != HandleFilter::NamedObjects)
                {
                    handleFilter_ = HandleFilter::NamedObjects;
                    visibleHandlesDirty_ = true;
                    handlesTableNeedsAutoSize_ = true;
                }
            }
            SameLineIfChipFits("With Indicators");
            if (ChipButton("With Indicators##HandleFilter", handleFilter_ == HandleFilter::WithIndicators, SeverityColor(Core::Severity::Low)))
            {
                if (handleFilter_ != HandleFilter::WithIndicators)
                {
                    handleFilter_ = HandleFilter::WithIndicators;
                    visibleHandlesDirty_ = true;
                    handlesTableNeedsAutoSize_ = true;
                }
            }
            EndInspectorCard();

            RebuildVisibleHandlesIfNeeded(*process);

            BeginInspectorCard("handles_summary", "Handle Summary", fonts_.bold);
            LabelValue("Total Loaded", std::to_wstring(selectedHandles_.handles.size()));
            LabelValue("Visible", std::to_wstring(visibleHandleIndexes_.size()));
            LabelValue("Sensitive", std::to_wstring(selectedHandles_.sensitiveCount));
            LabelValue("With Indicators", std::to_wstring(visibleHandlesWithIndicatorsCount_));
            LabelValue("Name Unavail/Skipped", std::to_wstring(visibleHandlesNameStatusCount_));
            ImGui::TextDisabled("Status");
            WrappedTextDisabled(selectedHandles_.statusMessage.empty() ? L"(no status)" : selectedHandles_.statusMessage);
            EndInspectorCard();

            if (visibleHandleIndexes_.empty())
            {
                BeginInspectorCard("handles_filter_empty", "Handles", fonts_.bold);
                RenderEmptyState("No handles match the current filters.");
                EndInspectorCard();
                return;
            }

            const ImGuiTableFlags flags =
                ImGuiTableFlags_BordersInnerV |
                ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Resizable |
                ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_SizingStretchProp |
                ImGuiTableFlags_NoSavedSettings |
                ImGuiTableFlags_Sortable |
                ImGuiTableFlags_SortTristate;
            AcknowledgeTableAutoSizeRequest(handlesTableNeedsAutoSize_);
            if (ImGui::BeginTable("HandlesTable##HandlesPanel", 5, flags))
            {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn(
                    "Handle",
                    ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_PreferSortAscending,
                    76.0f);
                ImGui::TableSetupColumn(
                    "Type",
                    ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_PreferSortAscending,
                    88.0f);
                ImGui::TableSetupColumn(
                    "Target / Name",
                    ImGuiTableColumnFlags_WidthStretch | ImGuiTableColumnFlags_PreferSortAscending);
                ImGui::TableSetupColumn(
                    "Access",
                    ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_PreferSortAscending,
                    92.0f);
                ImGui::TableSetupColumn(
                    "Indicators",
                    ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoSort,
                    118.0f);
                ImGui::TableHeadersRow();

                std::vector<std::size_t> handleView = visibleHandleIndexes_;
                SortInspectorIndexView(
                    handleView,
                    ImGui::TableGetSortSpecs(),
                    [this](std::size_t leftIndex, std::size_t rightIndex, int columnIndex) {
                        const Core::HandleInfo& left = selectedHandles_.handles[leftIndex];
                        const Core::HandleInfo& right = selectedHandles_.handles[rightIndex];
                        switch (columnIndex)
                        {
                        case 0:
                            return CompareInspectorUnsigned(left.handleValue, right.handleValue);
                        case 1:
                            return CompareInspectorTextCaseInsensitive(
                                HandleObjectTypeText(left),
                                HandleObjectTypeText(right));
                        case 2:
                            return CompareInspectorTextCaseInsensitive(
                                HandleTargetText(left),
                                HandleTargetText(right));
                        case 3:
                            return CompareInspectorUnsigned(left.grantedAccessRaw, right.grantedAccessRaw);
                        default:
                            return 0;
                        }
                    });

                ImGuiListClipper clipper;
                clipper.Begin(static_cast<int>(handleView.size()));
                while (clipper.Step())
                {
                    for (int rowIndex = clipper.DisplayStart; rowIndex < clipper.DisplayEnd; ++rowIndex)
                    {
                        const std::size_t handleIndex = handleView[static_cast<std::size_t>(rowIndex)];
                        if (handleIndex >= selectedHandles_.handles.size())
                        {
                            continue;
                        }
                        const Core::HandleInfo& handle = selectedHandles_.handles[handleIndex];
                        ImGui::TableNextRow();
                        if (handle.isSensitive)
                        {
                            ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, ColorU32(ImVec4(0.26f, 0.11f, 0.045f, 0.68f)));
                        }
                        else if (!handle.indicators.empty())
                        {
                            ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, ColorU32(ImVec4(0.15f, 0.12f, 0.05f, 0.42f)));
                        }
                        ImGui::PushID(static_cast<int>(handleIndex));

                        ImGui::TableSetColumnIndex(0);
                        const std::wstring handleValue = HandleValueText(handle.handleValue);
                        const bool pushedHandleFont = PushFontIfAvailable(fonts_.monospace);
                        if (handle.isSensitive)
                        {
                            ImGui::TextColored(SeverityColor(Core::Severity::Medium), "%s", WideToUtf8(handleValue).c_str());
                        }
                        else
                        {
                            ClippedTextWithTooltip(handleValue);
                        }
                        const bool handleContextRequested =
                            ImGui::IsItemHovered() && ImGui::IsMouseReleased(ImGuiMouseButton_Right);
                        PopFontIfPushed(pushedHandleFont);
                        RenderInspectorValueContextMenu(
                            "HandleValueContext",
                            handleValue,
                            handleContextRequested);

                        ImGui::TableSetColumnIndex(1);
                        const std::wstring objectTypeText = HandleObjectTypeText(handle);
                        ImGui::TextUnformatted(WideToUtf8(objectTypeText).c_str());
                        const bool typeHovered = ImGui::IsItemHovered();
                        if (typeHovered)
                        {
                            if (IsRawObjectTypeIndex(handle.objectType))
                            {
                                RenderWrappedTooltip(
                                    L"Object type name unavailable. Raw object type index: " + handle.objectType + L".",
                                    520.0f);
                            }
                            else
                            {
                                RenderWrappedTooltip(objectTypeText, 520.0f);
                            }
                        }
                        RenderInspectorValueContextMenu(
                            "HandleTypeValueContext",
                            objectTypeText,
                            typeHovered && ImGui::IsMouseReleased(ImGuiMouseButton_Right));

                        ImGui::TableSetColumnIndex(2);
                        const std::wstring targetText = HandleTargetText(handle);
                        ImGui::TextUnformatted(WideToUtf8(targetText).c_str());
                        const bool targetHovered = ImGui::IsItemHovered();
                        if (targetHovered)
                        {
                            RenderWrappedTooltip(HandleTargetTooltipText(handle), 600.0f);
                        }
                        RenderInspectorValueContextMenu(
                            "HandleTargetValueContext",
                            targetText,
                            targetHovered && ImGui::IsMouseReleased(ImGuiMouseButton_Right));

                        ImGui::TableSetColumnIndex(3);
                        const std::wstring accessText =
                            handle.grantedAccess.empty() ? L"(unknown)" : handle.grantedAccess;
                        const bool pushedAccessFont = PushFontIfAvailable(fonts_.monospace);
                        TextWide(accessText);
                        const bool accessHovered = ImGui::IsItemHovered();
                        PopFontIfPushed(pushedAccessFont);
                        if (accessHovered)
                        {
                            RenderWrappedTooltip(HandleAccessTooltipText(handle), 520.0f);
                        }
                        RenderInspectorValueContextMenu(
                            "HandleAccessValueContext",
                            accessText,
                            accessHovered && ImGui::IsMouseReleased(ImGuiMouseButton_Right));

                        ImGui::TableSetColumnIndex(4);
                        const std::wstring indicators = HandleIndicatorText(handle);
                        const std::wstring status = HandleStatusText(handle);
                        std::wstring displayedIndicatorText;
                        bool indicatorHovered = false;
                        if (!indicators.empty())
                        {
                            displayedIndicatorText = indicators;
                            ImGui::TextColored(
                                handle.isSensitive ? SeverityColor(Core::Severity::Medium) : SeverityColor(Core::Severity::Low),
                                "%s",
                                WideToUtf8(indicators).c_str());
                            indicatorHovered = ImGui::IsItemHovered();
                            if (indicatorHovered)
                            {
                                RenderWrappedTooltip(indicators, 560.0f);
                            }
                        }
                        else if (!status.empty())
                        {
                            displayedIndicatorText = status;
                            ImGui::TextDisabled("%s", WideToUtf8(status).c_str());
                            indicatorHovered = ImGui::IsItemHovered();
                            if (indicatorHovered && !handle.errorMessage.empty())
                            {
                                RenderWrappedTooltip(handle.errorMessage, 560.0f);
                            }
                        }
                        else
                        {
                            displayedIndicatorText = L"None";
                            ImGui::TextDisabled("None");
                            indicatorHovered = ImGui::IsItemHovered();
                        }
                        const bool indicatorContextRequested =
                            indicatorHovered && ImGui::IsMouseReleased(ImGuiMouseButton_Right);
                        RenderInspectorValueContextMenu(
                            "HandleIndicatorValueContext",
                            displayedIndicatorText,
                            indicatorContextRequested);

                        ImGui::PopID();
                    }
                }

                ImGui::EndTable();
            }
        }

        void RenderNetworkPanel()
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                RenderEmptyState("No process is selected.", "Select a process to review network connections.");
                return;
            }

            const bool pushedNetworkTitleFont = PushFontIfAvailable(fonts_.bold);
            ImGui::TextColored(ImVec4(0.72f, 0.84f, 0.96f, 1.0f), "%s", DisplayName(process->name).c_str());
            PopFontIfPushed(pushedNetworkTitleFont);
            ImGui::SameLine();
            const bool pushedNetworkPidFont = PushFontIfAvailable(fonts_.monospace);
            ImGui::TextDisabled("PID %u", process->pid);
            PopFontIfPushed(pushedNetworkPidFont);

            ImGui::Separator();
            if (LoadedSnapshotLiveActionButton("Refresh Network"))
            {
                RefreshNetwork(true);
            }
            ImGui::SameLine();
            const bool operationActive = IsLongOperationActive();
            const bool loadIntelDisabled = loadedSnapshotActive_ || operationActive;
            if (!loadIntelDisabled)
            {
                if (ImGui::Button("Load Intel Feed"))
                {
                    LoadNetworkIntelFeed();
                }
            }
            else
            {
                ImGui::BeginDisabled();
                ImGui::Button("Load Intel Feed");
                ImGui::EndDisabled();
                RenderDisabledReasonTooltip(
                    operationActive
                        ? "Unavailable while another operation is running."
                        : "Live collection is disabled while viewing a saved snapshot.");
            }
            ImGui::SameLine();
            const bool updateIntelDisabled =
                loadedSnapshotActive_ || networkIndicatorUpdateInProgress_ || operationActive;
            if (updateIntelDisabled)
            {
                ImGui::BeginDisabled();
            }
            if (ImGui::Button(networkIndicatorUpdateInProgress_ ? "Updating..." : "Update Intel Feed"))
            {
                RequestNetworkIntelFeedUpdate();
            }
            if (updateIntelDisabled)
            {
                ImGui::EndDisabled();
                const char* disabledReason = loadedSnapshotActive_
                    ? "Live collection is disabled while viewing a saved snapshot."
                    : (networkIndicatorUpdateInProgress_
                        ? "A Network Intelligence update is already running."
                        : "Unavailable while another operation is running.");
                RenderDisabledReasonTooltip(disabledReason);
            }
            WrappedTextDisabled(std::wstring(L"Last refreshed: ") + lastNetworkRefreshTime_);
            RenderNetworkIntelStatus();

            if (!networkLoaded_)
            {
                ImGui::Spacing();
                if (loadedSnapshotActive_)
                {
                    RenderEmptyState(
                        "Network rows were not collected in this saved snapshot.",
                        "Return to Live View to collect live network information.");
                }
                else
                {
                    RenderEmptyState(
                        "Network information has not been collected for this process.",
                        "Use Refresh Network to inspect local socket ownership.");
                }
                return;
            }

            if (loadedSnapshotActive_)
            {
                WrappedTextDisabled("Network rows are available from this saved snapshot.");
            }

            if (!networkSnapshot_.success)
            {
                WrappedTextColored(
                    ImVec4(0.96f, 0.52f, 0.20f, 1.0f),
                    "Network information is unavailable: " + WideToUtf8(networkSnapshot_.statusMessage));
            }
            else
            {
                WrappedTextDisabled(networkSnapshot_.statusMessage);
            }

            const std::vector<const Core::NetworkConnection*> selectedConnections = SelectedNetworkConnections();
            const NetworkSummary summary = GetNetworkSummary(process->pid);
            ImGui::TextDisabled(
                "%zu connections | %zu listening | %zu public remote",
                summary.connectionCount,
                summary.listeningCount,
                summary.publicRemoteCount);
            if (summary.intelMatchCount > 0)
            {
                ImGui::SameLine();
                ImGui::TextColored(
                    SeverityColor(Core::Severity::Medium),
                    "| %zu intel match%s",
                    summary.intelMatchCount,
                    summary.intelMatchCount == 1 ? "" : "es");
            }

            if (selectedConnections.empty())
            {
                ImGui::Spacing();
                RenderEmptyState("No network connections were observed for this process.");
                return;
            }

            const ImGuiTableFlags flags =
                ImGuiTableFlags_BordersInnerV |
                ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Resizable |
                ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_SizingStretchProp |
                ImGuiTableFlags_NoSavedSettings |
                ImGuiTableFlags_Sortable |
                ImGuiTableFlags_SortTristate;
            AcknowledgeTableAutoSizeRequest(networkTableNeedsAutoSize_);
            if (ImGui::BeginTable("NetworkTable##NetworkPanel", 6, flags))
            {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn(
                    "Protocol",
                    ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_PreferSortAscending,
                    76.0f);
                ImGui::TableSetupColumn(
                    "Local",
                    ImGuiTableColumnFlags_WidthStretch | ImGuiTableColumnFlags_PreferSortAscending);
                ImGui::TableSetupColumn(
                    "Remote",
                    ImGuiTableColumnFlags_WidthStretch | ImGuiTableColumnFlags_PreferSortAscending);
                ImGui::TableSetupColumn(
                    "State",
                    ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_PreferSortAscending,
                    96.0f);
                ImGui::TableSetupColumn(
                    "Type/Scope",
                    ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_PreferSortAscending,
                    150.0f);
                ImGui::TableSetupColumn(
                    "Intel",
                    ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoSort,
                    116.0f);
                ImGui::TableHeadersRow();

                std::vector<std::size_t> connectionView = NaturalInspectorIndexView(selectedConnections.size());
                SortInspectorIndexView(
                    connectionView,
                    ImGui::TableGetSortSpecs(),
                    [this, &selectedConnections](std::size_t leftIndex, std::size_t rightIndex, int columnIndex) {
                        const Core::NetworkConnection& left = *selectedConnections[leftIndex];
                        const Core::NetworkConnection& right = *selectedConnections[rightIndex];
                        int result = 0;
                        switch (columnIndex)
                        {
                        case 0:
                            return CompareInspectorTextCaseInsensitive(left.protocol, right.protocol);
                        case 1:
                            result = CompareInspectorTextCaseInsensitive(left.localAddress, right.localAddress);
                            return result != 0
                                ? result
                                : CompareInspectorUnsigned(left.localPort, right.localPort);
                        case 2:
                            result = CompareInspectorTextCaseInsensitive(left.remoteAddress, right.remoteAddress);
                            return result != 0
                                ? result
                                : CompareInspectorUnsigned(left.remotePort, right.remotePort);
                        case 3:
                            return CompareInspectorTextCaseInsensitive(left.state, right.state);
                        case 4:
                            return CompareInspectorTextCaseInsensitive(
                                NetworkScopeText(left),
                                NetworkScopeText(right));
                        default:
                            return 0;
                        }
                    });

                ImGuiListClipper clipper;
                clipper.Begin(static_cast<int>(connectionView.size()));
                while (clipper.Step())
                {
                    for (int rowIndex = clipper.DisplayStart; rowIndex < clipper.DisplayEnd; ++rowIndex)
                    {
                        const Core::NetworkConnection* connection =
                            selectedConnections[connectionView[static_cast<std::size_t>(rowIndex)]];
                        if (connection == nullptr)
                        {
                            continue;
                        }

                        ImGui::TableNextRow();
                        ImGui::PushID(static_cast<const void*>(connection));
                        ImGui::TableSetColumnIndex(0);
                        TextWide(connection->protocol);
                        RenderInspectorValueContextMenu(
                            "NetworkProtocolValueContext",
                            connection->protocol,
                            ImGui::IsItemHovered() && ImGui::IsMouseReleased(ImGuiMouseButton_Right));

                        const bool pushedEndpointFont = PushFontIfAvailable(fonts_.monospace);
                        ImGui::TableSetColumnIndex(1);
                        const std::wstring localEndpoint = NetworkEndpoint(*connection, false);
                        RenderInspectorClippedValue("NetworkLocalValueContext", localEndpoint);
                        ImGui::TableSetColumnIndex(2);
                        const std::wstring remoteEndpoint = NetworkEndpoint(*connection, true);
                        RenderInspectorClippedValue("NetworkRemoteValueContext", remoteEndpoint);
                        ImGui::TableSetColumnIndex(3);
                        const std::wstring stateText = connection->state.empty() ? L"-" : connection->state;
                        TextWide(stateText);
                        const bool stateContextRequested =
                            ImGui::IsItemHovered() && ImGui::IsMouseReleased(ImGuiMouseButton_Right);
                        PopFontIfPushed(pushedEndpointFont);
                        RenderInspectorValueContextMenu(
                            "NetworkStateValueContext",
                            stateText,
                            stateContextRequested);

                        ImGui::TableSetColumnIndex(4);
                        const std::wstring scopeText = NetworkScopeText(*connection);
                        if (connection->isPublicRemote)
                        {
                            ImGui::TextColored(SeverityColor(Core::Severity::Low), "%s", WideToUtf8(scopeText).c_str());
                        }
                        else
                        {
                            TextWide(scopeText);
                        }
                        RenderInspectorValueContextMenu(
                            "NetworkScopeValueContext",
                            scopeText,
                            ImGui::IsItemHovered() && ImGui::IsMouseReleased(ImGuiMouseButton_Right));

                        ImGui::TableSetColumnIndex(5);
                        const std::vector<const Core::NetworkIndicatorMatch*> intelMatches =
                            NetworkIntelMatchesForConnection(*connection);
                        std::wstring intelText = L"-";
                        bool intelHovered = false;
                        if (intelMatches.empty())
                        {
                            ImGui::TextDisabled("-");
                            intelHovered = ImGui::IsItemHovered();
                        }
                        else
                        {
                            const Core::NetworkIndicatorMatch& firstMatch = *intelMatches.front();
                            intelText = NetworkIndicatorMatchLabel(firstMatch);
                            const Core::Severity intelSeverity =
                                NetworkIndicatorSeverityAsCoreSeverity(firstMatch.indicator.severity);
                            ImGui::TextColored(
                                SeverityColor(intelSeverity),
                                "%s",
                                WideToUtf8(intelText).c_str());
                            intelHovered = ImGui::IsItemHovered();
                            if (intelHovered)
                            {
                                RenderWrappedTooltip(NetworkIndicatorTooltipText(intelMatches), 560.0f);
                            }
                        }
                        RenderInspectorValueContextMenu(
                            "NetworkIntelValueContext",
                            intelText,
                            intelHovered && ImGui::IsMouseReleased(ImGuiMouseButton_Right));
                        ImGui::PopID();
                    }
                }

                ImGui::EndTable();
            }
        }

        void RenderRuntimePanel()
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                RenderEmptyState("No process is selected.", "Select a process to review runtime information.");
                return;
            }

            const bool pushedRuntimeTitleFont = PushFontIfAvailable(fonts_.bold);
            ImGui::TextColored(ImVec4(0.72f, 0.84f, 0.96f, 1.0f), "%s", DisplayName(process->name).c_str());
            PopFontIfPushed(pushedRuntimeTitleFont);
            ImGui::SameLine();
            const bool pushedRuntimePidFont = PushFontIfAvailable(fonts_.monospace);
            ImGui::TextDisabled("PID %u", process->pid);
            PopFontIfPushed(pushedRuntimePidFont);

            ImGui::Separator();
            if (LoadedSnapshotLiveActionButton("Refresh Runtime"))
            {
                RefreshRuntime(true);
            }

            if (!RuntimeLoadedForProcess(*process))
            {
                ImGui::Spacing();
                BeginInspectorCard("runtime_empty_state", "Runtime", fonts_.bold);
                if (loadedSnapshotActive_)
                {
                    RenderEmptyState(
                        "Runtime information was not collected in this saved snapshot.",
                        "Return to Live View to collect live runtime information.");
                }
                else
                {
                    RenderEmptyState(
                        "Runtime information has not been collected for this process.",
                        "Use Refresh Runtime to collect read-only scheduling, CPU, and thread metadata.");
                }
                EndInspectorCard();
                return;
            }

            if (loadedSnapshotActive_)
            {
                WrappedTextDisabled("Showing metadata preserved in saved snapshot.");
            }

            const Core::RuntimeInfo& runtime = selectedRuntime_;
            if (!runtime.success)
            {
                BeginInspectorCard("runtime_unavailable", "Runtime", fonts_.bold);
                const std::string runtimeDetail = WideToUtf8(runtime.errorMessage.empty()
                    ? L"Access was denied or the process exited."
                    : runtime.errorMessage);
                RenderEmptyState("Runtime information is unavailable.", runtimeDetail.c_str());
                if (!runtime.threads.empty())
                {
                    WrappedTextDisabled("Thread snapshot data may still be partial.");
                }
                EndInspectorCard();
            }

            if (runtime.success)
            {
                BeginInspectorCard("runtime_scheduling", "Scheduling", fonts_.bold);
                LabelValue("Priority Class", runtime.priorityClassName.empty() ? L"(unavailable)" : runtime.priorityClassName);
                LabelValue("Base Priority", std::to_wstring(runtime.basePriority));
                LabelValue("Affinity", runtime.affinityMaskString.empty() ? L"(unavailable)" : runtime.affinityMaskString);
                LabelValue("Processor Group", runtime.processorGroup.empty() ? L"(unavailable)" : runtime.processorGroup);
                LabelValue("Architecture", runtime.architecture.empty() ? L"(unknown)" : runtime.architecture);
                LabelValue("WOW64", YesNo(runtime.isWow64));
                EndInspectorCard();

                BeginInspectorCard("runtime_cpu", "CPU Time", fonts_.bold);
                LabelValue("User", runtime.userCpuTime.empty() ? L"(unavailable)" : runtime.userCpuTime);
                LabelValue("Kernel", runtime.kernelCpuTime.empty() ? L"(unavailable)" : runtime.kernelCpuTime);
                LabelValue("Total", runtime.totalCpuTime.empty() ? L"(unavailable)" : runtime.totalCpuTime);
                EndInspectorCard();

                BeginInspectorCard("runtime_memory", "Memory", fonts_.bold);
                LabelValue("Working Set", FileSizeText(runtime.workingSetSize));
                LabelValue("Peak Working Set", FileSizeText(runtime.peakWorkingSetSize));
                LabelValue("Private Bytes", FileSizeText(runtime.privateBytes));
                LabelValue("Pagefile Usage", FileSizeText(runtime.pagefileUsage));
                LabelValue("Peak Pagefile", FileSizeText(runtime.peakPagefileUsage));
                EndInspectorCard();

                BeginInspectorCard("runtime_counts", "Counts", fonts_.bold);
                LabelValue("Threads", std::to_wstring(runtime.threadCount));
                LabelValue("Handles", std::to_wstring(runtime.handleCount));
                if (!runtime.errorMessage.empty())
                {
                    ImGui::SeparatorText("Status");
                    WrappedTextDisabled(runtime.errorMessage);
                }
                EndInspectorCard();
            }

            const Core::ChainAnalysisResult& chain = CachedChainAnalysis(*process);
            Core::FileIdentity loadedSnapshotFileIdentity;
            const Core::FileIdentity& fileIdentity = loadedSnapshotActive_
                ? loadedSnapshotFileIdentity
                : CachedFileIdentity(*process);
            const std::vector<Core::Finding>& findings =
                FindingsForSelectedProcess(*process, chain, fileIdentity);
            bool hasRuntimeContext = !runtime.contextNotes.empty();
            for (const Core::Finding& finding : findings)
            {
                if (finding.category == L"Runtime")
                {
                    hasRuntimeContext = true;
                    break;
                }
            }

            if (hasRuntimeContext)
            {
                BeginInspectorCard("runtime_context", "Runtime Context", fonts_.bold);
                for (const std::wstring& note : runtime.contextNotes)
                {
                    ImGui::Bullet();
                    ImGui::SameLine();
                    WrappedTextDisabled(note);
                }
                for (const Core::Finding& finding : findings)
                {
                    if (finding.category != L"Runtime")
                    {
                        continue;
                    }

                    SeverityText(FindingSeverityAsCoreSeverity(finding.severity));
                    ImGui::SameLine();
                    WrappedTextWide(finding.title);
                    for (const std::wstring& evidence : finding.evidence)
                    {
                        ImGui::Bullet();
                        ImGui::SameLine();
                        WrappedTextDisabled(evidence);
                    }
                    ImGui::Spacing();
                }
                EndInspectorCard();
            }

            BeginInspectorCard("runtime_threads", "Threads", fonts_.bold);
            if (runtime.threads.empty())
            {
                RenderEmptyState("No thread information was returned for this process.");
                EndInspectorCard();
                return;
            }

            const ImGuiTableFlags flags =
                ImGuiTableFlags_BordersInnerV |
                ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Resizable |
                ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_SizingStretchProp |
                ImGuiTableFlags_NoSavedSettings |
                ImGuiTableFlags_Sortable |
                ImGuiTableFlags_SortTristate;
            AcknowledgeTableAutoSizeRequest(runtimeTableNeedsAutoSize_);
            if (ImGui::BeginTable("RuntimeThreadsTable##RuntimePanel", 5, flags, ImVec2(0.0f, 270.0f)))
            {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn(
                    "Thread ID",
                    ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_PreferSortAscending,
                    88.0f);
                ImGui::TableSetupColumn(
                    "Base",
                    ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_PreferSortAscending,
                    64.0f);
                ImGui::TableSetupColumn(
                    "Current",
                    ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_PreferSortAscending,
                    76.0f);
                ImGui::TableSetupColumn(
                    "Start Address",
                    ImGuiTableColumnFlags_WidthStretch | ImGuiTableColumnFlags_PreferSortAscending);
                ImGui::TableSetupColumn(
                    "Module",
                    ImGuiTableColumnFlags_WidthStretch | ImGuiTableColumnFlags_PreferSortAscending);
                ImGui::TableHeadersRow();

                std::vector<std::size_t> threadView = NaturalInspectorIndexView(runtime.threads.size());
                SortInspectorIndexView(
                    threadView,
                    ImGui::TableGetSortSpecs(),
                    [&runtime](std::size_t leftIndex, std::size_t rightIndex, int columnIndex) {
                        const Core::ThreadInfo& left = runtime.threads[leftIndex];
                        const Core::ThreadInfo& right = runtime.threads[rightIndex];
                        switch (columnIndex)
                        {
                        case 0:
                            return CompareInspectorUnsigned(left.threadId, right.threadId);
                        case 1:
                            return CompareInspectorSigned(left.basePriority, right.basePriority);
                        case 2:
                            if (left.hasCurrentPriority != right.hasCurrentPriority)
                            {
                                return left.hasCurrentPriority ? -1 : 1;
                            }
                            return CompareInspectorSigned(left.currentPriority, right.currentPriority);
                        case 3:
                            return CompareInspectorUnsigned(
                                InspectorNumericAddress(left.startAddress),
                                InspectorNumericAddress(right.startAddress));
                        case 4:
                            return CompareInspectorTextCaseInsensitive(
                                left.startAddressResolvedModule,
                                right.startAddressResolvedModule);
                        default:
                            return 0;
                        }
                    });

                ImGuiListClipper clipper;
                clipper.Begin(static_cast<int>(threadView.size()));
                while (clipper.Step())
                {
                    for (int rowIndex = clipper.DisplayStart; rowIndex < clipper.DisplayEnd; ++rowIndex)
                    {
                        const std::size_t threadIndex = threadView[static_cast<std::size_t>(rowIndex)];
                        const Core::ThreadInfo& thread = runtime.threads[threadIndex];
                        ImGui::TableNextRow();
                        ImGui::PushID(static_cast<int>(threadIndex));

                        const bool pushedThreadFont = PushFontIfAvailable(fonts_.monospace);
                        ImGui::TableSetColumnIndex(0);
                        ImGui::Text("%u", thread.threadId);
                        const bool threadIdHovered = ImGui::IsItemHovered();
                        if (threadIdHovered && !thread.errorMessage.empty())
                        {
                            RenderWrappedTooltip(thread.errorMessage, 560.0f);
                        }
                        RenderInspectorValueContextMenu(
                            "RuntimeThreadIdValueContext",
                            std::to_wstring(thread.threadId),
                            threadIdHovered && ImGui::IsMouseReleased(ImGuiMouseButton_Right));

                        ImGui::TableSetColumnIndex(1);
                        ImGui::Text("%d", thread.basePriority);
                        RenderInspectorValueContextMenu(
                            "RuntimeBasePriorityValueContext",
                            std::to_wstring(thread.basePriority),
                            ImGui::IsItemHovered() && ImGui::IsMouseReleased(ImGuiMouseButton_Right));

                        ImGui::TableSetColumnIndex(2);
                        const std::wstring currentPriorityText = thread.hasCurrentPriority
                            ? std::to_wstring(thread.currentPriority)
                            : L"N/A";
                        if (thread.hasCurrentPriority)
                        {
                            ImGui::Text("%d", thread.currentPriority);
                        }
                        else
                        {
                            ImGui::TextDisabled("N/A");
                        }
                        RenderInspectorValueContextMenu(
                            "RuntimeCurrentPriorityValueContext",
                            currentPriorityText,
                            ImGui::IsItemHovered() && ImGui::IsMouseReleased(ImGuiMouseButton_Right));

                        ImGui::TableSetColumnIndex(3);
                        const std::wstring startAddress =
                            thread.startAddress.empty() ? L"Unavailable" : thread.startAddress;
                        RenderInspectorClippedValue("RuntimeStartAddressValueContext", startAddress);

                        ImGui::TableSetColumnIndex(4);
                        const std::wstring resolvedModule = thread.startAddressResolvedModule.empty()
                            ? L"(unresolved)"
                            : thread.startAddressResolvedModule;
                        RenderInspectorClippedValue("RuntimeModuleValueContext", resolvedModule);
                        PopFontIfPushed(pushedThreadFont);
                        ImGui::PopID();
                    }
                }

                ImGui::EndTable();
            }
            EndInspectorCard();
        }

        void RenderMemoryPanel()
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                RenderEmptyState("No process is selected.", "Select a process to review memory regions.");
                return;
            }

            const bool pushedMemoryTitleFont = PushFontIfAvailable(fonts_.bold);
            ImGui::TextColored(ImVec4(0.72f, 0.84f, 0.96f, 1.0f), "%s", DisplayName(process->name).c_str());
            PopFontIfPushed(pushedMemoryTitleFont);
            ImGui::SameLine();
            const bool pushedMemoryPidFont = PushFontIfAvailable(fonts_.monospace);
            ImGui::TextDisabled("PID %u", process->pid);
            PopFontIfPushed(pushedMemoryPidFont);

            ImGui::Separator();
            if (LoadedSnapshotLiveActionButton("Refresh Memory"))
            {
                RefreshMemory(true);
            }

            if (!MemoryLoadedForProcess(*process))
            {
                ImGui::Spacing();
                BeginInspectorCard("memory_empty_state", "Memory", fonts_.bold);
                if (loadedSnapshotActive_)
                {
                    RenderEmptyState(
                        "Memory region information was not collected in this saved snapshot.",
                        "Return to Live View to collect live memory region information.");
                }
                else
                {
                    RenderEmptyState(
                        "Memory region information has not been collected for this process.",
                        "Use Refresh Memory to inspect metadata only; memory contents are not read or saved.");
                }
                EndInspectorCard();
                return;
            }

            if (loadedSnapshotActive_)
            {
                WrappedTextDisabled("Showing metadata preserved in saved snapshot.");
            }

            const Core::MemoryCollectionResult& memory = selectedMemory_;
            if (!memory.success)
            {
                BeginInspectorCard("memory_unavailable", "Memory", fonts_.bold);
                const std::string memoryDetail = WideToUtf8(memory.statusMessage.empty()
                    ? L"Access was denied, the process is protected, or it exited."
                    : memory.statusMessage);
                RenderEmptyState("Memory region information is unavailable.", memoryDetail.c_str());
                EndInspectorCard();
                if (memory.regions.empty())
                {
                    return;
                }
            }

            BeginInspectorCard("memory_summary", "Memory Summary", fonts_.bold);
            LabelValue("Total Regions", std::to_wstring(memory.totalRegions));
            LabelValue("Executable", std::to_wstring(memory.executableRegions));
            LabelValue("Private Executable", std::to_wstring(memory.privateExecutableRegions));
            LabelValue("RWX", std::to_wstring(memory.rwxRegions));
            LabelValue("Suspicious", std::to_wstring(memory.suspiciousRegions));
            LabelValue("Guard Pages", std::to_wstring(memory.guardRegions));
            if (!memory.statusMessage.empty())
            {
                ImGui::SeparatorText("Status");
                WrappedTextDisabled(memory.statusMessage);
            }
            EndInspectorCard();

            BeginInspectorCard("memory_filters", "Filters", fonts_.bold);
            ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x);
            if (ImGui::InputTextWithHint(
                "##MemoryPanelSearch",
                "Search address, protection, type, mapped file, indicator",
                memorySearchBuffer_.data(),
                memorySearchBuffer_.size()))
            {
                const std::wstring loweredSearch = ToLower(Utf8ToWide(memorySearchBuffer_.data()));
                if (memorySearchText_ != loweredSearch)
                {
                    memorySearchText_ = loweredSearch;
                    visibleMemoryRegionsDirty_ = true;
                    memoryTableNeedsAutoSize_ = true;
                }
            }

            if (ChipButton("All##MemoryFilter", memoryFilter_ == MemoryFilter::All, AccentBlue()))
            {
                if (memoryFilter_ != MemoryFilter::All)
                {
                    memoryFilter_ = MemoryFilter::All;
                    visibleMemoryRegionsDirty_ = true;
                    memoryTableNeedsAutoSize_ = true;
                }
            }
            SameLineIfChipFits("Executable");
            if (ChipButton("Executable##MemoryFilter", memoryFilter_ == MemoryFilter::Executable, AccentBlue()))
            {
                if (memoryFilter_ != MemoryFilter::Executable)
                {
                    memoryFilter_ = MemoryFilter::Executable;
                    visibleMemoryRegionsDirty_ = true;
                    memoryTableNeedsAutoSize_ = true;
                }
            }
            SameLineIfChipFits("Writable");
            if (ChipButton("Writable##MemoryFilter", memoryFilter_ == MemoryFilter::Writable, SeverityColor(Core::Severity::Low)))
            {
                if (memoryFilter_ != MemoryFilter::Writable)
                {
                    memoryFilter_ = MemoryFilter::Writable;
                    visibleMemoryRegionsDirty_ = true;
                    memoryTableNeedsAutoSize_ = true;
                }
            }
            SameLineIfChipFits("Private");
            if (ChipButton("Private##MemoryFilter", memoryFilter_ == MemoryFilter::Private, AccentBlue()))
            {
                if (memoryFilter_ != MemoryFilter::Private)
                {
                    memoryFilter_ = MemoryFilter::Private;
                    visibleMemoryRegionsDirty_ = true;
                    memoryTableNeedsAutoSize_ = true;
                }
            }
            SameLineIfChipFits("Image");
            if (ChipButton("Image##MemoryFilter", memoryFilter_ == MemoryFilter::Image, AccentBlue()))
            {
                if (memoryFilter_ != MemoryFilter::Image)
                {
                    memoryFilter_ = MemoryFilter::Image;
                    visibleMemoryRegionsDirty_ = true;
                    memoryTableNeedsAutoSize_ = true;
                }
            }
            SameLineIfChipFits("Suspicious");
            if (ChipButton("Suspicious##MemoryFilter", memoryFilter_ == MemoryFilter::Suspicious, SeverityColor(Core::Severity::Medium)))
            {
                if (memoryFilter_ != MemoryFilter::Suspicious)
                {
                    memoryFilter_ = MemoryFilter::Suspicious;
                    visibleMemoryRegionsDirty_ = true;
                    memoryTableNeedsAutoSize_ = true;
                }
            }
            SameLineIfChipFits("RWX");
            if (ChipButton("RWX##MemoryFilter", memoryFilter_ == MemoryFilter::Rwx, SeverityColor(Core::Severity::Medium)))
            {
                if (memoryFilter_ != MemoryFilter::Rwx)
                {
                    memoryFilter_ = MemoryFilter::Rwx;
                    visibleMemoryRegionsDirty_ = true;
                    memoryTableNeedsAutoSize_ = true;
                }
            }
            EndInspectorCard();

            RebuildVisibleMemoryRegionsIfNeeded(*process);

            BeginInspectorCard("memory_regions", "Regions", fonts_.bold);
            LabelValue("Visible", std::to_wstring(visibleMemoryRegionIndexes_.size()));
            if (visibleMemoryRegionIndexes_.empty())
            {
                RenderEmptyState("No memory regions match the current filters.");
                EndInspectorCard();
                return;
            }

            const ImGuiTableFlags flags =
                ImGuiTableFlags_BordersInnerV |
                ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Resizable |
                ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_SizingStretchProp |
                ImGuiTableFlags_NoSavedSettings |
                ImGuiTableFlags_Sortable |
                ImGuiTableFlags_SortTristate;
            AcknowledgeTableAutoSizeRequest(memoryTableNeedsAutoSize_);
            if (ImGui::BeginTable("MemoryRegionsTable##MemoryPanel", 7, flags, ImVec2(0.0f, 340.0f)))
            {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn(
                    "Base",
                    ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_PreferSortAscending,
                    124.0f);
                ImGui::TableSetupColumn(
                    "Size",
                    ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_PreferSortAscending,
                    82.0f);
                ImGui::TableSetupColumn(
                    "State",
                    ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_PreferSortAscending,
                    78.0f);
                ImGui::TableSetupColumn(
                    "Type",
                    ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_PreferSortAscending,
                    76.0f);
                ImGui::TableSetupColumn(
                    "Protection",
                    ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_PreferSortAscending,
                    108.0f);
                ImGui::TableSetupColumn(
                    "Mapped file",
                    ImGuiTableColumnFlags_WidthStretch | ImGuiTableColumnFlags_PreferSortAscending);
                ImGui::TableSetupColumn(
                    "Indicators",
                    ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoSort,
                    140.0f);
                ImGui::TableHeadersRow();

                std::vector<std::size_t> regionView = visibleMemoryRegionIndexes_;
                SortInspectorIndexView(
                    regionView,
                    ImGui::TableGetSortSpecs(),
                    [&memory](std::size_t leftIndex, std::size_t rightIndex, int columnIndex) {
                        const Core::MemoryRegionInfo& left = memory.regions[leftIndex];
                        const Core::MemoryRegionInfo& right = memory.regions[rightIndex];
                        switch (columnIndex)
                        {
                        case 0:
                            return CompareInspectorUnsigned(left.baseAddress, right.baseAddress);
                        case 1:
                            return CompareInspectorUnsigned(left.regionSize, right.regionSize);
                        case 2:
                            return CompareInspectorTextCaseInsensitive(left.stateName, right.stateName);
                        case 3:
                            return CompareInspectorTextCaseInsensitive(left.typeName, right.typeName);
                        case 4:
                            return CompareInspectorTextCaseInsensitive(left.protectName, right.protectName);
                        case 5:
                            return CompareInspectorTextCaseInsensitive(left.mappedFilePath, right.mappedFilePath);
                        default:
                            return 0;
                        }
                    });

                ImGuiListClipper clipper;
                clipper.Begin(static_cast<int>(regionView.size()));
                while (clipper.Step())
                {
                    for (int rowIndex = clipper.DisplayStart; rowIndex < clipper.DisplayEnd; ++rowIndex)
                    {
                        const std::size_t regionIndex = regionView[static_cast<std::size_t>(rowIndex)];
                        if (regionIndex >= memory.regions.size())
                        {
                            continue;
                        }
                        const Core::MemoryRegionInfo& region = memory.regions[regionIndex];
                        ImGui::TableNextRow();
                        if (region.isSuspicious)
                        {
                            ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, ColorU32(ImVec4(0.24f, 0.10f, 0.05f, 0.55f)));
                        }
                        else if (region.isGuard)
                        {
                            ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, ColorU32(ImVec4(0.12f, 0.14f, 0.18f, 0.48f)));
                        }

                        ImGui::PushID(static_cast<int>(regionIndex));
                        const bool pushedAddressFont = PushFontIfAvailable(fonts_.monospace);
                        ImGui::TableSetColumnIndex(0);
                        RenderInspectorClippedValue("MemoryBaseValueContext", region.baseAddressString);
                        ImGui::TableSetColumnIndex(1);
                        TextWide(region.regionSizeString);
                        const bool sizeContextRequested =
                            ImGui::IsItemHovered() && ImGui::IsMouseReleased(ImGuiMouseButton_Right);
                        PopFontIfPushed(pushedAddressFont);
                        RenderInspectorValueContextMenu(
                            "MemorySizeValueContext",
                            region.regionSizeString,
                            sizeContextRequested);

                        ImGui::TableSetColumnIndex(2);
                        TextWide(region.stateName);
                        RenderInspectorValueContextMenu(
                            "MemoryStateValueContext",
                            region.stateName,
                            ImGui::IsItemHovered() && ImGui::IsMouseReleased(ImGuiMouseButton_Right));
                        ImGui::TableSetColumnIndex(3);
                        TextWide(region.typeName);
                        RenderInspectorValueContextMenu(
                            "MemoryTypeValueContext",
                            region.typeName,
                            ImGui::IsItemHovered() && ImGui::IsMouseReleased(ImGuiMouseButton_Right));
                        ImGui::TableSetColumnIndex(4);
                        const bool pushedProtectFont = PushFontIfAvailable(fonts_.monospace);
                        RenderInspectorClippedValue("MemoryProtectionValueContext", region.protectName);
                        PopFontIfPushed(pushedProtectFont);

                        ImGui::TableSetColumnIndex(5);
                        const std::wstring mappedFile =
                            region.mappedFilePath.empty() ? L"(none)" : region.mappedFilePath;
                        RenderInspectorClippedValue(
                            "MemoryMappedFileValueContext",
                            mappedFile,
                            region.mappedFilePath.empty() ? nullptr : &region.mappedFilePath);

                        ImGui::TableSetColumnIndex(6);
                        const std::wstring indicators = MemoryIndicatorText(region);
                        const std::wstring displayedIndicators = indicators.empty() ? L"None" : indicators;
                        bool indicatorsHovered = false;
                        if (indicators.empty())
                        {
                            ImGui::TextDisabled("None");
                            indicatorsHovered = ImGui::IsItemHovered();
                        }
                        else
                        {
                            ImGui::TextColored(
                                region.isSuspicious ? SeverityColor(Core::Severity::Medium) : SeverityColor(Core::Severity::Info),
                                "%s",
                                WideToUtf8(indicators).c_str());
                            indicatorsHovered = ImGui::IsItemHovered();
                            if (indicatorsHovered)
                            {
                                RenderWrappedTooltip(indicators, 600.0f);
                            }
                        }
                        RenderInspectorValueContextMenu(
                            "MemoryIndicatorsValueContext",
                            displayedIndicators,
                            indicatorsHovered && ImGui::IsMouseReleased(ImGuiMouseButton_Right));
                        ImGui::PopID();
                    }
                }
                ImGui::EndTable();
            }
            EndInspectorCard();
        }
