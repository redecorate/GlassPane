// ImGuiApp inspector subview render implementations.
// This file is intentionally included inside the ImGuiApp class definition so
// inspector rendering can move out of ImGuiApp.cpp without moving state ownership.

        void RenderTriagePanel()
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                ImGui::TextUnformatted("No process selected.");
                return;
            }

            const Core::ChainAnalysisResult& chain = CachedChainAnalysis(*process);
            const Core::FileIdentity& fileIdentity = CachedFileIdentity(process->executablePath);
            const std::vector<Core::Finding>& findings =
                FindingsForSelectedProcess(*process, chain, fileIdentity);
            const std::wstring triageSummary = Core::TriageSummary(findings);

            BeginInspectorCard("triage_summary", "Triage Summary", fonts_.bold);
            ImGui::TextDisabled("Selected Process");
            ImGui::SameLine(145.0f);
            TextWide((process->name.empty() ? L"(unknown)" : process->name) + L"  PID " + std::to_wstring(process->pid));
            ImGui::TextDisabled("Triage Verdict");
            ImGui::SameLine(145.0f);
            const Core::Severity verdictColorSeverity = findings.empty()
                ? Core::Severity::None
                : FindingSeverityAsCoreSeverity(Core::HighestFindingSeverity(findings));
            ImGui::TextColored(SeverityColor(verdictColorSeverity), "%s", WideToUtf8(triageSummary).c_str());
            ImGui::TextDisabled("Highest Severity");
            ImGui::SameLine(145.0f);
            if (findings.empty())
            {
                ImGui::TextDisabled("None");
            }
            else
            {
                SeverityText(FindingSeverityAsCoreSeverity(Core::HighestFindingSeverity(findings)));
            }
            LabelValue("Finding Count", std::to_wstring(findings.size()));
            ImGui::Spacing();
            if (ImGui::SmallButton("Copy Triage Summary"))
            {
                CopyTextToClipboard(FormatTriageSummaryForClipboard(*process, findings));
                AddLog(LogLevel::Info, "Copied triage summary to clipboard.");
            }
            ImGui::SameLine();
            if (ImGui::SmallButton("Copy All Findings"))
            {
                CopyTextToClipboard(FormatFindingsForClipboard(*process, findings));
                AddLog(LogLevel::Info, "Copied all triage findings to clipboard.");
            }
            ImGui::SameLine();
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
                WrappedTextDisabled("No triage findings for this process.");
                WrappedTextDisabled("Review details, modules, network, and chain context for raw evidence.");
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
                WrappedTextDisabled("No findings match the current triage filter.");
                WrappedTextDisabled("Current filter: " + WideToUtf8(TriageFilterLabel(triageFilter_)));
                EndInspectorCard();
            }
        }

        void RenderDetailsPanel()
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                ImGui::TextUnformatted("No process selected.");
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
            const Core::FileIdentity& fileIdentity = CachedFileIdentity(process->executablePath);
            const std::vector<Core::FileIdentityIndicator> fileIdentityIndicators =
                Core::BuildFileIdentityIndicators(fileIdentity, process->name, true);
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
            TextWide(process->name.empty() ? L"(unknown process)" : process->name);
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
            if (ImGui::SmallButton("Copy Path"))
            {
                CopyTextToClipboard(process->executablePath);
                AddLog(LogLevel::Info, "Copied executable path to clipboard.");
            }
            const bool pushedExecutionPathFont = PushFontIfAvailable(fonts_.monospace);
            WrappedTextWide(process->executablePath.empty() ? L"(not accessible)" : process->executablePath);
            PopFontIfPushed(pushedExecutionPathFont);
            ImGui::TextDisabled("Command Line");
            ImGui::SameLine();
            if (ImGui::SmallButton("Copy Command"))
            {
                CopyTextToClipboard(process->commandLine);
                AddLog(LogLevel::Info, "Copied command line to clipboard.");
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
                ImGui::TextDisabled("No process indicators.");
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
                ImGui::TextDisabled("No context notes.");
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

        void RenderChainPanel()
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                ImGui::TextUnformatted("No process selected.");
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
                ImGui::TextDisabled("No chain indicators.");
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
                ImGui::TextUnformatted("No process selected.");
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
            if (ImGui::Button("Refresh Modules"))
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
                ImGui::PushStyleColor(ImGuiCol_ChildBg, PanelBgRaised());
                ImGui::PushStyleColor(ImGuiCol_Border, PanelBorder());
                ImGui::BeginChild(
                    "modules_empty_state",
                    ImVec2(0.0f, 0.0f),
                    ImGuiChildFlags_Borders | ImGuiChildFlags_AlwaysUseWindowPadding | ImGuiChildFlags_AutoResizeY,
                    ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
                ImGui::TextColored(AccentBlue(), "Modules not loaded for this process.");
                ImGui::TextDisabled("Click Refresh Modules to inspect loaded DLLs.");
                ImGui::EndChild();
                ImGui::PopStyleColor(2);
                return;
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
                    "Modules unavailable: " + WideToUtf8(selectedModules_.statusMessage));
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
                WrappedTextDisabled("No modules returned for the selected process.");
                return;
            }

            const ImGuiTableFlags flags =
                ImGuiTableFlags_BordersInnerV |
                ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Resizable |
                ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_SizingStretchProp |
                ImGuiTableFlags_NoSavedSettings;
            AcknowledgeTableAutoSizeRequest(modulesTableNeedsAutoSize_);
            if (ImGui::BeginTable("ModulesTable##ModulesPanel", 4, flags))
            {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn("Module", ImGuiTableColumnFlags_WidthFixed, 155.0f);
                ImGui::TableSetupColumn("Base", ImGuiTableColumnFlags_WidthFixed, 112.0f);
                ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 76.0f);
                ImGui::TableSetupColumn("Path", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableHeadersRow();

                ImGuiListClipper clipper;
                clipper.Begin(static_cast<int>(selectedModules_.modules.size()));
                while (clipper.Step())
                {
                    for (int rowIndex = clipper.DisplayStart; rowIndex < clipper.DisplayEnd; ++rowIndex)
                    {
                        const std::size_t moduleIndex = static_cast<std::size_t>(rowIndex);
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
                        if (ImGui::Selectable(
                            WideToUtf8(module.moduleName.empty() ? L"(unknown)" : module.moduleName).c_str(),
                            moduleSelected,
                            ImGuiSelectableFlags_SpanAllColumns,
                            ImVec2(0.0f, 24.0f)))
                        {
                            selectedModulePid_ = selectedPid_;
                            selectedModuleIndex_ = moduleIndex;
                        }

                        ImGui::TableSetColumnIndex(1);
                        const bool pushedBaseFont = PushFontIfAvailable(fonts_.monospace);
                        TextWide(module.baseAddress);
                        ImGui::TableSetColumnIndex(2);
                        ImGui::Text("%u", module.sizeBytes);
                        ImGui::TableSetColumnIndex(3);
                        ClippedTextWithTooltip(module.modulePath.empty() ? L"(path unavailable)" : module.modulePath);
                        PopFontIfPushed(pushedBaseFont);
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
                TextWide(module.moduleName.empty() ? L"(unknown)" : module.moduleName);

                const bool pushedSelectedModuleFont = PushFontIfAvailable(fonts_.monospace);
                ImGui::TextDisabled("Base");
                ImGui::SameLine(92.0f);
                TextWide(module.baseAddress);
                ImGui::TextDisabled("Size");
                ImGui::SameLine(92.0f);
                ImGui::Text("%u", module.sizeBytes);
                ImGui::TextDisabled("Path");
                WrappedTextWide(module.modulePath.empty() ? L"(path unavailable)" : module.modulePath);
                PopFontIfPushed(pushedSelectedModuleFont);

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

        void RenderTokenPanel()
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                ImGui::TextUnformatted("No process selected.");
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
            if (ImGui::Button("Refresh Token"))
            {
                RefreshToken(true);
            }

            if (!TokenLoadedForProcess(*process))
            {
                ImGui::Spacing();
                BeginInspectorCard("token_empty_state", "Token", fonts_.bold);
                WrappedTextDisabled("Token data is not loaded for this process.");
                WrappedTextDisabled("Click Refresh Token to inspect read-only token metadata.");
                EndInspectorCard();
                return;
            }

            const Core::TokenInfo& token = selectedToken_;
            const std::wstring tokenUser = TokenUserText(token);
            const std::wstring integritySummary = token.integrityLevelName.empty()
                ? L"(unavailable)"
                : token.integrityLevelName + L" (" + std::to_wstring(token.integrityRid) + L")";

            if (!token.success)
            {
                BeginInspectorCard("token_unavailable", "Token", fonts_.bold);
                WrappedTextDisabled(
                    L"Token unavailable: " +
                    (token.errorMessage.empty() ? std::wstring(L"access denied or process exited") : token.errorMessage));
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
            const Core::FileIdentity& fileIdentity = CachedFileIdentity(process->executablePath);
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
                WrappedTextDisabled("No privileges returned for this token.");
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
                    WrappedTextDisabled("No privileges match the current filter.");
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
                ImGui::TextUnformatted("No process selected.");
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
            if (ImGui::Button("Refresh Handles"))
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
                WrappedTextDisabled("Handle data is not loaded for this process.");
                WrappedTextDisabled("Click Refresh Handles to inspect read-only handle metadata.");
                EndInspectorCard();
                return;
            }

            if (!selectedHandles_.success)
            {
                BeginInspectorCard("handles_unavailable", "Handles", fonts_.bold);
                WrappedTextColored(
                    ImVec4(0.96f, 0.52f, 0.20f, 1.0f),
                    "Handles unavailable: " + WideToUtf8(selectedHandles_.statusMessage.empty()
                        ? L"collection did not complete"
                        : selectedHandles_.statusMessage));
                EndInspectorCard();
                return;
            }

            if (selectedHandles_.handles.empty())
            {
                BeginInspectorCard("handles_none", "Handles", fonts_.bold);
                WrappedTextDisabled("No handles returned for this process.");
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
                WrappedTextDisabled("No handles match the current filters.");
                EndInspectorCard();
                return;
            }

            const ImGuiTableFlags flags =
                ImGuiTableFlags_BordersInnerV |
                ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Resizable |
                ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_SizingStretchProp |
                ImGuiTableFlags_NoSavedSettings;
            AcknowledgeTableAutoSizeRequest(handlesTableNeedsAutoSize_);
            if (ImGui::BeginTable("HandlesTable##HandlesPanel", 5, flags))
            {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn("Handle", ImGuiTableColumnFlags_WidthFixed, 76.0f);
                ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 88.0f);
                ImGui::TableSetupColumn("Target / Name", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Access", ImGuiTableColumnFlags_WidthFixed, 92.0f);
                ImGui::TableSetupColumn("Indicators", ImGuiTableColumnFlags_WidthFixed, 118.0f);
                ImGui::TableHeadersRow();

                ImGuiListClipper clipper;
                clipper.Begin(static_cast<int>(visibleHandleIndexes_.size()));
                while (clipper.Step())
                {
                    for (int rowIndex = clipper.DisplayStart; rowIndex < clipper.DisplayEnd; ++rowIndex)
                    {
                        const std::size_t visibleIndex = static_cast<std::size_t>(rowIndex);
                        const std::size_t handleIndex = visibleHandleIndexes_[visibleIndex];
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
                        const bool pushedHandleFont = PushFontIfAvailable(fonts_.monospace);
                        if (handle.isSensitive)
                        {
                            ImGui::TextColored(SeverityColor(Core::Severity::Medium), "%s", WideToUtf8(HandleValueText(handle.handleValue)).c_str());
                        }
                        else
                        {
                            ClippedTextWithTooltip(HandleValueText(handle.handleValue));
                        }
                        PopFontIfPushed(pushedHandleFont);

                        ImGui::TableSetColumnIndex(1);
                        const std::wstring objectTypeText = HandleObjectTypeText(handle);
                        ImGui::TextUnformatted(WideToUtf8(objectTypeText).c_str());
                        if (ImGui::IsItemHovered())
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

                        ImGui::TableSetColumnIndex(2);
                        ImGui::TextUnformatted(WideToUtf8(HandleTargetText(handle)).c_str());
                        if (ImGui::IsItemHovered())
                        {
                            RenderWrappedTooltip(HandleTargetTooltipText(handle), 600.0f);
                        }

                        ImGui::TableSetColumnIndex(3);
                        const bool pushedAccessFont = PushFontIfAvailable(fonts_.monospace);
                        TextWide(handle.grantedAccess.empty() ? L"(unknown)" : handle.grantedAccess);
                        PopFontIfPushed(pushedAccessFont);
                        if (ImGui::IsItemHovered())
                        {
                            RenderWrappedTooltip(HandleAccessTooltipText(handle), 520.0f);
                        }

                        ImGui::TableSetColumnIndex(4);
                        const std::wstring indicators = HandleIndicatorText(handle);
                        const std::wstring status = HandleStatusText(handle);
                        if (!indicators.empty())
                        {
                            ImGui::TextColored(
                                handle.isSensitive ? SeverityColor(Core::Severity::Medium) : SeverityColor(Core::Severity::Low),
                                "%s",
                                WideToUtf8(indicators).c_str());
                            if (ImGui::IsItemHovered())
                            {
                                RenderWrappedTooltip(indicators, 560.0f);
                            }
                        }
                        else if (!status.empty())
                        {
                            ImGui::TextDisabled("%s", WideToUtf8(status).c_str());
                            if (ImGui::IsItemHovered() && !handle.errorMessage.empty())
                            {
                                RenderWrappedTooltip(handle.errorMessage, 560.0f);
                            }
                        }
                        else
                        {
                            ImGui::TextDisabled("None");
                        }

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
                ImGui::TextUnformatted("No process selected.");
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
            if (ImGui::Button("Refresh Network"))
            {
                RefreshNetwork(true);
            }
            ImGui::SameLine();
            if (ImGui::Button("Load Intel Feed"))
            {
                LoadNetworkIntelFeed();
            }
            ImGui::SameLine();
            if (networkIndicatorUpdateInProgress_)
            {
                ImGui::BeginDisabled();
            }
            if (ImGui::Button(networkIndicatorUpdateInProgress_ ? "Updating..." : "Update Intel Feed"))
            {
                RequestNetworkIntelFeedUpdate();
            }
            if (networkIndicatorUpdateInProgress_)
            {
                ImGui::EndDisabled();
            }
            WrappedTextDisabled(std::wstring(L"Last refreshed: ") + lastNetworkRefreshTime_);
            RenderNetworkIntelStatus();

            if (!networkLoaded_)
            {
                ImGui::Spacing();
                ImGui::PushStyleColor(ImGuiCol_ChildBg, PanelBgRaised());
                ImGui::PushStyleColor(ImGuiCol_Border, PanelBorder());
                ImGui::BeginChild(
                    "network_empty_state",
                    ImVec2(0.0f, 0.0f),
                    ImGuiChildFlags_Borders | ImGuiChildFlags_AlwaysUseWindowPadding | ImGuiChildFlags_AutoResizeY,
                    ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
                ImGui::TextColored(AccentBlue(), "Network data not loaded.");
                ImGui::TextDisabled("Click Refresh Network to inspect local socket ownership.");
                ImGui::EndChild();
                ImGui::PopStyleColor(2);
                return;
            }

            if (!networkSnapshot_.success)
            {
                WrappedTextColored(
                    ImVec4(0.96f, 0.52f, 0.20f, 1.0f),
                    "Network unavailable: " + WideToUtf8(networkSnapshot_.statusMessage));
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
                ImGui::TextDisabled("No network connections for this process.");
                return;
            }

            const ImGuiTableFlags flags =
                ImGuiTableFlags_BordersInnerV |
                ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Resizable |
                ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_SizingStretchProp |
                ImGuiTableFlags_NoSavedSettings;
            AcknowledgeTableAutoSizeRequest(networkTableNeedsAutoSize_);
            if (ImGui::BeginTable("NetworkTable##NetworkPanel", 6, flags))
            {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn("Protocol", ImGuiTableColumnFlags_WidthFixed, 76.0f);
                ImGui::TableSetupColumn("Local", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Remote", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 96.0f);
                ImGui::TableSetupColumn("Type/Scope", ImGuiTableColumnFlags_WidthFixed, 150.0f);
                ImGui::TableSetupColumn("Intel", ImGuiTableColumnFlags_WidthFixed, 116.0f);
                ImGui::TableHeadersRow();

                ImGuiListClipper clipper;
                clipper.Begin(static_cast<int>(selectedConnections.size()));
                while (clipper.Step())
                {
                    for (int rowIndex = clipper.DisplayStart; rowIndex < clipper.DisplayEnd; ++rowIndex)
                    {
                        const Core::NetworkConnection* connection =
                            selectedConnections[static_cast<std::size_t>(rowIndex)];
                        if (connection == nullptr)
                        {
                            continue;
                        }

                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0);
                        TextWide(connection->protocol);

                        const bool pushedEndpointFont = PushFontIfAvailable(fonts_.monospace);
                        ImGui::TableSetColumnIndex(1);
                        ClippedTextWithTooltip(NetworkEndpoint(*connection, false));
                        ImGui::TableSetColumnIndex(2);
                        ClippedTextWithTooltip(NetworkEndpoint(*connection, true));
                        ImGui::TableSetColumnIndex(3);
                        TextWide(connection->state.empty() ? L"-" : connection->state);
                        PopFontIfPushed(pushedEndpointFont);

                        ImGui::TableSetColumnIndex(4);
                        if (connection->isPublicRemote)
                        {
                            ImGui::TextColored(SeverityColor(Core::Severity::Low), "%s", WideToUtf8(NetworkScopeText(*connection)).c_str());
                        }
                        else
                        {
                            TextWide(NetworkScopeText(*connection));
                        }

                        ImGui::TableSetColumnIndex(5);
                        const std::vector<const Core::NetworkIndicatorMatch*> intelMatches =
                            NetworkIntelMatchesForConnection(*connection);
                        if (intelMatches.empty())
                        {
                            ImGui::TextDisabled("-");
                        }
                        else
                        {
                            const Core::NetworkIndicatorMatch& firstMatch = *intelMatches.front();
                            const Core::Severity intelSeverity =
                                NetworkIndicatorSeverityAsCoreSeverity(firstMatch.indicator.severity);
                            ImGui::TextColored(
                                SeverityColor(intelSeverity),
                                "%s",
                                WideToUtf8(NetworkIndicatorMatchLabel(firstMatch)).c_str());
                            if (ImGui::IsItemHovered())
                            {
                                RenderWrappedTooltip(NetworkIndicatorTooltipText(intelMatches), 560.0f);
                            }
                        }
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
                ImGui::TextUnformatted("No process selected.");
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
            if (ImGui::Button("Refresh Runtime"))
            {
                RefreshRuntime(true);
            }

            if (!RuntimeLoadedForProcess(*process))
            {
                ImGui::Spacing();
                BeginInspectorCard("runtime_empty_state", "Runtime", fonts_.bold);
                WrappedTextDisabled("Runtime data is not loaded for this process.");
                WrappedTextDisabled("Click Refresh Runtime to inspect read-only scheduling, memory, CPU, and thread metadata.");
                EndInspectorCard();
                return;
            }

            const Core::RuntimeInfo& runtime = selectedRuntime_;
            if (!runtime.success)
            {
                BeginInspectorCard("runtime_unavailable", "Runtime", fonts_.bold);
                WrappedTextColored(
                    ImVec4(0.96f, 0.52f, 0.20f, 1.0f),
                    "Runtime unavailable: " + WideToUtf8(runtime.errorMessage.empty()
                        ? L"access denied or process exited"
                        : runtime.errorMessage));
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
            const Core::FileIdentity& fileIdentity = CachedFileIdentity(process->executablePath);
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
                WrappedTextDisabled("No thread metadata returned for this process.");
                EndInspectorCard();
                return;
            }

            const ImGuiTableFlags flags =
                ImGuiTableFlags_BordersInnerV |
                ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Resizable |
                ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_SizingStretchProp |
                ImGuiTableFlags_NoSavedSettings;
            AcknowledgeTableAutoSizeRequest(runtimeTableNeedsAutoSize_);
            if (ImGui::BeginTable("RuntimeThreadsTable##RuntimePanel", 5, flags, ImVec2(0.0f, 270.0f)))
            {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn("Thread ID", ImGuiTableColumnFlags_WidthFixed, 88.0f);
                ImGui::TableSetupColumn("Base", ImGuiTableColumnFlags_WidthFixed, 64.0f);
                ImGui::TableSetupColumn("Current", ImGuiTableColumnFlags_WidthFixed, 76.0f);
                ImGui::TableSetupColumn("Start Address", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Module", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableHeadersRow();

                ImGuiListClipper clipper;
                clipper.Begin(static_cast<int>(runtime.threads.size()));
                while (clipper.Step())
                {
                    for (int rowIndex = clipper.DisplayStart; rowIndex < clipper.DisplayEnd; ++rowIndex)
                    {
                        const Core::ThreadInfo& thread = runtime.threads[static_cast<std::size_t>(rowIndex)];
                        ImGui::TableNextRow();

                        const bool pushedThreadFont = PushFontIfAvailable(fonts_.monospace);
                        ImGui::TableSetColumnIndex(0);
                        ImGui::Text("%u", thread.threadId);
                        if (ImGui::IsItemHovered() && !thread.errorMessage.empty())
                        {
                            RenderWrappedTooltip(thread.errorMessage, 560.0f);
                        }

                        ImGui::TableSetColumnIndex(1);
                        ImGui::Text("%d", thread.basePriority);

                        ImGui::TableSetColumnIndex(2);
                        if (thread.hasCurrentPriority)
                        {
                            ImGui::Text("%d", thread.currentPriority);
                        }
                        else
                        {
                            ImGui::TextDisabled("N/A");
                        }

                        ImGui::TableSetColumnIndex(3);
                        ClippedTextWithTooltip(thread.startAddress.empty() ? L"Unavailable" : thread.startAddress);

                        ImGui::TableSetColumnIndex(4);
                        ClippedTextWithTooltip(thread.startAddressResolvedModule.empty()
                            ? L"(unresolved)"
                            : thread.startAddressResolvedModule);
                        PopFontIfPushed(pushedThreadFont);
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
                ImGui::TextUnformatted("No process selected.");
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
            if (ImGui::Button("Refresh Memory"))
            {
                RefreshMemory(true);
            }

            if (!MemoryLoadedForProcess(*process))
            {
                ImGui::Spacing();
                BeginInspectorCard("memory_empty_state", "Memory", fonts_.bold);
                WrappedTextDisabled("Memory region metadata is not loaded for this process.");
                WrappedTextDisabled("Click Refresh Memory to inspect virtual memory region metadata. GlassPane does not dump or read region contents.");
                EndInspectorCard();
                return;
            }

            const Core::MemoryCollectionResult& memory = selectedMemory_;
            if (!memory.success)
            {
                BeginInspectorCard("memory_unavailable", "Memory", fonts_.bold);
                WrappedTextColored(
                    ImVec4(0.96f, 0.52f, 0.20f, 1.0f),
                    "Memory unavailable: " + WideToUtf8(memory.statusMessage.empty()
                        ? L"access denied, protected process, or process exited"
                        : memory.statusMessage));
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
                WrappedTextDisabled("No memory regions match the current filters.");
                EndInspectorCard();
                return;
            }

            const ImGuiTableFlags flags =
                ImGuiTableFlags_BordersInnerV |
                ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Resizable |
                ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_SizingStretchProp |
                ImGuiTableFlags_NoSavedSettings;
            AcknowledgeTableAutoSizeRequest(memoryTableNeedsAutoSize_);
            if (ImGui::BeginTable("MemoryRegionsTable##MemoryPanel", 7, flags, ImVec2(0.0f, 340.0f)))
            {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn("Base", ImGuiTableColumnFlags_WidthFixed, 124.0f);
                ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 82.0f);
                ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 78.0f);
                ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 76.0f);
                ImGui::TableSetupColumn("Protection", ImGuiTableColumnFlags_WidthFixed, 108.0f);
                ImGui::TableSetupColumn("Mapped file", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Indicators", ImGuiTableColumnFlags_WidthFixed, 140.0f);
                ImGui::TableHeadersRow();

                ImGuiListClipper clipper;
                clipper.Begin(static_cast<int>(visibleMemoryRegionIndexes_.size()));
                while (clipper.Step())
                {
                    for (int rowIndex = clipper.DisplayStart; rowIndex < clipper.DisplayEnd; ++rowIndex)
                    {
                        const std::size_t visibleIndex = static_cast<std::size_t>(rowIndex);
                        const std::size_t regionIndex = visibleMemoryRegionIndexes_[visibleIndex];
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

                        ImGui::PushID(rowIndex);
                        const bool pushedAddressFont = PushFontIfAvailable(fonts_.monospace);
                        ImGui::TableSetColumnIndex(0);
                        ClippedTextWithTooltip(region.baseAddressString);
                        ImGui::TableSetColumnIndex(1);
                        TextWide(region.regionSizeString);
                        PopFontIfPushed(pushedAddressFont);

                        ImGui::TableSetColumnIndex(2);
                        TextWide(region.stateName);
                        ImGui::TableSetColumnIndex(3);
                        TextWide(region.typeName);
                        ImGui::TableSetColumnIndex(4);
                        const bool pushedProtectFont = PushFontIfAvailable(fonts_.monospace);
                        ClippedTextWithTooltip(region.protectName);
                        PopFontIfPushed(pushedProtectFont);

                        ImGui::TableSetColumnIndex(5);
                        ClippedTextWithTooltip(region.mappedFilePath.empty() ? L"(none)" : region.mappedFilePath);

                        ImGui::TableSetColumnIndex(6);
                        const std::wstring indicators = MemoryIndicatorText(region);
                        if (indicators.empty())
                        {
                            ImGui::TextDisabled("None");
                        }
                        else
                        {
                            ImGui::TextColored(
                                region.isSuspicious ? SeverityColor(Core::Severity::Medium) : SeverityColor(Core::Severity::Info),
                                "%s",
                                WideToUtf8(indicators).c_str());
                            if (ImGui::IsItemHovered())
                            {
                                RenderWrappedTooltip(indicators, 600.0f);
                            }
                        }
                        ImGui::PopID();
                    }
                }
                ImGui::EndTable();
            }
            EndInspectorCard();
        }
