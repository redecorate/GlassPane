// ImGuiApp inspector subview render implementations.
// This file is intentionally included inside the ImGuiApp class definition so
// inspector rendering can move out of ImGuiApp.cpp without moving state ownership.

        Core::SelectedProcessTriageAuthority SelectedTriageAuthorityForProcess(
            const Core::ProcessInfo& process) const
        {
            if (loadedSnapshotActive_)
            {
                Core::SelectedProcessTriageAuthority selected =
                    Core::SelectCapturedSelectedProcessTriageAuthority(
                    loadedSnapshotTriage_,
                    true,
                    process);
                if (loadedSnapshotMetadata_.schemaVersion >=
                        Export::GlassPaneSnapshotNativeEvidenceSchemaVersion &&
                    (selected.historicalFallbackCaptured || selected.notCaptured))
                {
                    selected.verdict = Core::TriageVerdict::Informational;
                    selected.analysisLevel =
                        Core::SelectedTriageAnalysisLevel::Unavailable;
                    selected.historicalFallbackCaptured = false;
                    selected.unavailable = true;
                    selected.notCaptured = false;
                    selected.availability.category =
                        Core::TriageAvailabilityCategory::ResultMissing;
                    selected.availability.disclosure =
                        Core::TriageAvailabilityDisclosure::TriageUnavailable;
                    selected.availabilityReason =
                        "The captured native TriageEngine result is unavailable for this process identity.";
                    selected.availability.diagnostic =
                        selected.availabilityReason;
                }
                return selected;
            }
            const Core::ObservationShadowState& authoritativeShadow =
                AuthoritativeSelectedObservationShadow();
            return Core::SelectNativeSelectedProcessTriageAuthority(
                authoritativeShadow,
                true,
                process,
                selectedEvidenceGeneration_,
                ObservationShadowEntityScope(process, loadedSnapshotActive_),
                processTriageCache_,
                CurrentProcessTriageCacheStamp());
        }

        const std::vector<Core::NativeSourceEvidenceRecord>&
        SelectedNativeSourceEvidenceForProcess(
            const Core::ProcessInfo& process) const
        {
            static const std::vector<Core::NativeSourceEvidenceRecord> empty;
            if (loadedSnapshotActive_)
            {
                if (loadedSnapshotMetadata_.schemaVersion <
                        Export::GlassPaneSnapshotNativeEvidenceSchemaVersion ||
                    !loadedSnapshotNativeSourceEvidence_.selectedRecord.has_value())
                {
                    return empty;
                }
                const Export::SavedNativeSourceEvidenceRecord& saved =
                    loadedSnapshotNativeSourceEvidence_.selectedRecord.value();
                return saved.identity == Core::MakeProcessIdentityKey(process)
                    ? saved.records
                    : empty;
            }

            const bool current =
                SelectedProcessEnrichedPublicationMatchesCurrent() &&
                Core::ObservationShadowMatches(
                    selectedObservationShadow_,
                    true,
                    process.pid,
                    ProcessCacheStamp(process),
                    selectedEvidenceGeneration_) &&
                selectedObservationShadow_.entityScope ==
                    ObservationShadowEntityScope(process, false);
            return current && selectedNativeSourceEvidence_.success
                ? selectedNativeSourceEvidence_.records
                : empty;
        }

        std::vector<Core::Finding> HistoricalSourceEvidenceForProcess(
            const Core::ProcessInfo& process) const
        {
            std::vector<Core::Finding> historical;
            if (!UsesHistoricalSourceEvidence())
            {
                return historical;
            }

            historical.reserve(
                process.indicators.size() + process.contextNotes.size());
            for (const std::wstring& indicator : process.indicators)
            {
                Core::Finding record;
                record.observationKind = Core::ExistingFindingKind::Unknown;
                // Historical process severity was not captured per source row.
                // Keep each projected row neutral rather than fabricating a
                // row-level legacy severity.
                record.severity = Core::FindingSeverity::Info;
                record.severityCaptured = false;
                record.title = indicator.empty()
                    ? L"Historical source record"
                    : indicator;
                record.category = L"Historical Source Evidence";
                record.description =
                    L"Imported legacy record retained as historical metadata. It is not current TriageEngine input.";
                historical.push_back(std::move(record));
            }
            for (const std::wstring& note : process.contextNotes)
            {
                Core::Finding record;
                record.observationKind = Core::ExistingFindingKind::Unknown;
                record.severity = Core::FindingSeverity::Info;
                record.severityCaptured = false;
                record.title = L"Historical collection/context note";
                record.category = L"Historical Source Evidence";
                record.description = note;
                historical.push_back(std::move(record));
            }
            return historical;
        }

        bool UsesHistoricalSourceEvidence() const
        {
            if (!loadedSnapshotActive_)
            {
                return false;
            }
            if (loadedSnapshotMetadata_.schemaVersion <
                Export::GlassPaneSnapshotNativeEvidenceSchemaVersion)
            {
                return true;
            }
            return std::any_of(
                snapshot_.processes.begin(),
                snapshot_.processes.end(),
                [](const Core::ProcessInfo& process) {
                    return process.historicalSeverityCaptured ||
                        process.historicalSuspiciousCaptured ||
                        !process.indicators.empty() ||
                        !process.contextNotes.empty();
                });
        }

        std::wstring InspectorTriageVerdictText(Core::TriageVerdict verdict)
        {
            const std::string text = Core::TriageVerdictDisplayText(verdict);
            return Utf8ToWide(text.c_str());
        }

        void RenderAuthoritativeRationaleSection(
            const Core::TriageResult& triage,
            Core::TriageRationaleSection section,
            const char* emptyText)
        {
            ImGui::TextDisabled(
                "%s",
                Core::TriageRationaleSectionDisplayText(section).c_str());

            bool rendered = false;
            for (const Core::TriageRationaleEntry& entry :
                 triage.previewRationaleEntries)
            {
                if (entry.section != section || entry.text.empty())
                {
                    continue;
                }
                ImGui::Bullet();
                ImGui::SameLine();
                WrappedTextColored(
                    ImGui::GetStyleColorVec4(ImGuiCol_Text),
                    entry.text);
                rendered = true;
            }

            if (!rendered)
            {
                WrappedTextDisabled(emptyText);
            }
        }

        void RenderAuthoritativeTriageRationale(
            const Core::SelectedProcessTriageAuthority& authority)
        {
            if (authority.persistedSummary != nullptr)
            {
                const auto renderPersisted = [this](
                    const char* heading,
                    const std::vector<std::string>& lines,
                    const char* emptyText)
                {
                    ImGui::TextDisabled("%s", heading);
                    if (lines.empty())
                    {
                        WrappedTextDisabled(emptyText);
                        return;
                    }
                    for (const std::string& line : lines)
                    {
                        ImGui::Bullet();
                        ImGui::SameLine();
                        WrappedTextColored(
                            ImGui::GetStyleColorVec4(ImGuiCol_Text),
                            line);
                    }
                };
                renderPersisted(
                    "Verdict basis",
                    authority.persistedSummary->verdictBasis,
                    "No review-relevant observation or completed correlation contributed.");
                renderPersisted(
                    "Completed correlations",
                    authority.persistedSummary->completedCorrelations,
                    "None observed.");
                renderPersisted(
                    "Supporting context",
                    authority.persistedSummary->supportingContext,
                    "None observed.");
                renderPersisted(
                    "Collection limitations",
                    authority.persistedSummary->collectionLimitations,
                    "None observed.");
                renderPersisted(
                    "Evidence-integrity context",
                    authority.persistedSummary->evidenceIntegrityContext,
                    "None observed.");
                renderPersisted(
                    "Unresolved correlations",
                    authority.persistedSummary->unresolvedCorrelations,
                    "None observed.");
                return;
            }

            if (authority.triageResult == nullptr ||
                !authority.triageResult->Succeeded())
            {
                return;
            }

            const Core::TriageResult& triage = *authority.triageResult;
            RenderAuthoritativeRationaleSection(
                triage,
                Core::TriageRationaleSection::VerdictBasis,
                "No review-relevant observation or completed correlation contributed.");
            RenderAuthoritativeRationaleSection(
                triage,
                Core::TriageRationaleSection::CompletedCorrelations,
                "None observed.");
            RenderAuthoritativeRationaleSection(
                triage,
                Core::TriageRationaleSection::SupportingContext,
                "None observed.");
            RenderAuthoritativeRationaleSection(
                triage,
                Core::TriageRationaleSection::CollectionLimitations,
                "None observed.");
            RenderAuthoritativeRationaleSection(
                triage,
                Core::TriageRationaleSection::EvidenceIntegrityContext,
                "None observed.");
            RenderAuthoritativeRationaleSection(
                triage,
                Core::TriageRationaleSection::UnresolvedCorrelations,
                "None observed.");
        }

        std::wstring FormatSelectedAuthorityForClipboard(
            const Core::ProcessInfo& process,
            const Core::SelectedProcessTriageAuthority& authority,
            std::size_t sourceEvidenceCount,
            bool historicalSourceEvidence)
        {
            std::wstringstream text;
            text << L"GlassPane Triage Summary\r\n\r\n";
            text << L"Verdict: ";
            if (authority.notCaptured)
            {
                text << L"Not captured\r\n";
            }
            else if (authority.unavailable)
            {
                text << L"Unavailable\r\n";
            }
            else
            {
                text << InspectorTriageVerdictText(authority.verdict) << L"\r\n";
            }
            text << L"Analysis level: " << Utf8ToWide(
                Core::SelectedTriageAnalysisLevelDisplayText(
                    authority.analysisLevel).c_str()) << L"\r\n";
            if (authority.UsesEnrichedTriage() && authority.baselineAvailable)
            {
                text << L"Baseline verdict: " <<
                    InspectorTriageVerdictText(authority.baselineVerdict) <<
                    L"\r\n";
            }
            text << L"Process: " <<
                (process.name.empty() ? L"(unknown)" : process.name) <<
                L" (PID " << process.pid << L")\r\n";

            if (authority.notCaptured)
            {
                text << L"\r\nAuthoritative TriageEngine results were not captured in this older snapshot.\r\n";
            }
            else if (authority.unavailable)
            {
                text << L"\r\nTriageEngine result unavailable for this entity. No authoritative attention level is available.\r\n";
            }
            else if (authority.analysisLevel ==
                Core::SelectedTriageAnalysisLevel::LegacyFallback)
            {
                text << L"\r\nThis schema-4 snapshot retained a captured historical legacy-fallback state. It was not recomputed.\r\n";
            }
            else if (authority.triageResult != nullptr &&
                authority.triageResult->Succeeded())
            {
                constexpr Core::TriageRationaleSection sections[] = {
                    Core::TriageRationaleSection::VerdictBasis,
                    Core::TriageRationaleSection::CompletedCorrelations,
                    Core::TriageRationaleSection::SupportingContext,
                    Core::TriageRationaleSection::CollectionLimitations,
                    Core::TriageRationaleSection::EvidenceIntegrityContext,
                    Core::TriageRationaleSection::UnresolvedCorrelations
                };
                for (Core::TriageRationaleSection section : sections)
                {
                    bool headingWritten = false;
                    for (const Core::TriageRationaleEntry& entry :
                        authority.triageResult->previewRationaleEntries)
                    {
                        if (entry.section != section || entry.text.empty())
                        {
                            continue;
                        }
                        if (!headingWritten)
                        {
                            text << L"\r\n" << Utf8ToWide(
                                Core::TriageRationaleSectionDisplayText(
                                    section).c_str()) << L":\r\n";
                            headingWritten = true;
                        }
                        text << L"- " << Utf8ToWide(entry.text.c_str()) <<
                            L"\r\n";
                    }
                    if (!headingWritten &&
                        section == Core::TriageRationaleSection::VerdictBasis)
                    {
                        text << L"\r\n" << Utf8ToWide(
                        Core::TriageRationaleSectionDisplayText(
                            section).c_str()) <<
                            L":\r\n- No review-relevant observation or completed correlation contributed.\r\n";
                    }
                }
            }
            else if (authority.persistedSummary != nullptr)
            {
                const auto appendLines = [&text](
                    const wchar_t* heading,
                    const std::vector<std::string>& lines)
                {
                    if (lines.empty())
                    {
                        return;
                    }
                    text << L"\r\n" << heading << L":\r\n";
                    for (const std::string& line : lines)
                    {
                        text << L"- " << Utf8ToWide(line.c_str()) << L"\r\n";
                    }
                };
                appendLines(L"Verdict basis", authority.persistedSummary->verdictBasis);
                appendLines(L"Completed correlations", authority.persistedSummary->completedCorrelations);
                appendLines(L"Supporting context", authority.persistedSummary->supportingContext);
                appendLines(L"Collection limitations", authority.persistedSummary->collectionLimitations);
                appendLines(L"Evidence-integrity context", authority.persistedSummary->evidenceIntegrityContext);
                appendLines(L"Unresolved correlations", authority.persistedSummary->unresolvedCorrelations);
            }

            text << L"\r\n" <<
                (historicalSourceEvidence
                    ? L"Historical source evidence"
                    : L"Native source evidence") << L":\r\n- " <<
                sourceEvidenceCount <<
                (sourceEvidenceCount == 1
                    ? L" record retained.\r\n"
                    : L" records retained.\r\n");
            return text.str();
        }

        std::wstring FormatNativeSourceEvidenceRecordForClipboard(
            const Core::NativeSourceEvidenceRecord& record)
        {
            std::wstringstream text;
            text << Utf8ToWide(record.title.c_str()) << L"\r\n";
            text << L"Domain: " << Utf8ToWide(
                Core::EvidenceDomainDisplayText(record.domain).c_str()) << L"\r\n";
            text << L"Disposition: " << Utf8ToWide(
                Core::ObservationDispositionDisplayText(
                    record.disposition).c_str()) << L"\r\n";
            text << L"Strength: " << Utf8ToWide(
                Core::ObservationStrengthDisplayText(
                    record.strength).c_str()) << L"\r\n";
            text << L"Confidence: " << Utf8ToWide(
                Core::ObservationConfidenceDisplayText(
                    record.confidence).c_str()) << L"\r\n";
            text << L"Role: " << (record.collectionLimitation
                ? L"Collection limitation"
                : (record.contributedToVerdict
                    ? L"Contributed to verdict"
                    : L"Supporting context")) << L"\r\n";
            if (!record.summary.empty())
            {
                text << Utf8ToWide(record.summary.c_str()) << L"\r\n";
            }
            for (const std::string& detail : record.details)
            {
                text << L"- " << Utf8ToWide(detail.c_str()) << L"\r\n";
            }
            for (const std::string& limitation : record.limitations)
            {
                text << L"- Limitation: " << Utf8ToWide(
                    limitation.c_str()) << L"\r\n";
            }
            if (!record.provenanceSummary.empty())
            {
                text << L"Provenance: " << Utf8ToWide(
                    record.provenanceSummary.c_str()) << L"\r\n";
            }
            return text.str();
        }

        std::wstring FormatSourceEvidenceForClipboard(
            const Core::ProcessInfo& process,
            const Core::SelectedProcessTriageAuthority& authority,
            const std::vector<Core::NativeSourceEvidenceRecord>& evidence)
        {
            std::wstringstream text;
            text << FormatSelectedAuthorityForClipboard(
                process,
                authority,
                evidence.size(),
                false);
            if (!evidence.empty())
            {
                text << L"\r\nNative Source Evidence\r\n";
                for (const Core::NativeSourceEvidenceRecord& record : evidence)
                {
                    text << L"\r\n" <<
                        FormatNativeSourceEvidenceRecordForClipboard(record);
                }
            }
            return text.str();
        }

        std::wstring FormatHistoricalSourceEvidenceForClipboard(
            const Core::ProcessInfo& process,
            const Core::SelectedProcessTriageAuthority& authority)
        {
            std::wstringstream text;
            text << FormatSelectedAuthorityForClipboard(
                process,
                authority,
                process.indicators.size() + process.contextNotes.size(),
                true);
            if (!process.indicators.empty() || !process.contextNotes.empty())
            {
                text << L"\r\nHistorical Source Evidence\r\n";
                text << L"Imported legacy records are retained as historical metadata and are not current TriageEngine input.\r\n";
                for (const std::wstring& indicator : process.indicators)
                {
                    text << L"- " << indicator <<
                        L" (historical source severity: Not captured)\r\n";
                }
                for (const std::wstring& note : process.contextNotes)
                {
                    text << L"- Collection/context note: " << note <<
                        L" (historical source severity: Not captured)\r\n";
                }
            }
            return text.str();
        }

        std::wstring InspectorProcessName(const Core::ProcessInfo& process)
        {
            return process.name.empty() ? L"(unknown process)" : process.name;
        }

        std::wstring InspectorEvidenceCountText(std::size_t recordCount)
        {
            return std::to_wstring(recordCount) +
                (recordCount == 1 ? L" record" : L" records");
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

#ifdef _DEBUG
        static constexpr std::size_t DebugObservationMaxVisibleCorrelations = 128;
        static constexpr std::size_t DebugObservationMaxVisibleGroups = 256;
        static constexpr std::size_t DebugObservationMaxVisibleRecords = 256;

        Core::Severity DebugObservationVerdictSeverity(Core::TriageVerdict verdict)
        {
            switch (verdict)
            {
            case Core::TriageVerdict::HighAttention:
                return Core::Severity::High;
            case Core::TriageVerdict::MediumAttention:
                return Core::Severity::Medium;
            case Core::TriageVerdict::LowAttention:
                return Core::Severity::Low;
            case Core::TriageVerdict::Informational:
            default:
                return Core::Severity::None;
            }
        }

        std::string DebugObservationDomainsText(const std::set<Core::EvidenceDomain>& domains)
        {
            std::string text;
            for (Core::EvidenceDomain domain : domains)
            {
                if (!text.empty())
                {
                    text += ", ";
                }
                text += Core::EvidenceDomainDisplayText(domain);
            }
            return text.empty() ? "None" : text;
        }

        std::string DebugObservationDomainsText(const std::vector<Core::EvidenceDomain>& domains)
        {
            std::string text;
            for (Core::EvidenceDomain domain : domains)
            {
                if (!text.empty())
                {
                    text += ", ";
                }
                text += Core::EvidenceDomainDisplayText(domain);
            }
            return text.empty() ? "None" : text;
        }

        std::string DebugObservationArtifactDomainCountsText(
            const std::vector<Core::ObservationDomainArtifactCount>& counts)
        {
            std::string text;
            for (const Core::ObservationDomainArtifactCount& count : counts)
            {
                if (!text.empty())
                {
                    text += ", ";
                }
                text += Core::EvidenceDomainDisplayText(count.domain) + ": " +
                    std::to_string(count.distinctArtifactCount);
            }
            return text.empty() ? "None" : text;
        }

        const char* DebugRefinedObservationRoleText(Core::RefinedObservationRole role)
        {
            switch (role)
            {
            case Core::RefinedObservationRole::Supporting:
                return "Supporting";
            case Core::RefinedObservationRole::ArtifactAttribute:
                return "Artifact attribute";
            case Core::RefinedObservationRole::Duplicate:
                return "Duplicate";
            case Core::RefinedObservationRole::Primary:
            default:
                return "Primary";
            }
        }

        void RenderDebugObservationField(const char* label, const std::string& value)
        {
            ImGui::TextDisabled("%s", label);
            if (value.empty())
            {
                WrappedTextDisabled("(not supplied)");
                return;
            }
            WrappedTextColored(ImGui::GetStyleColorVec4(ImGuiCol_Text), value);
        }

        void RenderDebugObservationStringList(
            const char* label,
            const std::vector<std::string>& values,
            const char* emptyText)
        {
            ImGui::TextDisabled("%s", label);
            if (values.empty())
            {
                WrappedTextDisabled(emptyText);
                return;
            }
            const std::size_t visibleCount = std::min(
                values.size(),
                DebugObservationMaxVisibleRecords);
            for (std::size_t index = 0; index < visibleCount; ++index)
            {
                ImGui::Bullet();
                ImGui::SameLine();
                WrappedTextColored(
                    ImGui::GetStyleColorVec4(ImGuiCol_Text),
                    values[index]);
            }
            if (values.size() > visibleCount)
            {
                WrappedTextDisabled(
                    std::to_string(values.size() - visibleCount) +
                    " additional bounded item(s) are retained in the pipeline state but omitted from this view.");
            }
        }

        void RenderDebugObservationArtifactAttributes(
            const std::vector<Core::ObservationArtifactAttribute>& attributes)
        {
            ImGui::TextDisabled("Artifact attributes");
            if (attributes.empty())
            {
                WrappedTextDisabled("No typed artifact attributes supplied.");
                return;
            }

            const std::size_t visibleCount = std::min(
                attributes.size(),
                DebugObservationMaxVisibleRecords);
            for (std::size_t index = 0; index < visibleCount; ++index)
            {
                const Core::ObservationArtifactAttribute& attribute =
                    attributes[index];
                std::string text = attribute.key.empty()
                    ? "Attribute"
                    : attribute.key;
                if (!attribute.value.empty())
                {
                    text += ": " + attribute.value;
                }
                ImGui::Bullet();
                ImGui::SameLine();
                WrappedTextColored(
                    ImGui::GetStyleColorVec4(ImGuiCol_Text),
                    text);
            }
            if (attributes.size() > visibleCount)
            {
                WrappedTextDisabled(
                    std::to_string(attributes.size() - visibleCount) +
                    " additional artifact attribute(s) are retained in the pipeline state but omitted from this view.");
            }
        }

        void RenderDebugObservationRecord(
            const Core::ObservationRecord& record,
            const Core::RefinedObservationMember* refinedMember)
        {
            const Core::Observation& sourceObservation = record.observation;
            const std::string label = sourceObservation.title.empty()
                ? (sourceObservation.id.empty()
                    ? "Untitled observation"
                    : sourceObservation.id)
                : sourceObservation.title;

            ImGui::PushID(static_cast<const void*>(&record));
            if (ImGui::TreeNodeEx(
                    "ObservationRecord",
                    ImGuiTreeNodeFlags_SpanAvailWidth,
                    "%s",
                    label.c_str()))
            {
                const Core::Observation effective = refinedMember != nullptr
                    ? Core::EffectiveObservation(*refinedMember)
                    : sourceObservation;
                RenderDebugObservationField("Observation ID", effective.id);
                RenderDebugObservationField("Rule ID", effective.ruleId);
                RenderDebugObservationField("Summary", effective.summary);
                RenderDebugObservationField(
                    "Domain",
                    Core::EvidenceDomainDisplayText(effective.domain));
                RenderDebugObservationField(
                    "Disposition",
                    Core::ObservationDispositionDisplayText(effective.disposition));
                RenderDebugObservationField(
                    "Strength (evidence significance)",
                    Core::ObservationStrengthDisplayText(effective.strength));
                RenderDebugObservationField(
                    "Confidence (support for the fact)",
                    Core::ObservationConfidenceDisplayText(effective.confidence));
                RenderDebugObservationField(
                    "Verdict contribution",
                    effective.contributesToVerdict ? "Contributing" : "Not contributing");
                RenderDebugObservationField("Entity scope", effective.entityScope);
                RenderDebugObservationField("Grouping key", effective.groupingKey);
                RenderDebugObservationField("Correlation key", effective.correlationKey);
                RenderDebugObservationField(
                    "Artifact kind",
                    Core::ObservationArtifactKindDisplayText(
                        effective.artifactIdentity.kind));
                RenderDebugObservationField(
                    "Artifact entity scope",
                    effective.artifactIdentity.entityScope);
                RenderDebugObservationField(
                    "Artifact key",
                    effective.artifactIdentity.artifactKey);
                RenderDebugObservationArtifactAttributes(
                    effective.artifactAttributes);

                if (refinedMember != nullptr)
                {
                    RenderDebugObservationField(
                        "Refined role",
                        DebugRefinedObservationRoleText(refinedMember->role));
                    RenderDebugObservationField(
                        "Semantic fingerprint",
                        refinedMember->semanticFingerprint);
                    if (!refinedMember->primaryObservationId.empty())
                    {
                        RenderDebugObservationField(
                            "Primary observation",
                            refinedMember->primaryObservationId);
                    }
                    if (refinedMember->suppressed)
                    {
                        RenderDebugObservationField(
                            "Original disposition",
                            Core::ObservationDispositionDisplayText(
                                record.observation.disposition));
                        RenderDebugObservationField(
                            "Original verdict contribution",
                            record.observation.contributesToVerdict
                                ? "Eligible"
                                : "Not contributing");
                        RenderDebugObservationField(
                            "Structural suppressor",
                            refinedMember->suppression.suppressorId);
                        RenderDebugObservationField(
                            "Suppression reason",
                            refinedMember->suppression.reason);
                    }
                }

                ImGui::Separator();
                ImGui::TextDisabled("Native typed source");
                RenderDebugObservationField("Source rule ID", record.source.sourceRuleId);
                RenderDebugObservationField("Source title", record.source.sourceTitle);
                RenderDebugObservationField("Source message", record.source.sourceMessage);
                RenderDebugObservationField("Source category", record.source.sourceCategory);

                ImGui::Separator();
                ImGui::TextDisabled("Provenance");
                RenderDebugObservationField(
                    "Source kind",
                    Core::ObservationSourceKindDisplayText(effective.provenance.sourceKind));
                RenderDebugObservationField(
                    "Source identifier",
                    effective.provenance.sourceIdentifier);
                RenderDebugObservationField(
                    "Collection method",
                    effective.provenance.collectionMethod);
                RenderDebugObservationField(
                    "Collection timestamp",
                    effective.provenance.collectionTimestamp);
                RenderDebugObservationField(
                    "Required privilege",
                    effective.provenance.requiredPrivilege);
                RenderDebugObservationField(
                    "Source availability",
                    effective.provenance.sourceAvailable ? "Available" : "Unavailable");
                RenderDebugObservationStringList(
                    "Provenance limitations",
                    effective.provenance.limitations,
                    "No provenance limitations supplied.");

                RenderDebugObservationStringList(
                    "Evidence",
                    effective.evidence,
                    "No source evidence strings supplied.");
                RenderDebugObservationStringList(
                    "Observation limitations",
                    effective.limitations,
                    "No observation limitations supplied.");

                if (ImGui::TreeNodeEx(
                        "EvidenceValues",
                        ImGuiTreeNodeFlags_SpanAvailWidth,
                        "Evidence values (expand to inspect)"))
                {
                    RenderDebugObservationField("Raw value", effective.rawValue);
                    RenderDebugObservationField("Normalized value", effective.normalizedValue);
                    RenderDebugObservationField(
                        "Raw source reference",
                        effective.provenance.rawSourceReference);
                    ImGui::TreePop();
                }
                ImGui::TreePop();
            }
            ImGui::PopID();
        }

        struct DebugObservationLookup
        {
            std::unordered_map<std::string, const Core::ObservationRecord*> records;
        };

        DebugObservationLookup BuildDebugObservationLookup(
            const Core::ObservationRefinementResult& refinement)
        {
            DebugObservationLookup lookup;
            lookup.records.reserve(refinement.summary.rawObservationCount);
            for (const Core::RefinedObservationGroup& group : refinement.groups)
            {
                for (const Core::RefinedObservationMember& member : group.members)
                {
                    lookup.records.emplace(
                        member.sourceRecord.observation.id,
                        &member.sourceRecord);
                }
            }
            for (const Core::ObservationRecord& note : refinement.collectionNotes)
            {
                lookup.records.emplace(note.observation.id, &note);
            }
            for (const Core::ObservationRecord& note : refinement.evidenceIntegrityNotes)
            {
                lookup.records.emplace(note.observation.id, &note);
            }
            return lookup;
        }

        void RenderDebugObservationReference(
            const std::string& observationId,
            const DebugObservationLookup& lookup)
        {
            const auto recordIterator = lookup.records.find(observationId);
            if (recordIterator == lookup.records.end() || recordIterator->second == nullptr)
            {
                ImGui::Bullet();
                ImGui::SameLine();
                WrappedTextDisabled(observationId + " (source observation unavailable)");
                return;
            }

            const Core::ObservationRecord& record = *recordIterator->second;
            const Core::Observation& observation = record.observation;

            std::string heading = observationId;
            if (!observation.title.empty())
            {
                heading += " — " + observation.title;
            }
            ImGui::Bullet();
            ImGui::SameLine();
            WrappedTextColored(ImGui::GetStyleColorVec4(ImGuiCol_Text), heading);
            if (!observation.summary.empty())
            {
                ImGui::Indent();
                WrappedTextDisabled(observation.summary);
                ImGui::Unindent();
            }
        }

        void RenderDebugObservationReferences(
            const char* emptyText,
            const std::vector<std::string>& observationIds,
            const DebugObservationLookup& lookup)
        {
            if (observationIds.empty())
            {
                WrappedTextDisabled(emptyText);
                return;
            }
            const std::size_t visibleCount = std::min(
                observationIds.size(),
                DebugObservationMaxVisibleRecords);
            for (std::size_t index = 0; index < visibleCount; ++index)
            {
                RenderDebugObservationReference(observationIds[index], lookup);
            }
            if (observationIds.size() > visibleCount)
            {
                WrappedTextDisabled(
                    std::to_string(observationIds.size() - visibleCount) +
                    " additional observation reference(s) are retained in the pipeline state but omitted from this view.");
            }
        }

        void RenderDebugRationaleEntries(
            const std::vector<Core::TriageRationaleEntry>& entries,
            Core::TriageRationaleSection section,
            std::size_t maximumItems,
            const char* emptyText,
            const char* omittedText)
        {
            std::size_t rendered = 0;
            for (const Core::TriageRationaleEntry& entry : entries)
            {
                if (entry.section != section)
                {
                    continue;
                }
                if (rendered >= maximumItems)
                {
                    break;
                }
                ImGui::Bullet();
                ImGui::SameLine();
                WrappedTextColored(ImGui::GetStyleColorVec4(ImGuiCol_Text), entry.text);
                ++rendered;
            }

            if (rendered == 0)
            {
                WrappedTextDisabled(emptyText);
                return;
            }

            std::size_t total = 0;
            for (const Core::TriageRationaleEntry& entry : entries)
            {
                if (entry.section == section)
                {
                    ++total;
                }
            }
            if (total > rendered)
            {
                WrappedTextDisabled(
                    std::to_string(total - rendered) +
                    omittedText);
            }
        }

        void RenderDebugRationaleSection(
            const Core::TriageResult& triage,
            Core::TriageRationaleSection section,
            std::size_t maximumItems)
        {
            RenderDebugRationaleEntries(
                triage.rationaleEntries,
                section,
                maximumItems,
                "No Core rationale entries in this section.",
                " additional Core rationale line(s) are available in details.");
        }

        void RenderDebugPreviewRationaleSection(
            const Core::TriageResult& triage,
            Core::TriageRationaleSection section,
            std::size_t maximumItems)
        {
            // Compact preview text is generated by Core specifically for the
            // summary surface. Never fall back to the detailed rationale here:
            // detailed entries intentionally retain internal audit identities.
            RenderDebugRationaleEntries(
                triage.previewRationaleEntries,
                section,
                maximumItems,
                "No compact Core rationale entries in this section.",
                " additional compact rationale line(s) are available in details.");
        }

        void RenderDebugCorrelationCard(
            const Core::ObservationCorrelation& correlation,
            const DebugObservationLookup& lookup)
        {
            ImGui::PushID(correlation.id.c_str());
            const std::string title = correlation.title.empty()
                ? "Completed typed correlation"
                : correlation.title;
            if (ImGui::TreeNodeEx(
                    "CorrelationCard",
                    ImGuiTreeNodeFlags_Framed | ImGuiTreeNodeFlags_SpanAvailWidth,
                    "%s",
                    title.c_str()))
            {
                RenderDebugObservationField("Correlation ID", correlation.id);
                RenderDebugObservationField("Rule ID", correlation.ruleId);
                RenderDebugObservationField(
                    "Significance",
                    Core::CorrelationSignificanceDisplayText(correlation.significance));
                RenderDebugObservationField(
                    "Confidence",
                    Core::ObservationConfidenceDisplayText(correlation.confidence));
                RenderDebugObservationField(
                    "Participating domains",
                    DebugObservationDomainsText(correlation.participatingDomains));
                RenderDebugObservationField(
                    "Participating domain count",
                    std::to_string(correlation.participatingDomains.size()));
                RenderDebugObservationField("Rationale", correlation.rationale);
                RenderDebugObservationField(
                    "Verdict contribution",
                    correlation.contributesToVerdict ? "Contributing" : "Not contributing");

                ImGui::TextDisabled("Participating observations");
                RenderDebugObservationReferences(
                    "No participating observation references supplied.",
                    correlation.participatingObservationIds,
                    lookup);

                ImGui::TextDisabled("Supporting observations");
                RenderDebugObservationReferences(
                    "No supporting observation references supplied.",
                    correlation.supportingObservationIds,
                    lookup);
                RenderDebugObservationStringList(
                    "Limitations",
                    correlation.limitations,
                    "No correlation limitations supplied.");
                ImGui::TreePop();
            }
            ImGui::PopID();
        }

        void RenderDebugObservationDetails(const Core::ObservationShadowState& shadow)
        {
            const Core::TriageResult& triage = shadow.triage;
            std::optional<DebugObservationLookup> lookup;
            const auto observationLookup = [&]() -> const DebugObservationLookup&
            {
                if (!lookup.has_value())
                {
                    lookup.emplace(BuildDebugObservationLookup(shadow.refinement));
                }
                return lookup.value();
            };

            if (ImGui::CollapsingHeader(
                    "Native pipeline diagnostics##ObservationDebugDiagnostics"))
            {
                const Core::ObservationShadowDecisionSummary& decision =
                    shadow.decisionSummary;
                RenderDebugObservationField(
                    "Raw observations",
                    std::to_string(decision.rawObservationCount));
                RenderDebugObservationField(
                    "Refined groups",
                    std::to_string(decision.refinedGroupCount));
                RenderDebugObservationField(
                    "Artifact groups",
                    std::to_string(decision.artifactGroupCount));
                RenderDebugObservationField(
                    "Distinct artifacts",
                    std::to_string(decision.distinctArtifactCount));
                RenderDebugObservationField(
                    "Artifact attributes",
                    std::to_string(decision.artifactAttributeCount));
                RenderDebugObservationField(
                    "Distinct artifacts by domain",
                    DebugObservationArtifactDomainCountsText(
                        shadow.refinement.summary.distinctArtifactCountsByDomain));
                RenderDebugObservationField(
                    "Activated correlations",
                    std::to_string(decision.activatedCorrelationCount));
                RenderDebugObservationField(
                    "Contributing observations",
                    std::to_string(decision.contributingObservationCount));
                RenderDebugObservationField(
                    "Contributing correlations",
                    std::to_string(decision.contributingCorrelationCount));
                RenderDebugObservationField(
                    "Contributing domains",
                    std::to_string(decision.contributingDomainCount));
                RenderDebugObservationField(
                    "Maximum correlation domains",
                    std::to_string(
                        decision.maximumContributingCorrelationDomainCount));
                RenderDebugObservationField(
                    "Same-domain correlations",
                    std::to_string(
                        decision.sameDomainContributingCorrelationCount));
                RenderDebugObservationField(
                    "Same-domain correlation Medium ceiling",
                    decision.sameDomainVerdictCeilingApplied
                        ? "Applied"
                        : "Not applied");
                RenderDebugObservationField(
                    "Standalone Strong High gate",
                    decision.qualifiedStandaloneStrongHighGateSatisfied
                        ? "Satisfied"
                        : "Not satisfied");
                RenderDebugObservationField(
                    "Coherent multi-domain High gate",
                    decision.coherentMultiDomainHighGateSatisfied
                        ? "Satisfied"
                        : "Not satisfied");
                RenderDebugObservationField(
                    "Context observations",
                    std::to_string(decision.contextCount));
                RenderDebugObservationField(
                    "Collection notes",
                    std::to_string(decision.collectionNoteCount));
                RenderDebugObservationField(
                    "Unresolved correlations",
                    std::to_string(decision.unresolvedCorrelationCount));
                RenderDebugObservationField(
                    "Typed source facts represented",
                    std::to_string(decision.typedSourceFactCount));
                RenderDebugObservationField(
                    "Source facts declared",
                    std::to_string(decision.declaredSourceFactCount));
                RenderDebugObservationField(
                    "Duplicate typed facts excluded",
                    std::to_string(decision.typedSourceFactDuplicateCount));
                RenderDebugObservationField(
                    "Native build duration",
                    std::to_string(decision.nativeBuildDurationMicroseconds) + " us");
                RenderDebugObservationField(
                    "Refinement duration",
                    std::to_string(decision.refinementDurationMicroseconds) + " us");
                RenderDebugObservationField(
                    "Correlation duration",
                    std::to_string(decision.correlationDurationMicroseconds) + " us");
                RenderDebugObservationField(
                    "Triage duration",
                    std::to_string(decision.triageDurationMicroseconds) + " us");
                RenderDebugObservationField(
                    "Rationale aggregation",
                    std::to_string(
                        decision.rationaleAggregationDurationMicroseconds) +
                        " us");
                RenderDebugObservationField(
                    "Total enriched pipeline duration",
                    std::to_string(decision.totalPipelineDurationMicroseconds) +
                        " us");
                WrappedTextDisabled(
                    "These counters are bounded in-memory diagnostics. They are not uploaded or persisted by this view.");
                RenderDebugObservationStringList(
                    "Refinement warnings",
                    shadow.refinement.warnings,
                    "No refinement warnings were retained.");
                RenderDebugObservationStringList(
                    "Correlation warnings",
                    shadow.correlation.warnings,
                    "No correlation warnings were retained.");
            }

            if (ImGui::CollapsingHeader(
                    "Triage rationale##ObservationDebugRationale",
                    ImGuiTreeNodeFlags_DefaultOpen))
            {
                constexpr Core::TriageRationaleSection Sections[] = {
                    Core::TriageRationaleSection::VerdictBasis,
                    Core::TriageRationaleSection::CompletedCorrelations,
                    Core::TriageRationaleSection::SupportingContext,
                    Core::TriageRationaleSection::CollectionLimitations,
                    Core::TriageRationaleSection::EvidenceIntegrityContext,
                    Core::TriageRationaleSection::UnresolvedCorrelations,
                    Core::TriageRationaleSection::PresentationNotes
                };
                for (Core::TriageRationaleSection section : Sections)
                {
                    ImGui::TextDisabled(
                        "%s",
                        Core::TriageRationaleSectionDisplayText(section).c_str());
                    RenderDebugRationaleSection(
                        triage,
                        section,
                        Core::TriageMaxRationaleEntries);
                }
                RenderDebugObservationStringList(
                    "Triage limitations",
                    triage.limitations,
                    "No triage-result limitations supplied.");
            }

            if (ImGui::CollapsingHeader(
                    "Completed correlations##ObservationDebugCorrelations"))
            {
                if (shadow.correlation.correlations.empty())
                {
                    WrappedTextDisabled("No typed correlations were completed.");
                }
                const std::size_t visibleCount = std::min(
                    shadow.correlation.correlations.size(),
                    DebugObservationMaxVisibleCorrelations);
                if (visibleCount > 0)
                {
                    const DebugObservationLookup& references = observationLookup();
                    for (std::size_t index = 0; index < visibleCount; ++index)
                    {
                        RenderDebugCorrelationCard(
                            shadow.correlation.correlations[index],
                            references);
                    }
                }
                if (shadow.correlation.correlations.size() > visibleCount)
                {
                    WrappedTextDisabled(
                        std::to_string(
                            shadow.correlation.correlations.size() - visibleCount) +
                        " additional completed correlation(s) are retained in the pipeline state but omitted from this view.");
                }
            }

            if (ImGui::CollapsingHeader(
                    "Contributing observations##ObservationDebugContributors"))
            {
                if (triage.contributingObservationIds.empty())
                {
                    WrappedTextDisabled(
                        "No observations contribute directly to the triage verdict.");
                }
                else
                {
                    RenderDebugObservationReferences(
                        "No observations contribute directly to the triage verdict.",
                        triage.contributingObservationIds,
                        observationLookup());
                }
            }

            if (ImGui::CollapsingHeader(
                    "Supporting context##ObservationDebugContext"))
            {
                if (triage.contextObservationIds.empty())
                {
                    WrappedTextDisabled(
                        "No supporting context observations were retained.");
                }
                else
                {
                    RenderDebugObservationReferences(
                        "No supporting context observations were retained.",
                        triage.contextObservationIds,
                        observationLookup());
                }
            }

            if (ImGui::CollapsingHeader(
                    "Collection limitations##ObservationDebugCollectionNotes"))
            {
                if (shadow.refinement.collectionNotes.empty())
                {
                    WrappedTextDisabled("No collection notes were retained.");
                }
                const std::size_t visibleCount = std::min(
                    shadow.refinement.collectionNotes.size(),
                    DebugObservationMaxVisibleRecords);
                for (std::size_t index = 0; index < visibleCount; ++index)
                {
                    RenderDebugObservationRecord(
                        shadow.refinement.collectionNotes[index],
                        nullptr);
                }
                if (shadow.refinement.collectionNotes.size() > visibleCount)
                {
                    WrappedTextDisabled(
                        std::to_string(
                            shadow.refinement.collectionNotes.size() - visibleCount) +
                        " additional collection note(s) are retained in the pipeline state but omitted from this view.");
                }
            }

            if (ImGui::CollapsingHeader(
                    "Evidence-integrity context##ObservationDebugIntegrityNotes"))
            {
                if (shadow.refinement.evidenceIntegrityNotes.empty())
                {
                    WrappedTextDisabled("No evidence-integrity notes were retained.");
                }
                const std::size_t visibleCount = std::min(
                    shadow.refinement.evidenceIntegrityNotes.size(),
                    DebugObservationMaxVisibleRecords);
                for (std::size_t index = 0; index < visibleCount; ++index)
                {
                    RenderDebugObservationRecord(
                        shadow.refinement.evidenceIntegrityNotes[index],
                        nullptr);
                }
                if (shadow.refinement.evidenceIntegrityNotes.size() > visibleCount)
                {
                    WrappedTextDisabled(
                        std::to_string(
                            shadow.refinement.evidenceIntegrityNotes.size() - visibleCount) +
                        " additional evidence-integrity note(s) are retained in the pipeline state but omitted from this view.");
                }
            }

            if (ImGui::CollapsingHeader(
                    "Unresolved correlations##ObservationDebugUnresolved"))
            {
                if (shadow.correlation.unresolvedPreparations.empty())
                {
                    WrappedTextDisabled("No unresolved typed correlation preparations remain.");
                }
                const std::size_t visibleCount = std::min(
                    shadow.correlation.unresolvedPreparations.size(),
                    DebugObservationMaxVisibleCorrelations);
                for (std::size_t index = 0; index < visibleCount; ++index)
                {
                    const Core::ObservationCorrelationPreparation& preparation =
                        shadow.correlation.unresolvedPreparations[index];
                    ImGui::PushID(static_cast<const void*>(&preparation));
                    const std::string heading = preparation.correlationKey.empty()
                        ? "Unresolved typed correlation"
                        : preparation.correlationKey;
                    if (ImGui::TreeNodeEx(
                            "UnresolvedCorrelation",
                            ImGuiTreeNodeFlags_SpanAvailWidth,
                            "%s",
                            heading.c_str()))
                    {
                        RenderDebugObservationField("Entity scope", preparation.entityScope);
                        RenderDebugObservationField(
                            "Available supporting domains",
                            DebugObservationDomainsText(
                                preparation.availableSupportingDomains));
                        RenderDebugObservationField(
                            "Contains CorrelatedOnly evidence",
                            preparation.containsCorrelatedOnly ? "Yes" : "No");
                        ImGui::TextDisabled("Participating source observations");
                        RenderDebugObservationReferences(
                            "No source observation references supplied.",
                            preparation.sourceObservationIds,
                            observationLookup());
                        ImGui::TreePop();
                    }
                    ImGui::PopID();
                }
                if (shadow.correlation.unresolvedPreparations.size() > visibleCount)
                {
                    WrappedTextDisabled(
                        std::to_string(
                            shadow.correlation.unresolvedPreparations.size() - visibleCount) +
                        " additional unresolved correlation preparation(s) are retained in the pipeline state but omitted from this view.");
                }
            }

            if (ImGui::CollapsingHeader(
                    "Suppressed observations##ObservationDebugSuppressions"))
            {
                std::size_t suppressedCount = 0;
                std::size_t renderedCount = 0;
                for (const Core::RefinedObservationGroup& group : shadow.refinement.groups)
                {
                    for (const Core::RefinedObservationMember& member : group.members)
                    {
                        if (!member.suppressed)
                        {
                            continue;
                        }
                        ++suppressedCount;
                        if (renderedCount < DebugObservationMaxVisibleRecords)
                        {
                            RenderDebugObservationRecord(member.sourceRecord, &member);
                            ++renderedCount;
                        }
                    }
                }
                if (suppressedCount == 0)
                {
                    WrappedTextDisabled("No structural suppressions were applied.");
                }
                else if (suppressedCount > renderedCount)
                {
                    WrappedTextDisabled(
                        std::to_string(suppressedCount - renderedCount) +
                        " additional suppressed observation(s) are retained in the pipeline state but omitted from this view.");
                }
            }

            if (ImGui::CollapsingHeader(
                    "All refined groups and source observations##ObservationDebugAllGroups"))
            {
                if (shadow.refinement.groups.empty())
                {
                    WrappedTextDisabled("No behavioral or context groups were retained.");
                }
                const std::size_t visibleGroupCount = std::min(
                    shadow.refinement.groups.size(),
                    DebugObservationMaxVisibleGroups);
                for (std::size_t groupIndex = 0;
                     groupIndex < visibleGroupCount;
                     ++groupIndex)
                {
                    const Core::RefinedObservationGroup& group =
                        shadow.refinement.groups[groupIndex];
                    ImGui::PushID(static_cast<const void*>(&group));
                    std::string heading = group.semanticFamily.empty()
                        ? (group.groupingKey.empty() ? "Singleton observation group" : group.groupingKey)
                        : group.semanticFamily;
                    heading += " — " + Core::EvidenceDomainDisplayText(group.domain);
                    heading += " — " + std::to_string(group.members.size()) + " source observation(s)";
                    if (ImGui::TreeNodeEx(
                            "RefinedObservationGroup",
                            ImGuiTreeNodeFlags_Framed | ImGuiTreeNodeFlags_SpanAvailWidth,
                            "%s",
                            heading.c_str()))
                    {
                        RenderDebugObservationField("Entity scope", group.entityScope);
                        RenderDebugObservationField("Grouping key", group.groupingKey);
                        RenderDebugObservationField("Semantic family", group.semanticFamily);
                        RenderDebugObservationField(
                            "Artifact kind",
                            Core::ObservationArtifactKindDisplayText(
                                group.artifactIdentity.kind));
                        RenderDebugObservationField(
                            "Artifact entity scope",
                            group.artifactIdentity.entityScope);
                        RenderDebugObservationField(
                            "Artifact key",
                            group.artifactIdentity.artifactKey);
                        RenderDebugObservationField(
                            "Artifact attributes",
                            std::to_string(group.artifactAttributeCount));
                        const std::size_t visibleMemberCount = std::min(
                            group.members.size(),
                            DebugObservationMaxVisibleRecords);
                        for (std::size_t memberIndex = 0;
                             memberIndex < visibleMemberCount;
                             ++memberIndex)
                        {
                            const Core::RefinedObservationMember& member =
                                group.members[memberIndex];
                            RenderDebugObservationRecord(member.sourceRecord, &member);
                        }
                        if (group.members.size() > visibleMemberCount)
                        {
                            WrappedTextDisabled(
                                std::to_string(
                                    group.members.size() - visibleMemberCount) +
                        " additional source observation(s) in this group are retained in the pipeline state but omitted from this view.");
                        }
                        ImGui::TreePop();
                    }
                    ImGui::PopID();
                }
                if (shadow.refinement.groups.size() > visibleGroupCount)
                {
                    WrappedTextDisabled(
                        std::to_string(
                            shadow.refinement.groups.size() - visibleGroupCount) +
                        " additional refined group(s) are retained in the pipeline state but omitted from this view.");
                }
            }
        }

        void RenderProcessTriageCacheDebugSummary(
            const Core::ProcessTriageCache& cache,
            bool hasCurrentSourceStamp)
        {
            if (!ImGui::CollapsingHeader(
                    "Process-wide baseline cache (Debug)##BaselineCacheDiagnostics"))
            {
                return;
            }

            const Core::ProcessTriageCacheSummary& summary = cache.summary;
            RenderDebugObservationField(
                "Cache source",
                cache.sourceStamp.loadedSnapshot
                    ? "Loaded snapshot evidence only"
                    : "Live process-wide evidence only");
            RenderDebugObservationField(
                "Current source stamp",
                hasCurrentSourceStamp ? "Yes" : "No");
            RenderDebugObservationField(
                "Status",
                Core::ProcessTriageCacheStatusDisplayText(cache.status));
            RenderDebugObservationField(
                "Process generation",
                std::to_string(cache.sourceStamp.processGeneration));
            RenderDebugObservationField(
                "Evidence generation",
                std::to_string(cache.sourceStamp.evidenceGeneration));
            RenderDebugObservationField(
                "Scope generation",
                std::to_string(cache.sourceStamp.scopeGeneration));
            RenderDebugObservationField(
                "Build invocations",
                std::to_string(baselineCacheBuildInvocationCount_));
            RenderDebugObservationField(
                "Source processes",
                std::to_string(summary.sourceProcessCount));
            RenderDebugObservationField(
                "Retained entries",
                std::to_string(summary.retainedProcessCount));
            RenderDebugObservationField(
                "Successful entries",
                std::to_string(summary.successfulEntryCount));
            RenderDebugObservationField(
                "Failed entries",
                std::to_string(summary.failedEntryCount));
            RenderDebugObservationField(
                "Omitted entries",
                std::to_string(summary.omittedProcessCount));
            RenderDebugObservationField(
                "Authority lookups",
                std::to_string(processAuthorityUnavailableKinds_.size()));
            RenderDebugObservationField(
                "Baseline authority successes",
                std::to_string(
                    processAuthorityUnavailableKinds_.size() >=
                            processAuthorityUnavailableCount_
                        ? processAuthorityUnavailableKinds_.size() -
                            processAuthorityUnavailableCount_
                        : 0));
            RenderDebugObservationField(
                "Per-entity unavailable",
                std::to_string(processAuthorityUnavailableCount_));
            for (std::size_t index = 1;
                index < processAuthorityUnavailableCountsByKind_.size();
                ++index)
            {
                if (processAuthorityUnavailableCountsByKind_[index] == 0)
                {
                    continue;
                }
                const auto kind =
                    static_cast<Core::ProcessTriageUnavailableKind>(index);
                std::string value = std::to_string(
                    processAuthorityUnavailableCountsByKind_[index]);
                const Core::TriageAvailabilityDisposition disposition =
                    loadedSnapshotActive_ &&
                        loadedSnapshotMetadata_.schemaVersion <
                            Export::GlassPaneSnapshotSchemaVersion
                        ? Core::TriageAvailabilityDisposition::HistoricalCompatibilityOnly
                        : Core::ClassifyTriageAvailability(
                            Core::CanonicalTriageUnavailableCategory(kind));
                value += "; " +
                    Core::TriageAvailabilityDispositionDisplayText(disposition);
                if (!processAuthorityUnavailableFirstIdentityByKind_[index].empty())
                {
                    value += "; first " +
                        processAuthorityUnavailableFirstIdentityByKind_[index];
                }
                if (!processAuthorityUnavailableFirstDiagnosticByKind_[index].empty())
                {
                    value += "; " +
                        processAuthorityUnavailableFirstDiagnosticByKind_[index];
                }
                RenderDebugObservationField(
                    Core::ProcessTriageUnavailableKindDisplayText(kind).c_str(),
                    value);
            }
            RenderDebugObservationField(
                "Duplicate identities",
                std::to_string(summary.duplicateIdentityCount));
            RenderDebugObservationField(
                "Ambiguous PID entries",
                std::to_string(summary.ambiguousPidEntryCount));
            RenderDebugObservationField(
                "Truncated entries",
                std::to_string(summary.truncatedEntryCount));
            RenderDebugObservationField(
                "Omitted source facts",
                std::to_string(summary.omittedFactCount));
            RenderDebugObservationField(
                "Verdicts",
                "Informational " + std::to_string(summary.informationalCount) +
                    ", Low " + std::to_string(summary.lowAttentionCount) +
                    ", Medium " + std::to_string(summary.mediumAttentionCount) +
                    ", High " + std::to_string(summary.highAttentionCount));
            RenderDebugObservationField(
                "Raw observations",
                std::to_string(summary.observationCount));
            RenderDebugObservationField(
                "Native typed facts",
                std::to_string(summary.nativeFactCount));
            RenderDebugObservationField(
                "Duplicate typed facts excluded",
                std::to_string(summary.duplicateExcludedCount));
            RenderDebugObservationField(
                "Contributing domains (sum across entries)",
                std::to_string(summary.contributingDomainCount));
            RenderDebugObservationField(
                "Activated correlations (sum across entries)",
                std::to_string(summary.activatedCorrelationCount));
            RenderDebugObservationField(
                "Total build duration",
                std::to_string(summary.totalBuildDurationMicroseconds) + " us");
            RenderDebugObservationField(
                "Maximum per-process duration",
                std::to_string(summary.maximumEntryBuildDurationMicroseconds) + " us");
            RenderDebugObservationField(
                "Average per-process duration",
                std::to_string(summary.averageEntryBuildDurationMicroseconds) + " us");
            if (!cache.statusMessage.empty())
            {
                RenderDebugObservationField("Cache diagnostic", cache.statusMessage);
            }
            RenderDebugObservationStringList(
                "Cache warnings",
                cache.warnings,
                "No process-wide cache warnings were retained.");
            WrappedTextDisabled(
                "These aggregate counters are bounded, local Debug diagnostics. Rendering this section does not rebuild the cache or collect evidence.");
        }

        void RenderSelectedBaselineDebugDetails(
            const Core::CachedBaselineTriage& entry)
        {
            if (!ImGui::CollapsingHeader(
                    "Selected baseline details (Debug)##SelectedBaselineDetails"))
            {
                return;
            }

            RenderDebugObservationField(
                "Entity PID",
                std::to_string(entry.identity.pid));
            RenderDebugObservationField(
                "Creation time identity",
                entry.identity.hasCreationTime
                    ? std::to_string(entry.identity.creationTimeFileTime)
                    : "Unavailable");
            RenderDebugObservationField(
                "Build status",
                entry.success ? "Success" : "Failed");
            RenderDebugObservationField(
                "Build duration",
                std::to_string(entry.buildDurationMicroseconds) + " us");
            if (!entry.diagnostic.empty())
            {
                RenderDebugObservationField("Diagnostic", entry.diagnostic);
            }
            RenderDebugObservationStringList(
                "Baseline evidence limitations",
                entry.baseline.limitations,
                "No baseline-evidence limitations were retained.");
            RenderDebugObservationStringList(
                "Triage limitations",
                entry.triage.limitations,
                "No baseline triage limitations were retained.");

            ImGui::TextDisabled("Core-generated baseline rationale");
            RenderDebugRationaleSection(
                entry.triage,
                Core::TriageRationaleSection::VerdictBasis,
                Core::TriageMaxRationaleEntries);
            RenderDebugRationaleSection(
                entry.triage,
                Core::TriageRationaleSection::CompletedCorrelations,
                Core::TriageMaxRationaleEntries);
            RenderDebugRationaleSection(
                entry.triage,
                Core::TriageRationaleSection::SupportingContext,
                Core::TriageMaxRationaleEntries);
            RenderDebugRationaleSection(
                entry.triage,
                Core::TriageRationaleSection::CollectionLimitations,
                Core::TriageMaxRationaleEntries);

            if (ImGui::TreeNodeEx(
                    "BaselineRawObservations",
                    ImGuiTreeNodeFlags_SpanAvailWidth,
                    "Raw baseline observations (%zu)",
                    entry.baseline.inventory.records.size()))
            {
                const std::size_t visibleCount = std::min(
                    entry.baseline.inventory.records.size(),
                    DebugObservationMaxVisibleRecords);
                for (std::size_t index = 0; index < visibleCount; ++index)
                {
                    RenderDebugObservationRecord(
                        entry.baseline.inventory.records[index],
                        nullptr);
                }
                if (entry.baseline.inventory.records.size() > visibleCount)
                {
                    WrappedTextDisabled(
                        std::to_string(
                            entry.baseline.inventory.records.size() -
                            visibleCount) +
                        " additional baseline observation(s) are retained but omitted from this view.");
                }
                ImGui::TreePop();
            }

            if (ImGui::TreeNodeEx(
                    "BaselineCompletedCorrelations",
                    ImGuiTreeNodeFlags_SpanAvailWidth,
                    "Completed baseline correlations (%zu)",
                    entry.correlations.correlations.size()))
            {
                const std::size_t visibleCount = std::min(
                    entry.correlations.correlations.size(),
                    DebugObservationMaxVisibleCorrelations);
                if (visibleCount > 0)
                {
                    const DebugObservationLookup lookup =
                        BuildDebugObservationLookup(entry.refinement);
                    for (std::size_t index = 0; index < visibleCount; ++index)
                    {
                        RenderDebugCorrelationCard(
                            entry.correlations.correlations[index],
                            lookup);
                    }
                }
                if (entry.correlations.correlations.size() > visibleCount)
                {
                    WrappedTextDisabled(
                        std::to_string(
                            entry.correlations.correlations.size() -
                            visibleCount) +
                        " additional baseline correlation(s) are retained but omitted from this view.");
                }
                ImGui::TreePop();
            }

            WrappedTextDisabled(
                "Deep selected-process collectors are not inputs to this baseline result. Expanding these details performs no collection or triage recomputation.");
        }

        static const char* SelectedEnrichedRejectionDebugText(
            Core::SelectedProcessEnrichedRejection rejection)
        {
            switch (rejection)
            {
            case Core::SelectedProcessEnrichedRejection::None:
                return "None";
            case Core::SelectedProcessEnrichedRejection::NoSelectedEntity:
                return "No selected entity";
            case Core::SelectedProcessEnrichedRejection::LoadedSnapshotScope:
                return "Loaded snapshot scope";
            case Core::SelectedProcessEnrichedRejection::PidMismatch:
                return "PID mismatch";
            case Core::SelectedProcessEnrichedRejection::CreationTimeAvailabilityMismatch:
                return "Creation-time availability mismatch";
            case Core::SelectedProcessEnrichedRejection::CreationTimeMismatch:
                return "Creation-time mismatch";
            case Core::SelectedProcessEnrichedRejection::ProcessGenerationMismatch:
                return "Process generation mismatch";
            case Core::SelectedProcessEnrichedRejection::EvidenceGenerationMismatch:
                return "Evidence generation mismatch";
            case Core::SelectedProcessEnrichedRejection::ScopeGenerationMismatch:
                return "Scope generation mismatch";
            case Core::SelectedProcessEnrichedRejection::ScopeMismatch:
                return "Live/snapshot scope mismatch";
            case Core::SelectedProcessEnrichedRejection::NativeObservationBuildFailed:
                return "Native observation build failed";
            case Core::SelectedProcessEnrichedRejection::RefinementFailed:
                return "Observation refinement failed";
            case Core::SelectedProcessEnrichedRejection::CorrelationFailed:
                return "Observation correlation failed";
            case Core::SelectedProcessEnrichedRejection::TriageFailed:
                return "TriageEngine failed";
            case Core::SelectedProcessEnrichedRejection::MaterialEvidenceIncomplete:
                return "Material evidence incomplete";
            case Core::SelectedProcessEnrichedRejection::InvalidResult:
            default:
                return "Invalid result";
            }
        }

        static const char* SelectedEnrichedRequestReasonDebugText(
            Core::SelectedProcessEnrichedRebuildReason reason)
        {
            switch (reason)
            {
            case Core::SelectedProcessEnrichedRebuildReason::SelectionChanged:
                return "Selection changed";
            case Core::SelectedProcessEnrichedRebuildReason::ProcessSnapshotChanged:
                return "Process snapshot changed";
            case Core::SelectedProcessEnrichedRebuildReason::FileIdentityChanged:
                return "File identity changed";
            case Core::SelectedProcessEnrichedRebuildReason::ChainChanged:
                return "Chain changed";
            case Core::SelectedProcessEnrichedRebuildReason::ModulesChanged:
                return "Modules changed";
            case Core::SelectedProcessEnrichedRebuildReason::MemoryChanged:
                return "Memory changed";
            case Core::SelectedProcessEnrichedRebuildReason::HandlesChanged:
                return "Handles changed";
            case Core::SelectedProcessEnrichedRebuildReason::TokenChanged:
                return "Token changed";
            case Core::SelectedProcessEnrichedRebuildReason::RuntimeChanged:
                return "Runtime changed";
            case Core::SelectedProcessEnrichedRebuildReason::NetworkChanged:
                return "Network changed";
            case Core::SelectedProcessEnrichedRebuildReason::ServiceAssociationChanged:
                return "Service association changed";
            case Core::SelectedProcessEnrichedRebuildReason::ExactIndicatorMatchesChanged:
                return "Exact indicator matches changed";
            case Core::SelectedProcessEnrichedRebuildReason::CollectionStateChanged:
                return "Collection state changed";
            case Core::SelectedProcessEnrichedRebuildReason::AllSelectedEvidenceChanged:
                return "All selected evidence changed";
            case Core::SelectedProcessEnrichedRebuildReason::ReturnToLive:
                return "Return to Live";
            case Core::SelectedProcessEnrichedRebuildReason::GenerationChangedDuringBuild:
                return "Generation changed during build";
            case Core::SelectedProcessEnrichedRebuildReason::None:
            default:
                return "None";
            }
        }

        void RenderSelectedProcessEnrichedLifecycleDebug(
            const Core::ProcessInfo& process)
        {
            const Core::SelectedProcessEnrichedLifecycleState& lifecycle =
                selectedEnrichedLifecycle_;
            const Core::SelectedProcessEnrichedSourceStamp current =
                CurrentSelectedProcessEnrichedSourceStamp();
            const Core::SelectedProcessTriageAuthority authority =
                SelectedTriageAuthorityForProcess(process);
            const char* authorityDecision = authority.UsesEnrichedTriage()
                ? "Enriched"
                : (authority.UsesBaselineTriage() ? "Baseline" : "Unavailable");
            const auto yesNo = [](bool value) { return value ? "Yes" : "No"; };
            const auto line = [this](const char* label, const std::string& value)
            {
                ImGui::TextDisabled("%s", label);
                ImGui::SameLine();
                WrappedTextDisabled(value);
            };

            BeginInspectorCard(
                "selected_enriched_lifecycle_debug",
                "Selected Enriched Lifecycle (Debug)",
                fonts_.bold);
            line("Selected PID:", std::to_string(current.identity.pid));
            line("Selected creation time available:",
                yesNo(current.identity.hasCreationTime));
            line("Selected creation time value:",
                current.identity.hasCreationTime
                    ? std::to_string(current.identity.creationTimeFileTime)
                    : std::string("Unavailable"));
            line("Live/snapshot scope:",
                current.scope == Core::SelectedProcessAnalysisScope::Live
                    ? std::string("Live")
                    : std::string("Loaded snapshot"));
            line("Selection generation:",
                std::to_string(lifecycle.selectionGeneration));
            line("Process generation:",
                std::to_string(current.processGeneration));
            line("Evidence generation:",
                std::to_string(current.evidenceGeneration));
            line("Scope generation:",
                std::to_string(current.scopeGeneration));
            line("Enriched request generation:",
                std::to_string(lifecycle.requestGeneration));
            line("Enriched request reason:",
                SelectedEnrichedRequestReasonDebugText(
                    lifecycle.lastRequestReason));
            line("Enriched build requested:", yesNo(lifecycle.buildRequested));
            line("Enriched build pending:", yesNo(lifecycle.buildPending));
            line("Enriched build started:", yesNo(lifecycle.buildStarted));
            line("Enriched build completed:", yesNo(lifecycle.buildCompleted));
            line("Native observation build success:",
                yesNo(lifecycle.nativeObservationBuildSuccess));
            line("Refinement success:", yesNo(lifecycle.refinementSuccess));
            line("Correlation success:", yesNo(lifecycle.correlationSuccess));
            line("Triage success:", yesNo(lifecycle.triageSuccess));
            line("Completeness sufficient for authority:",
                yesNo(lifecycle.completenessSufficientForAuthority));
            line("Publication attempted:",
                yesNo(lifecycle.publicationAttempted));
            line("Publication accepted:",
                yesNo(lifecycle.publicationAccepted));
            line("Publication rejected:",
                yesNo(lifecycle.publicationAttempted &&
                    !lifecycle.publicationAccepted));
            line("Exact rejection reason:",
                SelectedEnrichedRejectionDebugText(lifecycle.rejection));
            line("Stored enriched PID:",
                lifecycle.publicationAccepted
                    ? std::to_string(lifecycle.storedSource.identity.pid)
                    : std::string("Unavailable"));
            line("Stored enriched creation time:",
                lifecycle.publicationAccepted &&
                    lifecycle.storedSource.identity.hasCreationTime
                    ? std::to_string(
                        lifecycle.storedSource.identity.creationTimeFileTime)
                    : std::string("Unavailable"));
            line("Stored process/evidence/scope generations:",
                lifecycle.publicationAccepted
                    ? std::to_string(lifecycle.storedSource.processGeneration) +
                        "/" +
                        std::to_string(lifecycle.storedSource.evidenceGeneration) +
                        "/" +
                        std::to_string(lifecycle.storedSource.scopeGeneration)
                    : std::string("Unavailable"));
            line("Authority accessor decision:", authorityDecision);
            line("Completion timestamp/timing:",
                std::to_string(lifecycle.completionTimestampMilliseconds) +
                    " ms tick / " +
                    std::to_string(lifecycle.completionDurationMicroseconds) +
                    " us");
            if (!lifecycle.diagnostic.empty())
            {
                line("Bounded diagnostic:", lifecycle.diagnostic);
            }
            EndInspectorCard();
        }

        void RenderObservationEngineDebugPreview(
            const Core::ProcessInfo& process)
        {
            BeginInspectorCard(
                "observation_engine_debug_preview",
                "ObservationEngine Diagnostics (Debug)",
                fonts_.bold);
            WrappedTextColored(
                AccentBlue(),
                "TriageEngine uses the current native enriched result when available, then the current native baseline. An unavailable result never revives legacy verdict policy.");

            if (const CachedIconTexture* icon = FindCachedProcessIcon(process);
                icon != nullptr)
            {
                const char* stateText = "Unavailable";
                switch (icon->state)
                {
                case Core::ProcessIconState::Extracted:
                    stateText = "Extracted";
                    break;
                case Core::ProcessIconState::GenericFallback:
                    stateText = "Generic fallback";
                    break;
                case Core::ProcessIconState::Failed:
                    stateText = "Failed";
                    break;
                case Core::ProcessIconState::Unavailable:
                default:
                    break;
                }
                WrappedTextDisabled(
                    std::string("Process icon: ") + stateText + ". " +
                    icon->diagnostic);
                WrappedTextDisabled(
                    "Icon cache: " + std::to_string(processIconCacheHits_) +
                    " hit(s), " + std::to_string(processIconCacheMisses_) +
                    " miss(es), " +
                    std::to_string(processIconExtractionAttempts_) +
                    " extraction attempt(s), " +
                    std::to_string(genericProcessIconTextureBuilds_) +
                    " generic texture build(s).");
            }

            const Core::SelectedProcessTriageAuthority selectedAuthority =
                SelectedTriageAuthorityForProcess(process);
            ImGui::TextDisabled("Selected-process authority");
            WrappedTextColored(
                SeverityColor(
                    Core::ClassifyTriageVerdictForSurfaces(
                        selectedAuthority.verdict).severity),
                Core::TriageVerdictDisplayText(
                    selectedAuthority.verdict) + " - " +
                    Core::SelectedTriageAnalysisLevelDisplayText(
                        selectedAuthority.analysisLevel));
            if (selectedAuthority.unavailable &&
                !selectedAuthority.availabilityReason.empty())
            {
                WrappedTextDisabled(
                    "Unavailable category: " +
                    Core::TriageAvailabilityCategoryDisplayText(
                        selectedAuthority.availability.category));
                WrappedTextDisabled(
                    "Unavailable disposition: " +
                    Core::TriageAvailabilityDispositionDisplayText(
                        Core::ClassifyTriageAvailability(
                            selectedAuthority.availability.category)));
                WrappedTextDisabled(selectedAuthority.availabilityReason);
            }

            const Core::ProcessTriageCacheSourceStamp currentBaselineStamp =
                CurrentProcessTriageCacheStamp();
            // MatchesStamp intentionally means "current and usable." Debug
            // diagnosis must distinguish a failed build for the current source
            // generation from a successfully built but stale cache.
            const bool baselineCacheHasCurrentSourceStamp =
                processTriageCache_.attempted &&
                processTriageCache_.sourceStamp == currentBaselineStamp;
            const Core::CachedBaselineTriage* baselineEntry =
                baselineCacheHasCurrentSourceStamp
                    ? processTriageCache_.Find(process)
                    : nullptr;

            ImGui::TextDisabled("Baseline OE (process-wide authority when current)");
            if (baselineEntry != nullptr &&
                baselineEntry->success &&
                baselineEntry->triage.Succeeded())
            {
                WrappedTextColored(
                    SeverityColor(
                        DebugObservationVerdictSeverity(
                            baselineEntry->triage.verdict)),
                    Core::TriageVerdictDisplayText(
                        baselineEntry->triage.verdict));
                WrappedTextDisabled(
                    std::to_string(
                        baselineEntry->baseline.inventory.records.size()) +
                    " baseline observation(s), " +
                    std::to_string(
                        baselineEntry->triage.contributingDomains.size()) +
                    " contributing domain(s), " +
                    std::to_string(
                        baselineEntry->correlations.summary
                            .activatedCorrelationCount) +
                    " completed correlation(s), " +
                    std::to_string(
                        baselineEntry->buildDurationMicroseconds) +
                    " us.");
                WrappedTextDisabled(
                    "Coverage: globally available process, network, and service context only; selected-process deep evidence was not evaluated.");
                RenderSelectedBaselineDebugDetails(*baselineEntry);
            }
            else
            {
                WrappedTextColored(
                    SeverityColor(Core::Severity::Medium),
                    "Unavailable — no current baseline result is shown.");
                if (!baselineCacheHasCurrentSourceStamp)
                {
                    WrappedTextDisabled(
                        "The process-wide cache does not match the current process/evidence/scope generation.");
                }
                else if (!processTriageCache_.Succeeded())
                {
                    WrappedTextDisabled(
                        "The process-wide cache build failed for the current process/evidence/scope generation.");
                    if (!processTriageCache_.statusMessage.empty())
                    {
                        WrappedTextDisabled(processTriageCache_.statusMessage);
                    }
                }
                else if (baselineEntry == nullptr)
                {
                    WrappedTextDisabled(
                        "No retained baseline cache entry matches this process identity.");
                }
                else if (!baselineEntry->diagnostic.empty())
                {
                    WrappedTextDisabled(baselineEntry->diagnostic);
                }
            }
            RenderProcessTriageCacheDebugSummary(
                processTriageCache_,
                baselineCacheHasCurrentSourceStamp);
            WrappedTextDisabled(
                std::string("Authority projection: ") +
                (ProcessAuthorityProjectionMatchesCurrent()
                    ? "current"
                    : "unavailable or stale") +
                "; " + std::to_string(processAuthorityUnavailableCount_) +
                " per-entity unavailable row(s); " +
                std::to_string(processAuthorityProjectionBuildMicroseconds_) +
                " us projection time.");

            ImGui::TextDisabled("Enriched OE (selected-process authority when current)");

            const bool matchesCurrentGeneration = Core::ObservationShadowMatches(
                selectedObservationShadow_,
                true,
                process.pid,
                ProcessCacheStamp(process),
                selectedEvidenceGeneration_) &&
                selectedObservationShadow_.entityScope ==
                    ObservationShadowEntityScope(process, loadedSnapshotActive_) &&
                SelectedProcessEnrichedPublicationMatchesCurrent();
            if (!matchesCurrentGeneration)
            {
                WrappedTextDisabled(
                    "The enriched TriageEngine result is pending for the current selected-evidence generation. The current baseline remains authoritative when available; no prior enriched entity result is shown.");
                EndInspectorCard();
                return;
            }

            const Core::ObservationShadowState& shadow = selectedObservationShadow_;
            const Core::ObservationShadowDecisionSummary& decision = shadow.decisionSummary;
            const bool pipelineFailed = !shadow.success ||
                (shadow.refinement.attempted && !shadow.refinement.success) ||
                (shadow.correlation.attempted && !shadow.correlation.success) ||
                (shadow.triage.attempted && !shadow.triage.success);

            if (pipelineFailed)
            {
                WrappedTextColored(
                    SeverityColor(Core::Severity::Medium),
                    "Unavailable - enriched triage is not authoritative for this generation.");
                if (!shadow.success && !shadow.diagnosticMessage.empty())
                {
                    WrappedTextDisabled(shadow.diagnosticMessage);
                }
                else if (shadow.refinement.attempted && !shadow.refinement.success)
                {
                    WrappedTextDisabled(
                        "Refinement status: " +
                        Core::ObservationRefinementStatusDisplayText(
                            shadow.refinement.status));
                    RenderDebugObservationStringList(
                        "Refinement warnings",
                        shadow.refinement.warnings,
                        "No additional refinement diagnostic was retained.");
                }
                else if (shadow.correlation.attempted && !shadow.correlation.success)
                {
                    WrappedTextDisabled(
                        "Correlation status: " +
                        Core::ObservationCorrelationStatusDisplayText(
                            shadow.correlation.status));
                    RenderDebugObservationStringList(
                        "Correlation warnings",
                        shadow.correlation.warnings,
                        "No additional correlation diagnostic was retained.");
                }
                else if (shadow.triage.attempted && !shadow.triage.success)
                {
                    WrappedTextDisabled(
                        "Triage status: " +
                        Core::TriageEngineStatusDisplayText(
                            shadow.triage.status));
                    if (!shadow.triage.statusMessage.empty())
                    {
                        WrappedTextDisabled(shadow.triage.statusMessage);
                    }
                }
                if (shadow.refinement.Succeeded() &&
                    ImGui::CollapsingHeader(
                        "Available refined pipeline details##ObservationDebugFailureDetails"))
                {
                    WrappedTextDisabled(
                        "The enriched pipeline failed, but successful earlier stages remain available for audit. Baseline authority remains available independently.");
                    RenderDebugObservationDetails(shadow);
                }
                else if (shadow.success &&
                    ImGui::CollapsingHeader(
                        "Available raw observations##ObservationDebugFailureRaw"))
                {
                    WrappedTextDisabled(
                        "Refinement was unavailable. These retained raw native observations did not become authoritative.");
                    const std::size_t visibleCount = std::min(
                        shadow.inventory.records.size(),
                        DebugObservationMaxVisibleRecords);
                    for (std::size_t index = 0; index < visibleCount; ++index)
                    {
                        RenderDebugObservationRecord(
                            shadow.inventory.records[index],
                            nullptr);
                    }
                    if (shadow.inventory.records.size() > visibleCount)
                    {
                        WrappedTextDisabled(
                            std::to_string(
                                shadow.inventory.records.size() - visibleCount) +
                            " additional raw observation(s) are retained in the pipeline state but omitted from this view.");
                    }
                }
                EndInspectorCard();
                return;
            }

            if (!decision.attempted || !decision.success)
            {
                WrappedTextDisabled(
                    "The TriageEngine pipeline is pending for this current selected-evidence generation.");
                EndInspectorCard();
                return;
            }

            WrappedTextColored(
                SeverityColor(DebugObservationVerdictSeverity(decision.verdict)),
                Core::TriageVerdictDisplayText(decision.verdict));
            WrappedTextDisabled("TriageEngine pipeline status: Success.");
            ImGui::Spacing();
            InspectorSummaryChip(
                "debug_shadow_source_findings",
                "Native inputs",
                std::to_wstring(decision.nativeObservationCount),
                AccentBlue());
            SameLineIfFits(
                InspectorSummaryChipWidth(
                    "Refined groups",
                    std::to_wstring(decision.refinedGroupCount)),
                6.0f);
            InspectorSummaryChip(
                "debug_shadow_groups",
                "Refined groups",
                std::to_wstring(decision.refinedGroupCount),
                AccentBlue());
            SameLineIfFits(
                InspectorSummaryChipWidth(
                    "Artifacts",
                    std::to_wstring(decision.distinctArtifactCount)),
                6.0f);
            InspectorSummaryChip(
                "debug_shadow_artifacts",
                "Artifacts",
                std::to_wstring(decision.distinctArtifactCount),
                AccentBlue());
            SameLineIfFits(
                InspectorSummaryChipWidth(
                    "Correlations",
                    std::to_wstring(decision.activatedCorrelationCount)),
                6.0f);
            InspectorSummaryChip(
                "debug_shadow_correlations",
                "Correlations",
                std::to_wstring(decision.activatedCorrelationCount),
                AccentBlue());
            SameLineIfFits(
                InspectorSummaryChipWidth(
                    "Domains",
                    std::to_wstring(decision.contributingDomainCount)),
                6.0f);
            InspectorSummaryChip(
                "debug_shadow_domains",
                "Domains",
                std::to_wstring(decision.contributingDomainCount),
                AccentBlue());
            SameLineIfFits(
                InspectorSummaryChipWidth(
                    "Collection notes",
                    std::to_wstring(decision.collectionNoteCount)),
                6.0f);
            InspectorSummaryChip(
                "debug_shadow_collection_notes",
                "Collection notes",
                std::to_wstring(decision.collectionNoteCount),
                MutedText());
            SameLineIfFits(
                InspectorSummaryChipWidth(
                    "Typed facts",
                    std::to_wstring(decision.typedSourceFactCount)),
                6.0f);
            InspectorSummaryChip(
                "debug_shadow_typed_facts",
                "Typed facts",
                std::to_wstring(decision.typedSourceFactCount),
                AccentBlue());
            SameLineIfFits(
                InspectorSummaryChipWidth(
                    "Duplicates excluded",
                    std::to_wstring(
                        decision.typedSourceFactDuplicateCount)),
                6.0f);
            InspectorSummaryChip(
                "debug_shadow_duplicate_facts",
                "Duplicates excluded",
                std::to_wstring(
                    decision.typedSourceFactDuplicateCount),
                MutedText());
            SameLineIfFits(
                InspectorSummaryChipWidth(
                    "Native facts",
                    std::to_wstring(decision.nativeObservationCount)),
                6.0f);
            InspectorSummaryChip(
                "debug_shadow_native_facts",
                "Native facts",
                std::to_wstring(decision.nativeObservationCount),
                AccentBlue());
            SameLineIfFits(
                InspectorSummaryChipWidth(
                    "Token native",
                    std::to_wstring(
                        decision.nativeTokenObservationCount)),
                6.0f);
            InspectorSummaryChip(
                "debug_shadow_native_token",
                "Token native",
                std::to_wstring(decision.nativeTokenObservationCount),
                MutedText());
            SameLineIfFits(
                InspectorSummaryChipWidth(
                    "Handle native",
                    std::to_wstring(
                        decision.nativeHandleObservationCount)),
                6.0f);
            InspectorSummaryChip(
                "debug_shadow_native_handle",
                "Handle native",
                std::to_wstring(decision.nativeHandleObservationCount),
                MutedText());
            SameLineIfFits(
                InspectorSummaryChipWidth(
                    "Runtime native",
                    std::to_wstring(
                        decision.nativeRuntimeObservationCount)),
                6.0f);
            InspectorSummaryChip(
                "debug_shadow_native_runtime",
                "Runtime native",
                std::to_wstring(decision.nativeRuntimeObservationCount),
                MutedText());
            SameLineIfFits(
                InspectorSummaryChipWidth(
                    "Priority native",
                    std::to_wstring(
                        decision.nativePriorityObservationCount)),
                6.0f);
            InspectorSummaryChip(
                "debug_shadow_native_priority",
                "Priority native",
                std::to_wstring(decision.nativePriorityObservationCount),
                MutedText());
            WrappedTextDisabled(
                std::string("Native selected-process producer: ") +
                (decision.nativeBuildSucceeded
                    ? "Success"
                    : decision.nativeBuildAttempted
                        ? "Unavailable"
                        : "Not attempted") +
                "; " +
                std::to_string(
                    decision.nativeBuildDurationMicroseconds) +
                " us; material omissions " +
                std::to_string(
                    shadow.nativeObservations.omittedFactCount) + ".");

            WrappedTextDisabled(
                "Artifact grouping: " +
                std::to_string(decision.artifactGroupCount) +
                (decision.artifactGroupCount == 1
                    ? " group from "
                    : " groups from ") +
                std::to_string(decision.artifactAttributeCount) +
                (decision.artifactAttributeCount == 1
                    ? " retained artifact attribute."
                    : " retained artifact attributes."));
            WrappedTextDisabled(
                std::string("Same-domain correlation Medium ceiling: ") +
                (decision.sameDomainVerdictCeilingApplied
                    ? "Applied."
                    : "Not applied."));
            WrappedTextDisabled(
                std::string("High gates: standalone Strong ") +
                (decision.qualifiedStandaloneStrongHighGateSatisfied
                    ? "satisfied"
                    : "not satisfied") +
                "; coherent multi-domain " +
                (decision.coherentMultiDomainHighGateSatisfied
                    ? "satisfied."
                    : "not satisfied."));

            ImGui::Spacing();
            ImGui::TextDisabled("Verdict basis (Core-generated)");
            RenderDebugPreviewRationaleSection(
                shadow.triage,
                Core::TriageRationaleSection::VerdictBasis,
                3);
            ImGui::TextDisabled("Supporting context (Core-generated)");
            RenderDebugPreviewRationaleSection(
                shadow.triage,
                Core::TriageRationaleSection::SupportingContext,
                6);
            ImGui::TextDisabled("Collection limitations (Core-generated)");
            RenderDebugPreviewRationaleSection(
                shadow.triage,
                Core::TriageRationaleSection::CollectionLimitations,
                3);
            ImGui::TextDisabled("Presentation notes (Core-generated)");
            RenderDebugPreviewRationaleSection(
                shadow.triage,
                Core::TriageRationaleSection::PresentationNotes,
                2);

            if (ImGui::CollapsingHeader(
                    "ObservationEngine details (Debug)##ObservationDebugDetails"))
            {
                WrappedTextDisabled(
                    "Details render the retained Core pipeline state. Expanding this view performs no collection, observation building, refinement, correlation, or triage work.");
                RenderDebugObservationDetails(shadow);
            }
            EndInspectorCard();
        }
#endif

        void RenderTriagePanel()
        {
            const Core::ProcessInfo* process = Core::FindProcessByPid(snapshot_, selectedPid_);
            if (process == nullptr)
            {
                RenderEmptyState("No process is selected.", "Select a process to review triage evidence.");
                return;
            }

            const Core::SelectedProcessTriageAuthority authority =
                SelectedTriageAuthorityForProcess(*process);
            const std::vector<Core::NativeSourceEvidenceRecord>& nativeEvidence =
                SelectedNativeSourceEvidenceForProcess(*process);
            const bool historicalEvidence = UsesHistoricalSourceEvidence();
            const std::vector<Core::Finding> historicalRecords =
                historicalEvidence
                    ? HistoricalSourceEvidenceForProcess(*process)
                    : std::vector<Core::Finding>{};
            const std::size_t sourceRecordCount = historicalEvidence
                ? historicalRecords.size()
                : nativeEvidence.size();
            const NativeSourceEvidenceSectionPlan nativeEvidenceSection =
                PlanNativeSourceEvidenceSection(nativeEvidence.size());
            const std::wstring triageSummary = authority.notCaptured
                ? std::wstring(L"Not captured")
                : (authority.unavailable
                    ? std::wstring(L"Unavailable")
                    : InspectorTriageVerdictText(authority.verdict));
            const Core::TriageSurfaceClassification authorityClassification =
                Core::ClassifyTriageVerdictForSurfaces(authority.verdict);
            const Core::Severity verdictColorSeverity =
                authorityClassification.severity;
            const bool enrichedPending = !loadedSnapshotActive_ &&
                (selectedEnrichedLifecycle_.buildPending ||
                    selectedEnrichedLifecycle_.buildInProgress);
            const bool enrichedFailed = !loadedSnapshotActive_ &&
                selectedEnrichedLifecycle_.buildCompleted &&
                selectedEnrichedLifecycle_.publicationAttempted &&
                !selectedEnrichedLifecycle_.publicationAccepted &&
                !enrichedPending;
            const EnrichedAnalysisPresentationPlan enrichedPresentation =
                PlanEnrichedAnalysisPresentation(
                    authority.UsesEnrichedTriage(),
                    enrichedPending,
                    enrichedFailed,
                    IsExplicitEvidenceRefreshReason(
                        selectedEnrichedLifecycle_.lastRequestReason));

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
            SameLineIfFits(
                InspectorSummaryChipWidth(
                    "Source records",
                    InspectorEvidenceCountText(sourceRecordCount)),
                6.0f);
            InspectorSummaryChip(
                "triage_finding_count_chip",
                "Source records",
                InspectorEvidenceCountText(sourceRecordCount),
                sourceRecordCount == 0 ? MutedText() : SeverityColor(verdictColorSeverity));

            ImGui::Spacing();
            ImGui::TextDisabled(
                "Analysis level: %s",
                Core::SelectedTriageAnalysisLevelDisplayText(
                    authority.analysisLevel).c_str());
            if (authority.UsesEnrichedTriage() && authority.baselineAvailable)
            {
                ImGui::TextDisabled(
                    "Baseline triage: %s",
                    Core::TriageVerdictDisplayText(
                        authority.baselineVerdict).c_str());
                if (authority.verdict != authority.baselineVerdict)
                {
                    WrappedTextColored(
                        AccentBlue(),
                        "Additional selected-process evidence changed the result from the process-wide baseline.");
                }
            }
            else if (authority.UsesBaselineTriage())
            {
                WrappedTextDisabled(
                    enrichedPresentation.message[0] != '\0'
                        ? enrichedPresentation.message
                        : EnrichedAnalysisFailedMessage);
            }

            if (authority.notCaptured)
            {
                WrappedTextDisabled(
                    "Authoritative TriageEngine results were not captured in this older snapshot.");
            }
            else if (authority.unavailable)
            {
                WrappedTextColored(
                    SeverityColor(Core::Severity::Medium),
                    AuthoritativeTriageUnavailableMessage);
#ifdef _DEBUG
                if (!authority.availabilityReason.empty())
                {
                    WrappedTextDisabled(authority.availabilityReason);
                }
#endif
            }
            else if (authority.analysisLevel ==
                Core::SelectedTriageAnalysisLevel::LegacyFallback)
            {
                WrappedTextDisabled(
                    "This schema-4 snapshot retained a captured historical legacy-fallback state. It is displayed as captured metadata and is not recomputed.");
            }
            else
            {
                ImGui::Spacing();
                RenderAuthoritativeTriageRationale(authority);
                if (authority.persistedSummary != nullptr)
                {
                    ImGui::TextDisabled(
                        "Captured triage model: %u",
                        authority.persistedSummary->triageModelVersion);
                }
            }

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
                CopyTextToClipboard(
                    FormatSelectedAuthorityForClipboard(
                        *process,
                        authority,
                        sourceRecordCount,
                        historicalEvidence));
                AddLog(LogLevel::Info, "Copied triage summary to clipboard.");
            }
            SameLineIfFits(StandardButtonWidth("Copy Source Evidence"), 6.0f);
            const bool sourceEvidenceCopyEnabled = historicalEvidence
                ? sourceRecordCount != 0
                : nativeEvidenceSection.copyEnabled;
            if (!sourceEvidenceCopyEnabled)
            {
                ImGui::BeginDisabled();
            }
            if (ImGui::SmallButton("Copy Source Evidence"))
            {
                CopyTextToClipboard(historicalEvidence
                    ? FormatHistoricalSourceEvidenceForClipboard(
                        *process,
                        authority)
                    : FormatSourceEvidenceForClipboard(
                        *process,
                        authority,
                        nativeEvidence));
                AddLog(LogLevel::Info, "Copied source evidence to clipboard.");
            }
            if (!sourceEvidenceCopyEnabled)
            {
                ImGui::EndDisabled();
                RenderDisabledReasonTooltip(
                    "No source evidence is available to copy for this process.");
            }
            SameLineIfFits(StandardButtonWidth("Export Report"), 6.0f);
            if (ImGui::SmallButton("Export Report"))
            {
                ExportSelectedMarkdownReport();
            }
            EndInspectorCard();

#ifdef _DEBUG
            RenderSelectedProcessEnrichedLifecycleDebug(*process);
            RenderObservationEngineDebugPreview(*process);
#endif
            if (historicalEvidence)
            {
                BeginInspectorCard(
                    "triage_source_evidence_note",
                    "Historical Source Evidence",
                    fonts_.bold);
                WrappedTextDisabled(
                    "These imported legacy records are retained as historical metadata. They are readable and copyable, but they are not current TriageEngine input and no native verdict is fabricated from them.");
                ImGui::TextDisabled("Imported process-level severity metadata");
                ImGui::SameLine();
                if (process->historicalSeverityCaptured)
                {
                    SeverityText(process->severity);
                }
                else
                {
                    ImGui::TextDisabled("Not captured");
                }
                EndInspectorCard();

                if (historicalRecords.empty())
                {
                    BeginInspectorCard(
                        "triage_historical_empty",
                        "Historical Source Evidence",
                        fonts_.bold);
                    RenderEmptyState(
                        "No historical source records were captured for the selected process.");
                    EndInspectorCard();
                    return;
                }

                for (std::size_t index = 0; index < historicalRecords.size(); ++index)
                {
                    const Core::Finding& record = historicalRecords[index];
                    const std::string cardId =
                        "triage_historical_record_" + std::to_string(index);
                    const ImVec4 accent = AccentBlue();
                    ImGui::PushStyleColor(
                        ImGuiCol_ChildBg,
                        ImVec4(0.044f, 0.055f, 0.073f, 1.0f));
                    ImGui::PushStyleColor(
                        ImGuiCol_Border,
                        ImVec4(accent.x, accent.y, accent.z, 0.45f));
                    ImGui::BeginChild(
                        cardId.c_str(),
                        ImVec2(0.0f, 0.0f),
                        ImGuiChildFlags_Borders |
                            ImGuiChildFlags_AlwaysUseWindowPadding |
                            ImGuiChildFlags_AutoResizeY);
                    ImGui::TextColored(accent, "Historical source record");
                    ImGui::SameLine();
                    const bool pushedTitle = PushFontIfAvailable(fonts_.bold);
                    WrappedTextWide(
                        record.title.empty()
                            ? L"Historical source record"
                            : record.title);
                    PopFontIfPushed(pushedTitle);
                    WrappedTextWide(record.description);
                    ImGui::TextDisabled(
                        "Historical source severity: %s",
                        WideToUtf8(
                            Core::HistoricalFindingSeverityText(record)).c_str());
                    if (ImGui::SmallButton("Copy Historical Record"))
                    {
                        std::wstringstream copied;
                        copied << (record.title.empty()
                            ? L"Historical source record"
                            : record.title) << L"\r\n";
                        if (!record.description.empty())
                        {
                            copied << record.description << L"\r\n";
                        }
                        copied << L"Historical source severity: " <<
                            Core::HistoricalFindingSeverityText(record) <<
                            L"\r\n";
                        CopyTextToClipboard(copied.str());
                        AddLog(
                            LogLevel::Info,
                            "Copied historical source-evidence record to clipboard.");
                    }
                    ImGui::EndChild();
                    ImGui::PopStyleColor(2);
                    ImGui::Spacing();
                }
                return;
            }

            BeginInspectorCard(
                "triage_source_evidence_note",
                "Native Source Evidence",
                fonts_.bold);
            WrappedTextDisabled(
                "These bounded native records are projected from refined observations. They distinguish verdict contribution, supporting context, and collection limitations.");
            if (nativeEvidenceSection.showEmptyState)
            {
                ImGui::Spacing();
                RenderEmptyState(
                    "No native source-evidence records are available for this process.",
                    authority.unavailable
                        ? "The current analysis result is unavailable; no authoritative attention level is available."
                        : "A successful Informational result may legitimately contain no review-relevant source records.");
                EndInspectorCard();
                return;
            }

            if (nativeEvidenceSection.showFilters)
            {
                ImGui::Spacing();
                ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(6.0f, 6.0f));
                if (ChipButton("All##TriageFilter", triageFilter_ == TriageFilter::All, AccentBlue()))
                {
                    triageFilter_ = TriageFilter::All;
                }
                SameLineIfChipFits("Contributing");
                if (ChipButton(
                        "Contributing##TriageFilter",
                        triageFilter_ == TriageFilter::Contributing,
                        SeverityColor(Core::Severity::Medium)))
                {
                    triageFilter_ = TriageFilter::Contributing;
                }
                SameLineIfChipFits("Context");
                if (ChipButton(
                        "Context##TriageFilter",
                        triageFilter_ == TriageFilter::Context,
                        AccentBlue()))
                {
                    triageFilter_ = TriageFilter::Context;
                }
                SameLineIfChipFits("Limitations");
                if (ChipButton(
                        "Limitations##TriageFilter",
                        triageFilter_ == TriageFilter::Limitations,
                        SeverityColor(Core::Severity::Low)))
                {
                    triageFilter_ = TriageFilter::Limitations;
                }
                ImGui::PopStyleVar();
            }
            EndInspectorCard();

            std::size_t visibleRecords = 0;
            for (std::size_t index = 0; index < nativeEvidence.size(); ++index)
            {
                const Core::NativeSourceEvidenceRecord& record =
                    nativeEvidence[index];
                if (!NativeEvidenceMatchesFilter(record, triageFilter_))
                {
                    continue;
                }

                ++visibleRecords;
                const std::string cardId =
                    "triage_native_evidence_" + std::to_string(index);
                const ImVec4 accent = record.collectionLimitation
                    ? SeverityColor(Core::Severity::Low)
                    : (record.contributedToVerdict
                        ? SeverityColor(Core::Severity::Medium)
                        : AccentBlue());
                ImGui::PushStyleColor(
                    ImGuiCol_ChildBg,
                    ImVec4(0.044f, 0.055f, 0.073f, 1.0f));
                ImGui::PushStyleColor(
                    ImGuiCol_Border,
                    ImVec4(accent.x, accent.y, accent.z, 0.55f));
                ImGui::BeginChild(
                    cardId.c_str(),
                    ImVec2(0.0f, 0.0f),
                    ImGuiChildFlags_Borders | ImGuiChildFlags_AlwaysUseWindowPadding | ImGuiChildFlags_AutoResizeY);

                ImGui::TextColored(
                    accent,
                    "%s",
                    record.collectionLimitation
                        ? "Collection limitation"
                        : (record.contributedToVerdict
                            ? "Contributed to verdict"
                            : "Supporting context"));
                ImGui::SameLine();
                const bool pushedTitle = PushFontIfAvailable(fonts_.bold);
                WrappedTextColored(
                    ImVec4(0.88f, 0.93f, 0.98f, 1.0f),
                    record.title.empty()
                        ? "Untitled source evidence"
                        : record.title);
                PopFontIfPushed(pushedTitle);
                ImGui::SameLine();
                if (ImGui::SmallButton("Copy Record"))
                {
                    CopyTextToClipboard(
                        FormatNativeSourceEvidenceRecordForClipboard(record));
                    AddLog(LogLevel::Info, "Copied source-evidence record to clipboard.");
                }

                ImGui::TextDisabled("Domain");
                ImGui::SameLine(145.0f);
                ImGui::TextUnformatted(
                    Core::EvidenceDomainDisplayText(record.domain).c_str());
                ImGui::TextDisabled("Disposition");
                ImGui::SameLine(145.0f);
                ImGui::TextUnformatted(
                    Core::ObservationDispositionDisplayText(
                        record.disposition).c_str());
                ImGui::TextDisabled("Strength / confidence");
                ImGui::SameLine(145.0f);
                ImGui::Text(
                    "%s / %s",
                    Core::ObservationStrengthDisplayText(
                        record.strength).c_str(),
                    Core::ObservationConfidenceDisplayText(
                        record.confidence).c_str());
                if (!record.summary.empty())
                {
                    WrappedTextColored(
                        ImGui::GetStyleColorVec4(ImGuiCol_Text),
                        record.summary);
                }

                if (!record.details.empty())
                {
                    ImGui::SeparatorText("Details");
                    for (const std::string& detail : record.details)
                    {
                        ImGui::TextColored(ImVec4(accent.x, accent.y, accent.z, 0.80f), "-");
                        ImGui::SameLine();
                        WrappedTextDisabled(detail);
                    }
                }
                if (!record.limitations.empty())
                {
                    ImGui::SeparatorText("Limitations");
                    for (const std::string& limitation : record.limitations)
                    {
                        ImGui::Bullet();
                        ImGui::SameLine();
                        WrappedTextDisabled(limitation);
                    }
                }
                if (!record.provenanceSummary.empty())
                {
                    ImGui::TextDisabled("Provenance");
                    WrappedTextDisabled(record.provenanceSummary);
                }
#ifdef _DEBUG
                if (record.suppressedDuplicate)
                {
                    WrappedTextDisabled(
                        "Duplicate/supporting source retained for audit; it did not reinforce the verdict.");
                }
#endif
                ImGui::EndChild();
                ImGui::PopStyleColor(2);
                ImGui::Spacing();
            }

            if (visibleRecords == 0)
            {
                const std::string filterDetail =
                    "Current filter: " + WideToUtf8(TriageFilterLabel(triageFilter_));
                RenderEmptyState(
                    "No source-evidence records match the current filter.",
                    filterDetail.c_str());
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
            const NetworkSummary networkSummary = GetNetworkSummary(process->pid);
            Core::FileIdentity loadedSnapshotFileIdentity;
            const Core::FileIdentity& fileIdentity = loadedSnapshotActive_
                ? loadedSnapshotFileIdentity
                : CachedFileIdentity(*process);
            const Core::SelectedProcessTriageAuthority authority =
                SelectedTriageAuthorityForProcess(*process);
            const std::vector<Core::NativeSourceEvidenceRecord>& nativeEvidence =
                SelectedNativeSourceEvidenceForProcess(*process);
            const bool historicalEvidence = UsesHistoricalSourceEvidence();
            const Core::TriageSurfaceClassification authorityClassification =
                Core::ClassifyTriageVerdictForSurfaces(authority.verdict);
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
            ImGui::TextColored(SeverityColor(authorityClassification.severity),
                "%s",
                authority.unavailable
                    ? "Unavailable"
                    : Core::TriageVerdictDisplayText(authority.verdict).c_str());
            ImGui::TextDisabled("Analysis");
            ImGui::SameLine(82.0f);
            ImGui::TextUnformatted(
                Core::SelectedTriageAnalysisLevelDisplayText(
                    authority.analysisLevel).c_str());
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
                "process executable");
            EndInspectorCard();

            BeginInspectorCard("details_security", "Security", fonts_.bold);
            LabelValue(
                "Triage",
                authority.unavailable
                    ? std::wstring(L"Unavailable")
                    : InspectorTriageVerdictText(authority.verdict));
            LabelValue(
                "Analysis Level",
                Core::SelectedTriageAnalysisLevelDisplayText(
                    authority.analysisLevel).c_str());
            LabelValue(
                "Suspicious",
                authorityClassification.suspicious ? "Yes" : "No");
            ImGui::TextDisabled("Attention");
            ImGui::SameLine(145.0f);
            SeverityText(authorityClassification.severity);
            if (historicalEvidence)
            {
                ImGui::TextDisabled("Imported process severity metadata");
                ImGui::SameLine(145.0f);
                if (process->historicalSeverityCaptured)
                {
                    SeverityText(process->severity);
                }
                else
                {
                    ImGui::TextDisabled("Not captured");
                }
            }
            LabelValue("Network Connections", std::to_wstring(networkSummary.connectionCount));
            LabelValue("Listening Sockets", std::to_wstring(networkSummary.listeningCount));
            LabelValue("Public Remote", std::to_wstring(networkSummary.publicRemoteCount));
            LabelValue("Intel Matches", std::to_wstring(networkSummary.intelMatchCount));
            EndInspectorCard();

            BeginInspectorCard(
                "details_indicators",
                historicalEvidence
                    ? "Historical Source Evidence"
                    : "Native Evidence Summary",
                fonts_.bold);
            if (historicalEvidence)
            {
                if (process->indicators.empty())
                {
                    RenderEmptyState("No historical source records are available.");
                }
                for (const std::wstring& indicator : process->indicators)
                {
                    ImGui::Bullet();
                    ImGui::SameLine();
                    WrappedTextWide(indicator);
                }
            }
            else if (nativeEvidence.empty())
            {
                RenderEmptyState("No native source-evidence records are available.");
            }
            else
            {
                for (const Core::NativeSourceEvidenceRecord& record : nativeEvidence)
                {
                    ImGui::Bullet();
                    ImGui::SameLine();
                    WrappedTextColored(
                        record.contributedToVerdict
                            ? SeverityColor(Core::Severity::Medium)
                            : AccentBlue(),
                        record.title);
                }
            }
            EndInspectorCard();

            BeginInspectorCard("details_context", "Collection and Context Notes", fonts_.bold);
            bool renderedContext = false;
            if (historicalEvidence)
            {
                for (const std::wstring& note : process->contextNotes)
                {
                    ImGui::Bullet();
                    ImGui::SameLine();
                    WrappedTextWide(note);
                    renderedContext = true;
                }
            }
            else
            {
                for (const Core::NativeSourceEvidenceRecord& record : nativeEvidence)
                {
                    if (record.contributedToVerdict &&
                        !record.collectionLimitation)
                    {
                        continue;
                    }
                    ImGui::Bullet();
                    ImGui::SameLine();
                    WrappedTextDisabled(record.summary.empty()
                        ? record.title
                        : record.summary);
                    renderedContext = true;
                }
            }
            if (!renderedContext)
            {
                RenderEmptyState("No collection or supporting-context notes are available.");
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
                ImGui::PopID();
            }

            ImGui::SeparatorText(
                UsesHistoricalSourceEvidence()
                    ? "Historical Relationship Metadata"
                    : "Native Relationship Evidence");
            bool renderedRelationshipEvidence = false;
            if (UsesHistoricalSourceEvidence())
            {
                WrappedTextDisabled(
                    "Imported relationship records are retained in Historical Source Evidence below.");
                renderedRelationshipEvidence = true;
            }
            else
            {
                const std::vector<Core::NativeSourceEvidenceRecord>& evidence =
                    SelectedNativeSourceEvidenceForProcess(*process);
                for (const Core::NativeSourceEvidenceRecord& record : evidence)
                {
                    if (record.domain != Core::EvidenceDomain::ProcessRelationship)
                    {
                        continue;
                    }
                    ImGui::Bullet();
                    ImGui::SameLine();
                    WrappedTextWide(Utf8ToWide(record.title.c_str()));
                    renderedRelationshipEvidence = true;
                }
            }
            if (!renderedRelationshipEvidence)
            {
                RenderEmptyState("No relationship source-evidence records are available.");
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
                    ImGui::SeparatorText("File Identity");
                    RenderFileIdentityFields(
                        "selected_module_file_identity",
                        moduleFileIdentity,
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
                    ImGui::GetStyleColorVec4(ImGuiCol_Text),
                    fonts_.bold);
                ImGui::TableSetColumnIndex(1);
                TokenSummaryCell(
                    "Admin",
                    YesNo(token.isAdmin),
                    ImGui::GetStyleColorVec4(ImGuiCol_Text),
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

            const std::vector<Core::NativeSourceEvidenceRecord>& nativeEvidence =
                SelectedNativeSourceEvidenceForProcess(*process);
            bool hasTokenEvidence = false;
            for (const Core::NativeSourceEvidenceRecord& record : nativeEvidence)
            {
                if (record.domain == Core::EvidenceDomain::Token)
                {
                    if (!hasTokenEvidence)
                    {
                        BeginInspectorCard("token_context", "Token Context", fonts_.bold);
                        hasTokenEvidence = true;
                    }
                    WrappedTextColored(
                        record.contributedToVerdict
                            ? SeverityColor(Core::Severity::Medium)
                            : AccentBlue(),
                        record.title);
                    if (!record.summary.empty())
                    {
                        WrappedTextDisabled(record.summary);
                    }
                    for (const std::string& detail : record.details)
                    {
                        ImGui::Bullet();
                        ImGui::SameLine();
                        WrappedTextDisabled(detail);
                    }
                    ImGui::Spacing();
                }
            }
            if (hasTokenEvidence)
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
                            ImGui::TableSetColumnIndex(0);
                            const bool pushedPrivilegeFont = PushFontIfAvailable(fonts_.monospace);
                            ClippedTextWithTooltip(privilege.name.empty() ? L"(unknown)" : privilege.name);
                            PopFontIfPushed(pushedPrivilegeFont);

                            ImGui::TableSetColumnIndex(1);
                            const std::wstring state = PrivilegeStateText(privilege);
                            TextWide(state);

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

#ifdef _DEBUG
        void RenderHandleCollectionDebugDiagnostics(
            const Core::HandleCollectionResult& collection)
        {
            ImGui::SeparatorText("Collection diagnostics (Debug)");
            LabelValue(
                "State",
                HandleCollectionStateDisplayText(collection.state));
            LabelValue(
                "System Entries",
                std::to_wstring(collection.systemHandleCount) +
                    L" reported / " +
                    std::to_wstring(collection.systemEntriesScanned) +
                    L" scanned");
            LabelValue(
                "Selected Handles",
                std::to_wstring(collection.selectedProcessHandlesMatched) +
                    L" matched / " +
                    std::to_wstring(collection.handles.size()) +
                    L" retained / " +
                    std::to_wstring(collection.selectedProcessHandlesOmitted) +
                    L" omitted");
            LabelValue(
                "Query Buffer",
                FileSizeText(collection.queryBufferBytes) +
                    L" used / " +
                    FileSizeText(collection.queryBufferBudgetBytes) +
                    L" budget / " +
                    std::to_wstring(collection.queryAttemptCount) +
                    L" attempt(s)");
            LabelValue(
                "Compact Records",
                FileSizeText(collection.compactCoreRecordBytes));
            LabelValue(
                "Object Names",
                std::to_wstring(collection.namesResolved) +
                    L" resolved / " +
                    std::to_wstring(collection.namesSkipped) +
                    L" skipped / " +
                    std::to_wstring(collection.namesFailed) +
                    L" failed");
            LabelValue(
                "Type Metadata",
                std::to_wstring(collection.typeResolutionsResolved) +
                    L" resolved / " +
                    std::to_wstring(collection.typeResolutionsSkipped) +
                    L" skipped / " +
                    std::to_wstring(collection.typeResolutionsFailed) +
                    L" failed");
            LabelValue(
                "Target Identity",
                std::to_wstring(collection.targetsResolved) +
                    L" resolved / " +
                    std::to_wstring(collection.targetsUnresolved) +
                    L" unresolved");
            LabelValue(
                "Timing",
                std::to_wstring(collection.queryDurationMicroseconds) +
                    L" us query / " +
                    std::to_wstring(collection.enrichmentDurationMicroseconds) +
                    L" us enrichment / " +
                    std::to_wstring(collection.totalDurationMicroseconds) +
                    L" us total");
        }
#endif

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

            const HandleCollectionSectionPlan handlePresentation =
                PlanHandleCollectionSection(
                    selectedHandles_.state,
                    selectedHandles_.handles.size());

            if (handlePresentation.showUnavailableState)
            {
                BeginInspectorCard("handles_unavailable", "Handles", fonts_.bold);
                const std::string handleDetail = WideToUtf8(selectedHandles_.statusMessage.empty()
                    ? L"Collection did not complete."
                    : selectedHandles_.statusMessage);
                RenderEmptyState("Handle information is unavailable.", handleDetail.c_str());
#ifdef _DEBUG
                RenderHandleCollectionDebugDiagnostics(selectedHandles_);
#endif
                EndInspectorCard();
                return;
            }

            if (handlePresentation.showLimitationBanner)
            {
                BeginInspectorCard(
                    "handles_collection_limitation",
                    "Handle Collection Limitation",
                    fonts_.bold);
                WrappedTextColored(
                    SeverityColor(Core::Severity::Low),
                    WideToUtf8(selectedHandles_.statusMessage.empty()
                        ? L"Retained handle records are shown, but additional handles or optional metadata may not have been evaluated."
                        : selectedHandles_.statusMessage));
                EndInspectorCard();
            }

            if (handlePresentation.showEmptyState)
            {
                BeginInspectorCard("handles_none", "Handles", fonts_.bold);
                RenderEmptyState(
                    "No handles were found for this process.",
                    selectedHandles_.IsPartial()
                        ? "Collection completed partially; safety limits may have prevented full evaluation."
                        : nullptr);
#ifdef _DEBUG
                RenderHandleCollectionDebugDiagnostics(selectedHandles_);
#endif
                EndInspectorCard();
                return;
            }

            BeginInspectorCard("handles_filters", "Filters", fonts_.bold);
            ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x);
            if (ImGui::InputTextWithHint(
                "##HandlesPanelSearch",
                "Search handle, type, target, access, category",
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
            SameLineIfChipFits("Material Access");
            if (ChipButton("Material Access##HandleFilter", handleFilter_ == HandleFilter::MaterialAccess, AccentBlue()))
            {
                if (handleFilter_ != HandleFilter::MaterialAccess)
                {
                    handleFilter_ = HandleFilter::MaterialAccess;
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
            SameLineIfChipFits("With Access Categories");
            if (ChipButton("With Access Categories##HandleFilter", handleFilter_ == HandleFilter::WithAccessCategories, AccentBlue()))
            {
                if (handleFilter_ != HandleFilter::WithAccessCategories)
                {
                    handleFilter_ = HandleFilter::WithAccessCategories;
                    visibleHandlesDirty_ = true;
                    handlesTableNeedsAutoSize_ = true;
                }
            }
            EndInspectorCard();

            RebuildVisibleHandlesIfNeeded(*process);

            BeginInspectorCard("handles_summary", "Handle Summary", fonts_.bold);
            LabelValue("Total Loaded", std::to_wstring(selectedHandles_.handles.size()));
            LabelValue("Visible", std::to_wstring(visibleHandleIndexes_.size()));
            LabelValue("With Typed Access", std::to_wstring(visibleHandlesWithTypedAccessCount_));
            LabelValue("Name Unavail/Skipped", std::to_wstring(visibleHandlesNameStatusCount_));
            if (!handlePresentation.showLimitationBanner)
            {
                ImGui::TextDisabled("Status");
                WrappedTextDisabled(selectedHandles_.statusMessage.empty()
                    ? L"(no status)"
                    : selectedHandles_.statusMessage);
            }
#ifdef _DEBUG
            RenderHandleCollectionDebugDiagnostics(selectedHandles_);
#endif
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
                    "Access categories",
                    ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoSort,
                    148.0f);
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
                        ImGui::PushID(static_cast<int>(handleIndex));

                        ImGui::TableSetColumnIndex(0);
                        const std::wstring handleValue = HandleValueText(handle.handleValue);
                        const bool pushedHandleFont = PushFontIfAvailable(fonts_.monospace);
                        ClippedTextWithTooltip(handleValue);
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
                        const std::wstring accessCategories =
                            HandleAccessCategoryText(handle);
                        const std::wstring status = HandleStatusText(handle);
                        std::wstring displayedCategoryText;
                        bool categoryHovered = false;
                        if (!accessCategories.empty())
                        {
                            displayedCategoryText = accessCategories;
                            ImGui::TextUnformatted(
                                WideToUtf8(accessCategories).c_str());
                            categoryHovered = ImGui::IsItemHovered();
                            if (categoryHovered)
                            {
                                RenderWrappedTooltip(accessCategories, 560.0f);
                            }
                        }
                        else if (!status.empty())
                        {
                            displayedCategoryText = status;
                            ImGui::TextDisabled("%s", WideToUtf8(status).c_str());
                            categoryHovered = ImGui::IsItemHovered();
                            if (categoryHovered && !handle.errorMessage.empty())
                            {
                                RenderWrappedTooltip(handle.errorMessage, 560.0f);
                            }
                        }
                        else
                        {
                            displayedCategoryText = L"None";
                            ImGui::TextDisabled("None");
                            categoryHovered = ImGui::IsItemHovered();
                        }
                        const bool categoryContextRequested =
                            categoryHovered && ImGui::IsMouseReleased(ImGuiMouseButton_Right);
                        RenderInspectorValueContextMenu(
                            "HandleAccessCategoryValueContext",
                            displayedCategoryText,
                            categoryContextRequested);

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

            const std::vector<Core::NativeSourceEvidenceRecord>& nativeEvidence =
                SelectedNativeSourceEvidenceForProcess(*process);
            bool hasRuntimeContext = !runtime.contextNotes.empty();
            for (const Core::NativeSourceEvidenceRecord& record : nativeEvidence)
            {
                if (record.domain == Core::EvidenceDomain::Runtime)
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
                for (const Core::NativeSourceEvidenceRecord& record : nativeEvidence)
                {
                    if (record.domain != Core::EvidenceDomain::Runtime)
                    {
                        continue;
                    }

                    WrappedTextColored(
                        record.contributedToVerdict
                            ? SeverityColor(Core::Severity::Medium)
                            : AccentBlue(),
                        record.title);
                    if (!record.summary.empty())
                    {
                        WrappedTextDisabled(record.summary);
                    }
                    for (const std::string& detail : record.details)
                    {
                        ImGui::Bullet();
                        ImGui::SameLine();
                        WrappedTextDisabled(detail);
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
                "Search address, protection, type, mapped file, metadata",
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
            SameLineIfChipFits("Executable Context");
            if (ChipButton("Executable Context##MemoryFilter", memoryFilter_ == MemoryFilter::ExecutableContext, AccentBlue()))
            {
                if (memoryFilter_ != MemoryFilter::ExecutableContext)
                {
                    memoryFilter_ = MemoryFilter::ExecutableContext;
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
                    "Metadata",
                    ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoSort,
                    170.0f);
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
                        if (region.isGuard)
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
                        const std::wstring attributes = MemoryAttributeText(region);
                        const std::wstring displayedAttributes =
                            attributes.empty() ? L"None" : attributes;
                        bool attributesHovered = false;
                        if (attributes.empty())
                        {
                            ImGui::TextDisabled("None");
                            attributesHovered = ImGui::IsItemHovered();
                        }
                        else
                        {
                            ImGui::TextUnformatted(WideToUtf8(attributes).c_str());
                            attributesHovered = ImGui::IsItemHovered();
                            if (attributesHovered)
                            {
                                RenderWrappedTooltip(attributes, 600.0f);
                            }
                        }
                        RenderInspectorValueContextMenu(
                            "MemoryMetadataValueContext",
                            displayedAttributes,
                            attributesHovered && ImGui::IsMouseReleased(ImGuiMouseButton_Right));
                        ImGui::PopID();
                    }
                }
                ImGui::EndTable();
            }
            EndInspectorCard();
        }
