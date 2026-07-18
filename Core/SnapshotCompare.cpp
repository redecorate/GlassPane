#include "SnapshotCompare.h"

#include <Windows.h>

#include <algorithm>
#include <map>
#include <sstream>
#include <tuple>
#include <unordered_map>
#include <unordered_set>

namespace GlassPane::Core
{
    namespace
    {
        std::wstring ValueOr(const std::wstring& value, const wchar_t* fallback)
        {
            return value.empty() ? std::wstring(fallback) : value;
        }

        std::wstring SessionText(const SnapshotProcessRecord& process)
        {
            return process.hasSessionId ? std::to_wstring(process.sessionId) : L"(unknown)";
        }

        std::wstring Utf8ToWide(const std::string& value)
        {
            if (value.empty())
            {
                return {};
            }

            const int required = MultiByteToWideChar(
                CP_UTF8,
                MB_ERR_INVALID_CHARS,
                value.data(),
                static_cast<int>(value.size()),
                nullptr,
                0);
            if (required <= 0)
            {
                return L"(invalid UTF-8)";
            }

            std::wstring converted(static_cast<std::size_t>(required), L'\0');
            if (MultiByteToWideChar(
                    CP_UTF8,
                    MB_ERR_INVALID_CHARS,
                    value.data(),
                    static_cast<int>(value.size()),
                    converted.data(),
                    required) != required)
            {
                return L"(invalid UTF-8)";
            }
            return converted;
        }

        std::wstring BoolText(bool value)
        {
            return value ? L"Yes" : L"No";
        }

        std::wstring PersistedTriageAnalysisLevelText(
            PersistedTriageAnalysisLevel level)
        {
            return Utf8ToWide(PersistedTriageAnalysisLevelDisplayText(level));
        }

        std::wstring PersistedTriageVerdictText(TriageVerdict verdict)
        {
            return Utf8ToWide(TriageVerdictDisplayText(verdict));
        }

        std::wstring PersistedTriageBaselineVerdictText(
            const PersistedTriageSummary& summary)
        {
            return summary.baselineVerdictAvailable
                ? PersistedTriageVerdictText(summary.baselineVerdict)
                : L"Not available";
        }

        std::wstring PersistedTriageDomainsText(
            const std::vector<EvidenceDomain>& domains)
        {
            if (domains.empty())
            {
                return L"None";
            }

            std::wstringstream text;
            for (std::size_t index = 0; index < domains.size(); ++index)
            {
                if (index != 0)
                {
                    text << L", ";
                }
                text << Utf8ToWide(EvidenceDomainDisplayText(domains[index]));
            }
            return text.str();
        }

        std::vector<std::string> CanonicalPersistedTriageLines(
            const std::vector<std::string>& lines)
        {
            std::vector<std::string> canonical = lines;
            std::sort(canonical.begin(), canonical.end());
            canonical.erase(
                std::unique(canonical.begin(), canonical.end()),
                canonical.end());
            return canonical;
        }

        std::wstring PersistedTriageLinesText(
            const std::vector<std::string>& lines)
        {
            const std::vector<std::string> canonical =
                CanonicalPersistedTriageLines(lines);
            if (canonical.empty())
            {
                return L"None";
            }

            std::wstringstream text;
            for (std::size_t index = 0; index < canonical.size(); ++index)
            {
                if (index != 0)
                {
                    text << L"\n";
                }
                text << L"- " << Utf8ToWide(canonical[index]);
            }
            return text.str();
        }

        FindingSeverity FindingSeverityFromProcessSeverity(Severity severity)
        {
            switch (severity)
            {
            case Severity::High:
                return FindingSeverity::High;
            case Severity::Medium:
                return FindingSeverity::Medium;
            case Severity::Low:
                return FindingSeverity::Low;
            case Severity::Info:
            case Severity::None:
            default:
                return FindingSeverity::Info;
            }
        }

        std::wstring ProcessMapKey(const SnapshotProcessRecord& process)
        {
            return SnapshotProcessKeyToString(process.key);
        }

        std::wstring NetworkMapKey(const SnapshotNetworkEndpoint& endpoint)
        {
            std::wstringstream stream;
            stream << SnapshotProcessKeyToString(endpoint.owningProcessKey)
                   << L"|"
                   << endpoint.protocol
                   << L"|"
                   << endpoint.localAddress
                   << L":"
                   << endpoint.localPort
                   << L"|"
                   << endpoint.remoteAddress
                   << L":"
                   << endpoint.remotePort
                   << L"|"
                   << endpoint.state
                   << L"|"
                   << endpoint.addressFamily;
            return stream.str();
        }

        std::wstring FindingIdentityKey(const SnapshotFindingRecord& finding)
        {
            std::wstringstream stream;
            stream << SnapshotProcessKeyToString(finding.processKey)
                   << L"|"
                   << finding.category
                   << L"|"
                   << finding.title;
            return stream.str();
        }

        std::wstring FindingFullKey(const SnapshotFindingRecord& finding)
        {
            std::wstringstream stream;
            stream << FindingIdentityKey(finding)
                   << L"|"
                   << SnapshotFindingSeverityText(finding)
                   << L"|"
                   << finding.evidenceSummary;
            return stream.str();
        }

        std::vector<std::string> CanonicalTextItems(
            const std::vector<std::string>& values)
        {
            std::vector<std::string> canonical = values;
            std::sort(canonical.begin(), canonical.end());
            canonical.erase(
                std::unique(canonical.begin(), canonical.end()),
                canonical.end());
            return canonical;
        }

        std::wstring NativeTextItemsText(
            const std::vector<std::string>& values)
        {
            const std::vector<std::string> canonical =
                CanonicalTextItems(values);
            if (canonical.empty())
            {
                return L"None";
            }

            std::wstringstream text;
            for (std::size_t index = 0; index < canonical.size(); ++index)
            {
                if (index != 0)
                {
                    text << L"\n";
                }
                text << L"- " << Utf8ToWide(canonical[index]);
            }
            return text.str();
        }

        struct NativeSemanticIdentity
        {
            std::string stableRuleId;

            bool operator<(const NativeSemanticIdentity& other) const
            {
                return stableRuleId < other.stableRuleId;
            }
        };

        struct NativeSemanticValue
        {
            EvidenceDomain domain = EvidenceDomain::Unknown;
            ObservationDisposition disposition =
                ObservationDisposition::Informational;
            std::string artifactFamily;
            bool contributedToVerdict = false;
            bool collectionLimitation = false;
            std::vector<std::string> limitations;

            bool operator<(const NativeSemanticValue& other) const
            {
                return std::tie(
                        domain,
                        disposition,
                        artifactFamily,
                        contributedToVerdict,
                        collectionLimitation,
                        limitations) <
                    std::tie(
                        other.domain,
                        other.disposition,
                        other.artifactFamily,
                        other.contributedToVerdict,
                        other.collectionLimitation,
                        other.limitations);
            }

            bool operator==(const NativeSemanticValue& other) const
            {
                return domain == other.domain &&
                    disposition == other.disposition &&
                    artifactFamily == other.artifactFamily &&
                    contributedToVerdict == other.contributedToVerdict &&
                    collectionLimitation == other.collectionLimitation &&
                    limitations == other.limitations;
            }
        };

        NativeSemanticIdentity NativeIdentity(
            const NativeSourceEvidenceRecord& record)
        {
            return { record.stableRuleId };
        }

        NativeSemanticValue NativeValue(
            const NativeSourceEvidenceRecord& record)
        {
            return {
                record.domain,
                record.disposition,
                record.artifactFamily,
                record.contributedToVerdict,
                record.collectionLimitation,
                CanonicalTextItems(record.limitations)
            };
        }

        NativeSourceEvidenceRecord CanonicalNativeRecord(
            const NativeSourceEvidenceRecord& record)
        {
            NativeSourceEvidenceRecord canonical = record;
            canonical.details = CanonicalTextItems(canonical.details);
            canonical.limitations = CanonicalTextItems(canonical.limitations);
            return canonical;
        }

        bool NativeRecordLess(
            const NativeSourceEvidenceRecord& left,
            const NativeSourceEvidenceRecord& right)
        {
            const NativeSemanticIdentity leftIdentity = NativeIdentity(left);
            const NativeSemanticIdentity rightIdentity = NativeIdentity(right);
            if (leftIdentity < rightIdentity)
            {
                return true;
            }
            if (rightIdentity < leftIdentity)
            {
                return false;
            }

            const NativeSemanticValue leftValue = NativeValue(left);
            const NativeSemanticValue rightValue = NativeValue(right);
            if (leftValue < rightValue)
            {
                return true;
            }
            if (rightValue < leftValue)
            {
                return false;
            }

            // Presentation-only fields never decide semantic equality. They
            // are deterministic tie-breakers only when a representative must
            // be retained for a report row.
            return std::tie(
                    left.title,
                    left.summary,
                    left.strength,
                    left.confidence,
                    left.provenanceSummary,
                    left.suppressedDuplicate,
                    left.details) <
                std::tie(
                    right.title,
                    right.summary,
                    right.strength,
                    right.confidence,
                    right.provenanceSummary,
                    right.suppressedDuplicate,
                    right.details);
        }

        bool NativeContractRecordLess(
            const NativeSourceEvidenceRecord& left,
            const NativeSourceEvidenceRecord& right)
        {
            return std::tie(
                    left.domain,
                    left.disposition,
                    left.stableRuleId,
                    left.artifactFamily,
                    left.title,
                    left.summary,
                    left.provenanceSummary,
                    left.contributedToVerdict,
                    left.suppressedDuplicate,
                    left.collectionLimitation,
                    left.strength,
                    left.confidence,
                    left.details,
                    left.limitations) <
                std::tie(
                    right.domain,
                    right.disposition,
                    right.stableRuleId,
                    right.artifactFamily,
                    right.title,
                    right.summary,
                    right.provenanceSummary,
                    right.contributedToVerdict,
                    right.suppressedDuplicate,
                    right.collectionLimitation,
                    right.strength,
                    right.confidence,
                    right.details,
                    right.limitations);
        }

        bool SameSnapshotProcessKey(
            const SnapshotProcessKey& left,
            const SnapshotProcessKey& right)
        {
            return left.pid == right.pid &&
                left.hasCreationTime == right.hasCreationTime &&
                (!left.hasCreationTime ||
                    left.creationTimeFileTime == right.creationTimeFileTime);
        }

        void AddChangedField(
            std::vector<SnapshotChangedField>& fields,
            const std::wstring& field,
            const std::wstring& baselineValue,
            const std::wstring& currentValue)
        {
            if (baselineValue != currentValue)
            {
                fields.push_back({ field, baselineValue, currentValue });
            }
        }

        void AddChangedField(
            SnapshotProcessChange& change,
            const std::wstring& field,
            const std::wstring& baselineValue,
            const std::wstring& currentValue)
        {
            if (baselineValue != currentValue)
            {
                AddChangedField(
                    change.fields,
                    field,
                    baselineValue,
                    currentValue);
            }
        }

        void AddChangedDomainField(
            SnapshotProcessChange& change,
            const std::wstring& field,
            const std::vector<EvidenceDomain>& baseline,
            const std::vector<EvidenceDomain>& current)
        {
            if (baseline != current)
            {
                change.fields.push_back({
                    field,
                    PersistedTriageDomainsText(baseline),
                    PersistedTriageDomainsText(current)
                });
            }
        }

        void AddChangedTriageLinesField(
            SnapshotProcessChange& change,
            const std::wstring& field,
            const std::vector<std::string>& baseline,
            const std::vector<std::string>& current)
        {
            const std::vector<std::string> canonicalBaseline =
                CanonicalPersistedTriageLines(baseline);
            const std::vector<std::string> canonicalCurrent =
                CanonicalPersistedTriageLines(current);
            if (canonicalBaseline != canonicalCurrent)
            {
                change.fields.push_back({
                    field,
                    PersistedTriageLinesText(canonicalBaseline),
                    PersistedTriageLinesText(canonicalCurrent)
                });
            }
        }

        void AddPersistedTriageChangedFields(
            SnapshotProcessChange& change,
            const PersistedTriageSummary& baseline,
            const PersistedTriageSummary& current)
        {
            AddChangedField(
                change,
                L"Authoritative triage capture",
                baseline.captured ? L"Captured" : L"Not captured",
                current.captured ? L"Captured" : L"Not captured");
            if (!baseline.captured || !current.captured)
            {
                return;
            }

            AddChangedField(
                change,
                L"Authoritative triage verdict",
                PersistedTriageVerdictText(baseline.authoritativeVerdict),
                PersistedTriageVerdictText(current.authoritativeVerdict));
            AddChangedField(
                change,
                L"Triage analysis level",
                PersistedTriageAnalysisLevelText(baseline.analysisLevel),
                PersistedTriageAnalysisLevelText(current.analysisLevel));
            AddChangedField(
                change,
                L"Triage evaluation succeeded",
                BoolText(baseline.evaluationSucceeded),
                BoolText(current.evaluationSucceeded));
            AddChangedField(
                change,
                L"Triage baseline verdict",
                PersistedTriageBaselineVerdictText(baseline),
                PersistedTriageBaselineVerdictText(current));
            AddChangedField(
                change,
                L"Enriched evidence changed verdict",
                BoolText(baseline.enrichedChangedVerdict),
                BoolText(current.enrichedChangedVerdict));
            AddChangedField(
                change,
                L"Triage fallback",
                BoolText(baseline.usingFallback),
                BoolText(current.usingFallback));
            AddChangedField(
                change,
                L"Triage fallback reason",
                ValueOr(Utf8ToWide(baseline.fallbackReason), L"None"),
                ValueOr(Utf8ToWide(current.fallbackReason), L"None"));
            AddChangedDomainField(
                change,
                L"Triage contributing domains",
                baseline.contributingDomains,
                current.contributingDomains);
            AddChangedTriageLinesField(
                change,
                L"Triage verdict basis",
                baseline.verdictBasis,
                current.verdictBasis);
            AddChangedTriageLinesField(
                change,
                L"Triage completed correlations",
                baseline.completedCorrelations,
                current.completedCorrelations);
            AddChangedTriageLinesField(
                change,
                L"Triage supporting context",
                baseline.supportingContext,
                current.supportingContext);
            AddChangedTriageLinesField(
                change,
                L"Triage collection limitations",
                baseline.collectionLimitations,
                current.collectionLimitations);
            AddChangedTriageLinesField(
                change,
                L"Triage evidence-integrity context",
                baseline.evidenceIntegrityContext,
                current.evidenceIntegrityContext);
            AddChangedTriageLinesField(
                change,
                L"Triage unresolved correlations",
                baseline.unresolvedCorrelations,
                current.unresolvedCorrelations);
            AddChangedField(
                change,
                L"Triage source-evidence count",
                std::to_wstring(baseline.sourceEvidenceCount),
                std::to_wstring(current.sourceEvidenceCount));
            AddChangedField(
                change,
                L"Triage model version",
                std::to_wstring(baseline.triageModelVersion),
                std::to_wstring(current.triageModelVersion));
            AddChangedField(
                change,
                L"Triage status",
                ValueOr(Utf8ToWide(baseline.status), L"None"),
                ValueOr(Utf8ToWide(current.status), L"None"));
        }

        void AddNativeEvidenceChangedFields(
            SnapshotNativeSourceEvidenceChange& change)
        {
            AddChangedField(
                change.fields,
                L"Evidence domain",
                Utf8ToWide(EvidenceDomainDisplayText(
                    change.baseline.domain)),
                Utf8ToWide(EvidenceDomainDisplayText(
                    change.current.domain)));
            AddChangedField(
                change.fields,
                L"Disposition",
                Utf8ToWide(ObservationDispositionDisplayText(
                    change.baseline.disposition)),
                Utf8ToWide(ObservationDispositionDisplayText(
                    change.current.disposition)));
            AddChangedField(
                change.fields,
                L"Artifact family",
                ValueOr(
                    Utf8ToWide(change.baseline.artifactFamily),
                    L"None"),
                ValueOr(
                    Utf8ToWide(change.current.artifactFamily),
                    L"None"));
            AddChangedField(
                change.fields,
                L"Contributed to verdict",
                BoolText(change.baseline.contributedToVerdict),
                BoolText(change.current.contributedToVerdict));
            AddChangedField(
                change.fields,
                L"Collection limitation",
                BoolText(change.baseline.collectionLimitation),
                BoolText(change.current.collectionLimitation));

            const std::vector<std::string> baselineLimitations =
                CanonicalTextItems(change.baseline.limitations);
            const std::vector<std::string> currentLimitations =
                CanonicalTextItems(change.current.limitations);
            if (baselineLimitations != currentLimitations)
            {
                change.fields.push_back({
                    L"Limitations",
                    NativeTextItemsText(baselineLimitations),
                    NativeTextItemsText(currentLimitations)
                });
            }
        }

        std::vector<NativeSourceEvidenceRecord> CanonicalNativeRecords(
            const std::vector<NativeSourceEvidenceRecord>& records)
        {
            std::vector<NativeSourceEvidenceRecord> canonical;
            canonical.reserve(records.size());
            for (const NativeSourceEvidenceRecord& record : records)
            {
                canonical.push_back(CanonicalNativeRecord(record));
            }
            std::sort(
                canonical.begin(),
                canonical.end(),
                NativeContractRecordLess);
            return canonical;
        }

        void CompareNativeEvidenceRecords(
            const std::vector<NativeSourceEvidenceRecord>& baselineRecords,
            const std::vector<NativeSourceEvidenceRecord>& currentRecords,
            SnapshotSelectedNativeSourceEvidenceComparison& comparison)
        {
            using IdentityGroups = std::map<
                NativeSemanticIdentity,
                std::vector<NativeSourceEvidenceRecord>>;
            using ValueGroups = std::map<
                NativeSemanticValue,
                std::vector<NativeSourceEvidenceRecord>>;

            IdentityGroups baselineGroups;
            IdentityGroups currentGroups;
            for (const NativeSourceEvidenceRecord& record :
                 CanonicalNativeRecords(baselineRecords))
            {
                baselineGroups[NativeIdentity(record)].push_back(record);
            }
            for (const NativeSourceEvidenceRecord& record :
                 CanonicalNativeRecords(currentRecords))
            {
                currentGroups[NativeIdentity(record)].push_back(record);
            }

            std::map<NativeSemanticIdentity, bool> identities;
            for (const auto& entry : baselineGroups)
            {
                identities.emplace(entry.first, true);
            }
            for (const auto& entry : currentGroups)
            {
                identities.emplace(entry.first, true);
            }

            for (const auto& identityEntry : identities)
            {
                const NativeSemanticIdentity& identity = identityEntry.first;
                const auto baselineIt = baselineGroups.find(identity);
                const auto currentIt = currentGroups.find(identity);
                if (baselineIt == baselineGroups.end())
                {
                    comparison.newRecords.insert(
                        comparison.newRecords.end(),
                        currentIt->second.begin(),
                        currentIt->second.end());
                    continue;
                }
                if (currentIt == currentGroups.end())
                {
                    comparison.removedRecords.insert(
                        comparison.removedRecords.end(),
                        baselineIt->second.begin(),
                        baselineIt->second.end());
                    continue;
                }

                ValueGroups baselineValues;
                ValueGroups currentValues;
                for (const NativeSourceEvidenceRecord& record :
                     baselineIt->second)
                {
                    baselineValues[NativeValue(record)].push_back(record);
                }
                for (const NativeSourceEvidenceRecord& record :
                     currentIt->second)
                {
                    currentValues[NativeValue(record)].push_back(record);
                }

                std::vector<NativeSourceEvidenceRecord> baselineRemaining;
                std::vector<NativeSourceEvidenceRecord> currentRemaining;
                for (const auto& valueEntry : baselineValues)
                {
                    const auto currentValueIt =
                        currentValues.find(valueEntry.first);
                    const std::size_t matched =
                        currentValueIt == currentValues.end()
                            ? 0
                            : (std::min)(
                                valueEntry.second.size(),
                                currentValueIt->second.size());
                    baselineRemaining.insert(
                        baselineRemaining.end(),
                        valueEntry.second.begin() + matched,
                        valueEntry.second.end());
                    if (currentValueIt != currentValues.end())
                    {
                        currentRemaining.insert(
                            currentRemaining.end(),
                            currentValueIt->second.begin() + matched,
                            currentValueIt->second.end());
                    }
                }
                for (const auto& valueEntry : currentValues)
                {
                    if (baselineValues.find(valueEntry.first) ==
                        baselineValues.end())
                    {
                        currentRemaining.insert(
                            currentRemaining.end(),
                            valueEntry.second.begin(),
                            valueEntry.second.end());
                    }
                }

                std::sort(
                    baselineRemaining.begin(),
                    baselineRemaining.end(),
                    NativeRecordLess);
                std::sort(
                    currentRemaining.begin(),
                    currentRemaining.end(),
                    NativeRecordLess);
                const std::size_t changedCount = (std::min)(
                    baselineRemaining.size(),
                    currentRemaining.size());
                for (std::size_t index = 0; index < changedCount; ++index)
                {
                    SnapshotNativeSourceEvidenceChange change;
                    change.baseline = baselineRemaining[index];
                    change.current = currentRemaining[index];
                    AddNativeEvidenceChangedFields(change);
                    comparison.changedRecords.push_back(std::move(change));
                }
                comparison.removedRecords.insert(
                    comparison.removedRecords.end(),
                    baselineRemaining.begin() + changedCount,
                    baselineRemaining.end());
                comparison.newRecords.insert(
                    comparison.newRecords.end(),
                    currentRemaining.begin() + changedCount,
                    currentRemaining.end());
            }

            std::sort(
                comparison.newRecords.begin(),
                comparison.newRecords.end(),
                NativeRecordLess);
            std::sort(
                comparison.removedRecords.begin(),
                comparison.removedRecords.end(),
                NativeRecordLess);
            std::sort(
                comparison.changedRecords.begin(),
                comparison.changedRecords.end(),
                [](const SnapshotNativeSourceEvidenceChange& left,
                   const SnapshotNativeSourceEvidenceChange& right) {
                    if (NativeRecordLess(left.current, right.current))
                    {
                        return true;
                    }
                    if (NativeRecordLess(right.current, left.current))
                    {
                        return false;
                    }
                    return NativeRecordLess(left.baseline, right.baseline);
                });
        }

        void CompareSelectedNativeEvidence(
            const ProcessSnapshotCapture& baseline,
            const ProcessSnapshotCapture& current,
            SnapshotCompareResult& result)
        {
            result.selectedNativeEvidence.baseline =
                baseline.selectedNativeSourceEvidence;
            result.selectedNativeEvidence.current =
                current.selectedNativeSourceEvidence;
            if (result.selectedNativeEvidence.baseline.has_value() !=
                result.selectedNativeEvidence.current.has_value())
            {
                result.selectedNativeEvidence.availabilityMismatch = true;
                result.notes.push_back(
                    L"Selected native source evidence was captured on only one side and was not semantically compared.");
                return;
            }
            if (!result.selectedNativeEvidence.baseline.has_value())
            {
                return;
            }

            const SnapshotSelectedNativeSourceEvidenceRecord&
                baselineSelected =
                    *result.selectedNativeEvidence.baseline;
            const SnapshotSelectedNativeSourceEvidenceRecord&
                currentSelected =
                    *result.selectedNativeEvidence.current;
            result.selectedNativeEvidence.sameIdentity =
                SameSnapshotProcessKey(
                    baselineSelected.processKey,
                    currentSelected.processKey);
            if (!result.selectedNativeEvidence.sameIdentity)
            {
                result.notes.push_back(
                    L"Selected native source evidence belongs to different process identities and was not semantically compared.");
                return;
            }

            result.selectedNativeEvidence.safeIdentity =
                baselineSelected.processKey.hasCreationTime &&
                currentSelected.processKey.hasCreationTime;
            if (!result.selectedNativeEvidence.safeIdentity)
            {
                result.notes.push_back(
                    L"Selected native source evidence used a PID-only identity and was not semantically compared.");
                return;
            }

            result.selectedNativeEvidence.semanticCompared = true;
            result.nativeSourceEvidenceCompared = true;
            CompareNativeEvidenceRecords(
                baselineSelected.records,
                currentSelected.records,
                result.selectedNativeEvidence);
            const std::size_t changeCount =
                result.selectedNativeEvidence.newRecords.size() +
                result.selectedNativeEvidence.removedRecords.size() +
                result.selectedNativeEvidence.changedRecords.size();
            if (changeCount != 0)
            {
                result.notes.push_back(
                    L"Selected native source evidence changed semantically: " +
                    std::to_wstring(
                        result.selectedNativeEvidence.newRecords.size()) +
                    L" appeared, " +
                    std::to_wstring(
                        result.selectedNativeEvidence.removedRecords.size()) +
                    L" removed, and " +
                    std::to_wstring(
                        result.selectedNativeEvidence.changedRecords.size()) +
                    L" changed.");
            }
        }

        void SortProcessRecords(std::vector<SnapshotProcessRecord>& records)
        {
            std::sort(records.begin(), records.end(), [](const SnapshotProcessRecord& left, const SnapshotProcessRecord& right) {
                if (left.processName != right.processName)
                {
                    return left.processName < right.processName;
                }
                if (left.pid != right.pid)
                {
                    return left.pid < right.pid;
                }
                if (left.key.hasCreationTime != right.key.hasCreationTime)
                {
                    return left.key.hasCreationTime < right.key.hasCreationTime;
                }
                if (left.key.creationTimeFileTime != right.key.creationTimeFileTime)
                {
                    return left.key.creationTimeFileTime < right.key.creationTimeFileTime;
                }
                return left.executablePath < right.executablePath;
            });
        }

        void SortNetworkEndpoints(std::vector<SnapshotNetworkEndpoint>& endpoints)
        {
            std::sort(endpoints.begin(), endpoints.end(), [](const SnapshotNetworkEndpoint& left, const SnapshotNetworkEndpoint& right) {
                if (left.processName != right.processName)
                {
                    return left.processName < right.processName;
                }
                if (left.owningPid != right.owningPid)
                {
                    return left.owningPid < right.owningPid;
                }
                return NetworkMapKey(left) < NetworkMapKey(right);
            });
        }

        void SortFindings(std::vector<SnapshotFindingRecord>& findings)
        {
            std::sort(findings.begin(), findings.end(), [](const SnapshotFindingRecord& left, const SnapshotFindingRecord& right) {
                const int leftRank = left.severityCaptured
                    ? FindingSeverityRank(left.severity)
                    : 0;
                const int rightRank = right.severityCaptured
                    ? FindingSeverityRank(right.severity)
                    : 0;
                if (leftRank != rightRank)
                {
                    return leftRank > rightRank;
                }
                if (left.processName != right.processName)
                {
                    return left.processName < right.processName;
                }
                if (left.title != right.title)
                {
                    return left.title < right.title;
                }
                const std::wstring leftProcessKey =
                    SnapshotProcessKeyToString(left.processKey);
                const std::wstring rightProcessKey =
                    SnapshotProcessKeyToString(right.processKey);
                if (leftProcessKey != rightProcessKey)
                {
                    return leftProcessKey < rightProcessKey;
                }
                if (left.category != right.category)
                {
                    return left.category < right.category;
                }
                return left.evidenceSummary < right.evidenceSummary;
            });
        }

        void AddProcessFindingRecords(
            const ProcessInfo& process,
            std::vector<SnapshotFindingRecord>& findings)
        {
            const FindingSeverity processFindingSeverity = FindingSeverityFromProcessSeverity(process.severity);
            if (process.historicalSeverityCaptured &&
                SeverityRank(process.severity) >= SeverityRank(Severity::Low))
            {
                findings.push_back({
                    { process.pid, process.hasCreationTime, process.creationTimeFileTime },
                    process.pid,
                    process.name,
                    processFindingSeverity,
                    L"Historical legacy source severity: " + std::wstring(SeverityToString(process.severity)),
                    L"Historical Process",
                    L"Historical legacy source severity was " + std::wstring(SeverityToString(process.severity)),
                    true
                });
            }

            for (const std::wstring& indicator : process.indicators)
            {
                findings.push_back({
                    { process.pid, process.hasCreationTime, process.creationTimeFileTime },
                    process.pid,
                    process.name,
                    processFindingSeverity,
                    indicator,
                    L"Indicator",
                    indicator,
                    false
                });
            }

            for (const std::wstring& note : process.contextNotes)
            {
                findings.push_back({
                    { process.pid, process.hasCreationTime, process.creationTimeFileTime },
                    process.pid,
                    process.name,
                    FindingSeverity::Info,
                    note,
                    L"Context",
                    note,
                    false
                });
            }
        }
    }

    const wchar_t* SnapshotSourceEvidenceModelKindDisplayText(
        SnapshotSourceEvidenceModelKind kind)
    {
        switch (kind)
        {
        case SnapshotSourceEvidenceModelKind::Native:
            return L"Native";
        case SnapshotSourceEvidenceModelKind::HistoricalLegacy:
            return L"Historical legacy";
        case SnapshotSourceEvidenceModelKind::Unavailable:
        default:
            return L"Unavailable";
        }
    }

    std::wstring SnapshotProcessKeyToString(const SnapshotProcessKey& key)
    {
        std::wstringstream stream;
        stream << key.pid;
        if (key.hasCreationTime)
        {
            stream << L"|" << key.creationTimeFileTime;
        }
        else
        {
            stream << L"|pid-only";
        }
        return stream.str();
    }

    ProcessSnapshotCapture CaptureProcessSnapshotForCompare(
        const ProcessSnapshot& snapshot,
        const NetworkCollectionResult* networkSnapshot,
        bool includeNetwork,
        const std::wstring& captureTimeLocal,
        const PersistedTriageContext* triageContext,
        const SnapshotSourceEvidenceCaptureContext* sourceEvidenceContext)
    {
        ProcessSnapshotCapture capture;
        capture.captured = true;
        capture.captureTimeLocal = captureTimeLocal;
        capture.processes.reserve(snapshot.processes.size());
        std::size_t selectedIdentityMatchCount = 0;

        capture.sourceEvidenceModelKind = sourceEvidenceContext == nullptr
            ? SnapshotSourceEvidenceModelKind::HistoricalLegacy
            : sourceEvidenceContext->modelKind;
        if (capture.sourceEvidenceModelKind ==
            SnapshotSourceEvidenceModelKind::Native)
        {
            capture.nativeSourceEvidenceCaptured = true;
            capture.nativeSourceEvidenceModelVersion =
                sourceEvidenceContext == nullptr
                    ? NativeSourceEvidenceModelVersion
                    : sourceEvidenceContext->nativeModelVersion;
        }

        capture.triageContextCaptured = triageContext != nullptr;
        if (triageContext == nullptr)
        {
            capture.triageStatusMessage =
                L"Authoritative triage was not captured.";
        }
        else
        {
            const PersistedTriageValidationResult validation =
                ValidatePersistedTriageContext(*triageContext);
            capture.triageContextValid = validation.valid;
            if (!validation.valid)
            {
                capture.triageStatusMessage =
                    L"Authoritative triage context was rejected: " +
                    Utf8ToWide(validation.message);
            }
        }

        for (const ProcessInfo& process : snapshot.processes)
        {
            SnapshotProcessRecord record;
            record.key = { process.pid, process.hasCreationTime, process.creationTimeFileTime };
            record.pid = process.pid;
            record.parentPid = process.parentPid;
            record.processName = process.name;
            record.executablePath = process.executablePath;
            record.commandLine = process.commandLine;
            record.architecture = process.architecture;
            record.creationTimeLocal = process.creationTimeLocal;
            if (capture.sourceEvidenceModelKind ==
                SnapshotSourceEvidenceModelKind::HistoricalLegacy)
            {
                record.suspicious = process.suspicious;
                record.severity = process.severity;
                record.historicalSuspiciousCaptured =
                    process.historicalSuspiciousCaptured;
                record.historicalSeverityCaptured =
                    process.historicalSeverityCaptured;
                record.indicators = process.indicators;
                record.contextNotes = process.contextNotes;
            }
            record.authoritativeTriage =
                MakeNotCapturedPersistedTriageSummary();
            if (capture.triageContextValid)
            {
                const ProcessIdentityKey identity{
                    process.pid,
                    process.hasCreationTime,
                    process.creationTimeFileTime
                };
                const PersistedProcessTriageRecord* persisted =
                    triageContext->FindProcess(identity);
                if (persisted != nullptr)
                {
                    record.authoritativeTriage = persisted->summary;
                }
                if (triageContext->selectedRecord.has_value() &&
                    triageContext->selectedRecord->identity == identity)
                {
                    ++selectedIdentityMatchCount;
                }
            }
            if (record.authoritativeTriage.captured)
            {
                ++capture.triageCapturedProcessCount;
            }
            else
            {
                ++capture.triageNotCapturedProcessCount;
            }
            if (process.sessionId.has_value())
            {
                record.hasSessionId = true;
                record.sessionId = process.sessionId.value();
            }

            const auto parentIt = snapshot.indexByPid.find(process.parentPid);
            if (parentIt != snapshot.indexByPid.end())
            {
                const ProcessInfo& parent = snapshot.processes[parentIt->second];
                record.parentHasCreationTime = parent.hasCreationTime;
                record.parentCreationTimeFileTime = parent.creationTimeFileTime;
            }

            if (!process.hasCreationTime)
            {
                capture.usedPidOnlyFallback = true;
            }

            capture.processes.push_back(std::move(record));
            if (capture.sourceEvidenceModelKind ==
                SnapshotSourceEvidenceModelKind::HistoricalLegacy)
            {
                AddProcessFindingRecords(process, capture.findings);
            }
        }
        capture.findingsCaptured =
            capture.sourceEvidenceModelKind ==
                SnapshotSourceEvidenceModelKind::HistoricalLegacy;
        if (capture.findingsCaptured)
        {
            capture.sourceEvidenceStatusMessage =
                L"Historical legacy source-finding summaries captured.";
        }
        else if (capture.sourceEvidenceModelKind ==
            SnapshotSourceEvidenceModelKind::Native)
        {
            capture.sourceEvidenceStatusMessage =
                L"Native source-evidence model captured; no selected-process evidence record was available.";
            if (sourceEvidenceContext != nullptr &&
                sourceEvidenceContext->selectedNativeEvidence.has_value())
            {
                SnapshotSelectedNativeSourceEvidenceRecord selected =
                    *sourceEvidenceContext->selectedNativeEvidence;
                bool valid = selected.pid == selected.processKey.pid &&
                    selected.records.size() <= NativeSourceEvidenceMaxRecords;
                std::wstring diagnostic;
                if (!valid)
                {
                    diagnostic =
                        L"Selected native source evidence had an invalid identity or exceeded its record cap.";
                }
                for (std::size_t index = 0;
                    valid && index < selected.records.size();
                    ++index)
                {
                    const NativeSourceEvidenceValidationResult validation =
                        ValidateNativeSourceEvidenceRecord(
                            selected.records[index]);
                    if (!validation)
                    {
                        valid = false;
                        diagnostic =
                            L"Selected native source evidence record " +
                            std::to_wstring(index) + L" was rejected: " +
                            Utf8ToWide(validation.diagnostic);
                    }
                }

                std::size_t identityMatches = 0;
                const SnapshotProcessRecord* matchedProcess = nullptr;
                for (const SnapshotProcessRecord& process : capture.processes)
                {
                    if (SameSnapshotProcessKey(
                            selected.processKey,
                            process.key))
                    {
                        ++identityMatches;
                        matchedProcess = &process;
                    }
                }
                if (identityMatches != 1)
                {
                    valid = false;
                    diagnostic =
                        L"Selected native source evidence did not match exactly one captured process identity.";
                }

                if (valid)
                {
                    selected.records =
                        CanonicalNativeRecords(selected.records);
                    if (selected.processName.empty() &&
                        matchedProcess != nullptr)
                    {
                        selected.processName = matchedProcess->processName;
                    }
                    capture.selectedNativeSourceEvidence =
                        std::move(selected);
                    capture.sourceEvidenceStatusMessage =
                        L"Selected native source evidence captured.";
                }
                else
                {
                    capture.sourceEvidenceStatusMessage =
                        std::move(diagnostic);
                }
            }
        }
        else
        {
            capture.sourceEvidenceStatusMessage =
                L"Source-evidence model was not captured.";
        }
        if (capture.triageContextValid &&
            triageContext->selectedRecord.has_value() &&
            selectedIdentityMatchCount == 1)
        {
            capture.selectedAuthoritativeTriage =
                triageContext->selectedRecord;
        }
        if (capture.triageContextValid)
        {
            capture.triageStatusMessage =
                L"Authoritative triage captured for " +
                std::to_wstring(capture.triageCapturedProcessCount) +
                L" process record(s); " +
                std::to_wstring(capture.triageNotCapturedProcessCount) +
                L" process record(s) were not captured.";
        }

        if (includeNetwork)
        {
            capture.networkCaptured = true;
            if (networkSnapshot != nullptr)
            {
                capture.networkAvailable = networkSnapshot->success;
                capture.networkStatusMessage = networkSnapshot->statusMessage;
                capture.networkConnections.reserve(networkSnapshot->connections.size());
                for (const NetworkConnection& connection : networkSnapshot->connections)
                {
                    SnapshotNetworkEndpoint endpoint;
                    endpoint.owningPid = connection.owningPid;
                    endpoint.processName = connection.processName;
                    endpoint.protocol = connection.protocol;
                    endpoint.localAddress = connection.localAddress;
                    endpoint.localPort = connection.localPort;
                    endpoint.remoteAddress = connection.remoteAddress;
                    endpoint.remotePort = connection.remotePort;
                    endpoint.state = connection.state;
                    endpoint.addressFamily = connection.addressFamily;
                    endpoint.isListening = connection.isListening;
                    endpoint.isLoopback = connection.isLoopback;
                    endpoint.isLan = connection.isLan;
                    endpoint.isPublicRemote = connection.isPublicRemote;

                    const auto processIt = snapshot.indexByPid.find(connection.owningPid);
                    if (processIt != snapshot.indexByPid.end())
                    {
                        const ProcessInfo& owner = snapshot.processes[processIt->second];
                        endpoint.owningProcessKey = { owner.pid, owner.hasCreationTime, owner.creationTimeFileTime };
                        if (endpoint.processName.empty())
                        {
                            endpoint.processName = owner.name;
                        }
                    }
                    else
                    {
                        endpoint.owningProcessKey = { connection.owningPid, false, 0 };
                    }

                    capture.networkConnections.push_back(std::move(endpoint));
                }
            }
            else
            {
                capture.networkStatusMessage = L"Network table was not loaded when this snapshot was captured.";
            }
        }

        return capture;
    }

    SnapshotCompareResult CompareSnapshots(
        const ProcessSnapshotCapture& baseline,
        const ProcessSnapshotCapture& current)
    {
        SnapshotCompareResult result;
        result.hasBaseline = baseline.captured;
        result.hasCurrent = current.captured;
        if (!baseline.captured || !current.captured)
        {
            return result;
        }

        result.baselineSourceEvidenceModelKind =
            baseline.sourceEvidenceModelKind;
        result.currentSourceEvidenceModelKind =
            current.sourceEvidenceModelKind;
        const bool historicalModelComparison =
            baseline.sourceEvidenceModelKind ==
                SnapshotSourceEvidenceModelKind::HistoricalLegacy &&
            current.sourceEvidenceModelKind ==
                SnapshotSourceEvidenceModelKind::HistoricalLegacy;

        result.processCompared = true;
        result.baselineTriageCapturedProcessCount =
            static_cast<std::size_t>(std::count_if(
                baseline.processes.begin(),
                baseline.processes.end(),
                [](const SnapshotProcessRecord& process) {
                    return process.authoritativeTriage.captured;
                }));
        result.currentTriageCapturedProcessCount =
            static_cast<std::size_t>(std::count_if(
                current.processes.begin(),
                current.processes.end(),
                [](const SnapshotProcessRecord& process) {
                    return process.authoritativeTriage.captured;
                }));
        if (baseline.usedPidOnlyFallback || current.usedPidOnlyFallback)
        {
            result.notes.push_back(L"Some processes lacked creation time metadata; PID-only matching was used for those records.");
        }

        std::unordered_map<std::wstring, std::size_t> baselineProcesses;
        std::unordered_map<std::wstring, std::size_t> currentProcesses;
        std::unordered_set<std::wstring> ambiguousBaselineProcesses;
        std::unordered_set<std::wstring> ambiguousCurrentProcesses;
        for (std::size_t index = 0; index < baseline.processes.size(); ++index)
        {
            const std::wstring key = ProcessMapKey(baseline.processes[index]);
            if (ambiguousBaselineProcesses.find(key) !=
                ambiguousBaselineProcesses.end())
            {
                continue;
            }
            const auto inserted = baselineProcesses.emplace(key, index);
            if (!inserted.second)
            {
                baselineProcesses.erase(key);
                ambiguousBaselineProcesses.insert(key);
            }
        }
        for (std::size_t index = 0; index < current.processes.size(); ++index)
        {
            const std::wstring key = ProcessMapKey(current.processes[index]);
            if (ambiguousCurrentProcesses.find(key) !=
                ambiguousCurrentProcesses.end())
            {
                continue;
            }
            const auto inserted = currentProcesses.emplace(key, index);
            if (!inserted.second)
            {
                currentProcesses.erase(key);
                ambiguousCurrentProcesses.insert(key);
            }
        }
        result.baselineAmbiguousProcessIdentityCount =
            ambiguousBaselineProcesses.size();
        result.currentAmbiguousProcessIdentityCount =
            ambiguousCurrentProcesses.size();
        if (!ambiguousBaselineProcesses.empty() ||
            !ambiguousCurrentProcesses.empty())
        {
            result.notes.push_back(
                L"Ambiguous duplicate process identities were excluded from deterministic process and triage comparison.");
        }

        for (const SnapshotProcessRecord& process : current.processes)
        {
            const std::wstring key = ProcessMapKey(process);
            if (ambiguousBaselineProcesses.find(key) !=
                    ambiguousBaselineProcesses.end() ||
                ambiguousCurrentProcesses.find(key) !=
                    ambiguousCurrentProcesses.end())
            {
                continue;
            }
            const auto baselineIt = baselineProcesses.find(key);
            if (baselineIt == baselineProcesses.end())
            {
                result.newProcesses.push_back(process);
                continue;
            }

            const SnapshotProcessRecord& baselineProcess = baseline.processes[baselineIt->second];
            SnapshotProcessChange change;
            change.baseline = baselineProcess;
            change.current = process;
            AddChangedField(change, L"Parent PID", std::to_wstring(baselineProcess.parentPid), std::to_wstring(process.parentPid));
            AddChangedField(change, L"Executable path", ValueOr(baselineProcess.executablePath, L"(empty)"), ValueOr(process.executablePath, L"(empty)"));
            AddChangedField(change, L"Command line", ValueOr(baselineProcess.commandLine, L"(empty)"), ValueOr(process.commandLine, L"(empty)"));
            if (historicalModelComparison)
            {
                AddChangedField(
                    change,
                    L"Historical legacy source severity",
                    baselineProcess.historicalSeverityCaptured
                        ? SeverityToString(baselineProcess.severity)
                        : L"Not captured",
                    process.historicalSeverityCaptured
                        ? SeverityToString(process.severity)
                        : L"Not captured");
            }
            AddChangedField(change, L"Session", SessionText(baselineProcess), SessionText(process));
            AddChangedField(change, L"Architecture", ValueOr(baselineProcess.architecture, L"(unknown)"), ValueOr(process.architecture, L"(unknown)"));
            const bool safeTriageIdentity =
                baselineProcess.key.hasCreationTime &&
                process.key.hasCreationTime;
            if (!safeTriageIdentity)
            {
                if (baselineProcess.authoritativeTriage.captured ||
                    process.authoritativeTriage.captured)
                {
                    ++result.triageIdentityUnavailableCount;
                }
            }
            else
            {
                if (baselineProcess.authoritativeTriage.captured &&
                    process.authoritativeTriage.captured)
                {
                    ++result.comparableTriageProcessCount;
                }
                else if (baselineProcess.authoritativeTriage.captured !=
                    process.authoritativeTriage.captured)
                {
                    ++result.triageAvailabilityMismatchCount;
                }
                AddPersistedTriageChangedFields(
                    change,
                    baselineProcess.authoritativeTriage,
                    process.authoritativeTriage);
            }

            if (!change.fields.empty())
            {
                result.changedProcesses.push_back(std::move(change));
            }
        }

        for (const SnapshotProcessRecord& process : baseline.processes)
        {
            const std::wstring key = ProcessMapKey(process);
            if (ambiguousBaselineProcesses.find(key) !=
                    ambiguousBaselineProcesses.end() ||
                ambiguousCurrentProcesses.find(key) !=
                    ambiguousCurrentProcesses.end())
            {
                continue;
            }
            if (currentProcesses.find(key) == currentProcesses.end())
            {
                result.exitedProcesses.push_back(process);
            }
        }

        SortProcessRecords(result.newProcesses);
        SortProcessRecords(result.exitedProcesses);
        std::sort(result.changedProcesses.begin(), result.changedProcesses.end(), [](const SnapshotProcessChange& left, const SnapshotProcessChange& right) {
            if (left.current.processName != right.current.processName)
            {
                return left.current.processName < right.current.processName;
            }
            if (left.current.pid != right.current.pid)
            {
                return left.current.pid < right.current.pid;
            }
            if (left.current.key.hasCreationTime != right.current.key.hasCreationTime)
            {
                return left.current.key.hasCreationTime < right.current.key.hasCreationTime;
            }
            if (left.current.key.creationTimeFileTime !=
                right.current.key.creationTimeFileTime)
            {
                return left.current.key.creationTimeFileTime <
                    right.current.key.creationTimeFileTime;
            }
            return left.current.executablePath < right.current.executablePath;
        });

        result.triageCompared =
            result.comparableTriageProcessCount != 0 ||
            result.triageAvailabilityMismatchCount != 0;
        if (!result.triageCompared)
        {
            result.notes.push_back(
                L"No safely identified process had comparable captured authoritative triage.");
        }
        else if (!baseline.triageContextValid || !current.triageContextValid)
        {
            result.notes.push_back(
                L"Authoritative triage comparison is partial because one or both captures lacked a valid semantic triage context.");
        }
        if (result.triageIdentityUnavailableCount != 0)
        {
            result.notes.push_back(
                L"Authoritative triage was not compared for PID-only process identities.");
        }

        result.selectedTriage.baseline =
            baseline.selectedAuthoritativeTriage;
        result.selectedTriage.current =
            current.selectedAuthoritativeTriage;
        if (result.selectedTriage.baseline.has_value() &&
            result.selectedTriage.current.has_value())
        {
            const PersistedProcessTriageRecord& baselineSelected =
                *result.selectedTriage.baseline;
            const PersistedProcessTriageRecord& currentSelected =
                *result.selectedTriage.current;
            result.selectedTriage.sameIdentity =
                baselineSelected.identity == currentSelected.identity;
            if (!result.selectedTriage.sameIdentity)
            {
                result.notes.push_back(
                    L"Selected-process triage was captured for different process identities and was not semantically compared.");
            }
            else
            {
                result.selectedTriage.safeIdentity =
                    baselineSelected.identity.hasCreationTime &&
                    currentSelected.identity.hasCreationTime;
                if (!result.selectedTriage.safeIdentity)
                {
                    result.notes.push_back(
                        L"Selected-process triage used a PID-only identity and was not semantically compared.");
                }
                else
                {
                    result.selectedTriage.availabilityMismatch =
                        baselineSelected.summary.captured !=
                        currentSelected.summary.captured;
                    result.selectedTriage.semanticCompared =
                        (baselineSelected.summary.captured &&
                            currentSelected.summary.captured) ||
                        result.selectedTriage.availabilityMismatch;
                    SnapshotProcessChange selectedChange;
                    AddPersistedTriageChangedFields(
                        selectedChange,
                        baselineSelected.summary,
                        currentSelected.summary);
                    result.selectedTriage.fields =
                        std::move(selectedChange.fields);
                }
            }
        }
        else if (result.selectedTriage.baseline.has_value() !=
            result.selectedTriage.current.has_value())
        {
            result.selectedTriage.availabilityMismatch = true;
            result.selectedTriage.fields.push_back({
                L"Selected authoritative triage record",
                result.selectedTriage.baseline.has_value()
                    ? L"Present"
                    : L"Not present",
                result.selectedTriage.current.has_value()
                    ? L"Present"
                    : L"Not present"
            });
        }

        if (baseline.networkCaptured && current.networkCaptured && baseline.networkAvailable && current.networkAvailable)
        {
            result.networkCompared = true;
            std::unordered_map<std::wstring, std::size_t> baselineConnections;
            std::unordered_map<std::wstring, std::size_t> currentConnections;
            for (std::size_t index = 0; index < baseline.networkConnections.size(); ++index)
            {
                baselineConnections[NetworkMapKey(baseline.networkConnections[index])] = index;
            }
            for (std::size_t index = 0; index < current.networkConnections.size(); ++index)
            {
                currentConnections[NetworkMapKey(current.networkConnections[index])] = index;
            }

            for (const SnapshotNetworkEndpoint& endpoint : current.networkConnections)
            {
                if (baselineConnections.find(NetworkMapKey(endpoint)) == baselineConnections.end())
                {
                    result.newNetworkConnections.push_back(endpoint);
                }
            }
            for (const SnapshotNetworkEndpoint& endpoint : baseline.networkConnections)
            {
                if (currentConnections.find(NetworkMapKey(endpoint)) == currentConnections.end())
                {
                    result.closedNetworkConnections.push_back(endpoint);
                }
            }

            SortNetworkEndpoints(result.newNetworkConnections);
            SortNetworkEndpoints(result.closedNetworkConnections);
        }
        else
        {
            result.notes.push_back(L"Network comparison unavailable because network data was not loaded or did not collect successfully for both snapshots.");
        }

        if (baseline.sourceEvidenceModelKind !=
            current.sourceEvidenceModelKind)
        {
            result.sourceEvidenceModelMismatch = true;
            result.notes.push_back(
                L"Source-evidence model mismatch: baseline uses " +
                std::wstring(SnapshotSourceEvidenceModelKindDisplayText(
                    baseline.sourceEvidenceModelKind)) +
                L" evidence and current uses " +
                std::wstring(SnapshotSourceEvidenceModelKindDisplayText(
                    current.sourceEvidenceModelKind)) +
                L" evidence. Native and historical records were not title-matched or semantically compared.");
        }
        else if (baseline.sourceEvidenceModelKind ==
            SnapshotSourceEvidenceModelKind::Native)
        {
            if (!baseline.nativeSourceEvidenceCaptured ||
                !current.nativeSourceEvidenceCaptured)
            {
                result.notes.push_back(
                    L"Native source-evidence comparison unavailable because the native model was not captured on both sides.");
            }
            else if (baseline.nativeSourceEvidenceModelVersion !=
                current.nativeSourceEvidenceModelVersion)
            {
                result.nativeSourceEvidenceModelVersionMismatch = true;
                result.notes.push_back(
                    L"Native source-evidence model version mismatch; selected evidence was not semantically compared.");
            }
            else
            {
                result.sourceEvidenceCompared = true;
                CompareSelectedNativeEvidence(
                    baseline,
                    current,
                    result);
            }
        }
        else if (baseline.sourceEvidenceModelKind ==
            SnapshotSourceEvidenceModelKind::Unavailable)
        {
            result.notes.push_back(
                L"Source-evidence comparison unavailable because no evidence model was captured.");
        }

        if (historicalModelComparison &&
            baseline.findingsCaptured && current.findingsCaptured)
        {
            result.findingsCompared = true;
            result.sourceEvidenceCompared = true;
            std::unordered_map<std::wstring, std::size_t> baselineFindings;
            std::unordered_map<std::wstring, std::size_t> currentFindings;
            std::unordered_set<std::wstring> ambiguousBaselineFindings;
            std::unordered_set<std::wstring> ambiguousCurrentFindings;
            for (std::size_t index = 0; index < baseline.findings.size(); ++index)
            {
                const std::wstring key =
                    FindingIdentityKey(baseline.findings[index]);
                if (ambiguousBaselineFindings.find(key) !=
                    ambiguousBaselineFindings.end())
                {
                    continue;
                }
                const auto inserted = baselineFindings.emplace(key, index);
                if (!inserted.second)
                {
                    baselineFindings.erase(key);
                    ambiguousBaselineFindings.insert(key);
                }
            }
            for (std::size_t index = 0; index < current.findings.size(); ++index)
            {
                const std::wstring key =
                    FindingIdentityKey(current.findings[index]);
                if (ambiguousCurrentFindings.find(key) !=
                    ambiguousCurrentFindings.end())
                {
                    continue;
                }
                const auto inserted = currentFindings.emplace(key, index);
                if (!inserted.second)
                {
                    currentFindings.erase(key);
                    ambiguousCurrentFindings.insert(key);
                }
            }

            std::unordered_set<std::wstring> ambiguousFindingKeys =
                ambiguousBaselineFindings;
            ambiguousFindingKeys.insert(
                ambiguousCurrentFindings.begin(),
                ambiguousCurrentFindings.end());
            result.ambiguousFindingIdentityCount =
                ambiguousFindingKeys.size();
            if (!ambiguousFindingKeys.empty())
            {
                result.notes.push_back(
                    L"Ambiguous duplicate historical finding identities were excluded from deterministic historical finding comparison.");
            }

            for (const SnapshotFindingRecord& finding : current.findings)
            {
                const std::wstring key = FindingIdentityKey(finding);
                if (ambiguousFindingKeys.find(key) !=
                    ambiguousFindingKeys.end())
                {
                    continue;
                }
                const auto baselineIt = baselineFindings.find(key);
                if (baselineIt == baselineFindings.end())
                {
                    result.newFindings.push_back(finding);
                    continue;
                }

                const SnapshotFindingRecord& baselineFinding = baseline.findings[baselineIt->second];
                if (FindingFullKey(baselineFinding) != FindingFullKey(finding))
                {
                    result.changedFindings.push_back({ baselineFinding, finding, L"Historical finding changed" });
                }
            }

            for (const SnapshotFindingRecord& finding : baseline.findings)
            {
                const std::wstring key = FindingIdentityKey(finding);
                if (ambiguousFindingKeys.find(key) !=
                    ambiguousFindingKeys.end())
                {
                    continue;
                }
                if (currentFindings.find(key) == currentFindings.end())
                {
                    result.removedFindings.push_back(finding);
                }
            }

            SortFindings(result.newFindings);
            SortFindings(result.removedFindings);
            std::sort(result.changedFindings.begin(), result.changedFindings.end(), [](const SnapshotFindingChange& left, const SnapshotFindingChange& right) {
                const int leftRank = left.current.severityCaptured
                    ? FindingSeverityRank(left.current.severity)
                    : 0;
                const int rightRank = right.current.severityCaptured
                    ? FindingSeverityRank(right.current.severity)
                    : 0;
                if (leftRank != rightRank)
                {
                    return leftRank > rightRank;
                }
                if (left.current.title != right.current.title)
                {
                    return left.current.title < right.current.title;
                }
                const std::wstring leftProcessKey =
                    SnapshotProcessKeyToString(left.current.processKey);
                const std::wstring rightProcessKey =
                    SnapshotProcessKeyToString(right.current.processKey);
                if (leftProcessKey != rightProcessKey)
                {
                    return leftProcessKey < rightProcessKey;
                }
                if (left.current.category != right.current.category)
                {
                    return left.current.category < right.current.category;
                }
                if (left.current.evidenceSummary !=
                    right.current.evidenceSummary)
                {
                    return left.current.evidenceSummary <
                        right.current.evidenceSummary;
                }
                return left.changeType < right.changeType;
            });
        }
        else if (historicalModelComparison)
        {
            result.notes.push_back(L"Historical finding comparison unavailable because historical finding summaries were not captured for both snapshots.");
        }

        return result;
    }
}
