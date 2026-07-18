#include "Core/ChainAnalysis.h"
#include "Core/ProcessTree.h"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

namespace GlassPane::Tests
{
    namespace
    {
        using namespace GlassPane::Core;

        int failureCount = 0;

        void Check(bool condition, const wchar_t* testName)
        {
            if (!condition)
            {
                std::wcerr << L"FAILED: " << testName << L'\n';
                ++failureCount;
            }
        }

        template <typename Value>
        void CheckEqual(
            const Value& actual,
            const Value& expected,
            const wchar_t* testName)
        {
            Check(actual == expected, testName);
        }

        ProcessSnapshot MakeChainSnapshot(
            const std::wstring& parentName,
            const std::wstring& childName,
            const std::wstring& childCommandLine,
            bool commandLineAccessible = true)
        {
            ProcessSnapshot snapshot;

            ProcessInfo parent;
            parent.pid = 5100;
            parent.name = parentName;
            parent.executablePath =
                L"C:\\Program Files\\Generic Fixture\\parent.bin";
            parent.commandLine = L"parent.bin --ordinary";
            parent.commandLineAccessible = true;
            parent.hasCreationTime = true;
            parent.creationTimeFileTime = 51000;
            snapshot.processes.push_back(std::move(parent));

            ProcessInfo child;
            child.pid = 5200;
            child.parentPid = 5100;
            child.name = childName;
            child.executablePath =
                L"C:\\Program Files\\Generic Fixture\\child.bin";
            child.commandLine = childCommandLine;
            child.commandLineAccessible = commandLineAccessible;
            child.hasCreationTime = true;
            child.creationTimeFileTime = 52000;
            snapshot.processes.push_back(std::move(child));

            BuildProcessTree(snapshot);
            return snapshot;
        }

        std::size_t CountChainFacts(
            const ChainAnalysisResult& analysis,
            ChainIndicatorFactKind kind)
        {
            return static_cast<std::size_t>(std::count_if(
                analysis.chainIndicatorFacts.begin(),
                analysis.chainIndicatorFacts.end(),
                [kind](const ChainIndicatorFact& fact)
                {
                    return fact.kind == kind;
                }));
        }

        void CheckEquivalentFactSemantics(
            const ChainAnalysisResult& left,
            const ChainAnalysisResult& right,
            const wchar_t* testName)
        {
            if (left.chainIndicatorFacts.size() !=
                right.chainIndicatorFacts.size())
            {
                Check(false, testName);
                return;
            }

            for (std::size_t index = 0;
                index < left.chainIndicatorFacts.size();
                ++index)
            {
                const ChainIndicatorFact& leftFact =
                    left.chainIndicatorFacts[index];
                const ChainIndicatorFact& rightFact =
                    right.chainIndicatorFacts[index];
                if (leftFact.kind != rightFact.kind ||
                    leftFact.sourceRuleId != rightFact.sourceRuleId ||
                    leftFact.sourcePid != rightFact.sourcePid ||
                    leftFact.targetPid != rightFact.targetPid ||
                    leftFact.normalizedValue != rightFact.normalizedValue)
                {
                    Check(false, testName);
                    return;
                }
            }
            Check(true, testName);
        }

        void TestChainAnalysisRequiresExactFullTokens()
        {
            const std::vector<std::wstring> accepted = {
                L"child.bin -EncodedCommand payload",
                L"child.bin /encodedcommand payload",
                L"child.bin \"--ENCODED-COMMAND\" payload"
            };
            for (const std::wstring& commandLine : accepted)
            {
                const ProcessSnapshot snapshot = MakeChainSnapshot(
                    L"generic-parent-a.bin",
                    L"generic-child-a.bin",
                    commandLine);
                const ChainAnalysisResult analysis =
                    AnalyzeChain(snapshot, 5200);
                CheckEqual(
                    CountChainFacts(
                        analysis,
                        ChainIndicatorFactKind::EncodedCommand),
                    std::size_t(1),
                    L"AnalyzeChain accepts one exact encoded-command fact");
                CheckEqual(
                    CountChainFacts(
                        analysis,
                        ChainIndicatorFactKind::ProcessRelationship),
                    std::size_t(1),
                    L"AnalyzeChain pairs exact command evidence with one verified parent edge");
            }

            const std::vector<std::wstring> rejected = {
                L"child.bin -enc payload",
                L"child.bin text-encodedcommand payload",
                L"child.bin --encoded-command-extra payload",
                L"child.bin key=/encodedcommand payload",
                L"child.bin prefix--encoded-command payload"
            };
            for (const std::wstring& commandLine : rejected)
            {
                const ProcessSnapshot snapshot = MakeChainSnapshot(
                    L"generic-parent-a.bin",
                    L"generic-child-a.bin",
                    commandLine);
                const ChainAnalysisResult analysis =
                    AnalyzeChain(snapshot, 5200);
                Check(
                    analysis.chainIndicatorFacts.empty(),
                    L"AnalyzeChain rejects short or embedded encoded-command text");
            }
        }

        void TestChainAnalysisIsNameIndependent()
        {
            const std::wstring commandLine =
                L"child.bin --encoded-command payload";
            const ProcessSnapshot firstSnapshot = MakeChainSnapshot(
                L"generic-parent-a.bin",
                L"generic-child-a.bin",
                commandLine);
            const ProcessSnapshot renamedSnapshot = MakeChainSnapshot(
                L"renamed-parent-family.bin",
                L"renamed-child-family.bin",
                commandLine);
            const ChainAnalysisResult first =
                AnalyzeChain(firstSnapshot, 5200);
            const ChainAnalysisResult renamed =
                AnalyzeChain(renamedSnapshot, 5200);

            CheckEquivalentFactSemantics(
                first,
                renamed,
                L"AnalyzeChain typed semantics are independent of process names");
            const ProcessSnapshot noCommandSnapshot = MakeChainSnapshot(
                L"generic-parent-a.bin",
                L"generic-child-a.bin",
                L"child.bin --ordinary");
            const ChainAnalysisResult noCommand =
                AnalyzeChain(noCommandSnapshot, 5200);
            Check(
                noCommand.chainIndicatorFacts.empty(),
                L"a process relationship without typed command evidence remains neutral");
        }

    }

    int RunChainAnalysisTests()
    {
        failureCount = 0;
        TestChainAnalysisRequiresExactFullTokens();
        TestChainAnalysisIsNameIndependent();
        return failureCount;
    }
}
