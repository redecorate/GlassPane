#include "Observation.h"

#include <iomanip>
#include <sstream>

namespace GlassPane::Core
{
    namespace
    {
        std::string UnknownEnumDisplayText(std::uint32_t value)
        {
            std::ostringstream stream;
            stream << "Unknown (0x"
                   << std::uppercase
                   << std::hex
                   << std::setw(8)
                   << std::setfill('0')
                   << value
                   << ')';
            return stream.str();
        }
    }

    std::string EvidenceDomainDisplayText(EvidenceDomain domain)
    {
        switch (domain)
        {
        case EvidenceDomain::Unknown:
            return "Unknown";
        case EvidenceDomain::ProcessIdentity:
            return "Process identity";
        case EvidenceDomain::FilePath:
            return "File path";
        case EvidenceDomain::FileSignature:
            return "File signature";
        case EvidenceDomain::CommandLine:
            return "Command line";
        case EvidenceDomain::ProcessRelationship:
            return "Process relationship";
        case EvidenceDomain::Network:
            return "Network";
        case EvidenceDomain::Service:
            return "Service";
        case EvidenceDomain::Module:
            return "Module";
        case EvidenceDomain::Handle:
            return "Handle";
        case EvidenceDomain::Runtime:
            return "Runtime";
        case EvidenceDomain::MemoryMetadata:
            return "Memory metadata";
        case EvidenceDomain::Token:
            return "Token";
        case EvidenceDomain::Persistence:
            return "Persistence";
        case EvidenceDomain::CollectionQuality:
            return "Collection quality";
        case EvidenceDomain::EvidenceIntegrity:
            return "Evidence integrity";
        case EvidenceDomain::ImportedEvidence:
            return "Imported evidence";
        default:
            return UnknownEnumDisplayText(static_cast<std::uint32_t>(domain));
        }
    }

    std::string ObservationSourceKindDisplayText(ObservationSourceKind sourceKind)
    {
        switch (sourceKind)
        {
        case ObservationSourceKind::Direct:
            return "Direct";
        case ObservationSourceKind::Corroborated:
            return "Corroborated";
        case ObservationSourceKind::Derived:
            return "Derived";
        case ObservationSourceKind::Imported:
            return "Imported";
        case ObservationSourceKind::UserDefined:
            return "User defined";
        case ObservationSourceKind::Unverified:
            return "Unverified";
        case ObservationSourceKind::Unavailable:
            return "Unavailable";
        default:
            return UnknownEnumDisplayText(static_cast<std::uint32_t>(sourceKind));
        }
    }

    std::string ObservationDispositionDisplayText(ObservationDisposition disposition)
    {
        switch (disposition)
        {
        case ObservationDisposition::Informational:
            return "Informational";
        case ObservationDisposition::Context:
            return "Context";
        case ObservationDisposition::ReviewRelevant:
            return "Review relevant";
        case ObservationDisposition::CorrelatedOnly:
            return "Correlated only";
        case ObservationDisposition::CollectionNote:
            return "Collection note";
        case ObservationDisposition::EvidenceIntegrityNote:
            return "Evidence integrity note";
        case ObservationDisposition::SuppressedExpected:
            return "Suppressed expected";
        default:
            return UnknownEnumDisplayText(static_cast<std::uint32_t>(disposition));
        }
    }

    std::string ObservationStrengthDisplayText(ObservationStrength strength)
    {
        switch (strength)
        {
        case ObservationStrength::None:
            return "None";
        case ObservationStrength::Weak:
            return "Weak";
        case ObservationStrength::Moderate:
            return "Moderate";
        case ObservationStrength::Strong:
            return "Strong";
        default:
            return UnknownEnumDisplayText(static_cast<std::uint32_t>(strength));
        }
    }

    std::string ObservationConfidenceDisplayText(ObservationConfidence confidence)
    {
        switch (confidence)
        {
        case ObservationConfidence::Unknown:
            return "Unknown";
        case ObservationConfidence::Low:
            return "Low";
        case ObservationConfidence::Medium:
            return "Medium";
        case ObservationConfidence::High:
            return "High";
        default:
            return UnknownEnumDisplayText(static_cast<std::uint32_t>(confidence));
        }
    }

    std::string ObservationArtifactKindDisplayText(ObservationArtifactKind kind)
    {
        switch (kind)
        {
        case ObservationArtifactKind::None:
            return "None";
        case ObservationArtifactKind::Process:
            return "Process";
        case ObservationArtifactKind::File:
            return "File";
        case ObservationArtifactKind::MemoryRegion:
            return "Memory region";
        case ObservationArtifactKind::NetworkConnection:
            return "Network connection";
        case ObservationArtifactKind::Service:
            return "Service";
        case ObservationArtifactKind::Handle:
            return "Handle";
        case ObservationArtifactKind::Module:
            return "Module";
        case ObservationArtifactKind::Token:
            return "Token";
        case ObservationArtifactKind::RuntimeObject:
            return "Runtime object";
        default:
            return UnknownEnumDisplayText(static_cast<std::uint32_t>(kind));
        }
    }

    std::string EvidenceDomainToString(EvidenceDomain domain)
    {
        return EvidenceDomainDisplayText(domain);
    }

    std::string ObservationSourceKindToString(ObservationSourceKind sourceKind)
    {
        return ObservationSourceKindDisplayText(sourceKind);
    }

    std::string ObservationDispositionToString(ObservationDisposition disposition)
    {
        return ObservationDispositionDisplayText(disposition);
    }

    std::string ObservationStrengthToString(ObservationStrength strength)
    {
        return ObservationStrengthDisplayText(strength);
    }

    std::string ObservationConfidenceToString(ObservationConfidence confidence)
    {
        return ObservationConfidenceDisplayText(confidence);
    }

    std::string ObservationArtifactKindToString(ObservationArtifactKind kind)
    {
        return ObservationArtifactKindDisplayText(kind);
    }

    bool HasCompleteObservationArtifactIdentity(
        const ObservationArtifactIdentity& identity)
    {
        switch (identity.kind)
        {
        case ObservationArtifactKind::Process:
        case ObservationArtifactKind::File:
        case ObservationArtifactKind::MemoryRegion:
        case ObservationArtifactKind::NetworkConnection:
        case ObservationArtifactKind::Service:
        case ObservationArtifactKind::Handle:
        case ObservationArtifactKind::Module:
        case ObservationArtifactKind::Token:
        case ObservationArtifactKind::RuntimeObject:
            return !identity.entityScope.empty() &&
                identity.entityScope.size() <=
                    ObservationArtifactEntityScopeMaxCharacters &&
                !identity.artifactKey.empty() &&
                identity.artifactKey.size() <=
                    ObservationArtifactKeyMaxCharacters;
        case ObservationArtifactKind::None:
        default:
            return false;
        }
    }

    bool HasObservationArtifactIdentity(const Observation& observation)
    {
        return HasCompleteObservationArtifactIdentity(
                observation.artifactIdentity) &&
            observation.artifactIdentity.entityScope == observation.entityScope;
    }
}
