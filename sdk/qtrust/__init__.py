# sdk/qtrust/__init__.py
"""Q-Trust SDK — Post-Quantum Cryptography migration."""
from .client import QTrustClient
from .ipfs import PinataClient
from .schema import CBOM, AssetRecord, CBOMEntry, MigrationRecord, ProductAttestation, VendorInfo
from .did import DIDResolver, DIDDocument
from .vc import VCIssuer, VCPresenter, VCVerifier, VerifiableCredential, VerifiablePresentation, VCVerificationResult
from .trust import TrustAssessment, TrustEvaluator, EvidenceContribution, Conflict

__version__ = "0.2.0"
__all__ = [
    "QTrustClient",
    "CBOM",
    "CBOMEntry",
    "AssetRecord",
    "VendorInfo",
    "ProductAttestation",
    "MigrationRecord",
    "PinataClient",
    "DIDResolver",
    "DIDDocument",
    "VCIssuer",
    "VCPresenter",
    "VCVerifier",
    "VerifiableCredential",
    "VerifiablePresentation",
    "VCVerificationResult",
    "TrustAssessment",
    "TrustEvaluator",
    "EvidenceContribution",
    "Conflict",
]
