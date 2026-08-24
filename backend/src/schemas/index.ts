import { Type } from "@sinclair/typebox";

const FreeformObject = Type.Object({}, { additionalProperties: true });
const FindingItem = FreeformObject;

export const ErrorResponseSchema = Type.Object({
  error: Type.String(),
});

export const ScanRequestSchema = Type.Object({
  directory: Type.String({ minLength: 1 }),
});

export const ScanFullRequestSchema = Type.Object({
  target: Type.String({ minLength: 1 }),
  includeSource: Type.Optional(Type.Boolean()),
  includeManifests: Type.Optional(Type.Boolean()),
});

export const ScanResponseSchema = Type.Object({
  directory: Type.Optional(Type.String()),
  target: Type.Optional(Type.String()),
  findings: Type.Array(FindingItem),
  scanType: Type.Union([
    Type.Literal("source"),
    Type.Literal("manifests"),
    Type.Literal("full"),
  ]),
  timestamp: Type.String(),
});

export const RiskScoreSchema = Type.Object({
  findings: Type.Array(FindingItem),
});

export const ScoredFindingsResponseSchema = Type.Object({
  findings: Type.Array(FreeformObject),
});

export const ComplianceEvaluateSchema = Type.Object({
  findings: Type.Array(FindingItem),
  framework: Type.String({ minLength: 1 }),
});

export const ComplianceEvaluateResponseSchema = Type.Object({
  framework: Type.String(),
  results: Type.Array(FreeformObject),
  compliant: Type.Integer(),
  nonCompliant: Type.Integer(),
  total: Type.Integer(),
});

const LedgerEntrySchema = Type.Object({
  version: Type.String(),
  data: FreeformObject,
  integrityHash: Type.String(),
  previousHash: Type.String(),
  chainIndex: Type.Integer(),
});

export const EvidenceCreateSchema = Type.Object({
  scanResultHash: Type.String({ minLength: 1 }),
  scanTarget: Type.String({ minLength: 1 }),
  findingsCount: Type.Integer({ minimum: 0 }),
  riskSummary: FreeformObject,
});

export const EvidenceCreateResponseSchema = Type.Object({
  ledger: LedgerEntrySchema,
});

export const EvidenceVerifySchema = Type.Object({
  ledger: Type.Object(
    {
      data: FreeformObject,
      integrityHash: Type.String({ minLength: 1 }),
    },
    { additionalProperties: true },
  ),
});

export const EvidenceVerifyResponseSchema = Type.Object(
  {
    valid: Type.Boolean(),
  },
  { additionalProperties: true },
);

export const CredentialVerifySchema = Type.Object({
  presentation: FreeformObject,
  verifier_did: Type.Optional(Type.String()),
});

const HexAddress = Type.String({ pattern: "^0x[0-9a-fA-F]{40}$" });
const HexBytes32 = Type.String({ pattern: "^0x[0-9a-fA-F]{64}$" });
const HexSignature = Type.String({ pattern: "^0x[0-9a-fA-F]{130}$" });

// Mirrors AuditRegistry.postAuditSigned(address orgDid, uint8 result,
// uint256 assetsReviewed, uint256 assetsMigrated, bytes32 reportHash,
// string reportURI, uint256 nonce, bytes signature)
export const RelayAuditBodySchema = Type.Object({
  orgDid: HexAddress,
  result: Type.Integer({ minimum: 0, maximum: 3, description: "AuditResult enum: 0 Pending, 1 Passed, 2 Failed, 3 Conditional" }),
  assetsReviewed: Type.Integer({ minimum: 0 }),
  assetsMigrated: Type.Integer({ minimum: 0 }),
  reportHash: HexBytes32,
  reportURI: Type.String({ minLength: 1, maxLength: 2048 }),
  nonce: Type.Integer({ minimum: 0 }),
  signature: HexSignature,
});
