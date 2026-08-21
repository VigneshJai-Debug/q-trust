# Draft Claims — Q-Trust PQC Migration Coordination

> **Draft for attorney use only.** These claims are written in the style of provisional
> application claims to establish priority and to guide a formal drafting. They are not
> filed text; claim scope, antecedent basis, and dependent structure must be reviewed by
> qualified patent counsel. No claim herein should be construed as legal advice.

## Independent claim (system)

1. A system for coordinating cross-organizational migration of cryptographic assets
   from classical cryptography to post-quantum cryptography (PQC), comprising:

   (a) an inventory engine configured to discover cryptographic assets of an
   organization and to generate a cryptographic bill of materials (CBOM) data structure
   enumerating, for each asset, an algorithm identifier, a key size, a vendor
   PQC-readiness indicator, and a criticality value;

   (b) a dependency-graph builder configured to construct a dependency graph whose
   nodes represent said assets and whose edges represent migration-order dependencies
   between assets;

   (c) a graph neural network (GNN) ranking engine comprising (i) an order prediction
   head configured to output, for each node of said dependency graph, a migration
   priority score, and (ii) a risk prediction head configured to output, for each node,
   a dependency-aware migration risk score, wherein said GNN is trained with a
   ranking-based loss function to learn an ordered migration sequence over said
   dependency graph;

   (d) a set of smart contracts deployed on a distributed ledger, comprising an asset
   registry configured to store, for each asset, only a hash of the asset's CBOM record
   together with an organization identifier and timestamps; a vendor registry
   configured to store vendor attestations that a product version supports a target
   PQC algorithm, each attestation having a deterministic attestation identifier
   derived from the product identifier, version, and algorithm; a migration registry
   configured to store records of migrations from a source algorithm to a target
   algorithm together with evidence hashes; and an audit registry configured to store
   auditor attestations of said migrations; and

   (e) a verification interface configured to publicly verify, from said distributed
   ledger and without access to the off-chain CBOM, at least one of: asset existence
   and activity, product support for a target algorithm, migration completion, and
   audit result;

   whereby multiple organizations can coordinate and verify a PQC migration lifecycle
   without exposing the CBOM contents and without trusting any single party.

## Independent claim (method)

2. A computer-implemented method for coordinating migration of cryptographic assets to
   post-quantum cryptography across multiple organizations, comprising:

   (a) discovering cryptographic assets of a first organization and generating a CBOM
   data structure therefor;

   (b) constructing a dependency graph over said assets;

   (c) applying a graph neural network having an order prediction head and a risk
   prediction head to said dependency graph to produce an ordered migration sequence,
   said GNN having been trained with a ranking-based loss function;

   (d) storing on a distributed ledger, for each asset, only a hash of the asset's CBOM
   record together with an organization identifier;

   (e) receiving, from a vendor organization, an attestation that a product version
   supports a target PQC algorithm, and storing said attestation on said distributed
   ledger with a deterministic attestation identifier derived from the product
   identifier, version, and algorithm;

   (f) recording on said distributed ledger a migration of an asset from a source
   algorithm to a target algorithm according to said ordered migration sequence,
   together with an evidence hash;

   (g) recording on said distributed ledger an auditor attestation of said migration;
   and

   (h) publicly verifying, from said distributed ledger, one or more of asset activity,
   product support, migration completion, and audit result without access to the
   off-chain CBOM.

## Dependent claims

3. The system of claim 1, wherein the GNN comprises graph convolutional layers with
   residual connections, and wherein said ranking-based loss function is a ListMLE
   (Plackett-Luce) loss computed per dependency graph.

4. The system of claim 1, wherein the deterministic attestation identifier is computed
   as a cryptographic hash of a concatenation of the product identifier, the version,
   and the algorithm.

5. The system of claim 1, wherein the vendor registry enforces that only a registered
   vendor address may create or revoke an attestation, and wherein revocation
   automatically changes a product-support query result.

6. The system of claim 1, wherein the migration registry enforces a supported-algorithm
   check such that a migration to an unattested target algorithm is rejected.

7. The system of claim 1, further comprising a webhook delivery service configured to
   subscribe a consumer address to registry events and to deliver, via a message queue,
   notifications of newly created attestations and migration records.

8. The system of claim 1, wherein the distributed ledger is an Ethereum-compatible
   Layer-2 chain and the CBOM hash is stored in a single storage slot per asset.

9. The method of claim 2, wherein step (c) further comprises training said GNN on
   synthetic dependency graphs labeled by a priority heuristic, with a validation
   protocol reporting exact-rank accuracy, top-k overlap, and Kendall's tau.

10. The method of claim 2, further comprising emitting the ordered migration sequence
    to a first organization, a vendor organization, and an auditor organization, each
    of which performs a role-restricted write to the distributed ledger in accordance
    with its role.

## Notes for counsel

- Claims 1 and 2 are drafted broad (system/method); dependent claims 3–10 capture the
  specific technical details that distinguish from CARAF/QSTriage-style scorers and
  from generic blockchain-PKI patents (deterministic attestation IDs keyed to
  product/version/algorithm; role-separated four-registry lifecycle; ranking-loss
  trained GNN with dual heads; hash-only storage; webhook delivery).
- Consider adding means-plus-function or structural language per your jurisdiction's
  practice, and a claims chart mapping each claim element to the specification
  (see `invention_disclosure.md`).
- Recommended claim-language exclusions to preserve novelty: no claim over CBOM format
  per se (ECMA-424), no claim over generic blockchain PKI, no claim over GNNs in
  general.