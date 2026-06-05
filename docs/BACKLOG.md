# Backlog

> Generated from the plan. Create these on GitHub with `node scripts/bootstrap-github.mjs --apply`.

**57 issues** across 8 milestones; **8 epics**; **26 labels**.

## Labels

| Label | Description |
|-------|-------------|
| `type:epic` | A large body of work spanning multiple issues, usually one per milestone |
| `type:feature` | New end-user or operator-facing capability |
| `type:task` | Concrete unit of engineering work |
| `type:bug` | Defect: behavior diverges from spec or expectation |
| `type:security` | Security-critical work: crypto, threat model, hardening, review |
| `type:docs` | Documentation, specs, ADRs, READMEs |
| `type:research` | Investigation/spike to resolve an open question before building |
| `type:chore` | Tooling, build, repo hygiene, dependency and release plumbing |
| `area:crypto` | Cryptographic core: ElGamal, Chaum-Pedersen, DKG, Benaloh, nullifiers (vvp-crypto) |
| `area:kernel` | Protocol kernel, 5 ports, ElectionManifest, phase orchestrator |
| `area:bulletin-board` | BulletinBoard port and adapters (postgres-log, object-store, anchor-*) |
| `area:registrar` | Belenios-style credential issuance and identity separation |
| `area:voter-app` | Next.js cast-or-challenge voter client (WASM crypto) |
| `area:admin` | Operator/admin console and lifecycle control plane |
| `area:tally` | Homomorphic aggregation, threshold decryption, mixnet tallying |
| `area:verifier` | Independent Python verifier and ElectionGuard interop |
| `area:governance` | Governance/settlement adapters: EIP-712 votes, voting-power, oSnap |
| `area:rla` | Paper VVPAT and risk-limiting audit tooling (polling-place profile) |
| `area:infra` | Docker, monorepo, build, deployment plumbing |
| `area:ci` | Continuous integration, conformance suites, test vectors, releases |
| `priority:P0` | Blocker / critical path for the current milestone |
| `priority:P1` | Important; should land within the milestone |
| `priority:P2` | Nice-to-have; can slip to a later milestone |
| `good-first-issue` | Well-scoped, low-context entry point for new contributors |
| `blocked` | Cannot proceed until a dependency is resolved |
| `needs-design` | Requires a design decision or ADR before implementation |

## M0 — Scoping, threat model, honest spec, and ADRs

**EPIC: Epic: M0 - Scoping, threat model, honest README and ADRs** — Establish the trust foundation before any crypto claims. Deliver a signed-off threat model covering every actor (endpoint, registrar, casting server, trustees, board, anchor validators, network, coercer), a per-profile SCOPE document, and the load-bearing ADRs (no SSN-rooted identity, chain non-load-bearing, no PoS authority, paper+RLA as the only software-independence anchor, nullifiers over TTL, independent verifier in a different language, ristretto255+exponential ElGamal per ElectionGuard 2.x, receipt-freeness). DoD: threat model signed off; no public cryptographic guarantees are claimed until this epic closes.

- [ ] **Author THREAT_MODEL.md covering every actor and trust boundary**  `type:docs` `type:security` `area:infra` `priority:P0`
- [ ] **Author SCOPE.md mapping each E2E-V guarantee to its primitive, per profile**  `type:docs` `area:infra` `priority:P0`
- [ ] **ADR: Never derive identity tokens from SSN or any durable government ID**  `type:docs` `type:security` `area:registrar` `priority:P0`
- [ ] **ADR: The blockchain is non-load-bearing (anchor signed Merkle roots only)**  `type:docs` `area:bulletin-board` `priority:P0`
- [ ] **ADR: No Proof-of-Stake as election authority; permissioned BFT only if any chain**  `type:docs` `type:security` `area:bulletin-board` `priority:P0`
- [ ] **ADR: Paper + RLA is the only software-independence anchor**  `type:docs` `type:security` `area:rla` `priority:P0`
- [ ] **ADR: Single-use enforced by published nullifiers, not TTL**  `type:docs` `type:security` `area:crypto` `priority:P1`
- [ ] **ADR: Independent verifier in a different language and team than the core**  `type:docs` `type:security` `area:verifier` `priority:P1`
- [ ] **ADR: ristretto255 + exponential ElGamal following ElectionGuard 2.x (no hand-rolled ciphers)**  `type:docs` `type:security` `area:crypto` `priority:P1`
- [ ] **ADR: Receipt-freeness - never give a voter a transferable proof of their vote**  `type:docs` `type:security` `area:voter-app` `priority:P1`
- [ ] **Define the canonical transcript schema (CRYPTO_SPEC.md + transcript types)**  `type:docs` `type:security` `area:crypto` `priority:P0` `needs-design`
- [ ] **Stand up the monorepo: pnpm + Turborepo alongside a Cargo workspace**  `type:chore` `area:infra` `priority:P1` `good-first-issue`
- [ ] **Set up CI: typecheck + reference selftest on every PR**  `type:chore` `area:ci` `priority:P1` `good-first-issue`
- [ ] **Document and lock the M0 open questions before crypto work starts**  `type:research` `area:infra` `priority:P2`

## M1 — Cryptographic core (Rust vvp-crypto) + independent Python verifier

**EPIC: Epic: M1 - Cryptographic core (Rust vvp-crypto) + independent Python verifier** — Port the proven Stage-1 TypeScript PoC to an auditable Rust crate (vvp-crypto, curve25519-dalek/ristretto255, exponential ElGamal, disjunctive Chaum-Pedersen, Pedersen DKG, Benaloh, nullifiers, Merlin/STROBE Fiat-Shamir) compiled to WASM, plus an independent Python reference verifier written by a different track. DoD: a single transcript verifies under the Rust core AND the Python verifier AND the open ElectionGuard verifier.

- [ ] **Scaffold the vvp-crypto Rust crate (ristretto255 group + scalar ops)**  `type:task` `area:crypto` `priority:P0`
- [ ] **Implement exponential ElGamal (encrypt, homomorphic add, decryption share) in Rust**  `type:task` `area:crypto` `priority:P0`
- [ ] **Implement disjunctive Chaum-Pedersen ballot-validity proof in Rust**  `type:task` `type:security` `area:crypto` `priority:P0`
- [ ] **Implement Chaum-Pedersen decryption-correctness proof in Rust**  `type:task` `type:security` `area:crypto` `priority:P0`
- [ ] **Implement Pedersen DKG for k-of-n threshold trustees in Rust**  `type:task` `type:security` `area:crypto` `priority:P0` `needs-design`
- [ ] **Implement Benaloh cast-or-challenge primitive in Rust/WASM**  `type:task` `type:security` `area:crypto` `priority:P1` `needs-design`
- [ ] **Implement nullifier derivation and spent-set semantics in Rust**  `type:task` `type:security` `area:crypto` `priority:P1`
- [ ] **Compile vvp-crypto to WASM with a typed JS/TS binding**  `type:task` `area:crypto` `area:infra` `priority:P1`
- [ ] **Build the independent Python reference verifier (vvp-verify-py)**  `type:feature` `type:security` `area:verifier` `priority:P0`
- [ ] **Cross-verify a transcript under Rust core, Python verifier, AND ElectionGuard**  `type:task` `type:security` `area:verifier` `area:ci` `priority:P0`
- [ ] **Generate and publish ElectionGuard-compatible test vectors**  `type:task` `area:crypto` `area:ci` `priority:P1`
- [ ] **Add fuzzing/property tests for proof soundness in Rust**  `type:security` `area:crypto` `area:ci` `priority:P2`

## M2 — Protocol kernel, 5 typed ports, ElectionManifest, and BulletinBoard conformance suite

**EPIC: Epic: M2 - Protocol kernel, 5 ports, ElectionManifest, bulletin-board conformance** — Define the small kernel, the five typed ports (IdentityProvider, AnonymityLayer, TallyingScheme, BulletinBoard, Auditor), the Zod ElectionManifest, and the XState phase orchestrator. Ship the default postgres-log BulletinBoard plus an in-memory adapter and a conformance test suite. DoD: the same protocol runs byte-identically on the in-memory and Postgres boards.

- [ ] **Define the ElectionManifest schema (Zod) and TypeScript types**  `type:feature` `area:kernel` `priority:P0` `needs-design`
- [ ] **Define the five typed ports (IdentityProvider, AnonymityLayer, TallyingScheme, BulletinBoard, Auditor)**  `type:feature` `area:kernel` `priority:P0` `needs-design`
- [ ] **Implement the phase orchestrator (XState) for the election lifecycle**  `type:feature` `area:kernel` `priority:P0`
- [ ] **Implement the in-memory BulletinBoard adapter**  `type:task` `area:bulletin-board` `priority:P0` `good-first-issue`
- [ ] **Implement the postgres-log BulletinBoard adapter (default)**  `type:feature` `area:bulletin-board` `priority:P0`
- [ ] **Build the BulletinBoard conformance test suite**  `type:feature` `type:security` `area:bulletin-board` `area:ci` `priority:P0`
- [ ] **Wire the kernel to run an election byte-identically across boards (M2 DoD)**  `type:task` `area:kernel` `area:bulletin-board` `priority:P0`

## M3 — Registrar (Belenios separation) + cast-or-challenge voter app + k-of-n threshold tally

**EPIC: Epic: M3 - Registrar + cast-or-challenge voter app + threshold tally** — Deliver the society profile end to end: a Belenios-style registrar (identity separated from casting), a Next.js 15 cast-or-challenge voter app running the WASM crypto, a k-of-n Pedersen DKG threshold tally, and a published transcript. DoD: a club-style election runs and any third party verifies it from the published transcript alone.

- [ ] **Implement the Belenios-style registrar (credential issuance, identity separated)**  `type:feature` `type:security` `area:registrar` `priority:P0` `needs-design`
- [ ] **Implement the casting service: signed ballots + nullifier spent-set**  `type:feature` `type:security` `area:registrar` `area:kernel` `priority:P0`
- [ ] **Build the cast-or-challenge voter app (Next.js 15 + React 19 + WASM crypto)**  `type:feature` `area:voter-app` `priority:P0`
- [ ] **Implement k-of-n Pedersen DKG threshold tally pipeline**  `type:feature` `type:security` `area:tally` `priority:P0`
- [ ] **Run a club-style election end to end and verify from the transcript (M3 DoD)**  `type:task` `area:kernel` `area:verifier` `priority:P0`
- [ ] **Build the admin/operator console (create election, pick adapters and strategy)**  `type:feature` `area:admin` `priority:P1`
- [ ] **Implement the coordinator lifecycle control plane**  `type:task` `area:kernel` `area:admin` `priority:P1`
- [ ] **Voter-facing transcript explorer / public verification page**  `type:feature` `area:voter-app` `area:verifier` `priority:P2` `good-first-issue`

## M4 — Paper VVPAT + risk-limiting audit (software-independence anchor; in-person only)

**EPIC: Epic: M4 - Paper VVPAT + risk-limiting audit (software-independence anchor)** — Add the advanced, in-person-only polling-place profile: voter-verified paper ballots of record, chain-of-custody, and risk-limiting audit tooling (ballot-polling and comparison). DoD: an injected endpoint vote-flip is caught by the RLA against the paper record.

- [ ] **Specify the VVPAT paper-ballot record and chain-of-custody (polling-place)**  `type:feature` `type:security` `area:rla` `priority:P1` `needs-design`
- [ ] **Integrate risk-limiting audit tooling (ballot-polling + comparison)**  `type:feature` `type:security` `area:rla` `priority:P1`
- [ ] **Demonstrate RLA catches an injected endpoint vote-flip (M4 DoD)**  `type:task` `type:security` `area:rla` `priority:P0`

## M5 — Governance / settlement adapters (the 'all types of voting' reuse)

**EPIC: Epic: M5 - Governance and settlement adapters** — Deliver the governance profile reuse: gasless EIP-712 signed votes, pluggable voting-power strategies at a frozen snapshot, optional MACI private tier hook, and optional trustless optimistic settlement (oSnap/SafeSnap). DoD: a DAO-style proposal runs gasless and settles trustlessly, independently re-derivable from the transcript.

- [ ] **Implement gasless EIP-712 signed-vote VoteTransport (governance profile)**  `type:feature` `area:governance` `priority:P1`
- [ ] **Implement pluggable voting-power strategies at a frozen snapshot**  `type:feature` `area:governance` `priority:P1` `needs-design`
- [ ] **Add optional trustless optimistic settlement (oSnap/SafeSnap) with dispute window**  `type:feature` `area:governance` `priority:P2` `needs-design`
- [ ] **Run a gasless DAO proposal that settles trustlessly (M5 DoD)**  `type:task` `area:governance` `priority:P1`

## M6 — Optional coercion-resistant tiers + blockchain anchor adapters + adversary lab

**EPIC: Epic: M6 - Coercion-resistant tiers, chain-anchor adapters, adversary lab** — Add optional coercion-resistance tiers (Selene, MACI/Semaphore, JCJ/Civitas), the anchor-evm/anchor-cosmos/anchor-bitcoin adapters that publish only signed Merkle roots, and an adversary lab demonstrating why the original concept fails. DoD: the same election anchors to Postgres + IPFS + a permissioned BFT chain in parallel with identical verification.

- [ ] **Implement the Terelius-Wikstrom verifiable mixnet (ranked / write-in)**  `type:feature` `type:security` `area:tally` `priority:P2` `needs-design`
- [ ] **Implement optional coercion-resistant tiers (Selene, MACI/Semaphore, JCJ/Civitas)**  `type:feature` `type:security` `area:crypto` `priority:P2` `needs-design`
- [ ] **Implement anchor adapters (anchor-evm, anchor-cosmos, anchor-bitcoin) for signed roots only**  `type:feature` `area:bulletin-board` `priority:P2`
- [ ] **Demonstrate parallel anchoring to Postgres + IPFS + permissioned BFT with identical verification (M6 DoD)**  `type:task` `type:security` `area:bulletin-board` `area:ci` `priority:P1`
- [ ] **Build the adversary lab demonstrating why the original concept fails**  `type:feature` `area:infra` `type:docs` `priority:P2`

## M7 — Independent security review, signed reproducible releases, and low-stakes pilot

**EPIC: Epic: M7 - Independent security review, signed reproducible releases, low-stakes pilot** — Commission external cryptographic review and red-team, ship signed reproducible release builds, and run a real low-stakes pilot (a club or DAO, explicitly NOT a binding public election). DoD: external crypto review and red-team complete; a pilot election runs and is publicly verified.

- [ ] **Commission external cryptographic review and red-team**  `type:security` `area:crypto` `priority:P0`
- [ ] **Produce signed, reproducible release builds**  `type:chore` `area:ci` `area:infra` `priority:P1`
- [ ] **Run a low-stakes pilot election (club or DAO) - explicitly not a binding public election**  `type:task` `area:infra` `priority:P1`
- [ ] **Write the docker-compose for the full self-hostable stack**  `type:chore` `area:infra` `priority:P2` `good-first-issue`
