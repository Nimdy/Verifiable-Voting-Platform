# Roadmap

## Vision

An open, self-hostable, end-to-end-verifiable (E2E-V) voting PLATFORM whose root of trust is peer-reviewed cryptography — not a blockchain. The mission is to remove the human-in-the-middle INSIDER footholds: no registrar, server operator, trustee, board operator, or validator can alter a ballot, stuff the roll, or rig a tally without leaving public, mathematically detectable evidence. The guiding promise is "verify everything, reveal nothing" — anyone can re-verify a published transcript from the math alone, while no voter ever receives a transferable proof of how they voted. Trust is earned bottom-up: ship a solid, forkable foundation for low-stakes, low-coercion, recoverable elections (clubs, societies, HOAs, professional bodies, DAO/protocol governance, community polls, quadratic funding), prove it in the open with real groups, and let government interest follow trust rather than precede it. This is explicitly NOT a product for binding government/public elections and NOT a cloud service: expert consensus (NASEM 2018; Park-Specter-Narula-Rivest 2021; Specter-Koppel-Weitzner 2020) holds that the endpoint and the coercion environment — not the ledger — are the real attack surface, and that binding stakes require voter-verified paper ballots of record plus risk-limiting audits (software independence). We say so plainly and design to that boundary. A blockchain, when used at all, is a non-load-bearing adapter that anchors only signed Merkle roots; ballots never go on-chain.

## Principles

- **1.** Software independence is the line. Any remote/digital-only deployment states plainly that it does NOT achieve software independence; only the paper + risk-limiting-audit profile does, and only for supervised, in-person, recoverable elections. We never market beyond the evidence.
- **2.** No insider foothold. Every role (registrar, casting server, trustee, board operator, anchor validator) is assumed potentially malicious; integrity must survive any single dishonest insider and must produce public, detectable evidence of cheating. 'Trust us' is never an acceptable answer.
- **3.** Verify everything, reveal nothing. Every E2E-V guarantee (cast-as-intended, recorded-as-cast, counted-as-recorded) is delivered by a specific named, peer-reviewed construction with a public ZK proof — never by appeal to 'the blockchain' or to obscurity. Published artifacts contain encrypted ballots, proofs, and signed roots only — never plaintext votes or secret keys.
- **4.** Receipt-freeness is non-negotiable. No voter ever gets a transferable proof of how they voted. This is exactly the property the 2014 'see your vote on the chain' step violated, and it is a hard design constraint, not a feature flag.
- **5.** The blockchain is non-load-bearing. Default bulletin board is an authenticated Postgres transparency log (RFC 6962 signed tree heads), no chain. Optional anchors write only ~32-byte signed Merkle roots for timestamping/tamper-evidence; ballots NEVER touch a chain. Proof-of-Stake as election authority is rejected (stake is not franchise); any chain used is permissioned BFT with named, accountable validators.
- **6.** Identity stays off-ledger and never durable-government-rooted. Tokens are NEVER derived from SSN or any durable government ID. Identity proofing happens off-ledger; the voting layer sees only a fresh, unlinkable, per-election eligibility credential (Belenios-style). Single-use is enforced by published per-credential nullifiers, never by TTL.
- **7.** Two implementations, two teams, two languages. The security-critical core is Rust to WASM using only audited crates (no hand-rolled ciphers); the independent verifier is written in a different language (Python) by a different track, and we cross-check against the open ElectionGuard verifier so a single bug cannot mask itself.
- **8.** Standards over invention. Cryptography follows ElectionGuard 2.x: exponential ElGamal over ristretto255, disjunctive Chaum-Pedersen NIZKs, Pedersen DKG k-of-n threshold trustees (secret never reconstructed), Benaloh cast-or-challenge, Terelius-Wikstrom mixnet for ranked/write-in. Fiat-Shamir binds the full statement via a Merlin/STROBE transcript to avoid weak-Fiat-Shamir bugs.
- **9.** Conformance is tested, not asserted. 'Chain-agnostic' and 'byte-identical across boards' are claims only when a conformance suite runs identical vectors against every adapter and passes. Releases are reproducible and signed.
- **10.** Honesty is a feature. The README, scope doc, and per-profile claims state limits before capabilities. No cryptographic claim is published until the threat model is signed off and the relevant proof verifies under both implementations.
- **11.** Start small, earn trust, scale later. Adoption is bottom-up through real low-stakes groups; we run an external review and a red-team and a genuine pilot before claiming production-readiness, and the pilot is explicitly NOT a binding public election.

## Milestones

| ID | Title | Estimate | Depends on |
|----|-------|----------|------------|
| M0 | Scoping, threat model, honest spec, and ADRs | 2-3 weeks | — |
| M1 | Cryptographic core (Rust vvp-crypto) + independent Python verifier | 6-9 weeks | M0 |
| M2 | Protocol kernel, 5 typed ports, ElectionManifest, and BulletinBoard conformance suite | 5-7 weeks | M1 |
| M3 | Registrar (Belenios separation) + cast-or-challenge voter app + k-of-n threshold tally | 8-12 weeks | M2 |
| M4 | Paper VVPAT + risk-limiting audit (software-independence anchor; in-person only) | 7-10 weeks | M3 |
| M5 | Governance / settlement adapters (the 'all types of voting' reuse) | 6-9 weeks | M3 |
| M6 | Optional coercion-resistant tiers + blockchain anchor adapters + adversary lab | 10-14 weeks | M4, M5 |
| M7 | Independent security review, signed reproducible releases, and low-stakes pilot | 8-12 weeks | M6 |

### M0 — Scoping, threat model, honest spec, and ADRs

**Goal.** Lock the trust boundary and design invariants in writing BEFORE any new cryptographic claim is published, so every later milestone has a signed-off rubric to test against and no capability is ever oversold relative to the evidence.

**Estimate:** 2-3 weeks  |  **Depends on:** —

**In scope**
- docs/THREAT_MODEL.md enumerating every actor (voter endpoint, registrar, casting server, trustees, board operator, anchor validators, network, coercer) with explicit trust assumptions, the single-malicious-insider guarantee, and what each profile does and does not defend against
- docs/SCOPE.md mapping each E2E-V guarantee to its specific primitive and giving per-profile (governance / society / polling-place) honest scoping, including a plain statement that remote/digital-only profiles do NOT achieve software independence
- docs/ADRs/ for the eight key decisions: (1) no SSN/durable-gov-ID-derived identity tokens, off-ledger proofing; (2) blockchain non-load-bearing, anchor signed roots only; (3) no PoS authority, permissioned BFT with named validators if any chain; (4) paper+RLA is the only software-independence anchor; (5) single-use via published nullifiers not TTL; (6) verifier in a different language/team than the core; (7) ristretto255 + exponential ElGamal per ElectionGuard 2.x, no hand-rolled ciphers; (8) receipt-freeness, never a transferable proof of vote
- An explicit, written reconciliation between the current Stage-1 TypeScript PoC and the target spec, listing the known gaps (N-of-N not k-of-n DKG, ad-hoc Fiat-Shamir vs Merlin transcript, no nullifiers/credentials/Benaloh, verifier shares language with core, Merkle odd-node duplication caveat) so the roadmap is grounded in reality
- CONTRIBUTING/governance note and a definition of the conformance and release-signing bar that later milestones must meet

**Out of scope**
- Any new cryptographic implementation work
- Any claim of production-readiness or government suitability
- Marketing or website
- Choosing specific pilot partners

**Deliverables**
- /home/megatron/Coding/voting-system-blockchain/docs/THREAT_MODEL.md
- /home/megatron/Coding/voting-system-blockchain/docs/SCOPE.md
- /home/megatron/Coding/voting-system-blockchain/docs/ADRs/ (one file per decision, 8 total)
- /home/megatron/Coding/voting-system-blockchain/docs/CRYPTO_SPEC.md (authored: vvp-cryptospec-1 — encodings, label registry, proof transcripts, wire formats, worked example)
- A PoC-vs-spec gap register checked into docs/
- Updated top-level README cross-linking the above and stating the honest scope first

**Definition of done.** THREAT_MODEL.md, SCOPE.md, all eight ADRs, and CRYPTO_SPEC.md are reviewed and signed off (recorded approval by the owner and at least one external reviewer); the README leads with honest scope and links them; the PoC-vs-spec gap register is complete; and a written rule is in force that NO new cryptographic capability claim is published in README/docs until the corresponding proof verifies under both implementations (M1+). No code claim is added in this milestone.

---

### M1 — Cryptographic core (Rust vvp-crypto) + independent Python verifier

**Goal.** Reimplement and harden the proven Stage-1 primitives as a production-track Rust core compiled to WASM, add the missing real k-of-n Pedersen DKG and a proper Merlin/STROBE Fiat-Shamir transcript, and prove correctness by triple cross-verification (Rust core, independent Python verifier, open ElectionGuard verifier) so a single implementation bug cannot hide.

**Estimate:** 6-9 weeks  |  **Depends on:** M0

**In scope**
- crates/vvp-crypto: exponential ElGamal over ristretto255 (curve25519-dalek), disjunctive Chaum-Pedersen ballot-validity NIZKs, Chaum-Pedersen correct-decryption proofs, ported from and matching the Stage-1 reference semantics
- Replace ad-hoc sha512(label||points) Fiat-Shamir with a Merlin/STROBE transcript that binds the full statement (closing the weak-Fiat-Shamir gap noted in M0)
- Real Pedersen DKG implementing k-of-n threshold trustees with Lagrange-combined partial decryptions; the joint secret is NEVER reconstructed; tolerates loss/absence of up to n-k trustees (the Stage-1 PoC was N-of-N only — this closes that gap)
- WASM build of vvp-crypto consumable from the browser
- verifier/vvp-verify-py: an independent Python verifier (different language, different track) that rechecks ballot validity, aggregate, decryption proofs, and tally from a transcript
- Canonical transcript types (crates/vvp-transcript) shared as the interop format
- ElectionGuard 2.x test-vector interop: ingest published ElectionGuard vectors and verify them; export our transcript in a form the open ElectionGuard verifier accepts
- Property-based and randomized soundness tests (superseding the Stage-1 2000/2000 self-test) plus negative tests for forged/malleable proofs and threshold-edge cases

**Out of scope**
- Mixnet (deferred; ranked/write-in lands later)
- Coercion-resistant tiers (M6)
- Nullifiers/credential issuance and any network/server code (M2/M3)
- Any bulletin-board or chain code

**Deliverables**
- /home/megatron/Coding/voting-system-blockchain/crates/vvp-crypto/ (Rust + WASM)
- /home/megatron/Coding/voting-system-blockchain/crates/vvp-transcript/
- /home/megatron/Coding/voting-system-blockchain/verifier/vvp-verify-py/
- Triple-verification test harness and CI job
- Updated CRYPTO_SPEC.md reflecting the implemented Merlin transcript and k-of-n DKG

**Definition of done.** A single election transcript produced by the Rust vvp-crypto core verifies as VALID under (a) the Rust core's own verifier, (b) the independent Python verifier, and (c) the open ElectionGuard verifier; a k-of-n threshold tally decrypts correctly with only k of n trustees present and the joint secret is never materialized; every negative test (forged validity proof, mutated proof, wrong decryption share, out-of-range vote, sub-threshold trustee set) is rejected by all verifiers; property-based and randomized soundness suites pass in CI; and no hand-rolled cipher exists (only audited crates).

---

### M2 — Protocol kernel, 5 typed ports, ElectionManifest, and BulletinBoard conformance suite

**Goal.** Wrap the verified core in a small kernel with five typed ports and a declarative ElectionManifest, and prove the chain-pluggable seam works by running the identical protocol byte-for-byte across an in-memory board and the default Postgres transparency log under a shared conformance suite.

**Estimate:** 5-7 weeks  |  **Depends on:** M1

**In scope**
- packages/kernel: phase orchestrator (XState) plus the five typed ports IdentityProvider, AnonymityLayer, TallyingScheme, BulletinBoard, Auditor, and the optional VoteTransport port
- ElectionManifest schema (Zod) selecting adapters and parameters declaratively; profiles are presets of manifest choices
- packages/bulletin-board: in-memory adapter and the DEFAULT postgres-log adapter implementing RFC 6962 signed-tree-head semantics (append -> InclusionReceipt, getSignedRoot, proveInclusion, freeze, getEntries)
- Harden the Merkle/transparency-log construction to close the RFC 6962 second-preimage caveat (domain-separated leaf/node and tree size), with documented test vectors
- A BulletinBoard conformance suite running identical inclusion-proof and signed-root vectors against every adapter
- Integration of the M1 core and verifier behind the TallyingScheme and Auditor ports

**Out of scope**
- object-store and anchor-* adapters (M6)
- Registrar / credentials / voter app (M3)
- Governance transport adapters beyond the port definition (M5)
- RLA tooling (M4)

**Deliverables**
- /home/megatron/Coding/voting-system-blockchain/packages/kernel/
- /home/megatron/Coding/voting-system-blockchain/packages/bulletin-board/ (in-memory + postgres-log + conformance)
- ElectionManifest Zod schema and profile presets
- docker/ compose entries for Postgres and the board service
- BulletinBoard conformance test report in CI

**Definition of done.** The same ElectionManifest-driven election runs end to end and produces byte-identical transcripts and signed roots on both the in-memory board and the postgres-log board; the conformance suite passes identical inclusion-proof and signed-root vectors against both adapters in CI; the transcripts still verify under the independent Python verifier from M1; and the Merkle hardening is demonstrated by a passing second-preimage/forgery negative-test vector.

---

### M3 — Registrar (Belenios separation) + cast-or-challenge voter app + k-of-n threshold tally

**Goal.** Deliver the first complete, real, club-style E2E-V election (the 'society' profile, no chain) where eligibility is separated from casting, the voter can audit cast-as-intended, single-use is enforced by published nullifiers, and any third party can re-verify the whole election from the published transcript.

**Estimate:** 8-12 weeks  |  **Depends on:** M2

**In scope**
- packages/registrar: Belenios-style credential issuance issuing a fresh per-election Ed25519/Schnorr keypair; integrity survives if EITHER the registrar OR the casting server is honest; credentials are unlinkable and NEVER derived from SSN/durable government ID (per M0 ADR-1)
- Published per-credential nullifier set for single-use enforcement (NOT TTL, per ADR-5); double-vote attempts are publicly visible and rejected
- apps/voter: Next.js 15 + React 19 + Tailwind v4 cast-or-challenge client running the WASM crypto from M1, so Benaloh challenge runs client-side and a malicious server cannot fake the audit; voter receives a privacy-preserving tracking commitment and inclusion proof but NO transferable proof of vote (receipt-freeness, ADR-8)
- apps/admin: operator console to create an election, pick the 'society' profile, configure trustees and the manifest
- k-of-n threshold tally and decryption wired through the kernel TallyingScheme port to the M2/M1 stack and the postgres-log board
- An end-to-end 'society' demo election with multiple trustees, multiple voters, and a published transcript

**Out of scope**
- Paper VVPAT and RLA (M4)
- Governance/settlement and gasless voting (M5)
- Coercion-resistant tiers and chain anchors (M6)
- Ranked-choice/write-in mixnet (later)

**Deliverables**
- /home/megatron/Coding/voting-system-blockchain/packages/registrar/
- /home/megatron/Coding/voting-system-blockchain/apps/voter/
- /home/megatron/Coding/voting-system-blockchain/apps/admin/
- docker/ compose for registrar + casting service + trustee nodes + board + verifier
- A published example 'society' transcript and a one-command third-party re-verification path

**Definition of done.** A complete club-style 'society' election runs end to end (issue credentials -> cast-or-challenge -> threshold tally) with no chain; an independent party, using only the published transcript and the M1 Python verifier, re-derives and confirms the tally and confirms every ballot's validity and inclusion; a double-vote attempt is rejected and publicly evidenced via the nullifier set; a Benaloh challenge run on the client detects a deliberately cheating casting server; and no artifact handed to any voter can prove how they voted.

---

### M4 — Paper VVPAT + risk-limiting audit (software-independence anchor; in-person only)

**Goal.** Provide the ONLY profile that achieves software independence — the 'polling-place' profile — by adding voter-verified paper ballots of record and a mandatory risk-limiting audit, and prove it by catching a deliberately injected endpoint flip against the paper.

**Estimate:** 7-10 weeks  |  **Depends on:** M3

**In scope**
- rla/arlo-rla: risk-limiting audit tooling supporting ballot-polling and comparison audits against a paper ballot manifest, producing an auditable, reproducible report and a defined risk limit
- Paper VVPAT handling where the paper is the LEGAL ballot of record, inspected before the electronic cast finalizes and retained (not handed back, per the M0 paper ADR); discrepancies are resolved in favor of paper
- Endpoint-integrity controls documentation and harness for the polling-place profile (reproducible builds, measured boot, chain-of-custody) — opt-in, in-person, supervised only
- Adversary scenario: an injected endpoint flip (device shows A, records B) that the electronic transcript alone cannot catch
- Plain, prominent statement in the profile docs that ONLY this profile achieves software independence and that it remains for supervised low-coercion recoverable elections, NOT binding public elections

**Out of scope**
- Any remote/online voting claim of software independence
- Certification for legally binding government elections
- Governance/settlement adapters (M5)
- Coercion-resistant tiers (M6)

**Deliverables**
- /home/megatron/Coding/voting-system-blockchain/rla/arlo-rla/
- Polling-place profile preset in the ElectionManifest
- docs additions: paper-of-record procedures, endpoint-integrity controls, RLA operator guide
- An endpoint-flip adversary scenario and its RLA-catches-it test artifact

**Definition of done.** In the polling-place profile, a deliberately injected endpoint flip (recorded choice differs from voter-verified paper) is detected by the risk-limiting audit against the paper ballots of record, to the configured risk limit, and the audit report is reproducible by a third party; the electronic-only transcript by itself does NOT catch the flip (demonstrating why paper+RLA is the software-independence anchor); and the profile documentation states plainly that this is the only software-independent profile and is not for binding public elections.

---

### M5 — Governance / settlement adapters (the 'all types of voting' reuse)

**Goal.** Reuse the same verified kernel for DAO/protocol governance via the 'governance' profile — gasless EIP-712 signed votes with pluggable voting-power strategies and optional trustless optimistic settlement — and prove a DAO-style proposal is independently re-derivable from its transcript.

**Estimate:** 6-9 weeks  |  **Depends on:** M3

**In scope**
- packages/transport: VoteTransport adapters — OffChain (Snapshot-style gasless EIP-712), plus EVM/L2 and Mock — with signature verification across EIP-712, EIP-1271 (contract wallets), and ERC-6492 (pre-deploy)
- Pluggable voting-power strategies (token / NFT / quadratic / delegation / allowlist Merkle root) evaluated at a frozen snapshot block
- contracts/ (Foundry): minimal anchor contract and OZ Governor + Safe/Zodiac for optional optimistic settlement (oSnap/SafeSnap) behind a dispute window + timelock
- Governance profile preset in the ElectionManifest; bulletin board = object-store or postgres-log
- An end-to-end DAO-style proposal demo that runs gasless and (optionally) settles trustlessly
- Honest scoping note: governance is low-coercion low-stakes; it does NOT achieve software independence and is not a substitute for the polling-place profile

**Out of scope**
- Proof-of-Stake as election authority (rejected, ADR-3)
- Putting ballots on-chain (ADR-2 — anchors carry signed roots only; that anchoring work is M6)
- Coercion-resistant tiers (M6)
- Binding public-election use

**Deliverables**
- /home/megatron/Coding/voting-system-blockchain/packages/transport/
- /home/megatron/Coding/voting-system-blockchain/contracts/ (Foundry)
- Governance profile preset and voting-power strategy library
- A published DAO-style proposal transcript with a third-party re-derivation script

**Definition of done.** A DAO-style proposal runs in the governance profile with gasless EIP-712 signed votes (accepting EOA, contract-wallet, and pre-deploy signatures), tallies under a chosen voting-power strategy at a frozen snapshot, and optionally settles trustlessly behind a dispute window + timelock; an independent party re-derives the identical result from the published transcript and the snapshot data; and no ballot is written on-chain. The kernel/core/verifier from M1-M3 are reused unchanged.

---

### M6 — Optional coercion-resistant tiers + blockchain anchor adapters + adversary lab

**Goal.** Add the opt-in coercion-resistance tiers and the non-load-bearing chain-anchor adapters, and prove the chain is genuinely swappable by anchoring the same election to Postgres, IPFS, and a permissioned BFT chain in parallel with identical verification.

**Estimate:** 10-14 weeks  |  **Depends on:** M4, M5

**In scope**
- circuits/ and AnonymityLayer adapters for optional coercion-resistant tiers: Selene (deferred fakeable trackers), MACI/Semaphore (zk anti-collusion private tier), and full JCJ/Civitas (with documented quadratic tally cost and untappable-registration assumption)
- Optional verifiable re-encryption mixnet (Terelius-Wikstrom shuffle proofs) for ranked-choice / write-in, behind the TallyingScheme/AnonymityLayer ports
- Bulletin-board anchor adapters: object-store (IPFS/Helia or S3 + signed roots), anchor-evm (viem), anchor-cosmos (permissioned CometBFT with named validators), anchor-bitcoin (OP_RETURN) — each writing ONLY ~32-byte signed Merkle roots, never ballots (ADR-2); behind the AnchorTarget sub-interface
- Extend the BulletinBoard conformance suite to cover every anchor target and the parallel multi-anchor ('belt and suspenders') configuration
- apps/lab: composition harness and adversary demos showing why the original 2014 concept fails and that each tier/adapter behaves as specified

**Out of scope**
- Any use of PoS as the election authority (ADR-3)
- External security review and pilot (M7)
- New core primitives beyond what M1 established (these are layered tiers/adapters)

**Deliverables**
- /home/megatron/Coding/voting-system-blockchain/circuits/ (Semaphore, shuffle, MACI)
- /home/megatron/Coding/voting-system-blockchain/crates/vvp-mixnet/
- object-store, anchor-evm, anchor-cosmos, anchor-bitcoin adapters in packages/bulletin-board/
- /home/megatron/Coding/voting-system-blockchain/apps/lab/
- Extended conformance + parallel-anchor test report

**Definition of done.** The same election anchors in parallel to a Postgres transparency log, IPFS, and a permissioned BFT (CometBFT, named validators) chain, and the published signed Merkle root is identical across all anchors with verification passing identically against each; each anchor carries only signed roots (no ballot ever appears on any chain); at least one coercion-resistant tier (MACI/Semaphore private tier) runs end to end with a re-verifiable transcript and provides no transferable proof of vote; and the conformance suite passes across all anchor adapters in CI.

---

### M7 — Independent security review, signed reproducible releases, and low-stakes pilot

**Goal.** Subject the platform to external scrutiny and run a genuine real-world low-stakes pilot, then ship signed reproducible releases — establishing the public trust that is the whole point, without ever claiming binding-public-election suitability.

**Estimate:** 8-12 weeks  |  **Depends on:** M6

**In scope**
- External cryptography review of vvp-crypto and the transcript/verifier interop by an independent party, with findings published and material issues remediated
- Independent red-team / adversary engagement against the deployed 'society' and 'governance' profiles, with a published report
- Reproducible build pipeline and signed releases for all components (core, verifier, kernel, apps, adapters), per the M0 release-signing bar
- A real low-stakes pilot with an actual club/society/DAO (explicitly NOT a binding public election), publishing the transcript and an independent third-party verification
- Final honest README/scope pass confirming per-profile claims match what review + pilot demonstrated

**Out of scope**
- Any certification for binding government/public elections
- Operating a hosted/cloud product (this remains self-hostable/forkable foundation)
- Marketing claims beyond what the review and pilot evidence supports

**Deliverables**
- Published external crypto-review report + remediation log
- Published red-team report + remediation log
- Signed, reproducible release artifacts with verification instructions
- Pilot election transcript + independent verification writeup
- Final README/SCOPE update reflecting verified, honest per-profile claims

**Definition of done.** An external cryptographer's review and an independent red-team engagement are complete with all material findings remediated and the reports published; releases are reproducible (independently rebuildable to identical artifacts) and signed; a real club/DAO pilot has run on the platform with its transcript published and independently verified by a third party; and the README/scope statements are confirmed to match demonstrated capability, with the binding-public-election boundary stated plainly and never crossed.

---
