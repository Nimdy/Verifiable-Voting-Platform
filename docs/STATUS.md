# Project Status — where this actually stands

_Last updated: 2026-06-07. This is the single authoritative "where the project really is"
document. It is deliberately conservative. The core value of an end-to-end-verifiable
voting project is that it does not overclaim, so nothing below is marked done unless the
named deliverable actually exists in this repository and was checked against reality._

---

## 1. The honest framing: two tracks

This project is **two distinct tracks**. Conflating them is the single biggest way to be
misled about its maturity.

### Track A — the TypeScript REFERENCE PoC (exists TODAY)

A working, adversarially-hardened **reference implementation** whose job is to *define the
protocol and prove it is sound*, not to be deployed. What exists today:

- **`reference/src/` — 24 TypeScript modules** implementing the full cryptographic
  protocol (ristretto255 group, exponential ElGamal, Chaum–Pedersen proofs, k-of-n
  threshold/DKG, Belenios-style credentials + nullifiers, RFC-6962 bulletin board,
  Benaloh cast-or-challenge, verifiable mixnet, ranked/IRV, RLA anchor, chain-anchor
  seam, everlasting-privacy commitment trail, Selene trackers).
- **An independent Python/libsodium verifier** (`verifier/vvp-verify-py/vvp_verify.py`,
  ~62 KB, a *different language and different crypto library* per ADR-0006) that
  re-checks a published transcript from scratch.
- **A browser playground** (`playground/`, Vite + React) that runs the *exact* reference
  crypto client-side — interactive ballot, ranked, IRV, and a 10-step walkthrough.
- **Documentation**: THREAT_MODEL.md, SCOPE.md, PAPER_RLA_PROFILE.md, ROADMAP.md,
  PROJECT_PLAN.md, BACKLOG.md, ORIGINAL_CONCEPT.md, plus **12 Accepted ADRs**.
- **CI cross-language verification** (`.github/workflows/ci.yml`): the TS engine produces
  **seven transcript kinds** and the independent Python verifier re-verifies every one of
  them on each push/PR.
- **19 adversarial review rounds** recorded in `docs/CRYPTO_REVIEW.md`, every confirmed
  soundness bug locked behind self-tests (`reference/src/selftest.ts`). Round 1 found and
  fixed CVE-2012-2459 (Merkle malleability).

### Track B — the PRODUCTION platform (M0–M7 roadmap, largely NOT built)

The roadmap describes a real, deployable platform: a **Rust `vvp-crypto` core** (compiled
to WASM), a **pnpm + Turborepo / Cargo monorepo**, a **kernel + five typed ports**, a
**Belenios registrar service**, a **Next.js cast-or-challenge voter app**, **governance
adapters** (gasless EIP-712, voting-power strategies, optimistic settlement, chain
anchors), **paper + RLA** tooling integration, and **signed/reproducible releases**. The
overwhelming majority of this is **not built yet**.

### Misconceptions this document explicitly corrects

> **There is NO Rust monorepo.** Per direct audit of the working tree, there are **no**
> `Cargo.toml`, `Cargo.lock`, or `*.rs` files anywhere, and **no** `crates/`, `packages/`,
> `apps/`, `contracts/`, or `circuits/` directories. There is no `pnpm-workspace.yaml` and
> no `turbo.json`. The repo is three independent pieces: `reference/` (TS) + `playground/`
> (TS) + `verifier/` (Python).

> **`docs/CRYPTO_SPEC.md` now exists** (`vvp-cryptospec-1`, authored 2026-06-07). It pins every
> encoding, the full domain-separation label registry, all sigma-proof transcripts, the per-kind
> JSON wire formats, and a worked example with real expected hashes — the contract both the
> TypeScript and Python verifiers implement against (ADR-0006). This was previously the single
> biggest gap for a system claiming independent verifiability; it closed #11.

> **The crypto is reference-grade TypeScript, not production crypto.** It is trustworthy
> *as a specification and a correctness oracle*. It has **not** had external review and is
> **not** built on the audited Rust crate the roadmap calls for.

---

## 2. Milestone scoreboard

Status legend:
- **done** — the named deliverable genuinely exists and meets its acceptance criteria.
- **reference-done** — the *capability* is implemented and (often) cross-verified in the
  TypeScript reference, but the issue's named **production** artifact (Rust crate, service,
  Next.js app, monorepo package) does **not** exist. Stays open.
- **partial** — meaningful work exists but acceptance criteria are not fully met.
- **not-started** — nothing meaningful toward the deliverable exists.

| Milestone | done | reference-done | partial | not-started |
|-----------|:----:|:--------------:|:-------:|:-----------:|
| M0 — foundations / ADRs / CI | 11 | 0 | 1 | 2 |
| M1 — Rust vvp-crypto core | 0 | 7 | 2 | 3 |
| M2 — kernel + typed ports + boards | 0 | 4 | 0 | 3 |
| M3 — registrar / casting / voter app | 0 | 5 | 2 | 4 |
| M4 — paper + RLA polling-place | 0 | 1 | 3 | 0 |
| M5 — governance / DAO | 0 | 0 | 0 | 4 |
| M6 — anchors / coercion / adversary lab | 0 | 2 | 1 | 5 |
| M7 — review / pilot / release | 0 | 0 | 0 | 6 |
| (unmilestoned) | 1 | 0 | 0 | 0 |
| **Total** | **12** | **19** | **9** | **27** |

> **Reconciliation actions taken 2026-06-07.** Before this pass the tracker showed **67 open / 0 closed**
> across all milestones — which badly understated real progress. This pass: the 10 M0 deliverables
> (#1–#10) were **closed** as genuinely complete; 19 issues were labeled **`status:reference-done`** and
> 10 **`status:partial`**; #23 and #44 were re-classified from *done* to **partial** and kept open (their
> adversarial close-check found unmet acceptance criteria); and #65 was fixed in the same PR that adds this
> document. "done" below means the named deliverable exists; a closed issue is one whose done-ness was
> additionally confirmed by an adversarial skeptic. A follow-up PR authored `docs/CRYPTO_SPEC.md`, closing **#11** (the keystone gap) and clearing one of #23's blockers.

### M0 — Foundations, ADRs, CI

| # | Title | Status | Note |
|---|-------|--------|------|
| 1 | Author THREAT_MODEL.md covering every actor and trust boundary | done | 31 KB; per-actor residual-risk table T1–T8 (closed; skeptic rate-limited, manually confirmed) |
| 2 | Author SCOPE.md mapping each E2E-V guarantee to its primitive | done | 21 KB; per-profile matrix + non-goals citing NASEM/Park/Voatz |
| 3 | ADR-0001: never derive identity tokens from SSN/durable gov ID | done | Accepted; off-ledger fresh per-election credential |
| 4 | ADR-0002: blockchain is non-load-bearing (anchor signed roots only) | done | Accepted; cites Park et al. 2021 |
| 5 | ADR-0003: no PoS authority; permissioned BFT only if any chain | done | Accepted; named-validator anchor only |
| 6 | ADR-0004: paper + RLA is the only software-independence anchor | done | Accepted; mandatory no-SI disclaimer for digital-only |
| 7 | ADR-0005: single-use via published nullifiers, not TTL | done | Accepted; published-nullifier privacy noted |
| 8 | ADR-0006: independent verifier in a different language/team | done | ADR Accepted + Python verifier real; but the ADR's named CRYPTO_SPEC.md/Rust core/ElectionGuard cross-check do NOT yet exist |
| 9 | ADR-0007: ristretto255 + exponential ElGamal per ElectionGuard 2.x | done | Accepted; approved-crates list, no hand-rolled ciphers (closed; skeptic rate-limited, manually confirmed) |
| 10 | ADR-0008: receipt-freeness (no transferable proof of vote) | done | Accepted; MAY-keep vs MUST-NOT split |
| 11 | Define canonical transcript schema (CRYPTO_SPEC.md + types) | done | docs/CRYPTO_SPEC.md authored (`vvp-cryptospec-1`): encodings, full label registry, all proof transcripts, per-kind wire formats, worked-example vectors; transcript types in code |
| 12 | Stand up the monorepo (pnpm+Turborepo + Cargo workspace) | not-started | No workspace/Cargo/packages exist — fresh start |
| 13 | CI: typecheck + reference selftest on every PR | partial | CI live + cross-verify; only missing the README status badge |
| 14 | Document and lock the M0 open questions before crypto work | not-started | No consolidated open-questions register exists |

### M1 — Rust vvp-crypto core

| # | Title | Status | Note |
|---|-------|--------|------|
| 15 | Scaffold vvp-crypto Rust crate (ristretto255 group + scalars) | reference-done | Capability in `group.ts`; no Rust crate exists |
| 16 | Exponential ElGamal (encrypt/homomorphic add/dec share) in Rust | reference-done | In `elgamal.ts`; no Rust |
| 17 | Disjunctive Chaum–Pedersen ballot-validity proof in Rust | reference-done | In `proofs.ts` (proveBit/verifyBit); no Rust |
| 18 | Chaum–Pedersen decryption-correctness proof in Rust | reference-done | In `proofs.ts:108`; no Rust |
| 19 | Pedersen DKG for k-of-n threshold trustees in Rust | reference-done | Simulated DKG in `threshold.ts`; real distributed DKG is design work |
| 20 | Benaloh cast-or-challenge primitive in Rust/WASM | reference-done | In `session.ts`; no Rust/WASM |
| 21 | Nullifier derivation + spent-set semantics in Rust | reference-done | In `credentials.ts` + Python verifier; no Rust |
| 22 | Compile vvp-crypto to WASM with typed JS/TS binding | not-started | Downstream of #15; nothing to compile |
| 23 | Build the independent Python reference verifier | partial | Real, runs in CI across 7 kinds; CRYPTO_SPEC.md dependency (#11) now resolved; remaining: no Python negative-fixture tests for the 4 named attacks, no ElectionGuard (#24) |
| 24 | Cross-verify under Rust core, Python, AND ElectionGuard | partial | Real TS↔Python cross-check; Rust core + ElectionGuard interop absent |
| 25 | Generate/publish ElectionGuard-compatible test vectors | not-started | No vectors; ElectionGuard is prose-only influence |
| 26 | Fuzzing/property tests for proof soundness in Rust | not-started | No Rust, no fuzz/property harness in any language |

### M2 — Kernel + typed ports + bulletin boards

| # | Title | Status | Note |
|---|-------|--------|------|
| 27 | Define ElectionManifest schema (Zod) + TS types | reference-done | PoC configures elections imperatively; no Zod/`packages/kernel` |
| 28 | Define the five typed ports | reference-done | Roles exist as concrete modules, not typed seams |
| 29 | Phase orchestrator (XState) for election lifecycle | reference-done | Lifecycle run imperatively in `demo.ts`; no XState/guards |
| 30 | In-memory BulletinBoard adapter | reference-done | `bulletin.ts` has append/size/root only — no getSignedRoot/proveInclusion/freeze/getEntries |
| 31 | postgres-log BulletinBoard adapter (default) | not-started | No pg dep, no SQL, no transparency-log code |
| 32 | BulletinBoard conformance test suite | not-started | Depends on adapters that don't exist |
| 33 | Wire kernel to run byte-identical across boards (M2 DoD) | not-started | All prerequisites missing |

### M3 — Registrar, casting, voter app

| # | Title | Status | Note |
|---|-------|--------|------|
| 34 | Belenios-style registrar (identity separated) | reference-done | `registrar.ts`/`credentials.ts`; no service + no dual-honesty (stage-1 stores full keypairs) |
| 35 | Casting service: signed ballots + nullifier spent-set | reference-done | Logic in `election.ts`/`verify.ts`; no standalone service/receipt endpoint |
| 36 | Cast-or-challenge voter app (Next.js 15 + React 19 + WASM) | reference-done | Runs in Vite playground in TS; no Next.js app, no WASM |
| 37 | k-of-n Pedersen DKG threshold tally pipeline | reference-done | Complete + dual-verified in reference; no `crates/vvp-tally` |
| 38 | Run club-style election E2E + verify transcript (M3 DoD) | reference-done | Works end-to-end in reference + CI; production services behind it absent |
| 39 | Admin/operator console | not-started | No `apps/admin`; only narrative copy in playground |
| 40 | Coordinator lifecycle control plane | not-started | No `packages/coordinator`, no persistence |
| 41 | Voter-facing transcript explorer / public verification page | not-started | No browse/download/tracker-lookup page |
| 58 | Interactive lifecycle dashboard (role-based walkthrough) | partial | `Walkthrough.tsx` strong; missing role lanes, QR, sub-quorum cheat, live dual-verifier view |
| 59 | Hierarchical, tagged multi-contest ballots | partial | v1 shipped (`structured.ts` + UI); production multi-contest/per-contest credentials/admin UI open |
| 67 | "Getting Started for Deployers" operator guide | not-started | `docs/DEPLOYERS.md` absent; depends on #57 docker-compose |

### M4 — Paper + RLA polling-place

| # | Title | Status | Note |
|---|-------|--------|------|
| 42 | Specify VVPAT paper record + chain-of-custody | partial | Concept documented; no layout spec, no custody checklist, no enforced manifest |
| 43 | Integrate RLA tooling (ballot-polling + comparison) | reference-done | Export seam + illustrative BRAVO in `rla.ts`; no Arlo/SHANGRLA integration (comparison intentionally excluded for secret ballots) |
| 44 | Demonstrate RLA catches injected endpoint flip (M4 DoD) | partial | Demo + CI-gated self-tests + docs; illustrative BRAVO (outcome-swap, not per-ballot subset injection); real audit via Arlo/SHANGRLA (#43/#66) |
| 66 | E2E paper+RLA round-trip (anchor→manifest→Arlo/SHANGRLA) | partial | Export + TS/Python round-trip in CI; no actual Arlo/SHANGRLA consumption/reconciliation |

### M5 — Governance / DAO

| # | Title | Status | Note |
|---|-------|--------|------|
| 45 | Gasless EIP-712 signed-vote VoteTransport | not-started | No VoteTransport/EIP-712 anywhere |
| 46 | Pluggable voting-power strategies at frozen snapshot | not-started | One-credential-one-vote only; no weighted strategies |
| 47 | Optional optimistic settlement (oSnap/SafeSnap) | not-started | No Solidity/contracts/settlement logic |
| 48 | Gasless DAO proposal that settles trustlessly (M5 DoD) | not-started | Depends on #45–#47; none started |

### M6 — Anchors / coercion-resistance / adversary lab

| # | Title | Status | Note |
|---|-------|--------|------|
| 49 | Terelius–Wikström verifiable mixnet (ranked/write-in) | reference-done | EXPERIMENTAL `mixnet-tw.ts` shipped + cross-verified; production/audited (Verificatum) target open. Status comment posted. |
| 50 | Optional coercion-resistant tiers (Selene, MACI/Semaphore, JCJ) | partial | Selene mitigation shipped; MACI/Semaphore + JCJ/Civitas absent. Status comment posted. |
| 51 | Anchor adapters (anchor-evm, anchor-cosmos, anchor-bitcoin) | not-started | Only the in-memory seam (`anchorlog.ts`); named adapters in docs only |
| 52 | Parallel anchoring to Postgres + IPFS + BFT (M6 DoD) | not-started | Depends on #51 + object-store; no backends |
| 53 | Adversary lab demonstrating why original concept fails | reference-done | Substance in `demo.ts` (CLI); no `apps/lab` UI with per-demo ADR links |
| 69 | Productionize everlasting privacy (Rust port + external NIZK review) | not-started | TS capability exists; Rust port + external review absent (gap ticket) |
| 70 | Research spike: post-quantum INTEGRITY options | not-started | No PQ-integrity ADR/spike (gap ticket) |
| 72 | Distributed/threshold Selene tracker assignment | not-started | Tracker assignment still centralized in PoC (gap ticket) |

### M7 — External review, pilot, release

| # | Title | Status | Note |
|---|-------|--------|------|
| 54 | Commission external cryptographic review + red-team | not-started | Only the internal 19-round review exists; external pending |
| 55 | Produce signed, reproducible release builds | not-started | No signing/SLSA/provenance, no tags |
| 56 | Run a low-stakes pilot election (club/DAO) | not-started | Only synthetic demo; no real pilot |
| 57 | docker-compose for the full self-hostable stack | not-started | No Dockerfile/compose; services not built |
| 68 | Adopt SemVer + CHANGELOG; cut first tagged 0.x pre-release | not-started | No tags, no CHANGELOG, no policy (gap ticket) |
| 71 | Research spike: machine-checked / formally-verified proofs | not-started | No Coq/Lean/F*/EasyCrypt artifacts |

### Unmilestoned

| # | Title | Status | Note |
|---|-------|--------|------|
| 65 | Fix stale live-demo / GitHub Pages link after repo rename | done | Fixed in this PR — README now points to the live https://nimdy.github.io/Verifiable-Voting-Platform/ (old path returned HTTP 404) |

---

## 3. What actually exists today

### Reference capabilities (`reference/src/`, TypeScript)

- **Core crypto**: ristretto255 prime-order group + nothing-up-my-sleeve Pedersen base
  (`group.ts`); exponential ElGamal with additive homomorphism + distributed decryption
  shares (`elgamal.ts`); disjunctive Chaum–Pedersen bit proofs + decryption-share proofs
  (`proofs.ts`); Shamir + Feldman/Pedersen k-of-n threshold (simulated DKG) (`threshold.ts`).
- **Identity & single-use**: Belenios-style pseudonymous Schnorr credentials whose public
  key doubles as a single-use nullifier (`credentials.ts`); separate registration authority
  that publishes only an identity-free roll (`registrar.ts`).
- **Ballot lifecycle**: Benaloh cast-or-challenge with spoiled set (`session.ts`);
  single-contest E2E-V orchestration (`election.ts`); hierarchical multi-contest ballots
  (`structured.ts`).
- **Anonymity & ranked methods**: Sako–Kilian verifiable re-encryption mixnet (`mixnet.ts`);
  E2E-V instant-runoff via mixnet (`mixnet-irv.ts`); ranked/Borda validity (`ranked.ts`);
  **EXPERIMENTAL** Terelius–Wikström O(N) shuffle, opt-in, not audited (`mixnet-tw.ts`).
- **Transparency & anchoring**: RFC-6962 append-only Merkle bulletin board with
  CVE-2012-2459 hardening (`bulletin.ts`); signed, hash-chained chain-anchor seam, no
  ballots on-chain (`anchorlog.ts`).
- **Advanced privacy / verifiability**: everlasting (post-quantum) privacy via
  perfectly-hiding Pedersen commitment trail (`everlasting.ts`); Selene verifiable trackers
  for coercion-**mitigation** (`selene.ts`).
- **Paper + RLA**: ballot manifest, signed digital↔paper anchor, illustrative BRAVO
  ballot-polling reference (`rla.ts`).
- **Serialization & verification**: canonical deterministic codec + domain-separated context
  (`codec.ts`); language-neutral JSON wire format (`transcript-json.ts`); built-in
  independent verifier (`verify.ts`) + CLI (`verify-cli.ts`); full demo (`demo.ts`); soundness
  self-tests (`selftest.ts`).

### The independent verifier's seven transcript kinds

The Python/libsodium verifier (`verifier/vvp-verify-py/vvp_verify.py`) re-derives results
from the published wire format alone and dispatches on the transcript `kind` field. CI runs
it against all seven on every push/PR:

1. **plurality** — default single-contest E2E-V tally
2. **ranked** — Borda ranked-choice
3. **mixnet-irv** — instant-runoff via Sako–Kilian mixnet shuffle
4. **rla-export** — paper + RLA hybrid anchor seam
5. **everlasting-trail** — post-quantum privacy commitment trail
6. **selene** — coercion-mitigation tracker layer
7. **tw-shuffle** — **EXPERIMENTAL** Terelius–Wikström O(N) shuffle (not audited, opt-in)

---

## 4. Critical path to move forward

Ordered, honest next steps. Features can never substitute for the trust steps in (iii).

### (i) Cheap wins (documentation/hygiene; do these first)

1. **#65 — fix the dead GitHub Pages / live-demo link** (DONE in this PR). The old
   `voting-system-blockchain` Pages URL returned **HTTP 404** (GitHub does *not* redirect
   renamed project Pages); the README now points at the live
   https://nimdy.github.io/Verifiable-Voting-Platform/.
2. **#67 — write `docs/DEPLOYERS.md`** ("Getting Started for Deployers" beyond the
   playground). (Note: a full version depends on #57's docker-compose, but the conceptual
   guide can start now.)
3. **#68 — adopt SemVer + a CHANGELOG and cut the first tagged `0.x` pre-release.** No tags
   or CHANGELOG exist today; this gives the reference PoC a citable, versioned baseline.
4. **#13 (finish) — add the CI status badge to README.md**, the last unchecked acceptance
   item; CI itself is already live.

### (ii) The production-track gateway (do in this order — each unblocks the next)

1. **#12 — scaffold the monorepo** (pnpm + Turborepo TS workspace alongside a Cargo
   workspace). Nothing in Track B can land until this skeleton exists.
2. **#15–#19 — port the proven crypto to the Rust `vvp-crypto` core** (ristretto255 group,
   exponential ElGamal, disjunctive Chaum–Pedersen, decryption-correctness proof, Pedersen
   DKG), then **#22** compile it to WASM with typed bindings.
3. **#27–#33 — build the kernel + five typed ports**: ElectionManifest (Zod), the five port
   interfaces, the XState orchestrator, the in-memory + postgres-log board adapters, the
   conformance suite, culminating in the M2 DoD (byte-identical run across boards).
4. ~~**Author `docs/CRYPTO_SPEC.md`** (#11)~~ — **DONE** (`vvp-cryptospec-1`). The written contract
   independent verifiers implement against now exists; it also removes one of #23's blockers and is
   the reference for the Rust port (#15–#19).

### (iii) Trust steps that no feature can substitute for

These gate any real-world use. Building more features does **not** move these.

1. **#54 — commission an external cryptographic review and red-team.** The 19 internal
   rounds are valuable but are *self-conducted*. SECURITY.md already states the core must
   pass external review before real-world use.
2. **#56 — run a real low-stakes pilot election** (club or DAO), explicitly **not** a binding
   public election. The current "elections" are synthetic demos only.

### This session's bookkeeping

This review session created gap tickets **#65–#72** (stale link, deployer guide, SemVer +
CHANGELOG, everlasting-privacy productionization, PQ-integrity spike, formal-verification
spike, distributed Selene tracker assignment, and the paper+RLA round-trip test), and added
status comments to **#49** (EXPERIMENTAL TW mixnet vs. audited production target) and **#50**
(Selene shipped; MACI/JCJ tiers outstanding).

---

## 5. Honest scope (read this last, remember it first)

**Supported / appropriate uses:**
- Clubs, DAOs, HOAs, and community/society organizations seeking secret-ballot
  end-to-end verifiability.
- As the **digital companion to paper + RLA** in a supervised polling-place profile, where
  voter-verified paper is the legal record and a risk-limiting audit against that paper is
  the software-independence anchor.

**Explicitly NOT supported:**
- **Binding government remote/online elections.** This is a firm non-goal (SCOPE.md,
  ADR-0004), grounded in NASEM 2018, Park–Specter–Narula–Rivest 2021, and
  Specter–Koppel–Weitzner 2020 (Voatz). Remote/digital-only deployments do **not** achieve
  software independence and must say so plainly.

**Experimental, opt-in, NOT the default:**
- The **Terelius–Wikström O(N) proof of shuffle** (`mixnet-tw.ts`, ADR-0012) ships
  EXPERIMENTAL and unaudited. **Sako–Kilian remains the default** verifiable shuffle.

**Pre-audit:** the entire cryptographic core is the TypeScript reference PoC. It has **not**
undergone external cryptographic review and must not be used for any consequential election.
