# Project Plan

> The single entry point to how this project is planned and tracked.

## Mission

An open, self-hostable, end-to-end-verifiable (E2E-V) voting PLATFORM whose root of trust is peer-reviewed cryptography — not a blockchain. The mission is to remove the human-in-the-middle INSIDER footholds: no registrar, server operator, trustee, board operator, or validator can alter a ballot, stuff the roll, or rig a tally without leaving public, mathematically detectable evidence. The guiding promise is "verify everything, reveal nothing" — anyone can re-verify a published transcript from the math alone, while no voter ever receives a transferable proof of how they voted. Trust is earned bottom-up: ship a solid, forkable foundation for low-stakes, low-coercion, recoverable elections (clubs, societies, HOAs, professional bodies, DAO/protocol governance, community polls, quadratic funding), prove it in the open with real groups, and let government interest follow trust rather than precede it. This is explicitly NOT a product for binding government/public elections and NOT a cloud service: expert consensus (NASEM 2018; Park-Specter-Narula-Rivest 2021; Specter-Koppel-Weitzner 2020) holds that the endpoint and the coercion environment — not the ledger — are the real attack surface, and that binding stakes require voter-verified paper ballots of record plus risk-limiting audits (software independence). We say so plainly and design to that boundary. A blockchain, when used at all, is a non-load-bearing adapter that anchors only signed Merkle roots; ballots never go on-chain.

## Operating principles

- Software independence is the line. Any remote/digital-only deployment states plainly that it does NOT achieve software independence; only the paper + risk-limiting-audit profile does, and only for supervised, in-person, recoverable elections. We never market beyond the evidence.
- No insider foothold. Every role (registrar, casting server, trustee, board operator, anchor validator) is assumed potentially malicious; integrity must survive any single dishonest insider and must produce public, detectable evidence of cheating. 'Trust us' is never an acceptable answer.
- Verify everything, reveal nothing. Every E2E-V guarantee (cast-as-intended, recorded-as-cast, counted-as-recorded) is delivered by a specific named, peer-reviewed construction with a public ZK proof — never by appeal to 'the blockchain' or to obscurity. Published artifacts contain encrypted ballots, proofs, and signed roots only — never plaintext votes or secret keys.
- Receipt-freeness is non-negotiable. No voter ever gets a transferable proof of how they voted. This is exactly the property the 2014 'see your vote on the chain' step violated, and it is a hard design constraint, not a feature flag.
- The blockchain is non-load-bearing. Default bulletin board is an authenticated Postgres transparency log (RFC 6962 signed tree heads), no chain. Optional anchors write only ~32-byte signed Merkle roots for timestamping/tamper-evidence; ballots NEVER touch a chain. Proof-of-Stake as election authority is rejected (stake is not franchise); any chain used is permissioned BFT with named, accountable validators.
- Identity stays off-ledger and never durable-government-rooted. Tokens are NEVER derived from SSN or any durable government ID. Identity proofing happens off-ledger; the voting layer sees only a fresh, unlinkable, per-election eligibility credential (Belenios-style). Single-use is enforced by published per-credential nullifiers, never by TTL.
- Two implementations, two teams, two languages. The security-critical core is Rust to WASM using only audited crates (no hand-rolled ciphers); the independent verifier is written in a different language (Python) by a different track, and we cross-check against the open ElectionGuard verifier so a single bug cannot mask itself.
- Standards over invention. Cryptography follows ElectionGuard 2.x: exponential ElGamal over ristretto255, disjunctive Chaum-Pedersen NIZKs, Pedersen DKG k-of-n threshold trustees (secret never reconstructed), Benaloh cast-or-challenge, Terelius-Wikstrom mixnet for ranked/write-in. Fiat-Shamir binds the full statement via a Merlin/STROBE transcript to avoid weak-Fiat-Shamir bugs.
- Conformance is tested, not asserted. 'Chain-agnostic' and 'byte-identical across boards' are claims only when a conformance suite runs identical vectors against every adapter and passes. Releases are reproducible and signed.
- Honesty is a feature. The README, scope doc, and per-profile claims state limits before capabilities. No cryptographic claim is published until the threat model is signed off and the relevant proof verifies under both implementations.
- Start small, earn trust, scale later. Adoption is bottom-up through real low-stakes groups; we run an external review and a red-team and a genuine pilot before claiming production-readiness, and the pilot is explicitly NOT a binding public election.

## Current status

**Stage-1 reference engine — feature-complete & adversarially reviewed (15 rounds, ~4,800 fuzz tests, CI green).** Lives in [`reference/`](../reference):

- multi-candidate (1-of-K) ballots with a zero-knowledge "exactly one selected" proof
- voter **eligibility** credentials + single-use nullifiers, with a **registrar that separates identity from ballot** (no single party links a person to their vote)
- **k-of-n threshold** decryption (Pedersen/Feldman DKG + Lagrange) — any k of n trustees, none fewer
- **cast-or-challenge** (Benaloh) auditing
- a public RFC-6962 bulletin board + a homomorphic, publicly-verifiable tally
- **cast-or-challenge** (Benaloh) auditing
- **hierarchical, tagged multi-contest ballots** (parent groups → drill-down leaf contests), with the bundle authenticated against the spec
- **publish-and-reverify**: a canonical `transcript.json` re-checked from the public record alone
- a **second, independent verifier** in Python on libsodium — cross-checked against the TypeScript verifier in CI on every push

Plus a **live in-browser app** (https://nimdy.github.io/voting-system-blockchain/) with three views — 🎮 Playground, 🔬 How-it-works walkthrough, and 🗂️ Drill-down ballot — 59 tracked issues, and three green CI workflows.

**Next:** networked services (registrar / casting / coordinator), the production Rust core (M1), the [interactive lifecycle dashboard](https://github.com/Nimdy/voting-system-blockchain/issues/58), and ranked-choice ballots. See the [Roadmap](ROADMAP.md).

## Planning artifacts

| Doc | What it is |
|-----|------------|
| [ROADMAP.md](ROADMAP.md) | Vision, principles, milestones M0–M7 |
| [SCOPE.md](SCOPE.md) | What is guaranteed, per deployment profile, and what is explicitly out of scope |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Adversaries, trust assumptions, threats & mitigations |
| [ADRs/](ADRs/) | Architecture Decision Records (the load-bearing decisions) |
| [BACKLOG.md](BACKLOG.md) | The full issue backlog grouped by milestone |
| [CRYPTO_REVIEW.md](CRYPTO_REVIEW.md) | Adversarial audit of the reference crypto |
| [ORIGINAL_CONCEPT.md](ORIGINAL_CONCEPT.md) | The preserved 2014 seed idea |

## How work is tracked on GitHub

Labels, milestones, and issues are generated from this plan. To populate the GitHub repo, run:

```bash
node scripts/bootstrap-github.mjs        # dry run: prints what it would create
node scripts/bootstrap-github.mjs --apply # actually creates labels, milestones, issues
```

It requires the GitHub CLI (`gh`) installed and authenticated (`gh auth login`).
