# Verifiable Voting Platform

> A reusable, configurable, **end-to-end-verifiable (E2E-V)** voting platform whose trust root is
> peer-reviewed cryptography — *not* a blockchain. Deploy it for club, society, association, HOA,
> DAO/governance, and community voting. A blockchain is supported as **one optional, swappable
> bulletin-board / settlement adapter**, never as the thing you have to trust.

## ▶️ Try it

**🌐 Live, no install → https://nimdy.github.io/voting-system-blockchain/**

Or run it locally:

```bash
cd playground && npm install && npm run dev
```

The live app has five views: **Playground** (run an election, **audit your own ballot**, **verify the result yourself**, and **try to cheat it** — vote twice · vote without a credential · vote for two · flip a ballot · rig the tally — every attack caught), **How it works** (a step-by-step walkthrough with a plain↔*show-the-cryptography* depth toggle), **Full ballot** (hierarchical, tagged multi-contest ballots), **Ranked (Borda)** (rank the candidates and watch your ballot become an **encrypted permutation matrix** that's *provably* a valid ranking — every row & column proven to sum to one without revealing a single cell — then a homomorphic **Borda** tally you verify yourself; never reveals a ballot), and **Instant-runoff** (a **verifiable shuffle** unlinks voters from ballots, then the anonymized rankings are decrypted and eliminated round by round — *honest scope: IRV reveals the anonymized rankings and hides only which voter cast which*). Everything runs in your browser on the same crypto as [`reference/`](reference). (Pre-audit demo — not independently reviewed; not for binding elections.)

## ✅ What works today (stage-1 reference, 17× adversarially reviewed)

A complete, fuzz-tested (~4,900 trials) reference engine in [`reference/`](reference) — *trust root is cryptography, not a chain*:

- **Eligibility & one-vote-per-voter** — Belenios-style credentials + single-use nullifiers, with a **registrar that separates identity from ballot** (no single party links a person to their vote).
- **Ballots** — multi-candidate (1-of-K), **multi-seat "vote for exactly N"** (block voting), **hierarchical, tagged multi-contest** ballots (parent groups → drill-down leaf contests), and **ranked-choice (Borda)** — each ballot a K×K **permutation matrix** of encrypted bits (every row & column proven to sum to one) with a homomorphic, threshold-decrypted Borda tally and an interactive UI, all held to the same two-verifier bar. Each carries zero-knowledge validity proofs.
- **Ranked-choice IRV (instant-runoff)** — full end-to-end verifiable IRV via a **verifiable re-encryption mixnet** (Sako–Kilian cut-and-choose, soundness 2⁻¹²⁸): ballots are shuffled to break the voter↔ballot link, *the shuffle is proven correct*, then the anonymized ballots are threshold-decrypted and tabulated round-by-round — and the verifier re-runs the elimination itself. *(Honest scope: IRV **reveals the anonymized ranking multiset** and hides only **which voter** cast which ranking — weaker than Borda, which never reveals a ballot. The O(N) Terelius–Wikström/Bayer–Groth shuffle upgrade is tracked under [#49](https://github.com/Nimdy/voting-system-blockchain/issues/49).)*
- **Secrecy & integrity** — exponential ElGamal, **k-of-n threshold** decryption (Pedersen DKG + Lagrange; any k of n trustees, none fewer), **cast-or-challenge** (Benaloh) auditing, a public RFC-6962 bulletin board, and a homomorphic, publicly verifiable tally.
- **Trustlessness** — every election (plurality, ranked Borda, **and ranked-choice IRV**) publishes a canonical transcript anyone re-verifies from the public record alone, checked by **two independent verifiers** (TypeScript + Python/libsodium) **cross-checked in CI on every push** — including the full IRV transcript (ballots + verifiable shuffle + threshold decryption + tabulation), with a 15-case cross-language divergence battery showing zero divergence.
- **Paper + RLA hybrid** ([profile](docs/PAPER_RLA_PROFILE.md), [ADR-0009](docs/ADRs/ADR-0009-the-digital-paper-anchor-binds-the-board-root-to-the-paper-bal.md)) — a signed **digital↔paper anchor** binds the bulletin-board root to a paper ballot manifest (so neither record can be swapped undetected), plus a VotingWorks **Arlo/SHANGRLA** manifest export, for the supervised polling-place profile where **paper is the legal record and a risk-limiting audit on the paper** delivers software independence ([ADR-0004](docs/ADRs/ADR-0004-paper-ballots-of-record-plus-risk-limiting-audits-are-the-on.md)). Secret-ballot paths use ballot-**polling** RLAs — *never* per-ballot CVRs (secrecy). The anchor is held to the same two-verifier bar (TS + Python/libsodium, cross-checked in CI). *(The digital layer is the transparent audit companion, not the legal record; the RLA-of-record is run by external tools on the paper.)*
- **Everlasting / post-quantum privacy** ([everlasting.ts](reference/src/everlasting.ts), [ADR-0010](docs/ADRs/ADR-0010-everlasting-post-quantum-privacy-via-perfectly-hiding-pedersen.md)) — closes the **harvest-now-decrypt-later** gap: alongside each ballot, a **perfectly-(unconditionally-)hiding** Pedersen commitment `C = v·G + d·H` whose privacy survives even a *future adversary who breaks the elliptic curve* (a quantum computer), **bound** to the verifiable ElGamal ballot by a generalized-Schnorr consistency NIZK. The commitment record even proves **full ballot validity on its own** — an everlasting bit-proof on each commitment (0/1) plus an everlasting exactly-L sum-proof on each row (no over/undervote), from the commitments alone, so it stays self-sufficient if the ciphertexts are later discarded. Held to the two-verifier bar (TS + Python derive a byte-identical nothing-up-my-sleeve generator) with zero cross-language divergence. *Honest scope: this is the everlasting-privacy **primitive** + binding proof — post-quantum **privacy** of the commitment trail, **not** post-quantum integrity (binding stays discrete-log based). A fully everlasting-private deployment needs the commitments to be the permanent record while the ciphertexts are ephemeral tally material (Cuvelier–Pereira–Peters), so the demo artifact — which publishes both — is only computationally private.*
- **Optional chain-anchor seam** ([anchorlog.ts](reference/src/anchorlog.ts), [ADR-0002](docs/ADRs/ADR-0002-the-blockchain-is-non-load-bearing-anchor-only-signed-merkle.md)/[ADR-0003](docs/ADRs/ADR-0003-no-proof-of-stake-as-election-authority-permissioned-bft-wit.md)) — the *non-load-bearing* on-chain seam: a signed, hash-chained, append-only transparency log that anchors only the ~64-byte signed Merkle **roots** (board root + optional paper-manifest root), **never a ballot**, witnessed by **named, accountable** validators (no Proof-of-Stake). The place a deployment swaps in a permissioned-BFT chain or a CT-style log. *Honest scope: this gives tamper-evidence + relative ordering for the root within a presented copy (the embedded `anchoredAt` is a **signer-asserted** time label, bound into the signature but not checked against any trusted clock — real timestamping comes from the backend you swap in) — pin the head out-of-band for truncation safety, supply a validator allowlist for accountability; it is **not** fork/equivocation safety (needs gossip/witness-cosigning), **not** trust in the tally (that is E2E-V), and **not** software independence (that is paper + RLA). The trust root remains cryptography, not the chain.*

Seventeen independent adversarial crypto-review rounds; every finding fixed (including a critical anchor-forge caught pre-ship in round 13, the chain-anchor seam's over-claims tightened in rounds 14–15, a dual-verifier scalar-syntax divergence — latent across *all* transcript kinds — caught alongside the everlasting-privacy primitive in round 16, and the everlasting ballot-validity proofs completed in round 17 — see [docs/CRYPTO_REVIEW.md](docs/CRYPTO_REVIEW.md)). The rest of this README is the modernized specification and roadmap.

This project began as a 2014-era concept ([docs/ORIGINAL_CONCEPT.md](docs/ORIGINAL_CONCEPT.md)) for a
blockchain voting system. The good instincts in that concept — a public bulletin board, a paper
audit trail, single-use eligibility tokens, and separating *who is eligible* from *how they voted* —
are kept. The parts that 40 years of election-security research warns against are replaced with
named, sound constructions. This README is the modernized specification.

---

## ⚠️ Honest scope — read this first

A voting system is only as trustworthy as the weakest link between the voter's intent and the
final tally. That link is almost never the ledger; it is the **endpoint** (the device the voter
uses) and the **coercion environment** (whether someone can pressure or pay the voter). No amount
of blockchain fixes either. So we are explicit about what this platform is — and is not — for.

| Use case | Supported? | Notes |
|---|---|---|
| Clubs, societies, HOAs, professional/board elections (e.g. IACR-style) | ✅ **Primary target** | Full E2E-V; published transcript anyone can re-verify |
| DAO / on-chain governance, token/NFT/quadratic voting, community polls, public-goods funding | ✅ **Primary target** | Gasless signed votes, optional private (anti-collusion) tier |
| Internal corporate / association / shareholder-style polls | ✅ Supported | Identity via your existing roll/IdP |
| Supervised polling-place elections with paper ballots + risk-limiting audits | ⚠️ **Advanced, opt-in** | Requires the paper + RLA profile (software independence). Heavy operational burden. |
| **Legally binding government / public elections, remote/online** | ❌ **Not supported. Do not use.** | See below. This is the near-unanimous expert position, not a limitation we intend to "fix later." |

**Why not binding government elections?** Because the published consensus is clear:

- **NASEM 2018, *Securing the Vote*** — blockchain "does little to solve the fundamental security
  issues of elections, and indeed, blockchains introduce additional security vulnerabilities."
- **Park, Specter, Narula & Rivest 2021, *Going from Bad to Worse* (Journal of Cybersecurity)** —
  blockchain voting is *worse* than internet voting and *far* worse than paper.
- **Specter, Koppel & Weitzner 2020 (USENIX Security), the Voatz analysis** — the one app used in a
  US federal election was exploitable, and its blockchain was security-irrelevant.

The decisive reason: malware on a voting device can display "Candidate A" while recording
"Candidate B," and an immutable ledger then **locks the fraud in permanently**. A ledger gives
tamper-*evidence* for data already recorded; it does nothing for cast-as-intended, ballot secrecy,
eligibility, or coercion-resistance. The only known defense against a compromised endpoint is a
**voter-verified paper ballot that is the legal record, audited by a risk-limiting audit (RLA)** —
i.e. *software independence*. Where binding stakes are involved, that paper-and-RLA system is the
real answer, and the digital layer is at most a convenience.

---

## What this platform guarantees (and how)

End-to-end verifiability is three independent properties. Each is delivered by a *specific*
cryptographic mechanism — not by a vague appeal to "the blockchain."

| Guarantee | Plain meaning | Mechanism |
|---|---|---|
| **Cast-as-intended** | The encrypted ballot really contains the choice the voter made | **Benaloh cast-or-challenge** (the voter can spoil & audit a ballot on an independent device) + ZK proofs of ballot well-formedness |
| **Recorded-as-cast** | The voter's encrypted ballot is on the public record, unaltered | A privacy-preserving **tracking commitment** + a Merkle **inclusion proof** against signed roots — reveals *nothing* about the choice |
| **Counted-as-recorded** | The published tally is the honest count of the recorded ballots | **Homomorphic tally** (or a **verifiable mixnet**) + **threshold decryption** with public ZK proofs; an **independent verifier** re-checks everything |

**Independent cross-language verification.** A published election is a single `transcript.json` that
*anyone* re-checks from the public record alone. The repo ships **two independent verifiers** — the
TypeScript reference and a [Python verifier on libsodium](verifier/vvp-verify-py) — and CI runs
**both** on every push, so a bug in one implementation can't silently pass. Try it:
`cd reference && npm run demo && npm run verify -- out/transcript.json`.

A core principle throughout: **no voter ever receives a receipt that proves to a third party how
they voted.** That is what makes vote-buying and coercion impossible-by-construction in the
strong tiers — and it is precisely the property the original concept's "see your vote on the
blockchain" step violated.

---

## Architecture

One codebase, a small kernel, and **five typed ports** with swappable adapters. "Configurable for
anyone to deploy" means: you pick adapters and parameters in a declarative `ElectionManifest`, and
the same protocol runs unchanged.

```
                          ┌───────────────────────────────────────────────┐
                          │              Protocol Kernel                    │
                          │   ElectionManifest (Zod)  +  phase orchestrator │
                          └───────────────────────────────────────────────┘
        ┌──────────────┬───────────────┬───────────────┬──────────────┬───────────────┐
        ▼              ▼               ▼               ▼              ▼               ▼
 ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
 │ Identity     │ │ Anonymity   │ │ Tallying    │ │ Bulletin    │ │ Auditor /   │ │ (optional)  │
 │ Provider     │ │ Layer       │ │ Scheme      │ │ Board       │ │ Verifier    │ │ Vote        │
 │              │ │             │ │             │ │ (the chain- │ │             │ │ Transport   │
 │ org roll /   │ │ Belenios    │ │ homomorphic │ │ pluggable   │ │ independent │ │ (governance │
 │ OIDC /       │ │ creds /     │ │ ElGamal /   │ │ seam)       │ │ re-check in │ │ settlement) │
 │ Semaphore /  │ │ mixnet /    │ │ threshold   │ │             │ │ a different │ │             │
 │ JCJ creds    │ │ MACI/Selene │ │ decryption  │ │             │ │ language    │ │             │
 └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘
```

### The chain-pluggable seam (`BulletinBoard` port)

The blockchain is **never on the critical trust path**. The bulletin board is a *single narrow
interface* for authenticated, append-only, publicly-readable, replicated storage of **encrypted
ballots + proofs + signed Merkle roots** (RFC 6962 transparency-log semantics):

```
append(SignedArtifact) -> InclusionReceipt
getSignedRoot()        -> { merkleRoot, seq, sig }
proveInclusion(id)     -> MerkleAuditProof
freeze()               -> FinalRoot
getEntries(range)      -> SignedArtifact[]
```

Adapters behind that one interface:

- **`postgres-log` (DEFAULT)** — an authenticated append-only transparency log (Trillian/Sigstore-style
  signed tree heads). *No chain.* Per Park et al., a plain authenticated log does the bulletin-board
  job more simply and reliably than a blockchain.
- **`object-store`** — IPFS/Helia or S3 mirror + signed roots.
- **`anchor-*`** — writes **only** a ~32-byte signed Merkle root for tamper-evidence/timestamping
  (ballots *never* go on-chain), itself chain-agnostic via an `AnchorTarget` sub-interface:
  `anchor-evm` (viem), `anchor-cosmos` (permissioned CometBFT), `anchor-bitcoin` (OP_RETURN).

A **conformance test suite** runs identical inclusion-proof vectors against every adapter, so
"chain-agnostic" is *tested*, not asserted. You can even run several anchors in parallel
("belt and suspenders") purely by configuration.

> **Rejected by design:** Proof-of-Stake as the election authority (stake ≠ franchise → plutocratic
> capture; probabilistic finality contradicts "immutable"). Any anchoring chain must be permissioned
> BFT with named, accountable validators, or a public chain used *only* to timestamp roots.

### Cryptographic stack

Security-critical code is **Rust → WASM** (audited crates only; no hand-rolled ciphers). The
independent verifier is written in a **different language (Python)** by a different track, so a
single bug cannot mask itself.

- **Encryption / tally:** exponential **ElGamal over Ristretto255** (`curve25519-dalek`), additively
  homomorphic, following **ElectionGuard 2.x**.
- **Keys:** **Pedersen DKG**, *k*-of-*n* threshold trustees; the secret key is **never reconstructed**
  (Lagrange-combined partials).
- **Proofs:** disjunctive **Chaum-Pedersen** NIZKs (each ciphertext encrypts 0/1; per-contest sums
  well-formed); Chaum-Pedersen proofs of correct partial decryption. Non-interactive via Fiat-Shamir
  over a Merlin/STROBE transcript (avoids weak-Fiat-Shamir bugs).
- **Cast-as-intended:** **Benaloh** cast-or-challenge, runnable in-browser via the WASM verifier so a
  malicious server can't fake the audit.
- **Eligibility / anti-stuffing:** **Belenios-style** credential → an Ed25519/Schnorr keypair; the
  voter signs the ciphertext (ordinary signatures, *not* blind signatures). Integrity survives if the
  registrar *or* the server is honest. Double-voting prevented by a published per-credential
  **nullifier** (not a TTL).
- **Counted-as-recorded:** homomorphic aggregation + threshold ElGamal (default), or a verifiable
  **re-encryption mixnet** with Terelius-Wikström shuffle proofs (for ranked-choice / write-ins).
- **Optional coercion-resistant tiers:** **Selene** (deferred fakeable trackers), **MACI/Semaphore**
  (zk anti-collusion), or full **JCJ/Civitas** anonymous credentials (coercion-resistance at quadratic
  tally cost + untappable-registration assumption).
- **Governance signing:** EIP-712 + EIP-1271 + ERC-6492 (EOA, contract-wallet, and pre-deploy).

---

## Old concept → modern construction

Every invented or unsafe element of the original concept maps to a named, sound replacement.

| Original (2014 concept) | Why it fails | Modern replacement |
|---|---|---|
| `SST` — Social Security Token (SSN-rooted) | SSN is low-entropy, breached, non-revocable → national surveillance honeypot; "hashing an SSN" is reversible | Off-ledger identity proofing only; issue a fresh **≥128-bit unlinkable per-election credential**; the voting layer sees only an "is-eligible" attestation |
| `SPKE` — "Scrambled Prime Key Encryption" | Not a real primitive; security-by-obscurity; reversible | **Exponential ElGamal** + **Chaum-Pedersen ZK proofs**; **verifiable mixnet** for unlinkability |
| `VET`/`AAVET` — one stable token per voter | A stable pseudonym ≠ anonymity; re-linkable via the registration table | **Decouple issuance from casting** (time/order/device); unlinkable Belenios/Semaphore credential; single-use via published **nullifier** |
| "Voter can see their vote on the blockchain" (Step 17) | A transferable **vote-buying / coercion receipt** | Publish only *encrypted* ballots; release *aggregate* tallies after close; verify via Benaloh challenge + a privacy-preserving tracker; optional **Selene** fakeable tracker |
| `BRVC` reusable RFID card + `TTL` anti-reuse | Skimmable/clonable bearer credential; TTL bounds *when*, not *how many times* | Secret stays in a **secure element / client-side**, challenge-response signing (never exported); single-use via a server-side **spent-nullifier set** |
| `RFID-VPU` (one device reads ID *and* mints anon token) | Single point of total de-anonymization | **Separate** the authentication device from the credential-issuance device; neither sees both identity and ballot |
| `PoS` as election authority | Plutocratic capture; probabilistic finality ≠ immutable | Default = authenticated **transparency log** (no chain); if anchoring, **permissioned BFT** with named validators; per-jurisdiction sharding |
| VVPAT optional, handed to voter (Step 18) | Optional/unreconciled paper can't anchor an audit; handing it back is a coercion proof | Paper is the **legal ballot of record**, inspected *before* the electronic cast finalizes, retained behind glass; mandatory **RLA**; paper wins on discrepancy |

---

## Deployment profiles

Pick a profile in the manifest; it's a preset of adapter + parameter choices.

- **`governance` (default, low-stakes):** off-chain gasless EIP-712 signed votes (Snapshot-style),
  pluggable voting-power strategy (token / NFT / quadratic / delegation / allowlist Merkle root) at a
  frozen snapshot block, optional MACI private tier, optional trustless optimistic settlement
  (oSnap/SafeSnap) behind a dispute window + timelock. Bulletin board = `object-store` or `postgres-log`.
- **`society` (verifiable internal election):** Belenios-style credentials + homomorphic ElGamal +
  threshold trustees + `postgres-log` board + independent verifier. Full E2E-V, no chain required.
- **`polling-place` (advanced, software-independent):** everything in `society` **plus** voter-verified
  paper ballots of record + mandatory RLA + endpoint integrity controls (reproducible builds, measured
  boot, chain-of-custody). For supervised, low-coercion, recoverable elections only.

---

## Repository layout (planned)

Monorepo: pnpm + Turborepo (TypeScript) alongside a Cargo workspace (Rust).

```
voting-system-blockchain/
├── README.md                      # this file
├── docs/
│   ├── ORIGINAL_CONCEPT.md        # the preserved 2014 concept
│   ├── THREAT_MODEL.md            # endpoint, registrar, server, trustees, board, validators, network, coercer
│   ├── SCOPE.md                   # each E2E-V guarantee → its primitive; per-profile honest scoping
│   ├── CRYPTO_SPEC.md             # ElGamal / Chaum-Pedersen / DKG / Benaloh / nullifier spec
│   └── ADRs/                      # "No SSN tokens", "Chain is non-load-bearing", "No PoS authority", "Paper is record"
├── crates/                        # Rust workspace (security-critical path)
│   ├── vvp-crypto/                # ElGamal, Chaum-Pedersen NIZKs, Pedersen DKG, Benaloh, nullifiers (+WASM)
│   ├── vvp-mixnet/                # Terelius-Wikström verifiable shuffle (ranked / write-in)
│   ├── vvp-tally/                 # homomorphic aggregation + threshold decryption
│   └── vvp-transcript/            # canonical protobuf/JSON transcript types
├── packages/                      # TypeScript workspace
│   ├── kernel/                    # 5 ports + orchestrator (XState) + ElectionManifest (Zod)
│   ├── bulletin-board/            # postgres-log (default) | object-store | anchor-evm | anchor-cosmos | anchor-bitcoin | conformance
│   ├── transport/                 # VoteTransport port + OffChain(Snapshot)/Evm/L2/Mock adapters; voting-power strategies
│   ├── registrar/                 # Belenios-style credential issuance; Semaphore/JCJ variants
│   └── coordinator/               # lifecycle control plane
├── apps/
│   ├── voter/                     # Next.js 15 + React 19 + Tailwind v4 cast-or-challenge client (WASM crypto)
│   ├── admin/                     # operator console (create election, pick strategy + adapters)
│   └── lab/                       # composition harness + adversary demos (why the original concept fails)
├── verifier/vvp-verify-py/        # Python reference verifier (CLI + WASM) + ElectionGuard-verifier interop
├── rla/arlo-rla/                  # risk-limiting audit tooling (ballot-polling + comparison)
├── contracts/                     # Foundry: minimal anchor contract; OZ Governor + Safe/Zodiac (oSnap)
├── circuits/                      # circom/arkworks: Semaphore, shuffle, MACI (optional tiers)
└── docker/                        # Compose: registrar, casting service, trustee nodes, board adapters, verifier
```

## Roadmap

- **M0 — Scoping & threat model:** `THREAT_MODEL.md`, `SCOPE.md`, ADRs; lock the open questions below.
- **M1 — Crypto core + independent verifier:** `vvp-crypto` (Rust) cross-checked against ElectionGuard
  test vectors; Python reference verifier. *Done when a transcript verifies under both verifiers.*
- **M2 — Kernel, ports & bulletin-board conformance suite.** *Done when the same protocol runs
  byte-identically on in-memory and Postgres boards.*
- **M3 — Registrar + cast-or-challenge voter app + threshold tally.** *Done when a club-style election
  runs and any third party verifies it from the published transcript.*
- **M4 — Paper VVPAT + RLA (software-independence anchor).** *Done when an injected endpoint-flip is
  caught by the RLA against paper.*
- **M5 — Governance / settlement adapters (the "all types of voting" reuse).** *Done when a DAO-style
  proposal runs gasless and settles trustlessly, independently re-derivable.*
- **M6 — Optional coercion-resistant & chain-anchor tiers + adversary lab.**
- **M7 — Independent security review, signed reproducible releases, low-stakes pilot.**

## References

- National Academies of Sciences, Engineering, and Medicine. *Securing the Vote: Protecting American Democracy* (2018).
- Park, Specter, Narula, Rivest. *Going from Bad to Worse: From Internet Voting to Blockchain Voting.* Journal of Cybersecurity 7(1):tyaa025 (2021).
- Specter, Koppel, Weitzner. *The Ballot is Busted Before the Blockchain.* USENIX Security (2020).
- Adida. *Helios: Web-based Open-Audit Voting.* USENIX Security (2008).
- Cortier et al. *Belenios.* / Microsoft *ElectionGuard*. / Clarkson, Chong, Myers, *Civitas*.
- Benaloh. *Simple Verifiable Elections* (cast-or-challenge). Ryan et al., *Selene*. Appel/Stark, *Risk-Limiting Audits*.

---

*The original 2014 concept and its acronym glossary are preserved in [docs/ORIGINAL_CONCEPT.md](docs/ORIGINAL_CONCEPT.md). ;)*
