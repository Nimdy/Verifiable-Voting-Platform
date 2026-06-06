# Reference implementation (stage-1 proof of concept)

An executable, end-to-end-verifiable election in ~600 lines of TypeScript. It exists
to **prove the thesis runs** and to serve as the executable spec the production core
(Rust → WASM) and independent verifier (Python) are validated against.

> ⚠️ **Not audited. Not for any consequential election.** This is a learning/validation
> artifact. See [../SECURITY.md](../SECURITY.md) and [../docs/SCOPE.md](../docs/SCOPE.md).

## Run it

```bash
cd reference
npm install
npm run demo       # multi-candidate election + 8 insider attacks, all caught
npm run selftest   # ~4,700 randomized soundness trials
npm run verify -- out/transcript.json   # re-verify the published plurality transcript from the file ALONE
npm run verify -- out/ranked.json       # …and the ranked-choice (Borda) transcript
npm run typecheck
```

## What it demonstrates

> **Verify everything. Reveal nothing. No insider can cheat unseen.**

- **Multi-candidate ballots** — pick 1 of K candidates. Each candidate ciphertext is
  proven `0`/`1` (disjunctive Chaum–Pedersen) **and** an *exactly-one-selected* proof
  pins the ballot to a single choice — so undervotes and overvotes are rejected.
- **Eligibility & one-vote-per-voter** — Belenios-style credentials sign each ballot;
  a published eligible roll + a single-use nullifier block ineligible and double votes.
- **Registrar separation (privacy)** — a separate registrar holds the identity↔credential
  map privately and publishes only an identity-decorrelated roll; ballots are published in
  credential-sorted order, so no single party links a person to their **vote**. (The registrar
  alone still learns *turnout* — who voted — but never how; hiding turnout is an M3+ goal.)
- **k-of-n threshold trust** — the secret key is Shamir-shared across n trustees; **any
  k** can jointly decrypt the totals (surviving offline/faulty trustees), and no single
  trustee — nor any coalition smaller than k — can read a ballot. Each decryption share
  carries a correctness proof checked against keys recomputed from public commitments.
- **Cast-or-challenge (Benaloh)** — prepare a ballot, then either *challenge* it (reveal
  the randomness, audit it, and permanently discard it) or *cast* it (randomness stays
  secret). A challenged ballot can never be cast, so a cheating device can't predict an audit.
- **Hierarchical, tagged ballots** — an election is a tree of contests (parent groups →
  drill-down leaf contests) with tags; each leaf is an independently verifiable sub-election,
  and `verifyStructured` authenticates the whole bundle against the spec (no omit/duplicate/relabel).
- **Ranked-choice (Borda)** — full ranked elections: each ballot is a K×K **permutation matrix** of
  encrypted bits (every row & column sums to 1), and the **Borda** tally is homomorphic + k-of-n
  threshold-decrypted — no mixnet. *(True IRV elimination via a verifiable mixnet: #49.)*
- **Public bulletin board** — an append-only RFC-6962 Merkle log, context-bound to the
  election so ballots can't be replayed elsewhere; altering any ballot changes the root.
- **Independent verifier** — rechecks the entire public transcript from scratch, and
  **always returns a verdict** (never throws), even on malformed input.

The demo then plays the insider and the verifier catches every attack: a flipped
ballot, an out-of-range vote, a forged proof, and a rigged tally.

## What this PoC deliberately does NOT do yet

These are tracked on the [roadmap](../docs/ROADMAP.md) (M1/M3), not oversights:

- **Networked casting service** — the cast-or-challenge session (spoil-then-revote) is
  modeled in `session.ts`, but a real deployment wires it into a networked casting
  service with persisted per-voter state. → M3.
- **Networked registrar & full registrar-integrity** — the identity↔credential *privacy*
  separation is modeled (`registrar.ts`), but the networked registrar/casting services and a
  voter-contributed credential part (for full "safe if registrar OR server is honest" integrity)
  remain. → M3+.
- **Distributed DKG ceremony** — k-of-n threshold sharing is implemented, but the
  *coefficient sampling* is simulated in one process; a real deployment runs the
  multi-party DKG so no single machine ever sees the secret. → M3.
- **Input validation on deserialization** — points are passed in-process, not parsed
  from untrusted bytes with full validation. → M1.
- **Production hardening** — Merlin/STROBE transcripts, constant-time review, an
  external audit. → M1/M7.

## Files

| File | Role |
|------|------|
| `src/group.ts` | ristretto255 group + scalar helpers, Fiat–Shamir hashing |
| `src/elgamal.ts` | exponential ElGamal, distributed keys, homomorphic add, decryption |
| `src/proofs.ts` | Chaum–Pedersen bit / decryption / exactly-one-selected proofs |
| `src/credentials.ts` | Belenios-style voter credentials (Schnorr signatures) |
| `src/registrar.ts` | registration authority: identity↔credential separation |
| `src/threshold.ts` | k-of-n Pedersen DKG, Feldman commitments, Lagrange combine |
| `src/bulletin.ts` | append-only RFC-6962 Merkle bulletin board |
| `src/codec.ts` | canonical, context-bound ballot serialization |
| `src/election.ts` | runs a multi-candidate election; encrypt/audit a selection |
| `src/session.ts` | cast-or-challenge (Benaloh) voting session |
| `src/structured.ts` | hierarchical, tagged multi-contest elections + bundle verification |
| `src/ranked.ts` | ranked-choice ballots: permutation-matrix validity + homomorphic Borda |
| `src/mixnet.ts` | verifiable re-encryption shuffle (Sako–Kilian cut-and-choose) — the primitive for true IRV |
| `src/verify.ts` | the independent verifier (always returns a verdict) |
| `src/transcript-json.ts` | canonical JSON (de)serialization of a transcript (plurality **and** ranked) |
| `src/verify-cli.ts` | standalone CLI: re-verify a plurality or ranked transcript from the public record alone |
| `src/demo.ts` | end-to-end demo + seven insider attacks |
| `src/selftest.ts` | randomized soundness tests (~4,500 trials) |
