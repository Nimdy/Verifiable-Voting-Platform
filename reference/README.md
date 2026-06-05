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
npm run verify -- out/transcript.json   # re-verify the published transcript from the file ALONE
npm run typecheck
```

## What it demonstrates

> **Verify everything. Reveal nothing. No insider can cheat unseen.**

- **Multi-candidate ballots** — pick 1 of K candidates. Each candidate ciphertext is
  proven `0`/`1` (disjunctive Chaum–Pedersen) **and** an *exactly-one-selected* proof
  pins the ballot to a single choice — so undervotes and overvotes are rejected.
- **Eligibility & one-vote-per-voter** — Belenios-style credentials sign each ballot;
  a published eligible roll + a single-use nullifier block ineligible and double votes.
- **k-of-n threshold trust** — the secret key is Shamir-shared across n trustees; **any
  k** can jointly decrypt the totals (surviving offline/faulty trustees), and no single
  trustee — nor any coalition smaller than k — can read a ballot. Each decryption share
  carries a correctness proof checked against keys recomputed from public commitments.
- **Cast-or-challenge (Benaloh)** — prepare a ballot, then either *challenge* it (reveal
  the randomness, audit it, and permanently discard it) or *cast* it (randomness stays
  secret). A challenged ballot can never be cast, so a cheating device can't predict an audit.
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
- **Registrar identity-separation** — credentials are pseudonymous but issued in-process;
  the real Belenios split (registrar ≠ casting server, identity proofing off-ledger) is M3.
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
| `src/threshold.ts` | k-of-n Pedersen DKG, Feldman commitments, Lagrange combine |
| `src/bulletin.ts` | append-only RFC-6962 Merkle bulletin board |
| `src/codec.ts` | canonical, context-bound ballot serialization |
| `src/election.ts` | runs a multi-candidate election; encrypt/audit a selection |
| `src/session.ts` | cast-or-challenge (Benaloh) voting session |
| `src/verify.ts` | the independent verifier (always returns a verdict) |
| `src/transcript-json.ts` | canonical JSON (de)serialization of a published transcript |
| `src/verify-cli.ts` | standalone CLI: re-verify a transcript file from the public record alone |
| `src/demo.ts` | end-to-end demo + seven insider attacks |
| `src/selftest.ts` | randomized soundness tests (~4,500 trials) |
