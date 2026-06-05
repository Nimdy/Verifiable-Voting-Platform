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
npm run demo       # full election + four insider attacks, all caught
npm run selftest   # 2000 randomized soundness trials
npm run typecheck
```

## What it demonstrates

> **Verify everything. Reveal nothing. No insider can cheat unseen.**

- **Encrypted ballots** — exponential ElGamal over ristretto255 (`@noble/curves`).
- **Ballot validity (ZK)** — a disjunctive Chaum–Pedersen proof that each ballot
  encrypts `0` or `1`, without revealing which. Stuffing a `10` is impossible.
- **Distributed trust** — the secret key is split across N trustees; no single one can
  decrypt any ballot. Only the **total** is ever decrypted, with a correctness proof.
- **Public bulletin board** — an append-only Merkle log; altering any ballot changes
  the root and is detected.
- **Independent verifier** — rechecks the entire public transcript from scratch,
  trusting nothing about who produced it.

The demo then plays the insider and the verifier catches every attack: a flipped
ballot, an out-of-range vote, a forged proof, and a rigged tally.

## What this PoC deliberately does NOT do yet

These are tracked on the [roadmap](../docs/ROADMAP.md) (M1/M3), not oversights:

- **Eligibility & one-vote-per-voter** — no registrar, credentials, or nullifiers yet;
  ballots here are not bound to an eligible identity (so they are replayable). → M3.
- **k-of-n threshold** — uses simple N-of-N additive key sharing; real threshold
  decryption needs Pedersen DKG so the election survives an offline trustee. → M1/M3.
- **Cast-as-intended** — no Benaloh cast-or-challenge flow yet. → M3.
- **Input validation on deserialization** — points are passed in-process, not parsed
  from untrusted bytes with full validation. → M1.
- **Production hardening** — Merlin/STROBE transcripts, constant-time review, an
  external audit. → M1/M7.

## Files

| File | Role |
|------|------|
| `src/group.ts` | ristretto255 group + scalar helpers, Fiat–Shamir hashing |
| `src/elgamal.ts` | exponential ElGamal, distributed keys, homomorphic add, decryption |
| `src/proofs.ts` | disjunctive Chaum–Pedersen (ballot validity) + decryption-correctness proofs |
| `src/bulletin.ts` | append-only Merkle bulletin board |
| `src/codec.ts` | canonical ballot serialization |
| `src/election.ts` | runs an election, produces the public transcript |
| `src/verify.ts` | the independent verifier |
| `src/demo.ts` | end-to-end demo + insider attacks |
| `src/selftest.ts` | randomized soundness tests |
