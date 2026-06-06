// Zero-knowledge proofs — the heart of "verify everything, reveal nothing".
//
//  1. proveBit:        a non-interactive disjunctive Chaum–Pedersen proof that a
//                      ciphertext encrypts 0 OR 1 — without revealing which.
//                      This stops ballot stuffing: a vote of "2" (or 1000) can
//                      never produce a valid proof.
//
//  2. proveDecryption: a Chaum–Pedersen proof that a trustee computed its
//                      decryption share correctly (log_g(pub) == log_a(share)),
//                      without revealing the secret key. This stops a corrupt
//                      trustee from faking the count.
//
// Both are made non-interactive with the Fiat–Shamir transform.

import { G, H, N, mod, mul, randScalar, hashToScalar, inRange, type Point } from './group.js';
import type { Ciphertext } from './elgamal.js';

// ---------------------------------------------------------------------------
// 1. Ballot validity: proof that (a, b) encrypts m ∈ {0, 1} under key h.
//
// Statement i (i ∈ {0,1}) asserts the DH-equality  log_g(a) = log_h(B_i) = r,
// where B_0 = b  and  B_1 = b - g  (additive notation). Exactly one holds.
// We run a real Chaum–Pedersen proof for the true branch and simulate the
// false branch (Cramer–Damgård–Schoenmakers OR-composition).
// ---------------------------------------------------------------------------

export interface BitProof {
  T0g: Point; T0h: Point; // commitments, branch 0
  T1g: Point; T1h: Point; // commitments, branch 1
  c0: bigint; c1: bigint; // sub-challenges (c0 + c1 must equal the FS challenge)
  s0: bigint; s1: bigint; // responses
}

export function proveBit(h: Point, ct: Ciphertext, m: 0 | 1, r: bigint): BitProof {
  const { a, b } = ct;
  const B: [Point, Point] = [b, b.subtract(G)]; // B[0] = b, B[1] = b - g
  const real = m;
  const fake = (1 - m) as 0 | 1;

  // --- simulate the FALSE branch: pick c_fake, s_fake, derive commitments ---
  const cFake = randScalar();
  const sFake = randScalar();
  const TgFake = mul(G, sFake).subtract(mul(a, cFake)); // g^{s} · a^{-c}
  const ThFake = mul(h, sFake).subtract(mul(B[fake], cFake)); // h^{s} · B^{-c}

  // --- commit honestly on the TRUE branch ---
  const t = randScalar();
  const TgReal = mul(G, t);
  const ThReal = mul(h, t);

  const Tg: Point[] = [];
  const Th: Point[] = [];
  Tg[real] = TgReal; Th[real] = ThReal;
  Tg[fake] = TgFake; Th[fake] = ThFake;

  // Fiat–Shamir challenge binds the statement and all commitments.
  const c = hashToScalar('ballot-bit', [h, a, b, Tg[0]!, Th[0]!, Tg[1]!, Th[1]!]);

  const cReal = mod(c - cFake, N);
  const sReal = mod(t + cReal * r, N);

  const cArr: bigint[] = [];
  const sArr: bigint[] = [];
  cArr[real] = cReal; sArr[real] = sReal;
  cArr[fake] = cFake; sArr[fake] = sFake;

  return {
    T0g: Tg[0]!, T0h: Th[0]!, T1g: Tg[1]!, T1h: Th[1]!,
    c0: cArr[0]!, c1: cArr[1]!, s0: sArr[0]!, s1: sArr[1]!,
  };
}

export function verifyBit(h: Point, ct: Ciphertext, p: BitProof): boolean {
  const { a, b } = ct;
  const B: [Point, Point] = [b, b.subtract(G)];

  // Reject non-canonical scalar encodings (≥ N) so the proof object is not
  // malleable in its integer representation (audit hardening).
  if (![p.c0, p.c1, p.s0, p.s1].every(inRange)) return false;

  const c = hashToScalar('ballot-bit', [h, a, b, p.T0g, p.T0h, p.T1g, p.T1h]);

  // The two sub-challenges must sum to the bound challenge.
  if (mod(p.c0 + p.c1, N) !== c) return false;

  // Branch 0:  g^{s0} == T0g · a^{c0}   and   h^{s0} == T0h · B0^{c0}
  if (!mul(G, p.s0).equals(p.T0g.add(mul(a, p.c0)))) return false;
  if (!mul(h, p.s0).equals(p.T0h.add(mul(B[0], p.c0)))) return false;

  // Branch 1:  g^{s1} == T1g · a^{c1}   and   h^{s1} == T1h · B1^{c1}
  if (!mul(G, p.s1).equals(p.T1g.add(mul(a, p.c1)))) return false;
  if (!mul(h, p.s1).equals(p.T1h.add(mul(B[1], p.c1)))) return false;

  return true;
}

// ---------------------------------------------------------------------------
// 2. Correct decryption: proof that  log_g(pub) == log_a(share) == x.
// ---------------------------------------------------------------------------

export interface DecProof {
  Tg: Point;
  Ta: Point;
  c: bigint;
  s: bigint;
}

export function proveDecryption(a: Point, pub: Point, share: Point, x: bigint): DecProof {
  const t = randScalar();
  const Tg = mul(G, t);
  const Ta = mul(a, t);
  const c = hashToScalar('decryption', [G, a, pub, share, Tg, Ta]);
  const s = mod(t + c * x, N);
  return { Tg, Ta, c, s };
}

export function verifyDecryption(a: Point, pub: Point, share: Point, p: DecProof): boolean {
  if (!inRange(p.c) || !inRange(p.s)) return false;
  const c = hashToScalar('decryption', [G, a, pub, share, p.Tg, p.Ta]);
  if (c !== p.c) return false;
  if (!mul(G, p.s).equals(p.Tg.add(mul(pub, p.c)))) return false; // g^s == Tg · pub^c
  if (!mul(a, p.s).equals(p.Ta.add(mul(share, p.c)))) return false; // a^s == Ta · share^c
  return true;
}

// ---------------------------------------------------------------------------
// 3. Exactly-one-selected: proof that the homomorphic SUM of a contest's
//    per-candidate ciphertexts encrypts exactly 1 — i.e. the voter selected
//    exactly one candidate. Combined with each ciphertext being a 0/1 bit
//    (proveBit), this pins the ballot to a single valid selection.
//
//    The prover knows R = Σ r_j (the sum of the per-candidate randomness), so
//    this is a Chaum–Pedersen proof that  agg.a = g^R  and  agg.b − g = h^R.
// ---------------------------------------------------------------------------

export interface SumProof {
  Tg: Point;
  Th: Point;
  c: bigint;
  s: bigint;
}

/**
 * Generalized: proof that the homomorphic SUM encrypts exactly L (the selection limit) —
 * i.e. the voter selected exactly L candidates. L is bound into the challenge (via L·G) and
 * the verification target, so a proof for L cannot be reused as a proof for L'. Combined with
 * each ciphertext being a 0/1 bit, this pins the ballot to exactly L valid selections.
 */
export function proveSumEqual(h: Point, agg: Ciphertext, R: bigint, L: number): SumProof {
  const t = randScalar();
  const Tg = mul(G, t);
  const Th = mul(h, t);
  const c = hashToScalar('sum-eq', [h, agg.a, agg.b, mul(G, BigInt(L)), Tg, Th]);
  const s = mod(t + c * R, N);
  return { Tg, Th, c, s };
}

export function verifySumEqual(h: Point, agg: Ciphertext, p: SumProof, L: number): boolean {
  if (!inRange(p.c) || !inRange(p.s)) return false;
  const target = agg.b.subtract(mul(G, BigInt(L))); // equals h^R iff Σ votes == L
  const c = hashToScalar('sum-eq', [h, agg.a, agg.b, mul(G, BigInt(L)), p.Tg, p.Th]);
  if (c !== p.c) return false;
  if (!mul(G, p.s).equals(p.Tg.add(mul(agg.a, p.c)))) return false; // g^s == Tg · agg.a^c
  if (!mul(h, p.s).equals(p.Th.add(mul(target, p.c)))) return false; // h^s == Th · (agg.b − L·g)^c
  return true;
}

/** Exactly-one is the L=1 special case (plurality / single-choice). */
export const proveSumOne = (h: Point, agg: Ciphertext, R: bigint): SumProof => proveSumEqual(h, agg, R, 1);
export const verifySumOne = (h: Point, agg: Ciphertext, p: SumProof): boolean => verifySumEqual(h, agg, p, 1);

// ---------------------------------------------------------------------------
// 4. ElGamal↔Pedersen consistency (the everlasting-privacy binding).
//
//    Proves knowledge of (v, r, d) such that, SIMULTANEOUSLY:
//        a = r·G                      (ElGamal: the randomness commitment)
//        b = v·G + r·PK               (ElGamal: encrypts v under joint key PK)
//        C = v·G + d·H                (Pedersen: perfectly-hiding commitment to v)
//    i.e. the perfectly-hiding commitment C and the verifiable ciphertext (a,b) encode the SAME v.
//
//    This is a generalized-Schnorr / Maurer linear-relation proof for the homomorphism
//    φ(v,r,d) = (r·G, v·G + r·PK, v·G + d·H). The SINGLE shared response `zv` across the b-equation
//    and the C-equation is the entire cross-binding — it forces the same v in both. Combined with the
//    disjunctive bit-proof on (a,b) (§1), it follows that C commits to a value in {0,1}.
//
//    SCOPE: this binds C to the verifiable ballot (computational soundness under unknown dlog_G(H));
//    the everlasting/UNCONDITIONAL property is the *hiding* of C, not this proof. The proof is HVZK,
//    so publishing it leaks nothing about (v,r,d) and does not weaken C's perfect hiding.
// ---------------------------------------------------------------------------

export interface ConsistencyProof {
  Aa: Point; // kr·G
  Ab: Point; // kv·G + kr·PK
  Ac: Point; // kv·G + kd·H
  zv: bigint; // kv + e·v   (the SHARED response — binds the same v in b and C)
  zr: bigint; // kr + e·r
  zd: bigint; // kd + e·d
}

const CONSISTENCY_LABEL = 'everlasting-consistency-v1';

/** Prove the Pedersen commitment C = v·G + d·H commits to the same v that (a,b) encrypts under pk. */
export function proveConsistency(pk: Point, ct: Ciphertext, C: Point, v: 0 | 1, r: bigint, d: bigint): ConsistencyProof {
  const { a, b } = ct;
  const kv = randScalar();
  const kr = randScalar();
  const kd = randScalar();
  const Aa = mul(G, kr);
  const Ab = mul(G, kv).add(mul(pk, kr));
  const Ac = mul(G, kv).add(mul(H, kd));
  const e = hashToScalar(CONSISTENCY_LABEL, [G, H, pk, a, b, C, Aa, Ab, Ac]);
  return {
    Aa, Ab, Ac,
    zv: mod(kv + e * BigInt(v), N),
    zr: mod(kr + e * r, N),
    zd: mod(kd + e * d, N),
  };
}

/** Verify the ElGamal↔Pedersen consistency proof. Never trusts a transmitted challenge; recomputes e. */
export function verifyConsistency(pk: Point, ct: Ciphertext, C: Point, p: ConsistencyProof): boolean {
  const { a, b } = ct;
  // Reject non-canonical scalar encodings (≥ N) so the proof object is not malleable (audit hardening).
  if (![p.zv, p.zr, p.zd].every(inRange)) return false;
  const e = hashToScalar(CONSISTENCY_LABEL, [G, H, pk, a, b, C, p.Aa, p.Ab, p.Ac]);
  // a = r·G            :  zr·G == Aa + e·a
  if (!mul(G, p.zr).equals(p.Aa.add(mul(a, e)))) return false;
  // b = v·G + r·PK     :  zv·G + zr·PK == Ab + e·b
  if (!mul(G, p.zv).add(mul(pk, p.zr)).equals(p.Ab.add(mul(b, e)))) return false;
  // C = v·G + d·H      :  zv·G + zd·H == Ac + e·C   (SAME zv ⇒ same v as in b)
  if (!mul(G, p.zv).add(mul(H, p.zd)).equals(p.Ac.add(mul(C, e)))) return false;
  return true;
}
