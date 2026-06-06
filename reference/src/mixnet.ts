// Verifiable re-encryption MIXNET via Sako–Kilian cut-and-choose, made non-interactive
// with Fiat–Shamir. This is the building block true ranked-choice IRV needs: shuffle the
// encrypted ballots so no one can link a voter to their ballot, PROVE the shuffle is a
// genuine permutation + re-encryption (no ballot dropped, duplicated, or altered), then a
// later increment threshold-decrypts the ANONYMIZED ballots and runs public IRV tabulation.
//
// WHY cut-and-choose (and not Terelius–Wikström / Bayer–Groth) for this reference increment:
// its soundness is a one-paragraph transitivity argument and EVERY verifier step is a group-
// element equality or a finite bijection test — no Pedersen CRS, no polynomial/multi-exp
// argument to implement subtly wrong. Re-encryption-shuffle-equivalence is an equivalence
// relation (reflexive; symmetric — negate factors mod N; transitive — compose perms, add
// factors). Each intermediate M_j sits between input L0 and output L; if L is NOT a shuffle of
// L0 then by transitivity at most ONE of the two legs (L0→M_j, M_j→L) is honestly openable, so
// a random challenge bit catches a cheat with probability ≥ ½; t independent Fiat–Shamir-bound
// instances give soundness error 2^-t (t = SECURITY_T = 128 ⇒ 2^-128, with 2^128 grinding cost).
// The accepted price is O(t·n·W) proof size — irrelevant for a reference engine whose job is to
// be obviously correct and to anchor an independent re-implementation.
//
// Privacy (hiding the permutation π = the voter↔ballot link) is COMPUTATIONAL under DDH on
// ristretto255 + the Fiat–Shamir/ROM assumption — the same trust base as the rest of this engine.
// It hides ONLY the input↔output correspondence, NOT n, W, or the multiset of plaintexts (those
// are revealed by the later threshold decryption — the whole point of a mixnet). For each instance
// exactly ONE leg is ever opened, and the discarded M_j are never decrypted, so π stays hidden.
//
// Terelius–Wikström / Bayer–Groth give O(N)-size proofs with ~2^-250 soundness and are the
// documented efficiency UPGRADE for a later increment — after IRV is wired and this verifier has
// an independent re-implementation. This mirrors ranked.ts: a sound PRIMITIVE + independent
// verifier + adversarial tests ship first; the election is wired on top later.
//
// NOT YET AUDITED (pre-audit). Fisher–Yates / scalar-mul here are not constant-time (out of scope
// for a reference engine).

import { sha512 } from '@noble/hashes/sha512';
import { concatBytes, utf8ToBytes } from '@noble/hashes/utils';
import { G, N, mod, mul, randScalar, hashToScalar, inRange, scalarTo32, type Point } from './group.js';
import type { Ciphertext } from './elgamal.js';
import type { Check, VerifyResult } from './verify.js';

/** Fiat–Shamir grinding security: 2^-128 soundness, 2^128 grind. Verifier rejects any t < this. */
export const SECURITY_T = 128;

export type Item = Ciphertext[]; // one ballot = a vector of W component ciphertexts (W fixed list-wide; W=1 degenerate)
export type Reenc = bigint[]; // W re-encryption factors, one per component of one item

export interface OpenLeg {
  perm: number[]; // length n
  factors: Reenc[]; // length n, one Reenc[W] per OUTPUT position of this leg
}

export interface ShuffleProof {
  t: number; // carried so the independent verifier can enforce the SECURITY_T floor
  intermediates: Item[][]; // length t — the committed M_j (bound into Fiat–Shamir)
  openings: OpenLeg[]; // length t — one opened leg per instance. NO bit field (bits are recomputed).
}

export interface ShuffleResult {
  L: Item[];
  proof: ShuffleProof;
}

/** Re-encrypt every component of one item: component w with fresh factor s → (a_w + s·G, b_w + s·pk). */
export function reencItem(pk: Point, item: Item, factors: Reenc): Item {
  return item.map((ct, w) => ({ a: ct.a.add(mul(G, factors[w]!)), b: ct.b.add(mul(pk, factors[w]!)) }));
}

/** output[i] = src[perm[i]] — the ONE permutation convention, identical in prover and verifier. */
export function applyPerm<T>(src: T[], perm: number[]): T[] {
  return perm.map((p) => src[p]!);
}

function u32(n: number): Uint8Array {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

/** A uniform permutation of 0..n-1 via Fisher–Yates seeded by randScalar (NEVER Math.random). */
function fisherYates(n: number): number[] {
  const p = Array.from({ length: n }, (_, i) => i);
  for (let k = n - 1; k > 0; k--) {
    const j = Number(randScalar() % BigInt(k + 1));
    const tmp = p[k]!; p[k] = p[j]!; p[j] = tmp;
  }
  return p;
}

function isPermutation(perm: number[], n: number): boolean {
  if (!Array.isArray(perm) || perm.length !== n) return false;
  const seen = new Array<boolean>(n).fill(false);
  for (const v of perm) {
    if (!Number.isInteger(v) || v < 0 || v >= n || seen[v]) return false; // in-range + distinct + length n ⇒ bijection
    seen[v] = true;
  }
  return true;
}

/**
 * Deterministic Fiat–Shamir challenge bits. Binds the FULL statement (pk, L0, L) AND every
 * committed intermediate M_j — so a prover cannot adapt the M_j to the bits, and tampering any
 * point flips the bits and fails verification. Exported for white-box selftests.
 */
export function shuffleChallengeBits(pk: Point, L0: Item[], L: Item[], intermediates: Item[][], t: number): number[] {
  const points: Point[] = [pk];
  const pushFlat = (list: Item[]): void => {
    for (const item of list) for (const ct of item) { points.push(ct.a, ct.b); }
  };
  pushFlat(L0);
  pushFlat(L);
  for (const M of intermediates) pushFlat(M); // i-then-w-then-(a,b) order, each M_j in sequence
  const c = scalarTo32(hashToScalar('mixnet-shuffle', points)); // unique label; can't alias other proof types
  const blockDigest = (b: number): Uint8Array =>
    sha512(concatBytes(utf8ToBytes('vvp-fs-v1'), utf8ToBytes('mixnet-shuffle-bits'), c, u32(b)));
  const bits: number[] = [];
  let block = 0;
  let digest = blockDigest(0);
  for (let j = 0; j < t; j++) {
    const b = Math.floor(j / 512); // 512 bits per sha512 block — supports any t
    if (b !== block) { block = b; digest = blockDigest(b); }
    const idx = j % 512;
    bits.push((digest[idx >> 3]! >> (idx & 7)) & 1); // LSB-first within each byte
  }
  return bits;
}

/**
 * Prove (and produce) a re-encryption shuffle of L0. The secret permutation π and re-encryption
 * factors are the witness; the returned L is the public shuffled output and proof is the NIZK.
 * Trustee secrets are not involved — anyone holding the ciphertexts can shuffle.
 */
export function shuffleProve(pk: Point, L0: Item[], t: number = SECURITY_T): ShuffleResult {
  const n = L0.length;
  if (n < 1) throw new Error('shuffle requires ≥ 1 item');
  const W = L0[0]!.length;
  if (W < 1 || !L0.every((it) => it.length === W)) throw new Error('items must share a fixed width W ≥ 1');

  const pi = fisherYates(n);
  const rho: bigint[][] = Array.from({ length: n }, () => Array.from({ length: W }, () => randScalar()));
  const L: Item[] = applyPerm(L0, pi).map((it, i) => reencItem(pk, it, rho[i]!)); // L[i] = reenc(L0[π[i]], ρ[i])

  const intermediates: Item[][] = [];
  const legs: OpenLeg[][] = []; // legs[j] = [ {σ_j, α_j} , {τ_j, β_j} ]  (we keep both, open one)
  for (let j = 0; j < t; j++) {
    const sigma = fisherYates(n);
    const alpha: bigint[][] = Array.from({ length: n }, () => Array.from({ length: W }, () => randScalar()));
    const M: Item[] = applyPerm(L0, sigma).map((it, i) => reencItem(pk, it, alpha[i]!)); // M[i] = reenc(L0[σ[i]], α[i])

    const inv = new Array<number>(n);
    for (let i = 0; i < n; i++) inv[sigma[i]!] = i;
    const tau = pi.map((p) => inv[p]!); // σ[τ[i]] = π[i] ⇒ M[τ[i]] carries L[i]'s plaintext
    // β[i][w] = ρ[i][w] − α[τ[i]][w]  ⇒  reenc(M[τ[i]], β[i]) === L[i]
    const beta: bigint[][] = Array.from({ length: n }, (_, i) =>
      Array.from({ length: W }, (_, w) => mod(rho[i]![w]! - alpha[tau[i]!]![w]!, N)));

    intermediates.push(M);
    legs.push([{ perm: sigma, factors: alpha }, { perm: tau, factors: beta }]);
  }

  const bits = shuffleChallengeBits(pk, L0, L, intermediates, t);
  const openings: OpenLeg[] = bits.map((b, j) => legs[j]![b]!); // bit 0 → (σ,α) opens L0→M_j; bit 1 → (τ,β) opens M_j→L
  return { L, proof: { t, intermediates, openings } };
}

/**
 * Independent verifier: re-checks a shuffle proof from the public values alone, trusting nothing
 * about who produced it. ALWAYS returns a verdict (never throws); results is always null (a shuffle
 * has no tally). Matches the verify.ts house style.
 */
export function verifyShuffle(pk: Point, L0: Item[], L: Item[], proof: ShuffleProof): VerifyResult {
  const checks: Check[] = [];
  try {
    // S0 — shape gate (reject, never pad)
    const t = proof.t;
    if (!(Number.isInteger(t) && t >= SECURITY_T)) {
      checks.push({ name: `Proof t ≥ SECURITY_T (${SECURITY_T})`, ok: false, detail: `t=${t}` });
      return { ok: false, checks, results: null };
    }
    const n = L0.length;
    if (!(n >= 1 && Array.isArray(L) && L.length === n
      && Array.isArray(proof.intermediates) && proof.intermediates.length === t
      && Array.isArray(proof.openings) && proof.openings.length === t)) {
      checks.push({ name: 'Shape: n ≥ 1, |L| = |L0|, t intermediates and t openings', ok: false });
      return { ok: false, checks, results: null };
    }
    const W = L0[0]!.length;
    const widthOk = W >= 1
      && L0.every((it) => it.length === W)
      && L.every((it) => it.length === W)
      && proof.intermediates.every((M) => Array.isArray(M) && M.length === n && M.every((it) => it.length === W))
      && proof.openings.every((op) => Array.isArray(op.perm) && op.perm.length === n
        && Array.isArray(op.factors) && op.factors.length === n && op.factors.every((f) => Array.isArray(f) && f.length === W));
    checks.push({ name: `Shuffle proof shape (n=${n}, W=${W}, t=${t}; uniform width; no ragged arrays)`, ok: widthOk });
    if (!widthOk) return { ok: false, checks, results: null };

    // S1 — every revealed factor is a canonical scalar in [0, N)
    const scalarsOk = proof.openings.every((op) => op.factors.every((f) => f.every((s) => inRange(s))));
    checks.push({ name: 'All revealed re-encryption factors are canonical scalars (0 ≤ s < N)', ok: scalarsOk });
    if (!scalarsOk) return { ok: false, checks, results: null };

    // S2 — every opened permutation is a true bijection of 0..n-1 (no drops, no duplicates)
    const permsOk = proof.openings.every((op) => isPermutation(op.perm, n));
    checks.push({ name: 'Every opened permutation is a true bijection of 0..n-1', ok: permsOk });
    if (!permsOk) return { ok: false, checks, results: null };

    // S3 — recompute the challenge bits independently from (pk, L0, L, all M_j); trust no value in the proof
    const bits = shuffleChallengeBits(pk, L0, L, proof.intermediates, t);

    // S4 — every opened leg must be an EXACT permutation + re-encryption of its endpoint, on BOTH
    //      components of ALL W components of ALL n items, for ALL t instances.
    let reencOk = true;
    outer:
    for (let j = 0; j < t; j++) {
      const M = proof.intermediates[j]!;
      const op = proof.openings[j]!;
      const src = bits[j] === 0 ? L0 : M; // bit 0 opens L0→M_j (σ,α); bit 1 opens M_j→L (τ,β)
      const dst = bits[j] === 0 ? M : L;
      const permuted = applyPerm(src, op.perm); // same convention as the prover: output[i] = src[perm[i]]
      for (let i = 0; i < n; i++) {
        const cand = reencItem(pk, permuted[i]!, op.factors[i]!);
        const d = dst[i]!;
        for (let w = 0; w < W; w++) {
          if (!cand[w]!.a.equals(d[w]!.a) || !cand[w]!.b.equals(d[w]!.b)) { reencOk = false; break outer; }
        }
      }
    }
    checks.push({ name: 'Every opened leg is an exact permutation + re-encryption of its endpoint', ok: reencOk });

    return { ok: checks.every((c) => c.ok), checks, results: null };
  } catch (err) {
    checks.push({ name: 'Shuffle proof is well-formed (no exception)', ok: false, detail: String(err) });
    return { ok: false, checks, results: null };
  }
}

/** Thin boolean wrapper for reuse inside a future IRV transcript verifier. */
export function verifyShuffleBool(pk: Point, L0: Item[], L: Item[], proof: ShuffleProof): boolean {
  return verifyShuffle(pk, L0, L, proof).ok;
}
