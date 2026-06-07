// ⚠️ EXPERIMENTAL — Terelius–Wikström O(N) proof of shuffle. NOT AUDITED. NOT THE DEFAULT. (ADR-0012)
//
// This is the O(N) UPGRADE PATH for the verifiable re-encryption mixnet. The shipping, default mixnet is
// the Sako–Kilian cut-and-choose in `mixnet.ts` — a one-paragraph transitivity argument where every verifier
// step is a group equality or a finite bijection test. THIS module trades that by-hand obviousness for an
// O(N)-size proof (vs O(t·N)), at the cost of an intricate interior (a product/permutation argument).
//
// READ THIS BEFORE TRUSTING IT. A proof of shuffle is the most soundness-treacherous primitive in the field:
// the 2019 SwissPost/Scytl break was a MISSING CHECK in exactly this kind of proof that PASSED expert audit.
// This implementation is held to the project's bars (an independent byte-identical Python verifier + an
// adversarial test battery incl. the four known attack classes), but cross-verification + in-house review is
// NOT an external audit, and the soundness-critical interior is hand-rolled. So:
//   • It ships EXPERIMENTAL and OPT-IN. The default IRV/mix path stays Sako–Kilian (`mixnet.ts`) until this
//     has (a) the interior cross-checked against Verificatum's documented equations and (b) an EXTERNAL audit.
//   • For production, use an externally-audited mixnet (Verificatum). Do not use this module for a real election.
//
// CONSTRUCTION (Terelius–Wikström / Wikström commitment-consistent, non-interactive via vvp-fs-v1):
//   1. Permutation commitment, BEFORE any challenge (this is what stops an adaptive prover — see note below):
//        c_i = h_{π(i)} + r_i·H              (h_1..h_n = NUMS generator vector; H = pinned Pedersen base)
//   2. Fiat–Shamir challenge vector e = (e_1..e_n) bound to (pk, CRS, L0, L, c).
//   3. The verifier-computable D = Σ_i e_i·c_i = Σ_j g_j·h_j + r_D·H, where g_j = Σ_{i:π(i)=j} e_i are the
//      h-basis weights (= e_{π⁻¹(j)} for a genuine permutation). Prover commits Γ_j = g_j·G + γ_j·H.
//   4. ONE combined generalized-Schnorr proves, sharing the SAME committed g_j:  (a) D opens to Σ g_j h_j
//      (binds g to the pre-committed permutation c);  (b) Γ_j = g_j·G + γ_j·H;  (c) per component w the
//      re-encryption multi-exponentiation  Σ_i e_i·L[i].a_w = Σ_j g_j·L0[j].a_w + R_w·G  and  …b_w … = … + R_w·pk.
//   5. A product argument proves the multiset {g_j} = {e_i} (⇒ π is a genuine permutation, not just row-sums):
//      partial products A_k = (∏_{j≤k}(g_j − x))·G + ŝ_k·H, each step a committed-multiplication Schnorr
//      (A_k from A_{k-1} and Γ_k−x·G), endpoints A_0↦1 and A_n↦∏(e_i−x) (the verifier computes the target).
//
// WHY c MUST PRECEDE e (the soundness crux): if the prover committed g only AFTER seeing e, it could pick,
// among the n! permutations, a lucky one satisfying the single multi-exp equation for that e — and n! ≫ N once
// n>~57, so the union bound fails. Committing π (via c) before e removes the adaptive choice; the cross-basis
// step (4a) then forces the committed g to be the weights of that fixed c.
//
// SOUNDNESS (honest): SINGLE-INSTANCE — NO t-repetition, NO SECURITY_T floor. Error ≈ (2n+c)/N_order ≈
// 2^-128…2^-250 for realistic n, from the field size + a COMPLETE Fiat–Shamir transcript (every commitment
// absorbed before the challenge that uses it). Privacy of π is COMPUTATIONAL under DDH + FS/ROM, as elsewhere.
//
// Pre-audit; not constant-time. See ADR-0012 and docs/CRYPTO_REVIEW.md.

import { sha512 } from '@noble/hashes/sha512';
import { concatBytes, utf8ToBytes, bytesToHex } from '@noble/hashes/utils';
import { RistrettoPoint } from '@noble/curves/ed25519';
import { G, H, N, ZERO, mod, mul, randScalar, hashToScalar, inRange, scalarFromDecimal, scalarTo32, pointToHex, pointFromHex, type Point } from './group.js';
import type { Ciphertext } from './elgamal.js';
import type { Item, Reenc } from './mixnet.js';
import type { Check, VerifyResult } from './verify.js';

// --- NUMS generator vector (the binding root; byte-identical in @noble and libsodium) -------------------
// h_i = ristretto255 from_hash(sha512("vvp-tw-gen-v1|" + i)), the same RFC-9496 one-way map used for H.
// The verifier RE-DERIVES these from the label scheme and NEVER reads generators from a proof — a generator
// vector with a known discrete-log relation is exactly how a permutation commitment opens to a non-permutation.
const GEN_LABEL = 'vvp-tw-gen-v1|';
const GEN0_HEX = '805862570f1accee574731ffb63f498440e324a6bb3c6860902a8e393f4c067e';
const GEN1_HEX = 'd68b9a3ca482359610600caac1348fc92bce55ff7bc447aa5eaa43023811406f';

function deriveGen(i: number): Point {
  return RistrettoPoint.hashToCurve(sha512(utf8ToBytes(GEN_LABEL + i.toString())));
}
// Fail closed at module load: a wrong/backdoored hashToCurve breaks the binding root silently otherwise.
if (bytesToHex(deriveGen(0).toRawBytes()) !== GEN0_HEX || bytesToHex(deriveGen(1).toRawBytes()) !== GEN1_HEX) {
  throw new Error('mixnet-tw: NUMS generator vector does not match pinned constants');
}

/** Re-derive h_1..h_n (indices 0..n-1) and fail closed if any collides with G/H/ZERO or another h_j. */
export function generatorVector(n: number): Point[] {
  const hs: Point[] = [];
  const seen = new Set<string>();
  for (let i = 0; i < n; i++) {
    const h = deriveGen(i);
    const hex = pointToHex(h);
    if (h.equals(G) || h.equals(ZERO) || h.equals(H) || seen.has(hex)) {
      throw new Error(`mixnet-tw: degenerate generator at index ${i}`);
    }
    seen.add(hex);
    hs.push(h);
  }
  return hs;
}

// --- Pedersen commitment in base (G, H): Com(v; r) = v·G + r·H -----------------------------------------
const ped = (v: bigint, r: bigint): Point => mul(G, v).add(mul(H, r));

// --- generalized-Schnorr committed-multiplication proof (the product-chain step) -----------------------
//
// Proves, given X = a·G + rx·H and any base point Y and Z = a·Y + rz·H, knowledge of (a, rx, rz) — i.e. that
// Z equals a·Y blinded, where a is the SAME value committed in X (the shared response z_a is the binding).
// Used with X = A_{k-1} (commits P_{k-1}), Y = Γ_k − x·G (commits g_k−x), Z = A_k (commits P_{k-1}·(g_k−x)).
export interface MulProof { T1: string; T2: string; za: string; zrx: string; zrz: string; }
const MUL_LABEL = 'mixnet-tw-mul-v1';

export function proveMul(X: Point, Y: Point, Z: Point, a: bigint, rx: bigint, rz: bigint): MulProof {
  const ka = randScalar();
  const krx = randScalar();
  const krz = randScalar();
  const T1 = mul(G, ka).add(mul(H, krx)); // for X = a·G + rx·H
  const T2 = mul(Y, ka).add(mul(H, krz)); // for Z = a·Y + rz·H
  const c = hashToScalar(MUL_LABEL, [G, H, Y, X, Z, T1, T2]);
  return {
    T1: pointToHex(T1), T2: pointToHex(T2),
    za: mod(ka + c * a, N).toString(), zrx: mod(krx + c * rx, N).toString(), zrz: mod(krz + c * rz, N).toString(),
  };
}

export function verifyMul(X: Point, Y: Point, Z: Point, p: MulProof): boolean {
  let za: bigint; let zrx: bigint; let zrz: bigint;
  try { za = scalarFromDecimal(p.za); zrx = scalarFromDecimal(p.zrx); zrz = scalarFromDecimal(p.zrz); } catch { return false; } // strict canonical decimal (cross-verifier equivalence)
  if (!inRange(za) || !inRange(zrx) || !inRange(zrz)) return false;
  const T1 = pointFromHex(p.T1); const T2 = pointFromHex(p.T2);
  const c = hashToScalar(MUL_LABEL, [G, H, Y, X, Z, T1, T2]);
  if (!mul(G, za).add(mul(H, zrx)).equals(T1.add(mul(X, c)))) return false; // z_a·G + z_rx·H == T1 + c·X
  if (!mul(Y, za).add(mul(H, zrz)).equals(T2.add(mul(Z, c)))) return false; // z_a·Y + z_rz·H == T2 + c·Z
  return true;
}

// --- Fiat–Shamir helpers ------------------------------------------------------------------------------
function u32(n: number): Uint8Array {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}
/** Expand a point-transcript hash into n scalars (64-byte draws → negligible bias; mirrors randScalar). */
function challengeVector(label: string, points: Point[], n: number): bigint[] {
  const seed = scalarTo32(hashToScalar(label, points));
  const out: bigint[] = [];
  for (let i = 0; i < n; i++) {
    const d = sha512(concatBytes(utf8ToBytes('vvp-fs-v1'), utf8ToBytes(label), seed, u32(i)));
    let x = 0n;
    for (const b of d) x = (x << 8n) | BigInt(b);
    out.push(mod(x, N));
  }
  return out;
}
/** The full statement point-transcript, in one canonical order, bound into every challenge. */
function statementPoints(pk: Point, hs: Point[], L0: Item[], L: Item[], c: Point[]): Point[] {
  const pts: Point[] = [pk, H, ...hs];
  const pushFlat = (list: Item[]): void => { for (const it of list) for (const ct of it) { pts.push(ct.a, ct.b); } };
  pushFlat(L0); pushFlat(L);
  pts.push(...c);
  return pts;
}
/** Σ_j coeff_j · P_j (multi-scalar multiplication). */
function msm(coeffs: bigint[], pts: Point[]): Point {
  let acc = ZERO;
  for (let j = 0; j < coeffs.length; j++) acc = acc.add(mul(pts[j]!, coeffs[j]!));
  return acc;
}

export interface TwShuffleProof {
  c: string[]; // n permutation commitments c_i = h_{π(i)} + r_i·H
  Gamma: string[]; // n commitments Γ_j = g_j·G + γ_j·H
  // combined generalized-Schnorr (D-opening + Γ + per-component multi-exp), one challenge:
  TD: string; TG: string[]; Ta: string[]; Tb: string[];
  zg: string[]; zgamma: string[]; zrD: string; zR: string[];
  // product argument: A_0..A_n partial-product commitments + n committed-multiplication steps + endpoints
  A: string[]; // n+1
  steps: MulProof[]; // n
  s0: string; sN: string; // A_0 = 1·G + s0·H ; A_n = P*·G + sN·H
  W: number; // item width (echoed; verifier cross-checks against L)
}

export interface TwShuffleResult { L: Item[]; proof: TwShuffleProof; }

const EVEC_LABEL = 'mixnet-tw-evec';
const PRODX_LABEL = 'mixnet-tw-prodx';
const MSM_LABEL = 'mixnet-tw-msm';

/**
 * Prove (and produce) an O(N) Terelius–Wikström re-encryption shuffle of L0. Secret witness: the permutation
 * π (output[i] = L0[π[i]] re-encrypted) and the re-encryption factors. Anyone holding the ciphertexts can mix.
 */
export function twShuffleProve(pk: Point, L0: Item[], t?: number): TwShuffleResult {
  void t; // single-instance; no t-repetition (kept for signature symmetry with mixnet.ts callers)
  const n = L0.length;
  if (n < 2) throw new Error('TW shuffle requires ≥ 2 items');
  const W = L0[0]!.length;
  if (W < 1 || L0.some((it) => it.length !== W)) throw new Error('items must share a fixed width ≥ 1');
  const hs = generatorVector(n);

  // permutation π and re-encryption factors ρ; output[i] = reenc(L0[π[i]], ρ[i])
  const pi = fyShuffle(n);
  const rho: Reenc[] = Array.from({ length: n }, () => Array.from({ length: W }, () => randScalar()));
  const L: Item[] = pi.map((src, i) => L0[src]!.map((ct, w) => ({ a: ct.a.add(mul(G, rho[i]![w]!)), b: ct.b.add(mul(pk, rho[i]![w]!)) })));

  // (C1) permutation commitment c_i = h_{π(i)} + r_i·H  — committed BEFORE the challenge e
  const r = Array.from({ length: n }, () => randScalar());
  const c = pi.map((src, i) => hs[src]!.add(mul(H, r[i]!)));

  // (C2) challenge vector e bound to (pk, CRS, L0, L, c)
  const S = statementPoints(pk, hs, L0, L, c);
  const e = challengeVector(EVEC_LABEL, S, n);

  // weights g_j = Σ_{i: π(i)=j} e_i = e_{π⁻¹(j)} (genuine permutation), r_D = Σ_i e_i·r_i
  const g = new Array<bigint>(n).fill(0n);
  for (let i = 0; i < n; i++) g[pi[i]!] = mod(g[pi[i]!]! + e[i]!, N);
  const rD = e.reduce((acc, ei, i) => mod(acc + ei * r[i]!, N), 0n);
  const gamma = Array.from({ length: n }, () => randScalar());
  const Gamma = g.map((gj, j) => ped(gj, gamma[j]!));

  // verifier-computable D and the per-component multi-exp targets
  const D = msm(e, c);
  const L0a = (w: number): Point[] => L0.map((it) => it[w]!.a);
  const L0b = (w: number): Point[] => L0.map((it) => it[w]!.b);
  const Pa = Array.from({ length: W }, (_, w) => msm(e, L.map((it) => it[w]!.a)));
  const Pb = Array.from({ length: W }, (_, w) => msm(e, L.map((it) => it[w]!.b)));
  const R = Array.from({ length: W }, (_, w) => e.reduce((acc, ei, i) => mod(acc + ei * rho[i]![w]!, N), 0n));

  // (C4) ONE combined generalized-Schnorr: D-opening + Γ + per-component multi-exp, sharing g (and γ, r_D, R)
  const kg = Array.from({ length: n }, () => randScalar());
  const kgamma = Array.from({ length: n }, () => randScalar());
  const krD = randScalar();
  const kR = Array.from({ length: W }, () => randScalar());
  const TD = msm(kg, hs).add(mul(H, krD));
  const TG = kg.map((kgj, j) => mul(G, kgj).add(mul(H, kgamma[j]!)));
  const Ta = Array.from({ length: W }, (_, w) => msm(kg, L0a(w)).add(mul(G, kR[w]!)));
  const Tb = Array.from({ length: W }, (_, w) => msm(kg, L0b(w)).add(mul(pk, kR[w]!)));
  const ccPts = [...S, ...Gamma, D, TD, ...TG, ...Ta, ...Tb];
  const cc = hashToScalar(MSM_LABEL, ccPts);
  const zg = g.map((gj, j) => mod(kg[j]! + cc * gj, N));
  const zgamma = gamma.map((gj, j) => mod(kgamma[j]! + cc * gj, N));
  const zrD = mod(krD + cc * rD, N);
  const zR = R.map((Rw, w) => mod(kR[w]! + cc * Rw, N));

  // (C5) product argument {g} = {e}: x bound to (statement, Γ, D); partial-product chain with mul-step proofs
  const x = hashToScalar(PRODX_LABEL, [...S, ...Gamma, D]);
  const sHat = Array.from({ length: n + 1 }, () => randScalar());
  const P = new Array<bigint>(n + 1); // P[k] = ∏_{j<k} (g_j − x)
  P[0] = 1n;
  for (let k = 1; k <= n; k++) P[k] = mod(P[k - 1]! * mod(g[k - 1]! - x, N), N);
  const A = Array.from({ length: n + 1 }, (_, k) => ped(P[k]!, sHat[k]!));
  const steps: MulProof[] = [];
  for (let k = 1; k <= n; k++) {
    const Y = Gamma[k - 1]!.subtract(mul(G, x)); // = (g_{k-1} − x)·G + γ_{k-1}·H
    const rz = mod(sHat[k]! - P[k - 1]! * gamma[k - 1]!, N); // so A_k = P_{k-1}·Y + rz·H
    steps.push(proveMul(A[k - 1]!, Y, A[k]!, P[k - 1]!, sHat[k - 1]!, rz));
  }

  const proof: TwShuffleProof = {
    c: c.map(pointToHex), Gamma: Gamma.map(pointToHex),
    TD: pointToHex(TD), TG: TG.map(pointToHex), Ta: Ta.map(pointToHex), Tb: Tb.map(pointToHex),
    zg: zg.map((v) => v.toString()), zgamma: zgamma.map((v) => v.toString()), zrD: zrD.toString(), zR: zR.map((v) => v.toString()),
    A: A.map(pointToHex), steps, s0: sHat[0]!.toString(), sN: sHat[n]!.toString(), W,
  };
  return { L, proof };
}

/** A uniform permutation of 0..n-1 via Fisher–Yates seeded by randScalar (NEVER Math.random). */
function fyShuffle(n: number): number[] {
  const p = Array.from({ length: n }, (_, i) => i);
  for (let k = n - 1; k > 0; k--) {
    const j = Number(randScalar() % BigInt(k + 1));
    const tmp = p[k]!; p[k] = p[j]!; p[j] = tmp;
  }
  return p;
}

/**
 * Verify a TW shuffle from the public record alone (NEVER throws). Implements the full soundness checklist:
 * shape gate, CRS re-derivation, canonical points/scalars, Fiat–Shamir re-derivation, the combined
 * generalized-Schnorr (D-opening + Γ + both-sides-all-W multi-exp), and the product argument (every step +
 * both endpoints with the verifier-computed target P*).
 */
export function verifyTwShuffle(pk: Point, L0: Item[], L: Item[], proof: TwShuffleProof): VerifyResult {
  const checks: Check[] = [];
  try {
    const n = L0.length;
    // V0 — shape gate (reject, never pad)
    const W = proof.W;
    const shapeOk = n >= 2 && Number.isInteger(W) && W >= 1
      && L0.every((it) => it.length === W) && Array.isArray(L) && L.length === n && L.every((it) => it.length === W)
      && proof.c.length === n && proof.Gamma.length === n && proof.A.length === n + 1 && proof.steps.length === n
      && proof.TG.length === n && proof.zg.length === n && proof.zgamma.length === n
      && proof.Ta.length === W && proof.Tb.length === W && proof.zR.length === W;
    checks.push({ name: '⚠ EXPERIMENTAL / NOT AUDITED (ADR-0012; default mix is Sako–Kilian, production should use Verificatum) — shape: n≥2 items of uniform width W; n commitments, n+1 products, n steps, W per-component responses', ok: shapeOk });
    if (!shapeOk) return { ok: false, checks, results: null };

    // V4 (pk gate) — pk must not be the identity (else the b-side ··==R·pk degenerates and the payload is unconstrained)
    if (pk.equals(ZERO)) { checks.push({ name: 'Joint key pk is non-identity', ok: false }); return { ok: false, checks, results: null }; }

    // V1 — re-derive the CRS; never read generators from the proof
    const hs = generatorVector(n);
    checks.push({ name: 'NUMS generator vector re-derived from the label scheme (not the proof)', ok: true });

    // V2/V3 — canonical parse of every point and scalar (pointFromHex / inRange throw or gate)
    const c = proof.c.map(pointFromHex);
    const Gamma = proof.Gamma.map(pointFromHex);
    const A = proof.A.map(pointFromHex);
    const TD = pointFromHex(proof.TD);
    const TG = proof.TG.map(pointFromHex);
    const Ta = proof.Ta.map(pointFromHex);
    const Tb = proof.Tb.map(pointFromHex);
    // Strict canonical-DECIMAL parse (mirrors Python parse_scalar): rejects hex/underscore/out-of-range so a
    // same-value-different-syntax scalar cannot be accepted by one verifier and rejected by the other.
    let zg: bigint[]; let zgamma: bigint[]; let zrD: bigint; let zR: bigint[]; let s0: bigint; let sN: bigint;
    try {
      zg = proof.zg.map(scalarFromDecimal);
      zgamma = proof.zgamma.map(scalarFromDecimal);
      zrD = scalarFromDecimal(proof.zrD);
      zR = proof.zR.map(scalarFromDecimal);
      s0 = scalarFromDecimal(proof.s0); sN = scalarFromDecimal(proof.sN);
    } catch {
      checks.push({ name: 'All response scalars are canonical decimal in [0, N)', ok: false });
      return { ok: false, checks, results: null };
    }
    checks.push({ name: 'All response scalars are canonical decimal in [0, N)', ok: true });

    // V4 — re-derive Fiat–Shamir from the full statement; trust nothing challenge-side in the proof
    const S = statementPoints(pk, hs, L0, L, c);
    const e = challengeVector(EVEC_LABEL, S, n);
    const D = msm(e, c); // verifier computes D itself (never read from the proof)
    const x = hashToScalar(PRODX_LABEL, [...S, ...Gamma, D]);
    const cc = hashToScalar(MSM_LABEL, [...S, ...Gamma, D, TD, ...TG, ...Ta, ...Tb]);

    // per-component multi-exp targets, verifier-computed
    const L0a = (w: number): Point[] => L0.map((it) => it[w]!.a);
    const L0b = (w: number): Point[] => L0.map((it) => it[w]!.b);
    const Pa = Array.from({ length: W }, (_, w) => msm(e, L.map((it) => it[w]!.a)));
    const Pb = Array.from({ length: W }, (_, w) => msm(e, L.map((it) => it[w]!.b)));

    // V5(combined) — D-opening: Σ zg_j·h_j + zrD·H == TD + cc·D   (binds g to the pre-committed permutation c)
    const dOk = msm(zg, hs).add(mul(H, zrD)).equals(TD.add(mul(D, cc)));
    checks.push({ name: 'Commitment-consistency: D = Σ gⱼ·hⱼ + r_D·H binds g to the pre-committed permutation', ok: dOk });

    // V5(combined) — Γ openings: zg_j·G + zgamma_j·H == TG_j + cc·Γ_j
    let gammaOk = true;
    for (let j = 0; j < n; j++) if (!mul(G, zg[j]!).add(mul(H, zgamma[j]!)).equals(TG[j]!.add(mul(Gamma[j]!, cc)))) gammaOk = false;
    checks.push({ name: 'Every Γⱼ opens to the same gⱼ used everywhere (single committed permutation)', ok: gammaOk });

    // V7 — multi-exp BOTH sides, ALL W components (the SwissPost-class individual-soundness check)
    let meOk = true;
    for (let w = 0; w < W; w++) {
      if (!msm(zg, L0a(w)).add(mul(G, zR[w]!)).equals(Ta[w]!.add(mul(Pa[w]!, cc)))) meOk = false;
      if (!msm(zg, L0b(w)).add(mul(pk, zR[w]!)).equals(Tb[w]!.add(mul(Pb[w]!, cc)))) meOk = false;
    }
    checks.push({ name: 'Re-encryption multi-exp holds for BOTH (a,b) and ALL W components (same g ⇒ items moved whole)', ok: meOk });

    // V5(product) — {g} = {e}: endpoints + every committed-multiplication step
    const Pstar = e.reduce((acc, ei) => mod(acc * mod(ei - x, N), N), 1n); // verifier computes the target
    const ep0 = A[0]!.equals(ped(1n, s0)); // A_0 = 1·G + s0·H
    const epN = A[n]!.equals(ped(Pstar, sN)); // A_n = (∏(e_i−x))·G + sN·H
    let stepOk = true;
    for (let k = 1; k <= n; k++) {
      const Y = Gamma[k - 1]!.subtract(mul(G, x)); // (g_{k-1}−x) committed
      if (!verifyMul(A[k - 1]!, Y, A[k]!, proof.steps[k - 1]!)) stepOk = false;
    }
    checks.push({ name: 'Permutation argument: ∏(gⱼ−x) = ∏(eᵢ−x) via endpoints + every multiplication step (⇒ {g}={e} ⇒ genuine permutation)', ok: ep0 && epN && stepOk });

    return { ok: checks.every((c2) => c2.ok), checks, results: null };
  } catch (err) {
    return { ok: false, results: null, checks: [{ name: 'TW shuffle proof is well-formed (no exception)', ok: false, detail: String(err) }] };
  }
}

// --- self-contained transcript (so the standalone shuffle is independently re-verifiable) --------------
const ctToJ = (ct: Ciphertext): unknown => ({ a: pointToHex(ct.a), b: pointToHex(ct.b) });
const ctFromJ = (j: { a: string; b: string }): Ciphertext => ({ a: pointFromHex(j.a), b: pointFromHex(j.b) });
const itemToJ = (it: Item): unknown => it.map(ctToJ);
const itemFromJ = (j: { a: string; b: string }[]): Item => j.map(ctFromJ);

export interface TwTranscript { publicKey: Point; L0: Item[]; L: Item[]; proof: TwShuffleProof; }

export function twTranscriptToJSON(pk: Point, L0: Item[], L: Item[], proof: TwShuffleProof): string {
  return JSON.stringify({
    version: 'vvp-tw-shuffle-1', kind: 'tw-shuffle',
    publicKey: pointToHex(pk), L0: L0.map(itemToJ), L: L.map(itemToJ), proof,
  }, null, 2);
}

/* eslint-disable @typescript-eslint/no-explicit-any */
export function twTranscriptFromJSON(json: string): TwTranscript {
  const j: any = JSON.parse(json);
  if (j.kind !== 'tw-shuffle' || j.version !== 'vvp-tw-shuffle-1') throw new Error('not a vvp-tw-shuffle-1 document');
  return { publicKey: pointFromHex(j.publicKey), L0: j.L0.map(itemFromJ), L: j.L.map(itemFromJ), proof: j.proof };
}

/** Verify an already-parsed TW shuffle transcript (never throws). */
export function verifyTwTranscript(t: TwTranscript): VerifyResult {
  return verifyTwShuffle(t.publicKey, t.L0, t.L, t.proof);
}

/**
 * Verify a TW shuffle transcript straight from untrusted JSON, ALWAYS returning a verdict — the parse boundary
 * (`twTranscriptFromJSON`) is a throwing parser, so this wrapper try/catches it so the TS trust root emits a
 * clean verdict like the Python `main()` does (round-19 robustness finding).
 */
export function verifyTwTranscriptJSON(json: string): VerifyResult {
  let t: TwTranscript;
  try { t = twTranscriptFromJSON(json); } catch (err) {
    return { ok: false, results: null, checks: [{ name: 'TW shuffle transcript parses', ok: false, detail: String(err) }] };
  }
  return verifyTwTranscript(t);
}
