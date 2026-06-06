// The chain-anchor adapter SEAM — ADR-0002 (the blockchain is non-load-bearing: anchor only signed
// Merkle ROOTS, never ballots) and ADR-0003 (named, accountable validators; no Proof-of-Stake).
//
// The default reference backend is a signed, hash-chained, append-only TRANSPARENCY LOG of root
// commitments — the place a production deployment swaps in a permissioned-BFT chain or a CT-style log.
// It anchors ~64 bytes of roots (the digital bulletin-board root, and optionally the paper-manifest root
// from the RLA hybrid), NEVER a ballot — the API and runtime guards accept only a RootCommitment (hex
// roots + metadata validated as 32-byte roots), never a transcript. Each entry is signed by a NAMED
// validator and hash-chained to its predecessor, so within a single presented copy the sequence is
// tamper-evident, ordered, and attributable: altering, reordering, or forging any entry breaks the chain
// or a signature. Anyone can re-verify the whole presented log + that a given election's root is anchored.
//
// Honest scope — what a hash-chained log alone does NOT give you:
//   • Fork/equivocation safety. A signer can present log A to you and a divergent log B to someone else;
//     each is internally consistent. Detecting this needs gossip/witness cosigning (a CT-style ecosystem),
//     which this seam does NOT implement. The chain proves order WITHIN one copy, not a single global history.
//   • Truncation safety. A suppressed suffix (dropping the latest entries) is invisible from one copy.
//     Pass `expectHead`/`expectLength` (a head you pinned out-of-band) to verifyAnchorLog to detect it.
//   • Accountability without a roster. A valid self-signature only proves "some key signed this", not that
//     the key is one you trust. Pass `validators` (ADR-0003) or signer identities are self-asserted, not accountable.
//   • Trusted time. `anchoredAt` is a SIGNER-ASSERTED string: it is bound into the signature (so the signer
//     can't later deny the time it claimed), but the verifier checks no clock and no monotonicity, so it
//     attests only the time the signer CLAIMED — a backwards or far-future label still verifies. Real
//     timestamping (a time NOT under the signer's control) comes from the backend you swap in — a TSA or the
//     chain's consensus time — never from a self-signed field here. So the seam gives ORDER, not trusted TIME.
// And, as always: anchoring does NOT make the digital tally trustworthy on its own (that is E2E-V + the
// verifiers) and is NOT software independence (that is paper + RLA — ADR-0004). It binds "this root was
// witnessed by these named validators in this order"; it cannot attest the off-chain world. Pre-audit;
// not for binding government use.

import { sha256 } from '@noble/hashes/sha256';
import { concatBytes, utf8ToBytes, hexToBytes, bytesToHex } from '@noble/hashes/utils';
import { pointToHex, pointFromHex } from './group.js';
import { sign, verifySig, type Credential } from './credentials.js';
import type { Check, VerifyResult } from './verify.js';

function u32(n: number): Uint8Array {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}
// Canonical hex is LOWERCASE-ONLY: a root presented as upper- or mixed-case is a different string that
// hashes/sorts differently, so a relying party pinning a lowercase head must reject it rather than silently
// normalize. (Same latent case bug the round-13 anchor review flagged in rla.ts.)
const is32hex = (h: unknown): boolean => typeof h === 'string' && /^[0-9a-f]{64}$/.test(h);

export interface RootCommitment {
  version: 'vvp-root-commitment-1';
  contest: string;
  boardRoot: string; // the digital bulletin-board root (RFC-6962)
  paperManifestRoot?: string; // optional: the paper-manifest root (RLA hybrid), bound alongside
  anchoredAt: string; // caller/signer-asserted time label, bound into the signature but NOT verified (see header)
}

export interface AnchorEntry {
  index: number; // monotonic from 0
  prev: string; // hex sha256 of the previous entry's signed bytes ('' for index 0)
  commitment: RootCommitment;
  validatorPub: string; // hex ristretto255 — the NAMED validator that witnessed this entry
  sig: { R: string; s: string }; // Schnorr over the entry's canonical signed bytes
}

export function rootCommitment(contest: string, boardRoot: string, anchoredAt: string, paperManifestRoot?: string): RootCommitment {
  return paperManifestRoot === undefined
    ? { version: 'vvp-root-commitment-1', contest, boardRoot, anchoredAt }
    : { version: 'vvp-root-commitment-1', contest, boardRoot, paperManifestRoot, anchoredAt };
}

// Canonical, domain-separated, FULLY length-prefixed signed bytes (the round-13 anchor forge taught the
// lesson: no two field sets may produce the same bytes). The optional paper root is length 0 when absent.
function entrySignedBytes(index: number, prev: string, c: RootCommitment, validatorPub: string): Uint8Array {
  const ver = utf8ToBytes(c.version); // bind the commitment version so a future format can't be replayed as v1
  const cb = utf8ToBytes(c.contest);
  const at = utf8ToBytes(c.anchoredAt);
  const prevB = prev === '' ? new Uint8Array(0) : hexToBytes(prev);
  const br = hexToBytes(c.boardRoot);
  const pr = c.paperManifestRoot === undefined ? new Uint8Array(0) : hexToBytes(c.paperManifestRoot);
  const vp = hexToBytes(validatorPub);
  return concatBytes(
    utf8ToBytes('vvp-anchor-log-v1'),
    u32(ver.length), ver,
    u32(index),
    u32(prevB.length), prevB,
    u32(cb.length), cb,
    u32(br.length), br,
    u32(pr.length), pr,
    u32(at.length), at,
    u32(vp.length), vp,
  );
}

function entryHash(e: AnchorEntry): string {
  return bytesToHex(sha256(entrySignedBytes(e.index, e.prev, e.commitment, e.validatorPub)));
}

/**
 * The running head: sha256 of the latest entry's signed bytes ('' for an empty log). This is an UNSIGNED
 * running hash a relying party must pin OUT-OF-BAND (publish it, gossip it, compare copies). It is NOT a
 * CT-style signed tree head: there is no signature over the head itself, and the log offers no inclusion
 * or consistency proofs — re-verification re-walks the whole presented sequence. Two parties who pin the
 * same head saw the same prefix; that is the property `expectHead`/`expectLength` lets you enforce.
 */
export function logHead(entries: AnchorEntry[]): string {
  return Array.isArray(entries) && entries.length ? entryHash(entries[entries.length - 1]!) : '';
}

/** A named-validator-operated, append-only, hash-chained log of ROOT commitments (never ballots). */
export class AnchorLog {
  private es: AnchorEntry[] = [];

  /** A named validator witnesses a root commitment, hash-chaining + signing it onto the log. */
  append(commitment: RootCommitment, validator: Credential): AnchorEntry {
    if (!is32hex(commitment.boardRoot)) throw new Error('boardRoot must be 32-byte hex');
    if (commitment.paperManifestRoot !== undefined && !is32hex(commitment.paperManifestRoot)) throw new Error('paperManifestRoot must be 32-byte hex');
    const index = this.es.length;
    const prev = index === 0 ? '' : entryHash(this.es[index - 1]!);
    const validatorPub = pointToHex(validator.pub);
    const s = sign(validator.secret, entrySignedBytes(index, prev, commitment, validatorPub));
    const e: AnchorEntry = { index, prev, commitment, validatorPub, sig: { R: pointToHex(s.R), s: s.s.toString() } };
    this.es.push(e);
    return e;
  }

  entries(): AnchorEntry[] { return [...this.es]; }
  /** The running head (see `logHead`): an UNSIGNED hash to pin out-of-band, NOT a CT signed tree head. */
  head(): string { return logHead(this.es); }
}

/**
 * Verify a PRESENTED anchor log (never throws): canonical encodings, the expected commitment version,
 * monotonic indices from 0, the hash-chain links every entry to its predecessor (append-only + ordered),
 * and every entry is signed by its named validator.
 *
 * Accountability is checked UNCONDITIONALLY. Pass `validators` (ADR-0003) and every signer must be on that
 * accountable allowlist; OMIT it and the check FAILS with a note that signer identities are self-asserted —
 * a valid self-signature alone never proves the witness is one you trust, so "no roster" is not "all fine".
 *
 * Truncation is invisible from a single copy (see the module header). Pass a head you pinned out-of-band as
 * `expectHead` and/or the count you expect as `expectLength`, and a dropped suffix is caught here.
 */
export function verifyAnchorLog(
  entries: AnchorEntry[],
  opts?: { validators?: string[]; expectHead?: string; expectLength?: number },
): VerifyResult {
  const checks: Check[] = [];
  try {
    if (!Array.isArray(entries) || entries.length === 0) {
      checks.push({ name: 'Anchor log is non-empty', ok: false });
      return { ok: false, checks, results: null };
    }
    const canon = entries.every((e) =>
      Number.isInteger(e.index) && e.commitment?.version === 'vvp-root-commitment-1'
      && is32hex(e.commitment?.boardRoot)
      && (e.commitment.paperManifestRoot === undefined || is32hex(e.commitment.paperManifestRoot))
      && is32hex(e.validatorPub) && is32hex(e.sig?.R)
      && (e.index === 0 ? e.prev === '' : is32hex(e.prev)));
    checks.push({ name: 'Entries are canonically encoded (version v1; 32-byte roots/keys; index-0 prev empty)', ok: canon });
    if (!canon) return { ok: false, checks, results: null };

    let idxOk = true;
    let chainOk = true;
    for (let i = 0; i < entries.length; i++) {
      if (entries[i]!.index !== i) idxOk = false;
      const expectedPrev = i === 0 ? '' : entryHash(entries[i - 1]!);
      if (entries[i]!.prev !== expectedPrev) chainOk = false;
    }
    checks.push({ name: 'Indices are monotonic from 0', ok: idxOk });
    checks.push({ name: 'Hash-chain links each entry to its predecessor (append-only, ordered)', ok: chainOk });

    const allow = opts?.validators ? new Set(opts.validators) : null;
    let sigBad = 0;
    let unpinned = 0;
    for (const e of entries) {
      if (!verifySig(pointFromHex(e.validatorPub), entrySignedBytes(e.index, e.prev, e.commitment, e.validatorPub), { R: pointFromHex(e.sig.R), s: BigInt(e.sig.s) })) sigBad++;
      if (allow && !allow.has(e.validatorPub)) unpinned++;
    }
    checks.push({ name: 'Every entry is signed by its named validator', ok: sigBad === 0 });
    checks.push(allow
      ? { name: 'Every validator is on the accountable allowlist (ADR-0003)', ok: unpinned === 0 }
      : { name: 'Validators pinned to an accountable allowlist (ADR-0003)', ok: false, detail: 'no allowlist supplied — signer identities are self-asserted, NOT accountable; pass { validators } to enforce' });

    // Truncation pins (optional): only meaningful against a head/length obtained out-of-band.
    if (opts?.expectLength !== undefined) {
      checks.push({ name: `Log length matches the pinned expectation (${opts.expectLength})`, ok: entries.length === opts.expectLength, detail: entries.length === opts.expectLength ? undefined : `presented ${entries.length}` });
    }
    if (opts?.expectHead !== undefined) {
      const head = logHead(entries);
      checks.push({ name: 'Log head matches the head pinned out-of-band (no truncation/extension)', ok: head === opts.expectHead, detail: head === opts.expectHead ? undefined : `presented head ${head}` });
    }

    return { ok: checks.every((c) => c.ok), checks, results: null };
  } catch (err) {
    return { ok: false, results: null, checks: [{ name: 'Anchor log is well-formed (no exception)', ok: false, detail: String(err) }] };
  }
}

/** Verify the log AND that a given election's root(s) are anchored in it. */
export function verifyRootAnchored(
  entries: AnchorEntry[],
  boardRoot: string,
  opts?: { paperManifestRoot?: string; validators?: string[]; expectHead?: string; expectLength?: number },
): VerifyResult {
  // Defensive: mirror verifyAnchorLog's never-throws contract even on HOSTILE input — not just null
  // entries / a missing commitment (handled by the Array.isArray + optional-chaining below), but also a
  // throwing accessor (a Proxy or a `get commitment(){throw}` object), which optional chaining does NOT
  // stop (`e?.commitment` still invokes the getter for a non-null `e`). The try/catch is the backstop so a
  // bad log is always a clean `ok:false`, never an exception — symmetric with verifyAnchorLog.
  try {
    const base = verifyAnchorLog(entries, opts);
    const checks: Check[] = [...base.checks];
    const found = Array.isArray(entries) && entries.some((e) => e?.commitment?.boardRoot === boardRoot
      && (opts?.paperManifestRoot === undefined || e?.commitment?.paperManifestRoot === opts.paperManifestRoot));
    checks.push({ name: 'The election root is anchored in the log', ok: found });
    return { ok: checks.every((c) => c.ok), checks, results: null };
  } catch (err) {
    return { ok: false, results: null, checks: [{ name: 'Anchor log is well-formed (no exception)', ok: false, detail: String(err) }] };
  }
}
