// Paper + Risk-Limiting-Audit (RLA) hybrid deployment profile — the EXPORT + ANCHOR layer that
// implements ADR-0004 (paper ballots of record + a mandatory RLA are the only software-independence
// anchor; the digital layer is the transparent audit companion, never the legal record) and ADR-0009.
//
// THE MODEL: voters cast voter-verified PAPER ballots (the legal record); this E2E-V engine provides
// the transparent digital companion (encrypted RFC-6962 board, public proofs, a re-verifiable tally);
// a RISK-LIMITING AUDIT runs on the PAPER to statistically confirm the reported (digital) outcome to a
// risk limit α. This module produces (a) a ballot MANIFEST an external RLA tool (VotingWorks Arlo /
// SHANGRLA) ingests, (b) a signed digital↔paper ANCHOR binding the bulletin-board root to the paper
// batches so neither record can be swapped undetected, and (c) ONE clearly-labelled, NON-AUTHORITATIVE
// illustrative ballot-polling (BRAVO) reference. PAPER WINS on any discrepancy.
//
// HARD RULES (honesty / privacy — do not relax):
//  • We DO NOT re-implement authoritative RLA statistics. Arlo / SHANGRLA, run on the PAPER, are the
//    audit of record. The BRAVO function here is illustrative (top-two only; ignores undervotes/others).
//  • SECRET-BALLOT paths (plurality / multi-seat / Borda) decrypt ONLY per-candidate totals — there is
//    no per-ballot plaintext and we NEVER emit a per-ballot CVR for them. That is the privacy guarantee,
//    and it is exactly why secret-ballot tallies use ballot-POLLING RLAs (no CVRs), not comparison RLAs.
//    The mixnet-IRV path already reveals the anonymized ranking multiset (unlinked to voters); only
//    THOSE already-public rankings may be exported as anonymized CVRs (`toRankingsCsv`).
//  • Software independence comes from PAPER + a correctly-run RLA, NOT from this engine. A sound E2E-V
//    transcript over a malicious endpoint still faithfully carries a flipped choice; only the
//    paper-anchored RLA catches that. This is the in-person, supervised polling-place profile only.
//
// Pre-audit; not certified for binding government use. Chain-of-custody, the scanner, and the RLA
// ceremony are off-system / represented.

import { concatBytes, utf8ToBytes, hexToBytes } from '@noble/hashes/utils';
import { pointToHex, pointFromHex, type Point } from './group.js';
import { sign, verifySig, type Credential } from './credentials.js';
import { BulletinBoard } from './bulletin.js';
import type { Check, VerifyResult } from './verify.js';

function u32(n: number): Uint8Array {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}
const validU32 = (n: number): boolean => Number.isInteger(n) && n >= 0 && n <= 0xffffffff;
// Canonical hex is LOWERCASE-ONLY (a mixed-case root is a different string that hashes/sorts differently).
const is32hex = (h: unknown): boolean => typeof h === 'string' && /^[0-9a-f]{64}$/.test(h);

/** Deterministic, locale- and runtime-independent byte-lexicographic comparison (UTF-8 of batchId). */
function cmpBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i]! !== b[i]!) return a[i]! - b[i]!;
  return a.length - b.length;
}

// ---- ballot manifest (the paper batches an RLA samples from) ----------------
export interface BatchRow {
  batchId: string; // unique, e.g. "tabulator-3-batch-007"
  ballotCount: number; // paper ballots physically in this batch
  storageLocation?: string; // optional chain-of-custody note (off-system attested)
}
export interface BallotManifest {
  version: 'vvp-ballot-manifest-1';
  contest: string;
  batches: BatchRow[];
  paperBallotsTotal: number; // = Σ batches[i].ballotCount (verified, not trusted)
}

export function makeManifest(contest: string, batches: BatchRow[]): BallotManifest {
  for (const b of batches) if (!validU32(b.ballotCount)) throw new Error(`batch ${b.batchId}: ballotCount must be a uint32`);
  return { version: 'vvp-ballot-manifest-1', contest, batches, paperBallotsTotal: batches.reduce((a, b) => a + b.ballotCount, 0) };
}

// Canonical, domain-separated batch-row bytes; rows sorted by UTF-8 batchId for a reproducible root.
function batchRowBytes(row: BatchRow): Uint8Array {
  const id = utf8ToBytes(row.batchId);
  return concatBytes(utf8ToBytes('vvp-batch-v1'), u32(id.length), id, u32(row.ballotCount));
}
const sortedBatches = (m: BallotManifest): BatchRow[] =>
  [...m.batches].sort((x, y) => cmpBytes(utf8ToBytes(x.batchId), utf8ToBytes(y.batchId)));

/** RFC-6962 Merkle root over the manifest's batch rows — reuses the ONE (CVE-2012-2459-safe) board impl. */
export function ballotManifestRoot(m: BallotManifest): string {
  const board = new BulletinBoard();
  for (const row of sortedBatches(m)) board.append(batchRowBytes(row));
  return board.root();
}

// ---- the digital↔paper anchor (the spine: binds both roots under one signature) ----
export interface PaperAnchor {
  version: 'vvp-paper-anchor-1';
  contest: string;
  boardRoot: string; // from the published digital Transcript (the digital universe)
  paperManifestRoot: string; // RFC-6962 root over the paper batches (the paper universe)
  numVoters: number; // digital ballot count (Transcript.numVoters)
  paperBallotsTotal: number; // paper ballot count (Σ batch counts)
  publicKey: string; // hex; pins the election instance
  anchoredAt: string; // caller-supplied timestamp the (optional) chain anchor witnesses
  signerPub: string; // hex ristretto255 pubkey of the election-authority / ceremony key (BOUND into the signature)
  sig: { R: string; s: string };
}

type SignedFields = Pick<PaperAnchor, 'contest' | 'boardRoot' | 'paperManifestRoot' | 'numVoters' | 'paperBallotsTotal' | 'publicKey' | 'anchoredAt' | 'signerPub'>;

// Domain-separated AND fully length-prefixed: every variable-length field carries its own length, so no
// byte can shift across a field boundary while leaving the signed message identical (the canonicalization
// bug the round-1 review flagged for hashToScalar). signerPub is bound in, so the signer can't be swapped.
// What ADR-0002 means by "anchor only signed Merkle roots, never ballots": ~64 bytes of roots is the
// entire on-chain payload, and exactly what the signature covers.
function anchorBytes(a: SignedFields): Uint8Array {
  const cb = utf8ToBytes(a.contest);
  const at = utf8ToBytes(a.anchoredAt);
  const br = hexToBytes(a.boardRoot);
  const pr = hexToBytes(a.paperManifestRoot);
  const pk = hexToBytes(a.publicKey);
  const sp = hexToBytes(a.signerPub);
  return concatBytes(
    utf8ToBytes('vvp-anchor-v1'),
    u32(cb.length), cb,
    u32(br.length), br,
    u32(pr.length), pr,
    u32(a.numVoters), u32(a.paperBallotsTotal),
    u32(pk.length), pk,
    u32(sp.length), sp,
    u32(at.length), at,
  );
}

/** Bind a published digital transcript to a paper ballot manifest and sign it with the authority key. */
export function buildAnchor(opts: {
  contest: string; boardRoot: string; numVoters: number; publicKey: Point | string;
  manifest: BallotManifest; signer: Credential; anchoredAt: string;
}): PaperAnchor {
  if (!validU32(opts.numVoters)) throw new Error('numVoters must be a uint32');
  if (!is32hex(opts.boardRoot)) throw new Error('boardRoot must be 32-byte hex');
  const publicKey = typeof opts.publicKey === 'string' ? opts.publicKey : pointToHex(opts.publicKey);
  const signed: SignedFields = {
    contest: opts.contest,
    boardRoot: opts.boardRoot,
    paperManifestRoot: ballotManifestRoot(opts.manifest),
    numVoters: opts.numVoters,
    paperBallotsTotal: opts.manifest.paperBallotsTotal,
    publicKey,
    anchoredAt: opts.anchoredAt,
    signerPub: pointToHex(opts.signer.pub),
  };
  const s = sign(opts.signer.secret, anchorBytes(signed));
  return { version: 'vvp-paper-anchor-1', ...signed, sig: { R: pointToHex(s.R), s: s.s.toString() } };
}

/**
 * Verify an anchor from the public record alone (never throws). The signature is over ALL bound fields
 * incl. the signer key; a canonical-encoding gate pins every root/key to exactly 32 bytes so the bare
 * path is safe against field-boundary byte shifts. If `manifest` is given, the paper root and counts are
 * recomputed; if `expect` is given, the anchor is checked to bind that transcript's boardRoot/numVoters/
 * publicKey — and, when `expect.signerPub` is supplied, the signer is PINNED to that trusted authority key
 * (a valid self-signature alone proves only self-consistency, NOT that the authority you trust signed it).
 * A paper/digital count mismatch is flagged (ok:false) but is a discrepancy the canvass/RLA resolves —
 * paper wins (ADR-0004).
 */
export function verifyAnchor(
  anchor: PaperAnchor,
  manifest?: BallotManifest,
  expect?: { boardRoot: string; numVoters: number; publicKey: string; signerPub?: string },
): VerifyResult {
  const checks: Check[] = [];
  try {
    checks.push({ name: 'Anchor version is recognized', ok: anchor.version === 'vvp-paper-anchor-1' });
    const canon = is32hex(anchor.boardRoot) && is32hex(anchor.paperManifestRoot) && is32hex(anchor.publicKey)
      && is32hex(anchor.signerPub) && is32hex(anchor.sig.R) && validU32(anchor.numVoters) && validU32(anchor.paperBallotsTotal);
    checks.push({ name: 'Anchor fields are canonically encoded (32-byte roots/keys, uint32 counts)', ok: canon });
    if (!canon) return { ok: false, checks, results: null };

    const sigOk = verifySig(pointFromHex(anchor.signerPub), anchorBytes(anchor), { R: pointFromHex(anchor.sig.R), s: BigInt(anchor.sig.s) });
    checks.push({ name: 'Anchor self-signature is valid (over all bound fields, incl. the signer key)', ok: sigOk });
    if (expect?.signerPub !== undefined) {
      checks.push({ name: 'Anchor is signed by the PINNED election-authority key', ok: anchor.signerPub === expect.signerPub });
    }

    if (manifest) {
      checks.push({ name: 'Paper-manifest root matches the published batches', ok: ballotManifestRoot(manifest) === anchor.paperManifestRoot });
      const sum = manifest.batches.reduce((a, b) => a + b.ballotCount, 0);
      checks.push({ name: 'Manifest total = Σ batch counts = anchor paper total', ok: sum === manifest.paperBallotsTotal && sum === anchor.paperBallotsTotal });
    }
    if (expect) {
      checks.push({
        name: 'Anchor binds the published digital transcript (board root, count, key)',
        ok: anchor.boardRoot === expect.boardRoot && anchor.numVoters === expect.numVoters && anchor.publicKey === expect.publicKey,
      });
    }
    const reconciled = anchor.paperBallotsTotal === anchor.numVoters;
    checks.push({
      name: `Reconciliation: paper ballots (${anchor.paperBallotsTotal}) = digital ballots (${anchor.numVoters})`,
      ok: reconciled,
      detail: reconciled ? undefined : 'discrepancy — paper is the legal record; resolve by canvass/RLA (ADR-0004)',
    });
    return { ok: checks.every((c) => c.ok), checks, results: null };
  } catch (err) {
    return { ok: false, results: null, checks: [{ name: 'Anchor is well-formed (no exception)', ok: false, detail: String(err) }] };
  }
}

// ---- reported results + ballot-polling export (what the external RLA ingests) ----
export type TallyKind = 'plurality' | 'multiseat' | 'borda' | 'irv';

export interface ReportedResults {
  version: 'vvp-reported-results-1';
  contest: string;
  candidates: string[];
  auditMethod: 'ballot-polling'; // FORCED — secret-ballot tallies are polling-audited, never comparison
  tallyKind: TallyKind;
  reportedTally: number[]; // index-aligned to candidates (IRV: round-0 first-preference counts)
  totalBallots: number;
  winner: number; // candidate index whose outcome the RLA tests
}

export function reportedResults(contest: string, candidates: string[], tallyKind: TallyKind, reportedTally: number[], totalBallots: number, winner: number): ReportedResults {
  return { version: 'vvp-reported-results-1', contest, candidates, auditMethod: 'ballot-polling', tallyKind, reportedTally, totalBallots, winner };
}

export interface BallotPollingExport {
  version: 'vvp-bp-export-1';
  kind: 'rla-export'; // discriminator so a reader/CLI dispatches to the right verifier from the file alone
  anchor: PaperAnchor;
  manifest: BallotManifest;
  reported: ReportedResults; // carries ONLY totals — never a per-ballot CVR (privacy)
}

export function pollingExport(anchor: PaperAnchor, manifest: BallotManifest, reported: ReportedResults): BallotPollingExport {
  return { version: 'vvp-bp-export-1', kind: 'rla-export', anchor, manifest, reported };
}

/**
 * Verify a published RLA export from the file alone (never throws): the anchor (signature, canonical
 * encodings, manifest root, optional transcript binding + authority pinning, reconciliation) plus that
 * the reported results bind the same contest and are an aggregate ballot-polling tally (no per-ballot CVR).
 */
export function verifyExport(e: BallotPollingExport, expect?: { boardRoot: string; numVoters: number; publicKey: string; signerPub?: string }): VerifyResult {
  try {
    const base = verifyAnchor(e.anchor, e.manifest, expect);
    const checks: Check[] = [...base.checks];
    checks.push({ name: 'Reported results bind the same contest as the anchor', ok: e.reported.contest === e.anchor.contest });
    checks.push({
      name: 'Reported tally is an aggregate ballot-polling result (no per-ballot CVR)',
      ok: e.reported.auditMethod === 'ballot-polling' && Array.isArray(e.reported.reportedTally) && e.reported.reportedTally.length === e.reported.candidates.length,
    });
    return { ok: checks.every((c) => c.ok), checks, results: null };
  } catch (err) {
    return { ok: false, results: null, checks: [{ name: 'Export is well-formed (no exception)', ok: false, detail: String(err) }] };
  }
}

// Plain-JSON (de)serialization — every field is already a string/number, so a published export is a
// self-contained file an external tool (or verifyAnchor) re-reads.
export function pollingExportToJSON(e: BallotPollingExport): string { return JSON.stringify(e, null, 2); }
export function pollingExportFromJSON(json: string): BallotPollingExport { return JSON.parse(json) as BallotPollingExport; }

// ---- external-tool manifest emitters (the exact columns Arlo / SHANGRLA ingest) ----
function csvField(s: string): string { return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; }

/** VotingWorks Arlo ballot manifest CSV: Container, Tabulator, Batch Name, Number of Ballots. */
export function toArloManifestCsv(m: BallotManifest): string {
  return ['Container,Tabulator,Batch Name,Number of Ballots', ...sortedBatches(m).map((r) => `,,${csvField(r.batchId)},${r.ballotCount}`)].join('\n');
}

/** SHANGRLA manifest CSV: Batch, Total Ballots. */
export function toShangrlaManifestCsv(m: BallotManifest): string {
  return ['Batch,Total Ballots', ...sortedBatches(m).map((r) => `${csvField(r.batchId)},${r.ballotCount}`)].join('\n');
}

/**
 * Anonymized-CVR feed — ONLY for the mixnet-IRV path, whose anonymized ranking multiset is ALREADY
 * public (decrypted, unlinked to voters). `rankings[i][cand]` is the rank (0 = best). NEVER call this
 * with anything derived from a secret-ballot transcript — those have no per-ballot plaintext by design.
 */
export function toRankingsCsv(candidates: string[], rankings: number[][]): string {
  const header = ['anon_ballot', ...candidates.map((c) => `rank:${c}`)].join(',');
  return [header, ...rankings.map((r, i) => [`anon-${i + 1}`, ...r].join(','))].join('\n');
}

// ---- illustrative ballot-polling risk reference (NON-AUTHORITATIVE) ----
/**
 * Illustrative top-two BRAVO/ALPHA-mart ballot-polling sample-size estimate (Lindeman–Stark). NOT the
 * audit of record: ignores undervotes/other candidates, no stratification/ONEAudit. Run VotingWorks
 * Arlo or SHANGRLA on the PAPER for an authoritative risk-limiting audit. Returns Infinity when there is
 * no two-way margin to audit (a tie, an unopposed/zero-runner-up contest, or an empty tally).
 */
export function bravoSampleSize(reportedTally: number[], alpha: number): { sampleSize: number; marginPct: number; note: string } {
  const note = 'ILLUSTRATIVE top-two BRAVO; ignores undervotes/other candidates; NOT authoritative — run Arlo/SHANGRLA on paper';
  const total = reportedTally.reduce((a, b) => a + b, 0);
  const sorted = [...reportedTally].sort((a, b) => b - a);
  const w = sorted[0] ?? 0;
  const l = sorted[1] ?? 0;
  if (w <= l || l <= 0) return { sampleSize: Infinity, marginPct: 0, note }; // tie / unopposed / empty → no two-way margin
  const sw = w / (w + l);
  const sl = 1 - sw;
  const asn = Math.log(1 / alpha) / (sw * Math.log(2 * sw) + sl * Math.log(2 * sl));
  return { sampleSize: Math.ceil(asn), marginPct: total ? ((w - l) / total) * 100 : 0, note };
}

/**
 * Illustrative BRAVO ballot-polling SEQUENTIAL test (Lindeman–Stark). Walks the hand-read PAPER ballots
 * (`paper[i]` = candidate index, -1 = other/undervote) and runs the top-two likelihood-ratio test for the
 * REPORTED winner vs the reported runner-up; CONFIRMS when the statistic reaches 1/alpha, else the audit
 * escalates (does not confirm → full hand count). The point of the hybrid: if a compromised endpoint
 * flipped the digital outcome, the paper contradicts the reported winner, the statistic never reaches the
 * threshold, and the audit escalates — paper wins. NON-AUTHORITATIVE (top-two; ignores 3rd+ candidates;
 * a real audit draws a random sample and runs Arlo/SHANGRLA); for demonstration only.
 */
export function bravoBallotPolling(reportedTally: number[], paper: number[], alpha: number, maxDraws?: number): { confirmed: boolean; drawsExamined: number; stat: number; reportedWinner: number; note: string } {
  const note = 'ILLUSTRATIVE BRAVO ballot-polling sequential test (top-two); NOT authoritative — run Arlo/SHANGRLA on a random paper sample';
  const reportedWinner = reportedTally.indexOf(Math.max(...reportedTally));
  let loser = -1;
  let lc = -1;
  for (let c = 0; c < reportedTally.length; c++) if (c !== reportedWinner && reportedTally[c]! > lc) { lc = reportedTally[c]!; loser = c; }
  const w = reportedTally[reportedWinner] ?? 0;
  const l = loser >= 0 ? reportedTally[loser]! : 0;
  if (w <= l || w + l === 0) return { confirmed: false, drawsExamined: 0, stat: 0, reportedWinner, note };
  const sw = w / (w + l);
  const sl = 1 - sw;
  const target = 1 / alpha;
  let t = 1;
  let i = 0;
  const limit = Math.min(paper.length, maxDraws ?? paper.length);
  for (; i < limit; i++) {
    const b = paper[i]!;
    if (b === reportedWinner) t *= 2 * sw;
    else if (b === loser) t *= 2 * sl;
    // other candidates / undervotes contribute nothing to the two-way test
    if (t >= target) { i++; break; }
  }
  return { confirmed: t >= target, drawsExamined: i, stat: t, reportedWinner, note };
}

/**
 * A deterministic, proportionally-interleaved sequence over candidate `counts` — an illustration stand-in
 * for a random paper sample (representative at every prefix, so a sequential test behaves like the steady
 * state). A real audit draws ballots at random; this exists only to demonstrate confirm-vs-escalate.
 */
export function representativeSample(counts: number[]): number[] {
  const total = counts.reduce((a, b) => a + b, 0);
  const acc = counts.map(() => 0);
  const rem = [...counts];
  const out: number[] = [];
  for (let k = 0; k < total; k++) {
    let best = -1;
    let bestScore = -Infinity;
    for (let c = 0; c < counts.length; c++) {
      if (rem[c]! <= 0) continue;
      const score = (counts[c]! * (k + 1)) / total - acc[c]!; // largest-remainder round-robin
      if (score > bestScore) { bestScore = score; best = c; }
    }
    out.push(best);
    acc[best]! += 1;
    rem[best]! -= 1;
  }
  return out;
}
