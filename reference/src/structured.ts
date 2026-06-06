// Structured (hierarchical) elections — parent groups, drill-down contests, and tags.
//
// An ElectionSpec is a TREE of contest nodes: a node with `candidates` is a LEAF
// contest you actually vote in; a node without candidates is a GROUP/category used
// for drill-down and tag display. Each leaf contest is run as its own independently
// verifiable sub-election (reusing the audited single-contest engine unchanged), so
// the hierarchy and tags are pure structure/metadata over proven crypto. Because
// every contest binds its own id into the Fiat-Shamir/signature context, a ballot in
// one contest can never be replayed into another.

import { runElection, type Transcript } from './election.js';
import type { KeySetup } from './threshold.js';
import { verifyTranscript, type VerifyResult } from './verify.js';
import type { Credential } from './credentials.js';
import { pointToHex, type Point } from './group.js';

export interface ContestSpec {
  id: string;
  title: string;
  tags: string[];
  parent?: string; // id of the parent group (drill-down); undefined = top level
  candidates?: string[]; // present → a leaf contest you vote in; absent → a group/category node
}

export interface ElectionSpec {
  title: string;
  contests: ContestSpec[];
}

export interface StructuredVoter {
  credential: Credential;
  choices: Record<string, number>; // leaf contest id → candidate index (omit a contest to abstain from it)
}

export interface ContestResult {
  id: string;
  title: string;
  tags: string[];
  candidates: string[];
  transcript: Transcript;
}

export interface ElectionResult {
  spec: ElectionSpec;
  results: ContestResult[]; // one per LEAF contest
}

export const isLeaf = (c: ContestSpec): boolean => Array.isArray(c.candidates) && c.candidates.length > 0;
export const leafContests = (spec: ElectionSpec): ContestSpec[] => spec.contests.filter(isLeaf);
export const childrenOf = (spec: ElectionSpec, parent?: string): ContestSpec[] =>
  spec.contests.filter((c) => c.parent === parent);
export const allTags = (spec: ElectionSpec): string[] =>
  [...new Set(spec.contests.flatMap((c) => c.tags))].sort();

/** Validate the tree: unique ids, existing parents, no cycles. */
export function validateSpec(spec: ElectionSpec): void {
  const ids = new Set<string>();
  for (const c of spec.contests) {
    if (ids.has(c.id)) throw new Error(`duplicate contest id: ${c.id}`);
    ids.add(c.id);
  }
  for (const c of spec.contests) {
    if (c.parent !== undefined && !ids.has(c.parent)) throw new Error(`contest ${c.id}: unknown parent ${c.parent}`);
    let cur = c.parent;
    let hops = 0;
    while (cur !== undefined) {
      if (cur === c.id) throw new Error(`contest ${c.id}: parent cycle`);
      cur = spec.contests.find((x) => x.id === cur)?.parent;
      if (++hops > spec.contests.length) throw new Error('contest tree has a cycle');
    }
  }
  // A parent must be a group node (not itself a votable leaf).
  for (const c of spec.contests) {
    if (c.parent !== undefined && isLeaf(spec.contests.find((x) => x.id === c.parent)!)) {
      throw new Error(`contest ${c.id}: parent ${c.parent} is a leaf, not a group`);
    }
  }
  // There must be at least one votable (leaf) contest.
  if (leafContests(spec).length === 0) throw new Error('election has no votable (leaf) contest');
}

/**
 * Run a structured election: each leaf contest is run as its own verifiable sub-election
 * (same trustee key + eligible roll + voter credentials). A voter who omits a contest from
 * `choices` simply abstains from it; single-use is enforced per contest.
 */
export function runStructuredElection(
  spec: ElectionSpec,
  voters: StructuredVoter[],
  keys: KeySetup,
  eligibleRoll: Point[],
): ElectionResult {
  validateSpec(spec);
  const results: ContestResult[] = leafContests(spec).map((c) => {
    const contestVoters = voters
      .filter((v) => Object.hasOwn(v.choices, c.id))
      .map((v) => ({ credential: v.credential, choice: v.choices[c.id]! }));
    const transcript = runElection(c.id, c.candidates!, contestVoters, keys, eligibleRoll);
    return { id: c.id, title: c.title, tags: c.tags, candidates: c.candidates!, transcript };
  });
  return { spec, results };
}

export interface StructuredCheck { name: string; ok: boolean; detail?: string }

const rollEqual = (a: Point[], b: Point[]): boolean =>
  a.length === b.length && a.every((p, i) => pointToHex(p) === pointToHex(b[i]!));

/**
 * Verify a structured election trustlessly: not only must every leaf transcript verify,
 * the bundle must be AUTHENTICATED against the spec — otherwise a producer could omit,
 * duplicate, or relabel/substitute whole (validly-signed) contests. So we also require:
 * the spec is well-formed; results are a 1:1 cover of the spec's leaf contests; each
 * result's id/candidates match BOTH the spec leaf and the transcript it wraps; and all
 * contests share one trustee key + eligible roll.
 */
export function verifyStructured(result: ElectionResult): {
  ok: boolean;
  checks: StructuredCheck[];
  perContest: { id: string; result: VerifyResult }[];
} {
  const checks: StructuredCheck[] = [];

  let specOk = true;
  let specErr = '';
  try { validateSpec(result.spec); } catch (e) { specOk = false; specErr = String(e); }
  checks.push({ name: 'Election spec is well-formed', ok: specOk, detail: specOk ? undefined : specErr });

  const expected = specOk ? leafContests(result.spec) : [];
  const expectedIds = new Set(expected.map((c) => c.id));
  const gotIds = result.results.map((r) => r.id);
  const gotSet = new Set(gotIds);
  const bijection = specOk && gotIds.length === expected.length && gotIds.length === gotSet.size
    && [...expectedIds].every((id) => gotSet.has(id));
  checks.push({
    name: 'Results cover exactly the spec leaf contests (1:1)',
    ok: bijection,
    detail: bijection ? undefined : `expected [${[...expectedIds].join(',')}], got [${gotIds.join(',')}]`,
  });

  let mismatch = 0;
  for (const r of result.results) {
    const leaf = expected.find((c) => c.id === r.id);
    const idOk = r.id === r.transcript.contest;
    const candsT = JSON.stringify(r.transcript.candidates) === JSON.stringify(r.candidates);
    const candsS = leaf ? JSON.stringify(leaf.candidates) === JSON.stringify(r.candidates) : false;
    if (!(idOk && candsT && candsS)) mismatch++;
  }
  checks.push({ name: 'Each result matches its spec leaf and its own transcript', ok: mismatch === 0, detail: mismatch ? `${mismatch} mismatched` : undefined });

  const first = result.results[0]?.transcript;
  const sameKeyRoll = result.results.length > 0 && result.results.every((r) =>
    r.transcript.publicKey.equals(first!.publicKey)
    && r.transcript.commitments.length === first!.commitments.length
    && r.transcript.commitments.every((c, i) => c.equals(first!.commitments[i]!))
    && rollEqual(r.transcript.eligibleRoll, first!.eligibleRoll));
  checks.push({ name: 'All contests share one trustee key and eligible roll', ok: sameKeyRoll });

  const perContest = result.results.map((r) => ({ id: r.id, result: verifyTranscript(r.transcript) }));
  checks.push({
    name: 'Every leaf contest transcript verifies',
    ok: perContest.length > 0 && perContest.every((p) => p.result.ok),
    detail: `${perContest.filter((p) => p.result.ok).length}/${perContest.length}`,
  });

  return { ok: checks.every((c) => c.ok), checks, perContest };
}
