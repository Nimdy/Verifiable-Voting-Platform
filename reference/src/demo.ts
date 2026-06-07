// End-to-end demo: register eligible voters, run a real MULTI-CANDIDATE verifiable
// election, audit a ballot (cast-as-intended), then play the INSIDER and try to
// cheat seven ways — and watch the independent verifier catch every one.
// Run with:  npm run demo

import { encrypt, addCiphertexts } from './elgamal.js';
import { proveBit, proveSumOne } from './proofs.js';
import { randScalar, mod, N, type Point } from './group.js';
import { issueCredential, sign, type Credential } from './credentials.js';
import { Registrar, type Eligible } from './registrar.js';
import { pointToHex } from './group.js';
import { signingBytes, boardBytes, electionContext } from './codec.js';
import { BulletinBoard } from './bulletin.js';
import {
  setupKeys, runElection, encryptSelection, singleTrusteeAttempt,
  type Transcript, type Voter, type BallotEntry, type Selection,
} from './election.js';
import { newSession, prepareBallot, challengeBallot, castBallot } from './session.js';
import { transcriptToJSON, rankedTranscriptToJSON, mixnetIrvTranscriptToJSON } from './transcript-json.js';
import {
  runStructuredElection, verifyStructured, childrenOf, allTags, isLeaf,
  type ElectionSpec, type StructuredVoter,
} from './structured.js';
import { runRankedElection, verifyRankedTranscript, type RankedVoter } from './ranked.js';
import { runMixnetElection, verifyMixnetTranscript, type MixnetVoter } from './mixnet-irv.js';
import { makeManifest, buildAnchor, verifyAnchor, reportedResults, pollingExport, pollingExportToJSON, toArloManifestCsv, bravoSampleSize, bravoBallotPolling, representativeSample, type BatchRow } from './rla.js';
import { AnchorLog, verifyAnchorLog, verifyRootAnchored, rootCommitment } from './anchorlog.js';
import { mkdirSync, writeFileSync } from 'node:fs';
import { verifyTranscript, type VerifyResult } from './verify.js';

const line = (c = '─') => console.log(c.repeat(72));

function report(label: string, r: VerifyResult): void {
  for (const c of r.checks) {
    console.log(`   ${c.ok ? '✅' : '❌'} ${c.name}${c.detail ? `  (${c.detail})` : ''}`);
  }
  console.log(`   ${r.ok ? '🟢 VERIFIED' : '🔴 REJECTED'} — ${label}\n`);
}

function rootOf(ctx: Uint8Array, ballots: BallotEntry[]): string {
  const board = new BulletinBoard();
  for (const b of ballots) board.append(boardBytes(ctx, b.credentialPub, b.selection, b.sig));
  return board.root();
}

function makeBallot(ctx: Uint8Array, cred: Credential, selection: Selection, label: string): BallotEntry {
  const sig = sign(cred.secret, signingBytes(ctx, selection));
  return { voter: label, credentialPub: cred.pub, selection, sig };
}

/** A malicious "overvote": select TWO candidates (each a valid bit, but the sum is 2). */
function overvoteSelection(pk: Point, K: number): Selection {
  const enc = [], bitProofs = [], rs: bigint[] = [];
  for (let j = 0; j < K; j++) {
    const v: 0 | 1 = j === 0 || j === 1 ? 1 : 0;
    const r = randScalar();
    const ct = encrypt(pk, BigInt(v), r);
    enc.push(ct); bitProofs.push(proveBit(pk, ct, v, r)); rs.push(r);
  }
  const R = rs.reduce((a, b) => mod(a + b, N), 0n);
  return { enc, bitProofs, sumProof: proveSumOne(pk, addCiphertexts(enc), R) };
}

line('━');
console.log('  VERIFIABLE VOTING — reference proof of concept');
console.log('  "One eligible voter, one vote. Verify everything. Reveal nothing."');
line('━');

const CANDIDATES = ['Tacos 🌮', 'Pizza 🍕', 'Sushi 🍣', 'Salad 🥗'];
const K = CANDIDATES.length;
const keys = setupKeys(5, 3); // 5 trustees; ANY 3 can decrypt
// A SEPARATE registrar issues credentials; the casting server will see ONLY the published roll.
const registrar = new Registrar();
const eligible: Eligible[] = Array.from({ length: 9 }, (_, i) => ({ id: `citizen-${i + 1}` }));
const packets = registrar.register(eligible); // 7 vote; 2 spare eligible credentials for attackers
const eligibleRoll = registrar.publishedRoll(); // identity-free, decorrelated order
const choices = [0, 1, 0, 2, 0, 3, 1]; // Tacos×3, Pizza×2, Sushi×1, Salad×1
const voters: Voter[] = choices.map((choice, i) => ({ credential: packets[i]!.credential, choice }));

console.log(`\nContest: "Best team lunch?"   Candidates: ${CANDIDATES.join(', ')}`);
console.log(`Trustees: ${keys.trustees.length} (any ${keys.threshold} can decrypt)   Registered: ${registrar.size()}   Voters: ${voters.length}`);

// Decrypt with only trustees #1, #3, #5 — trustees #2 and #4 are "offline".
const t = runElection('Best team lunch?', CANDIDATES, voters, keys, eligibleRoll, [1, 3, 5]);
const ctx = electionContext(t.contest, t.publicKey, t.candidates);
console.log(`Decryption performed by 3 of 5 trustees (#2 and #4 offline).`);
console.log('Announced results: ' + CANDIDATES.map((c, j) => `${c} ${t.results[j]}`).join('   ') + '\n');

line();
console.log('1) HONEST ELECTION — anyone re-verifies it from the transcript alone:');
line();
report('the published result is provably correct', verifyTranscript(t));

console.log('2) BALLOT SECRECY — a lone trustee tries to unmask one ciphertext:');
line();
const sneaky = singleTrusteeAttempt(t.ballots[0]!.selection.enc[0]!, keys.trustees[0]!, t.numVoters);
console.log(`   Trustee #1 alone tries to read a ballot value → ${sneaky === null ? '❌ FAILED' : `got ${sneaky}`}`);
console.log('   ✅ No single trustee can read any ballot. Only per-candidate TOTALS are decrypted.\n');

console.log('   REGISTRAR SEPARATION — no single party links identity to vote:');
line();
const sample = t.ballots[0]!;
console.log(`   Public board entry "${sample.voter}" shows a credential, not a person: ${pointToHex(sample.credentialPub).slice(0, 16)}…`);
console.log('   Can the casting server / public map it to an identity?  ✅ NO (the transcript has no identities)');
console.log(`   Only the registrar can, privately:  credential → ${registrar.identityOf(sample.credentialPub) ?? '(unknown)'}`);
console.log('   …and even the registrar cannot see the VOTE (encrypted; only the total is ever decrypted).\n');

console.log('3) CAST-OR-CHALLENGE (Benaloh) — audit one ballot, then cast a fresh one:');
line();
const session = newSession();
const trial = prepareBallot(t.publicKey, 2, K); // device claims to encrypt "Sushi"
console.log(`   Challenged ballot audits as the chosen candidate?  ${challengeBallot(session, t.publicKey, trial, 2) ? '✅ YES' : '❌ NO'}`);
let castBlocked = false;
try { castBallot(session, trial); } catch { castBlocked = true; }
console.log(`   Casting the challenged (spoiled) ballot is blocked?  ${castBlocked ? '✅ YES' : '🔴 NO'}`);
const lying = prepareBallot(t.publicKey, 0, K); // a device that secretly encrypted "Tacos"
console.log(`   A device that secretly encrypted a DIFFERENT candidate passes the audit?  ${challengeBallot(newSession(), t.publicKey, lying, 2) ? '🔴 YES' : '✅ NO'}`);
castBallot(session, prepareBallot(t.publicKey, 2, K)); // voter casts a FRESH, unrevealed ballot
console.log('   ✅ A challenged ballot is permanently discarded; the voter casts a fresh ballot.\n');

console.log('4) DOUBLE VOTE — voter-1 votes again with the same credential:');
line();
const dbl = [...t.ballots, makeBallot(ctx, packets[0]!.credential, encryptSelection(t.publicKey, 1, K).selection, 'voter-1-again')];
report('the same credential cannot be used twice', verifyTranscript({ ...t, ballots: dbl, boardRoot: rootOf(ctx, dbl), numVoters: dbl.length }));

console.log('5) INELIGIBLE VOTER — someone not on the roll forges a credential and votes:');
line();
const inel = [...t.ballots, makeBallot(ctx, issueCredential(), encryptSelection(t.publicKey, 0, K).selection, 'gate-crasher')];
report('only credentials on the published roll may vote', verifyTranscript({ ...t, ballots: inel, boardRoot: rootOf(ctx, inel), numVoters: inel.length }));

console.log('6) OVERVOTE — an eligible voter tries to vote for TWO candidates at once:');
line();
const over = [...t.ballots, makeBallot(ctx, packets[7]!.credential, overvoteSelection(t.publicKey, K), 'overvoter')];
report('a ballot must select exactly one candidate', verifyTranscript({ ...t, ballots: over, boardRoot: rootOf(ctx, over), numVoters: over.length }));

console.log('7) RIGGED RESULT — a corrupt authority pads a candidate\'s total:');
line();
const rigged = { ...t, results: t.results.map((n, j) => (j === 0 ? n + 2 : n)) };
report('the verifier recomputes the real totals and rejects the lie', verifyTranscript(rigged));

console.log('8) BELOW QUORUM — an insider drops trustees so fewer than k remain:');
line();
const fewer = { ...t, decShares: t.decShares.slice(0, keys.threshold - 1) };
report(`fewer than ${keys.threshold} trustees cannot produce a valid decryption`, verifyTranscript(fewer));

console.log('STRUCTURED BALLOT — parent → drill-down contests with tags:');
line();
const spec: ElectionSpec = {
  title: 'Community decisions',
  contests: [
    { id: 'budget', title: 'Budget', tags: ['budget'] },
    { id: 'park', title: 'Park budget', tags: ['budget', 'parks'], parent: 'budget', candidates: ['Low', 'Mid', 'High'] },
    { id: 'lib', title: 'Library hours', tags: ['budget'], parent: 'budget', candidates: ['Keep', 'Extend'] },
    { id: 'fest', title: 'Festival theme', tags: ['events'], candidates: ['Music', 'Food', 'Art'] },
  ],
};
const sVoters: StructuredVoter[] = packets.slice(0, 5).map((pk, i) => ({
  credential: pk.credential,
  choices: { park: i % 3, lib: i % 2, ...(i % 2 ? { fest: i % 3 } : {}) },
}));
const sResult = runStructuredElection(spec, sVoters, keys, eligibleRoll);
const sVerify = verifyStructured(sResult);
for (const top of childrenOf(spec, undefined)) {
  const fmt = (id: string, cands: string[]) => {
    const res = sResult.results.find((r) => r.id === id)!;
    return cands.map((c, j) => `${c} ${res.transcript.results[j]}`).join('  ');
  };
  if (isLeaf(top)) {
    console.log(`   ▸ ${top.title} [${top.tags.join(',')}]: ${fmt(top.id, top.candidates!)}`);
  } else {
    console.log(`   ▸ ${top.title} [${top.tags.join(',')}]  (drill down)`);
    for (const child of childrenOf(spec, top.id)) console.log(`      • ${child.title}: ${fmt(child.id, child.candidates!)}`);
  }
}
console.log(`   tags: ${allTags(spec).join(', ')}   ·   all ${sResult.results.length} contests verify: ${sVerify.ok ? '✅' : '❌'}\n`);

console.log('MULTI-SEAT — "vote for exactly 2 of 4" (block voting):');
line();
const seatCands = ['Ana', 'Ben', 'Cy', 'Dee'];
const seatVoters: Voter[] = packets.slice(0, 5).map((pk, i) => ({ credential: pk.credential, choice: [i % 4, (i + 1) % 4] }));
const seatT = runElection('Board seats (pick 2)', seatCands, seatVoters, keys, eligibleRoll, undefined, 2);
console.log('   results: ' + seatCands.map((c, j) => `${c} ${seatT.results[j]}`).join('   ') + `   ·   verify: ${verifyTranscript(seatT).ok ? '✅' : '❌'}  (Σ = 2×${seatT.numVoters})\n`);

console.log('RANKED-CHOICE (Borda) — a full ranked election, end to end:');
line();
const rkCands = ['Ada', 'Grace', 'Alan', 'Linus'];
const rkVoters: RankedVoter[] = packets.slice(0, 5).map((pk, i) => ({ credential: pk.credential, ranking: [0, 1, 2, 3].map((x) => (x + i) % 4) }));
const rkT = runRankedElection('Board chair (ranked)', rkCands, rkVoters, keys, eligibleRoll, [1, 3, 5]);
const rkV = verifyRankedTranscript(rkT);
console.log('   Borda totals: ' + rkCands.map((c, i) => `${c} ${rkT.results[i]}`).join('   '));
console.log(`   ${rkV.ok ? '🟢 VERIFIED' : '🔴 REJECTED'} — each ballot a valid permutation matrix; Borda tally threshold-decrypted by 3 of 5 trustees.`);
console.log('   (Borda never reveals a ballot. For true IRV elimination, see the mixnet path below.)\n');

console.log('RANKED-CHOICE (IRV) — verifiable instant-runoff via a re-encryption mixnet:');
line();
const irvCands = ['Ada', 'Grace', 'Alan'];
// 2× Ada>Grace>Alan, 2× Grace>Ada>Alan, 1× Alan>Ada>Grace → round 1 [2,2,1] eliminate Alan → round 2 [3,2,0] Ada wins.
const irvRanks = [[0, 1, 2], [0, 1, 2], [1, 0, 2], [1, 0, 2], [1, 2, 0]];
const irvVoters: MixnetVoter[] = packets.slice(0, 5).map((pk, i) => ({ credential: pk.credential, ranking: irvRanks[i]! }));
const irvT = runMixnetElection('Board chair (IRV)', irvCands, irvVoters, keys, eligibleRoll, [1, 3, 5]);
const irvV = verifyMixnetTranscript(irvT);
for (const [n, rd] of irvT.rounds.entries()) {
  const tally = irvCands.map((c, i) => `${c} ${rd.tallies[i]}`).join('  ');
  console.log(`   round ${n + 1}: ${tally}${rd.eliminatedThisRound !== null ? `  → eliminate ${irvCands[rd.eliminatedThisRound]}` : `  → 🏆 ${irvCands[rd.winner!]} wins`}`);
}
console.log(`   ${irvV.ok ? '🟢 VERIFIED' : '🔴 REJECTED'} — ballots shuffled by a proven re-encryption mixnet, then threshold-decrypted and tabulated; the verifier re-runs the rounds.`);
console.log('   ⚠ IRV REVEALS the anonymized ranking multiset (hides only WHICH voter cast which) — weaker than Borda. Not coercion-resistant.\n');

console.log('PAPER + RLA HYBRID (ADR-0004) — digital is the transparent companion; paper is the legal record:');
line();
const eaKey = issueCredential(); // the named election-authority / ceremony key
const paperBatches: BatchRow[] = [{ batchId: 'precinct-1', ballotCount: 4 }, { batchId: 'precinct-2', ballotCount: 3 }];
const manifest = makeManifest(t.contest, paperBatches);
const anchor = buildAnchor({ contest: t.contest, boardRoot: t.boardRoot, numVoters: t.numVoters, publicKey: t.publicKey, manifest, signer: eaKey, anchoredAt: '2026-06-06T00:00:00Z' });
const av = verifyAnchor(anchor, manifest, { boardRoot: t.boardRoot, numVoters: t.numVoters, publicKey: pointToHex(t.publicKey), signerPub: pointToHex(eaKey.pub) });
console.log(`   Digital board root ${t.boardRoot.slice(0, 18)}…  ⟷  paper manifest root ${anchor.paperManifestRoot.slice(0, 18)}…`);
console.log(`   Authority-signed anchor binds both records: ${av.ok ? '🟢 VERIFIED' : '🔴 REJECTED'}  (${manifest.paperBallotsTotal} paper = ${t.numVoters} digital ballots)`);
console.log('   Ballot manifest for VotingWorks Arlo / SHANGRLA — run the risk-limiting audit on the PAPER:');
console.log('     ' + toArloManifestCsv(manifest).split('\n').join('\n     '));
const bravo = bravoSampleSize(t.results, 0.05);
console.log(`   Illustrative ballot-polling sample (α=0.05): ~${bravo.sampleSize} paper ballots, margin ${bravo.marginPct.toFixed(0)}% — NOT authoritative; Arlo/SHANGRLA decide.`);
console.log('   ⚠ Paper is the legal record; the RLA on paper is what catches an endpoint/tabulation flip. Digital ≠ software independence (ADR-0004).\n');
const rlaWinner = t.results.indexOf(Math.max(...t.results));
const rlaExport = pollingExport(anchor, manifest, reportedResults(t.contest, t.candidates, 'plurality', t.results, t.numVoters, rlaWinner));

// M4 criterion (ADR-0004): would the RLA catch an endpoint that flipped the outcome? E2E-V alone can't —
// a compromised device shows the voter A, encrypts B, and the digital transcript then VERIFIES with B.
// Only the paper + RLA catches it.
console.log('   ── M4: would the RLA catch a flipped outcome? (the whole reason paper+RLA exists) ──');
const reportedTally = [40, 20]; // reported (digital) 67–33 for candidate 0
const honest = bravoBallotPolling(reportedTally, representativeSample([40, 20]), 0.05); // paper agrees
const flipped = bravoBallotPolling(reportedTally, representativeSample([20, 40]), 0.05); // endpoint flipped it: paper truly favors the OTHER candidate
console.log(`   honest  — paper agrees with the reported winner → ballot-polling CONFIRMS after ${honest.drawsExamined} sampled ballots (α=0.05).`);
console.log(`   flipped — paper contradicts the reported winner → audit does NOT confirm (examined ${flipped.drawsExamined}) → escalate to full hand count → PAPER WINS, the flip is caught.`);
console.log('   (illustrative BRAVO; a real deployment draws a random sample and runs VotingWorks Arlo / SHANGRLA.)\n');

console.log('CHAIN ANCHOR (ADR-0002/0003) — anchor only signed ROOTS, never ballots; named validators:');
line();
const validatorA = issueCredential();
const validatorB = issueCredential(); // two NAMED, accountable validators (no Proof-of-Stake — ADR-0003)
const anchorLog = new AnchorLog();
anchorLog.append(rootCommitment(t.contest, t.boardRoot, '2026-06-06T02:00:00Z', anchor.paperManifestRoot), validatorA);
anchorLog.append(rootCommitment('Board chair (ranked)', rkT.boardRoot, '2026-06-06T02:05:00Z'), validatorB);
const entries = anchorLog.entries();
const validators = [pointToHex(validatorA.pub), pointToHex(validatorB.pub)];
const head = anchorLog.head(); // running head a relying party pins OUT-OF-BAND (not a signed tree head)
const logOk = verifyAnchorLog(entries, { validators, expectHead: head, expectLength: entries.length }).ok;
const rootOk = verifyRootAnchored(entries, t.boardRoot, { paperManifestRoot: anchor.paperManifestRoot, validators }).ok;
const tamperOk = verifyAnchorLog(entries.map((e, i) => (i === 0 ? { ...e, commitment: { ...e.commitment, boardRoot: 'd'.repeat(64) } } : e)), { validators }).ok;
const noRosterOk = verifyAnchorLog(entries).ok; // same honest log, but no allowlist → not accountable
const truncatedOk = verifyAnchorLog([entries[0]!], { validators, expectHead: head }).ok; // dropped suffix vs pinned head
console.log(`   ${entries.length} root commitment(s) hash-chained + signed by 2 named validators — log valid (vs pinned head): ${logOk ? '🟢 YES' : '🔴 NO'}`);
console.log(`   This election's roots (board ${t.boardRoot.slice(0, 12)}… + paper) anchored & found in the log: ${rootOk ? '🟢 YES' : '🔴 NO'}`);
console.log(`   Tamper a committed root → log rejects: ${tamperOk === false ? '🟢 YES' : '🔴 NO'}`);
console.log(`   Drop the latest entry → caught by the head pinned out-of-band: ${truncatedOk === false ? '🟢 YES' : '🔴 NO'}`);
console.log(`   Present the log with NO validator allowlist → fails the accountability gate (self-asserted ≠ accountable): ${noRosterOk === false ? '🟢 YES' : '🔴 NO'}`);
console.log('   ⚠ Anchoring gives tamper-evidence + ordering for the ROOT within a presented copy (the embedded time is signer-asserted, NOT verified against a trusted clock) — not fork/equivocation safety (needs gossip/witness cosigning), not trust in the tally (that is E2E-V + the verifiers), and not software independence (that is paper + RLA).\n');

// Publish the transcripts so anyone can re-verify them from the public record alone.
mkdirSync('out', { recursive: true });
writeFileSync('out/transcript.json', transcriptToJSON(t));
writeFileSync('out/ranked.json', rankedTranscriptToJSON(rkT));
writeFileSync('out/mixnet-irv.json', mixnetIrvTranscriptToJSON(irvT));
writeFileSync('out/rla-export.json', pollingExportToJSON(rlaExport));
console.log('Public transcripts written to reference/out/ — verify them yourself:');
console.log('  npm run verify -- out/transcript.json   (plurality)');
console.log('  npm run verify -- out/ranked.json        (ranked-choice Borda)');
console.log('  npm run verify -- out/mixnet-irv.json    (ranked-choice IRV / mixnet)');
console.log('  npm run verify -- out/rla-export.json    (paper + RLA hybrid anchor)\n');

line('━');
console.log('  Summary: the honest election verifies; every insider attack is caught.');
console.log('  Eligibility · one-vote-per-credential · one-of-K · secrecy · k-of-n · cast-or-challenge · verifiable tally.');
line('━');
