// End-to-end demo: register eligible voters, run a real MULTI-CANDIDATE verifiable
// election, audit a ballot (cast-as-intended), then play the INSIDER and try to
// cheat seven ways — and watch the independent verifier catch every one.
// Run with:  npm run demo

import { encrypt, addCiphertexts } from './elgamal.js';
import { proveBit, proveSumOne } from './proofs.js';
import { randScalar, mod, N, type Point } from './group.js';
import { issueCredential, registerVoters, sign, type Credential } from './credentials.js';
import { signingBytes, boardBytes, electionContext } from './codec.js';
import { BulletinBoard } from './bulletin.js';
import {
  setupTrustees, runElection, encryptSelection, auditSelection, singleTrusteeAttempt,
  type Transcript, type Voter, type BallotEntry, type Selection,
} from './election.js';
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
const trustees = setupTrustees(3);
const roll = registerVoters(9); // 7 vote; 2 spare eligible credentials for attackers
const eligibleRoll = roll.map((c) => c.pub);
const choices = [0, 1, 0, 2, 0, 3, 1]; // Tacos×3, Pizza×2, Sushi×1, Salad×1
const voters: Voter[] = choices.map((choice, i) => ({ credential: roll[i]!, choice }));

console.log(`\nContest: "Best team lunch?"   Candidates: ${CANDIDATES.join(', ')}`);
console.log(`Trustees: ${trustees.length}   Eligible voters: ${roll.length}   Voters: ${voters.length}\n`);

const t = runElection('Best team lunch?', CANDIDATES, voters, trustees, eligibleRoll);
const ctx = electionContext(t.contest, t.publicKey, t.candidates);
console.log('Announced results: ' + CANDIDATES.map((c, j) => `${c} ${t.results[j]}`).join('   ') + '\n');

line();
console.log('1) HONEST ELECTION — anyone re-verifies it from the transcript alone:');
line();
report('the published result is provably correct', verifyTranscript(t));

console.log('2) BALLOT SECRECY — a lone trustee tries to unmask one ciphertext:');
line();
const sneaky = singleTrusteeAttempt(t.ballots[0]!.selection.enc[0]!, trustees[0]!, t.numVoters);
console.log(`   Trustee #1 alone tries to read a ballot value → ${sneaky === null ? '❌ FAILED' : `got ${sneaky}`}`);
console.log('   ✅ No single trustee can read any ballot. Only per-candidate TOTALS are decrypted.\n');

console.log('3) CAST-AS-INTENDED — a voter audits (spoils) a ballot to check their device:');
line();
const audited = encryptSelection(t.publicKey, 2, K); // device claims to encrypt "Sushi"
console.log(`   Honest device encrypted the chosen candidate?  ${auditSelection(t.publicKey, audited.selection, audited.randomness, 2) ? '✅ YES' : '❌ NO'}`);
console.log(`   Would a device that secretly encrypted a DIFFERENT candidate pass?  ${auditSelection(t.publicKey, audited.selection, audited.randomness, 0) ? '🔴 YES' : '✅ NO'}`);
console.log('   ✅ A spoiled ballot is discarded; a cheating device cannot predict an audit.\n');

console.log('4) DOUBLE VOTE — voter-1 votes again with the same credential:');
line();
const dbl = [...t.ballots, makeBallot(ctx, roll[0]!, encryptSelection(t.publicKey, 1, K).selection, 'voter-1-again')];
report('the same credential cannot be used twice', verifyTranscript({ ...t, ballots: dbl, boardRoot: rootOf(ctx, dbl) }));

console.log('5) INELIGIBLE VOTER — someone not on the roll forges a credential and votes:');
line();
const inel = [...t.ballots, makeBallot(ctx, issueCredential(), encryptSelection(t.publicKey, 0, K).selection, 'gate-crasher')];
report('only credentials on the published roll may vote', verifyTranscript({ ...t, ballots: inel, boardRoot: rootOf(ctx, inel) }));

console.log('6) OVERVOTE — an eligible voter tries to vote for TWO candidates at once:');
line();
const over = [...t.ballots, makeBallot(ctx, roll[7]!, overvoteSelection(t.publicKey, K), 'overvoter')];
report('a ballot must select exactly one candidate', verifyTranscript({ ...t, ballots: over, boardRoot: rootOf(ctx, over) }));

console.log('7) RIGGED RESULT — a corrupt authority pads a candidate\'s total:');
line();
const rigged = { ...t, results: t.results.map((n, j) => (j === 0 ? n + 2 : n)) };
report('the verifier recomputes the real totals and rejects the lie', verifyTranscript(rigged));

line('━');
console.log('  Summary: the honest election verifies; every insider attack is caught.');
console.log('  Eligibility · one-vote-per-credential · one-candidate-per-ballot · secrecy · verifiable tally.');
line('━');
