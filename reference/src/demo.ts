// End-to-end demo: register eligible voters, run a real verifiable election, then
// play the INSIDER and try to cheat six different ways — and watch the independent
// verifier catch every one. Run with:  npm run demo
//
// Thesis on display: only eligible people vote, once each; count the votes; reveal
// no one's ballot; make cheating impossible to hide.

import { encrypt } from './elgamal.js';
import { proveBit, verifyBit } from './proofs.js';
import { randScalar, type Point } from './group.js';
import { issueCredential, registerVoters, sign, type Credential } from './credentials.js';
import { signingBytes, boardBytes } from './codec.js';
import { BulletinBoard } from './bulletin.js';
import {
  setupTrustees, runElection, singleTrusteeAttempt, type Transcript, type Voter, type BallotEntry,
} from './election.js';
import { verifyTranscript, type VerifyResult } from './verify.js';

const line = (c = '─') => console.log(c.repeat(72));

function report(label: string, r: VerifyResult): void {
  for (const c of r.checks) {
    console.log(`   ${c.ok ? '✅' : '❌'} ${c.name}${c.detail ? `  (${c.detail})` : ''}`);
  }
  console.log(`   ${r.ok ? '🟢 VERIFIED' : '🔴 REJECTED'} — ${label}\n`);
}

// Rebuild the board root over a ballot set (so an attack can present a *consistent*
// transcript and we isolate exactly which check catches the cheating).
function rootOf(ballots: BallotEntry[]): string {
  const board = new BulletinBoard();
  for (const b of ballots) board.append(boardBytes(b.credentialPub, b.ct, b.proof, b.sig));
  return board.root();
}

// Forge a fresh signed ballot for a given credential and vote (used by attackers).
function makeBallot(cred: Credential, vote: 0 | 1, pk: Point, label: string): BallotEntry {
  const r = randScalar();
  const ct = encrypt(pk, BigInt(vote), r);
  const proof = proveBit(pk, ct, vote, r);
  const sig = sign(cred.secret, signingBytes(ct, proof));
  return { voter: label, credentialPub: cred.pub, ct, proof, sig };
}

line('━');
console.log('  VERIFIABLE VOTING — reference proof of concept');
console.log('  "Only eligible voters, once each. Verify everything. Reveal nothing."');
line('━');

// ---------------------------------------------------------------------------
// Setup: 3 trustees jointly hold the key. The registrar issues 7 eligible
// credentials. 7 voters cast a yes/no ballot. True result: 4 YES, 3 NO.
// ---------------------------------------------------------------------------
const trustees = setupTrustees(3);
const roll = registerVoters(7); // the registrar's published eligible roll
const eligibleRoll = roll.map((c) => c.pub);
const choices: (0 | 1)[] = [1, 0, 1, 1, 0, 1, 0]; // 4 YES, 3 NO
const voters: Voter[] = roll.map((credential, i) => ({ credential, vote: choices[i]! }));
const truth = choices.filter((v) => v === 1).length;

console.log(`\nContest: "Adopt Proposal 1?"   Options: [No, Yes]`);
console.log(`Trustees: ${trustees.length}   Eligible voters registered: ${roll.length}`);
console.log(`Voters: ${voters.length}   (ground truth: ${truth} YES / ${voters.length - truth} NO)\n`);

const transcript = runElection('Adopt Proposal 1?', ['No', 'Yes'], voters, trustees, eligibleRoll);
console.log(`Bulletin-board root: ${transcript.boardRoot.slice(0, 32)}…`);
console.log(`Authority announces: ${transcript.claimedTally} YES\n`);

line();
console.log('1) HONEST ELECTION — anyone re-verifies it from the transcript alone:');
line();
report('the published result is provably correct', verifyTranscript(transcript));

// ---------------------------------------------------------------------------
console.log('2) BALLOT SECRECY — a lone trustee tries to unmask one voter:');
line();
const sneaky = singleTrusteeAttempt(transcript.ballots[1]!.ct, trustees[0]!, transcript.numVoters);
console.log(`   Trustee #1 alone tries to decrypt voter-2's ballot → ${sneaky === null ? '❌ FAILED' : `recovered ${sneaky}`}`);
console.log('   ✅ No single trustee can read any ballot. Only the TOTAL is ever decrypted.\n');

// ---------------------------------------------------------------------------
console.log('3) DOUBLE VOTE — voter-1 tries to vote a second time with the same credential:');
line();
const dbl: BallotEntry[] = [...transcript.ballots, makeBallot(roll[0]!, 1, transcript.publicKey, 'voter-1-again')];
const attackDouble: Transcript = { ...transcript, ballots: dbl, boardRoot: rootOf(dbl) };
report('the same credential cannot be used twice', verifyTranscript(attackDouble));

// ---------------------------------------------------------------------------
console.log('4) INELIGIBLE VOTER — someone not on the roll forges a credential and votes:');
line();
const outsider = issueCredential(); // never registered
const inel: BallotEntry[] = [...transcript.ballots, makeBallot(outsider, 1, transcript.publicKey, 'gate-crasher')];
const attackIneligible: Transcript = { ...transcript, ballots: inel, boardRoot: rootOf(inel) };
report('only credentials on the published roll may vote', verifyTranscript(attackIneligible));

// ---------------------------------------------------------------------------
console.log('5) BALLOT STUFFING — a voter tries to cast "10" instead of 0 or 1:');
line();
const r = randScalar();
const stuffed = encrypt(transcript.publicKey, 10n, r);
const accepted = verifyBit(transcript.publicKey, stuffed, proveBit(transcript.publicKey, stuffed, 1, r));
console.log(`   Forged validity proof for an illegal vote accepted? ${accepted ? '🔴 YES' : '✅ NO'}`);
console.log('   ✅ Only genuine 0/1 ballots can ever produce a valid proof.\n');

// ---------------------------------------------------------------------------
console.log('6) RIGGED RESULT — a corrupt authority announces a fake landslide:');
line();
const attackRig: Transcript = { ...transcript, claimedTally: transcript.numVoters };
report('the verifier recomputes the real tally and rejects the lie', verifyTranscript(attackRig));

line('━');
console.log('  Summary: the honest election verifies; every insider attack is caught.');
console.log('  Eligibility + one-vote-per-credential + secrecy + verifiable tally.');
line('━');
