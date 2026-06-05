import { useMemo, useState, type ReactNode } from 'react';
import {
  buildScenario, verify, auditCheck,
  tamperBallot, rigResult, doubleVote, ineligibleVote, overvote, ptShort,
  type Scenario, type VerifyResult,
} from './engine';

type Live = 'audit' | 'verify' | 'adversary' | null;
type Mode = 'real' | 'represented';

interface Phase {
  id: string;
  step: string;
  title: string;
  actor: string;
  mode: Mode;
  plain: string;
  tech: ReactNode;
  live?: Live;
}

function Row({ k, v }: { k: string; v: ReactNode }) {
  return (
    <div className="flex flex-wrap gap-2 text-xs">
      <span className="w-40 shrink-0 text-slate-500">{k}</span>
      <span className="font-mono text-indigo-200">{v}</span>
    </div>
  );
}

function Check({ ok, name, detail }: { ok: boolean; name: string; detail?: string }) {
  return (
    <li className="flex items-start gap-2 text-sm">
      <span className={ok ? 'text-emerald-400' : 'text-rose-400'}>{ok ? '✓' : '✗'}</span>
      <span className={ok ? 'text-slate-200' : 'text-rose-200'}>{name}{detail ? <span className="text-slate-400"> — {detail}</span> : null}</span>
    </li>
  );
}

export default function Walkthrough() {
  const sc: Scenario = useMemo(() => buildScenario(), []);
  const result: VerifyResult = useMemo(() => verify(sc.transcript), [sc]);
  const [i, setI] = useState(0);
  const [tech, setTech] = useState(false);
  const [cheat, setCheat] = useState<{ kind: string; result: VerifyResult } | null>(null);
  const [auditPick, setAuditPick] = useState<number | null>(null);

  const t = sc.transcript;
  const roll = t.eligibleRoll;
  const sampleBallot = t.ballots[0]!;

  const phases: Phase[] = [
    {
      id: 'setup', step: '1', title: 'Set up the election', actor: 'Organizer', mode: 'real',
      plain: 'An organizer states the question and candidates, and names the trustees who will jointly hold the decryption key — so no one person can ever open ballots alone.',
      tech: (<>
        <Row k="contest" v={t.contest} />
        <Row k="candidates" v={t.candidates.join('  ·  ')} />
        <Row k="trustees / threshold" v={`${t.trustees} trustees · any ${t.threshold} can decrypt`} />
        <p className="mt-2 text-xs text-slate-400">Captured declaratively in an <code>ElectionManifest</code>; everything below is derived from it.</p>
      </>),
    },
    {
      id: 'keygen', step: '2', title: 'Trustees generate the key together', actor: 'Trustees', mode: 'real',
      plain: 'The trustees run a joint ceremony that produces ONE public election key. The matching secret is split among them — it is never assembled in one place, so no single trustee (or small group) can decrypt anything.',
      tech: (<>
        <Row k="scheme" v="Pedersen / Feldman k-of-n DKG over ristretto255" />
        <Row k="public key  (= C₀)" v={ptShort(t.publicKey)} />
        <Row k="commitments" v={`${t.commitments.length} (C₀…C${t.commitments.length - 1}), one per polynomial coefficient`} />
        <p className="mt-2 text-xs text-slate-400">The secret is a Shamir-shared polynomial P with P(0)=x; trustee j holds P(j). x is never reconstructed — decryption uses Lagrange interpolation on partial results.</p>
      </>),
    },
    {
      id: 'register', step: '3', title: 'Register eligible voters', actor: 'Registrar', mode: 'represented',
      plain: 'A SEPARATE registrar checks who is eligible and privately hands each voter a personal credential. It publishes only an anonymous list of credential keys — never names. So the people who run the election never see who is who.',
      tech: (<>
        <Row k="credential" v="a fresh Schnorr keypair per voter (no SSN / durable ID — ADR-0001)" />
        <Row k="published roll" v={`${roll.length} credential public keys, e.g. ${ptShort(roll[0]!)}`} />
        <Row k="identity ↔ credential" v="held ONLY by the registrar, never serialized" />
        <p className="mt-2 text-xs text-amber-200/90">📟 <strong>Represented:</strong> the eligibility/ID check itself happens off-system (an org roll, OIDC, a check-in kiosk). The credential keypair is real.</p>
      </>),
    },
    {
      id: 'cast', step: '4', title: 'Vote on your own device', actor: 'Voter', mode: 'represented',
      plain: 'On their own device, the voter picks one candidate. The device encrypts the choice and attaches zero-knowledge proofs that it is a valid single selection — then signs it with the voter’s credential. The choice itself never leaves the device in the clear.',
      tech: (<>
        <Row k="encryption" v="exponential ElGamal (one ciphertext per candidate)" />
        <Row k="proofs" v="disjunctive Chaum–Pedersen (each is 0/1) + an ‘exactly one selected’ proof" />
        <Row k="signed by" v="the voter’s credential (Schnorr)" />
        <Row k="sample ciphertext" v={ptShort(sampleBallot.selection.enc[0]!.b)} />
        <p className="mt-2 text-xs text-amber-200/90">📟 <strong>Represented:</strong> the “phone / ballot-marking device” is a panel here — but the encryption + proofs run for real, client-side.</p>
      </>),
      live: 'audit',
    },
    {
      id: 'board', step: '5', title: 'Post to the public board', actor: 'Public', mode: 'real',
      plain: 'Every encrypted, signed ballot is posted to a public append-only board that anyone can read. Change, drop, or reorder any ballot and it’s immediately detectable.',
      tech: (<>
        <Row k="structure" v="RFC-6962 Merkle transparency log" />
        <Row k="ballots on board" v={`${t.ballots.length} (published in credential-sorted order — board position leaks no identity/timing)`} />
        <Row k="Merkle root" v={t.boardRoot.slice(0, 24) + '…'} />
      </>),
    },
    {
      id: 'tally', step: '6', title: 'Close & tally (quorum decrypts totals)', actor: 'Trustees', mode: 'real',
      plain: 'Voting closes. A quorum of trustees jointly decrypts only the TOTALS for each candidate — never any individual ballot. Each contributes a step with a proof that they did it honestly.',
      tech: (<>
        <Row k="aggregate" v="homomorphic sum of all ballots, per candidate" />
        <Row k="decryption" v={`${t.decShares.length} of ${t.trustees} trustees · Lagrange-combined · each share proven`} />
        <Row k="results" v={t.candidates.map((c, j) => `${c} ${t.results[j]}`).join('   ')} />
        <p className="mt-2 text-xs text-slate-400">Only the per-candidate totals are ever decrypted — there is no code path that decrypts a single ballot.</p>
      </>),
    },
    {
      id: 'publish', step: '7', title: 'Publish the whole election', actor: 'Public', mode: 'real',
      plain: 'The entire election is published as one self-contained file. It holds encrypted ballots, proofs, and signed roots — no names, no plaintext votes.',
      tech: (<>
        <Row k="format" v="canonical transcript.json (versioned wire format)" />
        <Row k="contains" v="eligible roll · encrypted ballots + proofs · aggregates · proven decryptions · results" />
        <Row k="does NOT contain" v="identities · plaintext votes · secret keys" />
      </>),
    },
    {
      id: 'verify', step: '8', title: 'Anyone verifies it', actor: 'Anyone', mode: 'real',
      plain: 'Anyone can re-check the entire result from that file, trusting only the math — not the people who ran it. We ship TWO independent verifiers (TypeScript and Python/libsodium) and cross-check them in CI.',
      tech: (<>
        <Row k="checks" v="signatures · eligibility · single-use · valid selections · honest aggregate · proven decryptions · tally" />
        <Row k="independence" v="TypeScript verifier ⇄ Python/libsodium verifier — agree byte-for-byte" />
      </>),
      live: 'verify',
    },
    {
      id: 'privacy', step: '9', title: 'Who knows what', actor: 'Everyone', mode: 'real',
      plain: 'No single party can link a person to their vote. The registrar can map a credential to an identity — but the vote is encrypted. The public sees credentials and encrypted ballots — but no identities. The trustees decrypt only totals.',
      tech: (<>
        <Row k="public board entry" v={`${sampleBallot.voter} → credential ${ptShort(sampleBallot.credentialPub)}`} />
        <Row k="public can map to a person?" v="no — the transcript has no identities" />
        <Row k="registrar (privately) maps it to" v={sc.registrar.identityOf(sampleBallot.credentialPub) ?? '(unknown)'} />
        <p className="mt-2 text-xs text-slate-400">The registrar alone learns <em>turnout</em> (who voted), never the vote. Linking a person to their actual choice would need the registrar AND a trustee quorum AND going off-protocol.</p>
      </>),
    },
    {
      id: 'adversary', step: '10', title: 'Try to cheat it', actor: 'Insider', mode: 'real',
      plain: 'Play the insider. Every classic attack — vote twice, vote without a credential, vote for two, flip a ballot, rig the total — is caught by the math, and anyone can see it.',
      tech: (<p className="text-xs text-slate-400">Each button runs the real verifier against a tampered transcript and shows exactly which check fails.</p>),
      live: 'adversary',
    },
  ];

  const p = phases[i]!;
  const runCheat = (kind: 'double' | 'ineligible' | 'overvote' | 'tamper' | 'rig') => {
    const f = {
      double: (x = t) => doubleVote(x, sc.voters), ineligible, overvote: (x = t) => overvote(x, sc.spare),
      tamper: tamperBallot, rig: rigResult,
    }[kind];
    setCheat({ kind, result: verify(f(t)) });
  };

  return (
    <div className="mx-auto max-w-4xl px-5 py-8">
      <header className="mb-6 text-center">
        <h1 className="bg-gradient-to-r from-indigo-300 to-emerald-300 bg-clip-text text-3xl font-extrabold text-transparent">🔬 How it works — end to end</h1>
        <p className="mt-1 text-sm text-slate-400">A real election, step by step. Every artifact below is produced by the actual engine.</p>
        <div className="mt-3 inline-flex items-center gap-2 rounded-full bg-white/5 p-1 text-xs">
          <button onClick={() => setTech(false)} className={`rounded-full px-3 py-1 ${!tech ? 'bg-indigo-500 text-white' : 'text-slate-300'}`}>Explain simply</button>
          <button onClick={() => setTech(true)} className={`rounded-full px-3 py-1 ${tech ? 'bg-indigo-500 text-white' : 'text-slate-300'}`}>Show the cryptography</button>
        </div>
      </header>

      {/* stepper */}
      <div className="mb-5 flex flex-wrap gap-1.5">
        {phases.map((ph, idx) => (
          <button key={ph.id} onClick={() => { setI(idx); setCheat(null); setAuditPick(null); }}
            className={`rounded-md px-2.5 py-1 text-xs font-medium ${idx === i ? 'bg-indigo-500 text-white' : idx < i ? 'bg-emerald-500/20 text-emerald-300' : 'bg-white/5 text-slate-400 hover:text-white'}`}>
            {ph.step}. {ph.title}
          </button>
        ))}
      </div>

      <section className="rounded-2xl border border-white/10 bg-white/5 p-6 shadow-xl">
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <span className="rounded-full bg-indigo-500/30 px-2.5 py-0.5 text-xs font-semibold text-indigo-200">{p.actor}</span>
          <span className={`rounded-full px-2.5 py-0.5 text-xs ${p.mode === 'real' ? 'bg-emerald-500/20 text-emerald-300' : 'bg-amber-400/15 text-amber-200'}`}>
            {p.mode === 'real' ? '● runs for real' : '📟 device represented'}
          </span>
          <h2 className="ml-auto text-lg font-semibold text-white">{p.step}. {p.title}</h2>
        </div>

        <p className="text-sm leading-relaxed text-slate-200">{p.plain}</p>

        {tech && <div className="mt-4 space-y-1.5 rounded-lg bg-slate-900/60 p-4">{p.tech}</div>}

        {/* live: audit */}
        {p.live === 'audit' && (
          <div className="mt-4 rounded-lg bg-slate-800/60 p-4">
            <p className="mb-2 text-xs text-slate-400">Audit a test ballot (Benaloh challenge): your device claims a choice — spoil it and check. A spoiled ballot is discarded, so a cheating device can never predict an audit.</p>
            <div className="flex flex-wrap gap-2">
              {t.candidates.map((c, j) => (
                <button key={j} onClick={() => setAuditPick(j)} className="rounded-lg bg-slate-700/70 px-3 py-1.5 text-xs font-semibold text-white hover:bg-slate-600">audit “{c}”</button>
              ))}
            </div>
            {auditPick !== null && (
              <div className="mt-3 text-sm">
                <p className="text-emerald-300">✓ Honest device that encrypted “{t.candidates[auditPick]}” passes: {String(auditCheck(t, auditPick, auditPick))}</p>
                <p className="text-rose-300">✗ A device that secretly encrypted “{t.candidates[(auditPick + 1) % t.candidates.length]}” passes as “{t.candidates[auditPick]}”? {String(auditCheck(t, (auditPick + 1) % t.candidates.length, auditPick))}</p>
              </div>
            )}
          </div>
        )}

        {/* live: verify */}
        {p.live === 'verify' && (
          <div className="mt-4 rounded-lg bg-slate-800/60 p-4">
            <ul className="space-y-1">{result.checks.map((c, idx) => <Check key={idx} {...c} />)}</ul>
            <p className={`mt-3 rounded px-3 py-2 text-sm font-semibold ${result.ok ? 'bg-emerald-500/15 text-emerald-300' : 'bg-rose-500/15 text-rose-300'}`}>
              {result.ok ? '🟢 VERIFIED from the public record alone — and the independent Python verifier agrees (checked in CI).' : '🔴 REJECTED'}
            </p>
          </div>
        )}

        {/* live: adversary */}
        {p.live === 'adversary' && (
          <div className="mt-4 rounded-lg bg-slate-800/60 p-4">
            <div className="flex flex-wrap gap-2">
              {(['double', 'ineligible', 'overvote', 'tamper', 'rig'] as const).map((k) => (
                <button key={k} onClick={() => runCheat(k)} className="rounded-lg bg-rose-600/80 px-3 py-1.5 text-xs font-semibold text-white hover:bg-rose-500">
                  😈 {{ double: 'Vote twice', ineligible: 'No credential', overvote: 'Vote for two', tamper: 'Flip a ballot', rig: 'Rig the result' }[k]}
                </button>
              ))}
            </div>
            {cheat && (
              <div className="mt-3">
                <ul className="space-y-1">{cheat.result.checks.filter((c) => !c.ok).map((c, idx) => <Check key={idx} {...c} />)}</ul>
                <p className="mt-2 text-sm font-semibold text-rose-300">🔴 Caught — the verifier rejects it.</p>
              </div>
            )}
          </div>
        )}

        <div className="mt-5 flex items-center justify-between">
          <button disabled={i === 0} onClick={() => { setI(i - 1); setCheat(null); setAuditPick(null); }} className="rounded-lg px-3 py-1.5 text-sm text-slate-300 hover:text-white disabled:text-slate-600">← Back</button>
          <span className="text-xs text-slate-500">{i + 1} / {phases.length}</span>
          <button disabled={i === phases.length - 1} onClick={() => { setI(i + 1); setCheat(null); setAuditPick(null); }} className="rounded-lg bg-indigo-500/80 px-4 py-1.5 text-sm font-semibold text-white hover:bg-indigo-400 disabled:bg-slate-700 disabled:text-slate-500">Next →</button>
        </div>
      </section>

      <p className="mt-6 text-center text-xs text-slate-500">
        Real cryptography, end to end; only the physical devices (phone, kiosk, printer) are represented. Pre-audit demo — not for binding government elections.
      </p>
    </div>
  );
}
