import { useMemo, useState, type ReactNode } from 'react';
import {
  makeKeys, issueSpare, newVoter, tally, verify, ballotCipher, auditCheck,
  tamperBallot, rigResult, doubleVote, ineligibleVote, overvote, TRUSTEES, THRESHOLD,
  type VerifyResult, type Transcript, type Voter, type Credential,
} from './engine';
import Walkthrough from './Walkthrough';

const CANDIDATES = ['Tacos 🌮', 'Pizza 🍕', 'Sushi 🍣', 'Salad 🥗'];
const BAR = ['bg-emerald-400', 'bg-indigo-400', 'bg-amber-400', 'bg-rose-400'];

type CheatOutcome = { kind: 'tamper' | 'rig' | 'double' | 'ineligible' | 'overvote'; result: VerifyResult };

const CHEAT_MSG: Record<CheatOutcome['kind'], string> = {
  tamper: 'Altering a ballot breaks the Merkle root and its proof.',
  rig: 'The verifier recomputed the real totals — the lie does not match.',
  double: 'The same credential cannot vote twice (single-use nullifier).',
  ineligible: 'Only credentials on the published roll may vote.',
  overvote: 'A ballot must select exactly one candidate (the sum proof fails).',
};

function Card(props: { step: string; title: string; children: ReactNode }) {
  return (
    <section className="rounded-2xl border border-white/10 bg-white/5 p-6 shadow-xl backdrop-blur">
      <div className="mb-4 flex items-center gap-3">
        <span className="flex h-7 w-7 items-center justify-center rounded-full bg-indigo-500/30 text-sm font-bold text-indigo-200">{props.step}</span>
        <h2 className="text-lg font-semibold text-white">{props.title}</h2>
      </div>
      {props.children}
    </section>
  );
}

function CheckRow({ ok, name, detail }: { ok: boolean; name: string; detail?: string }) {
  return (
    <li className="flex items-start gap-2 text-sm">
      <span className={ok ? 'text-emerald-400' : 'text-rose-400'}>{ok ? '✓' : '✗'}</span>
      <span className={ok ? 'text-slate-200' : 'text-rose-200'}>
        {name}{detail ? <span className="text-slate-400"> — {detail}</span> : null}
      </span>
    </li>
  );
}

function Playground() {
  const [contest, setContest] = useState('Best team lunch? 🍽️');
  const [keys] = useState(() => makeKeys());
  const [spare] = useState<Credential>(() => issueSpare()); // an eligible-but-unused voter, for the overvote demo
  const [voters, setVoters] = useState<Voter[]>([]);
  const [revealed, setRevealed] = useState(false);
  const [cheat, setCheat] = useState<CheatOutcome | null>(null);
  const [auditFor, setAuditFor] = useState<number | null>(null);

  const transcript: Transcript | null = useMemo(
    () => (voters.length ? tally(contest, CANDIDATES, voters, keys, [spare.pub]) : null),
    [voters, keys, contest, spare],
  );
  const result = useMemo(() => (revealed && transcript ? verify(transcript) : null), [revealed, transcript]);
  const maxVotes = transcript ? Math.max(1, ...((result?.results ?? transcript.results) ?? [])) : 1;

  const cast = (choice: number) => { setVoters((p) => [...p, newVoter(choice)]); setRevealed(false); setCheat(null); };
  const simulate = () => {
    setVoters(Array.from({ length: 9 }, () => newVoter(Math.floor(Math.random() * CANDIDATES.length))));
    setRevealed(false); setCheat(null);
  };
  const reset = () => { setVoters([]); setRevealed(false); setCheat(null); setAuditFor(null); };

  const runCheat = (kind: CheatOutcome['kind']) => {
    if (!transcript) return;
    const f = { tamper: tamperBallot, rig: rigResult, double: (t: Transcript) => doubleVote(t, voters), ineligible: ineligibleVote, overvote: (t: Transcript) => overvote(t, spare) }[kind];
    setCheat({ kind, result: verify(f(transcript)) });
  };

  return (
    <div className="min-h-screen bg-gradient-to-b from-slate-950 via-slate-900 to-indigo-950 text-slate-100">
      <div className="mx-auto max-w-3xl px-5 py-10">
        <header className="mb-8 text-center">
          <h1 className="bg-gradient-to-r from-indigo-300 to-emerald-300 bg-clip-text text-4xl font-extrabold text-transparent">🗳️ Verifiable Voting</h1>
          <p className="mt-2 text-lg font-medium text-slate-200">One eligible voter, one vote. Verify everything. Reveal nothing.</p>
          <p className="mt-1 text-sm text-slate-400">No insider can cheat without getting caught — and you can prove it yourself, right here.</p>
        </header>

        <div className="space-y-5">
          {/* 1 — vote */}
          <Card step="1" title="Run an election">
            <input
              value={contest}
              onChange={(e) => { setContest(e.target.value); setRevealed(false); }}
              className="mb-3 w-full rounded-lg border border-white/10 bg-slate-800/60 px-3 py-2 text-sm text-white outline-none focus:border-indigo-400"
            />
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              {CANDIDATES.map((c, j) => (
                <button key={j} onClick={() => cast(j)} className="rounded-lg bg-slate-700/70 px-3 py-3 text-sm font-semibold text-white hover:bg-slate-600">
                  {c}
                </button>
              ))}
            </div>
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <button onClick={simulate} className="rounded-lg bg-indigo-500/80 px-4 py-2 text-sm font-semibold text-white hover:bg-indigo-400">🎲 Simulate 9 voters</button>
              {voters.length > 0 && <button onClick={reset} className="rounded-lg px-3 py-2 text-sm text-slate-400 hover:text-white">reset</button>}
              <span className="ml-auto text-sm text-slate-400">{voters.length} eligible voter(s)</span>
            </div>
            <p className="mt-3 text-xs text-slate-500">Each vote issues a fresh eligible-voter credential and is cryptographically signed — only registered voters count, once each, for exactly one candidate.</p>
          </Card>

          {/* 2 — board */}
          <Card step="2" title="The public bulletin board">
            {!transcript ? (
              <p className="text-sm text-slate-400">Cast a vote above and it appears here — encrypted.</p>
            ) : (
              <>
                <ul className="space-y-1 font-mono text-xs text-slate-300">
                  {transcript.ballots.slice(0, 8).map((_, i) => (
                    <li key={i} className="flex gap-3">
                      <span className="text-slate-500">{transcript.ballots[i]!.voter}</span>
                      <span className="text-emerald-500/80">✔ eligible</span>
                      <span className="truncate text-indigo-300">{ballotCipher(transcript, i).slice(0, 34)}…</span>
                    </li>
                  ))}
                  {transcript.ballots.length > 8 && <li className="text-slate-500">+ {transcript.ballots.length - 8} more…</li>}
                </ul>
                <p className="mt-3 rounded-lg bg-amber-400/10 px-3 py-2 text-xs text-amber-200">
                  👆 All the public sees: signed, encrypted ballots. The result is provable, yet no choice is exposed.
                  Merkle root: <span className="font-mono">{transcript.boardRoot.slice(0, 24)}…</span>
                </p>
              </>
            )}
          </Card>

          {/* 3 — tally & verify */}
          <Card step="3" title="Tally & verify">
            <button
              disabled={!transcript}
              onClick={() => { setRevealed(true); setCheat(null); }}
              className="rounded-lg bg-emerald-500 px-5 py-2.5 text-sm font-bold text-white hover:bg-emerald-400 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-500"
            >
              Tally &amp; Verify
            </button>
            {result && transcript && (
              <div className="mt-4">
                <div className="space-y-2">
                  {transcript.candidates.map((c, j) => {
                    const n = (result.results ?? transcript.results)[j] ?? 0;
                    return (
                      <div key={j} className="flex items-center gap-3">
                        <div className="w-28 shrink-0 text-sm text-slate-200">{c}</div>
                        <div className="h-6 flex-1 overflow-hidden rounded bg-slate-800">
                          <div className={`h-full ${BAR[j % BAR.length]} transition-all`} style={{ width: `${(n / maxVotes) * 100}%` }} />
                        </div>
                        <div className="w-8 text-right text-sm font-bold text-white">{n}</div>
                      </div>
                    );
                  })}
                </div>
                <ul className="mt-4 space-y-1">{result.checks.map((c, i) => <CheckRow key={i} {...c} />)}</ul>
                <p className={`mt-3 rounded-lg px-3 py-2 text-sm font-semibold ${result.ok ? 'bg-emerald-500/15 text-emerald-300' : 'bg-rose-500/15 text-rose-300'}`}>
                  {result.ok ? '🟢 VERIFIED by anyone, from the public record alone.' : '🔴 REJECTED.'}
                </p>
                <p className="mt-2 text-xs text-slate-400">🔒 Only these totals were ever decrypted. No individual ballot was — or can be — revealed.</p>
              </div>
            )}
          </Card>

          {/* 4 — audit (Benaloh) */}
          <Card step="4" title="Audit your ballot (cast-as-intended)">
            <p className="mb-3 text-xs text-slate-400">Worried your device encrypted the wrong choice? Spoil a test ballot and check it. (A spoiled ballot is discarded, so a cheating device can never predict an audit.)</p>
            <div className="flex flex-wrap gap-2">
              {CANDIDATES.map((c, j) => (
                <button key={j} disabled={!transcript} onClick={() => setAuditFor(j)} className="rounded-lg bg-slate-700/70 px-3 py-2 text-xs font-semibold text-white hover:bg-slate-600 disabled:bg-slate-800 disabled:text-slate-600">
                  audit “{c}”
                </button>
              ))}
            </div>
            {auditFor !== null && transcript && (
              <div className="mt-3 rounded-lg bg-slate-800/60 p-3 text-sm">
                <p className="text-emerald-300">✓ Honest device that encrypted “{CANDIDATES[auditFor]}” passes the audit: {String(auditCheck(transcript, auditFor, auditFor))}</p>
                <p className="text-rose-300">✗ A device that secretly encrypted “{CANDIDATES[(auditFor + 1) % CANDIDATES.length]}” would pass as “{CANDIDATES[auditFor]}”? {String(auditCheck(transcript, (auditFor + 1) % CANDIDATES.length, auditFor))}</p>
              </div>
            )}
          </Card>

          {/* 5 — cheat */}
          <Card step="5" title="Now try to cheat it (you're the insider)">
            <div className="flex flex-wrap gap-2">
              {(['double', 'ineligible', 'overvote', 'tamper', 'rig'] as const).map((k) => (
                <button key={k} disabled={!transcript} onClick={() => runCheat(k)} className="rounded-lg bg-rose-600/80 px-3 py-2 text-sm font-semibold text-white hover:bg-rose-500 disabled:bg-slate-700 disabled:text-slate-500">
                  😈 {{ double: 'Vote twice', ineligible: 'Vote without a credential', overvote: 'Vote for two', tamper: 'Flip a ballot', rig: 'Rig the result' }[k]}
                </button>
              ))}
            </div>
            {cheat && (
              <div className="mt-4 rounded-lg bg-slate-800/60 p-4">
                <ul className="space-y-1">{cheat.result.checks.map((c, i) => <CheckRow key={i} {...c} />)}</ul>
                <p className="mt-3 text-sm font-semibold text-rose-300">🔴 Caught. {CHEAT_MSG[cheat.kind]}</p>
              </div>
            )}
            {!transcript && <p className="mt-3 text-xs text-slate-400">Cast some votes first, then come back and try.</p>}
          </Card>
        </div>

        <footer className="mt-10 text-center text-xs text-slate-500">
          🔑 The decryption key is split across {TRUSTEES} trustees — <strong>any {THRESHOLD}</strong> can decrypt the totals, none alone.<br />
          Runs entirely in your browser using the same audited crypto as the <code className="text-slate-400">reference/</code> core. Pre-audit demo — not for binding elections.
        </footer>
      </div>
    </div>
  );
}

export default function App() {
  const [tab, setTab] = useState<'play' | 'walk'>('play');
  const tabCls = (on: boolean) =>
    `rounded-lg px-4 py-1.5 text-sm font-semibold ${on ? 'bg-indigo-500 text-white' : 'text-slate-300 hover:text-white'}`;
  return (
    <div className="min-h-screen bg-gradient-to-b from-slate-950 via-slate-900 to-indigo-950 text-slate-100">
      <nav className="sticky top-0 z-10 flex justify-center gap-2 border-b border-white/10 bg-slate-950/80 px-4 py-2 backdrop-blur">
        <button onClick={() => setTab('play')} className={tabCls(tab === 'play')}>🎮 Playground</button>
        <button onClick={() => setTab('walk')} className={tabCls(tab === 'walk')}>🔬 How it works</button>
      </nav>
      {tab === 'play' ? <Playground /> : <Walkthrough />}
    </div>
  );
}
