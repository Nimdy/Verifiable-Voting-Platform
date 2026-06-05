import { useMemo, useState, type ReactNode } from 'react';
import {
  makeTrustees, newVoter, tally, verify, ballotCipher, yesCount, noCount,
  tamperBallot, rigResult, doubleVote, ineligibleVote, stuffingAccepted,
  type VerifyResult, type Transcript, type Voter,
} from './engine';

type CheatOutcome =
  | { kind: 'tamper' | 'rig' | 'double' | 'ineligible'; result: VerifyResult }
  | { kind: 'stuff'; accepted: boolean };

const CHEAT_MSG: Record<Exclude<CheatOutcome['kind'], 'stuff'>, string> = {
  tamper: 'Altering a ballot breaks the Merkle root and its proof.',
  rig: 'The verifier recomputed the real tally — the lie does not match.',
  double: 'The same credential cannot vote twice (single-use nullifier).',
  ineligible: 'Only credentials on the published roll may vote.',
};

function Card(props: { step: string; title: string; children: ReactNode }) {
  return (
    <section className="rounded-2xl border border-white/10 bg-white/5 p-6 shadow-xl backdrop-blur">
      <div className="mb-4 flex items-center gap-3">
        <span className="flex h-7 w-7 items-center justify-center rounded-full bg-indigo-500/30 text-sm font-bold text-indigo-200">
          {props.step}
        </span>
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
        {name}
        {detail ? <span className="text-slate-400"> — {detail}</span> : null}
      </span>
    </li>
  );
}

export default function App() {
  const [question, setQuestion] = useState('Should 🌮 Taco Tuesday be official?');
  const [trustees] = useState(() => makeTrustees(3));
  const [voters, setVoters] = useState<Voter[]>([]);
  const [revealed, setRevealed] = useState(false);
  const [cheat, setCheat] = useState<CheatOutcome | null>(null);

  const transcript: Transcript | null = useMemo(
    () => (voters.length ? tally(question, voters, trustees) : null),
    [voters, trustees, question],
  );
  const result = useMemo(
    () => (revealed && transcript ? verify(transcript) : null),
    [revealed, transcript],
  );

  const cast = (v: 0 | 1) => { setVoters((p) => [...p, newVoter(v)]); setRevealed(false); setCheat(null); };
  const simulate = () => {
    setVoters(Array.from({ length: 7 }, () => newVoter(Math.random() < 0.55 ? 1 : 0)));
    setRevealed(false); setCheat(null);
  };
  const reset = () => { setVoters([]); setRevealed(false); setCheat(null); };

  const runCheat = (kind: CheatOutcome['kind']) => {
    if (!transcript) return;
    if (kind === 'tamper') setCheat({ kind, result: verify(tamperBallot(transcript)) });
    else if (kind === 'rig') setCheat({ kind, result: verify(rigResult(transcript)) });
    else if (kind === 'double') setCheat({ kind, result: verify(doubleVote(transcript, voters)) });
    else if (kind === 'ineligible') setCheat({ kind, result: verify(ineligibleVote(transcript)) });
    else setCheat({ kind: 'stuff', accepted: stuffingAccepted(transcript) });
  };

  const cheatBtn = (kind: CheatOutcome['kind'], label: string) => (
    <button
      disabled={!transcript}
      onClick={() => runCheat(kind)}
      className="rounded-lg bg-rose-600/80 px-3 py-2 text-sm font-semibold text-white hover:bg-rose-500 disabled:bg-slate-700 disabled:text-slate-500"
    >
      {label}
    </button>
  );

  return (
    <div className="min-h-screen bg-gradient-to-b from-slate-950 via-slate-900 to-indigo-950 text-slate-100">
      <div className="mx-auto max-w-3xl px-5 py-10">
        <header className="mb-8 text-center">
          <h1 className="bg-gradient-to-r from-indigo-300 to-emerald-300 bg-clip-text text-4xl font-extrabold text-transparent">
            🗳️ Verifiable Voting
          </h1>
          <p className="mt-2 text-lg font-medium text-slate-200">
            One eligible voter, one vote. Verify everything. Reveal nothing.
          </p>
          <p className="mt-1 text-sm text-slate-400">
            No insider can cheat without getting caught — and you can prove it yourself, right here.
          </p>
        </header>

        <div className="space-y-5">
          {/* 1 — vote */}
          <Card step="1" title="Register voters & collect votes">
            <input
              value={question}
              onChange={(e) => { setQuestion(e.target.value); setRevealed(false); }}
              className="mb-3 w-full rounded-lg border border-white/10 bg-slate-800/60 px-3 py-2 text-sm text-white outline-none focus:border-indigo-400"
            />
            <div className="flex flex-wrap items-center gap-2">
              <button onClick={() => cast(1)} className="rounded-lg bg-emerald-500/90 px-4 py-2 text-sm font-semibold text-white hover:bg-emerald-400">
                Vote Yes
              </button>
              <button onClick={() => cast(0)} className="rounded-lg bg-slate-600 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-500">
                Vote No
              </button>
              <button onClick={simulate} className="rounded-lg bg-indigo-500/80 px-4 py-2 text-sm font-semibold text-white hover:bg-indigo-400">
                🎲 Simulate 7 voters
              </button>
              {voters.length > 0 && (
                <button onClick={reset} className="rounded-lg px-3 py-2 text-sm text-slate-400 hover:text-white">reset</button>
              )}
              <span className="ml-auto text-sm text-slate-400">{voters.length} eligible voter(s)</span>
            </div>
            <p className="mt-3 text-xs text-slate-500">
              Each vote issues a fresh eligible-voter credential and is cryptographically signed — so only registered
              voters count, and only once each.
            </p>
          </Card>

          {/* 2 — bulletin board */}
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
                      <span className="truncate text-indigo-300">{ballotCipher(transcript, i).slice(0, 38)}…</span>
                    </li>
                  ))}
                  {transcript.ballots.length > 8 && (
                    <li className="text-slate-500">+ {transcript.ballots.length - 8} more…</li>
                  )}
                </ul>
                <p className="mt-3 rounded-lg bg-amber-400/10 px-3 py-2 text-xs text-amber-200">
                  👆 This is <strong>all</strong> the public ever sees: signed, encrypted ballots. The result is still
                  provable, yet no choice is exposed. Merkle root: <span className="font-mono">{transcript.boardRoot.slice(0, 24)}…</span>
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
                <div className="mb-4 flex gap-4">
                  <div className="flex-1 rounded-xl bg-emerald-500/15 p-4 text-center">
                    <div className="text-3xl font-extrabold text-emerald-300">{yesCount(transcript)}</div>
                    <div className="text-xs text-emerald-200">Yes</div>
                  </div>
                  <div className="flex-1 rounded-xl bg-slate-600/20 p-4 text-center">
                    <div className="text-3xl font-extrabold text-slate-200">{noCount(transcript)}</div>
                    <div className="text-xs text-slate-400">No</div>
                  </div>
                </div>
                <ul className="space-y-1">
                  {result.checks.map((c, i) => <CheckRow key={i} {...c} />)}
                </ul>
                <p className={`mt-3 rounded-lg px-3 py-2 text-sm font-semibold ${result.ok ? 'bg-emerald-500/15 text-emerald-300' : 'bg-rose-500/15 text-rose-300'}`}>
                  {result.ok ? '🟢 VERIFIED by anyone, from the public record alone.' : '🔴 REJECTED.'}
                </p>
                <p className="mt-2 text-xs text-slate-400">
                  🔒 Only these totals were ever decrypted. No individual ballot was — or can be — revealed.
                </p>
              </div>
            )}
          </Card>

          {/* 4 — cheat */}
          <Card step="4" title="Now try to cheat it (you're the insider)">
            <div className="flex flex-wrap gap-2">
              {cheatBtn('double', '😈 Vote twice')}
              {cheatBtn('ineligible', '😈 Vote without a credential')}
              {cheatBtn('tamper', '😈 Flip a stored ballot')}
              {cheatBtn('stuff', '😈 Stuff a fake vote')}
              {cheatBtn('rig', '😈 Rig the result')}
            </div>
            {cheat && (
              <div className="mt-4 rounded-lg bg-slate-800/60 p-4">
                {cheat.kind === 'stuff' ? (
                  <p className="text-sm font-semibold text-emerald-300">
                    {cheat.accepted
                      ? '🔴 Accepted?! (this should never happen)'
                      : '✓ Rejected — an out-of-range vote cannot produce a valid zero-knowledge proof.'}
                  </p>
                ) : (
                  <>
                    <ul className="space-y-1">
                      {cheat.result.checks.map((c, i) => <CheckRow key={i} {...c} />)}
                    </ul>
                    <p className="mt-3 text-sm font-semibold text-rose-300">🔴 Caught. {CHEAT_MSG[cheat.kind]}</p>
                  </>
                )}
              </div>
            )}
            {!transcript && <p className="mt-3 text-xs text-slate-400">Cast some votes first, then come back and try.</p>}
          </Card>
        </div>

        <footer className="mt-10 text-center text-xs text-slate-500">
          Runs entirely in your browser using the same audited crypto as the{' '}
          <code className="text-slate-400">reference/</code> core. Pre-audit demo — not for binding elections.
        </footer>
      </div>
    </div>
  );
}
