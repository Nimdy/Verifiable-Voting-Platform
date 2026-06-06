import { useMemo, useState, type ReactNode } from 'react';
import {
  makeKeys, issueSpare, newRankedVoter, rankedTally, verifyRanked,
  buildRankedBallot, verifyGrid, forgeInvalidBallot, cellCipher,
  TRUSTEES, THRESHOLD,
  type RankedBallot, type RankedTranscript, type RankedVoter, type VerifyResult,
  type GridVerdict, type Credential,
} from './engine';

// Fixed 4 candidates: the grid must stay groktable, so candidates are NOT user-editable.
const CANDIDATES = ['🌮 Tacos', '🍕 Pizza', '🍣 Sushi', '🥗 Salad'];
const RANKS = ['1st 🥇', '2nd 🥈', '3rd 🥉', '4th'];
const K = CANDIDATES.length;
const BAR = ['bg-emerald-400', 'bg-indigo-400', 'bg-amber-400', 'bg-rose-400'];
// per-candidate row tint (left border + faint fill) so each candidate's row reads as one unit
const TINT = [
  'border-emerald-400/60 bg-emerald-400/5',
  'border-indigo-400/60 bg-indigo-400/5',
  'border-amber-400/60 bg-amber-400/5',
  'border-rose-400/60 bg-rose-400/5',
];

const prefersReducedMotion =
  typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;

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

// A margin pill showing the proven sum of a row/column. PASS/FAIL is the REAL verifier; Σ is
// display-only. No per-badge aria-live — a single consolidated status region (below the grid)
// announces the outcome so screen readers get one coherent sentence, not an 8-part burst.
function SumBadge({ state }: { state: { ok: boolean; sum: number } | null }) {
  if (!state) {
    return <span className="inline-block rounded-full bg-white/5 px-2 py-0.5 text-[11px] text-slate-400">Σ = ?</span>;
  }
  return (
    <span className={`inline-block rounded-full px-2 py-0.5 text-[11px] font-semibold ${state.ok ? 'bg-emerald-500/20 text-emerald-300' : 'bg-rose-500/15 text-rose-300'}`}>
      = {state.sum} {state.ok ? '✓' : '✗'}
    </span>
  );
}

/** The hero: a candidates×ranks grid of identical locked cells whose margins prove a permutation. */
function MatrixGrid({ ballot, verdict }: { ballot: RankedBallot; verdict: GridVerdict | null }) {
  return (
    <div className="overflow-x-auto">
      <table className="border-separate border-spacing-1 text-center">
        <thead>
          <tr>
            <th className="px-2 py-1" />
            {RANKS.map((r, j) => (
              <th key={j} scope="col" className="px-1 py-1 text-xs font-medium text-slate-300">
                <div>{r}</div>
                <div className="text-[10px] text-slate-500">+{K - 1 - j}</div>
              </th>
            ))}
            <th scope="col" className="px-2 py-1 text-[11px] font-medium text-slate-400">each candidate</th>
          </tr>
        </thead>
        <tbody>
          {CANDIDATES.map((cand, i) => (
            <tr key={i}>
              <th scope="row" className={`whitespace-nowrap rounded-l-lg border-l-2 py-1 pl-2 pr-3 text-left text-xs font-medium text-slate-200 ${TINT[i % TINT.length]}`}>{cand}</th>
              {RANKS.map((_, r) => {
                const passed = verdict?.cells[i]?.[r] === true;
                return (
                  <td key={r} className="p-0">
                    <div
                      title={cellCipher(ballot, i, r)}
                      aria-label={`${CANDIDATES[i]}, ${RANKS[r]}: encrypted, hidden value${verdict ? (passed ? ', bit-proof valid' : ', bit-proof failed') : ''}`}
                      className={`flex h-11 w-11 items-center justify-center rounded-lg border bg-slate-800/70 text-slate-500 transition ${passed ? 'border-emerald-400/40 ring-1 ring-emerald-400/40' : 'border-white/5'}`}
                      style={passed && !prefersReducedMotion ? { transitionDelay: `${(i * K + r) * 35}ms` } : undefined}
                    >
                      🔒
                    </div>
                  </td>
                );
              })}
              <td className="pl-2"><SumBadge state={verdict ? verdict.rows[i]! : null} /></td>
            </tr>
          ))}
          <tr>
            <th scope="row" className="py-1 pr-3 text-right text-[11px] font-medium text-slate-400">each rank</th>
            {RANKS.map((_, r) => (
              <td key={r} className="py-1"><SumBadge state={verdict ? verdict.cols[r]! : null} /></td>
            ))}
            <td className="py-1">
              {verdict && (
                <span className={`inline-block rounded-full px-2 py-0.5 text-[11px] font-bold ${verdict.overall ? 'bg-emerald-500/20 text-emerald-300' : 'bg-rose-500/15 text-rose-300'}`}>
                  {verdict.overall ? '🟢 VALID' : '🔴 INVALID'}
                </span>
              )}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  );
}

export default function Ranked() {
  const [keys] = useState(() => makeKeys());
  const [spare] = useState<Credential>(() => issueSpare()); // an eligible-but-unused credential (mirrors Playground)
  const [order, setOrder] = useState<number[]>([0, 1, 2, 3]); // order[position] = candidate index
  const [verdict, setVerdict] = useState<GridVerdict | null>(null);
  const [forged, setForged] = useState<{ ballot: RankedBallot; verdict: GridVerdict } | null>(null);
  const [voters, setVoters] = useState<RankedVoter[]>([]);
  const [revealed, setRevealed] = useState(false);

  // ranking[candidate] = position (0 = best). Derived from the display order.
  const ranking = useMemo(() => {
    const r: number[] = new Array(K);
    order.forEach((c, pos) => { r[c] = pos; });
    return r;
  }, [order]);

  const ballot = useMemo(() => buildRankedBallot(keys.publicKey, ranking), [keys, ranking]);
  const transcript: RankedTranscript | null = useMemo(
    () => (voters.length ? rankedTally('Best team lunch? 🍽️', CANDIDATES, voters, keys, [spare.pub]) : null),
    [voters, keys, spare],
  );
  const result: VerifyResult | null = useMemo(
    () => (revealed && transcript ? verifyRanked(transcript) : null),
    [revealed, transcript],
  );
  const maxBorda = result?.results ? Math.max(1, ...result.results) : 1;

  const clearChecks = () => { setVerdict(null); setForged(null); };
  const move = (pos: number, dir: -1 | 1) => {
    const j = pos + dir;
    if (j < 0 || j >= K) return;
    setOrder((p) => { const n = [...p]; [n[pos], n[j]] = [n[j]!, n[pos]!]; return n; });
    clearChecks();
  };
  const randomize = () => {
    setOrder((p) => { const n = [...p]; for (let i = n.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [n[i], n[j]] = [n[j]!, n[i]!]; } return n; });
    clearChecks();
  };
  const randomRanking = (): number[] => {
    const o = [0, 1, 2, 3];
    for (let i = o.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [o[i], o[j]] = [o[j]!, o[i]!]; }
    const r: number[] = new Array(K);
    o.forEach((c, pos) => { r[c] = pos; });
    return r;
  };

  const runChecks = () => { setForged(null); setVerdict(verifyGrid(keys.publicKey, ballot)); };
  const forge = () => {
    const f = forgeInvalidBallot(keys.publicKey, K);
    setForged({ ballot: f.ballot, verdict: verifyGrid(keys.publicKey, f.ballot, f.trueSums) });
  };

  const addBallot = () => { setVoters((p) => [...p, newRankedVoter(ranking)]); setRevealed(false); };
  const seed9 = () => { setVoters(Array.from({ length: 9 }, () => newRankedVoter(randomRanking()))); setRevealed(false); };
  const reset = () => { setVoters([]); setRevealed(false); };

  const shownBallot = forged ? forged.ballot : ballot;
  const shownVerdict = forged ? forged.verdict : verdict;
  // One consolidated screen-reader announcement for the grid outcome (instead of 8 badge bursts).
  const gridStatus = !shownVerdict
    ? ''
    : shownVerdict.overall
      ? 'Ballot valid: every row and every column sums to exactly one. Values stay encrypted.'
      : 'Ballot invalid: ' +
        shownVerdict.cols.map((c, r) => (c.ok ? null : `column ${RANKS[r]!.split(' ')[0]} sums to ${c.sum}`)).filter(Boolean).join(', ') + '.';

  return (
    <div className="min-h-screen bg-gradient-to-b from-slate-950 via-slate-900 to-indigo-950 text-slate-100">
      <div className="mx-auto max-w-3xl px-5 py-10">
        <header className="mb-8 text-center">
          <div className="flex items-center justify-center gap-2">
            <h1 className="bg-gradient-to-r from-indigo-300 to-emerald-300 bg-clip-text text-4xl font-extrabold text-transparent">🏆 Ranked-Choice Voting</h1>
            <span className="rounded-full bg-amber-400/15 px-2.5 py-0.5 text-xs text-amber-200">Borda tally · not IRV</span>
          </div>
          <p className="mt-2 text-lg font-medium text-slate-200">Rank the candidates. We prove your ballot is valid — without ever seeing it.</p>
          <p className="mt-1 text-sm text-slate-400">Your ranking becomes a wall of encrypted locks that's <em>provably</em> a real ranking. Check it yourself.</p>
        </header>

        <div className="space-y-5">
          {/* 1 — rank */}
          <Card step="1" title="Rank them (best at top)">
            <p className="mb-3 text-xs text-slate-400">This is your private ballot — one ranking becomes one ballot. Reorder, or roll a random ranking.</p>
            <ul className="space-y-2">
              {order.map((cand, pos) => (
                <li key={cand} className={`flex items-center gap-3 rounded-lg border-l-2 bg-slate-800/40 px-3 py-2 ${TINT[cand % TINT.length]}`}>
                  <span className="w-12 shrink-0 text-xs font-semibold text-slate-300">{RANKS[pos]}</span>
                  <span className="text-sm font-medium text-white">{CANDIDATES[cand]}</span>
                  <span className="ml-auto flex gap-1">
                    <button aria-label={`move ${CANDIDATES[cand]} up`} disabled={pos === 0} onClick={() => move(pos, -1)} className="rounded bg-slate-700/70 px-2 py-1 text-xs text-white hover:bg-slate-600 disabled:opacity-30">▲</button>
                    <button aria-label={`move ${CANDIDATES[cand]} down`} disabled={pos === K - 1} onClick={() => move(pos, 1)} className="rounded bg-slate-700/70 px-2 py-1 text-xs text-white hover:bg-slate-600 disabled:opacity-30">▼</button>
                  </span>
                </li>
              ))}
            </ul>
            <button onClick={randomize} className="mt-3 rounded-lg bg-indigo-500/80 px-4 py-2 text-sm font-semibold text-white hover:bg-indigo-400">🎲 Random ranking</button>
          </Card>

          {/* 2 — the locked grid (hero) + 3 — forge it (soundness) */}
          <Card step="2" title="Your ballot, encrypted">
            <p className="mb-3 text-xs text-slate-400">
              The same ranking, as a {K}×{K} matrix of <strong>encrypted</strong> 0/1 cells. You can never read a cell — yet the margins
              prove it's a real ranking. Hover a 🔒 to see its (real) ciphertext.
            </p>
            <MatrixGrid ballot={shownBallot} verdict={shownVerdict} />
            <p className="sr-only" role="status" aria-live="polite">{gridStatus}</p>
            <p className="mt-2 text-[11px] text-slate-400">🔒 = an encrypted 0-or-1 you can never read · ✓ = the math proved this line sums to exactly one.</p>

            {!forged ? (
              <>
                <button onClick={runChecks} className="mt-4 rounded-lg bg-emerald-500 px-5 py-2.5 text-sm font-bold text-white hover:bg-emerald-400">▶ Run the zero-knowledge checks</button>
                {verdict && (
                  <p className="mt-3 rounded-lg bg-emerald-500/10 px-3 py-2 text-sm text-emerald-200">
                    Every row one ✓ <strong>and</strong> every column one ✓ ⇒ provably <strong>one rank per candidate, one candidate per rank</strong> — a real ranking. We proved it without learning a thing. 🔐
                  </p>
                )}
                <div className="mt-3">
                  <button onClick={forge} className="rounded-lg bg-rose-600/80 px-3 py-2 text-sm font-semibold text-white hover:bg-rose-500">😈 Forge it: rank two candidates #1</button>
                </div>
              </>
            ) : (
              <>
                <p className="mt-3 rounded-lg bg-rose-500/10 px-3 py-2 text-sm text-rose-200">
                  🔴 REJECTED by the real verifier — column “1st” holds <strong>two</strong> #1s (= 2 ✗) and “2nd” holds none (= 0 ✗). A ranking can't do that, so it's not a valid ballot.
                </p>
                <button onClick={() => setForged(null)} className="mt-3 text-xs text-slate-400 hover:text-white">← back to my ballot</button>
              </>
            )}
          </Card>

          {/* 4 — tally */}
          <Card step="3" title="Add voters & run the Borda tally">
            <p className="mb-3 text-xs text-slate-400">Borda: each ranking gives a candidate {K - 1} points for 1st … 0 for last. Totals are summed homomorphically and threshold-decrypted — no individual ranking is ever revealed.</p>
            <div className="flex flex-wrap items-center gap-2">
              <button onClick={addBallot} className="rounded-lg bg-slate-700/70 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-600">+ Add this ballot</button>
              <button onClick={seed9} className="rounded-lg bg-indigo-500/80 px-4 py-2 text-sm font-semibold text-white hover:bg-indigo-400">🎲 Simulate 9 voters</button>
              {voters.length > 0 && <button onClick={reset} className="rounded-lg px-3 py-2 text-sm text-slate-400 hover:text-white">reset</button>}
              <span className="ml-auto text-sm text-slate-400">{voters.length} ranked ballot(s)</span>
            </div>
            {transcript && (
              <p className="mt-3 rounded-lg bg-amber-400/10 px-3 py-2 text-xs text-amber-200">
                {transcript.ballots.length} signed, encrypted ranking(s) on the public board. Merkle root: <span className="font-mono">{transcript.boardRoot.slice(0, 24)}…</span>
              </p>
            )}
            <button
              disabled={!transcript}
              onClick={() => setRevealed(true)}
              className="mt-3 rounded-lg bg-emerald-500 px-5 py-2.5 text-sm font-bold text-white hover:bg-emerald-400 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-500"
            >
              Tally &amp; Verify
            </button>
            {result && transcript && (
              <div className="mt-4">
                <div className="space-y-2">
                  {CANDIDATES.map((c, j) => {
                    const n = (result.results ?? transcript.results)[j] ?? 0;
                    return (
                      <div key={j} className="flex items-center gap-3">
                        <div className="w-28 shrink-0 text-sm text-slate-200">{c}</div>
                        <div className="h-6 flex-1 overflow-hidden rounded bg-slate-800">
                          <div className={`h-full ${BAR[j % BAR.length]} transition-all`} style={{ width: `${(n / maxBorda) * 100}%` }} />
                        </div>
                        <div className="w-10 text-right text-sm font-bold text-white">{n}</div>
                      </div>
                    );
                  })}
                </div>
                <p className="mt-1 text-right text-[11px] text-slate-500">Borda points</p>
                <ul className="mt-3 space-y-1">{result.checks.map((c, i) => <CheckRow key={i} {...c} />)}</ul>
                <p role="status" className={`mt-3 rounded-lg px-3 py-2 text-sm font-semibold ${result.ok ? 'bg-emerald-500/15 text-emerald-300' : 'bg-rose-500/15 text-rose-300'}`}>
                  {result.ok ? '🟢 VERIFIED by anyone, from the public record alone.' : '🔴 REJECTED.'}
                </p>
                <p className="mt-2 text-xs text-slate-400">🔒 Only these totals were ever decrypted. No individual ranking was — or can be — revealed.</p>
              </div>
            )}
          </Card>
        </div>

        <div className="mt-6 rounded-lg bg-amber-400/10 px-3 py-2 text-xs text-amber-200">
          ⚠ This counts ranks as <strong>points</strong> (Borda: 1st = {K - 1} … last = 0), summed homomorphically — <strong>no mixnet</strong>.
          It is <strong>not</strong> instant-runoff: true IRV round-by-round elimination needs a verifiable mixnet (tracked as issue #49) and is not built here.
          What you <em>can</em> trust completely: every ballot is a provably valid ranking, and the Borda total is verifiable by anyone.
        </div>

        <footer className="mt-8 text-center text-xs text-slate-500">
          🔑 The decryption key is split across {TRUSTEES} trustees — <strong>any {THRESHOLD}</strong> can decrypt the totals, none alone.<br />
          Runs entirely in your browser using the same audited crypto as the <code className="text-slate-400">reference/</code> core. Pre-audit demo — not for binding elections.
        </footer>
      </div>
    </div>
  );
}
