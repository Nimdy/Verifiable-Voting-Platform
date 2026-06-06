import { useMemo, useState } from 'react';
import { Card, CheckRow, StatusLine, Artifact, Bar, CAT } from './ui';
import {
  makeKeys, issueSpare, newRankedVoter, rankedTally, verifyRanked,
  buildRankedBallot, verifyGrid, forgeInvalidBallot, cellCipher,
  type RankedBallot, type RankedTranscript, type RankedVoter, type VerifyResult,
  type GridVerdict, type Credential,
} from './engine';

// Food emoji here are ballot DATA (candidate names), not chrome. Grid stays groktable: K fixed at 4.
const CANDIDATES = ['🌮 Tacos', '🍕 Pizza', '🍣 Sushi', '🥗 Salad'];
const RANKS = ['1st', '2nd', '3rd', '4th'];
const K = CANDIDATES.length;

const prefersReducedMotion =
  typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;

// A margin pill showing the proven sum of a row/column. PASS/FAIL is the REAL verifier; Σ is display-only.
function SumBadge({ state }: { state: { ok: boolean; sum: number } | null }) {
  if (!state) {
    return <span className="inline-block rounded-md bg-surface-2 px-2 py-0.5 text-[11px] text-ink-faint">Σ = ?</span>;
  }
  return (
    <span className={`inline-block rounded-md px-2 py-0.5 text-[11px] font-semibold ${state.ok ? 'bg-pass-soft text-pass' : 'bg-fail-soft text-fail'}`}>
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
              <th key={j} scope="col" className="px-1 py-1 text-xs font-medium text-ink-muted">
                <div>{r}</div>
                <div className="font-mono text-[10px] text-ink-faint">+{K - 1 - j}</div>
              </th>
            ))}
            <th scope="col" className="px-2 py-1 text-[11px] font-medium text-ink-faint">each candidate</th>
          </tr>
        </thead>
        <tbody>
          {CANDIDATES.map((cand, i) => (
            <tr key={i}>
              <th scope="row" className="whitespace-nowrap rounded-l-lg border-l-2 bg-surface-2 py-1 pl-2 pr-3 text-left text-xs font-medium text-ink-muted" style={{ borderLeftColor: CAT[i % CAT.length] }}>{cand}</th>
              {RANKS.map((_, r) => {
                const passed = verdict?.cells[i]?.[r] === true;
                return (
                  <td key={r} className="p-0">
                    <div
                      title={cellCipher(ballot, i, r)}
                      aria-label={`${CANDIDATES[i]}, ${RANKS[r]}: encrypted, hidden value${verdict ? (passed ? ', bit-proof valid' : ', bit-proof failed') : ''}`}
                      className={`flex h-11 w-11 items-center justify-center rounded-lg border bg-surface-2 text-ink-faint transition ${passed ? 'border-pass/40 ring-1 ring-pass/40' : 'border-line'}`}
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
            <th scope="row" className="py-1 pr-3 text-right text-[11px] font-medium text-ink-faint">each rank</th>
            {RANKS.map((_, r) => (
              <td key={r} className="py-1"><SumBadge state={verdict ? verdict.cols[r]! : null} /></td>
            ))}
            <td className="py-1">
              {verdict && (
                <span className={`inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-[11px] font-semibold ${verdict.overall ? 'bg-pass-soft text-pass' : 'bg-fail-soft text-fail'}`}>
                  <span className={`h-1.5 w-1.5 rounded-full ${verdict.overall ? 'bg-pass' : 'bg-fail'}`} />{verdict.overall ? 'VALID' : 'INVALID'}
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
  const [spare] = useState<Credential>(() => issueSpare());
  const [order, setOrder] = useState<number[]>([0, 1, 2, 3]); // order[position] = candidate index
  const [verdict, setVerdict] = useState<GridVerdict | null>(null);
  const [forged, setForged] = useState<{ ballot: RankedBallot; verdict: GridVerdict } | null>(null);
  const [voters, setVoters] = useState<RankedVoter[]>([]);
  const [revealed, setRevealed] = useState(false);

  const ranking = useMemo(() => { const r: number[] = new Array(K); order.forEach((c, pos) => { r[c] = pos; }); return r; }, [order]);
  const ballot = useMemo(() => buildRankedBallot(keys.publicKey, ranking), [keys, ranking]);
  const transcript: RankedTranscript | null = useMemo(
    () => (voters.length ? rankedTally('Best team lunch? 🍽️', CANDIDATES, voters, keys, [spare.pub]) : null),
    [voters, keys, spare],
  );
  const result: VerifyResult | null = useMemo(() => (revealed && transcript ? verifyRanked(transcript) : null), [revealed, transcript]);
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
    const r: number[] = new Array(K); o.forEach((c, pos) => { r[c] = pos; }); return r;
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
  const gridStatus = !shownVerdict
    ? ''
    : shownVerdict.overall
      ? 'Ballot valid: every row and every column sums to exactly one. Values stay encrypted.'
      : 'Ballot invalid: ' +
        shownVerdict.cols.map((c, r) => (c.ok ? null : `column ${RANKS[r]!.split(' ')[0]} sums to ${c.sum}`)).filter(Boolean).join(', ') + '.';

  return (
    <div className="mx-auto max-w-3xl space-y-5 px-5 pb-14">
      <div className="rounded-r-lg border-l-2 border-warn bg-warn-soft px-4 py-3 text-sm text-warn">
        <strong className="font-semibold">Borda tally · never reveals a ballot.</strong> Only per-candidate point totals are ever decrypted. For round-by-round <em>elimination</em> (which reveals the anonymized rankings), see the Instant-runoff tab.
      </div>

      {/* 1 — rank */}
      <Card step="1" title="Rank them (best at top)">
        <p className="mb-3 text-xs text-ink-faint">This is your private ballot — one ranking becomes one ballot. Reorder, or roll a random ranking.</p>
        <ul className="space-y-2">
          {order.map((cand, pos) => (
            <li key={cand} className="flex items-center gap-3 rounded-lg border border-line border-l-2 bg-surface-2 px-3 py-2" style={{ borderLeftColor: CAT[cand % CAT.length] }}>
              <span className="w-12 shrink-0 font-mono text-xs text-ink-faint">{RANKS[pos]}</span>
              <span className="text-sm font-medium text-ink">{CANDIDATES[cand]}</span>
              <span className="ml-auto flex gap-1">
                <button aria-label={`move ${CANDIDATES[cand]} up`} disabled={pos === 0} onClick={() => move(pos, -1)} className="rounded border border-line bg-surface px-2 py-1 text-xs text-ink hover:border-line-strong disabled:opacity-30">▲</button>
                <button aria-label={`move ${CANDIDATES[cand]} down`} disabled={pos === K - 1} onClick={() => move(pos, 1)} className="rounded border border-line bg-surface px-2 py-1 text-xs text-ink hover:border-line-strong disabled:opacity-30">▼</button>
              </span>
            </li>
          ))}
        </ul>
        <button onClick={randomize} className="mt-3 rounded-lg border border-line bg-surface-2 px-4 py-2 text-sm font-medium text-ink hover:border-line-strong">Random ranking</button>
      </Card>

      {/* 2 — locked grid + forge */}
      <Card step="2" title="Your ballot, encrypted">
        <p className="mb-3 text-xs text-ink-faint">
          The same ranking, as a {K}×{K} matrix of <strong>encrypted</strong> 0/1 cells. You can never read a cell — yet the margins prove it's a real ranking. Hover a 🔒 to see its (real) ciphertext.
        </p>
        <MatrixGrid ballot={shownBallot} verdict={shownVerdict} />
        <p className="sr-only" role="status" aria-live="polite">{gridStatus}</p>
        <p className="mt-2 text-[11px] text-ink-faint">🔒 = an encrypted 0-or-1 you can never read · ✓ = the math proved this line sums to exactly one.</p>
        {!forged ? (
          <>
            <button onClick={runChecks} className="mt-4 rounded-lg bg-accent-strong px-5 py-2.5 text-sm font-semibold text-white hover:opacity-90">Run the zero-knowledge checks</button>
            {verdict && (
              <p className="mt-3 rounded-lg bg-pass-soft px-3 py-2 text-sm text-pass">
                Every row one ✓ <strong>and</strong> every column one ✓ ⇒ provably <strong>one rank per candidate, one candidate per rank</strong> — a real ranking. We proved it without learning a thing.
              </p>
            )}
            <div className="mt-3">
              <button onClick={forge} className="rounded-lg border border-fail/40 px-3 py-2 text-sm font-medium text-fail hover:bg-fail-soft">Forge it: rank two candidates #1</button>
            </div>
          </>
        ) : (
          <>
            <p className="mt-3 rounded-lg bg-fail-soft px-3 py-2 text-sm text-fail">
              REJECTED by the real verifier — column “1st” holds <strong>two</strong> #1s (= 2 ✗) and “2nd” holds none (= 0 ✗). A ranking can't do that, so it's not a valid ballot.
            </p>
            <button onClick={() => setForged(null)} className="mt-3 text-xs text-ink-faint hover:text-ink">← back to my ballot</button>
          </>
        )}
      </Card>

      {/* 3 — tally */}
      <Card step="3" title="Add voters & run the Borda tally">
        <p className="mb-3 text-xs text-ink-faint">Borda: each ranking gives a candidate {K - 1} points for 1st … 0 for last. Totals are summed homomorphically and threshold-decrypted — no individual ranking is ever revealed.</p>
        <div className="flex flex-wrap items-center gap-2">
          <button onClick={addBallot} className="rounded-lg border border-line bg-surface-2 px-4 py-2 text-sm font-medium text-ink hover:border-line-strong">+ Add this ballot</button>
          <button onClick={seed9} className="rounded-lg border border-line bg-surface-2 px-4 py-2 text-sm font-medium text-ink hover:border-line-strong">Simulate 9 voters</button>
          {voters.length > 0 && <button onClick={reset} className="px-3 py-2 text-sm text-ink-faint hover:text-ink">reset</button>}
          <span className="ml-auto text-sm text-ink-faint">{voters.length} ranked ballot(s)</span>
        </div>
        {transcript && (
          <p className="mt-3 flex flex-wrap items-center gap-2 text-xs text-ink-faint">
            {transcript.ballots.length} signed, encrypted ranking(s) on the board. Root: <Artifact>{transcript.boardRoot.slice(0, 24)}…</Artifact>
          </p>
        )}
        <button
          disabled={!transcript}
          onClick={() => setRevealed(true)}
          className="mt-3 rounded-lg bg-accent-strong px-5 py-2.5 text-sm font-semibold text-white hover:opacity-90 disabled:cursor-not-allowed disabled:bg-surface-2 disabled:text-ink-faint"
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
                    <div className="w-28 shrink-0 text-sm text-ink-muted">{c}</div>
                    <Bar value={n} max={maxBorda} cat={j} />
                    <div className="w-10 text-right font-mono text-sm font-semibold tabular-nums text-ink">{n}</div>
                  </div>
                );
              })}
            </div>
            <p className="mt-1 text-right text-[11px] text-ink-faint">Borda points</p>
            <ul className="mt-3 space-y-1">{result.checks.map((c, i) => <CheckRow key={i} {...c} />)}</ul>
            <StatusLine ok={result.ok}>{result.ok ? 'by anyone, from the public record alone.' : ''}</StatusLine>
            <p className="mt-2 text-xs text-ink-faint">Only these totals were ever decrypted. No individual ranking was — or can be — revealed.</p>
          </div>
        )}
      </Card>

      <p className="font-mono text-xs text-ink-faint">one call: runRankedElection(contest, candidates, voters, keys, roll) — swap the arguments to run your own ranked election.</p>
    </div>
  );
}
