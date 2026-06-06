import { useMemo, useState } from 'react';
import { Card, CheckRow, StatusLine, Artifact, Bar } from './ui';
import {
  makeKeys, issueSpare, newMixnetVoter, runIrv, verifyIrv, ballotToRanks, credShort, itemSampleHex,
  SECURITY_T, TRUSTEES, THRESHOLD,
  type MixnetVoter, type MixnetIrvTranscript, type VerifyResult, type Credential,
} from './engine';

// Food emoji here are ballot DATA (candidate names the engine carries), not chrome. K fixed at 4 (bounds O(n·K²)).
const CANDIDATES = ['🌮 Tacos', '🍕 Pizza', '🍣 Sushi', '🥗 Salad'];
const RANKS = ['1st', '2nd', '3rd', '4th'];
const K = CANDIDATES.length;

export default function Irv() {
  const [keys] = useState(() => makeKeys());
  const [spare] = useState<Credential>(() => issueSpare());
  const [order, setOrder] = useState<number[]>([0, 1, 2, 3]); // order[position] = candidate index
  const [voters, setVoters] = useState<MixnetVoter[]>([]);
  const [showRanks, setShowRanks] = useState(false);
  const [revealed, setRevealed] = useState(false);

  const ranking = useMemo(() => { const r: number[] = new Array(K); order.forEach((c, pos) => { r[c] = pos; }); return r; }, [order]);
  const transcript: MixnetIrvTranscript | null = useMemo(
    () => (voters.length ? runIrv('Best team lunch? 🍽️', CANDIDATES, voters, keys, [spare.pub]) : null),
    [voters, keys, spare],
  );
  const result: VerifyResult | null = useMemo(() => (revealed && transcript ? verifyIrv(transcript) : null), [revealed, transcript]);

  const move = (pos: number, dir: -1 | 1) => {
    const j = pos + dir;
    if (j < 0 || j >= K) return;
    setOrder((p) => { const n = [...p]; [n[pos], n[j]] = [n[j]!, n[pos]!]; return n; });
  };
  const randomRanking = (): number[] => {
    const o = [0, 1, 2, 3];
    for (let i = o.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [o[i], o[j]] = [o[j]!, o[i]!]; }
    const r: number[] = new Array(K); o.forEach((c, pos) => { r[c] = pos; }); return r;
  };
  const clear = () => { setShowRanks(false); setRevealed(false); };
  const addBallot = () => { setVoters((p) => [...p, newMixnetVoter(ranking)]); clear(); };
  const simulate = () => { setVoters(Array.from({ length: 9 }, () => newMixnetVoter(randomRanking()))); clear(); };
  const reset = () => { setVoters([]); clear(); };
  const randomize = () => { setOrder(() => { const o = [0, 1, 2, 3]; for (let i = o.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [o[i], o[j]] = [o[j]!, o[i]!]; } return o; }); };

  const orderingOf = (M: number[][]): string => {
    const ranks = ballotToRanks(M, K);
    if (!ranks) return '(invalid)';
    return ranks.map((rank, cand) => ({ rank, cand })).sort((a, b) => a.rank - b.rank).map((x) => CANDIDATES[x.cand]).join('  ›  ');
  };

  return (
    <div className="mx-auto max-w-3xl space-y-5 px-5 pb-14">
      {/* Honesty note — persistent, before any card */}
      <div className="rounded-r-lg border-l-2 border-warn bg-warn-soft px-4 py-3 text-sm text-warn">
        <strong className="font-semibold">Privacy.</strong> This path <strong className="font-semibold">reveals every anonymized ranking</strong> — IRV needs the cleartext rankings to eliminate. It hides only <em>which voter</em> cast which ranking (computational, under DDH), and that link-hiding is the only secrecy here. It is strictly weaker than the Borda tab, which never reveals any ballot. No coercion-resistance, no receipt-freeness. With a small or unusual electorate, a unique ranking can still point back at a person.
      </div>
      <p className="text-sm text-ink-muted">Need your ranking to stay secret? Use <span className="text-ink">Ranked (Borda)</span> — it never reveals a ballot.</p>

      {/* 1 — ballots */}
      <Card step="1" title="Signed ballots on the board">
        <p className="mb-3 text-xs text-ink-faint">Rank the candidates (best at top). Validity is proven <em>before</em> the shuffle — every ballot is a true strict ranking, so a junk ballot can never enter the mix.</p>
        <ul className="space-y-2">
          {order.map((cand, pos) => (
            <li key={cand} className="flex items-center gap-3 rounded-lg border border-line bg-surface-2 px-3 py-2">
              <span className="w-10 shrink-0 font-mono text-xs text-ink-faint">{RANKS[pos]}</span>
              <span className="text-sm font-medium text-ink">{CANDIDATES[cand]}</span>
              <span className="ml-auto flex gap-1">
                <button aria-label={`move ${CANDIDATES[cand]} up`} disabled={pos === 0} onClick={() => move(pos, -1)} className="rounded border border-line bg-surface px-2 py-1 text-xs text-ink hover:border-line-strong disabled:opacity-30">▲</button>
                <button aria-label={`move ${CANDIDATES[cand]} down`} disabled={pos === K - 1} onClick={() => move(pos, 1)} className="rounded border border-line bg-surface px-2 py-1 text-xs text-ink hover:border-line-strong disabled:opacity-30">▼</button>
              </span>
            </li>
          ))}
        </ul>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <button onClick={addBallot} className="rounded-lg border border-line bg-surface-2 px-4 py-2 text-sm font-medium text-ink hover:border-line-strong">+ Add this ranking</button>
          <button onClick={randomize} className="rounded-lg border border-line bg-surface-2 px-3 py-2 text-sm font-medium text-ink hover:border-line-strong">Shuffle order</button>
          <button onClick={simulate} className="rounded-lg border border-line bg-surface-2 px-4 py-2 text-sm font-medium text-ink hover:border-line-strong">Simulate 9 voters</button>
          {voters.length > 0 && <button onClick={reset} className="px-3 py-2 text-sm text-ink-faint hover:text-ink">reset</button>}
          <span className="ml-auto text-sm text-ink-faint">{voters.length} ballot(s)</span>
        </div>
        {transcript && (
          <p className="mt-3 flex flex-wrap items-center gap-2 text-xs text-ink-faint">
            {transcript.ballots.length} signed, encrypted ranking(s) on the board. Root: <Artifact>{transcript.boardRoot.slice(0, 26)}…</Artifact>
          </p>
        )}
      </Card>

      {/* 2 — shuffle */}
      <Card step="2" title="Verifiable shuffle">
        <p className="mb-3 text-xs text-ink-faint">A re-encryption shuffle: every output is a fresh ciphertext of some input ballot, <em>proven</em> a permutation — but which-maps-to-which is destroyed.</p>
        {!transcript ? (
          <p className="text-sm text-ink-faint">Add a ballot above to populate the board.</p>
        ) : (
          <>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="mb-1 font-mono text-[11px] uppercase tracking-wide text-ink-faint">board order</p>
                <ul className="space-y-1 font-mono text-xs">
                  {transcript.ballots.slice(0, 6).map((b, i) => (
                    <li key={i} className="flex gap-2"><span className="text-ink-muted">{b.voter}</span><span className="text-ink-faint">cred {credShort(transcript, i)}</span></li>
                  ))}
                </ul>
              </div>
              <div>
                <p className="mb-1 font-mono text-[11px] uppercase tracking-wide text-ink-faint">shuffled output</p>
                <ul className="space-y-1 font-mono text-xs">
                  {transcript.shuffled.slice(0, 6).map((_, i) => (
                    <li key={i} className="text-accent-ink">{itemSampleHex(transcript, i)}…</li>
                  ))}
                </ul>
              </div>
            </div>
            <p className="mt-3 text-xs italic text-ink-faint">The missing names on the right are the privacy property — shown, not claimed: the link from voter to ballot is gone.</p>
            <p className="mt-2 font-mono text-xs text-ink-faint">
              shuffle proof t = {transcript.shuffleProof.t} ≥ {SECURITY_T}{' '}
              <span className={transcript.shuffleProof.t >= SECURITY_T ? 'text-pass' : 'text-fail'}>{transcript.shuffleProof.t >= SECURITY_T ? '✓' : '✗'}</span>
            </p>
          </>
        )}
      </Card>

      {/* 3 — decrypt */}
      <Card step="3" title={`Decrypt the anonymized rankings · ${THRESHOLD} of ${TRUSTEES} trustees`}>
        {!transcript ? (
          <p className="text-sm text-ink-faint">The anonymized rankings appear here once you cast ballots and decrypt.</p>
        ) : !showRanks ? (
          <button onClick={() => setShowRanks(true)} className="rounded-lg border border-line bg-surface-2 px-4 py-2 text-sm font-medium text-ink hover:border-line-strong">Decrypt rankings</button>
        ) : (
          <>
            <ul className="space-y-1 text-sm">
              {transcript.decryptedMatrices.slice(0, 8).map((M, i) => (
                <li key={i} className="flex flex-wrap items-center gap-2">
                  <span className="text-ink-muted">{orderingOf(M)}</span>
                  <span className="text-xs text-ink-faint">← anonymized, not linked to any voter</span>
                </li>
              ))}
            </ul>
            <p className="mt-3 font-mono text-xs text-ink-faint">decrypted by {transcript.threshold} of {transcript.trustees} trustees · each share proven (Chaum–Pedersen)</p>
            <p className="mt-1 text-xs text-warn">These are the real rankings, now in the clear — exactly the privacy cost IRV pays. With a small electorate, a unique ranking can still hint who cast it.</p>
          </>
        )}
      </Card>

      {/* 4 — rounds */}
      <Card step="4" title="Instant-runoff rounds">
        {!transcript ? (
          <p className="text-sm text-ink-faint">Round-by-round elimination appears here.</p>
        ) : !showRanks ? (
          <p className="text-sm text-ink-faint">Decrypt the rankings in step 3 first — the rounds are tabulated from the revealed rankings, so the result is downstream of decryption.</p>
        ) : (
          <>
            <ol className="space-y-4">
              {transcript.rounds.map((R, j) => {
                const max = Math.max(1, ...R.tallies);
                return (
                  <li key={j}>
                    <p className="mb-1 font-mono text-xs uppercase tracking-wide text-ink-faint">Round {j + 1}</p>
                    <div className="space-y-1">
                      {CANDIDATES.map((c, ci) => (R.eliminated.includes(ci) ? (
                        <div key={ci} className="flex items-center gap-3 text-sm">
                          <div className="w-28 shrink-0 text-ink-faint line-through">{c}</div>
                          <span className="text-xs text-ink-faint">eliminated</span>
                        </div>
                      ) : (
                        <div key={ci} className="flex items-center gap-3">
                          <div className="w-28 shrink-0 text-sm text-ink-muted">{c}</div>
                          <Bar value={R.tallies[ci]!} max={max} cat={ci} />
                          <div className="w-8 text-right font-mono text-sm font-semibold tabular-nums text-ink">{R.tallies[ci]}</div>
                        </div>
                      )))}
                    </div>
                    {R.eliminatedThisRound !== null && (
                      <p className="mt-1 text-xs text-ink-faint">No majority (need &gt; half). Eliminate {CANDIDATES[R.eliminatedThisRound]} (fewest first-preferences; ties → highest index); its votes transfer.</p>
                    )}
                    {R.winner !== null && <StatusLine ok>WINNER: {CANDIDATES[R.winner]}</StatusLine>}
                  </li>
                );
              })}
            </ol>
            <button onClick={() => setRevealed(true)} className="mt-4 rounded-lg bg-accent-strong px-5 py-2.5 text-sm font-semibold text-white hover:opacity-90">Verify everything</button>
            {result && (
              <div className="mt-4">
                <ul className="space-y-1">{result.checks.map((c, i) => <CheckRow key={i} {...c} />)}</ul>
                <StatusLine ok={result.ok}>— the verifier re-ran the identical tabulation over its own recovered matrices.</StatusLine>
                <p className="mt-2 text-xs text-ink-faint">The verifier doesn't trust the published rounds — it re-derives the board, re-checks the shuffle proof, re-decrypts, and re-runs IRV itself.</p>
              </div>
            )}
          </>
        )}
      </Card>

      <p className="font-mono text-xs text-ink-faint">one call: runMixnetElection(contest, candidates, voters, keys, roll) — swap the arguments to run your own ranked election.</p>
    </div>
  );
}
