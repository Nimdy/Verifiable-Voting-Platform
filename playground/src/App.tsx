import { useMemo, useState, type ReactNode } from 'react';
import {
  makeKeys, issueSpare, newVoter, tally, verify, ballotCipher, auditCheck,
  tamperBallot, rigResult, doubleVote, ineligibleVote, overvote,
  type VerifyResult, type Transcript, type Voter, type Credential,
} from './engine';
import { Card, CheckRow, StatusLine, Artifact, Bar } from './ui';
import Walkthrough from './Walkthrough';
import Ballot from './Ballot';
import Ranked from './Ranked';
import Irv from './Irv';

const CANDIDATES = ['Tacos 🌮', 'Pizza 🍕', 'Sushi 🍣', 'Salad 🥗'];

type CheatOutcome = { kind: 'tamper' | 'rig' | 'double' | 'ineligible' | 'overvote'; result: VerifyResult };

const CHEAT_MSG: Record<CheatOutcome['kind'], string> = {
  tamper: 'Altering a ballot breaks the Merkle root and its proof.',
  rig: 'The verifier recomputed the real totals — the lie does not match.',
  double: 'The same credential cannot vote twice (single-use nullifier).',
  ineligible: 'Only credentials on the published roll may vote.',
  overvote: 'A ballot must select exactly one candidate (the sum proof fails).',
};

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
    <div className="mx-auto max-w-3xl space-y-5 px-5 pb-14">
      {/* 1 — vote */}
      <Card step="1" title="Run an election">
        <input
          value={contest}
          onChange={(e) => { setContest(e.target.value); setRevealed(false); }}
          className="mb-3 w-full rounded-lg border border-line bg-surface-2 px-3 py-2 text-sm text-ink outline-none focus:border-line-strong"
        />
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          {CANDIDATES.map((c, j) => (
            <button key={j} onClick={() => cast(j)} className="rounded-lg border border-line bg-surface-2 px-3 py-3 text-sm font-medium text-ink hover:border-line-strong">
              {c}
            </button>
          ))}
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <button onClick={simulate} className="rounded-lg border border-line bg-surface-2 px-4 py-2 text-sm font-medium text-ink hover:border-line-strong">Simulate 9 voters</button>
          {voters.length > 0 && <button onClick={reset} className="px-3 py-2 text-sm text-ink-faint hover:text-ink">reset</button>}
          <span className="ml-auto text-sm text-ink-faint">{voters.length} eligible voter(s)</span>
        </div>
        <p className="mt-3 text-xs text-ink-faint">Each vote issues a fresh eligible-voter credential and is cryptographically signed — only registered voters count, once each, for exactly one candidate.</p>
      </Card>

      {/* 2 — board */}
      <Card step="2" title="The public bulletin board">
        {!transcript ? (
          <p className="text-sm text-ink-faint">Cast a vote above and it appears here — encrypted.</p>
        ) : (
          <>
            <ul className="space-y-1 font-mono text-xs text-ink-muted">
              {transcript.ballots.slice(0, 8).map((_, i) => (
                <li key={i} className="flex gap-3">
                  <span className="text-ink-faint">{transcript.ballots[i]!.voter}</span>
                  <span className="text-pass">✓ eligible</span>
                  <span className="truncate text-accent-ink">{ballotCipher(transcript, i).slice(0, 34)}…</span>
                </li>
              ))}
              {transcript.ballots.length > 8 && <li className="text-ink-faint">+ {transcript.ballots.length - 8} more…</li>}
            </ul>
            <p className="mt-3 flex flex-wrap items-center gap-2 rounded-lg border-l-2 border-warn bg-warn-soft px-3 py-2 text-xs text-warn">
              All the public sees: signed, encrypted ballots. The result is provable, yet no choice is exposed. Merkle root: <Artifact>{transcript.boardRoot.slice(0, 24)}…</Artifact>
            </p>
          </>
        )}
      </Card>

      {/* 3 — tally & verify */}
      <Card step="3" title="Tally & verify">
        <button
          disabled={!transcript}
          onClick={() => { setRevealed(true); setCheat(null); }}
          className="rounded-lg bg-accent-strong px-5 py-2.5 text-sm font-semibold text-white hover:opacity-90 disabled:cursor-not-allowed disabled:bg-surface-2 disabled:text-ink-faint"
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
                    <div className="w-28 shrink-0 text-sm text-ink-muted">{c}</div>
                    <Bar value={n} max={maxVotes} cat={j} />
                    <div className="w-8 text-right font-mono text-sm font-semibold tabular-nums text-ink">{n}</div>
                  </div>
                );
              })}
            </div>
            <ul className="mt-4 space-y-1">{result.checks.map((c, i) => <CheckRow key={i} {...c} />)}</ul>
            <StatusLine ok={result.ok}>{result.ok ? 'by anyone, from the public record alone.' : ''}</StatusLine>
            <p className="mt-2 text-xs text-ink-faint">Only these totals were ever decrypted. No individual ballot was — or can be — revealed.</p>
          </div>
        )}
      </Card>

      {/* 4 — audit (Benaloh) */}
      <Card step="4" title="Audit your ballot (cast-as-intended)">
        <p className="mb-3 text-xs text-ink-faint">Worried your device encrypted the wrong choice? Spoil a test ballot and check it. (A spoiled ballot is discarded, so a cheating device can never predict an audit.)</p>
        <div className="flex flex-wrap gap-2">
          {CANDIDATES.map((c, j) => (
            <button key={j} disabled={!transcript} onClick={() => setAuditFor(j)} className="rounded-lg border border-line bg-surface-2 px-3 py-2 text-xs font-medium text-ink hover:border-line-strong disabled:opacity-40">
              audit “{c}”
            </button>
          ))}
        </div>
        {auditFor !== null && transcript && (
          <div className="mt-3 rounded-lg border border-line bg-surface-2 p-3 text-sm">
            <p className="text-pass">✓ Honest device that encrypted “{CANDIDATES[auditFor]}” passes the audit: {String(auditCheck(transcript, auditFor, auditFor))}</p>
            <p className="text-fail">✗ A device that secretly encrypted “{CANDIDATES[(auditFor + 1) % CANDIDATES.length]}” would pass as “{CANDIDATES[auditFor]}”? {String(auditCheck(transcript, (auditFor + 1) % CANDIDATES.length, auditFor))}</p>
          </div>
        )}
      </Card>

      {/* 5 — cheat */}
      <Card step="5" title="Now try to cheat it (you're the insider)">
        <div className="flex flex-wrap gap-2">
          {(['double', 'ineligible', 'overvote', 'tamper', 'rig'] as const).map((k) => (
            <button key={k} disabled={!transcript} onClick={() => runCheat(k)} className="rounded-lg border border-fail/40 px-3 py-2 text-sm font-medium text-fail hover:bg-fail-soft disabled:opacity-40">
              {{ double: 'Vote twice', ineligible: 'Vote without a credential', overvote: 'Vote for two', tamper: 'Flip a ballot', rig: 'Rig the result' }[k]}
            </button>
          ))}
        </div>
        {cheat && (
          <div className="mt-4 rounded-lg border border-line bg-surface-2 p-4">
            <ul className="space-y-1">{cheat.result.checks.map((c, i) => <CheckRow key={i} {...c} />)}</ul>
            <StatusLine ok={cheat.result.ok}>Caught — {CHEAT_MSG[cheat.kind]}</StatusLine>
          </div>
        )}
        {!transcript && <p className="mt-3 text-xs text-ink-faint">Cast some votes first, then come back and try.</p>}
      </Card>
    </div>
  );
}

type Tab = 'play' | 'walk' | 'ballot' | 'ranked' | 'irv';

const TABS: [Tab, string][] = [
  ['play', 'Playground'], ['walk', 'How it works'], ['ballot', 'Full ballot'],
  ['ranked', 'Ranked (Borda)'], ['irv', 'Instant-runoff'],
];

const HERO: Record<Tab, { title: string; sub: string; chips: boolean }> = {
  play: { title: 'Verifiable Voting', sub: 'One eligible voter, one vote. Verify everything, reveal nothing — real cryptography, running entirely in your browser.', chips: true },
  walk: { title: 'How it works', sub: 'A real election, end to end — every artifact below is produced by the actual engine. Switch between plain language and the cryptography.', chips: false },
  ballot: { title: 'Full ballot', sub: 'Many contests in one ballot, organized into categories and tags — each leaf contest its own independently verifiable election.', chips: false },
  ranked: { title: 'Ranked-choice (Borda)', sub: 'Rank the candidates; your ballot becomes an encrypted permutation matrix that is provably a valid ranking without revealing a single choice.', chips: true },
  irv: { title: 'Instant-runoff voting', sub: 'A verifiable shuffle unlinks voters from ballots, then the anonymized rankings are decrypted and eliminated round by round.', chips: true },
};

const TRUST_CHIPS = ['ristretto255', 'threshold 2-of-3', 'RFC-6962 log'];

function Hero({ tab }: { tab: Tab }) {
  const h = HERO[tab];
  return (
    <div className="relative overflow-hidden">
      <div className="pointer-events-none absolute inset-0" style={{ background: 'radial-gradient(50rem 24rem at 50% -8%, var(--color-accent-soft), transparent)' }} />
      <div className="relative mx-auto max-w-3xl px-5 pb-2 pt-10">
        <p className="font-mono text-[11px] uppercase tracking-[0.08em] text-ink-faint">END-TO-END VERIFIABLE · RUNS IN YOUR BROWSER</p>
        <h1 className="mt-1 text-3xl font-semibold tracking-tight text-ink">{h.title}</h1>
        <p className="mt-2 max-w-2xl text-sm text-ink-muted">{h.sub}</p>
        {h.chips && (
          <div className="mt-3 flex flex-wrap gap-1.5">
            {TRUST_CHIPS.map((c) => (
              <span key={c} className="rounded-md border border-line px-2 py-1 font-mono text-[11px] text-ink-faint">{c}</span>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function Footer() {
  return (
    <footer className="mx-auto max-w-3xl px-5 py-10 text-xs leading-relaxed text-ink-faint">
      <p>
        Open foundation for verifiable elections. Clone it, read the <code className="text-ink-muted">reference/</code> core, and{' '}
        <span className="text-ink-muted">self-host</span> your own — any contest, any candidates. No server, no account, no vendor.
      </p>
      <p className="mt-2">
        The decryption key is <strong className="font-medium text-ink-muted">threshold-split across the trustees</strong> — a quorum can decrypt the totals, none alone.
        Runs entirely in your browser on the same crypto as the <code className="text-ink-muted">reference/</code> core. <strong className="font-medium text-ink-muted">Pre-audit, not independently reviewed</strong> — not for binding elections.
      </p>
    </footer>
  );
}

export default function App() {
  const [tab, setTab] = useState<Tab>('play');
  const tabCls = (on: boolean) =>
    `border-b-2 px-1 pb-[11px] pt-[14px] text-sm ${on ? 'border-accent font-medium text-ink' : 'border-transparent text-ink-muted hover:text-ink'}`;
  return (
    <div className="min-h-screen bg-canvas text-ink">
      <nav className="sticky top-0 z-10 border-b border-line bg-canvas/85 backdrop-blur">
        <div className="mx-auto flex max-w-3xl flex-wrap items-center gap-x-5 gap-y-1 px-5">
          <span className="flex items-center gap-2 py-3">
            <span className="font-mono text-accent">[✓]</span>
            <span className="font-semibold tracking-tight text-ink">Verifiable Voting</span>
            <span className="rounded-md border border-line px-1.5 py-0.5 font-mono text-[11px] text-ink-faint">pre-audit</span>
          </span>
          <div className="ml-auto flex flex-wrap gap-4" role="tablist" aria-label="Demo sections">
            {TABS.map(([key, label]) => (
              <button key={key} id={`tab-${key}`} role="tab" aria-selected={tab === key} aria-controls="panel" tabIndex={tab === key ? 0 : -1} onClick={() => setTab(key)} className={tabCls(tab === key)}>{label}</button>
            ))}
          </div>
        </div>
      </nav>
      <Hero tab={tab} />
      <main id="panel" role="tabpanel" aria-labelledby={`tab-${tab}`} tabIndex={0}>
        {tab === 'play' ? <Playground /> : tab === 'walk' ? <Walkthrough /> : tab === 'ballot' ? <Ballot /> : tab === 'ranked' ? <Ranked /> : <Irv />}
      </main>
      <Footer />
    </div>
  );
}
