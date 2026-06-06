import { useMemo, useState } from 'react';
import { buildBallotScenario, childrenOf, allTags, isLeaf, type ContestSpec } from './engine';
import { Bar } from './ui';

export default function Ballot() {
  const sc = useMemo(() => buildBallotScenario(), []);
  const spec = sc.spec;
  const [tag, setTag] = useState('All');
  const [parent, setParent] = useState<string | undefined>(undefined);
  const resOf = (id: string) => sc.result.results.find((r) => r.id === id);
  const tags = ['All', ...allTags(spec)];

  function ResultCard({ c }: { c: ContestSpec }) {
    const r = resOf(c.id);
    const max = r ? Math.max(1, ...r.transcript.results) : 1;
    return (
      <div className="rounded-xl border border-line bg-surface p-4 shadow-card">
        <div className="mb-2 flex items-center gap-2">
          <h3 className="font-semibold tracking-tight text-ink">{c.title}</h3>
          {sc.verified.has(c.id) && <span className="rounded-md bg-pass-soft px-2 py-0.5 text-[10px] font-semibold text-pass">✓ verified</span>}
          <span className="ml-auto flex gap-1">{c.tags.map((tg) => (
            <button key={tg} onClick={() => { setTag(tg); setParent(undefined); }} className="rounded border border-line px-1.5 py-0.5 font-mono text-[10px] text-ink-faint hover:text-ink">#{tg}</button>
          ))}</span>
        </div>
        {r && c.candidates!.map((cand, j) => {
          const n = r.transcript.results[j] ?? 0;
          return (
            <div key={j} className="mb-1 flex items-center gap-2">
              <div className="w-28 shrink-0 text-xs text-ink-muted">{cand}</div>
              <Bar value={n} max={max} cat={j} />
              <div className="w-6 text-right font-mono text-xs font-semibold tabular-nums text-ink">{n}</div>
            </div>
          );
        })}
      </div>
    );
  }

  let body;
  if (tag !== 'All') {
    const leaves = spec.contests.filter((c) => isLeaf(c) && c.tags.includes(tag));
    body = (<div className="space-y-3"><p className="text-xs text-ink-faint">Contests tagged <span className="font-mono text-accent-ink">#{tag}</span>:</p>{leaves.map((c) => <ResultCard key={c.id} c={c} />)}</div>);
  } else {
    const nodes = childrenOf(spec, parent);
    body = (
      <>
        {parent && (
          <button onClick={() => setParent(spec.contests.find((c) => c.id === parent)?.parent)} className="mb-3 text-xs text-ink-faint hover:text-ink">← back</button>
        )}
        <div className="space-y-3">
          {nodes.map((c) => isLeaf(c)
            ? <ResultCard key={c.id} c={c} />
            : (
              <button key={c.id} onClick={() => setParent(c.id)} className="flex w-full items-center gap-2 rounded-xl border border-line bg-surface p-4 text-left shadow-card hover:border-line-strong">
                <span className="text-lg font-semibold tracking-tight text-ink">{c.title}</span>
                <span className="text-xs text-ink-faint">{childrenOf(spec, c.id).length} contests</span>
                <span className="ml-auto flex gap-1">{c.tags.map((tg) => <span key={tg} className="rounded border border-line px-1.5 py-0.5 font-mono text-[10px] text-ink-faint">#{tg}</span>)}</span>
                <span className="text-ink-faint">▸</span>
              </button>
            ))}
        </div>
      </>
    );
  }

  return (
    <div className="mx-auto max-w-3xl px-5 pb-14">
      <div className="mb-5">
        <h2 className="text-lg font-semibold tracking-tight text-ink">{spec.title}</h2>
        <p className="mt-1 text-sm">
          {sc.ok ? <span className="text-pass">All {sc.result.results.length} contests verified ✓</span> : <span className="text-fail">verification failed</span>}
        </p>
      </div>
      <div className="mb-4 flex flex-wrap gap-1.5">
        {tags.map((t) => (
          <button key={t} onClick={() => { setTag(t); setParent(undefined); }} className={`rounded-md px-3 py-1 text-xs font-medium ${tag === t ? 'bg-accent-strong text-white' : 'border border-line bg-surface-2 text-ink-muted hover:text-ink'}`}>
            {t === 'All' ? 'All' : '#' + t}
          </button>
        ))}
      </div>
      {body}
      <p className="mt-6 text-xs text-ink-faint">Each contest is its own verifiable sub-election — a ballot can never be replayed across contests. Pre-audit demo — not for binding government elections.</p>
    </div>
  );
}
