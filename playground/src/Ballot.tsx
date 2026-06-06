import { useMemo, useState } from 'react';
import { buildBallotScenario, childrenOf, allTags, isLeaf, type ContestSpec } from './engine';

const BAR = ['bg-emerald-400', 'bg-indigo-400', 'bg-amber-400', 'bg-rose-400', 'bg-pink-400'];

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
      <div className="rounded-xl border border-white/10 bg-white/5 p-4">
        <div className="mb-2 flex items-center gap-2">
          <h3 className="font-semibold text-white">{c.title}</h3>
          {sc.verified.has(c.id) && <span className="rounded-full bg-emerald-500/20 px-2 py-0.5 text-[10px] font-semibold text-emerald-300">✓ verified</span>}
          <span className="ml-auto flex gap-1">{c.tags.map((tg) => (
            <button key={tg} onClick={() => { setTag(tg); setParent(undefined); }} className="rounded bg-white/10 px-1.5 py-0.5 text-[10px] text-slate-300 hover:text-white">#{tg}</button>
          ))}</span>
        </div>
        {r && c.candidates!.map((cand, j) => {
          const n = r.transcript.results[j] ?? 0;
          return (
            <div key={j} className="mb-1 flex items-center gap-2">
              <div className="w-28 shrink-0 text-xs text-slate-300">{cand}</div>
              <div className="h-4 flex-1 overflow-hidden rounded bg-slate-800"><div className={`h-full ${BAR[j % BAR.length]}`} style={{ width: `${(n / max) * 100}%` }} /></div>
              <div className="w-6 text-right text-xs font-bold text-white">{n}</div>
            </div>
          );
        })}
      </div>
    );
  }

  let body;
  if (tag !== 'All') {
    const leaves = spec.contests.filter((c) => isLeaf(c) && c.tags.includes(tag));
    body = (<div className="space-y-3"><p className="text-xs text-slate-400">Contests tagged <span className="text-indigo-300">#{tag}</span>:</p>{leaves.map((c) => <ResultCard key={c.id} c={c} />)}</div>);
  } else {
    const nodes = childrenOf(spec, parent);
    body = (
      <>
        {parent && (
          <button onClick={() => setParent(spec.contests.find((c) => c.id === parent)?.parent)} className="mb-3 text-xs text-slate-400 hover:text-white">← back</button>
        )}
        <div className="space-y-3">
          {nodes.map((c) => isLeaf(c)
            ? <ResultCard key={c.id} c={c} />
            : (
              <button key={c.id} onClick={() => setParent(c.id)} className="flex w-full items-center gap-2 rounded-xl border border-white/10 bg-white/5 p-4 text-left hover:bg-white/10">
                <span className="text-lg font-semibold text-white">{c.title}</span>
                <span className="text-xs text-slate-400">{childrenOf(spec, c.id).length} contests</span>
                <span className="ml-auto flex gap-1">{c.tags.map((tg) => <span key={tg} className="rounded bg-white/10 px-1.5 py-0.5 text-[10px] text-slate-300">#{tg}</span>)}</span>
                <span className="text-slate-500">▸</span>
              </button>
            ))}
        </div>
      </>
    );
  }

  return (
    <div className="mx-auto max-w-3xl px-5 py-8">
      <header className="mb-5 text-center">
        <h1 className="bg-gradient-to-r from-indigo-300 to-emerald-300 bg-clip-text text-3xl font-extrabold text-transparent">🗂️ {spec.title}</h1>
        <p className="mt-1 text-sm text-slate-400">
          A ballot of many contests, organized into parent categories and tags — each leaf contest independently verifiable.{' '}
          {sc.ok ? <span className="text-emerald-300">All {sc.result.results.length} contests verified ✓</span> : <span className="text-rose-300">verification failed</span>}
        </p>
      </header>
      <div className="mb-4 flex flex-wrap gap-1.5">
        {tags.map((t) => (
          <button key={t} onClick={() => { setTag(t); setParent(undefined); }} className={`rounded-full px-3 py-1 text-xs font-medium ${tag === t ? 'bg-indigo-500 text-white' : 'bg-white/5 text-slate-300 hover:text-white'}`}>
            {t === 'All' ? 'All' : '#' + t}
          </button>
        ))}
      </div>
      {body}
      <p className="mt-6 text-center text-xs text-slate-500">Each contest is its own verifiable sub-election — a ballot can never be replayed across contests. Pre-audit demo — not for binding government elections.</p>
    </div>
  );
}
