// Shared UI primitives — one source of truth for the playground's visual language, so all five
// tabs re-theme consistently. Presentational only; no engine logic lives here.
import type { ReactNode } from 'react';

/** Muted categorical colors for candidate bars (CSS vars from index.css @theme). */
export const CAT = ['var(--color-cat-1)', 'var(--color-cat-2)', 'var(--color-cat-3)', 'var(--color-cat-4)', 'var(--color-cat-5)'];

/** A numbered step panel. `step` is a short marker (e.g. "1"); rendered as a squared mono chip. */
export function Card({ step, title, children }: { step: string; title: string; children: ReactNode }) {
  return (
    <section className="rounded-xl border border-line bg-surface p-5 shadow-card">
      <div className="mb-4 flex items-center gap-3">
        <span className="flex h-6 min-w-6 items-center justify-center rounded-md border border-line bg-surface-2 px-1.5 font-mono text-xs font-medium text-ink-faint">{step}</span>
        <h2 className="text-[17px] font-semibold tracking-tight text-ink">{title}</h2>
      </div>
      {children}
    </section>
  );
}

/** One verifier check line: a colored ✓/✗ glyph + name (+ optional detail). */
export function CheckRow({ ok, name, detail }: { ok: boolean; name: string; detail?: string }) {
  return (
    <li className="flex items-start gap-2 text-sm">
      <span className={ok ? 'text-pass' : 'text-fail'}>{ok ? '✓' : '✗'}</span>
      <span className={ok ? 'text-ink-muted' : 'text-fail'}>
        {name}{detail ? <span className="text-ink-faint"> — {detail}</span> : null}
      </span>
    </li>
  );
}

/** Headline verdict: a status dot + mono VERIFIED/REJECTED label, with optional trailing prose. */
export function StatusLine({ ok, children }: { ok: boolean; children?: ReactNode }) {
  return (
    <p role="status" className={`mt-3 flex flex-wrap items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium ${ok ? 'bg-pass-soft text-pass' : 'bg-fail-soft text-fail'}`}>
      <span className={`h-2 w-2 shrink-0 rounded-full ${ok ? 'bg-pass' : 'bg-fail'}`} />
      <span className="font-mono text-xs tracking-wide">{ok ? 'VERIFIED' : 'REJECTED'}</span>
      {children ? <span className="text-ink-muted">{children}</span> : null}
    </p>
  );
}

/** A monospace "well" for crypto artifacts (Merkle roots, ciphertext hex, keys). */
export function Artifact({ children }: { children: ReactNode }) {
  return <span className="rounded-md border border-line bg-surface-2 px-2 py-1 font-mono text-xs text-ink-faint">{children}</span>;
}

/** A horizontal tally bar in a muted categorical color. */
export function Bar({ value, max, cat }: { value: number; max: number; cat: number }) {
  return (
    <div className="h-5 flex-1 overflow-hidden rounded bg-surface-2">
      <div className="h-full transition-all" style={{ width: `${(value / Math.max(1, max)) * 100}%`, backgroundColor: CAT[cat % CAT.length] }} />
    </div>
  );
}
