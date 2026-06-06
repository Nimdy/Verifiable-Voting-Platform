import { useMemo, useState, type ReactNode } from 'react';
import {
  buildScenario, verify, auditCheck,
  tamperBallot, rigResult, doubleVote, ineligibleVote, overvote, ptShort,
  type Scenario, type VerifyResult,
} from './engine';
import { CheckRow as Check, StatusLine } from './ui';

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
  emits?: string; // the data that flows from this node to the next (the edge label)
}

function Row({ k, v }: { k: string; v: ReactNode }) {
  return (
    <div className="flex flex-wrap gap-2 text-xs">
      <span className="w-40 shrink-0 text-ink-faint">{k}</span>
      <span className="font-mono text-accent-ink">{v}</span>
    </div>
  );
}

/** A labeled data edge between two flow nodes — a line, the data payload, a line. */
function Edge({ label }: { label: string }) {
  return (
    <div className="flex flex-col items-center" aria-hidden="true">
      <span className="h-4 w-px bg-line" />
      <span className="rounded-md border border-line bg-surface-2 px-2 py-0.5 font-mono text-[11px] text-accent-ink">↓ {label}</span>
      <span className="h-4 w-px bg-line" />
    </div>
  );
}

export default function Walkthrough() {
  const sc: Scenario = useMemo(() => buildScenario(), []);
  const result: VerifyResult = useMemo(() => verify(sc.transcript), [sc]);
  const [tech, setTech] = useState(false);
  const [cheat, setCheat] = useState<{ kind: string; result: VerifyResult } | null>(null);
  const [auditPick, setAuditPick] = useState<number | null>(null);

  const t = sc.transcript;
  const roll = t.eligibleRoll;
  const sampleBallot = t.ballots[0]!;
  const runCheat = (kind: 'double' | 'ineligible' | 'overvote' | 'tamper' | 'rig') => {
    const f = { double: (x = t) => doubleVote(x, sc.voters), ineligible: ineligibleVote, overvote: (x = t) => overvote(x, sc.spare), tamper: tamperBallot, rig: rigResult }[kind];
    setCheat({ kind, result: verify(f(t)) });
  };

  const phases: Phase[] = [
    {
      id: 'setup', step: '1', title: 'Set up the election', actor: 'Organizer', mode: 'real', emits: 'election manifest',
      plain: 'An organizer states the question and candidates, and names the trustees who will jointly hold the decryption key — so no one person can ever open ballots alone.',
      tech: (<>
        <Row k="contest" v={t.contest} />
        <Row k="candidates" v={t.candidates.join('  ·  ')} />
        <Row k="trustees / threshold" v={`${t.trustees} trustees · any ${t.threshold} can decrypt`} />
        <p className="mt-2 text-xs text-ink-faint">Captured declaratively in an <code>ElectionManifest</code>; everything below is derived from it.</p>
      </>),
    },
    {
      id: 'keygen', step: '2', title: 'Trustees generate the key together', actor: 'Trustees', mode: 'real', emits: 'joint public key',
      plain: 'The trustees run a joint ceremony that produces ONE public election key. The matching secret is split among them — it is never assembled in one place, so no single trustee (or small group) can decrypt anything.',
      tech: (<>
        <Row k="scheme" v="Pedersen / Feldman k-of-n DKG over ristretto255" />
        <Row k="public key  (= C₀)" v={ptShort(t.publicKey)} />
        <Row k="commitments" v={`${t.commitments.length} (C₀…C${t.commitments.length - 1}), one per polynomial coefficient`} />
        <p className="mt-2 text-xs text-ink-faint">The secret is a Shamir-shared polynomial P with P(0)=x; trustee j holds P(j). x is never reconstructed — decryption uses Lagrange interpolation on partial results.</p>
      </>),
    },
    {
      id: 'register', step: '3', title: 'Register eligible voters', actor: 'Registrar', mode: 'represented', emits: 'credentials + published roll',
      plain: 'A SEPARATE registrar checks who is eligible and privately hands each voter a personal credential. It publishes only an anonymous list of credential keys — never names. So the people who run the election never see who is who.',
      tech: (<>
        <Row k="credential" v="a fresh Schnorr keypair per voter (no SSN / durable ID — ADR-0001)" />
        <Row k="published roll" v={`${roll.length} credential public keys, e.g. ${ptShort(roll[0]!)}`} />
        <Row k="identity ↔ credential" v="held ONLY by the registrar, never serialized" />
        <p className="mt-2 text-xs text-warn"><strong>Represented:</strong> the eligibility/ID check itself happens off-system (an org roll, OIDC, a check-in kiosk). The credential keypair is real.</p>
      </>),
    },
    {
      id: 'cast', step: '4', title: 'Vote on your own device', actor: 'Voter', mode: 'represented', emits: 'encrypted, signed ballot', live: 'audit',
      plain: 'On their own device, the voter picks one candidate. The device encrypts the choice and attaches zero-knowledge proofs that it is a valid single selection — then signs it with the voter’s credential. The choice itself never leaves the device in the clear.',
      tech: (<>
        <Row k="encryption" v="exponential ElGamal (one ciphertext per candidate)" />
        <Row k="proofs" v="disjunctive Chaum–Pedersen (each is 0/1) + an ‘exactly one selected’ proof" />
        <Row k="signed by" v="the voter’s credential (Schnorr)" />
        <Row k="sample ciphertext" v={ptShort(sampleBallot.selection.enc[0]!.b)} />
        <p className="mt-2 text-xs text-warn"><strong>Represented:</strong> the “phone / ballot-marking device” is a panel here — but the encryption + proofs run for real, client-side.</p>
      </>),
    },
    {
      id: 'board', step: '5', title: 'Post to the public board', actor: 'Public', mode: 'real', emits: 'Merkle root',
      plain: 'Every encrypted, signed ballot is posted to a public append-only board that anyone can read. Change, drop, or reorder any ballot and it’s immediately detectable.',
      tech: (<>
        <Row k="structure" v="RFC-6962 Merkle transparency log" />
        <Row k="ballots on board" v={`${t.ballots.length} (published in credential-sorted order — board position leaks no identity/timing)`} />
        <Row k="Merkle root" v={t.boardRoot.slice(0, 24) + '…'} />
      </>),
    },
    {
      id: 'tally', step: '6', title: 'Close & tally (quorum decrypts totals)', actor: 'Trustees', mode: 'real', emits: 'proven decryption shares',
      plain: 'Voting closes. A quorum of trustees jointly decrypts only the TOTALS for each candidate — never any individual ballot. Each contributes a step with a proof that they did it honestly.',
      tech: (<>
        <Row k="aggregate" v="homomorphic sum of all ballots, per candidate" />
        <Row k="decryption" v={`${t.decShares.length} of ${t.trustees} trustees · Lagrange-combined · each share proven`} />
        <Row k="results" v={t.candidates.map((c, j) => `${c} ${t.results[j]}`).join('   ')} />
        <p className="mt-2 text-xs text-ink-faint">Only the per-candidate totals are ever decrypted — there is no code path that decrypts a single ballot.</p>
      </>),
    },
    {
      id: 'publish', step: '7', title: 'Publish the whole election', actor: 'Public', mode: 'real', emits: 'transcript.json',
      plain: 'The entire election is published as one self-contained file. It holds encrypted ballots, proofs, and signed roots — no names, no plaintext votes.',
      tech: (<>
        <Row k="format" v="canonical transcript.json (versioned wire format)" />
        <Row k="contains" v="eligible roll · encrypted ballots + proofs · aggregates · proven decryptions · results" />
        <Row k="does NOT contain" v="identities · plaintext votes · secret keys" />
      </>),
    },
    {
      id: 'verify', step: '8', title: 'Anyone verifies it', actor: 'Anyone', mode: 'real', emits: 'who can see what?', live: 'verify',
      plain: 'Anyone can re-check the entire result from that file, trusting only the math — not the people who ran it. We ship TWO independent verifiers (TypeScript and Python/libsodium) and cross-check them in CI.',
      tech: (<>
        <Row k="checks" v="signatures · eligibility · single-use · valid selections · honest aggregate · proven decryptions · tally" />
        <Row k="independence" v="TypeScript verifier ⇄ Python/libsodium verifier — agree byte-for-byte" />
      </>),
    },
    {
      id: 'privacy', step: '9', title: 'Who knows what', actor: 'Everyone', mode: 'real', emits: 'so try to break it',
      plain: 'No single party can link a person to their vote. The registrar can map a credential to an identity — but the vote is encrypted. The public sees credentials and encrypted ballots — but no identities. The trustees decrypt only totals.',
      tech: (<>
        <Row k="public board entry" v={`${sampleBallot.voter} → credential ${ptShort(sampleBallot.credentialPub)}`} />
        <Row k="public can map to a person?" v="no — the transcript has no identities" />
        <Row k="registrar (privately) maps it to" v={sc.registrar.identityOf(sampleBallot.credentialPub) ?? '(unknown)'} />
        <p className="mt-2 text-xs text-ink-faint">The registrar alone learns <em>turnout</em> (who voted), never the vote. Linking a person to their actual choice would need the registrar AND a trustee quorum AND going off-protocol.</p>
      </>),
    },
    {
      id: 'adversary', step: '10', title: 'Try to cheat it', actor: 'Insider', mode: 'real', live: 'adversary',
      plain: 'Play the insider. Every classic attack — vote twice, vote without a credential, vote for two, flip a ballot, rig the total — is caught by the math, and anyone can see it.',
      tech: (<p className="text-xs text-ink-faint">Each button runs the real verifier against a tampered transcript and shows exactly which check fails.</p>),
    },
  ];

  const actorTint = (mode: Mode) => (mode === 'real' ? 'bg-pass-soft text-pass' : 'bg-warn-soft text-warn');

  return (
    <div className="mx-auto max-w-3xl px-5 pb-14">
      <div className="mb-6 inline-flex items-center gap-1 rounded-lg border border-line bg-surface-2 p-1 text-xs">
        <button onClick={() => setTech(false)} className={`rounded-md px-3 py-1 ${!tech ? 'bg-accent-strong text-white' : 'text-ink-muted hover:text-ink'}`}>Explain simply</button>
        <button onClick={() => setTech(true)} className={`rounded-md px-3 py-1 ${tech ? 'bg-accent-strong text-white' : 'text-ink-muted hover:text-ink'}`}>Show the cryptography</button>
      </div>

      {/* data-flow pipeline — the whole protocol at once, top to bottom */}
      <div>
        {phases.map((p, idx) => (
          <div key={p.id}>
            <section className="rounded-xl border border-line bg-surface p-4 shadow-card">
              <div className="mb-2 flex flex-wrap items-center gap-2">
                <span className="flex h-6 min-w-6 items-center justify-center rounded-md border border-line bg-surface-2 px-1.5 font-mono text-xs font-medium text-ink-faint">{p.step}</span>
                <h3 className="text-[15px] font-semibold tracking-tight text-ink">{p.title}</h3>
                <span className="rounded-md bg-accent-soft px-2 py-0.5 text-[11px] font-medium text-accent-ink">{p.actor}</span>
                <span className={`rounded-md px-2 py-0.5 text-[11px] ${actorTint(p.mode)}`}>{p.mode === 'real' ? '● runs for real' : 'device represented'}</span>
              </div>
              <p className="text-sm leading-relaxed text-ink-muted">{p.plain}</p>

              {tech && <div className="mt-3 space-y-1.5 rounded-lg border border-line bg-surface-2 p-3">{p.tech}</div>}

              {p.live === 'audit' && (
                <div className="mt-3 rounded-lg border border-line bg-surface-2 p-3">
                  <p className="mb-2 text-xs text-ink-faint">Audit a test ballot (Benaloh challenge): your device claims a choice — spoil it and check. A spoiled ballot is discarded, so a cheating device can never predict an audit.</p>
                  <div className="flex flex-wrap gap-2">
                    {t.candidates.map((c, j) => (
                      <button key={j} onClick={() => setAuditPick(j)} className="rounded-lg border border-line bg-surface px-3 py-1.5 text-xs font-medium text-ink hover:border-line-strong">audit “{c}”</button>
                    ))}
                  </div>
                  {auditPick !== null && (
                    <div className="mt-3 text-sm">
                      <p className="text-pass">✓ Honest device that encrypted “{t.candidates[auditPick]}” passes: {String(auditCheck(t, auditPick, auditPick))}</p>
                      <p className="text-fail">✗ A device that secretly encrypted “{t.candidates[(auditPick + 1) % t.candidates.length]}” passes as “{t.candidates[auditPick]}”? {String(auditCheck(t, (auditPick + 1) % t.candidates.length, auditPick))}</p>
                    </div>
                  )}
                </div>
              )}

              {p.live === 'verify' && (
                <div className="mt-3 rounded-lg border border-line bg-surface-2 p-3">
                  <ul className="space-y-1">{result.checks.map((c, idx2) => <Check key={idx2} {...c} />)}</ul>
                  <StatusLine ok={result.ok}>{result.ok ? 'from the public record alone — and the independent Python verifier agrees (checked in CI).' : ''}</StatusLine>
                </div>
              )}

              {p.live === 'adversary' && (
                <div className="mt-3 rounded-lg border border-line bg-surface-2 p-3">
                  <div className="flex flex-wrap gap-2">
                    {(['double', 'ineligible', 'overvote', 'tamper', 'rig'] as const).map((k) => (
                      <button key={k} onClick={() => runCheat(k)} className="rounded-lg border border-fail/40 px-3 py-1.5 text-xs font-medium text-fail hover:bg-fail-soft">
                        {{ double: 'Vote twice', ineligible: 'No credential', overvote: 'Vote for two', tamper: 'Flip a ballot', rig: 'Rig the result' }[k]}
                      </button>
                    ))}
                  </div>
                  {cheat && (
                    <div className="mt-3">
                      <ul className="space-y-1">{cheat.result.checks.filter((c) => !c.ok).map((c, idx2) => <Check key={idx2} {...c} />)}</ul>
                      <StatusLine ok={false}>Caught — the verifier rejects it.</StatusLine>
                    </div>
                  )}
                </div>
              )}
            </section>
            {p.emits && idx < phases.length - 1 && <Edge label={p.emits} />}
          </div>
        ))}
      </div>

      <p className="mt-6 text-xs text-ink-faint">
        Real cryptography, end to end; only the physical devices (phone, kiosk, printer) are represented. Pre-audit demo — not for binding government elections.
      </p>
    </div>
  );
}
