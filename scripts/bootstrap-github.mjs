#!/usr/bin/env node
// Populate the GitHub repo with labels, milestones, and issues from scripts/backlog.json.
//
//   node scripts/bootstrap-github.mjs            # DRY RUN — prints what it would do
//   node scripts/bootstrap-github.mjs --apply    # actually create them
//
// Requires the GitHub CLI authenticated:  gh auth login
// Idempotent: labels use --force; existing milestones/issues (by title) are skipped.

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const APPLY = process.argv.includes('--apply');
const backlog = JSON.parse(readFileSync(join(HERE, 'backlog.json'), 'utf8'));

const gh = (args, opts = {}) => execFileSync('gh', args, { encoding: 'utf8', ...opts });
const tag = APPLY ? '' : '[dry-run] ';
let created = { labels: 0, milestones: 0, issues: 0, skipped: 0 };

function ensureGh() {
  try { gh(['auth', 'status'], { stdio: 'ignore' }); }
  catch { console.error('✗ GitHub CLI not authenticated. Run: gh auth login'); process.exit(1); }
}

function repoSlug() {
  return gh(['repo', 'view', '--json', 'nameWithOwner', '-q', '.nameWithOwner']).trim();
}

function run(args) {
  if (!APPLY) { console.log(`${tag}gh ${args.join(' ')}`); return ''; }
  try { return gh(args); }
  catch (e) { console.error(`  ! gh ${args.slice(0, 2).join(' ')} failed: ${String(e.stderr || e.message).split('\n')[0]}`); return ''; }
}

// ---- labels ----
function doLabels() {
  console.log(`\n== Labels (${backlog.labels.length}) ==`);
  for (const l of backlog.labels) {
    const color = String(l.color).replace('#', '');
    run(['label', 'create', l.name, '--color', color, '--description', l.description || '', '--force']);
    created.labels++;
  }
}

// ---- milestones (title == milestone id, e.g. "M1") ----
function existingMilestones(slug) {
  if (!APPLY) return {};
  const j = JSON.parse(gh(['api', `repos/${slug}/milestones?state=all&per_page=100`]) || '[]');
  return Object.fromEntries(j.map((m) => [m.title, m.number]));
}
function doMilestones(slug) {
  console.log(`\n== Milestones (${backlog.milestones.length}) ==`);
  const have = existingMilestones(slug);
  for (const m of backlog.milestones) {
    if (have[m.id] !== undefined) { console.log(`  · ${m.id} exists (#${have[m.id]})`); created.skipped++; continue; }
    run(['api', '-X', 'POST', `repos/${slug}/milestones`,
      '-f', `title=${m.id}`, '-f', `description=${m.title} — ${m.description}`]);
    created.milestones++;
  }
}

// ---- issues ----
function existingIssueTitles() {
  if (!APPLY) return new Set();
  const j = JSON.parse(gh(['issue', 'list', '--state', 'all', '--limit', '1000', '--json', 'title']) || '[]');
  return new Set(j.map((i) => i.title));
}
function doIssues() {
  console.log(`\n== Issues (${backlog.issues.length}) ==`);
  const have = existingIssueTitles();
  for (const i of backlog.issues) {
    if (have.has(i.title)) { console.log(`  · skip (exists): ${i.title}`); created.skipped++; continue; }
    const args = ['issue', 'create', '--title', i.title, '--body', i.body || '', '--milestone', i.milestone];
    for (const l of i.labels || []) args.push('--label', l);
    run(args);
    created.issues++;
  }
}

console.log(`${APPLY ? '🚀 APPLYING' : '🔎 DRY RUN'} — labels, milestones, issues from backlog.json`);
let slug = 'Nimdy/voting-system-blockchain';
if (APPLY) { ensureGh(); slug = repoSlug(); console.log(`Repo: ${slug}`); }
doLabels();
doMilestones(slug);
doIssues();
console.log(`\nSummary: +${created.labels} labels, +${created.milestones} milestones, +${created.issues} issues, ${created.skipped} skipped.`);
if (!APPLY) console.log('Re-run with --apply to create them (needs: gh auth login).');
