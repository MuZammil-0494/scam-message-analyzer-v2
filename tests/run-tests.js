/* ============================================================================
 * tests/run-tests.js — Node runner for the scoring engine.
 *
 *   node tests/run-tests.js
 *
 * Loads the plain JS modules with Node's vm (no bundler needed), runs every
 * sample through SCAM.analyze, and checks the expected levels/attacks.
 * Exits 1 if anything fails.
 * ==========================================================================*/
'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.join(__dirname, '..');
const FILES = [
  'js/rules.js',
  'js/links.js',
  'js/email.js',
  'js/scoring.js',
  'tests/samples.js'
];

const ctx = { console, URL, URLSearchParams, localStorage: storageShim(), navigator: {}, window: {} };
ctx.window = ctx;
vm.createContext(ctx);

for (const f of FILES) {
  const code = fs.readFileSync(path.join(ROOT, f), 'utf8');
  vm.runInContext(code, ctx, { filename: f });
}

function storageShim() {
  const store = {};
  return {
    getItem: (k) => (k in store ? store[k] : null),
    setItem: (k, v) => { store[k] = String(v); },
    removeItem: (k) => { delete store[k]; }
  };
}

const { SAMPLES } = ctx;
let pass = 0, fail = 0;
const failures = [];

function check(sample) {
  try {
    const r = ctx.SCAM.analyze(sample.input);
    const score = r.score;
    const level = r.level.id;
    const attackIds = r.attacks.map((a) => a.id);
    const notes = [];

    // 1) score band
    if (sample.minScore !== undefined && score < sample.minScore) {
      notes.push('score ' + score + ' < min ' + sample.minScore);
    }
    if (sample.maxScore !== undefined && score > sample.maxScore) {
      notes.push('score ' + score + ' > max ' + sample.maxScore);
    }
    // 2) allowed level
    if (sample.expectLevels && sample.expectLevels.indexOf(level) === -1) {
      notes.push('level="' + level + '" not in [' + sample.expectLevels.join(',') + ']');
    }
    // 3) required attacks
    (sample.expectAttacks || []).forEach((id) => {
      if (attackIds.indexOf(id) === -1) notes.push('missing attack: ' + id);
    });
    // 4) blacklisted attacks (must NOT be named)
    (sample.noFalse || []).forEach((id) => {
      if (attackIds.indexOf(id) !== -1) notes.push('false attack: ' + id + ' (' +
        r.attacks.filter((a) => a.id === id).map((a) => a.confidence + '%').join(',') + ')');
    });

    if (notes.length) {
      fail++;
      failures.push({ name: sample.name, score, level, attacks: attackIds, notes });
    } else {
      pass++;
    }
    return { ok: !notes.length, r, notes };
  } catch (e) {
    fail++;
    failures.push({ name: sample.name, notes: ['CRASH: ' + e.message] });
    return { ok: false, notes: [] };
  }
}

const results = SAMPLES.map(check);

console.log('');
console.log('--- SAMPLES / SCORE / LEVEL / ATTACKS ---');
SAMPLES.forEach((s, i) => {
  const r = results[i].r;
  if (!r) { console.log(' ✕ ' + s.name + ' -> CRASH'); return; }
  console.log(' ' + (results[i].ok ? '✓' : '✕') + ' ' + s.name.padEnd(46) +
    ' ' + String(r.score).padStart(3) + '/100 [' + r.level.id + '] ' +
    (r.attacks.map((a) => a.id + ':' + a.confidence).join(' ') || '—'));
});

console.log('');
if (failures.length) {
  console.log('FAILURES (' + fail + '):');
  failures.forEach((f) => {
    console.log('\n• ' + f.name + '  (score ' + f.score + ', level ' + f.level + ')');
    console.log('  attacks: ' + (f.attacks || []).join(', '));
    f.notes.forEach((n) => console.log('  - ' + n));
  });
} else {
  console.log('✓ ALL ' + pass + ' SAMPLES PASSED');
}
process.exit(fail ? 1 : 0);