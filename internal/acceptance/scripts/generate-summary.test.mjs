import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { generateSummary } from './generate-summary.mjs';

const summaryScript = fileURLToPath(new URL('./generate-summary.mjs', import.meta.url));

const featureMap = {
  categories: {
    Authentication: {
      description: 'Authentication coverage',
      files: { 'authn/login.spec.ts': ['OIDC login'] },
    },
  },
};

function playwrightResults(status, {
  errors = [],
  attempts = [{ status: 'passed', duration: 1_200 }],
} = {}) {
  return {
    errors,
    stats: { duration: 1_200 },
    suites: [{
      file: 'authn/login.spec.ts',
      specs: [{
        title: 'signs in through OIDC',
        tests: [{ status, results: attempts }],
      }],
    }],
  };
}

test('accepts passing results', () => {
  const summary = generateSummary(playwrightResults('expected'), featureMap);

  assert.equal(summary.failed, false);
  assert.match(summary.markdown, /## ✅ Acceptance Test Summary/);
});

test('reports failed tests', () => {
  const summary = generateSummary(playwrightResults('unexpected', {
    attempts: [{ status: 'failed', duration: 1_200 }],
  }), featureMap);

  assert.equal(summary.failed, true);
  assert.match(summary.markdown, /## ❌ Acceptance Test Summary/);
});

test('accepts skipped results', () => {
  const summary = generateSummary(playwrightResults('skipped', {
    attempts: [{ status: 'skipped', duration: 0 }],
  }), featureMap);

  assert.equal(summary.failed, false);
  assert.match(summary.markdown, /\| ⊘ Skipped \| 1 \|/);
});

for (const [name, results, message] of [
  ['results without test outcomes', { errors: [], suites: [{ specs: [] }] }, /Results Unavailable/],
  ['an invalid suite shape', { errors: [], suites: [null] }, /invalid structure/],
  ['top-level Playwright errors', playwrightResults('expected', {
    errors: [{ message: 'global setup failed' }],
  }), /top-level error/],
  ['interrupted final attempts', playwrightResults('skipped', {
    attempts: [{ status: 'interrupted', duration: 1_200 }],
  }), /interrupted final attempt/],
  ['an unknown test outcome', playwrightResults('unknown'), /missing or unknown status/],
  ['an attempt status used as a test outcome', playwrightResults('failed', {
    attempts: [{ status: 'failed' }],
  }), /missing or unknown status/],
  ['an unknown final attempt', playwrightResults('expected', {
    attempts: [{ status: 'unknown' }],
  }), /missing or unknown status/],
  ['a flaky result without a passing final attempt', playwrightResults('flaky', {
    attempts: [{ status: 'failed', duration: 1_200 }],
  }), /without a passing final attempt/],
]) {
  test(`rejects ${name}`, () => {
    const summary = generateSummary(results, featureMap);

    assert.equal(summary.failed, true);
    assert.match(summary.markdown, message);
  });
}

test('keeps a completed flaky retry as a warning', () => {
  const summary = generateSummary(playwrightResults('flaky', {
    attempts: [
      { status: 'failed', duration: 800 },
      { status: 'passed', duration: 400 },
    ],
  }), featureMap);

  assert.equal(summary.failed, false);
  assert.match(summary.markdown, /## ⚠️ Acceptance Test Summary/);
});

test('writes an unavailable summary before exiting nonzero', (t) => {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'pomerium-acceptance-summary-')));
  t.after(() => rmSync(directory, { recursive: true, force: true }));

  const resultsDirectory = join(directory, 'results');
  const featureMapsDirectory = join(directory, 'feature-maps');
  const output = join(directory, 'summary.md');
  mkdirSync(resultsDirectory);
  mkdirSync(featureMapsDirectory);
  writeFileSync(join(resultsDirectory, 'results.json'), 'null');
  writeFileSync(join(featureMapsDirectory, 'feature-map.json'), JSON.stringify(featureMap));

  const result = spawnSync(process.execPath, [
    summaryScript,
    '--results-dir', resultsDirectory,
    '--feature-maps-dir', featureMapsDirectory,
    '--output', output,
  ]);

  assert.equal(result.status, 1);
  assert.match(readFileSync(output, 'utf8'), /Acceptance Test Results Unavailable/);
});

test('rejects a missing harness results file', (t) => {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'pomerium-acceptance-summary-')));
  t.after(() => rmSync(directory, { recursive: true, force: true }));

  const resultsDirectory = join(directory, 'results');
  const featureMapsDirectory = join(directory, 'feature-maps');
  const output = join(directory, 'summary.md');
  mkdirSync(resultsDirectory);
  mkdirSync(featureMapsDirectory);
  writeFileSync(join(resultsDirectory, 'results.json'), JSON.stringify(playwrightResults('expected')));
  writeFileSync(join(featureMapsDirectory, 'feature-map.json'), JSON.stringify(featureMap));

  const result = spawnSync(process.execPath, [
    summaryScript,
    '--results-dir', resultsDirectory,
    '--feature-maps-dir', featureMapsDirectory,
    '--expected-results', '2',
    '--output', output,
  ]);

  assert.equal(result.status, 1);
  assert.match(readFileSync(output, 'utf8'), /Expected 2 Playwright results files, but found 1/);
});
