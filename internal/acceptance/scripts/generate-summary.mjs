#!/usr/bin/env node
/**
 * Aggregate the acceptance-test summary across every e2e harness.
 *
 * Each harness (browser, mcp, ...) runs independently in its own CI job and
 * emits two things:
 *   - a Playwright `results.json` (uploaded as the `e2e-results-<harness>`
 *     artifact and downloaded into --results-dir), and
 *   - a committed `feature-map.json` fragment declaring its category/feature
 *     coverage (discovered under --feature-maps-dir).
 *
 * This script globs every results.json + every feature-map fragment, merges
 * them, and renders ONE combined Feature Coverage table containing all modules.
 * Adding a new harness needs no change here: drop a feature-map.json in the new
 * harness dir and upload its results.json as another e2e-results-* artifact.
 *
 * Usage:
 *   node generate-summary.mjs [--results-dir <dir>] [--feature-maps-dir <dir>] [--output <file>]
 *
 * Defaults keep a single-harness local run working (e.g. after `make test`):
 *   --results-dir       internal/acceptance   (recurses for results.json)
 *   --feature-maps-dir  internal/acceptance   (recurses for feature-map.json)
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync, statSync } from 'fs';
import { join, dirname, resolve } from 'path';
import { fileURLToPath } from 'url';

// Directories that never contain harness results or fragments — skipping them
// keeps discovery fast and avoids picking up dependencies' stray JSON.
const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  'test-results',
  'report',
  'playwright-report',
  '.certs',
  'dist',
]);
const ATTEMPT_OUTCOMES = new Set(['passed', 'failed', 'skipped', 'timedOut', 'interrupted']);

/**
 * Parse command line arguments.
 */
function parseArgs() {
  const args = process.argv.slice(2);
  const result = {
    output: null,
    resultsDir: 'internal/acceptance',
    featureMapsDir: 'internal/acceptance',
    expectedResults: null,
  };

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--output' && args[i + 1]) {
      result.output = args[++i];
    } else if (args[i] === '--results-dir' && args[i + 1]) {
      result.resultsDir = args[++i];
    } else if (args[i] === '--feature-maps-dir' && args[i + 1]) {
      result.featureMapsDir = args[++i];
    } else if (args[i] === '--expected-results' && args[i + 1]) {
      result.expectedResults = Number(args[++i]);
    }
  }

  return result;
}

/**
 * Recursively find files named `fileName` under `root`, skipping SKIP_DIRS.
 */
function findFiles(root, fileName) {
  const found = [];
  if (!existsSync(root)) return found;

  function walk(dir) {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) walk(full);
      } else if (entry.isFile() && entry.name === fileName) {
        found.push(full);
      }
    }
  }

  if (statSync(root).isDirectory()) walk(root);

  return found.sort();
}

/**
 * Merge every feature-map fragment into one { categories } object. Fragments
 * that declare the same category name have their `files` maps merged.
 */
function mergeFeatureMaps(paths) {
  const merged = { categories: {} };

  for (const path of paths) {
    let fragment;
    try {
      fragment = JSON.parse(readFileSync(path, 'utf8'));
    } catch (err) {
      console.error(`Warning: skipping unparseable feature map ${path}: ${err.message}`);
      continue;
    }
    for (const [name, data] of Object.entries(fragment.categories || {})) {
      if (!merged.categories[name]) merged.categories[name] = { files: {} };
      Object.assign(merged.categories[name].files, data.files || {});
    }
  }

  return merged;
}

/**
 * Combine every results.json into one { suites, stats } shape. Stats are summed
 * so the top-line totals reflect all harnesses together.
 */
function combineResults(paths) {
  const errors = [];
  const suites = [];
  const stats = { expected: 0, unexpected: 0, skipped: 0, flaky: 0, duration: 0 };

  for (const path of paths) {
    let data;
    try {
      data = JSON.parse(readFileSync(path, 'utf8'));
    } catch (err) {
      console.error(`Warning: skipping unparseable results file ${path}: ${err.message}`);
      errors.push({ message: `Could not parse ${path}` });
      continue;
    }
    if (!data || typeof data !== 'object' || Array.isArray(data)) {
      errors.push({ message: `${path} is not a Playwright report object` });
      continue;
    }
    if (!Array.isArray(data.suites) || data.suites.length === 0) {
      errors.push({ message: `${path} contains no test suites` });
    } else {
      suites.push(...data.suites);
    }
    if (data.errors !== undefined && !Array.isArray(data.errors)) {
      errors.push({ message: `${path} has an invalid error list` });
    } else if (data.errors?.length > 0) {
      errors.push(...data.errors);
    }
    const s = data.stats || {};
    stats.expected += s.expected || 0;
    stats.unexpected += s.unexpected || 0;
    stats.skipped += s.skipped || 0;
    stats.flaky += s.flaky || 0;
    stats.duration += s.duration || 0;
  }

  // Empty suites (nothing parsed) render as the "no results" summary downstream.
  return { errors, suites, stats };
}

/**
 * Extract test file path from spec location.
 * Playwright results.json uses paths relative to testDir (e.g., "authn/login.spec.ts").
 */
function getTestFilePath(spec) {
  const file = spec.file || '';
  if (!file) return null;

  // If already in category/file.spec.ts format, use as-is
  if (file.match(/^[a-z]+\/[^/]+\.spec\.ts$/)) {
    return file;
  }

  // Try to extract from full path
  const match = file.match(/tests\/(.+\.spec\.ts)$/);
  return match ? match[1] : file;
}

/**
 * Get status emoji.
 */
function getStatusEmoji(status) {
  switch (status) {
    case 'passed':
    case 'expected':
      return '✅';
    case 'failed':
    case 'unexpected':
      return '❌';
    case 'skipped':
      return '⊘';
    case 'flaky':
      return '⚠️';
    case 'timedOut':
    case 'interrupted':
      return '⏰';
    default:
      return '❓';
  }
}

/**
 * Categorize a test status for counting purposes.
 */
function categorizeStatus(status) {
  switch (status) {
    case 'expected':
      return 'passed';
    case 'unexpected':
      return 'failed';
    case 'skipped':
      return 'skipped';
    case 'flaky':
      return 'flaky';
    default:
      return 'other';
  }
}

/**
 * Format duration in seconds.
 */
function formatDuration(ms) {
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

/**
 * Aggregate results by category using feature map.
 */
function aggregateByCategory(suites, featureMap) {
  const categories = {};
  const unmappedFiles = new Set();
  const allTests = [];

  // Initialize categories from feature map
  for (const [categoryName, categoryData] of Object.entries(featureMap.categories)) {
    categories[categoryName] = {
      files: {},
      tests: [],
      passed: 0,
      failed: 0,
      skipped: 0,
      flaky: 0,
      features: new Set(),
    };

    // Pre-populate files from feature map
    for (const [filePath, features] of Object.entries(categoryData.files)) {
      categories[categoryName].files[filePath] = {
        features,
        tests: [],
      };
      features.forEach((f) => categories[categoryName].features.add(f));
    }
  }

  // Build reverse lookup: file path -> category
  const fileToCategory = {};
  for (const [categoryName, categoryData] of Object.entries(featureMap.categories)) {
    for (const filePath of Object.keys(categoryData.files)) {
      fileToCategory[filePath] = categoryName;
    }
  }

  // Process all test results recursively
  function processSpecs(specs, parentFile = null, suiteTitle = '') {
    for (const spec of specs) {
      const filePath = getTestFilePath(spec) || parentFile;

      if (spec.tests) {
        // This is a test with actual results
        for (const testResult of spec.tests) {
          const fullTitle = suiteTitle ? `${suiteTitle} › ${spec.title}` : spec.title;
          const test = {
            title: spec.title,
            file: filePath,
            status: testResult.status,
            attempts: Array.isArray(testResult.results) ? testResult.results : [],
            duration: Array.isArray(testResult.results)
              ? testResult.results.reduce((sum, result) => sum + (result.duration || 0), 0)
              : 0,
            fullTitle,
          };

          allTests.push(test);

          const categoryName = fileToCategory[filePath];
          if (categoryName && categories[categoryName]) {
            categories[categoryName].tests.push(test);
            if (categories[categoryName].files[filePath]) {
              categories[categoryName].files[filePath].tests.push(test);
            }

            // Update counts
            const statusCategory = categorizeStatus(test.status);
            if (statusCategory === 'passed') {
              categories[categoryName].passed++;
            } else if (statusCategory === 'failed') {
              categories[categoryName].failed++;
            } else if (statusCategory === 'skipped') {
              categories[categoryName].skipped++;
            } else if (statusCategory === 'flaky') {
              categories[categoryName].flaky++;
            }
          } else if (filePath) {
            unmappedFiles.add(filePath);
          }
        }
      }

      // Recurse into nested specs/suites
      if (spec.specs) {
        processSpecs(spec.specs, filePath, suiteTitle);
      }
      if (spec.suites) {
        for (const suite of spec.suites) {
          const nestedSuiteTitle = suiteTitle ? `${suiteTitle} › ${suite.title}` : suite.title;
          processSpecs(suite.specs || [], filePath, nestedSuiteTitle);
          if (suite.suites) {
            processSuites(suite.suites, filePath, nestedSuiteTitle);
          }
        }
      }
    }
  }

  function processSuites(suites, parentFile = null, parentSuiteTitle = '') {
    for (const suite of suites) {
      const filePath = getTestFilePath(suite) || parentFile;
      const suiteTitle = parentSuiteTitle ? `${parentSuiteTitle} › ${suite.title}` : suite.title;

      if (suite.specs) {
        processSpecs(suite.specs, filePath, suiteTitle);
      }
      if (suite.suites) {
        processSuites(suite.suites, filePath, suiteTitle);
      }
    }
  }

  processSuites(suites);

  return { categories, unmappedFiles: Array.from(unmappedFiles), allTests };
}

/**
 * Find the slowest tests.
 */
function findSlowestTests(allTests, count = 3) {
  return [...allTests]
    .filter((t) => t.duration > 0)
    .sort((a, b) => b.duration - a.duration)
    .slice(0, count);
}

/**
 * Generate the markdown summary.
 */
function generateSummary(results, featureMap) {
  const lines = [];

  if (!results || !Array.isArray(results.suites) || results.suites.length === 0) {
    return unavailableResultsSummary('No Playwright test results were recorded. The test run may have crashed before producing output.');
  }

  if (results.errors !== undefined && !Array.isArray(results.errors)) {
    return unavailableResultsSummary('The Playwright report has an invalid top-level error list, so the test outcome cannot be trusted.');
  }

  if (results.errors?.length > 0) {
    return unavailableResultsSummary(
      `Playwright reported ${results.errors.length} top-level ${results.errors.length === 1 ? 'error' : 'errors'} (for example, a global setup failure), so the test outcome cannot be trusted.`,
    );
  }

  let aggregate;
  try {
    aggregate = aggregateByCategory(results.suites, featureMap);
  } catch (err) {
    return unavailableResultsSummary(`The Playwright report has an invalid structure: ${err.message}`);
  }
  const { categories, unmappedFiles, allTests } = aggregate;
  if (allTests.length === 0) {
    return unavailableResultsSummary('No Playwright test outcomes were recorded. The test run may have crashed before producing output.');
  }

  const unknownOutcomes = allTests.filter(
    (test) => categorizeStatus(test.status) === 'other' ||
      !ATTEMPT_OUTCOMES.has(test.attempts.at(-1)?.status),
  );
  if (unknownOutcomes.length > 0) {
    return unavailableResultsSummary(
      `Playwright recorded ${unknownOutcomes.length} test ${unknownOutcomes.length === 1 ? 'outcome' : 'outcomes'} with a missing or unknown status.`,
      unknownOutcomes,
    );
  }

  const interruptedFinalAttempts = allTests.filter(
    (test) => test.attempts.at(-1)?.status === 'interrupted',
  );
  if (interruptedFinalAttempts.length > 0) {
    return unavailableResultsSummary(
      `Playwright recorded ${interruptedFinalAttempts.length} interrupted final ${interruptedFinalAttempts.length === 1 ? 'attempt' : 'attempts'}, so the test run did not complete.`,
      interruptedFinalAttempts,
    );
  }

  const incompleteFlakyTests = allTests.filter(
    (test) => test.status === 'flaky' && test.attempts.at(-1).status !== 'passed',
  );
  if (incompleteFlakyTests.length > 0) {
    return unavailableResultsSummary(
      `Playwright recorded ${incompleteFlakyTests.length} flaky ${incompleteFlakyTests.length === 1 ? 'outcome' : 'outcomes'} without a passing final attempt.`,
      incompleteFlakyTests,
    );
  }

  const passed = allTests.filter((test) => categorizeStatus(test.status) === 'passed').length;
  const failed = allTests.filter((test) => categorizeStatus(test.status) === 'failed').length;
  const skipped = allTests.filter((test) => categorizeStatus(test.status) === 'skipped').length;
  const flaky = allTests.filter((test) => categorizeStatus(test.status) === 'flaky').length;
  const duration = results.stats?.duration || allTests.reduce((sum, test) => sum + test.duration, 0);

  // Header with overall status
  const overallStatus = failed > 0 ? '❌' : flaky > 0 ? '⚠️' : '✅';
  lines.push(`## ${overallStatus} Acceptance Test Summary\n`);

  // Summary table
  lines.push('| Result | Count |');
  lines.push('|--------|-------|');
  lines.push(`| ✅ Passed | ${passed} |`);
  lines.push(`| ❌ Failed | ${failed} |`);
  if (flaky > 0) {
    lines.push(`| ⚠️ Flaky | ${flaky} |`);
  }
  lines.push(`| ⊘ Skipped | ${skipped} |`);
  lines.push(`| ⏱️ Duration | ${formatDuration(duration)} |`);
  lines.push('');

  // Feature coverage table
  lines.push('### Feature Coverage\n');
  lines.push('| Category | Tests | Status | Features |');
  lines.push('|----------|-------|--------|----------|');

  for (const [categoryName, data] of Object.entries(categories)) {
    const total = data.passed + data.failed + data.skipped + data.flaky;
    const status = data.failed > 0 ? '❌' : data.flaky > 0 ? '⚠️' : data.passed > 0 ? '✅' : '⊘';
    const features = Array.from(data.features).slice(0, 6).join(', ');
    lines.push(`| ${categoryName} | ${total} | ${status} | ${features} |`);
  }
  lines.push('');

  // Slowest tests
  const slowest = findSlowestTests(allTests, 3);
  if (slowest.length > 0) {
    lines.push('### ⏱️ Slowest Tests\n');
    slowest.forEach((test, i) => {
      lines.push(`${i + 1}. \`${test.fullTitle}\` (${formatDuration(test.duration)})`);
    });
    lines.push('');
  }

  // Warn about unmapped files
  if (unmappedFiles.length > 0) {
    lines.push('### ⚠️ Unmapped Test Files\n');
    lines.push('The following test files are not in any harness `feature-map.json`:\n');
    unmappedFiles.forEach((f) => lines.push(`- \`${f}\``));
    lines.push('');
  }

  // Detailed breakdown in collapsible section
  lines.push('<details>');
  lines.push('<summary>📋 All Tests by Category</summary>\n');

  for (const [categoryName, data] of Object.entries(categories)) {
    const total = data.passed + data.failed + data.skipped + data.flaky;
    lines.push(`#### ${categoryName} (${total})\n`);

    for (const test of data.tests) {
      const emoji = getStatusEmoji(test.status);
      const durationStr = test.duration > 0 ? ` (${formatDuration(test.duration)})` : '';
      lines.push(`- ${emoji} ${test.title}${durationStr}`);
    }
    lines.push('');
  }

  lines.push('</details>');

  return { markdown: lines.join('\n'), failed: failed > 0 };
}

/**
 * Build an actionable summary when the Playwright output cannot be used.
 */
function unavailableResultsSummary(message, affectedTests = []) {
  const affectedTestsMarkdown = affectedTests.length === 0
    ? ''
    : [
      '### Affected Tests\n',
      ...affectedTests.map((test) => {
        const file = test.file ? ` in \`${test.file}\`` : '';
        return `- \`${test.fullTitle}\`${file}`;
      }),
      '',
    ].join('\n');

  return {
    failed: true,
    markdown: [
      '## ❌ Acceptance Test Results Unavailable\n',
      `${message}\n`,
      affectedTestsMarkdown,
      'Inspect the workflow run and artifacts to determine why the acceptance results were not produced or cannot be trusted.\n',
    ].join('\n'),
  };
}

/**
 * Main entry point.
 */
function main() {
  const args = parseArgs();

  // Discover feature-map fragments and results files.
  const featureMapPaths = findFiles(args.featureMapsDir, 'feature-map.json');
  const resultsPaths = findFiles(args.resultsDir, 'results.json');

  const emit = (summary) => {
    if (args.output) {
      mkdirSync(dirname(args.output), { recursive: true });
      writeFileSync(args.output, summary.markdown);
      console.log(`Summary written to ${args.output}`);
    } else {
      console.log(summary.markdown);
    }
    process.exitCode = summary.failed ? 1 : 0;
  };

  if (resultsPaths.length === 0) {
    emit(unavailableResultsSummary('No Playwright results files were found. A test harness may have crashed before producing output.'));
    return;
  }

  if (featureMapPaths.length === 0) {
    emit(unavailableResultsSummary(`No feature-map.json fragments were found under ${args.featureMapsDir}.`));
    return;
  }

  if (args.expectedResults !== null) {
    if (!Number.isInteger(args.expectedResults) || args.expectedResults < 1) {
      emit(unavailableResultsSummary('The expected Playwright results count is invalid.'));
      return;
    }
    if (resultsPaths.length !== args.expectedResults) {
      emit(unavailableResultsSummary(
        `Expected ${args.expectedResults} Playwright results ${args.expectedResults === 1 ? 'file' : 'files'}, but found ${resultsPaths.length}.`,
      ));
      return;
    }
  }

  const featureMap = mergeFeatureMaps(featureMapPaths);
  const results = combineResults(resultsPaths);

  emit(generateSummary(results, featureMap));
}

export { generateSummary };

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
