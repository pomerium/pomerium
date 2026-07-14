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
import { join, dirname } from 'path';

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

/**
 * Parse command line arguments.
 */
function parseArgs() {
  const args = process.argv.slice(2);
  const result = {
    output: null,
    resultsDir: 'internal/acceptance',
    featureMapsDir: 'internal/acceptance',
  };

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--output' && args[i + 1]) {
      result.output = args[++i];
    } else if (args[i] === '--results-dir' && args[i + 1]) {
      result.resultsDir = args[++i];
    } else if (args[i] === '--feature-maps-dir' && args[i + 1]) {
      result.featureMapsDir = args[++i];
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
  const suites = [];
  const stats = { expected: 0, unexpected: 0, skipped: 0, flaky: 0, duration: 0 };

  for (const path of paths) {
    let data;
    try {
      data = JSON.parse(readFileSync(path, 'utf8'));
    } catch (err) {
      console.error(`Warning: skipping unparseable results file ${path}: ${err.message}`);
      continue;
    }
    if (Array.isArray(data.suites)) suites.push(...data.suites);
    const s = data.stats || {};
    stats.expected += s.expected || 0;
    stats.unexpected += s.unexpected || 0;
    stats.skipped += s.skipped || 0;
    stats.flaky += s.flaky || 0;
    stats.duration += s.duration || 0;
  }

  // Empty suites (nothing parsed) render as the "no results" summary downstream.
  return { suites, stats };
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
    case 'passed':
    case 'expected':
      return 'passed';
    case 'failed':
    case 'unexpected':
    case 'timedOut':
    case 'interrupted':
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
            duration: testResult.results?.reduce((sum, r) => sum + (r.duration || 0), 0) || 0,
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
function generateMarkdown(results, featureMap) {
  const lines = [];

  // Handle missing or empty results
  if (!results || !results.suites || results.suites.length === 0) {
    lines.push('## ⚠️ Acceptance Test Summary\n');
    lines.push('No test results found. Playwright may have crashed before producing output.\n');
    return lines.join('\n');
  }

  // Aggregate data
  const { categories, unmappedFiles, allTests } = aggregateByCategory(results.suites, featureMap);

  // Totals come from the summed Playwright stats produced by combineResults
  // (Playwright counts timed-out/interrupted tests as `unexpected`).
  const { expected: passed, unexpected: failed, skipped, flaky, duration } = results.stats;

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

  return lines.join('\n');
}

/**
 * Main entry point.
 */
function main() {
  const args = parseArgs();

  // Discover feature-map fragments and results files.
  const featureMapPaths = findFiles(args.featureMapsDir, 'feature-map.json');
  const resultsPaths = findFiles(args.resultsDir, 'results.json');

  const emit = (markdown) => {
    if (args.output) {
      mkdirSync(dirname(args.output), { recursive: true });
      writeFileSync(args.output, markdown);
      console.log(`Summary written to ${args.output}`);
    } else {
      console.log(markdown);
    }
  };

  if (resultsPaths.length === 0) {
    emit('## ⚠️ Acceptance Test Summary\n\nNo results found. Playwright may have crashed before producing output.\n');
    process.exit(0);
  }

  if (featureMapPaths.length === 0) {
    console.error(`Error: no feature-map.json fragments found under ${args.featureMapsDir}`);
    process.exit(1);
  }

  const featureMap = mergeFeatureMaps(featureMapPaths);
  const results = combineResults(resultsPaths);

  emit(generateMarkdown(results, featureMap));
}

main();
