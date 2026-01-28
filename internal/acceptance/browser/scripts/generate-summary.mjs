#!/usr/bin/env node
/**
 * Generate acceptance test summary from Playwright results.
 *
 * Usage: node scripts/generate-summary.mjs [--output file.md]
 *
 * Reads: ../artifacts/playwright/results.json
 * Writes: stdout (for GITHUB_STEP_SUMMARY) or specified file
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const RESULTS_PATH = join(__dirname, '../../artifacts/playwright/results.json');
const FEATURE_MAP_PATH = join(__dirname, '../fixtures/feature-map.json');

/**
 * Parse command line arguments.
 */
function parseArgs() {
  const args = process.argv.slice(2);
  const result = { output: null };

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--output' && args[i + 1]) {
      result.output = args[++i];
    }
  }

  return result;
}

/**
 * Extract test file path from spec location.
 * Playwright results.json uses paths relative to testDir (e.g., "authn/login.spec.ts")
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
      return '\u2705';
    case 'failed':
    case 'unexpected':
      return '\u274c';
    case 'skipped':
      return '\u2298';
    case 'flaky':
      return '\u26a0\ufe0f';
    case 'timedOut':
    case 'interrupted':
      return '\u23f0';
    default:
      return '\u2753';
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
      description: categoryData.description,
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
          const fullTitle = suiteTitle ? `${suiteTitle} \u203a ${spec.title}` : spec.title;
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
          const nestedSuiteTitle = suiteTitle ? `${suiteTitle} \u203a ${suite.title}` : suite.title;
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
      const suiteTitle = parentSuiteTitle ? `${parentSuiteTitle} \u203a ${suite.title}` : suite.title;

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
    lines.push('## \u26a0\ufe0f Acceptance Test Summary\n');
    lines.push('No test results found. Playwright may have crashed before producing output.\n');
    return lines.join('\n');
  }

  // Aggregate data
  const { categories, unmappedFiles, allTests } = aggregateByCategory(results.suites, featureMap);

  // Calculate totals
  const stats = results.stats || {};
  const passed = stats.expected || allTests.filter((t) => categorizeStatus(t.status) === 'passed').length;
  const failed = (stats.unexpected || 0) + allTests.filter((t) => ['timedOut', 'interrupted'].includes(t.status)).length ||
    allTests.filter((t) => categorizeStatus(t.status) === 'failed').length;
  const skipped = stats.skipped || allTests.filter((t) => categorizeStatus(t.status) === 'skipped').length;
  const flaky = stats.flaky || allTests.filter((t) => categorizeStatus(t.status) === 'flaky').length;
  const duration = stats.duration || allTests.reduce((sum, t) => sum + t.duration, 0);

  // Header with overall status
  const overallStatus = failed > 0 ? '\u274c' : flaky > 0 ? '\u26a0\ufe0f' : '\u2705';
  lines.push(`## ${overallStatus} Acceptance Test Summary\n`);

  // Summary table
  lines.push('| Result | Count |');
  lines.push('|--------|-------|');
  lines.push(`| \u2705 Passed | ${passed} |`);
  lines.push(`| \u274c Failed | ${failed} |`);
  if (flaky > 0) {
    lines.push(`| \u26a0\ufe0f Flaky | ${flaky} |`);
  }
  lines.push(`| \u2298 Skipped | ${skipped} |`);
  lines.push(`| \u23f1\ufe0f Duration | ${formatDuration(duration)} |`);
  lines.push('');

  // Feature coverage table
  lines.push('### Feature Coverage\n');
  lines.push('| Category | Tests | Status | Features |');
  lines.push('|----------|-------|--------|----------|');

  for (const [categoryName, data] of Object.entries(categories)) {
    const total = data.passed + data.failed + data.skipped + data.flaky;
    const status = data.failed > 0 ? '\u274c' : data.flaky > 0 ? '\u26a0\ufe0f' : data.passed > 0 ? '\u2705' : '\u2298';
    const features = Array.from(data.features).slice(0, 6).join(', ');
    lines.push(`| ${categoryName} | ${total} | ${status} | ${features} |`);
  }
  lines.push('');

  // Slowest tests
  const slowest = findSlowestTests(allTests, 3);
  if (slowest.length > 0) {
    lines.push('### \u23f1\ufe0f Slowest Tests\n');
    slowest.forEach((test, i) => {
      lines.push(`${i + 1}. \`${test.fullTitle}\` (${formatDuration(test.duration)})`);
    });
    lines.push('');
  }

  // Warn about unmapped files
  if (unmappedFiles.length > 0) {
    lines.push('### \u26a0\ufe0f Unmapped Test Files\n');
    lines.push('The following test files are not in `fixtures/feature-map.json`:\n');
    unmappedFiles.forEach((f) => lines.push(`- \`${f}\``));
    lines.push('');
  }

  // Detailed breakdown in collapsible section
  lines.push('<details>');
  lines.push('<summary>\ud83d\udccb All Tests by Category</summary>\n');

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

  // Check if results.json exists
  if (!existsSync(RESULTS_PATH)) {
    const noResults = '## \u26a0\ufe0f Acceptance Test Summary\n\nNo results found. Playwright may have crashed before producing output.\n';
    if (args.output) {
      mkdirSync(dirname(args.output), { recursive: true });
      writeFileSync(args.output, noResults);
    } else {
      console.log(noResults);
    }
    process.exit(0);
  }

  // Check if feature map exists
  if (!existsSync(FEATURE_MAP_PATH)) {
    console.error(`Error: Feature map not found at ${FEATURE_MAP_PATH}`);
    process.exit(1);
  }

  // Load files
  let results, featureMap;
  try {
    results = JSON.parse(readFileSync(RESULTS_PATH, 'utf8'));
  } catch (err) {
    console.error(`Error parsing results.json: ${err.message}`);
    process.exit(1);
  }

  try {
    featureMap = JSON.parse(readFileSync(FEATURE_MAP_PATH, 'utf8'));
  } catch (err) {
    console.error(`Error parsing feature-map.json: ${err.message}`);
    process.exit(1);
  }

  // Generate markdown
  const markdown = generateMarkdown(results, featureMap);

  // Output
  if (args.output) {
    mkdirSync(dirname(args.output), { recursive: true });
    writeFileSync(args.output, markdown);
    console.log(`Summary written to ${args.output}`);
  } else {
    console.log(markdown);
  }
}

main();
