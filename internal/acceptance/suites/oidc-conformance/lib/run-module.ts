// Drives one conformance test module to completion, doing what a human tester
// does in the suite's UI: visit each URL the module asks for in a browser
// (with the HTTP method it asks for), sign in at Keycloak whenever Pomerium
// sends the browser there, and upload the screenshot the module asks for.
//
// Some modules can only be judged by the tester, e.g. "the server must ask the
// user to login for a second time": the suite marks them REVIEW. The driver
// makes that judgement itself and records a problem when the OP did not
// behave as required, so REVIEW is not a free pass.

import type { Page } from "@playwright/test";
import { submitLoginForm } from "../../shared/keycloak-login.js";
import { testUsers } from "../../shared/users.js";
import { CONFORMANCE_BASE_URL, KEYCLOAK_HOSTNAME } from "../setup/constants.js";
import {
  createModule,
  getBrowserState,
  getLog,
  getModuleInfo,
  getPendingUploads,
  startModule,
  uploadImage,
  type LogEntry,
  type PlanModule,
  type TestResult,
  type TestStatus,
} from "./conformance-api.js";

const CONFORMANCE_HOST = new URL(CONFORMANCE_BASE_URL).host;
const USER = testUsers.alice;

/** How long a module may sit in WAITING with nothing left for the browser to do. */
const STALL_MS = 30_000;
const POLL_MS = 500;

export interface ModuleOutcome {
  testId: string;
  testModule: string;
  variant?: Record<string, string>;
  status: TestStatus;
  result: TestResult | "STALLED";
  /** Log entries the suite flagged as FAILURE or WARNING. */
  findings: { result: string; src?: string; msg?: string; requirements?: string[] }[];
  /** OP misbehavior detected by the driver (what a human reviewer would reject). */
  problems: string[];
  /** Other observations made by the driver. */
  notes: string[];
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function runModule(
  page: Page,
  planId: string,
  mod: PlanModule,
  timeoutMs: number,
): Promise<ModuleOutcome> {
  const testId = await createModule(planId, mod);
  const notes: string[] = [];
  const problems: string[] = [];
  const visited = new Set<string>();
  const uploaded = new Set<string>();
  const deadline = Date.now() + timeoutMs;
  /** Screenshot of the login page the last visit showed, if any. */
  let loginPage: Buffer | undefined;
  let started = false;
  let idleSince: number | undefined;
  let status: TestStatus = "CREATED";
  let result: ModuleOutcome["result"] = "UNKNOWN";

  for (;;) {
    const info = await getModuleInfo(testId);
    status = info.status;
    if (status === "FINISHED" || status === "INTERRUPTED") {
      result = info.result ?? "UNKNOWN";
      break;
    }
    if (Date.now() > deadline) {
      notes.push(`driver timed out with the module in status ${status}`);
      result = "STALLED";
      break;
    }

    let acted = false;
    if (status === "CONFIGURED" && !started) {
      await startModule(testId);
      started = true;
      acted = true;
    } else if (status === "WAITING") {
      const browser = await getBrowserState(testId);
      const next = (browser?.urlsWithMethod ?? browser?.urls.map((url) => ({ url, method: "GET" })))
        ?.find((u) => !visited.has(u.url));
      if (next) {
        visited.add(next.url);
        loginPage = await visit(page, next.url, next.method, notes, problems);
        acted = true;
      } else {
        for (const upload of await getPendingUploads(testId)) {
          if (uploaded.has(upload.placeholder)) continue;
          uploaded.add(upload.placeholder);
          let png: Buffer;
          if (/log ?in/i.test(upload.msg)) {
            if (loginPage) {
              png = loginPage;
              notes.push(`uploaded the login page for "${upload.msg}"`);
            } else {
              problems.push(`the OP did not show a login page: "${upload.msg}"`);
              png = await page.screenshot({ fullPage: true });
            }
          } else {
            notes.push(`uploaded a screenshot of ${page.url()} for "${upload.msg}"`);
            png = await page.screenshot({ fullPage: true });
          }
          await uploadImage(testId, upload.placeholder, png);
          acted = true;
        }
      }
    }

    if (acted || status !== "WAITING") {
      idleSince = undefined;
    } else if (idleSince === undefined) {
      idleSince = Date.now();
    } else if (Date.now() - idleSince > STALL_MS) {
      notes.push(
        `module stalled in WAITING for ${STALL_MS / 1000}s with every browser URL visited ` +
          `(last page: ${page.url()})`,
      );
      result = "STALLED";
      break;
    }
    await sleep(POLL_MS);
  }

  const findings = (await getLog(testId))
    .filter((e: LogEntry) => e.result === "FAILURE" || e.result === "WARNING")
    .map((e) => ({ result: e.result!, src: e.src, msg: e.msg, requirements: e.requirements }));

  return {
    testId,
    testModule: mod.testModule,
    variant: mod.variant,
    status,
    result,
    findings,
    problems,
    notes,
  };
}

/** One line per driver problem, driver note and suite finding. */
export function describeOutcome(o: ModuleOutcome): string[] {
  return [
    ...o.problems.map((p) => `PROBLEM ${p}`),
    ...o.notes.map((n) => `driver: ${n}`),
    ...o.findings.map((f) => `${f.result} ${f.src ?? ""}: ${f.msg ?? ""}`),
  ];
}

/**
 * Sign in on the Keycloak login page, returning a screenshot of it. When
 * re-authenticating a known user (prompt=login, max_age) Keycloak may only ask
 * for the password.
 */
async function signIn(page: Page): Promise<Buffer> {
  const password = page.getByLabel("Password", { exact: true });
  await password.waitFor();
  const screenshot = await page.screenshot({ fullPage: true });
  if (await page.getByLabel(/username/i).isVisible()) {
    await submitLoginForm(page, USER.email, USER.password);
  } else {
    await password.fill(USER.password);
    await page.getByRole("button", { name: /sign in/i }).click();
  }
  return screenshot;
}

/** Navigate to url with method, sending its query parameters as a form body for POST. */
async function navigate(page: Page, url: string, method: string): Promise<void> {
  if (method.toUpperCase() !== "POST") {
    await page.goto(url, { waitUntil: "domcontentloaded" });
    return;
  }
  const target = new URL(url);
  const fields = [...target.searchParams];
  target.search = "";
  await page.setContent("<!doctype html><form method=post></form>");
  await Promise.all([
    page.waitForURL((u) => u.protocol !== "about:" && u.href !== "about:blank", {
      waitUntil: "domcontentloaded",
    }),
    page.evaluate(
      ({ action, fields }) => {
        const form = document.forms[0];
        form.action = action;
        for (const [name, value] of fields) {
          const input = document.createElement("input");
          input.type = "hidden";
          input.name = name;
          input.value = value;
          form.appendChild(input);
        }
        form.submit();
      },
      { action: target.toString(), fields },
    ),
  ]);
}

/**
 * Visit one authorization URL and follow the redirect chain until the browser
 * lands back on the conformance suite (the RP callback) or settles on some
 * other page (e.g. an OP error page that the module wants a screenshot of).
 * Returns a screenshot of the login page, if the visit showed one.
 */
async function visit(
  page: Page,
  url: string,
  method: string,
  notes: string[],
  problems: string[],
): Promise<Buffer | undefined> {
  let loginPage: Buffer | undefined;
  const promptNone = new URL(url).searchParams.get("prompt") === "none";
  try {
    await navigate(page, url, method);
  } catch (err) {
    notes.push(`${method} ${url} failed: ${(err as Error).message.split("\n")[0]}`);
    return undefined;
  }

  for (let hops = 0; hops < 10; hops++) {
    const current = new URL(page.url());
    if (current.host === CONFORMANCE_HOST) {
      // The callback page may post the response back to the suite with JS.
      await page.waitForLoadState("networkidle").catch(() => {});
      return loginPage;
    }
    if (current.hostname === KEYCLOAK_HOSTNAME) {
      if (promptNone) {
        problems.push("prompt=none: the OP sent the browser to an interactive login page");
        return loginPage;
      }
      loginPage = await signIn(page);
      await page
        .waitForURL((u) => u.hostname !== KEYCLOAK_HOSTNAME, { timeout: 30_000 })
        .catch(() => notes.push(`Keycloak sign-in did not redirect away (at ${page.url()})`));
      continue;
    }
    // Somewhere else (typically the authenticate service): either an
    // intermediate redirect or a final page such as an error page.
    const before = page.url();
    const moved = await page
      .waitForURL((u) => u.href !== before, { timeout: 3_000 })
      .then(() => true)
      .catch(() => false);
    if (!moved) return loginPage;
  }
  notes.push(`gave up following redirects at ${page.url()}`);
  return loginPage;
}
