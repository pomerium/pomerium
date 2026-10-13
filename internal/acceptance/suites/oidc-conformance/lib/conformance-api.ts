// Minimal client for the OpenID Foundation conformance suite REST API, i.e. the
// subset that the suite's own scripts/conformance.py uses to run a test plan.
// The server runs with the "dev" Spring profile, so no API token is needed.

import { CONFORMANCE_API_URL } from "../setup/constants.js";

export type TestStatus =
  | "CREATED"
  | "CONFIGURED"
  | "WAITING"
  | "RUNNING"
  | "FINISHED"
  | "INTERRUPTED";

export type TestResult = "PASSED" | "FAILED" | "WARNING" | "REVIEW" | "SKIPPED" | "UNKNOWN";

export interface PlanModule {
  testModule: string;
  variant?: Record<string, string>;
}

export interface Plan {
  id: string;
  name: string;
  modules: PlanModule[];
}

export interface ModuleInfo {
  testId: string;
  testName: string;
  status: TestStatus;
  result: TestResult | null;
}

export interface BrowserState {
  urls: string[];
  urlsWithMethod?: { url: string; method: string }[];
  visited: string[];
}

export interface LogEntry {
  _id: string;
  src?: string;
  msg?: string;
  result?: string;
  requirements?: string[];
  upload?: string;
  img?: string;
  [key: string]: unknown;
}

async function call<T>(
  method: string,
  pathAndQuery: string,
  body?: string,
  contentType = "application/json",
): Promise<T> {
  const res = await fetch(`${CONFORMANCE_API_URL}${pathAndQuery}`, {
    method,
    headers: {
      // The suite refuses requests that did not arrive over https; the runner
      // talks to it directly over the published plain-HTTP port.
      "X-Forwarded-Proto": "https",
      ...(body !== undefined ? { "Content-Type": contentType } : {}),
    },
    body,
  });
  const text = await res.text();
  if (!res.ok) {
    throw new Error(`${method} ${pathAndQuery}: HTTP ${res.status}: ${text.slice(0, 500)}`);
  }
  return (text ? JSON.parse(text) : undefined) as T;
}

export async function createPlan(
  planName: string,
  config: object,
  variant?: Record<string, string>,
): Promise<Plan> {
  const q = new URLSearchParams({ planName });
  if (variant) q.set("variant", JSON.stringify(variant));
  return call<Plan>("POST", `/api/plan?${q}`, JSON.stringify(config));
}

export async function createModule(planId: string, mod: PlanModule): Promise<string> {
  const q = new URLSearchParams({ test: mod.testModule, plan: planId });
  if (mod.variant) q.set("variant", JSON.stringify(mod.variant));
  const res = await call<{ id: string }>("POST", `/api/runner?${q}`);
  return res.id;
}

export async function startModule(testId: string): Promise<void> {
  await call("POST", `/api/runner/${testId}`);
}

export async function getModuleInfo(testId: string): Promise<ModuleInfo> {
  return call<ModuleInfo>("GET", `/api/info/${testId}`);
}

/** Browser URLs the test wants visited; undefined once the test is gone from the runner. */
export async function getBrowserState(testId: string): Promise<BrowserState | undefined> {
  try {
    const res = await call<{ browser?: BrowserState }>("GET", `/api/runner/${testId}`);
    return res.browser;
  } catch {
    return undefined;
  }
}

export async function getLog(testId: string): Promise<LogEntry[]> {
  return call<LogEntry[]>("GET", `/api/log/${testId}`);
}

export interface PendingUpload {
  placeholder: string;
  /** What the screenshot must show, e.g. "The server must ask the user to login...". */
  msg: string;
}

/** Log entries that are placeholders for a screenshot the tester must upload. */
export async function getPendingUploads(testId: string): Promise<PendingUpload[]> {
  const images = await call<LogEntry[]>("GET", `/api/log/${testId}/images`);
  return images
    .filter((e) => e.upload && !e.img)
    .map((e) => ({ placeholder: e.upload as string, msg: e.msg ?? "" }));
}

export async function uploadImage(testId: string, placeholder: string, png: Buffer): Promise<void> {
  const dataURL = `data:image/png;base64,${png.toString("base64")}`;
  await call(
    "POST",
    `/api/log/${testId}/images/${encodeURIComponent(placeholder)}`,
    dataURL,
    "text/plain",
  );
}

export function logDetailURL(testId: string): string {
  return `${CONFORMANCE_API_URL}/log-detail.html?log=${testId}`;
}
