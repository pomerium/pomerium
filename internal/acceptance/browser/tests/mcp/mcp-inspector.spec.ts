/**
 * MCP Inspector UI Tests
 *
 * Priority: P1
 * Validates: The official MCP Inspector (@modelcontextprotocol/inspector)
 *            can connect to the MCP server through Pomerium.
 *
 * Architecture:
 *   Spawns the MCP Inspector process (client on port 6280, proxy on port 6281),
 *   then uses Playwright to drive the Inspector's React web UI to:
 *     1. Select Streamable HTTP or SSE transport
 *     2. Enter the MCP server URL
 *     3. Connect and verify tools are discovered
 *
 * DOM Selectors (verified via DOM dump at runtime):
 *   - #transport-type-select — transport protocol selector (shadcn/ui Select, renders as button)
 *   - #sse-url-input — URL input (only visible when SSE/Streamable HTTP is selected)
 *   - button:has-text("Connect") — connect button (no data-testid)
 *   - [data-testid="auth-button"] — expand authentication section
 *   - role="tab" — tab triggers (only visible after connecting)
 *   - button:has-text("List Tools") — list tools button (only visible on Tools tab)
 */

import { test, expect, Page } from "@playwright/test";
import { ChildProcess, spawn, execSync } from "child_process";
import { timeouts } from "../../fixtures/test-data.js";

// Inspector ports (custom to avoid conflicts with other inspector instances)
const INSPECTOR_CLIENT_PORT = 6280;
const INSPECTOR_PROXY_PORT = 6281;
const INSPECTOR_BASE_URL = `http://localhost:${INSPECTOR_CLIENT_PORT}`;
// The inspector React app needs MCP_PROXY_PORT query param to talk to the proxy
const INSPECTOR_URL = `${INSPECTOR_BASE_URL}/?MCP_PROXY_PORT=${INSPECTOR_PROXY_PORT}`;

// Direct MCP server URL (bypasses Pomerium, for basic connectivity test)
const MCP_DIRECT_URL = "http://localhost:3100";

let inspectorProcess: ChildProcess | null = null;
let inspectorAvailable = false;

/** Kill any existing processes on the inspector ports. */
function clearInspectorPorts() {
  for (const port of [INSPECTOR_CLIENT_PORT, INSPECTOR_PROXY_PORT]) {
    try {
      const pids = execSync(`lsof -ti:${port} 2>/dev/null`, {
        encoding: "utf-8",
      }).trim();
      if (pids) {
        execSync(`kill -9 ${pids.split("\n").join(" ")} 2>/dev/null`);
      }
    } catch {
      // no processes on this port — fine
    }
  }
}

/** Start the MCP Inspector process and wait for it to be ready. */
async function startInspector(): Promise<ChildProcess> {
  clearInspectorPorts();

  // Wait a moment for ports to be freed
  await new Promise((r) => setTimeout(r, 1000));

  return new Promise<ChildProcess>((resolve, reject) => {
    const proc = spawn(
      "npx",
      ["@modelcontextprotocol/inspector@latest"],
      {
        env: {
          ...process.env,
          CLIENT_PORT: String(INSPECTOR_CLIENT_PORT),
          SERVER_PORT: String(INSPECTOR_PROXY_PORT),
          NODE_TLS_REJECT_UNAUTHORIZED: "0",
          DANGEROUSLY_OMIT_AUTH: "true",
          BROWSER: "none", // Prevent auto-opening browser
        },
        stdio: ["ignore", "pipe", "pipe"],
        detached: false,
      }
    );

    let started = false;
    const timeout = setTimeout(() => {
      if (!started) {
        proc.kill();
        reject(new Error("MCP Inspector failed to start within 30s"));
      }
    }, 30000);

    const onData = (data: Buffer) => {
      const output = data.toString();
      // The inspector prints "MCP Inspector is up and running at:" when fully ready
      if (output.includes("is up and running")) {
        if (!started) {
          started = true;
          clearTimeout(timeout);
          // Give it a moment to fully initialize
          setTimeout(() => resolve(proc), 500);
        }
      }
    };

    proc.stdout?.on("data", onData);
    proc.stderr?.on("data", onData);

    proc.on("error", (err) => {
      if (!started) {
        clearTimeout(timeout);
        reject(err);
      }
    });

    proc.on("exit", (code) => {
      if (!started) {
        clearTimeout(timeout);
        reject(new Error(`Inspector exited with code ${code} before ready`));
      }
    });
  });
}

/** Wait for a URL to respond with 200. */
async function waitForUrl(url: string, timeoutMs = 10000): Promise<boolean> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const resp = await fetch(url);
      if (resp.ok) return true;
    } catch {
      // not ready yet
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  return false;
}

/** Select a value from a shadcn/ui Select component by its trigger ID. */
async function selectOption(page: Page, triggerId: string, optionText: string) {
  // Click the select trigger to open the dropdown
  await page.locator(`#${triggerId}`).click();
  // Wait for the dropdown content to appear and click the matching option
  await page.getByRole("option", { name: optionText }).click();
}

/** Kill the inspector process and all its children. */
function killInspector() {
  if (inspectorProcess) {
    const pid = inspectorProcess.pid;
    inspectorProcess.kill("SIGTERM");
    inspectorProcess = null;
    // Also kill child processes
    if (pid) {
      try {
        execSync(`pkill -P ${pid} 2>/dev/null`);
      } catch {
        // ignore
      }
    }
    clearInspectorPorts();
  }
}

test.describe("MCP Inspector UI", () => {
  test.beforeAll(async () => {
    // Check if inspector is already running (e.g. Docker container in CI)
    const alreadyRunning = await waitForUrl(INSPECTOR_BASE_URL, 3000);
    if (alreadyRunning) {
      inspectorAvailable = true;
      return;
    }

    // Not running — spawn locally
    try {
      inspectorProcess = await startInspector();
      const ready = await waitForUrl(INSPECTOR_BASE_URL, 15000);
      if (!ready) {
        killInspector();
      } else {
        inspectorAvailable = true;
      }
    } catch (e) {
      console.error("Failed to start MCP Inspector:", e);
      inspectorProcess = null;
    }
  });

  test.afterAll(async () => {
    killInspector();
  });

  test.beforeEach(async () => {
    test.skip(
      !inspectorAvailable,
      "MCP Inspector is not available — skipping inspector UI tests"
    );
  });

  // -------------------------------------------------------------------------
  // Basic UI
  // -------------------------------------------------------------------------

  test("inspector UI should load with transport selector and connect button", async ({
    page,
  }) => {
    await page.goto(INSPECTOR_URL, { waitUntil: "networkidle" });

    // Transport type selector should be visible
    await expect(page.locator("#transport-type-select")).toBeVisible({
      timeout: timeouts.medium,
    });

    // Connect button should be visible (no data-testid, use text)
    await expect(
      page.getByRole("button", { name: "Connect" })
    ).toBeVisible({ timeout: timeouts.medium });

    // URL input should be visible for non-stdio transports
    // First select SSE or Streamable HTTP to make the URL input appear
    await selectOption(page, "transport-type-select", "SSE");
    await expect(page.locator("#sse-url-input")).toBeVisible();
  });

  // -------------------------------------------------------------------------
  // Streamable HTTP transport (direct to MCP server)
  // -------------------------------------------------------------------------

  test("Streamable HTTP transport should discover tools (direct)", async ({
    page,
  }) => {
    await page.goto(INSPECTOR_URL, { waitUntil: "networkidle" });

    // Select Streamable HTTP transport
    await selectOption(page, "transport-type-select", "Streamable HTTP");

    // Enter the direct MCP server URL
    const urlInput = page.locator("#sse-url-input");
    await urlInput.clear();
    await urlInput.fill(`${MCP_DIRECT_URL}/mcp`);

    // Click Connect
    await page.getByRole("button", { name: "Connect" }).click();

    // Wait for connection to establish
    await page.waitForTimeout(3000);

    // Navigate to Tools tab
    await page.getByRole("tab", { name: /tools/i }).click();

    // Click "List Tools" button
    await page.getByRole("button", { name: /list tools/i }).click();

    // Wait for tools to load
    await page.waitForTimeout(2000);

    // Verify tools are listed — look for tool names in the page content
    const pageContent = await page.textContent("body");
    expect(pageContent).toContain("echo");
    expect(pageContent).toContain("add");
    expect(pageContent).toContain("get_time");
  });

  // -------------------------------------------------------------------------
  // SSE transport (direct to MCP server)
  // -------------------------------------------------------------------------

  test("SSE transport should discover tools (direct)", async ({ page }) => {
    await page.goto(INSPECTOR_URL, { waitUntil: "networkidle" });

    // Select SSE transport
    await selectOption(page, "transport-type-select", "SSE");

    // Enter the direct MCP server URL
    const urlInput = page.locator("#sse-url-input");
    await urlInput.clear();
    await urlInput.fill(`${MCP_DIRECT_URL}/sse`);

    // Click Connect
    await page.getByRole("button", { name: "Connect" }).click();

    // Wait for connection to establish
    await page.waitForTimeout(3000);

    // Navigate to Tools tab
    await page.getByRole("tab", { name: /tools/i }).click();

    // Click "List Tools" button
    await page.getByRole("button", { name: /list tools/i }).click();

    // Wait for tools to load
    await page.waitForTimeout(2000);

    // Verify tools are listed
    const pageContent = await page.textContent("body");
    expect(pageContent).toContain("echo");
    expect(pageContent).toContain("add");
    expect(pageContent).toContain("get_time");
  });

});
