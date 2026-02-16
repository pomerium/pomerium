/**
 * MCPJam Inspector UI Tests
 *
 * Priority: P1
 * Validates: The MCPJam Inspector (@mcpjam/inspector) can connect
 *            to the MCP server and discover tools.
 *
 * Architecture:
 *   Spawns the MCPJam Inspector process (single port, always 6274),
 *   then uses Playwright to drive its web UI.
 *
 * DOM Selectors (verified via DOM dump at runtime):
 *   MCPJam Inspector has NO data-testid or id attributes. All selectors
 *   are based on text content, placeholders, and roles:
 *   - button:has-text("Add Your First Server") or button:has-text("Add Server") — open dialog
 *   - input[placeholder="my-mcp-server"] — server name
 *   - input[placeholder="http://localhost:8080/mcp"] — server URL
 *   - select with values "STDIO"/"HTTP" — connection type
 *   - select with values "No Authentication"/"Bearer Token"/"OAuth 2.0" — auth
 *   - The dialog submit button is also "Add Server" (last occurrence)
 *   - Sidebar nav: "Tools", "Resources", "Prompts" buttons
 *
 * Port constraint: MCPJam Inspector ALWAYS runs on port 6274 (hardcoded).
 */

import { test, expect } from "@playwright/test";
import { ChildProcess, spawn, execSync } from "child_process";
import { timeouts } from "../../fixtures/test-data.js";

// MCPJam Inspector port (hardcoded, cannot be changed)
const JAM_INSPECTOR_PORT = 6274;
const JAM_INSPECTOR_URL = `http://localhost:${JAM_INSPECTOR_PORT}`;

// Direct MCP server URL
const MCP_DIRECT_URL = "http://localhost:3100";

let inspectorProcess: ChildProcess | null = null;
let inspectorAvailable = false;

/** Kill any existing processes on the MCPJam inspector port. */
function clearJamInspectorPort() {
  try {
    const pids = execSync(`lsof -ti:${JAM_INSPECTOR_PORT} 2>/dev/null`, {
      encoding: "utf-8",
    }).trim();
    if (pids) {
      execSync(`kill -9 ${pids.split("\n").join(" ")} 2>/dev/null`);
    }
  } catch {
    // no processes on this port — fine
  }
  // Also kill any MCPJam processes by name
  try {
    execSync('pkill -f "@mcpjam/inspector" 2>/dev/null');
  } catch {
    // ignore
  }
}

/** Start the MCPJam Inspector process and wait for it to be ready. */
async function startJamInspector(): Promise<ChildProcess> {
  clearJamInspectorPort();
  await new Promise((r) => setTimeout(r, 1000));

  return new Promise<ChildProcess>((resolve, reject) => {
    const proc = spawn(
      "npx",
      ["@mcpjam/inspector@1.5.17"],
      {
        env: {
          ...process.env,
          NODE_TLS_REJECT_UNAUTHORIZED: "0",
          BROWSER: "none",
        },
        stdio: ["ignore", "pipe", "pipe"],
        detached: false,
      }
    );

    let started = false;
    const timeout = setTimeout(() => {
      if (!started) {
        proc.kill();
        reject(new Error("MCPJam Inspector failed to start within 30s"));
      }
    }, 30000);

    const onData = (data: Buffer) => {
      const output = data.toString();
      // MCPJam prints "Browser opened at http://127.0.0.1:6274" when ready
      if (
        output.includes("Browser opened") ||
        output.includes("6274") ||
        output.includes("listening") ||
        output.includes("ready")
      ) {
        if (!started) {
          started = true;
          clearTimeout(timeout);
          setTimeout(() => resolve(proc), 1000);
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
        reject(
          new Error(`MCPJam Inspector exited with code ${code} before ready`)
        );
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

/** Kill the inspector process and all its children. */
function killJamInspector() {
  if (inspectorProcess) {
    const pid = inspectorProcess.pid;
    inspectorProcess.kill("SIGTERM");
    inspectorProcess = null;
    if (pid) {
      try {
        execSync(`pkill -P ${pid} 2>/dev/null`);
      } catch {
        // ignore
      }
    }
    clearJamInspectorPort();
  }
}

test.describe("MCPJam Inspector UI", () => {
  test.beforeAll(async () => {
    // Check if inspector is already running (e.g. Docker container in CI)
    const alreadyRunning = await waitForUrl(JAM_INSPECTOR_URL, 3000);
    if (alreadyRunning) {
      inspectorAvailable = true;
      return;
    }

    // Not running — spawn locally
    try {
      inspectorProcess = await startJamInspector();
      const ready = await waitForUrl(JAM_INSPECTOR_URL, 15000);
      if (!ready) {
        killJamInspector();
      } else {
        inspectorAvailable = true;
      }
    } catch (e) {
      console.error("Failed to start MCPJam Inspector:", e);
      inspectorProcess = null;
    }
  });

  test.afterAll(async () => {
    killJamInspector();
  });

  test.beforeEach(async () => {
    test.skip(
      !inspectorAvailable,
      "MCPJam Inspector is not available — skipping MCPJam inspector UI tests"
    );
  });

  // -------------------------------------------------------------------------
  // Basic UI
  // -------------------------------------------------------------------------

  test("MCPJam inspector UI should load with Add Server button", async ({
    page,
  }) => {
    await page.goto(JAM_INSPECTOR_URL, { waitUntil: "networkidle" });

    // MCPJam shows "Add Your First Server" or "Add Server" button
    const addServerBtn = page
      .getByRole("button", { name: /add.*server/i })
      .first();
    await expect(addServerBtn).toBeVisible({ timeout: timeouts.medium });

    // Sidebar should have navigation items
    const toolsBtn = page.getByRole("button", { name: "Tools" });
    await expect(toolsBtn).toBeVisible();
  });

  // -------------------------------------------------------------------------
  // HTTP transport (direct to MCP server)
  // -------------------------------------------------------------------------

  test("HTTP transport should discover tools (direct)", async ({ page }) => {
    await page.goto(JAM_INSPECTOR_URL, { waitUntil: "networkidle" });

    // Click "Add Your First Server" or "Add Server"
    const addBtn = page
      .getByRole("button", { name: /add.*first.*server|add server/i })
      .first();
    await addBtn.click();
    await page.waitForTimeout(500);

    // Wait for the "Add MCP Server" dialog
    const dialog = page.locator('[role="dialog"]');
    await expect(dialog).toBeVisible({ timeout: timeouts.medium });

    // Fill server name
    await page.getByPlaceholder("my-mcp-server").fill("test-mcp-server");

    // Connection type should default to "HTTP" — verify
    const connectionSelect = page.locator("select").first();
    const connectionValue = await connectionSelect.inputValue();
    if (connectionValue !== "http") {
      await connectionSelect.selectOption("http");
    }

    // Fill URL
    await page
      .getByPlaceholder("http://localhost:8080/mcp")
      .fill(`${MCP_DIRECT_URL}/mcp`);

    // Auth stays "No Authentication" (default for direct)

    // Click the submit "Add Server" button (inside dialog, not sidebar)
    // The dialog has "Cancel" and "Add Server" — pick the last "Add Server"
    await dialog.getByRole("button", { name: "Add Server" }).click();

    // Wait for connection to establish
    await page.waitForTimeout(3000);

    // Navigate to "Tools" in the sidebar
    await page.getByRole("button", { name: "Tools" }).click();
    await page.waitForTimeout(2000);

    // Verify tools are listed on the page
    const pageContent = await page.textContent("body");
    expect(pageContent).toContain("echo");
    expect(pageContent).toContain("add");
    expect(pageContent).toContain("get_time");
  });
});
