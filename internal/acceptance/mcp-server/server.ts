/**
 * Minimal MCP test server for E2E acceptance tests.
 *
 * Supports both SSE and Streamable HTTP transports.
 * Implements a few simple tools for testing:
 *   - echo: returns the input message
 *   - add: adds two numbers
 *   - get_time: returns current server time
 *
 * Also exposes a /health endpoint for Docker health checks.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import express from "express";
import { z } from "zod";

const PORT = parseInt(process.env.PORT || "3000", 10);

function createMcpServer(): McpServer {
  const server = new McpServer({
    name: "pomerium-test-server",
    version: "1.0.0",
  });

  server.tool(
    "echo",
    "Echoes back the provided message",
    { message: z.string().describe("Message to echo") },
    async ({ message }) => ({
      content: [{ type: "text", text: `Echo: ${message}` }],
    })
  );

  server.tool(
    "add",
    "Adds two numbers together",
    {
      a: z.number().describe("First number"),
      b: z.number().describe("Second number"),
    },
    async ({ a, b }) => ({
      content: [{ type: "text", text: `${a + b}` }],
    })
  );

  server.tool(
    "get_time",
    "Returns the current server time",
    async () => ({
      content: [{ type: "text", text: new Date().toISOString() }],
    })
  );

  server.resource(
    "server-info",
    "info://server",
    async () => ({
      contents: [{
        uri: "info://server",
        text: JSON.stringify({
          name: "pomerium-test-server",
          version: "1.0.0",
          transports: ["sse", "streamable-http"],
        }),
      }],
    })
  );

  return server;
}

const app = express();
app.use(express.json());

// Health check endpoint
app.get("/health", (_req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// --- SSE Transport ---
const sseTransports = new Map<string, SSEServerTransport>();

app.get("/sse", async (req, res) => {
  console.log("[SSE] New connection");
  const transport = new SSEServerTransport("/messages", res);
  const sessionId = transport.sessionId;
  sseTransports.set(sessionId, transport);

  res.on("close", () => {
    console.log(`[SSE] Connection closed: ${sessionId}`);
    sseTransports.delete(sessionId);
  });

  const server = createMcpServer();
  await server.connect(transport);
});

app.post("/messages", async (req, res) => {
  const sessionId = req.query.sessionId as string;
  const transport = sseTransports.get(sessionId);
  if (!transport) {
    res.status(400).json({ error: "Unknown session" });
    return;
  }
  await transport.handlePostMessage(req, res, req.body);
});

// --- Streamable HTTP Transport ---
app.post("/mcp", async (req, res) => {
  console.log("[HTTP] Streamable HTTP request");
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
  });
  const server = createMcpServer();

  res.on("close", () => {
    transport.close();
    server.close();
  });

  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

app.get("/mcp", async (req, res) => {
  console.log("[HTTP] Streamable HTTP GET (SSE stream)");
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
  });
  const server = createMcpServer();

  res.on("close", () => {
    transport.close();
    server.close();
  });

  await server.connect(transport);
  await transport.handleRequest(req, res);
});

app.delete("/mcp", async (_req, res) => {
  res.status(200).json({ status: "terminated" });
});

app.listen(PORT, () => {
  console.log(`MCP test server listening on port ${PORT}`);
  console.log(`  SSE transport:          GET  /sse`);
  console.log(`  SSE messages:           POST /messages`);
  console.log(`  Streamable HTTP:        POST /mcp`);
  console.log(`  Health:                 GET  /health`);
});
