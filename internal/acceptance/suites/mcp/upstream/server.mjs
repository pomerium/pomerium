// Minimal upstream MCP server used as the protected resource behind Pomerium.
//
// It speaks the MCP "Streamable HTTP" transport on POST /mcp and exposes three
// trivial tools:
//   - add   (a, b)        -> text sum
//   - echo  (message)     -> text echo
//   - stats (numbers[])   -> structured output (outputSchema) with sum/count/mean
// It performs NO authentication of its own — Pomerium sits in front and enforces
// the OAuth 2.1 / policy layer. The server runs in stateless mode (a fresh
// McpServer + transport per request), the simplest correct configuration for a
// request/response tool server.
//
// This file is mounted into a node container as a volume (see setup/containers.ts).

import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

const PORT = Number(process.env.PORT || 8080);

/** Build a fresh MCP server instance with the test tools registered. */
function buildServer() {
  const server = new McpServer({
    name: "pomerium-mcp-e2e-upstream",
    version: "1.0.0",
  });

  server.registerTool(
    "add",
    {
      title: "Add",
      description: "Add two numbers and return the sum.",
      inputSchema: { a: z.number(), b: z.number() },
    },
    async ({ a, b }) => ({
      content: [{ type: "text", text: String(a + b) }],
    }),
  );

  server.registerTool(
    "echo",
    {
      title: "Echo",
      description: "Echo back the provided message.",
      inputSchema: { message: z.string() },
    },
    async ({ message }) => ({
      content: [{ type: "text", text: message }],
    }),
  );

  // Structured output: declares an outputSchema and returns structuredContent
  // (MCP 2025-11-25 typed tool results).
  server.registerTool(
    "stats",
    {
      title: "Stats",
      description: "Return sum, count and mean of a list of numbers.",
      inputSchema: { numbers: z.array(z.number()).min(1) },
      outputSchema: { sum: z.number(), count: z.number(), mean: z.number() },
    },
    async ({ numbers }) => {
      const sum = numbers.reduce((a, b) => a + b, 0);
      const count = numbers.length;
      const structured = { sum, count, mean: sum / count };
      return {
        content: [{ type: "text", text: JSON.stringify(structured) }],
        structuredContent: structured,
      };
    },
  );

  return server;
}

function methodNotAllowed(_req, res) {
  res.status(405).json({
    jsonrpc: "2.0",
    error: { code: -32000, message: "Method not allowed (stateless server)." },
    id: null,
  });
}

const app = express();
app.use(express.json());

// Plain health endpoint (handy for manual debugging; the container readiness
// wait keys off the "listening" log line below).
app.get("/healthz", (_req, res) => res.status(200).send("ok"));

app.post("/mcp", async (req, res) => {
  // Stateless: create per-request instances so concurrent requests cannot
  // collide on JSON-RPC ids or shared transport state.
  const server = buildServer();
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on("close", () => {
    transport.close();
    server.close();
  });
  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (err) {
    console.error("MCP request handling failed:", err);
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: "2.0",
        error: { code: -32603, message: "Internal server error" },
        id: null,
      });
    }
  }
});

// Streamable HTTP GET (server->client SSE) and DELETE (session teardown) are
// not used in stateless mode.
app.get("/mcp", methodNotAllowed);
app.delete("/mcp", methodNotAllowed);

app.listen(PORT, () => {
  console.log(`upstream MCP server listening on :${PORT} (POST /mcp)`);
});
