/**
 * Simple WebSocket echo server for E2E acceptance tests.
 * Echoes back any message received.
 * Also handles CORS preflight requests for testing cors_allow_preflight.
 */

const http = require("http");
const { WebSocketServer } = require("ws");

const PORT = process.env.PORT || 8080;

/**
 * Standard CORS headers for testing.
 */
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Custom-Header, X-Pomerium-Jwt-Assertion",
  "Access-Control-Allow-Credentials": "true",
  "Access-Control-Max-Age": "86400",
  "Access-Control-Expose-Headers": "X-Pomerium-Jwt-Assertion",
};

/**
 * Add CORS headers to response.
 */
function addCorsHeaders(res, origin) {
  // If a specific origin is provided, use it; otherwise use wildcard
  if (origin && origin !== "null") {
    res.setHeader("Access-Control-Allow-Origin", origin);
  } else {
    res.setHeader("Access-Control-Allow-Origin", "*");
  }
  res.setHeader("Access-Control-Allow-Methods", corsHeaders["Access-Control-Allow-Methods"]);
  res.setHeader("Access-Control-Allow-Headers", corsHeaders["Access-Control-Allow-Headers"]);
  res.setHeader("Access-Control-Allow-Credentials", corsHeaders["Access-Control-Allow-Credentials"]);
  res.setHeader("Access-Control-Max-Age", corsHeaders["Access-Control-Max-Age"]);
  res.setHeader("Access-Control-Expose-Headers", corsHeaders["Access-Control-Expose-Headers"]);
}

// Create HTTP server for health checks and CORS testing
const server = http.createServer((req, res) => {
  const origin = req.headers["origin"];

  // Handle CORS preflight (OPTIONS)
  if (req.method === "OPTIONS") {
    addCorsHeaders(res, origin);
    res.writeHead(204);
    res.end();
    return;
  }

  // Health check endpoints
  if (req.url === "/health" || req.url === "/") {
    addCorsHeaders(res, origin);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "ok", service: "websocket-server" }));
    return;
  }

  // CORS test endpoint - echoes back request info
  if (req.url && req.url.startsWith("/cors")) {
    addCorsHeaders(res, origin);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      path: req.url,
      method: req.method,
      origin: origin,
      headers: req.headers,
    }));
    return;
  }

  res.writeHead(404);
  res.end();
});

// Create WebSocket server
const wss = new WebSocketServer({ server });

wss.on("connection", (ws, req) => {
  console.log(`New WebSocket connection from ${req.socket.remoteAddress}`);
  console.log(`Headers:`, JSON.stringify(req.headers, null, 2));

  // Send a welcome message
  ws.send(
    JSON.stringify({
      type: "connected",
      message: "WebSocket connection established",
      host: req.headers.host || "",
    })
  );

  ws.on("message", (data, isBinary) => {
    const message = isBinary ? data : data.toString();
    console.log(`Received: ${message}`);

    // Echo the message back
    if (isBinary) {
      ws.send(data);
    } else {
      try {
        const parsed = JSON.parse(message);
        ws.send(JSON.stringify({ type: "echo", data: parsed }));
      } catch {
        ws.send(JSON.stringify({ type: "echo", data: message }));
      }
    }
  });

  ws.on("close", (code, reason) => {
    console.log(`WebSocket closed: code=${code}, reason=${reason}`);
  });

  ws.on("error", (err) => {
    console.error("WebSocket error:", err);
  });
});

server.listen(PORT, () => {
  console.log(`WebSocket server listening on port ${PORT}`);
});
