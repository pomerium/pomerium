import assert from "node:assert/strict";
import { test } from "node:test";

import {
  canRefresh,
  findServerStatus,
  refreshTokenCaption,
} from "../src/util/mcpRouteStatus.ts";

test("matches a server whose URL includes the configured MCP server path", () => {
  const server = { url: "https://mcp.example.com/mcp", connected: false };
  assert.equal(findServerStatus([server], "https://mcp.example.com"), server);
});

test("matches regardless of port, like the server's host lookup", () => {
  const server = { url: "https://mcp.example.com:8443/api", connected: true };
  assert.equal(findServerStatus([server], "https://mcp.example.com"), server);
});

test("picks the server for the route's host among several", () => {
  const other = { url: "https://other.example.com", connected: true };
  const mine = { url: "https://mcp.example.com/mcp", connected: false };
  assert.equal(
    findServerStatus([other, mine], "https://mcp.example.com"),
    mine,
  );
});

test("returns undefined when no server matches or input is unusable", () => {
  const server = { url: "https://other.example.com", connected: true };
  assert.equal(
    findServerStatus([server], "https://mcp.example.com"),
    undefined,
  );
  assert.equal(
    findServerStatus(undefined, "https://mcp.example.com"),
    undefined,
  );
  assert.equal(
    findServerStatus([{ url: "not a url" }], "not a url"),
    undefined,
  );
});

test("offers refresh only with a refresh token", () => {
  assert.equal(canRefresh({ url: "", refresh_token_available: true }), true);
  assert.equal(canRefresh({ url: "", refresh_token_available: false }), false);
});

test("flags a missing refresh token as an error", () => {
  assert.deepEqual(
    refreshTokenCaption({
      url: "",
      connected: true,
      refresh_token_available: false,
    }),
    { text: "Refresh token: not available", color: "error" },
  );
  assert.deepEqual(
    refreshTokenCaption({
      url: "",
      connected: true,
      refresh_token_available: true,
    }),
    { text: "Refresh token: available", color: "textSecondary" },
  );
});
