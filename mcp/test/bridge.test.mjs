// Tests for the disasm MCP front-end.
//
// Run with: node --test mcp/test
//
// The interesting part is the seam between the MCP protocol and the
// little protocol Emacs speaks: tool mapping, waiting for the target to
// stop, error reporting and the JSON-RPC framing.  The last test starts
// a fake Emacs listener so that the TCP client is exercised for real.

import test from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import {
  TOOLS,
  EmacsClient,
  PROTOCOL_VERSION,
  VERSION,
  createDispatcher,
  findTool,
  readToken,
  renderResult,
  requestFor,
  sleep,
} from "../disasm-mcp-server.mjs";

/* ------------------------------------------------------------------ *
 * Tool table
 * ------------------------------------------------------------------ */

test("every tool has a name, a description and a schema", () => {
  assert.ok(TOOLS.length >= 15);
  for (const tool of TOOLS) {
    assert.equal(typeof tool.name, "string", `${tool.name}: name`);
    assert.ok(tool.description.length > 20, `${tool.name}: description`);
    assert.equal(tool.inputSchema.type, "object", `${tool.name}: schema type`);
    assert.ok(tool.op === null || typeof tool.op === "string", `${tool.name}: op`);
  }
});

test("tool names are unique", () => {
  const names = TOOLS.map((tool) => tool.name);
  assert.equal(new Set(names).size, names.length);
});

test("findTool looks tools up by name", () => {
  assert.equal(findTool("state").op, "state");
  assert.equal(findTool("nope"), undefined);
});

test("only operations that resume the target wait by default", () => {
  const waiting = TOOLS.filter((tool) => tool.wait).map((tool) => tool.name);
  assert.deepEqual(waiting.sort(), ["attach", "continue", "launch", "step", "wait"]);
});

test("requestFor strips the plumbing arguments", () => {
  const tool = findTool("step");
  const { op, args, wait, timeoutMs } = requestFor(tool, {
    mode: "over",
    session: "42",
    wait: false,
    timeout_ms: 1234,
  });
  assert.equal(op, "step");
  assert.deepEqual(args, { mode: "over", session: "42" });
  assert.equal(wait, false);
  assert.equal(timeoutMs, 1234);
});

test("requestFor tolerates missing arguments", () => {
  const { op, args } = requestFor(findTool("sessions"), undefined);
  assert.equal(op, "sessions");
  assert.deepEqual(args, {});
});

/* ------------------------------------------------------------------ *
 * Rendering
 * ------------------------------------------------------------------ */

test("renderResult shows a listing before the metadata", () => {
  const text = renderResult(findTool("disassemble"), {
    session: "7",
    address_hex: "0x401000",
    instructions: [{ address: 4198400 }],
    text: "  0x401000  55  push rbp",
  });
  assert.ok(text.startsWith("  0x401000  55  push rbp"));
  assert.ok(text.includes("0x401000"));
  assert.ok(!text.includes("instructions"));
});

test("renderResult falls back to pretty JSON", () => {
  const text = renderResult(findTool("state"), { state: "stopped", pc_hex: "0x401000" });
  assert.deepEqual(JSON.parse(text), { state: "stopped", pc_hex: "0x401000" });
});

test("renderResult merges the state snapshot the waiter produced", () => {
  const text = renderResult(findTool("step"), { id: "7" }, { state: "stopped" });
  assert.equal(JSON.parse(text).state, "stopped");
});

/* ------------------------------------------------------------------ *
 * Token handling
 * ------------------------------------------------------------------ */

test("readToken reads the trailing newline away", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "disasm-mcp-"));
  const file = path.join(dir, "token");
  writeFileSync(file, "deadbeef\n");
  assert.equal(readToken(file), "deadbeef");
});

test("readToken returns null when the file is missing", () => {
  assert.equal(readToken(path.join(tmpdir(), "definitely-not-here")), null);
});

/* ------------------------------------------------------------------ *
 * Dispatching
 * ------------------------------------------------------------------ */

function fakeClient(handler) {
  return {
    calls: [],
    async call(op, args) {
      this.calls.push({ op, args });
      return handler(op, args);
    },
    async waitForStop(session, timeoutMs) {
      this.waited = { session, timeoutMs };
      return { state: "stopped", reason: "breakpoint-hit", id: session };
    },
    close() {},
  };
}

test("initialize advertises the tools capability and echoes the version", async () => {
  const handle = createDispatcher(fakeClient(() => ({})));
  const response = await handle({
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: { protocolVersion: "2024-11-05" },
  });
  assert.equal(response.id, 1);
  assert.equal(response.result.protocolVersion, "2024-11-05");
  assert.ok(response.result.capabilities.tools);
  assert.equal(response.result.serverInfo.version, VERSION);
  assert.ok(response.result.instructions.includes("Emacs"));
});

test("initialize falls back to the server's protocol version", async () => {
  const handle = createDispatcher(fakeClient(() => ({})));
  const response = await handle({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
  assert.equal(response.result.protocolVersion, PROTOCOL_VERSION);
});

test("tools/list returns the declarations without the private op field", async () => {
  const handle = createDispatcher(fakeClient(() => ({})));
  const response = await handle({ jsonrpc: "2.0", id: 2, method: "tools/list" });
  const names = response.result.tools.map((tool) => tool.name);
  assert.ok(names.includes("disassemble"));
  for (const tool of response.result.tools) {
    assert.equal("op" in tool, false);
    assert.equal("wait" in tool, false);
  }
});

test("tools/call forwards the operation and returns text content", async () => {
  const client = fakeClient(() => ({ state: "stopped", pc_hex: "0x401000" }));
  const handle = createDispatcher(client);
  const response = await handle({
    jsonrpc: "2.0",
    id: 3,
    method: "tools/call",
    params: { name: "state", arguments: { session: "7" } },
  });
  assert.deepEqual(client.calls, [{ op: "state", args: { session: "7" } }]);
  assert.equal(response.id, 3);
  assert.equal(response.result.content[0].type, "text");
  assert.equal(JSON.parse(response.result.content[0].text).state, "stopped");
  assert.equal(response.result.isError, undefined);
});

test("tools/call reports a failed operation without a JSON-RPC error", async () => {
  const handle = createDispatcher(
    fakeClient(() => {
      throw new Error("The target must be stopped to step");
    }),
  );
  const response = await handle({
    jsonrpc: "2.0",
    id: 4,
    method: "tools/call",
    params: { name: "step", arguments: {} },
  });
  assert.equal(response.error, undefined);
  assert.equal(response.result.isError, true);
  assert.match(response.result.content[0].text, /must be stopped/);
});

test("a resuming tool waits for the stop and reports its reason", async () => {
  const client = fakeClient(() => ({ id: "7", state: "running" }));
  const handle = createDispatcher(client);
  const response = await handle({
    jsonrpc: "2.0",
    id: 5,
    method: "tools/call",
    params: { name: "continue", arguments: {} },
  });
  assert.deepEqual(client.waited, { session: "7", timeoutMs: 30000 });
  const body = JSON.parse(response.result.content[0].text);
  assert.equal(body.state, "stopped");
  assert.equal(body.reason, "breakpoint-hit");
});

test("passing wait:false skips the wait", async () => {
  const client = fakeClient(() => ({ id: "7", state: "running" }));
  const handle = createDispatcher(client);
  await handle({
    jsonrpc: "2.0",
    id: 6,
    method: "tools/call",
    params: { name: "continue", arguments: { wait: false } },
  });
  assert.equal(client.waited, undefined);
});

test("the wait tool polls without sending an operation", async () => {
  const client = fakeClient(() => {
    throw new Error("should not be called");
  });
  const handle = createDispatcher(client);
  const response = await handle({
    jsonrpc: "2.0",
    id: 7,
    method: "tools/call",
    params: { name: "wait", arguments: { session: "9", timeout_ms: 500 } },
  });
  assert.deepEqual(client.calls, []);
  assert.deepEqual(client.waited, { session: "9", timeoutMs: 500 });
  assert.equal(response.result.isError, undefined);
});

test("an operation that is not a tool is refused", async () => {
  const handle = createDispatcher(fakeClient(() => ({})));
  const response = await handle({
    jsonrpc: "2.0",
    id: 8,
    method: "tools/call",
    params: { name: "launch_missiles", arguments: {} },
  });
  assert.equal(response.result.isError, true);
  assert.match(response.result.content[0].text, /unknown tool/);
});

test("an unknown method yields a JSON-RPC error", async () => {
  const handle = createDispatcher(fakeClient(() => ({})));
  const response = await handle({ jsonrpc: "2.0", id: 9, method: "resources/list" });
  assert.equal(response.error.code, -32601);
});

test("a notification is answered with nothing", async () => {
  const handle = createDispatcher(fakeClient(() => ({})));
  assert.equal(await handle({ jsonrpc: "2.0", method: "notifications/initialized" }), null);
  assert.equal(await handle({ jsonrpc: "2.0", method: "notifications/cancelled", params: {} }), null);
  assert.equal(await handle({ jsonrpc: "2.0", method: "whatever" }), null);
});

test("ping keeps the connection alive", async () => {
  const handle = createDispatcher(fakeClient(() => ({})));
  const response = await handle({ jsonrpc: "2.0", id: 10, method: "ping" });
  assert.deepEqual(response.result, {});
});

/* ------------------------------------------------------------------ *
 * The TCP client
 * ------------------------------------------------------------------ */

/** A stand-in for disasm-mcp.el: one JSON object per line, token checked. */
function fakeEmacs(handler) {
  const server = net.createServer((socket) => {
    let buffer = "";
    socket.setEncoding("utf8");
    socket.on("data", (chunk) => {
      buffer += chunk;
      let index;
      while ((index = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, index);
        buffer = buffer.slice(index + 1);
        if (!line.trim()) continue;
        const request = JSON.parse(line);
        if (request.token !== "test-token") {
          socket.write(
            JSON.stringify({ id: request.id, ok: false, error: "bad token", kind: "auth" }) + "\n",
          );
          continue;
        }
        const answer = handler(request);
        if (answer !== undefined) {
          socket.write(JSON.stringify({ id: request.id, ok: true, result: answer }) + "\n");
        }
      }
    });
  });
  return server;
}

async function withFakeEmacs(handler, body) {
  const dir = mkdtempSync(path.join(tmpdir(), "disasm-mcp-"));
  const tokenFile = path.join(dir, "token");
  writeFileSync(tokenFile, "test-token\n");
  const server = fakeEmacs(handler);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const client = new EmacsClient({
    host: "127.0.0.1",
    port: server.address().port,
    tokenFile,
    timeout: 2000,
  });
  try {
    await body(client);
  } finally {
    client.close();
    await new Promise((resolve) => server.close(resolve));
  }
}

test("the client speaks the line protocol and matches answers by id", async () => {
  const seen = [];
  await withFakeEmacs(
    (request) => {
      seen.push(request);
      return { state: "stopped", pid: 42 };
    },
    async (client) => {
      const first = await client.call("state", {});
      assert.deepEqual(first, { state: "stopped", pid: 42 });
      const second = await client.call("sessions", {});
      assert.deepEqual(second, { state: "stopped", pid: 42 });
      assert.deepEqual(
        seen.map((request) => request.op),
        ["state", "sessions"],
      );
      assert.equal(seen[0].token, "test-token");
      assert.equal(seen[0].id, 1);
      assert.equal(seen[1].id, 2);
    },
  );
});

test("the client surfaces a refusal as an error", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "disasm-mcp-"));
  const tokenFile = path.join(dir, "token");
  writeFileSync(tokenFile, "wrong-token\n");
  const server = fakeEmacs(() => ({}));
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const client = new EmacsClient({
    host: "127.0.0.1",
    port: server.address().port,
    tokenFile,
    timeout: 2000,
  });
  try {
    await assert.rejects(() => client.call("state", {}), /bad token/);
  } finally {
    client.close();
    await new Promise((resolve) => server.close(resolve));
  }
});

test("a missing token file explains how to start the listener", async () => {
  const client = new EmacsClient({
    host: "127.0.0.1",
    port: 1,
    tokenFile: path.join(tmpdir(), "no-such-token-file"),
    timeout: 500,
  });
  await assert.rejects(() => client.call("state", {}), /disasm-mcp-start/);
});

test("an unreachable listener explains how to start it", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "disasm-mcp-"));
  const tokenFile = path.join(dir, "token");
  writeFileSync(tokenFile, "test-token\n");
  // Bind and immediately close a port so that nothing is listening there.
  const probe = net.createServer();
  await new Promise((resolve) => probe.listen(0, "127.0.0.1", resolve));
  const port = probe.address().port;
  await new Promise((resolve) => probe.close(resolve));
  const client = new EmacsClient({ host: "127.0.0.1", port, tokenFile, timeout: 1000 });
  await assert.rejects(() => client.call("state", {}), /disasm-mcp-start|ECONNREFUSED/);
});

test("waitForStop polls until the target stops", async () => {
  const states = ["running", "running", "stopped"];
  await withFakeEmacs(
    (request) => {
      assert.equal(request.op, "state");
      return { id: "7", state: states.shift() ?? "stopped", reason: "end-stepping-range" };
    },
    async (client) => {
      const state = await client.waitForStop("7", 2000);
      assert.equal(state.state, "stopped");
      assert.equal(state.reason, "end-stepping-range");
      assert.equal(state.timed_out, undefined);
    },
  );
});

test("waitForStop gives up when the target keeps running", async () => {
  await withFakeEmacs(
    () => ({ state: "running" }),
    async (client) => {
      const state = await client.waitForStop("7", 150);
      assert.equal(state.state, "running");
      assert.equal(state.timed_out, true);
    },
  );
});

test("a stale session id falls back to the default session", async () => {
  const server = net.createServer((socket) => {
    let buffer = "";
    socket.setEncoding("utf8");
    socket.on("data", (chunk) => {
      buffer += chunk;
      let index;
      while ((index = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, index);
        buffer = buffer.slice(index + 1);
        if (!line.trim()) continue;
        const request = JSON.parse(line);
        const answer = request.args.session
          ? { id: request.id, ok: false, error: "No such session: 99", kind: "user-error" }
          : { id: request.id, ok: true, result: { state: "stopped", id: "7" } };
        socket.write(JSON.stringify(answer) + "\n");
      }
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const dir = mkdtempSync(path.join(tmpdir(), "disasm-mcp-"));
  const tokenFile = path.join(dir, "token");
  writeFileSync(tokenFile, "test-token\n");
  const client = new EmacsClient({
    host: "127.0.0.1",
    port: server.address().port,
    tokenFile,
    timeout: 2000,
  });
  try {
    const state = await client.waitForStop("99", 1000);
    assert.equal(state.state, "stopped");
    assert.equal(state.id, "7");
  } finally {
    client.close();
    await new Promise((resolve) => server.close(resolve));
  }
});

test("the client reconnects after the socket goes away", async () => {
  let connections = 0;
  const server = net.createServer((socket) => {
    connections += 1;
    socket.setEncoding("utf8");
    socket.on("data", (chunk) => {
      for (const line of chunk.split("\n")) {
        if (!line.trim()) continue;
        const request = JSON.parse(line);
        socket.write(JSON.stringify({ id: request.id, ok: true, result: { n: connections } }) + "\n");
      }
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const dir = mkdtempSync(path.join(tmpdir(), "disasm-mcp-"));
  const tokenFile = path.join(dir, "token");
  writeFileSync(tokenFile, "test-token\n");
  const client = new EmacsClient({
    host: "127.0.0.1",
    port: server.address().port,
    tokenFile,
    timeout: 2000,
  });
  try {
    assert.deepEqual(await client.call("state", {}), { n: 1 });
    client.socket.destroy();
    client.socket = null;
    await sleep(10);
    assert.deepEqual(await client.call("state", {}), { n: 2 });
    assert.equal(connections, 2);
  } finally {
    client.close();
    await new Promise((resolve) => server.close(resolve));
  }
});
