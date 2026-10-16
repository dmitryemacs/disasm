#!/usr/bin/env node
// disasm-mcp-server.mjs --- MCP front-end for the disasm Emacs debugger.
//
// This is a dependency-free Model Context Protocol server that speaks
// stdio JSON-RPC to the agent host and a tiny line-delimited JSON
// protocol over TCP to Emacs (see disasm-mcp.el).  Every tool call is
// forwarded to a running Emacs, where it drives the very same commands
// the user has on F5/F10/F11 and friends, so the debugger's panes, the
// listing and the hex view update as the agent works.
//
// Environment:
//   DISASM_MCP_HOST        TCP host of the Emacs listener (127.0.0.1)
//   DISASM_MCP_PORT        TCP port of the Emacs listener (37373)
//   DISASM_MCP_TOKEN_FILE  file holding the access token
//   DISASM_MCP_TIMEOUT     timeout for one Emacs request, ms (15000)
//   DISASM_MCP_WAIT        default wait-for-stop timeout, ms (30000)

import { readFileSync } from "node:fs";
import { createInterface } from "node:readline";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

export const VERSION = "0.1.0";
export const PROTOCOL_VERSION = "2025-06-18";

const TERMINAL_STATES = new Set(["stopped", "exited", "error", "detached"]);

/* ------------------------------------------------------------------ *
 * Tool declarations
 * ------------------------------------------------------------------ */

const SESSION = {
  type: "string",
  description:
    "Debug session id (the process id) as reported by the sessions tool. " +
    "Omit it to use the session the user is looking at.",
};

const WAIT = {
  type: "boolean",
  description:
    "Wait for the target to stop before answering (default true for " +
    "operations that resume it).",
};

const TIMEOUT_MS = {
  type: "integer",
  description: "How long to wait for the target to stop, in milliseconds.",
};

export const TOOLS = [
  {
    name: "sessions",
    op: "sessions",
    description:
      "List the debugging sessions currently open in Emacs. Call this " +
      "first to find out whether anything is being debugged and which " +
      "ids can be passed to the other tools.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "state",
    op: "state",
    description:
      "Report the execution state of the target: whether it is stopped " +
      "or running, why it stopped (reason, hit breakpoint), the program " +
      "counter, the selected thread and frame. Use `include` to add " +
      "sections: registers, flags, threads, frames, modules, breakpoints.",
    inputSchema: {
      type: "object",
      properties: {
        session: SESSION,
        include: {
          type: "array",
          items: {
            type: "string",
            enum: [
              "registers",
              "flags",
              "threads",
              "frames",
              "modules",
              "breakpoints",
            ],
          },
          description: "Extra sections to include in the answer.",
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "disassemble",
    op: "disassemble",
    description:
      "Disassemble instructions starting at an address. Instructions are " +
      "read from the file that backs the address when possible and from " +
      "live memory otherwise (the target must then be stopped). Returns " +
      "one entry per instruction with address, raw bytes, mnemonic and " +
      "operands, plus a ready-to-read listing in `text`.",
    inputSchema: {
      type: "object",
      properties: {
        address: {
          type: "string",
          description: "Live address to start at, e.g. \"0x401000\".",
        },
        count: {
          type: "integer",
          description: "How many instructions to return (default 16).",
        },
        session: SESSION,
      },
      required: ["address"],
      additionalProperties: false,
    },
  },
  {
    name: "read_memory",
    op: "read_memory",
    description:
      "Read target memory. Returns the bytes as hex, as ASCII, and as " +
      "unsigned integers of the requested width. The target must be " +
      "stopped.",
    inputSchema: {
      type: "object",
      properties: {
        address: {
          type: "string",
          description: "Live address to read from, e.g. \"0x401000\".",
        },
        length: {
          type: "integer",
          description: "How many bytes to read (default 16, max 4096).",
        },
        format: {
          type: "string",
          enum: ["hex", "ascii", "u8", "u16", "u32", "u64", "int"],
          description: "How to interpret the bytes (default hex).",
        },
        session: SESSION,
      },
      required: ["address"],
      additionalProperties: false,
    },
  },
  {
    name: "write_memory",
    op: "write_memory",
    description:
      "Overwrite target memory. `bytes` is a hex string, with or " +
      "without separators (\"90 90 c3\" or \"9090c3\"). The target must " +
      "be stopped.",
    inputSchema: {
      type: "object",
      properties: {
        address: {
          type: "string",
          description: "Live address to write to, e.g. \"0x401000\".",
        },
        bytes: {
          type: "string",
          description: "Bytes to write, as hexadecimal.",
        },
        session: SESSION,
      },
      required: ["address", "bytes"],
      additionalProperties: false,
    },
  },
  {
    name: "set_register",
    op: "set_register",
    description:
      "Set a register of the target, for example name \"rip\", value " +
      "\"0x401000\". The target must be stopped.",
    inputSchema: {
      type: "object",
      properties: {
        name: { type: "string", description: "Register name, e.g. \"rax\"." },
        value: {
          type: "string",
          description: "New value, hexadecimal by default (\"0d42\" for decimal).",
        },
        session: SESSION,
      },
      required: ["name", "value"],
      additionalProperties: false,
    },
  },
  {
    name: "goto",
    op: "goto",
    description:
      "Show an address in the user's listing and hex panes. Use this to " +
      "point the human at what you are looking at.",
    inputSchema: {
      type: "object",
      properties: {
        address: { type: "string", description: "Live address to show." },
        session: SESSION,
      },
      required: ["address"],
      additionalProperties: false,
    },
  },
  {
    name: "select_thread",
    op: "select_thread",
    description:
      "Make a thread the current one; the listing follows its program " +
      "counter. The target must be stopped.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string", description: "Thread id from the state tool." },
        session: SESSION,
      },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "select_frame",
    op: "select_frame",
    description:
      "Select a stack frame; the listing follows its program counter. " +
      "The target must be stopped.",
    inputSchema: {
      type: "object",
      properties: {
        level: {
          type: "integer",
          description: "Frame level from the state tool (0 is innermost).",
        },
        session: SESSION,
      },
      required: ["level"],
      additionalProperties: false,
    },
  },
  {
    name: "breakpoint",
    op: "breakpoint",
    description:
      "Manage breakpoints: action \"set\" with an address, \"delete\" " +
      "with a number or an address, \"clear\" for all of them, or " +
      "\"list\". The target must be stopped for everything but \"list\".",
    inputSchema: {
      type: "object",
      properties: {
        action: {
          type: "string",
          enum: ["set", "delete", "clear", "list"],
        },
        address: { type: "string", description: "Live address (set/delete)." },
        number: { type: "integer", description: "Breakpoint number (delete)." },
        session: SESSION,
      },
      required: ["action"],
      additionalProperties: false,
    },
  },
  {
    name: "step",
    op: "step",
    wait: true,
    description:
      "Step the target: mode \"in\" (one instruction, follows calls), " +
      "\"over\" (one instruction, skips calls) or \"out\" (run until the " +
      "current function returns).",
    inputSchema: {
      type: "object",
      properties: {
        mode: { type: "string", enum: ["in", "over", "out"] },
        session: SESSION,
        wait: WAIT,
        timeout_ms: TIMEOUT_MS,
      },
      additionalProperties: false,
    },
  },
  {
    name: "continue",
    op: "continue",
    wait: true,
    description:
      "Resume the target. By default it waits until the target stops " +
      "again (breakpoint, exit or interrupt) and reports why.",
    inputSchema: {
      type: "object",
      properties: {
        session: SESSION,
        wait: WAIT,
        timeout_ms: TIMEOUT_MS,
      },
      additionalProperties: false,
    },
  },
  {
    name: "interrupt",
    op: "interrupt",
    description:
      "Interrupt a running target so that it stops. Note that the stop " +
      "arrives asynchronously; use the wait tool afterwards if you need " +
      "to be sure it happened.",
    inputSchema: {
      type: "object",
      properties: { session: SESSION },
      additionalProperties: false,
    },
  },
  {
    name: "attach",
    op: "attach",
    wait: true,
    description:
      "Attach the debugger to a running process. Use the sessions tool " +
      "to see whether you are already attached to it.",
    inputSchema: {
      type: "object",
      properties: {
        pid: { type: "integer", description: "Process id to attach to." },
        name: {
          type: "string",
          description: "Image name, used to label the session.",
        },
        wait: WAIT,
        timeout_ms: TIMEOUT_MS,
      },
      required: ["pid"],
      additionalProperties: false,
    },
  },
  {
    name: "launch",
    op: "launch",
    wait: true,
    description:
      "Start a program under the debugger and stop at the beginning of " +
      "its main function. The working directory is the one the image " +
      "lives in.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Absolute path to the image." },
        arguments: {
          type: "string",
          description: "Command line arguments for the program.",
        },
        wait: WAIT,
        timeout_ms: TIMEOUT_MS,
      },
      required: ["path"],
      additionalProperties: false,
    },
  },
  {
    name: "detach",
    op: "detach",
    description:
      "Detach the debugger and let the target run on; the session is " +
      "closed.",
    inputSchema: {
      type: "object",
      properties: { session: SESSION },
      additionalProperties: false,
    },
  },
  {
    name: "open_file",
    op: "open_file",
    description:
      "Open a static disassembly listing for a file on disk, without " +
      "starting or attaching to anything. Useful to look around before " +
      "debugging.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Path to the binary." },
      },
      required: ["path"],
      additionalProperties: false,
    },
  },
  {
    name: "wait",
    op: null,
    wait: true,
    description:
      "Block until the target is stopped (for example after an " +
      "interrupt) and report its state.",
    inputSchema: {
      type: "object",
      properties: { session: SESSION, timeout_ms: TIMEOUT_MS },
      additionalProperties: false,
    },
  },
];

export function findTool(name) {
  return TOOLS.find((tool) => tool.name === name);
}

/* ------------------------------------------------------------------ *
 * Talking to Emacs
 * ------------------------------------------------------------------ */

export function defaultTokenFile() {
  if (process.env.DISASM_MCP_TOKEN_FILE) return process.env.DISASM_MCP_TOKEN_FILE;
  return path.join(os.homedir(), ".emacs.d", "disasm-mcp-token");
}

export function readToken(file = defaultTokenFile()) {
  try {
    return readFileSync(file, "utf8").trim();
  } catch {
    return null;
  }
}

/** The login error an agent sees when Emacs is not listening. */
export function connectionHint() {
  const port = process.env.DISASM_MCP_PORT || "37373";
  return (
    `Cannot reach the disasm debugger in Emacs on 127.0.0.1:${port}. ` +
    `Start it with M-x disasm-mcp-start inside Emacs (it is started ` +
    `automatically when the disasm package loads) and make sure ` +
    `${defaultTokenFile()} is readable.`
  );
}

/**
 * A line-delimited JSON client for the Emacs listener.
 *
 * Requests are sent one at a time and matched to their answers by id,
 * which is all the protocol needs because Emacs serialises them too.
 */
export class EmacsClient {
  constructor(options = {}) {
    this.host = options.host ?? process.env.DISASM_MCP_HOST ?? "127.0.0.1";
    this.port = Number(options.port ?? process.env.DISASM_MCP_PORT ?? 37373);
    this.tokenFile = options.tokenFile ?? defaultTokenFile();
    this.timeout = Number(options.timeout ?? process.env.DISASM_MCP_TIMEOUT ?? 15000);
    this.socket = null;
    this.buffer = "";
    this.nextId = 1;
    this.pending = new Map();
  }

  connected() {
    return this.socket !== null && !this.socket.destroyed;
  }

  async connect() {
    if (this.connected()) return;
    const token = readToken(this.tokenFile);
    if (token === null) throw new Error(connectionHint());
    this.token = token;
    this.buffer = "";
    this.socket = await new Promise((resolve, reject) => {
      const socket = net.connect({ host: this.host, port: this.port });
      const fail = (error) => {
        socket.destroy();
        reject(new Error(`${connectionHint()} (${error.message})`));
      };
      socket.once("error", fail);
      socket.once("connect", () => {
        socket.off("error", fail);
        socket.setNoDelay(true);
        resolve(socket);
      });
    });
    this.socket.setEncoding("utf8");
    this.socket.on("data", (chunk) => this.onData(chunk));
    this.socket.on("error", () => this.failAll(new Error(connectionHint())));
    this.socket.on("close", () => {
      this.socket = null;
      this.failAll(new Error(connectionHint()));
    });
  }

  onData(chunk) {
    this.buffer += chunk;
    let index;
    while ((index = this.buffer.indexOf("\n")) >= 0) {
      const line = this.buffer.slice(0, index).replace(/\r$/, "");
      this.buffer = this.buffer.slice(index + 1);
      if (!line.trim()) continue;
      let message;
      try {
        message = JSON.parse(line);
      } catch {
        continue;
      }
      const entry = this.pending.get(message.id);
      if (!entry) continue;
      this.pending.delete(message.id);
      clearTimeout(entry.timer);
      if (message.ok) entry.resolve(message.result ?? {});
      else {
        const error = new Error(message.error || "the debugger refused the request");
        error.kind = message.kind;
        entry.reject(error);
      }
    }
  }

  failAll(error) {
    for (const [, entry] of this.pending) {
      clearTimeout(entry.timer);
      entry.reject(error);
    }
    this.pending.clear();
  }

  /** Send one operation and wait for its answer. */
  async call(op, args = {}) {
    await this.connect();
    const id = this.nextId++;
    const request = { id, token: this.token, op, args: args ?? {} };
    return await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`the disasm debugger did not answer ${op} in time`));
      }, this.timeout);
      this.pending.set(id, { resolve, reject, timer });
      this.socket.write(JSON.stringify(request) + "\n", (error) => {
        if (error && this.pending.has(id)) {
          this.pending.delete(id);
          clearTimeout(timer);
          reject(new Error(connectionHint()));
        }
      });
    });
  }

  /** Poll `state` until the target stops or the timeout elapses. */
  async waitForStop(sessionId, timeoutMs) {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      let state;
      try {
        state = await this.call("state", sessionId ? { session: sessionId } : {});
      } catch (error) {
        if (sessionId && /no such session/i.test(error.message)) {
          state = await this.call("state", {});
        } else {
          throw error;
        }
      }
      if (TERMINAL_STATES.has(state.state)) return state;
      if (Date.now() >= deadline) return { ...state, timed_out: true };
      await sleep(60);
    }
  }

  close() {
    if (this.socket) {
      this.socket.removeAllListeners("close");
      this.socket.destroy();
      this.socket = null;
    }
    this.failAll(new Error("closing"));
  }
}

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/* ------------------------------------------------------------------ *
 * Tool calls
 * ------------------------------------------------------------------ */

/** Split the request/response plumbing from the tool's own arguments. */
export function requestFor(tool, args) {
  const { wait, timeout_ms: timeoutMs, ...rest } = args ?? {};
  return { op: tool.op, args: rest, wait, timeoutMs };
}

/** Render a successful result as the text the agent reads. */
export function renderResult(tool, result, extra = {}) {
  if (result && typeof result.text === "string" && result.text.trim()) {
    const meta = { ...result };
    delete meta.text;
    delete meta.instructions;
    return result.text + "\n\n" + JSON.stringify({ ...meta, ...extra }, null, 2);
  }
  return JSON.stringify({ ...result, ...extra }, null, 2);
}

/**
 * Build the JSON-RPC message handler.
 *
 * `client` only needs `call`, `waitForStop` and `close`, so the tests
 * can pass a stand-in.
 */
export function createDispatcher(client, options = {}) {
  const defaultWait = Number(options.defaultWait ?? process.env.DISASM_MCP_WAIT ?? 30000);
  const log = options.log ?? (() => {});

  async function callTool(name, args) {
    const tool = findTool(name);
    if (!tool) throw new Error(`unknown tool: ${name}`);
    const { op, args: forwarded, wait, timeoutMs } = requestFor(tool, args);
    const result = op ? await client.call(op, forwarded) : {};
    const shouldWait = tool.wait ? wait !== false : wait === true;
    if (!shouldWait) return { result };
    const session =
      result && typeof result === "object" && result.id !== undefined
        ? result.id
        : forwarded.session;
    const state = await client.waitForStop(session, Number(timeoutMs) || defaultWait);
    return { result, state };
  }

  return async function handle(message) {
    const { id, method, params } = message ?? {};
    const isRequest = id !== undefined && id !== null;
    const reply = (result) => (isRequest ? { jsonrpc: "2.0", id, result } : null);
    const fail = (code, text, data) =>
      isRequest
        ? { jsonrpc: "2.0", id, error: { code, message: text, data } }
        : null;

    try {
      switch (method) {
        case "initialize":
          return reply({
            protocolVersion: params?.protocolVersion ?? PROTOCOL_VERSION,
            capabilities: { tools: { listChanged: false } },
            serverInfo: { name: "disasm", title: "disasm debugger", version: VERSION },
            instructions:
              "Drives the disasm debugger running inside the user's Emacs. " +
              "Everything you do is visible there live: the listing, the " +
              "register panes and the log buffer. Start with the sessions " +
              "tool, then state to see where the target is stopped, then " +
              "disassemble/read_memory to look around and breakpoint/step/" +
              "continue to run it. Addresses are hexadecimal strings.",
          });
        case "notifications/initialized":
        case "notifications/cancelled":
        case "notifications/roots/list_changed":
          return null;
        case "ping":
          return reply({});
        case "tools/list":
          return reply({
            tools: TOOLS.map(({ name, description, inputSchema }) => ({
              name,
              description,
              inputSchema,
            })),
          });
        case "tools/call": {
          const name = params?.name;
          const args = params?.arguments ?? {};
          log(`tool ${name} ${JSON.stringify(args)}`);
          try {
            const { result, state } = await callTool(name, args);
            const extra = state ? { state: state.state, reason: state.reason ?? "" } : {};
            return reply({
              content: [{ type: "text", text: renderResult(findTool(name), result, extra) }],
              structuredContent: state ? { ...result, state_snapshot: state } : result,
            });
          } catch (error) {
            return reply({
              content: [{ type: "text", text: `Error: ${error.message}` }],
              isError: true,
            });
          }
        }
        default:
          return fail(-32601, `method not found: ${method}`);
      }
    } catch (error) {
      return fail(-32603, error.message);
    }
  };
}

/* ------------------------------------------------------------------ *
 * stdio plumbing
 * ------------------------------------------------------------------ */

export function serveStdio(client = new EmacsClient()) {
  const handle = createDispatcher(client, {
    log: (text) => process.stderr.write(`disasm-mcp: ${text}\n`),
  });
  const lines = createInterface({ input: process.stdin, terminal: false });
  const write = (message) => {
    if (!message) return;
    process.stdout.write(JSON.stringify(message) + "\n");
  };
  let queue = Promise.resolve();
  lines.on("line", (line) => {
    if (!line.trim()) return;
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      write({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse error" } });
      return;
    }
    queue = queue
      .then(() => handle(message))
      .then(write)
      .catch((error) => {
        write({
          jsonrpc: "2.0",
          id: message.id ?? null,
          error: { code: -32603, message: error.message },
        });
      });
  });
  lines.on("close", () => {
    client.close();
    process.exit(0);
  });
}

const isMain =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) serveStdio();
