#!/usr/bin/env node

const BRIDGE_URL = process.env.CODEX_BRIDGE_URL ?? "ws://127.0.0.1:4747";
const TIMEOUT_MS = Number(process.env.CODEX_BRIDGE_PROBE_TIMEOUT_MS ?? "8000");

function initializeRequest() {
  return {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      clientInfo: {
        name: "codex-bridge-local-probe",
        title: "Codex Bridge Local Probe",
        version: "0.1.0",
      },
      capabilities: {
        experimentalApi: true,
        requestAttestation: false,
        optOutNotificationMethods: [],
      },
    },
  };
}

function summarize(message) {
  if (!message || typeof message !== "object" || Array.isArray(message)) {
    return { kind: typeof message };
  }
  return {
    jsonrpc: message.jsonrpc ?? null,
    id: message.id ?? null,
    method: message.method ?? null,
    hasResult: Object.hasOwn(message, "result"),
    hasError: Object.hasOwn(message, "error"),
    paramsKeys: message.params && typeof message.params === "object"
      ? Object.keys(message.params).sort()
      : null,
    notificationError: message.params?.error && typeof message.params.error === "object"
      ? {
          type: message.params.error.type ?? null,
          code: message.params.error.code ?? null,
          message: typeof message.params.error.message === "string"
            ? message.params.error.message.replace(/(?:\/[^\s:]+)+/gu, "<path>")
            : null,
        }
      : null,
    resultKeys: message.result && typeof message.result === "object"
      ? Object.keys(message.result).sort()
      : null,
  };
}

const events = [];
const ws = new WebSocket(BRIDGE_URL);
let settled = false;

function finish(ok, extra = {}) {
  if (settled) {
    return;
  }
  settled = true;
  try {
    ws.close();
  } catch {
    // ignored
  }
  console.log(JSON.stringify({
    ok,
    bridgeUrl: BRIDGE_URL,
    events,
    ...extra,
  }, null, 2));
  process.exitCode = ok ? 0 : 1;
}

const timeout = setTimeout(() => {
  finish(false, { error: "Timed out waiting for initialize response." });
}, TIMEOUT_MS);

ws.addEventListener("open", () => {
  events.push({ event: "open" });
  ws.send(JSON.stringify(initializeRequest()));
});

ws.addEventListener("message", (event) => {
  let parsed = null;
  try {
    parsed = JSON.parse(String(event.data));
  } catch {
    parsed = null;
  }
  const summary = summarize(parsed);
  events.push({ event: "message", summary });
  if (parsed?.id === 1 && Object.hasOwn(parsed, "result")) {
    clearTimeout(timeout);
    finish(true, { initializeResponse: summary });
  }
});

ws.addEventListener("error", () => {
  clearTimeout(timeout);
  finish(false, { error: "WebSocket error." });
});

ws.addEventListener("close", (event) => {
  if (!settled) {
    clearTimeout(timeout);
    finish(false, { error: "WebSocket closed before initialize response.", close: { code: event.code, reason: event.reason } });
  }
});
