#!/usr/bin/env node

import crypto from "node:crypto";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import tls from "node:tls";
import { spawn } from "node:child_process";
import { Buffer } from "node:buffer";
import {
  deviceIdentityHash,
  loadOrCreateSoftwareDeviceKey,
  signDeviceKeyPayload,
} from "./lib/device-key.mjs";
import {
  DEFAULT_ENROLLMENT_PATH,
  readEnrollment,
} from "./lib/enrollment-store.mjs";

const CODEX_BIN = process.env.CODEX_BIN ?? "codex";
const CODEX_ARGS = (process.env.CODEX_APP_SERVER_ARGS ?? "app-server --stdio")
  .split(/\s+/u)
  .filter(Boolean);
const BASE_URL = process.env.CHATGPT_BASE_URL ?? "https://chatgpt.com/backend-api";
const ACCOUNT_ID = process.env.CHATGPT_ACCOUNT_ID;
const ORIGINATOR = process.env.CODEX_ORIGINATOR ?? "Codex Desktop";
const USER_AGENT = process.env.CODEX_WS_USER_AGENT ?? "Codex Desktop/26.519.81530 (Linux; arm64)";
const TIMEOUT_MS = Number(process.env.CODEX_TIMEOUT_MS ?? "5000");
const LISTEN_HOST = process.env.CODEX_BRIDGE_LISTEN_HOST ?? "127.0.0.1";
const LISTEN_PORT = Number(process.env.CODEX_BRIDGE_LISTEN_PORT ?? "4747");
const TARGET_ENV_ID = process.env.CODEX_REMOTE_ENV_ID;
const TARGET_ENV_NAME = process.env.CODEX_REMOTE_ENV_NAME;
const STREAM_PING_MS = Number(process.env.CODEX_BRIDGE_STREAM_PING_MS ?? "30000");
const REMOTE_RECONNECT_INITIAL_MS = Number(process.env.CODEX_BRIDGE_RECONNECT_INITIAL_MS ?? "1000");
const REMOTE_RECONNECT_MAX_MS = Number(process.env.CODEX_BRIDGE_RECONNECT_MAX_MS ?? "30000");
const SESSION_REFRESH_SKEW_SECONDS = Number(process.env.CODEX_BRIDGE_SESSION_REFRESH_SKEW_SECONDS ?? "60");
const DEVICE_KEY_PATH = process.env.CODEX_BRIDGE_DEVICE_KEY_PATH ??
  path.join(os.homedir(), ".codex-bridge", "controller-device-key.json");
const ENROLLMENT_PATH = process.env.CODEX_BRIDGE_ENROLLMENT_PATH ?? DEFAULT_ENROLLMENT_PATH;

function apiPath(pathname) {
  return `${BASE_URL}${pathname}`;
}

function controllerWebsocketUrl() {
  const base = new URL(BASE_URL);
  const ws = new URL(`${base.pathname.replace(/\/+$/u, "")}/codex/remote/control/client`, base);
  ws.protocol = base.protocol === "https:" ? "wss:" : "ws:";
  return ws.toString();
}

function log(event, fields = {}) {
  console.error(JSON.stringify({
    ts: new Date().toISOString(),
    event,
    ...fields,
  }));
}

function frame(message) {
  return Buffer.from(`${JSON.stringify(message)}\n`, "utf8");
}

function parseNdjson(buffer) {
  const messages = [];
  let offset = 0;
  while (offset < buffer.length) {
    const lineEnd = buffer.indexOf("\n", offset, "utf8");
    if (lineEnd === -1) {
      break;
    }
    const line = buffer.subarray(offset, lineEnd).toString("utf8").trim();
    if (line) {
      messages.push(JSON.parse(line));
    }
    offset = lineEnd + 1;
  }
  return { messages, remaining: buffer.subarray(offset) };
}

function redactString(value, keepEdge = false) {
  if (typeof value !== "string") {
    return value;
  }
  if (!keepEdge || value.length <= 12) {
    return { redacted: true, length: value.length };
  }
  return { redacted: true, length: value.length, prefix: value.slice(0, 8), suffix: value.slice(-4) };
}

function sanitize(value, key = "") {
  const lowered = key.toLowerCase();
  if (typeof value === "string") {
    if (
      lowered.includes("token") ||
      lowered.includes("secret") ||
      lowered.includes("authorization") ||
      lowered.includes("nonce") ||
      lowered.includes("signature") ||
      lowered.includes("signed_payload") ||
      lowered.includes("signedpayload") ||
      lowered.includes("public_key") ||
      lowered.includes("publickey") ||
      lowered.includes("identity_hash") ||
      lowered.includes("identityhash") ||
      lowered.includes("sha256") ||
      lowered.includes("account_user_id") ||
      lowered.includes("accountuserid") ||
      lowered === "user_id"
    ) {
      return redactString(value, false);
    }
    if (
      lowered.endsWith("_id") ||
      lowered.endsWith("id") ||
      lowered === "id" ||
      lowered === "client_id" ||
      lowered === "clientid" ||
      lowered === "env_id" ||
      lowered === "envid" ||
      lowered === "stream_id" ||
      lowered === "streamid" ||
      lowered === "sessionid" ||
      lowered === "session_id" ||
      lowered === "key_id" ||
      lowered === "keyid"
    ) {
      return redactString(value, true);
    }
    return value;
  }
  if (!value || typeof value !== "object") {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => sanitize(item, key));
  }
  const out = {};
  for (const [field, fieldValue] of Object.entries(value)) {
    out[field] = sanitize(fieldValue, field);
  }
  return out;
}

function decodeJwtPayload(token) {
  const parts = token.split(".");
  if (parts.length < 2 || !parts[1]) {
    return null;
  }
  try {
    return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

function chatgptAccountId(token) {
  const payload = decodeJwtPayload(token);
  const auth = payload?.["https://api.openai.com/auth"];
  if (!auth || typeof auth !== "object") {
    return null;
  }
  return typeof auth.chatgpt_account_id === "string"
    ? auth.chatgpt_account_id
    : typeof auth.account_id === "string"
      ? auth.account_id
      : null;
}

async function getAuthStatusWithToken() {
  const child = spawn(CODEX_BIN, CODEX_ARGS, { stdio: ["pipe", "pipe", "pipe"] });
  let stdout = Buffer.alloc(0);
  let stderr = "";
  const messages = [];
  let response;
  const closePromise = new Promise((resolve) => child.on("close", resolve));

  child.stdout.on("data", (chunk) => {
    stdout = Buffer.concat([stdout, chunk]);
    const parsed = parseNdjson(stdout);
    stdout = parsed.remaining;
    messages.push(...parsed.messages);
    response = messages.find((message) => message && message.id === 2);
    if (response) {
      child.stdin.end();
    }
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString("utf8");
  });

  child.stdin.write(frame({
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      clientInfo: { name: "codex-bridge-helper", title: "Codex Bridge Helper", version: "0.1.0" },
      capabilities: { experimentalApi: true, requestAttestation: false, optOutNotificationMethods: [] },
    },
  }));
  child.stdin.write(frame({ jsonrpc: "2.0", method: "initialized" }));
  child.stdin.write(frame({
    jsonrpc: "2.0",
    id: 2,
    method: "getAuthStatus",
    params: { includeToken: true, refreshToken: true },
  }));

  const timedOut = await Promise.race([
    new Promise((resolve) => setTimeout(() => resolve(true), TIMEOUT_MS)),
    closePromise.then(() => false),
  ]);
  if (timedOut) {
    child.kill("SIGTERM");
    await closePromise;
  }
  if (!response) {
    throw new Error(`getAuthStatus did not return response id 2; stderr=${JSON.stringify(stderr.trim())}`);
  }
  if (response.error) {
    throw new Error(`getAuthStatus error: ${JSON.stringify(response.error)}`);
  }
  const token = response.result?.authToken;
  if (!token) {
    throw new Error("getAuthStatus returned no authToken");
  }
  return token;
}

async function postJson(pathname, body, token) {
  const accountId = ACCOUNT_ID ?? chatgptAccountId(token);
  const headers = {
    accept: "application/json",
    authorization: `Bearer ${token}`,
    "content-type": "application/json",
    "user-agent": "codex-bridge-helper/0.1",
  };
  if (accountId) {
    headers["chatgpt-account-id"] = accountId;
  }
  const response = await fetch(apiPath(pathname), {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
  const text = await response.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }
  if (!response.ok) {
    throw new Error(`POST ${pathname} failed (${response.status}): ${JSON.stringify(sanitize(json ?? text.slice(0, 500)))}`);
  }
  return json;
}

async function fetchJson(pathname, token) {
  const accountId = ACCOUNT_ID ?? chatgptAccountId(token);
  const headers = {
    accept: "application/json",
    authorization: `Bearer ${token}`,
    "user-agent": "codex-bridge-helper/0.1",
  };
  if (accountId) {
    headers["chatgpt-account-id"] = accountId;
  }
  const response = await fetch(apiPath(pathname), { headers });
  const text = await response.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }
  if (!response.ok) {
    throw new Error(`GET ${pathname} failed (${response.status}): ${JSON.stringify(sanitize(json ?? text.slice(0, 500)))}`);
  }
  return json;
}

async function selectEnvironment(authToken) {
  const environments = await fetchJson("/codex/remote/control/environments?limit=25", authToken);
  const items = Array.isArray(environments.items) ? environments.items : [];
  let candidates = items.filter((item) => item && item.online === true);
  const effectiveEnvId = TARGET_ENV_ID?.startsWith("env_") ? TARGET_ENV_ID : null;
  const effectiveEnvName = TARGET_ENV_NAME ?? (effectiveEnvId ? null : TARGET_ENV_ID);
  if (effectiveEnvId) {
    candidates = candidates.filter((item) => item.env_id === effectiveEnvId);
  }
  if (effectiveEnvName) {
    candidates = candidates.filter((item) =>
      item.display_name === effectiveEnvName ||
      item.host_name === effectiveEnvName ||
      item.name === effectiveEnvName
    );
  }
  if (candidates.length !== 1) {
    throw new Error(`Expected exactly one matching online environment; got ${candidates.length}: ${JSON.stringify(sanitize(items.map((item) => ({
      env_id: item.env_id,
      display_name: item.display_name,
      host_name: item.host_name,
      online: item.online,
      busy: item.busy,
      os: item.os,
      arch: item.arch,
      app_server_version: item.app_server_version,
    }))))}`);
  }
  return candidates[0];
}

function refreshPayload(enrollment, challenge, identityHash) {
  return {
    type: "remoteControlClientEnrollment",
    nonce: challenge.nonce,
    audience: challenge.audience,
    challengeId: challenge.challenge_id,
    targetOrigin: challenge.target_origin,
    targetPath: challenge.target_path,
    accountUserId: enrollment.accountUserId,
    clientId: enrollment.clientId,
    deviceIdentitySha256Base64url: challenge.device_identity_hash ?? identityHash,
    challengeExpiresAt: challenge.challenge_expires_at,
  };
}

async function refreshClientSession({ authToken, enrollment, keyState }) {
  const start = await postJson(
    "/codex/remote/control/client/refresh/start",
    { client_id: enrollment.clientId },
    authToken,
  );
  const challenge = start?.device_key_challenge;
  if (!challenge) {
    throw new Error(`refresh/start returned no challenge: ${JSON.stringify(sanitize(start))}`);
  }
  const identityHash = deviceIdentityHash(keyState.deviceKey);
  const signedPayload = refreshPayload(enrollment, challenge, identityHash);
  const proof = signDeviceKeyPayload(keyState.deviceKey, signedPayload);
  const finish = await postJson(
    "/codex/remote/control/client/refresh/finish",
    {
      client_id: enrollment.clientId,
      device_key_proof: {
        challenge_token: challenge.challenge_token,
        key_id: keyState.deviceKey.keyId,
        signature_der_base64: proof.signatureDerBase64,
        signed_payload_base64: proof.signedPayloadBase64,
        algorithm: keyState.deviceKey.algorithm,
      },
    },
    authToken,
  );
  if (typeof finish?.remote_control_token !== "string") {
    throw new Error(`refresh/finish returned no remote_control_token: ${JSON.stringify(sanitize(finish))}`);
  }
  const tokenExpiresAt = Math.floor(Date.parse(finish.expires_at) / 1000);
  if (!Number.isSafeInteger(tokenExpiresAt)) {
    throw new Error(`refresh/finish returned invalid expires_at: ${JSON.stringify(sanitize(finish))}`);
  }
  return {
    remoteControlToken: finish.remote_control_token,
    tokenExpiresAt,
    scopes: Array.isArray(finish.scopes) ? finish.scopes : [],
  };
}

function connectionPayload(challenge) {
  return {
    type: "remoteControlClientConnection",
    nonce: challenge.nonce,
    audience: challenge.audience,
    sessionId: challenge.sessionId,
    targetOrigin: challenge.targetOrigin,
    targetPath: challenge.targetPath,
    accountUserId: challenge.accountUserId,
    clientId: challenge.clientId,
    tokenSha256Base64url: challenge.tokenSha256Base64url,
    tokenExpiresAt: challenge.tokenExpiresAt,
    scopes: challenge.scopes,
  };
}

function validateWebsocketChallenge({ challenge, wsUrl, enrollment, remoteControlToken, tokenExpiresAt, scopes }) {
  const url = new URL(wsUrl);
  const expectedOrigin = `${url.protocol === "wss:" ? "https:" : "http:"}//${url.host}`;
  const tokenHash = crypto.createHash("sha256").update(remoteControlToken, "utf8").digest("base64url");
  const errors = [];
  if (challenge.purpose !== "remote_control_client_websocket") errors.push("purpose");
  if (challenge.audience !== "remote_control_client_websocket") errors.push("audience");
  if (challenge.targetOrigin !== expectedOrigin) errors.push("targetOrigin");
  if (challenge.targetPath !== url.pathname) errors.push("targetPath");
  if (challenge.accountUserId !== enrollment.accountUserId) errors.push("accountUserId");
  if (challenge.clientId !== enrollment.clientId) errors.push("clientId");
  if (challenge.tokenSha256Base64url !== tokenHash) errors.push("tokenSha256Base64url");
  if (challenge.tokenExpiresAt !== tokenExpiresAt) errors.push("tokenExpiresAt");
  if (!Array.isArray(challenge.scopes) || challenge.scopes.join("\0") !== scopes.join("\0")) errors.push("scopes");
  if (errors.length > 0) {
    throw new Error(`websocket device-key challenge validation failed: ${errors.join(", ")}`);
  }
}

function websocketProof({ challenge, keyState }) {
  const payload = connectionPayload(challenge);
  const proof = signDeviceKeyPayload(keyState.deviceKey, payload);
  return {
    type: "device_key_proof",
    keyId: keyState.deviceKey.keyId,
    signatureDerBase64: proof.signatureDerBase64,
    signedPayloadBase64: proof.signedPayloadBase64,
    algorithm: keyState.deviceKey.algorithm,
  };
}

function headerLine(name, value) {
  if (/[\r\n]/u.test(name) || /[\r\n]/u.test(String(value))) {
    throw new Error(`Invalid header value for ${name}`);
  }
  return `${name}: ${value}\r\n`;
}

function encodeFrame(opcode, payload = Buffer.alloc(0), { mask = false } = {}) {
  const length = payload.length;
  let headerLength = 2;
  if (length >= 126 && length <= 0xffff) {
    headerLength += 2;
  } else if (length > 0xffff) {
    headerLength += 8;
  }
  const maskBytes = mask ? crypto.randomBytes(4) : null;
  const frameBuffer = Buffer.alloc(headerLength + (mask ? 4 : 0) + length);
  frameBuffer[0] = 0x80 | opcode;
  let offset = 2;
  if (length < 126) {
    frameBuffer[1] = (mask ? 0x80 : 0) | length;
  } else if (length <= 0xffff) {
    frameBuffer[1] = (mask ? 0x80 : 0) | 126;
    frameBuffer.writeUInt16BE(length, offset);
    offset += 2;
  } else {
    frameBuffer[1] = (mask ? 0x80 : 0) | 127;
    frameBuffer.writeBigUInt64BE(BigInt(length), offset);
    offset += 8;
  }
  if (maskBytes) {
    maskBytes.copy(frameBuffer, offset);
    offset += 4;
    for (let index = 0; index < length; index += 1) {
      frameBuffer[offset + index] = payload[index] ^ maskBytes[index % 4];
    }
  } else {
    payload.copy(frameBuffer, offset);
  }
  return frameBuffer;
}

function decodeFrames(buffer) {
  const frames = [];
  let offset = 0;
  while (buffer.length - offset >= 2) {
    const first = buffer[offset];
    const second = buffer[offset + 1];
    const fin = (first & 0x80) !== 0;
    const opcode = first & 0x0f;
    const masked = (second & 0x80) !== 0;
    let length = second & 0x7f;
    let cursor = offset + 2;
    if (length === 126) {
      if (buffer.length - cursor < 2) break;
      length = buffer.readUInt16BE(cursor);
      cursor += 2;
    } else if (length === 127) {
      if (buffer.length - cursor < 8) break;
      const bigLength = buffer.readBigUInt64BE(cursor);
      if (bigLength > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error("websocket frame is too large.");
      }
      length = Number(bigLength);
      cursor += 8;
    }
    let mask = null;
    if (masked) {
      if (buffer.length - cursor < 4) break;
      mask = buffer.subarray(cursor, cursor + 4);
      cursor += 4;
    }
    if (buffer.length - cursor < length) break;
    const payload = Buffer.from(buffer.subarray(cursor, cursor + length));
    if (mask) {
      for (let index = 0; index < payload.length; index += 1) {
        payload[index] ^= mask[index % 4];
      }
    }
    frames.push({ fin, opcode, payload });
    offset = cursor + length;
  }
  return { frames, remaining: buffer.subarray(offset) };
}

async function openWebSocket({ url, headers }) {
  const parsed = new URL(url);
  const isTls = parsed.protocol === "wss:";
  if (!isTls && parsed.protocol !== "ws:") {
    throw new Error(`Unsupported websocket protocol: ${parsed.protocol}`);
  }
  const port = Number(parsed.port || (isTls ? 443 : 80));
  const key = crypto.randomBytes(16).toString("base64");
  const socket = isTls
    ? tls.connect({ host: parsed.hostname, port, servername: parsed.hostname })
    : net.connect({ host: parsed.hostname, port });

  await new Promise((resolve, reject) => {
    const eventName = isTls ? "secureConnect" : "connect";
    const cleanup = () => {
      socket.off(eventName, onReady);
      socket.off("error", onError);
    };
    const onReady = () => {
      cleanup();
      resolve();
    };
    const onError = (error) => {
      cleanup();
      reject(error);
    };
    socket.once(eventName, onReady);
    socket.once("error", onError);
  });

  let request = `GET ${parsed.pathname}${parsed.search} HTTP/1.1\r\n` +
    headerLine("Host", parsed.host) +
    headerLine("Upgrade", "websocket") +
    headerLine("Connection", "Upgrade") +
    headerLine("Sec-WebSocket-Version", "13") +
    headerLine("Sec-WebSocket-Key", key);
  for (const [name, value] of Object.entries(headers)) {
    if (value != null) {
      request += headerLine(name, value);
    }
  }
  request += "\r\n";
  socket.write(request, "utf8");

  let buffer = Buffer.alloc(0);
  const response = await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      cleanup();
      reject(new Error("Timed out waiting for websocket upgrade response."));
    }, TIMEOUT_MS);
    const cleanup = () => {
      clearTimeout(timeout);
      socket.off("data", onData);
      socket.off("error", onError);
      socket.off("close", onClose);
    };
    const onError = (error) => {
      cleanup();
      reject(error);
    };
    const onClose = () => {
      cleanup();
      reject(new Error("Socket closed before websocket upgrade completed."));
    };
    const onData = (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      const headerEnd = buffer.indexOf("\r\n\r\n");
      if (headerEnd === -1) {
        return;
      }
      cleanup();
      resolve({
        headerText: buffer.subarray(0, headerEnd).toString("utf8"),
        remaining: buffer.subarray(headerEnd + 4),
      });
    };
    socket.on("data", onData);
    socket.once("error", onError);
    socket.once("close", onClose);
  });

  const lines = response.headerText.split("\r\n");
  const statusMatch = /^HTTP\/1\.[01]\s+(\d+)/u.exec(lines[0] ?? "");
  const status = statusMatch ? Number(statusMatch[1]) : null;
  if (status !== 101) {
    socket.destroy();
    throw new Error(`websocket upgrade failed (${status ?? "unknown"}): ${response.remaining.toString("utf8").slice(0, 500)}`);
  }
  const headersOut = {};
  for (const line of lines.slice(1)) {
    const index = line.indexOf(":");
    if (index !== -1) {
      headersOut[line.slice(0, index).toLowerCase()] = line.slice(index + 1).trim();
    }
  }
  const expectedAccept = crypto
    .createHash("sha1")
    .update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`, "utf8")
    .digest("base64");
  if (headersOut["sec-websocket-accept"] !== expectedAccept) {
    socket.destroy();
    throw new Error("websocket upgrade response had invalid Sec-WebSocket-Accept.");
  }
  return { socket, remaining: response.remaining };
}

function sendText(socket, text, { mask = false } = {}) {
  socket.write(encodeFrame(0x1, Buffer.from(text, "utf8"), { mask }));
}

function sendJson(socket, message, { mask = false } = {}) {
  sendText(socket, JSON.stringify(message), { mask });
}

function sendClose(socket, { mask = false, code = 1000, reason = "" } = {}) {
  const reasonBuffer = Buffer.from(reason, "utf8");
  const payload = Buffer.alloc(2 + reasonBuffer.length);
  payload.writeUInt16BE(code, 0);
  reasonBuffer.copy(payload, 2);
  socket.write(encodeFrame(0x8, payload, { mask }));
}

class ServerMessageReassembler {
  assemblies = new Map();

  observe(envelope) {
    if (envelope.type !== "server_message_chunk") {
      return envelope;
    }
    const key = `${envelope.env_id}:${envelope.stream_id}:${envelope.seq_id}`;
    let assembly = this.assemblies.get(key);
    if (!assembly) {
      assembly = {
        first: envelope,
        chunks: Array(envelope.segment_count).fill(null),
      };
      this.assemblies.set(key, assembly);
    }
    if (
      assembly.first.message_size_bytes !== envelope.message_size_bytes ||
      assembly.first.segment_count !== envelope.segment_count ||
      envelope.segment_id < 0 ||
      envelope.segment_id >= envelope.segment_count
    ) {
      this.assemblies.delete(key);
      return null;
    }
    assembly.chunks[envelope.segment_id] = envelope.message_chunk_base64;
    if (assembly.chunks.some((item) => item == null)) {
      return null;
    }
    this.assemblies.delete(key);
    const payload = Buffer.concat(assembly.chunks.map((chunk) => Buffer.from(chunk, "base64")));
    if (payload.length !== envelope.message_size_bytes) {
      return null;
    }
    let message;
    try {
      message = JSON.parse(payload.toString("utf8"));
    } catch {
      return null;
    }
    return {
      type: "server_message",
      client_id: envelope.client_id,
      env_id: envelope.env_id,
      stream_id: envelope.stream_id,
      seq_id: envelope.seq_id,
      cursor: envelope.cursor,
      message,
    };
  }

  forgetStream(streamId) {
    for (const key of Array.from(this.assemblies.keys())) {
      if (key.includes(`:${streamId}:`)) {
        this.assemblies.delete(key);
      }
    }
  }
}

class RemoteController {
  constructor({ authToken, enrollment, keyState, session, env }) {
    this.authToken = authToken;
    this.enrollment = enrollment;
    this.keyState = keyState;
    this.session = session;
    this.env = env;
    this.wsUrl = controllerWebsocketUrl();
    this.socket = null;
    this.buffer = Buffer.alloc(0);
    this.ready = false;
    this.streams = new Map();
    this.reassembler = new ServerMessageReassembler();
    this.cursor = null;
    this.connectPromise = null;
    this.reconnectTimer = null;
    this.reconnectAttempt = 0;
    this.hasConnected = false;
    this.unackedEnvelopes = new Map();
  }

  async connect() {
    await this.ensureRemoteOpen();
  }

  isRemoteOpen() {
    return this.ready && this.socket != null && !this.socket.destroyed;
  }

  async ensureRemoteOpen() {
    if (this.isRemoteOpen()) {
      return;
    }
    if (this.connectPromise) {
      return this.connectPromise;
    }
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.connectPromise = this.openRemote().finally(() => {
      this.connectPromise = null;
    });
    return this.connectPromise;
  }

  async refreshSessionForConnect() {
    const now = Math.floor(Date.now() / 1000);
    const shouldRefresh = !this.session ||
      this.hasConnected ||
      this.session.tokenExpiresAt <= now + SESSION_REFRESH_SKEW_SECONDS;
    if (!shouldRefresh) {
      return;
    }
    this.session = await refreshClientSession({
      authToken: this.authToken,
      enrollment: this.enrollment,
      keyState: this.keyState,
    });
    log("controller-session-refreshed", {
      expiresAt: new Date(this.session.tokenExpiresAt * 1000).toISOString(),
      scopes: this.session.scopes,
    });
  }

  async openRemote() {
    await this.refreshSessionForConnect();
    const accountId = ACCOUNT_ID ?? chatgptAccountId(this.authToken);
    const headers = {
      Authorization: `Bearer ${this.authToken}`,
      ...(accountId ? { "ChatGPT-Account-Id": accountId } : {}),
      originator: ORIGINATOR,
      "User-Agent": USER_AGENT,
      "x-codex-client-id": this.enrollment.clientId,
      "x-codex-protocol-version": "3",
      "x-codex-client-session-token": `Bearer ${this.session.remoteControlToken}`,
      ...(this.cursor ? { "x-codex-subscribe-cursor": this.cursor } : {}),
    };
    let socket = null;
    const opened = await openWebSocket({
      url: this.wsUrl,
      headers,
    });
    socket = opened.socket;
    this.socket = socket;
    this.buffer = opened.remaining;
    this.ready = false;

    try {
      await new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
          cleanup();
          reject(new Error("Timed out waiting for remote-control websocket challenge."));
        }, TIMEOUT_MS);
        const cleanup = () => {
          clearTimeout(timeout);
          socket.off("data", onData);
          socket.off("error", onError);
          socket.off("close", onClose);
        };
        const onData = (chunk) => {
          this.buffer = Buffer.concat([this.buffer, chunk]);
          try {
            this.processBuffer();
            if (this.ready) {
              cleanup();
              resolve();
            }
          } catch (error) {
            cleanup();
            reject(error);
          }
        };
        const onError = (error) => {
          cleanup();
          reject(error);
        };
        const onClose = () => {
          cleanup();
          reject(new Error("Remote-control websocket closed during challenge."));
        };
        socket.on("data", onData);
        socket.once("error", onError);
        socket.once("close", onClose);
        onData(Buffer.alloc(0));
      });
    } catch (error) {
      if (this.socket === socket) {
        this.socket = null;
        this.ready = false;
        this.buffer = Buffer.alloc(0);
      }
      socket.destroy();
      throw error;
    }

    this.installRemoteSocket(socket);
    this.reconnectAttempt = 0;
    this.hasConnected = true;
    log("remote-controller-ready", {
      wsUrl: this.wsUrl,
      cursorPresent: this.cursor != null,
      unackedCount: this.unackedEnvelopes.size,
      env: sanitize({
        env_id: this.env.env_id,
        display_name: this.env.display_name,
        host_name: this.env.host_name,
      }),
    });
    this.replayUnackedEnvelopes();
    this.restoreStreamSubscriptions();
  }

  installRemoteSocket(socket) {
    socket.on("data", (chunk) => {
      if (this.socket !== socket) {
        return;
      }
      this.buffer = Buffer.concat([this.buffer, chunk]);
      try {
        this.processBuffer();
      } catch (error) {
        log("remote-frame-error", { error: error instanceof Error ? error.message : String(error) });
        this.handleRemoteDisconnect("remote frame error", socket);
      }
    });
    socket.on("error", (error) => {
      log("remote-websocket-error", { error: error.message });
      this.handleRemoteDisconnect("remote websocket error", socket);
    });
    socket.on("close", () => {
      this.handleRemoteDisconnect("remote websocket closed", socket);
    });
  }

  handleRemoteDisconnect(reason, socket = this.socket) {
    if (socket != null && this.socket !== socket) {
      return;
    }
    if (this.socket == null && !this.ready) {
      return;
    }
    if (socket && !socket.destroyed) {
      socket.destroy();
    }
    this.socket = null;
    this.ready = false;
    this.buffer = Buffer.alloc(0);
    log("remote-websocket-disconnected", {
      reason,
      activeStreams: this.streams.size,
      unackedCount: this.unackedEnvelopes.size,
      cursorPresent: this.cursor != null,
    });
    if (this.streams.size > 0 || this.unackedEnvelopes.size > 0) {
      this.scheduleReconnect(reason);
    }
  }

  scheduleReconnect(reason) {
    if (this.isRemoteOpen() || this.connectPromise || this.reconnectTimer) {
      return;
    }
    const delayMs = Math.min(
      REMOTE_RECONNECT_MAX_MS,
      REMOTE_RECONNECT_INITIAL_MS * (2 ** this.reconnectAttempt),
    );
    this.reconnectAttempt += 1;
    log("remote-reconnect-scheduled", {
      reason,
      delayMs,
      activeStreams: this.streams.size,
      unackedCount: this.unackedEnvelopes.size,
    });
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.ensureRemoteOpen().catch((error) => {
        log("remote-reconnect-failed", {
          error: error instanceof Error ? error.message : String(error),
          activeStreams: this.streams.size,
          unackedCount: this.unackedEnvelopes.size,
        });
        if (this.streams.size > 0 || this.unackedEnvelopes.size > 0) {
          this.scheduleReconnect("remote reconnect failed");
        }
      });
    }, delayMs);
  }

  envelopeKey(envelope) {
    return [
      envelope.env_id ?? "",
      envelope.stream_id ?? "",
      String(envelope.seq_id ?? ""),
      String(envelope.segment_id ?? ""),
      envelope.type ?? "",
    ].join(":");
  }

  trackEnvelope(envelope) {
    this.unackedEnvelopes.set(this.envelopeKey(envelope), envelope);
  }

  handleAck(ack) {
    let removed = 0;
    const ackSegmentId = ack.segment_id ?? Number.MAX_SAFE_INTEGER;
    for (const [key, envelope] of Array.from(this.unackedEnvelopes.entries())) {
      if (envelope.env_id !== ack.env_id || envelope.stream_id !== ack.stream_id) {
        continue;
      }
      const envelopeSegmentId = envelope.segment_id ?? 0;
      const acked = envelope.seq_id < ack.seq_id ||
        (envelope.seq_id === ack.seq_id && envelopeSegmentId <= ackSegmentId);
      if (acked) {
        this.unackedEnvelopes.delete(key);
        removed += 1;
      }
    }
    if (removed > 0) {
      log("remote-ack", {
        stream_id: sanitize(ack.stream_id, "stream_id"),
        seq_id: ack.seq_id,
        removed,
        unackedCount: this.unackedEnvelopes.size,
      });
    }
  }

  rememberCursor(envelope) {
    if (typeof envelope.cursor === "string" && envelope.cursor.length > 0) {
      this.cursor = envelope.cursor;
    }
  }

  sendRemoteEnvelope(envelope, { track = true } = {}) {
    if (track) {
      this.trackEnvelope(envelope);
    }
    if (!this.isRemoteOpen()) {
      this.scheduleReconnect("send while remote disconnected");
      return;
    }
    sendJson(this.socket, envelope, { mask: true });
  }

  replayUnackedEnvelopes() {
    if (!this.isRemoteOpen() || this.unackedEnvelopes.size === 0) {
      return;
    }
    log("remote-replay-unacked", { count: this.unackedEnvelopes.size });
    for (const envelope of this.unackedEnvelopes.values()) {
      sendJson(this.socket, envelope, { mask: true });
    }
  }

  restoreStreamSubscriptions() {
    if (!this.isRemoteOpen()) {
      return;
    }
    for (const stream of this.streams.values()) {
      if (stream.streamId) {
        this.sendPing(stream);
      }
    }
  }

  forgetStreamEnvelopes(streamId) {
    for (const [key, envelope] of Array.from(this.unackedEnvelopes.entries())) {
      if (envelope.stream_id === streamId) {
        this.unackedEnvelopes.delete(key);
      }
    }
  }

  processBuffer() {
    const decoded = decodeFrames(this.buffer);
    this.buffer = decoded.remaining;
    for (const frameItem of decoded.frames) {
      if (frameItem.opcode === 0x1) {
        this.handleRemoteText(frameItem.payload.toString("utf8"));
      } else if (frameItem.opcode === 0x8) {
        this.handleRemoteDisconnect("remote websocket close frame");
      } else if (frameItem.opcode === 0x9) {
        this.socket.write(encodeFrame(0x0a, frameItem.payload, { mask: true }));
      }
    }
  }

  handleRemoteText(text) {
    let message;
    try {
      message = JSON.parse(text);
    } catch {
      log("remote-non-json-text", { bytes: Buffer.byteLength(text, "utf8") });
      return;
    }

    if (message.type === "device_key_challenge") {
      validateWebsocketChallenge({
        challenge: message,
        wsUrl: this.wsUrl,
        enrollment: this.enrollment,
        remoteControlToken: this.session.remoteControlToken,
        tokenExpiresAt: this.session.tokenExpiresAt,
        scopes: this.session.scopes,
      });
      sendJson(this.socket, websocketProof({ challenge: message, keyState: this.keyState }), { mask: true });
      this.ready = true;
      return;
    }

    if (message.type === "ack") {
      this.handleAck(message);
      return;
    }

    if (message.type === "server_message" || message.type === "server_message_chunk") {
      const envelope = this.reassembler.observe(message);
      if (!envelope) {
        return;
      }
      const stream = this.streams.get(envelope.stream_id);
      if (!stream) {
        return;
      }
      this.rememberCursor(envelope);
      sendJson(stream.localSocket, envelope.message, { mask: false });
      return;
    }

    if (message.type === "pong") {
      const stream = this.streams.get(message.stream_id);
      this.rememberCursor(message);
      if (stream && message.status === "unknown") {
        stream.closeLocal(1011, "remote stream unknown");
      }
      return;
    }

    log("remote-unhandled-message", {
      type: message.type ?? null,
      code: message.code ?? message.error?.code ?? null,
      error: message.error?.message ?? (typeof message.message === "string" ? message.message : null),
      keys: Object.keys(message).sort(),
    });
  }

  registerLocal(localSocket) {
    const stream = {
      streamId: null,
      nextSeqId: 1,
      localSocket,
      pingTimer: null,
      closeLocal: (code, reason) => {
        sendClose(localSocket, { code, reason, mask: false });
        localSocket.destroy();
      },
    };
    return stream;
  }

  ensureStream(stream, message) {
    if (stream.streamId == null || message?.method === "initialize") {
      if (stream.streamId != null) {
        this.forgetStreamEnvelopes(stream.streamId);
        this.sendClientClosed(stream);
        this.streams.delete(stream.streamId);
        this.reassembler.forgetStream(stream.streamId);
      }
      stream.streamId = crypto.randomUUID();
      stream.nextSeqId = 1;
      this.streams.set(stream.streamId, stream);
      this.startStreamPing(stream);
    }
    return stream.streamId;
  }

  sendClientMessage(stream, message) {
    const streamId = this.ensureStream(stream, message);
    const envelope = {
      type: "client_message",
      client_id: this.enrollment.clientId,
      env_id: this.env.env_id,
      stream_id: streamId,
      seq_id: stream.nextSeqId,
      skip_history: false,
      message,
    };
    stream.nextSeqId += 1;
    this.sendRemoteEnvelope(envelope);
  }

  sendPing(stream) {
    if (!stream.streamId || !this.isRemoteOpen()) {
      return;
    }
    const envelope = {
      type: "ping",
      client_id: this.enrollment.clientId,
      env_id: this.env.env_id,
      stream_id: stream.streamId,
      seq_id: stream.nextSeqId,
      state: "foreground",
      skip_history: true,
    };
    stream.nextSeqId += 1;
    this.sendRemoteEnvelope(envelope);
  }

  startStreamPing(stream) {
    if (stream.pingTimer) {
      clearInterval(stream.pingTimer);
    }
    stream.pingTimer = setInterval(() => this.sendPing(stream), STREAM_PING_MS);
  }

  sendClientClosed(stream) {
    if (!stream.streamId) {
      return;
    }
    const envelope = {
      type: "client_closed",
      client_id: this.enrollment.clientId,
      env_id: this.env.env_id,
      stream_id: stream.streamId,
      seq_id: stream.nextSeqId,
    };
    stream.nextSeqId += 1;
    this.sendRemoteEnvelope(envelope);
  }

  closeStream(stream) {
    if (stream.pingTimer) {
      clearInterval(stream.pingTimer);
      stream.pingTimer = null;
    }
    if (stream.streamId) {
      this.forgetStreamEnvelopes(stream.streamId);
      this.sendClientClosed(stream);
      this.streams.delete(stream.streamId);
      this.reassembler.forgetStream(stream.streamId);
      stream.streamId = null;
    }
  }

  closeAllLocal(code, reason) {
    for (const stream of this.streams.values()) {
      if (stream.pingTimer) {
        clearInterval(stream.pingTimer);
        stream.pingTimer = null;
      }
      stream.closeLocal(code, reason);
    }
    this.streams.clear();
  }
}

function acceptLocalWebSocket({ request, socket, head, controller }) {
  const key = request.headers["sec-websocket-key"];
  if (typeof key !== "string" || request.headers.upgrade?.toLowerCase() !== "websocket") {
    socket.write("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
    socket.destroy();
    return;
  }
  const accept = crypto
    .createHash("sha1")
    .update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`, "utf8")
    .digest("base64");
  socket.write([
    "HTTP/1.1 101 Switching Protocols",
    "Upgrade: websocket",
    "Connection: Upgrade",
    `Sec-WebSocket-Accept: ${accept}`,
    "",
    "",
  ].join("\r\n"));

  const stream = controller.registerLocal(socket);
  let buffer = Buffer.from(head ?? Buffer.alloc(0));
  const processBuffer = () => {
    const decoded = decodeFrames(buffer);
    buffer = decoded.remaining;
    for (const frameItem of decoded.frames) {
      if (frameItem.opcode === 0x1 || frameItem.opcode === 0x2) {
        const text = frameItem.payload.toString("utf8");
        let message;
        try {
          message = JSON.parse(text);
        } catch {
          stream.closeLocal(1003, "expected JSON-RPC text frame");
          return;
        }
        controller.sendClientMessage(stream, message);
      } else if (frameItem.opcode === 0x8) {
        controller.closeStream(stream);
        sendClose(socket, { mask: false });
        socket.destroy();
        return;
      } else if (frameItem.opcode === 0x9) {
        socket.write(encodeFrame(0x0a, frameItem.payload, { mask: false }));
      }
    }
  };

  socket.on("data", (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);
    try {
      processBuffer();
    } catch (error) {
      log("local-frame-error", { error: error instanceof Error ? error.message : String(error) });
      stream.closeLocal(1011, "local frame error");
    }
  });
  socket.on("error", (error) => {
    log("local-websocket-error", { error: error.message });
    controller.closeStream(stream);
  });
  socket.on("close", () => {
    controller.closeStream(stream);
  });
  processBuffer();
  log("local-client-connected");
}

async function main() {
  const keyState = loadOrCreateSoftwareDeviceKey(DEVICE_KEY_PATH);
  if (keyState.created) {
    throw new Error(`No existing helper device key found at ${DEVICE_KEY_PATH}; refusing bridge startup with a new key.`);
  }
  const enrollment = readEnrollment(ENROLLMENT_PATH);
  if (enrollment.keyId !== keyState.deviceKey.keyId) {
    throw new Error("Enrollment keyId does not match local device key.");
  }

  const authToken = await getAuthStatusWithToken();
  const env = await selectEnvironment(authToken);
  const session = await refreshClientSession({ authToken, enrollment, keyState });
  const controller = new RemoteController({ authToken, enrollment, keyState, session, env });
  if (process.env.CODEX_BRIDGE_ENABLE_SIGNAL_DEBUG === "1") {
    process.on("SIGUSR2", () => {
      log("debug-signal", { signal: "SIGUSR2", action: "simulate remote websocket disconnect" });
      controller.handleRemoteDisconnect("SIGUSR2 debug remote disconnect");
    });
  }
  await controller.connect();

  const server = http.createServer((request, response) => {
    response.writeHead(426, { "content-type": "text/plain; charset=utf-8" });
    response.end("Expected WebSocket upgrade.\n");
  });
  server.on("upgrade", (request, socket, head) => {
    acceptLocalWebSocket({ request, socket, head, controller });
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(LISTEN_PORT, LISTEN_HOST, () => {
      server.off("error", reject);
      resolve();
    });
  });
  log("bridge-ready", {
    localUrl: `ws://${LISTEN_HOST}:${LISTEN_PORT}`,
    env: sanitize({
      env_id: env.env_id,
      display_name: env.display_name,
      host_name: env.host_name,
      online: env.online,
      busy: env.busy,
      os: env.os,
      arch: env.arch,
      app_server_version: env.app_server_version,
    }),
  });
}

main().catch((error) => {
  console.error(JSON.stringify({
    event: "bridge-fatal",
    error: error instanceof Error ? error.message : String(error),
  }));
  process.exitCode = 1;
});
