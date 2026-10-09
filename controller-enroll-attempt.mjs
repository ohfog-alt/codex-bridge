#!/usr/bin/env node

import crypto from "node:crypto";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { Buffer } from "node:buffer";
import {
  deviceIdentity,
  deviceIdentityHash,
  loadOrCreateSoftwareDeviceKey,
  signDeviceKeyPayload,
} from "./lib/device-key.mjs";
import {
  DEFAULT_ENROLLMENT_PATH,
  buildEnrollmentRecord,
  writeEnrollment,
} from "./lib/enrollment-store.mjs";

const CODEX_BIN = process.env.CODEX_BIN ?? "codex";
const CODEX_ARGS = (process.env.CODEX_APP_SERVER_ARGS ?? "app-server --stdio")
  .split(/\s+/u)
  .filter(Boolean);
const BASE_URL = process.env.CHATGPT_BASE_URL ?? "https://chatgpt.com/backend-api";
const ACCOUNT_ID = process.env.CHATGPT_ACCOUNT_ID;
const TIMEOUT_MS = Number(process.env.CODEX_TIMEOUT_MS ?? "5000");
const STEP_UP_TOKEN = process.env.CODEX_STEP_UP_TOKEN;
const STEP_UP_MODE = process.env.CODEX_STEP_UP_MODE ?? "";
const STEP_UP_TIMEOUT_MS = Number(process.env.CODEX_STEP_UP_TIMEOUT_MS ?? String(10 * 60 * 1000));
const STEP_UP_ISSUER = process.env.CODEX_STEP_UP_ISSUER ?? "https://auth.openai.com";
const STEP_UP_CLIENT_ID = process.env.CODEX_STEP_UP_CLIENT_ID ?? "app_EMoamEEZ73f0CkXaXp7hrann";
const STEP_UP_SCOPE = "codex.remote_control.enroll";
const STEP_UP_REAUTH = "remote_control";
const STEP_UP_CALLBACK_PATH = "/auth/callback";
const STEP_UP_CALLBACK_PORTS = [1455, 1457];
const ORIGINATOR = process.env.CODEX_ORIGINATOR ?? "Codex Desktop";
const HTTP_ORIGINATOR = process.env.CODEX_HTTP_ORIGINATOR ?? ORIGINATOR;
const HTTP_USER_AGENT = process.env.CODEX_HTTP_USER_AGENT ?? "codex-bridge-helper/0.1";
const ALLOW_STATE_CHANGE = process.env.CODEX_ALLOW_STATE_CHANGE === "client-enroll-finish";
const DEVICE_KEY_PATH = process.env.CODEX_BRIDGE_DEVICE_KEY_PATH ??
  path.join(os.homedir(), ".codex-bridge", "controller-device-key.json");
const ENROLLMENT_PATH = process.env.CODEX_BRIDGE_ENROLLMENT_PATH ?? DEFAULT_ENROLLMENT_PATH;
const PROTECTION_CLASS = process.env.CODEX_DEVICE_PROTECTION_CLASS ??
  "os_protected_nonextractable";
const DEVICE_KEY_ID_PREFIX = process.env.CODEX_DEVICE_KEY_ID_PREFIX ?? "";

if (!ALLOW_STATE_CHANGE) {
  console.error(JSON.stringify({
    error: "Refusing state-changing enrollment finish. Set CODEX_ALLOW_STATE_CHANGE=client-enroll-finish.",
  }, null, 2));
  process.exit(2);
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

function tokenMetadata(token) {
  return {
    received: Boolean(token),
    length: token.length,
    sha256Prefix: crypto.createHash("sha256").update(token).digest("hex").slice(0, 12),
    looksLikeJwt: token.split(".").length === 3,
  };
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

function stepUpFreshnessMetadata(token) {
  const payload = decodeJwtPayload(token);
  const now = Math.floor(Date.now() / 1000);
  const numericClaim = (name) => typeof payload?.[name] === "number" ? payload[name] : null;
  const iat = numericClaim("iat");
  const rawPwdAuthTime = numericClaim("pwd_auth_time");
  const pwdAuthTime = rawPwdAuthTime != null && rawPwdAuthTime > 10_000_000_000
    ? Math.floor(rawPwdAuthTime / 1000)
    : rawPwdAuthTime;
  const authTime = numericClaim("auth_time");
  const stringList = (value) => typeof value === "string"
    ? value.split(/\s+/u).filter(Boolean)
    : Array.isArray(value)
      ? value.filter((item) => typeof item === "string")
      : [];
  const scope = stringList(payload?.scope);
  const scp = stringList(payload?.scp);
  const permissions = stringList(payload?.permissions);
  const amr = stringList(payload?.amr);
  const authClaim = payload?.["https://api.openai.com/auth"];
  const authAmr = stringList(authClaim?.amr);
  const ageSeconds = (value) => value == null ? null : now - value;
  return {
    jwtDecoded: Boolean(payload),
    claimKeys: payload && typeof payload === "object" ? Object.keys(payload).sort() : [],
    now,
    iat,
    iatAgeSeconds: ageSeconds(iat),
    rawPwdAuthTimeUnit: rawPwdAuthTime != null && rawPwdAuthTime > 10_000_000_000
      ? "milliseconds"
      : rawPwdAuthTime == null ? null : "seconds",
    pwdAuthTime,
    pwdAuthAgeSeconds: ageSeconds(pwdAuthTime),
    authTime,
    authAgeSeconds: ageSeconds(authTime),
    scope,
    scp,
    permissions,
    amr,
    authAmr,
    freshWithin300Seconds: iat != null && pwdAuthTime != null &&
      ageSeconds(iat) >= 0 && ageSeconds(iat) <= 300 &&
      ageSeconds(pwdAuthTime) >= 0 && ageSeconds(pwdAuthTime) <= 300,
  };
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

function redactString(value, keepEdge = false) {
  if (typeof value !== "string") {
    return value;
  }
  if (!keepEdge || value.length <= 12) {
    return { redacted: true, length: value.length };
  }
  return {
    redacted: true,
    length: value.length,
    prefix: value.slice(0, 8),
    suffix: value.slice(-4),
  };
}

function sanitize(value, key = "") {
  const lowered = key.toLowerCase();
  if (typeof value === "string") {
    if (
      lowered.includes("token") ||
      lowered.includes("secret") ||
      lowered.includes("authorization") ||
      lowered.includes("cursor") ||
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
      lowered === "challenge_id" ||
      lowered === "challengeid" ||
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

async function getAuthStatusWithToken() {
  const child = spawn(CODEX_BIN, CODEX_ARGS, {
    stdio: ["pipe", "pipe", "pipe"],
  });

  let stdout = Buffer.alloc(0);
  let stderr = "";
  const messages = [];
  let response;

  const closePromise = new Promise((resolve) => {
    child.on("close", resolve);
  });

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
      clientInfo: {
        name: "codex-bridge-helper",
        title: "Codex Bridge Helper",
        version: "0.1.0",
      },
      capabilities: {
        experimentalApi: true,
        requestAttestation: false,
        optOutNotificationMethods: [],
      },
    },
  }));
  child.stdin.write(frame({ jsonrpc: "2.0", method: "initialized" }));
  child.stdin.write(frame({
    jsonrpc: "2.0",
    id: 2,
    method: "getAuthStatus",
    params: {
      includeToken: true,
      refreshToken: true,
    },
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
    throw new Error(`getAuthStatus returned no authToken; result=${JSON.stringify(sanitize(response.result))}`);
  }

  return {
    token,
    status: {
      authMethod: response.result?.authMethod ?? null,
      requiresOpenaiAuth: response.result?.requiresOpenaiAuth ?? null,
    },
    appServer: {
      command: `${CODEX_BIN} ${CODEX_ARGS.join(" ")}`,
      stderr: stderr.trim() || null,
      timedOut,
    },
  };
}

async function postJson(pathname, body, token) {
  const accountId = ACCOUNT_ID ?? chatgptAccountId(token);
  const headers = {
    accept: "application/json",
    authorization: `Bearer ${token}`,
    "content-type": "application/json",
    originator: HTTP_ORIGINATOR,
    "user-agent": HTTP_USER_AGENT,
  };
  if (accountId) {
    headers["chatgpt-account-id"] = accountId;
  }

  const response = await fetch(`${BASE_URL}${pathname}`, {
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

  return {
    path: pathname,
    method: "POST",
    requestBody: sanitize(body),
    status: response.status,
    contentType: response.headers.get("content-type"),
    body: json === null ? text.slice(0, 500) : sanitize(json),
    rawBody: json,
  };
}

function randomBase64url(byteLength) {
  return crypto.randomBytes(byteLength).toString("base64url");
}

function codeChallenge(codeVerifier) {
  return crypto.createHash("sha256").update(codeVerifier).digest("base64url");
}

function issuerBase() {
  return STEP_UP_ISSUER.replace(/\/+$/u, "");
}

function writeText(response, status, text) {
  response.writeHead(status, {
    "content-type": "text/plain; charset=utf-8",
    connection: "close",
  });
  response.end(text);
}

function writeSuccess(response) {
  response.writeHead(200, {
    "content-type": "text/html; charset=utf-8",
    connection: "close",
  });
  response.end(`<!doctype html>
<html>
  <body>
    <p>Remote control authorization completed.</p>
  </body>
</html>`);
}

async function listenForStepUpCode(state) {
  let server = null;
  let port = null;
  let timeout = null;
  let settled = false;
  let resolveCode = null;
  let rejectCode = null;

  const authorizationCode = new Promise((resolve, reject) => {
    resolveCode = resolve;
    rejectCode = reject;
  });

  const settle = (fn) => {
    if (settled) {
      return;
    }
    settled = true;
    if (timeout) {
      clearTimeout(timeout);
    }
    fn();
  };

  for (const candidatePort of STEP_UP_CALLBACK_PORTS) {
    const candidate = http.createServer((request, response) => {
      try {
        if (!request.url) {
          writeText(response, 400, "Bad Request");
          return;
        }
        const url = new URL(request.url, `http://localhost:${candidatePort}`);
        if (url.pathname !== STEP_UP_CALLBACK_PATH) {
          writeText(response, 404, "Not Found");
          return;
        }
        if (url.searchParams.get("state") !== state) {
          writeText(response, 400, "State mismatch");
          return;
        }
        const error = url.searchParams.get("error");
        if (error) {
          const description = url.searchParams.get("error_description");
          writeText(response, 400, "Remote control login failed");
          settle(() => rejectCode(new Error(description?.length ? `${error}: ${description}` : error)));
          return;
        }
        const code = url.searchParams.get("code");
        if (!code) {
          writeText(response, 400, "Missing authorization code");
          return;
        }
        writeSuccess(response);
        settle(() => resolveCode(code));
      } catch (error) {
        writeText(response, 400, "Bad Request");
        settle(() => rejectCode(error));
      }
    });

    try {
      await new Promise((resolve, reject) => {
        candidate.once("error", reject);
        candidate.listen(candidatePort, "localhost", () => {
          candidate.off("error", reject);
          resolve();
        });
      });
      server = candidate;
      port = candidatePort;
      break;
    } catch (error) {
      candidate.close();
      if (!(error instanceof Error) || error.code !== "EADDRINUSE") {
        throw error;
      }
    }
  }

  if (!server || !port) {
    throw new Error("Remote control login callback ports 1455 and 1457 are already in use.");
  }

  timeout = setTimeout(() => {
    settle(() => rejectCode(new Error("Timed out waiting for remote control step-up login.")));
  }, STEP_UP_TIMEOUT_MS);

  return {
    redirectUri: `http://localhost:${port}${STEP_UP_CALLBACK_PATH}`,
    authorizationCode,
    close: () => {
      if (timeout) {
        clearTimeout(timeout);
      }
      server?.close();
    },
  };
}

function stepUpAuthorizeUrl({ accountId, codeChallengeValue, redirectUri, state }) {
  const url = new URL("/oauth/authorize", issuerBase());
  const params = new URLSearchParams({
    response_type: "code",
    client_id: STEP_UP_CLIENT_ID,
    redirect_uri: redirectUri,
    scope: STEP_UP_SCOPE,
    code_challenge: codeChallengeValue,
    code_challenge_method: "S256",
    state,
    originator: ORIGINATOR,
    reauth: STEP_UP_REAUTH,
    max_age: "0",
    codex_cli_simplified_flow: "true",
  });
  if (accountId) {
    params.set("allowed_workspace_id", accountId);
    params.set("current_workspace_id", accountId);
  }
  url.search = params.toString();
  return url.toString();
}

async function exchangeStepUpCode({ authorizationCode, codeVerifier, redirectUri }) {
  const response = await fetch(new URL("/oauth/token", issuerBase()).toString(), {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: authorizationCode,
      redirect_uri: redirectUri,
      client_id: STEP_UP_CLIENT_ID,
      code_verifier: codeVerifier,
    }).toString(),
  });

  const text = await response.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }

  if (!response.ok) {
    throw new Error(`Remote control step-up token exchange failed with status ${response.status}: ${json ? JSON.stringify(sanitize(json)) : text.slice(0, 300)}`);
  }
  if (typeof json?.access_token !== "string" || json.access_token.length === 0) {
    throw new Error(`Remote control step-up token exchange returned no access_token: ${JSON.stringify(sanitize(json))}`);
  }
  return json.access_token;
}

async function oauthStepUpToken(authToken) {
  const codeVerifier = randomBase64url(32);
  const state = randomBase64url(32);
  const listener = await listenForStepUpCode(state);
  const accountId = ACCOUNT_ID ?? chatgptAccountId(authToken);
  const authorizeUrl = stepUpAuthorizeUrl({
    accountId,
    codeChallengeValue: codeChallenge(codeVerifier),
    redirectUri: listener.redirectUri,
    state,
  });

  try {
    console.error(JSON.stringify({
      event: "step-up-auth-url",
      message: "Open this URL in a browser authenticated as the same ChatGPT account. If running from a different machine, forward local port 1455 or 1457 to the controller machine first.",
      redirectUri: listener.redirectUri,
      accountIdProvided: Boolean(accountId),
      originator: ORIGINATOR,
      url: authorizeUrl,
    }, null, 2));

    const authorizationCode = await listener.authorizationCode;
    return await exchangeStepUpCode({
      authorizationCode,
      codeVerifier,
      redirectUri: listener.redirectUri,
    });
  } finally {
    listener.close();
  }
}

async function resolveStepUpToken(authToken) {
  if (STEP_UP_TOKEN) {
    return { token: STEP_UP_TOKEN, source: "env" };
  }
  if (STEP_UP_MODE === "oauth") {
    return { token: await oauthStepUpToken(authToken), source: "oauth" };
  }
  return { token: "", source: "empty" };
}

function challengePayload(startBody, challenge, identityHash) {
  return {
    type: "remoteControlClientEnrollment",
    nonce: challenge.nonce,
    audience: challenge.audience,
    challengeId: challenge.challenge_id,
    targetOrigin: challenge.target_origin,
    targetPath: challenge.target_path,
    accountUserId: startBody.account_user_id,
    clientId: startBody.client_id,
    deviceIdentitySha256Base64url: challenge.device_identity_hash ?? identityHash,
    challengeExpiresAt: challenge.challenge_expires_at,
  };
}

try {
  const keyState = loadOrCreateSoftwareDeviceKey(
    DEVICE_KEY_PATH,
    PROTECTION_CLASS,
    DEVICE_KEY_ID_PREFIX,
  );
  const identity = deviceIdentity(keyState.deviceKey);
  const identityHash = deviceIdentityHash(keyState.deviceKey);
  const auth = await getAuthStatusWithToken();
  const stepUp = await resolveStepUpToken(auth.token);

  const start = await postJson("/codex/remote/control/client/enroll/start", {}, auth.token);
  if (start.status < 200 || start.status >= 300) {
    throw new Error(`enroll/start failed: ${JSON.stringify(start.body)}`);
  }

  const startBody = start.rawBody;
  const challenge = startBody?.device_key_challenge;
  if (!startBody?.client_id || !startBody?.account_user_id || !challenge) {
    throw new Error(`enroll/start returned unexpected body: ${JSON.stringify(start.body)}`);
  }

  const signedPayload = challengePayload(startBody, challenge, identityHash);
  const proof = signDeviceKeyPayload(keyState.deviceKey, signedPayload);
  const finishBody = {
    client_id: startBody.client_id,
    step_up_token: stepUp.token,
    device_identity: identity,
    device_key_proof: {
      challenge_token: challenge.challenge_token,
      key_id: keyState.deviceKey.keyId,
      signature_der_base64: proof.signatureDerBase64,
      signed_payload_base64: proof.signedPayloadBase64,
      algorithm: keyState.deviceKey.algorithm,
    },
  };

  const finish = await postJson("/codex/remote/control/client/enroll/finish", finishBody, auth.token);
  const persistedEnrollment = finish.status >= 200 && finish.status < 300 &&
    typeof finish.rawBody?.client_id === "string" &&
    typeof finish.rawBody?.account_user_id === "string";
  if (persistedEnrollment) {
    writeEnrollment(buildEnrollmentRecord({
      accountUserId: finish.rawBody.account_user_id,
      clientId: finish.rawBody.client_id,
      deviceKey: keyState.deviceKey,
      source: "controller-enroll-attempt",
    }), ENROLLMENT_PATH);
  }
  delete start.rawBody;
  delete finish.rawBody;

  console.log(JSON.stringify({
    stateChange: "client-enroll-finish",
    baseUrl: BASE_URL,
    accountHeaderProvided: Boolean(ACCOUNT_ID ?? chatgptAccountId(auth.token)),
    authenticatedRequestHeaders: {
      originator: HTTP_ORIGINATOR,
      userAgent: HTTP_USER_AGENT,
    },
    stepUpTokenProvided: Boolean(stepUp.token),
    stepUpTokenSource: stepUp.source,
    stepUpFreshness: stepUp.token ? stepUpFreshnessMetadata(stepUp.token) : null,
    enrollmentPersisted: persistedEnrollment,
    enrollmentPath: ENROLLMENT_PATH,
    appServer: auth.appServer,
    authStatus: auth.status,
    token: tokenMetadata(auth.token),
    deviceKey: {
      created: keyState.created,
      path: keyState.keyPath,
      keyId: sanitize(keyState.deviceKey.keyId, "key_id"),
      algorithm: keyState.deviceKey.algorithm,
      protectionClass: keyState.deviceKey.protectionClass,
      publicKeySpkiDerBase64Length: keyState.deviceKey.publicKeySpkiDerBase64.length,
      publicKeySha256Base64url: sanitize(keyState.deviceKey.publicKeySha256Base64url, "identity_hash"),
      identityHash: sanitize(identityHash, "identity_hash"),
    },
    signedPayload: sanitize(signedPayload),
    proof: {
      signatureDerLength: proof.signatureDerLength,
      verified: proof.verified,
    },
    start,
    finish,
  }, null, 2));
} catch (error) {
  console.error(JSON.stringify({
    error: error instanceof Error ? error.message : String(error),
  }, null, 2));
  process.exitCode = 1;
}
