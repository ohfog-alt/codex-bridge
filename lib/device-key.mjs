import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { base64, base64url, utf8Bytes } from "./encoding.mjs";

const CURVE_NAME = "prime256v1";
const ALGORITHM = "ecdsa_p256_sha256";
const DEFAULT_PROTECTION_CLASS = "os_protected_nonextractable";
const SIGNING_DOMAIN = "codex-device-key-sign-payload/v1";

function keyMaterialFromPair(pair, keyId, protectionClass = DEFAULT_PROTECTION_CLASS) {
  const publicKeySpkiDer = pair.publicKey.export({ type: "spki", format: "der" });
  const publicKeySpkiDerBase64 = base64(publicKeySpkiDer);
  const publicKeySha256Base64url = base64url(
    crypto.createHash("sha256").update(publicKeySpkiDer).digest(),
  );

  return {
    algorithm: ALGORITHM,
    keyId,
    protectionClass,
    privateKey: pair.privateKey,
    publicKey: pair.publicKey,
    publicKeySpkiDerBase64,
    publicKeySha256Base64url,
  };
}

export function createEphemeralDeviceKey() {
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: CURVE_NAME });
  const publicKey = pair.publicKey.export({ type: "spki", format: "der" });
  const publicKeyHash = base64url(crypto.createHash("sha256").update(publicKey).digest());
  return keyMaterialFromPair(pair, `helper-${publicKeyHash.slice(0, 24)}`);
}

export function loadOrCreateSoftwareDeviceKey(
  keyPath,
  protectionClass = DEFAULT_PROTECTION_CLASS,
  keyIdPrefix = "",
) {
  if (fs.existsSync(keyPath)) {
    const stored = JSON.parse(fs.readFileSync(keyPath, "utf8"));
    const privateKey = crypto.createPrivateKey(stored.privateKeyPkcs8Pem);
    const publicKey = crypto.createPublicKey(privateKey);

    return {
      created: false,
      keyPath,
      deviceKey: keyMaterialFromPair(
        { privateKey, publicKey },
        stored.keyId,
        stored.protectionClass ?? protectionClass,
      ),
    };
  }

  fs.mkdirSync(path.dirname(keyPath), { recursive: true, mode: 0o700 });
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: CURVE_NAME });
  if (keyIdPrefix && !/^[A-Za-z0-9_-]+$/u.test(keyIdPrefix)) {
    throw new Error("Device key id prefix contains unsupported characters.");
  }
  const keyId = keyIdPrefix
    ? `${keyIdPrefix}${crypto.randomBytes(32).toString("base64url")}`
    : crypto.randomUUID();
  const privateKeyPkcs8Pem = pair.privateKey.export({ type: "pkcs8", format: "pem" });
  const deviceKey = keyMaterialFromPair(pair, keyId, protectionClass);

  fs.writeFileSync(
    keyPath,
    JSON.stringify({
      version: 1,
      keyId,
      algorithm: ALGORITHM,
      protectionClass,
      privateKeyPkcs8Pem,
      createdAt: new Date().toISOString(),
    }, null, 2),
    { mode: 0o600 },
  );
  fs.chmodSync(keyPath, 0o600);

  return {
    created: true,
    keyPath,
    deviceKey,
  };
}

export function deviceIdentity(deviceKey) {
  return {
    key_id: deviceKey.keyId,
    public_key_spki_der_base64: deviceKey.publicKeySpkiDerBase64,
    algorithm: deviceKey.algorithm,
    protection_class: deviceKey.protectionClass,
  };
}

export function deviceIdentityHash(deviceKey) {
  return base64url(crypto
    .createHash("sha256")
    .update(JSON.stringify({
      algorithm: deviceKey.algorithm,
      keyId: deviceKey.keyId,
      protectionClass: deviceKey.protectionClass,
      publicKeySpkiDerBase64: deviceKey.publicKeySpkiDerBase64,
    }))
    .digest());
}

function canonicalDeviceKeyPayload(payload) {
  switch (payload.type) {
    case "remoteControlClientConnection":
      return {
        accountUserId: payload.accountUserId,
        audience: payload.audience,
        clientId: payload.clientId,
        nonce: payload.nonce,
        scopes: payload.scopes,
        sessionId: payload.sessionId,
        targetOrigin: payload.targetOrigin,
        targetPath: payload.targetPath,
        tokenExpiresAt: payload.tokenExpiresAt,
        tokenSha256Base64url: payload.tokenSha256Base64url,
        type: payload.type,
      };

    case "remoteControlClientEnrollment":
      return {
        accountUserId: payload.accountUserId,
        audience: payload.audience,
        challengeExpiresAt: payload.challengeExpiresAt,
        challengeId: payload.challengeId,
        clientId: payload.clientId,
        deviceIdentitySha256Base64url: payload.deviceIdentitySha256Base64url,
        nonce: payload.nonce,
        targetOrigin: payload.targetOrigin,
        targetPath: payload.targetPath,
        type: payload.type,
      };

    default:
      throw new Error(`Unknown device-key payload type: ${String(payload.type)}`);
  }
}

export function signDeviceKeyPayload(deviceKey, payload) {
  const signedPayload = JSON.stringify({
    domain: SIGNING_DOMAIN,
    payload: canonicalDeviceKeyPayload(payload),
  });
  const signedPayloadBytes = utf8Bytes(signedPayload);
  const signature = crypto.sign("sha256", signedPayloadBytes, deviceKey.privateKey);
  const verified = crypto.verify("sha256", signedPayloadBytes, deviceKey.publicKey, signature);

  return {
    keyId: deviceKey.keyId,
    algorithm: deviceKey.algorithm,
    signedPayload,
    signedPayloadBase64: base64(signedPayloadBytes),
    signatureDerBase64: base64(signature),
    signatureDerLength: signature.length,
    verified,
  };
}
