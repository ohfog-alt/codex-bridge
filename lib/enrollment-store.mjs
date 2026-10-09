import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export const DEFAULT_ENROLLMENT_PATH = path.join(
  os.homedir(),
  ".codex-bridge",
  "controller-enrollment.json",
);

export function readEnrollment(enrollmentPath = DEFAULT_ENROLLMENT_PATH) {
  return JSON.parse(fs.readFileSync(enrollmentPath, "utf8"));
}

export function writeEnrollment(enrollment, enrollmentPath = DEFAULT_ENROLLMENT_PATH) {
  fs.mkdirSync(path.dirname(enrollmentPath), { recursive: true, mode: 0o700 });
  fs.writeFileSync(enrollmentPath, JSON.stringify({
    version: 1,
    ...enrollment,
    updatedAt: new Date().toISOString(),
  }, null, 2), { mode: 0o600 });
  fs.chmodSync(enrollmentPath, 0o600);
}

export function buildEnrollmentRecord({ accountUserId, clientId, deviceKey, source }) {
  return {
    accountUserId,
    clientId,
    keyId: deviceKey.keyId,
    algorithm: deviceKey.algorithm,
    protectionClass: deviceKey.protectionClass,
    publicKeySpkiDerBase64: deviceKey.publicKeySpkiDerBase64,
    source,
  };
}
