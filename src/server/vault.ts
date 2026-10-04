import "server-only";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { DATA_DIR } from "./db";
import { insertPassword, sealedPasswordFor } from "./repo";

// Passwords are AES-256-GCM encrypted at rest. The master key lives in the macOS
// Keychain when available, otherwise in a 0600 file under .data/. Plaintext secrets
// are only ever decrypted to type them into a page — never returned to the model or UI.

const SERVICE = "dots-openai-vault";
const g = globalThis as unknown as { __dotsVaultKey?: Buffer };

function masterKey(): Buffer {
  if (g.__dotsVaultKey) return g.__dotsVaultKey;
  let hex: string | null = null;
  if (process.platform === "darwin") {
    try {
      hex = execFileSync("security", ["find-generic-password", "-s", SERVICE, "-a", "master", "-w"], { stdio: ["ignore", "pipe", "ignore"] })
        .toString().trim();
    } catch {
      const fresh = crypto.randomBytes(32).toString("hex");
      try {
        execFileSync("security", ["add-generic-password", "-s", SERVICE, "-a", "master", "-w", fresh, "-U"], { stdio: "ignore" });
        hex = fresh;
      } catch {
        // Never fall back to a key file next to the database by surprise: that would quietly turn "protected by
        // the Keychain" into "protected by nothing". Fail loudly unless the user explicitly opted in.
        if (process.env.DOTS_ALLOW_FILE_KEY !== "1") {
          throw new Error("Open Dot could not use the macOS Keychain for its encryption key, so saved passwords are disabled. Unlock the login keychain and restart the app (or set DOTS_ALLOW_FILE_KEY=1 to accept a key file instead).");
        }
      }
    }
  }
  if (!hex) {
    const file = path.join(DATA_DIR, "vault.key");
    fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
    if (!fs.existsSync(file)) fs.writeFileSync(file, crypto.randomBytes(32).toString("hex"), { mode: 0o600 });
    else fs.chmodSync(file, 0o600);
    hex = fs.readFileSync(file, "utf8").trim();
  }
  // A truncated or corrupted value would silently give a short, weak key.
  if (!/^[0-9a-f]{64}$/i.test(hex)) throw new Error("The vault key is malformed (expected 32 bytes of hex). Saved passwords are disabled until it is fixed.");
  g.__dotsVaultKey = Buffer.from(hex, "hex");
  return g.__dotsVaultKey;
}

/** Encrypt any secret with the vault key (also used for Composio OAuth tokens). */
export function seal(plain: string): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", masterKey(), iv);
  const data = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  return [iv, cipher.getAuthTag(), data].map((b) => b.toString("base64")).join(".");
}

export function unseal(sealed: string): string {
  const [iv, tag, data] = sealed.split(".").map((s) => Buffer.from(s, "base64"));
  const decipher = crypto.createDecipheriv("aes-256-gcm", masterKey(), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]).toString("utf8");
}

export function savePassword(site: string, username: string, password: string) {
  return insertPassword(site.trim(), username.trim(), seal(password));
}

export function credentialFor(site: string): { site: string; username: string; password: string } | null {
  const row = sealedPasswordFor(site);
  return row ? { site: row.site, username: row.username, password: unseal(row.sealed) } : null;
}
