import { createHmac, pbkdf2Sync, randomBytes, timingSafeEqual } from "crypto";

export function randomId(prefix: string): string {
  return `${prefix}_${randomBytes(18).toString("hex")}`;
}

export function hashPassword(password: string): string {
  const salt = randomBytes(16).toString("hex");
  const hash = pbkdf2Sync(password, salt, 210_000, 32, "sha256").toString("hex");
  return `pbkdf2$${salt}$${hash}`;
}

export function verifyPassword(password: string, stored: string): boolean {
  const [, salt, expected] = stored.split("$");
  if (!salt || !expected) return false;
  const actual = pbkdf2Sync(password, salt, 210_000, 32, "sha256");
  const expectedBuf = Buffer.from(expected, "hex");
  return actual.length === expectedBuf.length && timingSafeEqual(actual, expectedBuf);
}

export function hmac(value: string, secret: string): string {
  return createHmac("sha256", secret).update(value).digest("hex");
}

export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

export function redactError(error: unknown): string {
  if (error instanceof Error) return error.name || "Error";
  return "unknown_error";
}

export function sanitizeScopes(scopes: string[], allowed: string[]): string[] {
  const allow = new Set(allowed);
  return Array.from(new Set(scopes.filter((scope) => allow.has(scope))));
}
