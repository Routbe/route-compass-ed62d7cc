/**
 * Short unlock window for the private side of the ROUT card (back QR, live code,
 * wallet key). Opened only right after a fresh verification, proven by an
 * HMAC-signed HttpOnly cookie bound to the member, closed on lock/freeze/replace.
 */
import { hmacSha256Hex } from "@/lib/audit-chain";
import { CARD_UNLOCK_COOKIE, CARD_UNLOCK_TTL_S, cardUnlockPayload, checkCardUnlockPayload } from "./card-lifecycle";

async function secret(): Promise<string> {
  const { resolveAuthSecret } = await import("@/lib/better-auth.server");
  const s = resolveAuthSecret();
  if (!s) throw new Error("auth secret missing");
  return `card-unlock:${s.secret}`;
}

function safeEqual(a: string, b: string) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

/** Expiry in ms of a valid cookie value for this member, else null. Exported for tests. */
export async function verifyCardUnlockCookie(raw: string | null | undefined, userId: string, nowMs = Date.now()): Promise<number | null> {
  if (!raw) return null;
  const i = raw.lastIndexOf(".");
  if (i < 0) return null;
  const payload = raw.slice(0, i);
  if (!safeEqual(raw.slice(i + 1), await hmacSha256Hex(await secret(), payload))) return null;
  const exp = checkCardUnlockPayload(payload, userId, Math.floor(nowMs / 1000));
  return exp === null ? null : exp * 1000;
}

export async function signCardUnlock(userId: string, nowMs = Date.now()): Promise<{ value: string; expiresAt: number }> {
  const exp = Math.floor(nowMs / 1000) + CARD_UNLOCK_TTL_S;
  const payload = cardUnlockPayload(userId, exp);
  return { value: `${payload}.${await hmacSha256Hex(await secret(), payload)}`, expiresAt: exp * 1000 };
}

/** Opens the window (call only after ensureStepUpSession). Returns its expiry in ms. */
export async function openCardUnlock(userId: string): Promise<number> {
  const { value, expiresAt } = await signCardUnlock(userId);
  const { writeResponseCookie } = await import("@/lib/request-context");
  writeResponseCookie(CARD_UNLOCK_COOKIE, value, { httpOnly: true, secure: true, sameSite: "strict", path: "/", maxAge: CARD_UNLOCK_TTL_S });
  const { recordSecurityEvent } = await import("@/lib/audit-log.server");
  void recordSecurityEvent({ eventType: "card.unlocked", userId, payload: {} });
  return expiresAt;
}

export async function cardUnlockedUntil(userId: string): Promise<number | null> {
  const { readRequestCookie } = await import("@/lib/request-context");
  return verifyCardUnlockCookie(readRequestCookie(CARD_UNLOCK_COOKIE), userId);
}

export async function closeCardUnlock(): Promise<void> {
  const { clearResponseCookie } = await import("@/lib/request-context");
  clearResponseCookie(CARD_UNLOCK_COOKIE, { path: "/" });
}
