/**
 * Pure rules for step-up re-verification on sensitive actions.
 * Passkey or TOTP are required once either is enrolled; an e-mail code is only a
 * fallback for accounts that have neither.
 * ROUT card actions accept every factor the member has active (passkey, TOTP,
 * SMS, recovery code, password), but never e-mail, and only after 2FA is on.
 */
export const STEP_UP_MAX_AGE_SEC = 120;
export const STEP_UP_REQUIRED = "STEP_UP_REQUIRED";
export const STEP_UP_COOKIE = "rout_stepup";

export type StepUpMethod = "passkey" | "totp" | "email" | "sms" | "backup" | "password";
export type StepUpAction = "vault_export" | "account_delete" | "oauth_secret" | "workspace_role" | "account_merge" | "oauth_subject_type" | "primary_email_change" | "app_email_reassign" | "app_email_revoke" | "passkey_add" | "recovery_vault" | "card_reveal" | "card_lifecycle";

export type EnrolledFactors = { passkey: boolean; totp: boolean; sms?: boolean; backup?: boolean; password?: boolean };

/** Actions on the private ROUT card (show its codes, freeze/block/replace it). */
export const CARD_STEP_UP_ACTIONS: readonly StepUpAction[] = ["card_reveal", "card_lifecycle"];
export const isCardStepUpAction = (action: StepUpAction | undefined) => !!action && CARD_STEP_UP_ACTIONS.includes(action);

/** A real second factor: passkey, authenticator app or a verified phone for SMS. */
export function hasSecondFactor(enrolled: EnrolledFactors): boolean {
  return enrolled.passkey || enrolled.totp || !!enrolled.sms;
}

export function allowedStepUpMethods(enrolled: EnrolledFactors, action?: StepUpAction): StepUpMethod[] {
  if (isCardStepUpAction(action)) {
    if (!hasSecondFactor(enrolled)) return [];
    const card: StepUpMethod[] = [];
    if (enrolled.passkey) card.push("passkey");
    if (enrolled.totp) card.push("totp");
    if (enrolled.sms) card.push("sms");
    if (enrolled.backup) card.push("backup");
    if (enrolled.password) card.push("password");
    return card;
  }
  const strong: StepUpMethod[] = [];
  if (enrolled.passkey) strong.push("passkey");
  if (enrolled.totp) strong.push("totp");
  return strong.length ? strong : ["email"];
}

/** Which proofs a given action accepts; card-only methods never unlock other actions. */
export function methodAcceptedFor(action: StepUpAction, method: StepUpMethod): boolean {
  if (isCardStepUpAction(action)) return method !== "email";
  return method === "passkey" || method === "totp" || method === "email";
}

const STEP_UP_METHODS: readonly StepUpMethod[] = ["passkey", "totp", "email", "sms", "backup", "password"];

export function stepUpPayload(userId: string, method: StepUpMethod, verifiedAtSec: number): string {
  return `v1.${userId}.${method}.${verifiedAtSec}`;
}

/** Parses a payload and checks owner + freshness; returns the method or null. */
export function checkStepUpPayload(payload: string, userId: string, nowSec: number): StepUpMethod | null {
  const parts = payload.split(".");
  if (parts.length !== 4) return null;
  const [v, uid, method, ts] = parts;
  if (v !== "v1" || uid !== userId) return null;
  if (!STEP_UP_METHODS.includes(method as StepUpMethod)) return null;
  const at = Number(ts);
  if (!Number.isFinite(at) || at > nowSec + 5) return null;
  return nowSec - at <= STEP_UP_MAX_AGE_SEC ? (method as StepUpMethod) : null;
}

export function isStepUpRequiredError(e: unknown): boolean {
  return e instanceof Error && e.message.includes(STEP_UP_REQUIRED);
}
