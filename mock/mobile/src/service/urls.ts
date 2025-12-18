export const REALM_BASE = process.env.REALM_BASE ?? 'http://localhost:8080/realms/demo';
export const ENROLL_COMPLETE_URL =
  process.env.ENROLL_COMPLETE_URL ?? `${REALM_BASE}/push-mfa/enroll/complete`;
export const TOKEN_ENDPOINT =
  process.env.TOKEN_ENDPOINT ?? `${REALM_BASE}/protocol/openid-connect/token`;
export const CHALLENGE_URL =
  process.env.CHALLENGE_URL ?? `${REALM_BASE}/push-mfa/login/challenges/CHALLENGE_ID/respond`;
export const LOGIN_PENDING_URL =
  process.env.LOGIN_PENDING_URL ?? `${REALM_BASE}/push-mfa/login/pending`;
