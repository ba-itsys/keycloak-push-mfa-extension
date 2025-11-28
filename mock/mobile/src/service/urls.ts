export const REALM_BASE = process.env.REALM_BASE ?? 'http://localhost:8080/realms/demo';
export const ENROLL_COMPLETE_URL = process.env.ENROLL_COMPLETE_URL ?? `${REALM_BASE}/push-mfa/enroll/complete`;
export const TOKEN_ENDPOINT = process.env.TOKEN_ENDPOINT ?? `${REALM_BASE}/protocol/openid-connect/token`;