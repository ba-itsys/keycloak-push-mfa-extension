import {
  decodeJwt,
  exportJWK,
  importPKCS8,
  importSPKI,
  JWTHeaderParameters,
  JWTPayload,
  SignJWT,
} from 'jose';
import type { JWK, KeyLike } from 'jose';
import { getKeyPair } from '../model/keys.js';
import { v4 as uuidv4 } from 'uuid';

const DPOP_HEADER_TYPE = 'dpop+jwt';
const JWT_HEADER_TYPE = 'JWT';
const ALG_RS256 = 'RS256';
const KID = 'DEVICE_KEY_ID';
const DEVICE_KEY_SUFFIX = 'device-key-';
const DEVICE_STATIC_ID = `device-static-id`;
const DEVICE_ALIAS = '-device-alias-';
const DEVICE_TYPE = 'ios';
const PUSH_PROVIDER_ID = 'demo-push-provider-token';
const PUSH_PROVIDER_TYPE = 'log';
const DEVICE_LABEL = 'Demo Phone';

export type DpopPayload = {
  cid?: string;
  htm?: string;
  htu?: string;
  sub?: string;
  deviceId?: string;
  credId?: string;
  action?: string;
  userVerification?: string;
};

export type EnrollmentValues = {
  enrollmentId: string;
  nonce: string;
  userId: string;
};

export type ConfirmLoginValues = {
  challengeId: string;
  userId: string;
};

export function unpackEnrollmentToken(token: string): EnrollmentValues | null {
  const enrollPayload = decodeJwt(token);
  const enrollmentId = (enrollPayload as any).enrollmentId;
  const nonce = (enrollPayload as any).nonce;
  const userId = (enrollPayload as any).sub;

  if (!enrollmentId || !nonce || !userId) {
    return null;
  }
  return { enrollmentId, nonce, userId };
}

export function unpackLoginConfirmToken(token: string): ConfirmLoginValues | null {
  const confirmPayload = decodeJwt(token);

  const challengeId = (confirmPayload as any).cid;
  const userId = (confirmPayload as any).credId;

  if (!challengeId || !userId) {
    return null;
  }
  return { challengeId, userId };
}

export async function createConfirmJwt(payload: DpopPayload) {
  const exp = Math.floor(Date.now() / 1000) + 300;
  const { privateKey } = await keyPairForDevice(ALG_RS256);

  const protectedHeader = { alg: ALG_RS256, kid: KID, typ: JWT_HEADER_TYPE };

  return await signJwt(payload, protectedHeader, exp, privateKey);
}

export async function createEnrollmentJwt(enrollmentValues: EnrollmentValues, context: string) {
  const exp = Math.floor(Date.now() / 1000) + 300;
  const { privateKey, jwkPub } = await keyPairForDevice(ALG_RS256);

  const deviceKeyId = `${DEVICE_KEY_SUFFIX}${uuidv4()}`;

  const credentialId = getCredentialId(enrollmentValues.userId, context);
  const protectedHeader = { alg: ALG_RS256, kid: deviceKeyId, typ: JWT_HEADER_TYPE };

  jwkPub.kid = deviceKeyId;
  const cnf = { jwk: jwkPub };

  let jwtPayload = {
    enrollmentId: enrollmentValues.enrollmentId,
    nonce: enrollmentValues.nonce,
    sub: enrollmentValues.userId,
    deviceType: DEVICE_TYPE,
    pushProviderId: PUSH_PROVIDER_ID,
    pushProviderType: PUSH_PROVIDER_TYPE,
    credentialId: credentialId,
    deviceId: DEVICE_STATIC_ID,
    deviceLabel: DEVICE_LABEL,
    cnf,
  };
  console.debug('Creating Enrollment with credentialId: ', credentialId);
  return await signJwt(jwtPayload, protectedHeader, exp, privateKey);
}

export async function createAccessToken(userId: string, htu: string) {
  return await createDpopProof(userId, 'POST', htu);
}

export function extractUserIdFromCredentialId(credentialId: string): string | null {
  const aliasIndex = credentialId.indexOf(DEVICE_ALIAS);
  if (aliasIndex < 0) {
    return null;
  }
  return credentialId.slice(aliasIndex + DEVICE_ALIAS.length);
}

export async function createDpopProof(credentialId: string, method: string, htu: string) {
  const userId = extractUserIdFromCredentialId(credentialId) ?? credentialId;

  const dpopTokenPayload: DpopPayload = {
    htm: method,
    htu: htu,
    sub: userId,
    deviceId: DEVICE_STATIC_ID,
  };

  return await createDpopJwt(dpopTokenPayload);
}

export async function createChallengeToken(
  userId: string,
  challengeId: string,
  action: string = 'approve',
  userVerification?: string,
) {
  const body: DpopPayload = {
    cid: challengeId,
    credId: userId,
    deviceId: DEVICE_STATIC_ID,
    action: action,
  };
  if (userVerification && userVerification.trim().length > 0) {
    body.userVerification = userVerification;
  }
  return await createConfirmJwt(body);
}

export function getCredentialId(userId: string, context: string) {
  return `${context}${DEVICE_ALIAS}${userId}`;
}

async function createDpopJwt(dpopPayload: DpopPayload) {
  const { privateKey, jwkPub } = await keyPairForDevice(ALG_RS256);
  return await signDpopJwt(
    dpopPayload,
    { alg: ALG_RS256, typ: DPOP_HEADER_TYPE, jwk: jwkPub },
    uuidv4(),
    privateKey,
  );
}

async function keyPairForDevice(
  alg: string,
): Promise<{ privateKey: KeyLike; publicKey: KeyLike; jwkPub: JWK }> {
  if (alg === ALG_RS256) {
    const { privateKeyString, publicKeyString } = getKeyPair();

    const privateKey = await importPKCS8(privateKeyString, ALG_RS256);
    const publicKey = await importSPKI(publicKeyString, ALG_RS256);
    const jwkPub = await exportJWK(publicKey);

    return { privateKey, publicKey, jwkPub };
  }
  return Promise.reject();
}

async function signDpopJwt(
  payload: JWTPayload,
  protectedHeader: JWTHeaderParameters,
  jti: string,
  privateKey: KeyLike | Uint8Array | JWK,
) {
  return await new SignJWT(payload)
    .setProtectedHeader(protectedHeader)
    .setIssuedAt()
    .setJti(jti)
    .sign(privateKey);
}

async function signJwt(
  payload: JWTPayload,
  protectedHeader: JWTHeaderParameters,
  exp: number | string | Date,
  privateKey: KeyLike | Uint8Array | JWK,
) {
  return await new SignJWT(payload)
    .setProtectedHeader(protectedHeader)
    .setExpirationTime(exp)
    .sign(privateKey);
}
