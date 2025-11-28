import 'dotenv/config';
import express from 'express';
import bodyParser from 'body-parser';
// @ts-ignore
import { v4 as uuidv4 } from 'uuid';
import {
    exportJWK,
    generateKeyPair,
    SignJWT,
    decodeJwt,
    JWK,
    KeyLike,
    importPKCS8,
    importSPKI
} from 'jose';


import {getKeyPair} from "./model/keys";
import {getView} from "./view";
import {postEnrollComplete, postConfirmLoginAccessToken, postChallengesResponse} from "./service/http-util";
import {CHALLENGE_URL, TOKEN_ENDPOINT} from "./service/urls";

const app = express();
app.use(bodyParser.json());

// Env defaults (mirror bash)
export const DEVICE_CLIENT_ID = process.env.DEVICE_CLIENT_ID ?? 'push-device-client';
export const DEVICE_CLIENT_SECRET = process.env.DEVICE_CLIENT_SECRET ?? 'device-client-secret';
const DEVICE_TYPE = process.env.DEVICE_TYPE ?? 'ios';
const PUSH_PROVIDER_ID = process.env.PUSH_PROVIDER_ID ?? 'demo-push-provider-token';
const PUSH_PROVIDER_TYPE = process.env.PUSH_PROVIDER_TYPE ?? 'log';
const DEVICE_KEY_TYPE = (process.env.DEVICE_KEY_TYPE ?? 'RSA').toUpperCase();
const DEVICE_EC_CURVE = (process.env.DEVICE_EC_CURVE ?? 'P-256').toUpperCase();
const DEVICE_LABEL = process.env.DEVICE_LABEL ?? 'Demo Phone';
const PORT = Number(process.env.PORT ?? 3001);
const DEVICE_STATIC_ID = `device-static-id`;
const ALG_RS256 = 'RS256';

type DpopPayload = {
    htm?: string;
    htu?: string;
    sub?: string;
    deviceId?: string;
};

function defaultAlg(): string {
    if (DEVICE_KEY_TYPE === 'RSA') return process.env.DEVICE_SIGNING_ALG?.toUpperCase() ?? ALG_RS256;
    if (DEVICE_KEY_TYPE === 'EC') {
        const map: Record<string, { alg: string; crv: string }> = {
            'P-256': { alg: 'ES256', crv: 'P-256' },
            'P-384': { alg: 'ES384', crv: 'P-384' },
            'P-521': { alg: 'ES512', crv: 'P-521' }
        };
        const entry = map[DEVICE_EC_CURVE];
        if (!entry) throw new Error(`Unsupported DEVICE_EC_CURVE '${DEVICE_EC_CURVE}'`);
        return process.env.DEVICE_SIGNING_ALG?.toUpperCase() ?? entry.alg;
    }
    throw new Error(`Unsupported DEVICE_KEY_TYPE '${DEVICE_KEY_TYPE}'`);
}

function validateAlg(alg: string) {
    if (DEVICE_KEY_TYPE === 'RSA') {
        if (![ALG_RS256, 'RS384', 'RS512'].includes(alg)) {
            throw new Error(`Unsupported DEVICE_SIGNING_ALG '${alg}' for RSA (use RS256/RS384/RS512)`);
        }
    } else if (DEVICE_KEY_TYPE === 'EC') {
        const map: Record<string, string> = {
            'ES256': 'P-256',
            'ES384': 'P-384',
            'ES512': 'P-521'
        };
        const needCurve = map[alg];
        if (!needCurve) throw new Error(`Unsupported DEVICE_SIGNING_ALG '${alg}' for EC (use ES256/ES384/ES512)`);
        if (DEVICE_EC_CURVE !== needCurve) {
            throw new Error(`${alg} requires DEVICE_EC_CURVE=${needCurve}`);
        }
    } else {
        throw new Error(`Unsupported DEVICE_KEY_TYPE '${DEVICE_KEY_TYPE}'`);
    }
}

async function createDpopProof(dpopPayload: DpopPayload) {
    const { privateKeyString, publicKeyString } = getKeyPair();

    const  privateKey =  await importPKCS8(privateKeyString, ALG_RS256);
    const publicKey =  await importSPKI(publicKeyString, ALG_RS256);

    const jwkPub = await exportJWK(publicKey);

    return await new SignJWT(dpopPayload)
        .setProtectedHeader({ alg: ALG_RS256, typ: 'dpop+jwt', jwk: jwkPub })
        .setIssuedAt()
        .setJti(uuidv4())
        .sign(privateKey)

}

async function keyPairForDevice(alg: string): Promise<{ privateKey: KeyLike; publicKey: KeyLike; jwkPub: JWK }> {
    if (DEVICE_KEY_TYPE === 'RSA') {
        const { privateKeyString, publicKeyString } = getKeyPair();

        const  privateKey =  await importPKCS8(privateKeyString, ALG_RS256);
        const publicKey =  await importSPKI(publicKeyString, ALG_RS256);

        const jwkPub = await exportJWK(publicKey);

        return { privateKey, publicKey, jwkPub };
    } else {
        const curveMap: Record<string, string> = { 'P-256': 'P-256', 'P-384': 'P-384', 'P-521': 'P-521' };
        const crv = curveMap[DEVICE_EC_CURVE];
        const { publicKey, privateKey } = await generateKeyPair(alg, { crv });
        const jwkPub = await exportJWK(publicKey);
        jwkPub.kty = 'EC';
        jwkPub.crv = crv;
        jwkPub.alg = alg;
        jwkPub.use = 'sig';
        return { privateKey, publicKey, jwkPub };
    }
}

app.post('/confirm-login', async (req, res) => {
    try {
        const { token } = req.body as { token?: string };
        if (!token) return res.status(400).json({ error: 'token required' });

        const confirmPayload = decodeJwt(token);
        const challengeId = confirmPayload['cid'] as string;
        const userId = confirmPayload['sub'] as string;

        const index = "device-alias-".length;

        const ekid = userId?.slice(index) as string;

        const dpopTokenPayload : DpopPayload = {
            htm: 'POST',
            htu: TOKEN_ENDPOINT,
            sub: ekid,
            deviceId: DEVICE_STATIC_ID
        }

        const dPopToken = await createDpopProof(dpopTokenPayload);
        const tokenResponse = await postConfirmLoginAccessToken(dPopToken);

        if (!tokenResponse.ok) {
            throw new Error(`HTTP ${res.status}: ${await tokenResponse.text()}`);
        }

        const url = CHALLENGE_URL.replace('CHALLENGE_ID', challengeId);

        const dpopChallengePayload : DpopPayload = {
            htm: 'POST',
            htu: url,
            sub: ekid,
            deviceId: DEVICE_STATIC_ID
        }

        const dpopChallengeToken = await createDpopProof(dpopChallengePayload);

        let accessTokenJson = await tokenResponse.json();
        let accessToken = accessTokenJson['access_token'];

        const body :any = {
            cid: challengeId,
            credId: userId,
            deviceId: DEVICE_STATIC_ID,
            action: 'approve'
        }

        const signedToken = await signPayload(body);
        const challangeResponse = await postChallengesResponse(url, dpopChallengeToken, accessToken, signedToken)

        if (!challangeResponse.ok) {
            throw new Error(`HTTP ${res.status}: ${await challangeResponse.text()}`);
        }
    } catch (e: any) {
        res.status(500).json({ error: e.message ?? 'internal error' });
    }
});

async function signPayload(payload: any) {
    const exp = Math.floor(Date.now() / 1000) + 300;
    const { privateKey } = await keyPairForDevice(ALG_RS256);

    let protectedHeader = { alg: ALG_RS256, kid: 'DEVICE_KEY_ID', typ: 'JWT' };
    return await new SignJWT(payload)
        .setProtectedHeader(protectedHeader)
        .setExpirationTime(exp)
        .sign(privateKey);
}

app.post('/enroll', async (req, res) => {
    try {
        const { token } = req.body as { token?: string };
        if (!token) return res.status(400).json({ error: 'token required' });

        // Decode enrollment challenge JWS payload (no verification in mock)
        const enrollPayload = decodeJwt(token);
        const ENROLLMENT_ID = (enrollPayload as any).enrollmentId;
        const ENROLL_NONCE = (enrollPayload as any).nonce;
        const USER_ID = (enrollPayload as any).sub;
        if (!ENROLLMENT_ID || !ENROLL_NONCE || !USER_ID) {
            return res.status(400).json({ error: 'invalid enrollment token payload' });
        }

        // Generate ids (pseudonymous id, device, key id)
        const PSEUDONYMOUS_ID = process.env.PSEUDONYMOUS_ID ?? `device-alias-${USER_ID}`;

        const DEVICE_KEY_ID = process.env.DEVICE_KEY_ID ?? `device-key-${uuidv4()}`;
        // TODO impl defaultAlg()
        const signingAlg = ALG_RS256;
        validateAlg(signingAlg);

        // Generate key pair and public JWK
        const { privateKey, jwkPub } = await keyPairForDevice(signingAlg);
        jwkPub.kid = DEVICE_KEY_ID;

        // Build enrollment response JWT
        const exp = Math.floor(Date.now() / 1000) + 300;
        const cnf = { jwk: jwkPub };

        const enrollReplyJwt = await new SignJWT({
            enrollmentId: ENROLLMENT_ID,
            nonce: ENROLL_NONCE,
            sub: USER_ID,
            deviceType: DEVICE_TYPE,
            pushProviderId: PUSH_PROVIDER_ID,
            pushProviderType: PUSH_PROVIDER_TYPE,
            credentialId: PSEUDONYMOUS_ID,
            deviceId: DEVICE_STATIC_ID,
            deviceLabel: DEVICE_LABEL,
            cnf
        }).setProtectedHeader({ alg: signingAlg, kid: DEVICE_KEY_ID, typ: 'JWT' })
            .setExpirationTime(exp)
            .sign(privateKey);

        const keycloakResponse = await postEnrollComplete(enrollReplyJwt);

        res.json({
            enrollment: {
                enrollmentId: ENROLLMENT_ID,
                userId: USER_ID
            },
            keycloakResponse
        });
    } catch (e: any) {
        res.status(500).json({ error: e.message ?? 'internal error' });
    }
});

app.get('/', (_req, res) => {
    res.type('html').send(getView());
});

app.listen(PORT, () => {
    console.log(`Mock server listening on http://localhost:${PORT}`);
});
