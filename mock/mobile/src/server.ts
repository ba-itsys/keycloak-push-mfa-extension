import 'dotenv/config';
import express from 'express';
import bodyParser from 'body-parser';
import { getView } from './view.js';
import {
  postChallengesResponse,
  postAccessToken,
  postEnrollComplete,
  getPendingChallenges,
} from './service/http-util.js';
import {
  CHALLENGE_URL,
  ENROLL_COMPLETE_URL,
  LOGIN_PENDING_URL,
  REALM_BASE,
  TOKEN_ENDPOINT,
} from './service/urls.js';
import {
  createEnrollmentJwt,
  createChallengeToken,
  createDpopProof,
  unpackEnrollmentToken,
  unpackLoginConfirmToken,
  extractUserIdFromCredentialId,
  getCredentialId,
} from './service/token-util.js';

const app = express();
app.use(bodyParser.json());

const PORT = Number(process.env.PORT ?? 3001);
const CHALLENGE_ID = 'CHALLENGE_ID';

app.post('/confirm-login', async (req, res) => {
  try {
    const { token, context, userVerification, action } = req.body as {
      token?: string;
      context?: string;
      userVerification?: string;
      action?: string;
    };
    if (!token) {
      return res.status(400).json({ error: 'token required' });
    }

    const effectiveAction = (action ?? 'approve').trim().toLowerCase();
    const effectiveUserVerification = userVerification ?? context;

    const confirmValues = unpackLoginConfirmToken(token);
    if (confirmValues === null) {
      return res.status(400).json({ error: 'invalid confirm token payload' });
    }

    const credentialId = confirmValues.userId;
    const challengeId = confirmValues.challengeId;
    const userId = extractUserIdFromCredentialId(credentialId);
    if (!userId) {
      return res.status(400).json({ error: 'unable to extract user id from credential id' });
    }

    const dPopAccessToken = await createDpopProof(credentialId, 'POST', TOKEN_ENDPOINT);
    const accessTokenResponse = await postAccessToken(dPopAccessToken);

    if (!accessTokenResponse.ok) {
      return res
        .status(accessTokenResponse.status)
        .json({ error: `${await accessTokenResponse.text()}` });
    }
    const accessTokenJson = (await accessTokenResponse.json()) as any;
    const accessToken = accessTokenJson['access_token'];

    const pendingUrl = new URL(LOGIN_PENDING_URL);
    pendingUrl.searchParams.set('userId', userId);
    const pendingHtu = pendingUrl.toString();
    const pendingDpop = await createDpopProof(credentialId, 'GET', pendingHtu);
    const pendingResponse = await getPendingChallenges(pendingHtu, pendingDpop, accessToken);
    if (!pendingResponse.ok) {
      return res.status(pendingResponse.status).json({ error: `${await pendingResponse.text()}` });
    }
    const pendingJson = (await pendingResponse.json()) as any;
    const pendingChallenge =
      pendingJson?.challenges?.find((candidate: any) => candidate?.cid === challengeId) ?? null;
    const pendingUserVerification = pendingChallenge?.userVerification ?? null;

    if (
      effectiveAction === 'approve' &&
      pendingUserVerification != null &&
      (!effectiveUserVerification || effectiveUserVerification.trim().length === 0)
    ) {
      return res.status(400).json({
        error: 'userVerification required',
        userVerification: pendingUserVerification,
      });
    }

    const url = CHALLENGE_URL.replace(CHALLENGE_ID, challengeId);
    const dpopChallengeToken = await createDpopProof(credentialId, 'POST', url);
    const challengeToken = await createChallengeToken(
      credentialId,
      challengeId,
      effectiveAction,
      effectiveAction === 'approve' ? effectiveUserVerification : undefined,
    );

    const challangeResponse = await postChallengesResponse(
      url,
      dpopChallengeToken,
      accessToken,
      challengeToken,
    );

    if (!challangeResponse.ok) {
      return res
        .status(challangeResponse.status)
        .json({ error: `${await challangeResponse.text()}` });
    }

    res.json({
      userId: userId,
      responseStatus: challangeResponse.status,
      userVerification: pendingUserVerification,
    });
  } catch (e: any) {
    res.status(500).json({ error: e.message ?? 'internal error' });
  }
});

app.post('/enroll', async (req, res) => {
  try {
    const { token, context } = req.body as { token?: string; context?: string };
    if (!token) {
      return res.status(400).json({ error: 'token required' });
    }
    const ctx = context ? context : '';
    const enrollmentValues = unpackEnrollmentToken(token);
    if (enrollmentValues === null) {
      return res.status(400).json({ error: 'invalid enrollment token payload' });
    }

    const enrollmentJwt = await createEnrollmentJwt(enrollmentValues, ctx);
    const keycloakResponse = await postEnrollComplete(enrollmentJwt);

    if (!keycloakResponse.ok) {
      return res
        .status(keycloakResponse.status)
        .json({ error: `${await keycloakResponse.text()}` });
    }

    res.json({
      enrollment: {
        enrollmentId: enrollmentValues.enrollmentId,
        userId: getCredentialId(enrollmentValues.userId, ctx),
      },
      responseStatus: keycloakResponse.status,
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

app.get('/meta', (_req, res) => {
  res.json({
    endpoints: {
      enroll: 'POST /enroll { token, context }',
      confirmLogin: 'POST /confirm-login { token, action?, userVerification? }',
    },
    defaults: {
      REALM_BASE: REALM_BASE,
      ENROLL_COMPLETE_URL: ENROLL_COMPLETE_URL,
      TOKEN_ENDPOINT: TOKEN_ENDPOINT,
    },
  });
});
