import 'dotenv/config';
import express from 'express';
import bodyParser from 'body-parser';
import { getView } from './view.js';
import {
  postChallengesResponse,
  postAccessToken,
  postEnrollComplete,
} from './service/http-util.js';
import { CHALLENGE_URL, ENROLL_COMPLETE_URL, REALM_BASE, TOKEN_ENDPOINT } from './service/urls.js';
import {
  createEnrollmentJwt,
  createChallengeToken,
  createAccessToken,
  unpackEnrollmentToken,
  unpackLoginConfirmToken,
  getCredentialId,
} from './service/token-util.js';

const app = express();
app.use(bodyParser.json());

const PORT = Number(process.env.PORT ?? 3001);
const CHALLENGE_ID = 'CHALLENGE_ID';

app.post('/confirm-login', async (req, res) => {
  try {
    const { token } = req.body as { token?: string; context?: string };
    if (!token) {
      return res.status(400).json({ error: 'token required' });
    }

    const confirmValues = unpackLoginConfirmToken(token);
    if (confirmValues === null) {
      return res.status(400).json({ error: 'invalid confirm token payload' });
    }

    const userId = confirmValues.userId;
    const challengeId = confirmValues.challengeId;
    const dPopAccessToken = await createAccessToken(userId, TOKEN_ENDPOINT);
    const accessTokenResponse = await postAccessToken(dPopAccessToken);

    if (!accessTokenResponse.ok) {
      return res
        .status(accessTokenResponse.status)
        .json({ error: `${await accessTokenResponse.text()}` });
    }
    const accessTokenJson = (await accessTokenResponse.json()) as any;
    const accessToken = accessTokenJson['access_token'];

    const url = CHALLENGE_URL.replace(CHALLENGE_ID, challengeId);
    const dpopChallengeToken = await createAccessToken(userId, url);
    const challengeToken = await createChallengeToken(userId, challengeId);

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
      confirmLogin: 'POST /confirm-login { token}',
    },
    defaults: {
      REALM_BASE: REALM_BASE,
      ENROLL_COMPLETE_URL: ENROLL_COMPLETE_URL,
      TOKEN_ENDPOINT: TOKEN_ENDPOINT,
    },
  });
});
