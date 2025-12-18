import { ENROLL_COMPLETE_URL, TOKEN_ENDPOINT } from './urls.js';

export const DEVICE_CLIENT_ID = 'push-device-client';
export const DEVICE_CLIENT_SECRET = 'device-client-secret';

export async function postEnrollComplete(enrollReplyToken: string) {
  return await post(
    ENROLL_COMPLETE_URL,
    { 'Content-Type': 'application/json' },
    JSON.stringify({ token: enrollReplyToken }),
  );
}

export async function postAccessToken(dPop: string) {
  const header = {
    'Content-Type': 'application/x-www-form-urlencoded',
    DPoP: dPop,
  };
  const body = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: DEVICE_CLIENT_ID,
    client_secret: DEVICE_CLIENT_SECRET,
  });
  return await post(TOKEN_ENDPOINT, header, body);
}

export async function postChallengesResponse(
  url: string,
  dPop: string,
  accessToken: string,
  token: string,
) {
  const header = {
    Authorization: `DPoP ${accessToken}`,
    'Content-Type': 'application/json',
    DPoP: dPop,
  };
  const body = {
    token: token,
  };
  return await post(url, header, JSON.stringify(body));
}

export async function getPendingChallenges(url: string, dPop: string, accessToken: string) {
  const header = {
    Authorization: `DPoP ${accessToken}`,
    Accept: 'application/json',
    DPoP: dPop,
  };
  return await fetch(url, {
    method: 'GET',
    headers: header,
  });
}

async function post(url: string, headers?: HeadersInit, body?: any): Promise<Response> {
  return await fetch(url, {
    method: 'POST',
    headers: headers,
    body: body,
  });
}
