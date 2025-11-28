import {DEVICE_CLIENT_ID, DEVICE_CLIENT_SECRET} from "../server";
import { ENROLL_COMPLETE_URL, TOKEN_ENDPOINT} from "./urls";


export async function postEnrollComplete(enrollReplyToken: string) {
    const res = await post(ENROLL_COMPLETE_URL, {'Content-Type': 'application/json'}, JSON.stringify({token: enrollReplyToken}));
    if (!res.ok) {
        throw new Error(`HTTP ${res.status}: ${await res.text()}`);
    }
    return res.json();
}

export async function postConfirmLoginAccessToken(dPop : string) {
    const header = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'DPoP': dPop
    };
    const body = new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: DEVICE_CLIENT_ID,
        client_secret: DEVICE_CLIENT_SECRET,
    });
    const res = await post(TOKEN_ENDPOINT, header, body);
    if (!res.ok) {
        throw new Error(`HTTP ${res.status}: ${await res.text()}`);
    }
    return res;
}

export async function postChallengesResponse(url: string, dPop : string, accessToken: string, token: string) {
    const header = {
        'Authorization': `DPoP ${accessToken}`,
        'Content-Type': 'application/json',
        'DPoP': dPop
    };
    const body = {
        token : token
    }
    const res = await post(url, header, JSON.stringify(body));
    if (!res.ok) {
        throw new Error(`HTTP ${res.status}: ${await res.text()}`);
    }
    return res;
}

async function post(url: string, headers?: HeadersInit, body?: any): Promise<Response> {
    return await fetch(url, {
        method: 'POST',
        headers: headers,
        body: body
    });
}

