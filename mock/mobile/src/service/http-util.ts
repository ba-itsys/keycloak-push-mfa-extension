import {DEVICE_CLIENT_ID, DEVICE_CLIENT_SECRET} from "../server";


export async function postEnrollComplete(enrollReplyToken: string) {
    const url = 'http://localhost:8080/realms/demo/push-mfa/enroll/complete';
    const res = await post(url, {'Content-Type': 'application/json'}, JSON.stringify({token: enrollReplyToken}));
    if (!res.ok) {
        throw new Error(`HTTP ${res.status}: ${await res.text()}`);
    }
    return res.json();
}

export async function postConfirmLoginAccessToken(dPop : string) {
    const url = 'http://localhost:8080/realms/demo/protocol/openid-connect/token';
    const header = {
        'Content-Type': 'application/x-www-form-urlencoded',
        DPoP: dPop
    };
    const body = new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: DEVICE_CLIENT_ID,
        client_secret: DEVICE_CLIENT_SECRET,
    });
    const res = await post(url, header, body);
    if (!res.ok) {
        throw new Error(`HTTP ${res.status}: ${await res.text()}`);
    }
    return res.json();
}


async function post(url: string, headers?: HeadersInit, body?: BodyInit): Promise<Response> {
    return await fetch(url, {
        method: 'POST',
        headers: headers,
        body: body
    });
}

