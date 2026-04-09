import http from 'k6/http';
import encoding from 'k6/encoding';
import exec from 'k6/execution';
import { sleep } from 'k6';
import { parseHTML } from 'k6/html';
import { browser } from 'k6/browser';

const ADMIN_BASE_URI = env('LOAD_ADMIN_BASE_URI', 'http://localhost:18080');
const BROWSER_BASE_URIS = csvEnv('LOAD_BROWSER_BASE_URIS', 'http://localhost:18081,http://localhost:18082');
const ENROLLMENT_DEVICE_BASE_URIS = csvEnv(
    'LOAD_ENROLLMENT_DEVICE_BASE_URIS',
    'http://localhost:18081,http://localhost:18082',
);
const DEVICE_BASE_URIS = csvEnv('LOAD_DEVICE_BASE_URIS', 'http://localhost:18082,http://localhost:18081');
const REALM_NAME = env('LOAD_REALM', 'demo');
const ADMIN_REALM_NAME = env('LOAD_ADMIN_REALM', 'master');
const ADMIN_USERNAME = env('LOAD_ADMIN_USERNAME', 'admin');
const ADMIN_PASSWORD = env('LOAD_ADMIN_PASSWORD', 'admin');
const ADMIN_CLIENT_ID = env('LOAD_ADMIN_CLIENT_ID', 'admin-cli');
const BROWSER_CLIENT_ID = env('LOAD_BROWSER_CLIENT_ID', 'test-app');
const BROWSER_REDIRECT_URI = env('LOAD_BROWSER_REDIRECT_URI', '');
const DEVICE_CLIENT_ID = env('LOAD_DEVICE_CLIENT_ID', 'push-device-client');
const DEVICE_CLIENT_SECRET = env('LOAD_DEVICE_CLIENT_SECRET', 'device-client-secret');
const USER_PREFIX = env('LOAD_USER_PREFIX', 'load-user-');
const PASSWORD = env('LOAD_PASSWORD', 'load-test');
const USER_COUNT = intEnv('LOAD_USER_COUNT', 40);
const RATE_PER_SECOND = intEnv('LOAD_RATE_PER_SECOND', 10);
const DURATION_SECONDS = intEnv('LOAD_DURATION_SECONDS', 30);
const PRE_ALLOCATED_VUS = intEnv('LOAD_PRE_ALLOCATED_VUS', 40);
const MAX_VUS = intEnv('LOAD_MAX_VUS', PRE_ALLOCATED_VUS);
const AUTH_TIMEOUT_MS = intEnv('LOAD_AUTH_TIMEOUT_MS', 10000);
const LOGIN_COMPLETE_TIMEOUT_MS = intEnv('LOAD_LOGIN_COMPLETE_TIMEOUT_MS', 20000);
const CONFIGURE_PUSH_MFA = boolEnv('LOAD_CONFIGURE_PUSH_MFA', true);
const INSECURE_TLS = boolEnv('LOAD_INSECURE_TLS', false);

let vuState = null;

export const options = {
    insecureSkipTLSVerify: INSECURE_TLS,
    scenarios: {
        browser_sse: {
            executor: 'constant-arrival-rate',
            exec: 'loginFlow',
            rate: RATE_PER_SECOND,
            timeUnit: '1s',
            duration: `${DURATION_SECONDS}s`,
            preAllocatedVUs: PRE_ALLOCATED_VUS,
            maxVUs: MAX_VUS,
            options: {
                browser: {
                    type: 'chromium',
                },
            },
        },
    },
};

export async function setup() {
    console.log(`Admin base URI: ${ADMIN_BASE_URI}`);
    console.log(`Realm: ${REALM_NAME}`);
    console.log(`Browser base URIs: ${BROWSER_BASE_URIS.join(', ')}`);
    console.log(`Enrollment device base URIs: ${ENROLLMENT_DEVICE_BASE_URIS.join(', ')}`);
    console.log(`Device base URIs: ${DEVICE_BASE_URIS.join(', ')}`);
    console.log(`Browser client ID: ${BROWSER_CLIENT_ID}`);
    console.log(`Browser redirect URI: ${BROWSER_REDIRECT_URI}`);
    console.log(`Device client ID: ${DEVICE_CLIENT_ID}`);
    console.log(`Users: ${USER_COUNT}`);
    console.log(`Rate: ${RATE_PER_SECOND} logins/s`);
    console.log(`Duration: ${DURATION_SECONDS}s`);
    console.log(`Pre-allocated VUs: ${PRE_ALLOCATED_VUS}`);
    console.log(`Max VUs: ${MAX_VUS}`);

    const admin = new AdminApi();
    if (CONFIGURE_PUSH_MFA) {
        admin.configurePushMfaAuthenticator({
            userVerification: 'none',
            autoAddRequiredAction: 'true',
            waitChallengeEnabled: 'false',
        });
    }
    if (BROWSER_CLIENT_ID === 'test-app') {
        admin.ensureClientRedirectUris(
            BROWSER_CLIENT_ID,
            BROWSER_REDIRECT_URI
                ? [BROWSER_REDIRECT_URI]
                : BROWSER_BASE_URIS.map((baseUri) => buildBrowserRedirectUri(baseUri)),
        );
    }

    const users = [];
    const devices = [];
    for (let i = 1; i <= USER_COUNT; i += 1) {
        const username = `${USER_PREFIX}${i}`;
        admin.ensureUser(username, PASSWORD);
        admin.resetUserState(username);
        const user = { username, password: PASSWORD, index: i - 1 };
        const browserBaseUri = pickUri(BROWSER_BASE_URIS, user.index);
        const enrollmentDeviceBaseUri = pickUri(ENROLLMENT_DEVICE_BASE_URIS, user.index);
        const device = await createDeviceState();
        await enrollUser(user, browserBaseUri, enrollmentDeviceBaseUri, device);
        users.push(user);
        devices.push(device);
    }
    return { users, devices };
}

export async function loginFlow(data) {
    const user = data.users[(exec.vu.idInTest - 1) % data.users.length];
    if (!vuState) {
        const browserBaseUri = pickUri(BROWSER_BASE_URIS, user.index);
        vuState = {
            user,
            browserBaseUri,
            enrollmentDeviceBaseUri: pickUri(ENROLLMENT_DEVICE_BASE_URIS, user.index),
            deviceBaseUri: pickUri(DEVICE_BASE_URIS, user.index),
            expectedRedirectUri: buildBrowserRedirectUri(browserBaseUri),
            device: normalizeDevice(data.devices[user.index]),
        };
    }

    const context = await browser.newContext({ ignoreHTTPSErrors: INSECURE_TLS });
    const page = await context.newPage();
    try {
        await page.goto(buildAuthorizationUrl(vuState.browserBaseUri), { waitUntil: 'networkidle' });
        await page.locator('input[name="username"]').fill(vuState.user.username);
        await page.locator('input[name="password"]').fill(vuState.user.password);
        await Promise.all([
            page.locator('#kc-push-wait-root').waitFor({ state: 'visible', timeout: AUTH_TIMEOUT_MS }),
            page.locator('#kc-login').click(),
        ]);

        const confirmToken = await textContent(page, '#kc-push-confirm-token');
        const challengeId = await page.locator('form#kc-push-form input[name="challengeId"]').inputValue();
        await respondToChallenge(vuState.deviceBaseUri, vuState.device, confirmToken, challengeId);

        await page.waitForURL(new RegExp(`^${escapeRegex(trimTrailingSlash(vuState.expectedRedirectUri))}(?:\\?.*)?$`), {
            timeout: LOGIN_COMPLETE_TIMEOUT_MS,
        });
        const currentUrl = page.url();
        if (!/[?&]code=/.test(currentUrl)) {
            throw new Error(`Login completed without authorization code: ${currentUrl}`);
        }
    } finally {
        await page.close();
        await context.close();
    }
}

async function enrollUser(user, browserBaseUri, deviceBaseUri, device) {
    const jar = new http.CookieJar();
    const authResponse = requestPage(buildAuthorizationUrl(browserBaseUri), 'GET', null, jar);
    const loginForm = requireSingle(authResponse.document, 'form#kc-form-login', 'login form');
    const loginAction = resolveUrl(authResponse.url, loginForm.attr('action'));
    const loginParams = serializeForm(loginForm);
    loginParams.username = user.username;
    loginParams.password = user.password;

    const enrollResponse = requestPage(
        loginAction,
        'POST',
        encodeForm(loginParams),
        jar,
        { 'Content-Type': 'application/x-www-form-urlencoded' },
    );
    const token = requireText(enrollResponse.document, '#kc-push-token', 'enrollment token', enrollResponse);
    const registerForm = requireSingle(enrollResponse.document, '#kc-push-register-form', 'enrollment form');

    await completeEnrollment(deviceBaseUri, device, token);

    const registerAction = resolveUrl(enrollResponse.url, registerForm.attr('action'));
    const checkResponse = request(
        registerAction,
        'POST',
        'check=true',
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        false,
        jar,
    );
    if (checkResponse.status !== 302) {
        throw new Error(`Enrollment completion failed: ${checkResponse.status} ${checkResponse.body}`);
    }
}

async function completeEnrollment(baseUri, device, enrollmentToken) {
    const claims = parseJwt(enrollmentToken);
    device.userId = claims.sub;

    const bodyToken = await signJwt(
        {
            enrollmentId: claims.enrollmentId,
            nonce: claims.nonce,
            sub: device.userId,
            deviceType: 'ios',
            pushProviderId: device.pushProviderId,
            pushProviderType: device.pushProviderType,
            credentialId: device.deviceCredentialId,
            deviceId: device.deviceId,
            deviceLabel: device.deviceLabel,
            exp: nowEpochSeconds() + 300,
            cnf: { jwk: device.publicJwk },
        },
        device,
        { typ: 'JWT' },
    );

    const response = requestJson(
        resolveRealmUrl(baseUri, 'push-mfa/enroll/complete'),
        { token: bodyToken },
        {},
        false,
    );
    if (response.status !== 200) {
        throw new Error(`Enrollment failed: ${response.status} ${response.body}`);
    }
}

async function respondToChallenge(baseUri, device, confirmToken, challengeId) {
    const confirmClaims = parseJwt(confirmToken);
    const cid = confirmClaims.cid || challengeId;
    const loginToken = await signJwt(
        {
            cid,
            credId: confirmClaims.credId,
            deviceId: device.deviceId,
            action: 'approve',
            exp: nowEpochSeconds() + 120,
        },
        device,
        { typ: 'JWT' },
    );

    const respondUri = resolveRealmUrl(baseUri, `push-mfa/login/challenges/${cid}/respond`);
    const accessToken = await fetchDeviceAccessToken(baseUri, device);
    const response = requestJson(
        respondUri,
        { token: loginToken },
        {
            Authorization: `DPoP ${accessToken}`,
            DPoP: await createDpopProof('POST', respondUri, device),
        },
        false,
    );
    if (response.status !== 200) {
        throw new Error(`Challenge response failed: ${response.status} ${response.body}`);
    }
}

async function fetchDeviceAccessToken(baseUri, device) {
    const tokenUri = resolveRealmUrl(baseUri, 'protocol/openid-connect/token');
    const body = encodeForm({
        grant_type: 'client_credentials',
        client_id: DEVICE_CLIENT_ID,
        client_secret: DEVICE_CLIENT_SECRET,
    });

    let lastResponse = null;
    for (let attempt = 0; attempt < 10; attempt += 1) {
        lastResponse = request(tokenUri, 'POST', body, {
            'Content-Type': 'application/x-www-form-urlencoded',
            DPoP: await createDpopProof('POST', tokenUri, device),
        }, false);
        if (lastResponse.status === 200) {
            return lastResponse.json('access_token');
        }
        if (lastResponse.status === 400 && String(lastResponse.body).includes('"unauthorized_client"')) {
            sleep(0.1);
            continue;
        }
        break;
    }
    throw new Error(`Device token request failed: ${lastResponse && lastResponse.status} ${lastResponse && lastResponse.body}`);
}

function buildAuthorizationUrl(baseUri) {
    const state = randomId();
    const nonce = randomId();
    const redirectUri = buildBrowserRedirectUri(baseUri);
    const params = encodeForm({
        client_id: BROWSER_CLIENT_ID,
        redirect_uri: redirectUri,
        response_type: 'code',
        scope: 'openid',
        state,
        nonce,
    });
    return resolveRealmUrl(baseUri, `protocol/openid-connect/auth?${params}`);
}

function buildBrowserRedirectUri(baseUri) {
    if (BROWSER_REDIRECT_URI) {
        return BROWSER_REDIRECT_URI;
    }
    return `${trimTrailingSlash(baseUri)}/${BROWSER_CLIENT_ID}/callback`;
}

function resolveRealmUrl(baseUri, path) {
    return `${trimTrailingSlash(baseUri)}/realms/${encodeURIComponent(REALM_NAME)}/${path}`;
}

function requestPage(url, method = 'GET', body = null, jar = null, headers = {}) {
    const response = request(
        url,
        method,
        body,
        { Accept: 'text/html,application/xhtml+xml', ...headers },
        true,
        jar,
    );
    if (response.status < 200 || response.status >= 300) {
        throw new Error(`Expected HTML page from ${url} but received ${response.status}: ${response.body}`);
    }
    return { url: response.url, document: parseHTML(response.body), body: response.body };
}

function requestJson(url, payload, headers = {}, followSameHost = true) {
    const response = request(
        url,
        'POST',
        JSON.stringify(payload),
        { 'Content-Type': 'application/json', ...headers },
        followSameHost,
    );
    return response;
}

function request(url, method = 'GET', body = null, headers = {}, followSameHost = true, jar = null) {
    let currentUrl = url;
    let currentMethod = method;
    let currentBody = body;
    const origin = originOf(url);

    for (let i = 0; i < 10; i += 1) {
        const response = http.request(currentMethod, currentUrl, currentBody, {
            redirects: 0,
            headers,
            jar,
            timeout: `${AUTH_TIMEOUT_MS}ms`,
        });
        if (!isRedirect(response.status)) {
            return response;
        }
        if (!followSameHost) {
            return response;
        }
        const next = firstHeader(response, 'Location');
        if (!next) {
            return response;
        }
        const resolved = resolveUrl(currentUrl, next);
        if (originOf(resolved) !== origin) {
            return response;
        }
        currentUrl = resolved;
        currentMethod = 'GET';
        currentBody = null;
    }
    throw new Error(`Too many redirects for ${url}`);
}

class AdminApi {
    constructor() {
        this.accessToken = null;
    }

    configurePushMfaAuthenticator(config) {
        const execution = this.findExecution('browser-push-forms', 'push-mfa-authenticator');
        if (!execution) {
            throw new Error('Push MFA authenticator execution not found');
        }
        const executionId = execution.id;
        let configId = execution.authenticationConfig || execution.authenticatorConfig || null;
        if (!configId) {
            const payload = {
                alias: 'push-mfa-authenticator-config',
                config: {
                    userVerification: config.userVerification,
                    autoAddRequiredAction: config.autoAddRequiredAction,
                    waitChallengeEnabled: config.waitChallengeEnabled,
                },
            };
            const createResponse = this.authorizedRequest(
                this.adminRealmUrl(`authentication/executions/${executionId}/config`),
                'POST',
                JSON.stringify(payload),
            );
            if (createResponse.status !== 201) {
                throw new Error(`Failed to create authenticator config: ${createResponse.status} ${createResponse.body}`);
            }
        } else {
            const configUri = this.adminRealmUrl(`authentication/config/${configId}`);
            const existing = this.authorizedJson(configUri);
            const payload = {
                id: configId,
                alias: existing.alias || 'push-mfa-authenticator-config',
                config: {
                    ...(existing.config || {}),
                    userVerification: config.userVerification,
                    autoAddRequiredAction: config.autoAddRequiredAction,
                    waitChallengeEnabled: config.waitChallengeEnabled,
                },
            };
            const updateResponse = this.authorizedRequest(configUri, 'PUT', JSON.stringify(payload));
            if (updateResponse.status !== 204) {
                throw new Error(`Failed to update authenticator config: ${updateResponse.status} ${updateResponse.body}`);
            }
        }
        this.clearRealmCaches();
    }

    ensureUser(username, password) {
        let userId = this.findUserId(username);
        if (!userId) {
            userId = this.createUser(username);
        }
        this.setUserPassword(userId, password);
        return userId;
    }

    resetUserState(username) {
        const userId = this.findUserId(username);
        if (!userId) {
            throw new Error(`User not found: ${username}`);
        }
        this.deletePushCredentials(userId);
        this.logoutUser(userId);
        this.clearRealmCaches();
    }

    ensureClientRedirectUris(clientId, redirectUris) {
        const client = this.findClient(clientId);
        if (!client) {
            throw new Error(`Client not found: ${clientId}`);
        }
        const clientUri = this.adminRealmUrl(`clients/${client.id}`);
        const existing = this.authorizedJson(clientUri);
        const mergedRedirectUris = Array.from(
            new Set([...(existing.redirectUris || []), ...redirectUris]),
        );
        if (sameStringSet(existing.redirectUris || [], mergedRedirectUris)) {
            return;
        }
        const updateResponse = this.authorizedRequest(
            clientUri,
            'PUT',
            JSON.stringify({
                ...existing,
                redirectUris: mergedRedirectUris,
            }),
        );
        if (updateResponse.status !== 204) {
            throw new Error(`Client redirect update failed: ${updateResponse.status} ${updateResponse.body}`);
        }
    }

    findUserId(username) {
        const response = this.authorizedRequest(this.adminRealmUrl(`users?username=${encodeURIComponent(username)}`), 'GET');
        if (response.status !== 200) {
            throw new Error(`User lookup failed: ${response.status} ${response.body}`);
        }
        const users = JSON.parse(response.body);
        return Array.isArray(users) && users.length > 0 ? users[0].id : null;
    }

    createUser(username) {
        const payload = JSON.stringify({ username, enabled: true });
        const response = this.authorizedRequest(this.adminRealmUrl('users'), 'POST', payload);
        if (response.status === 201) {
            const location = firstHeader(response, 'Location');
            return location.substring(location.lastIndexOf('/') + 1);
        }
        if (response.status === 409) {
            const userId = this.findUserId(username);
            if (userId) {
                return userId;
            }
        }
        throw new Error(`User create failed: ${response.status} ${response.body}`);
    }

    setUserPassword(userId, password) {
        const payload = JSON.stringify({ type: 'password', value: password, temporary: false });
        const response = this.authorizedRequest(this.adminRealmUrl(`users/${userId}/reset-password`), 'PUT', payload);
        if (response.status !== 204) {
            throw new Error(`Password reset failed: ${response.status} ${response.body}`);
        }
    }

    deletePushCredentials(userId) {
        const response = this.authorizedRequest(this.adminRealmUrl(`users/${userId}/credentials`), 'GET');
        if (response.status !== 200) {
            throw new Error(`Credential fetch failed: ${response.status} ${response.body}`);
        }
        for (const item of JSON.parse(response.body)) {
            if (item.type !== 'push-mfa' || !item.id) {
                continue;
            }
            const deleteResponse = this.authorizedRequest(
                this.adminRealmUrl(`users/${userId}/credentials/${item.id}`),
                'DELETE',
            );
            if (deleteResponse.status !== 204) {
                throw new Error(`Credential delete failed: ${deleteResponse.status} ${deleteResponse.body}`);
            }
        }
    }

    logoutUser(userId) {
        const response = this.authorizedRequest(this.adminRealmUrl(`users/${userId}/logout`), 'POST');
        if (response.status !== 204) {
            throw new Error(`Logout failed: ${response.status} ${response.body}`);
        }
    }

    clearRealmCaches() {
        for (const path of ['clear-realm-cache', 'clear-user-cache']) {
            const response = this.authorizedRequest(this.adminRealmUrl(path), 'POST');
            if (response.status !== 204) {
                throw new Error(`Cache clear failed for ${path}: ${response.status} ${response.body}`);
            }
        }
    }

    findExecution(flowAlias, authenticatorId) {
        const executions = this.authorizedJson(this.adminRealmUrl(`authentication/flows/${flowAlias}/executions`));
        return executions.find(
            (item) => item.authenticator === authenticatorId || item.providerId === authenticatorId,
        );
    }

    findClient(clientId) {
        const clients = this.authorizedJson(
            this.adminRealmUrl(`clients?clientId=${encodeURIComponent(clientId)}`),
        );
        return Array.isArray(clients) && clients.length > 0 ? clients[0] : null;
    }

    adminRealmUrl(path) {
        return `${trimTrailingSlash(ADMIN_BASE_URI)}/admin/realms/${encodeURIComponent(REALM_NAME)}/${path}`;
    }

    authorizedJson(url) {
        const response = this.authorizedRequest(url, 'GET');
        if (response.status !== 200) {
            throw new Error(`Admin GET failed: ${response.status} ${response.body}`);
        }
        return JSON.parse(response.body);
    }

    authorizedRequest(url, method, body = null) {
        const headers = {
            Authorization: `Bearer ${this.ensureAccessToken()}`,
        };
        if (body !== null) {
            headers['Content-Type'] = 'application/json';
        }
        const response = http.request(method, url, body, { redirects: 0, headers, timeout: `${AUTH_TIMEOUT_MS}ms` });
        if (response.status === 401) {
            this.accessToken = null;
            headers.Authorization = `Bearer ${this.ensureAccessToken()}`;
            return http.request(method, url, body, { redirects: 0, headers, timeout: `${AUTH_TIMEOUT_MS}ms` });
        }
        return response;
    }

    ensureAccessToken() {
        if (this.accessToken) {
            return this.accessToken;
        }
        const body = encodeForm({
            grant_type: 'password',
            client_id: ADMIN_CLIENT_ID,
            username: ADMIN_USERNAME,
            password: ADMIN_PASSWORD,
        });
        const tokenUri = `${trimTrailingSlash(ADMIN_BASE_URI)}/realms/${encodeURIComponent(
            ADMIN_REALM_NAME,
        )}/protocol/openid-connect/token`;
        const response = http.post(tokenUri, body, {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            redirects: 0,
            timeout: `${AUTH_TIMEOUT_MS}ms`,
        });
        if (response.status !== 200) {
            throw new Error(`Admin token request failed: ${response.status} ${response.body}`);
        }
        this.accessToken = response.json('access_token');
        return this.accessToken;
    }
}

async function createDeviceState() {
    const keyPair = await crypto.subtle.generateKey(
        {
            name: 'RSASSA-PKCS1-v1_5',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256',
        },
        true,
        ['sign', 'verify'],
    );
    const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
    const privateJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
    return {
        keyId: `user-key-${randomId()}`,
        algorithm: 'RS256',
        publicJwk,
        privateJwk,
        deviceId: `device-${randomId()}`,
        deviceCredentialId: `device-credential-${randomId()}`,
        deviceLabel: 'k6 Load Test Device',
        pushProviderId: 'mock-push-provider',
        pushProviderType: 'log',
        userId: null,
    };
}

async function createDpopProof(method, uri, device) {
    return signJwt(
        {
            htm: method,
            htu: uri,
            sub: device.userId,
            deviceId: device.deviceId,
            iat: nowEpochSeconds(),
            jti: randomId(),
        },
        device,
        { typ: 'dpop+jwt', jwk: device.publicJwk },
    );
}

async function signJwt(claims, device, extraHeader = {}) {
    const privateKey = await ensurePrivateKey(device);
    const header = {
        alg: device.algorithm,
        kid: device.keyId,
        ...extraHeader,
    };
    const input = `${base64UrlEncode(JSON.stringify(header))}.${base64UrlEncode(JSON.stringify(claims))}`;
    const signature = await crypto.subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, privateKey, textEncode(input));
    return `${input}.${encoding.b64encode(signature, 'rawurl')}`;
}

function parseJwt(token) {
    const parts = token.split('.');
    if (parts.length < 2) {
        throw new Error(`Invalid JWT: ${token}`);
    }
    return JSON.parse(encoding.b64decode(parts[1], 'rawurl', 's'));
}

async function textContent(page, selector) {
    const value = await page.locator(selector).textContent();
    return value ? value.trim() : '';
}

function serializeForm(selection) {
    return decodeForm(selection.serialize());
}

function decodeForm(value) {
    const params = {};
    if (!value) {
        return params;
    }
    for (const pair of value.split('&')) {
        if (!pair) {
            continue;
        }
        const [rawKey, rawValue = ''] = pair.split('=', 2);
        params[decodeURIComponent(rawKey)] = decodeURIComponent(rawValue.replace(/\+/g, ' '));
    }
    return params;
}

function encodeForm(params) {
    return Object.entries(params)
        .filter(([, value]) => value !== undefined && value !== null)
        .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`)
        .join('&');
}

function requireSingle(doc, selector, label, response = null) {
    const node = doc.find(selector);
    if (!node || node.size() === 0) {
        throw new Error(describeMissing(label, response));
    }
    return node.first();
}

function requireText(doc, selector, label, response = null) {
    const node = requireSingle(doc, selector, label, response);
    const text = node.text();
    if (!text) {
        throw new Error(describeMissing(label, response));
    }
    return text.trim();
}

function describeMissing(label, response) {
    if (!response) {
        return `Missing ${label}`;
    }
    const body = String(response.body || '').replace(/\s+/g, ' ').trim().slice(0, 400);
    return `Missing ${label} from ${response.url}: ${body}`;
}

function resolveUrl(base, relative) {
    if (relative.startsWith('http://') || relative.startsWith('https://')) {
        return relative;
    }
    if (relative.startsWith('/')) {
        return `${originOf(base)}${relative}`;
    }
    const normalizedBase = base.split('#')[0].split('?')[0];
    const slash = normalizedBase.lastIndexOf('/');
    const prefix = slash >= 0 ? normalizedBase.slice(0, slash + 1) : `${normalizedBase}/`;
    return `${prefix}${relative}`;
}

function originOf(url) {
    const match = String(url).match(/^(https?:\/\/[^/]+)/i);
    if (!match) {
        throw new Error(`Unable to determine origin for ${url}`);
    }
    return match[1];
}

function firstHeader(response, name) {
    if (!response || !response.headers) {
        return null;
    }
    const value = response.headers[name] || response.headers[name.toLowerCase()];
    if (Array.isArray(value)) {
        return value.length > 0 ? value[0] : null;
    }
    return value || null;
}

function sameStringSet(left, right) {
    if (left.length !== right.length) {
        return false;
    }
    const sortedLeft = [...left].sort();
    const sortedRight = [...right].sort();
    return sortedLeft.every((value, index) => value === sortedRight[index]);
}

function escapeRegex(value) {
    return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function trimTrailingSlash(value) {
    return value.endsWith('/') ? value.slice(0, -1) : value;
}

function isRedirect(status) {
    return status >= 300 && status < 400;
}

function pickUri(values, index) {
    return values[index % values.length];
}

function csvEnv(name, fallback) {
    return env(name, fallback)
        .split(',')
        .map((value) => value.trim())
        .filter((value) => value.length > 0);
}

function env(name, fallback) {
    return __ENV[name] && __ENV[name] !== '' ? __ENV[name] : fallback;
}

function intEnv(name, fallback) {
    const value = __ENV[name];
    return value ? parseInt(value, 10) : fallback;
}

function boolEnv(name, fallback) {
    const value = __ENV[name];
    if (!value) {
        return fallback;
    }
    return value.toLowerCase() === 'true';
}

function nowEpochSeconds() {
    return Math.floor(Date.now() / 1000);
}

function randomId() {
    return crypto.randomUUID();
}

function base64UrlEncode(value) {
    return encoding.b64encode(value, 'rawurl');
}

function textEncode(value) {
    const bytes = new Uint8Array(value.length);
    for (let i = 0; i < value.length; i += 1) {
        bytes[i] = value.charCodeAt(i);
    }
    return bytes;
}

async function ensurePrivateKey(device) {
    if (device.privateKey) {
        return device.privateKey;
    }
    device.privateKey = await crypto.subtle.importKey(
        'jwk',
        device.privateJwk,
        {
            name: 'RSASSA-PKCS1-v1_5',
            hash: 'SHA-256',
        },
        false,
        ['sign'],
    );
    return device.privateKey;
}

function normalizeDevice(device) {
    if (!device) {
        throw new Error('Missing device state from setup');
    }
    return {
        algorithm: 'RS256',
        ...device,
    };
}
