'use strict';

(function () {

    function ready(fn) {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', fn);
        } else {
            fn();
        }
    }

    function submitForm(formId) {
        if (!formId) {
            console.warn('push-mfa: no formId provided');
            return;
        }
        const form = document.getElementById(formId);
        if (!form) {
            console.warn(`push-mfa: form with id ${formId} not found`);
            return;
        }

        // Submit form (which includes validation)
        form.requestSubmit();
    }

    function renderQrCode(containerId, payload) {
        if (!containerId || !payload) {
            return;
        }
        const container = document.getElementById(containerId);
        if (!container || typeof QRCode === 'undefined') {
            return;
        }
        container.innerHTML = '';

        // generate QR code
        new QRCode(container, {
            text: payload,
            width: 240,
            height: 240,
            correctLevel: QRCode.CorrectLevel.M
        });
    }

    function createChallengeWatcher(config) {
        const eventsUrl = config.eventsUrl || '';
        const formId = config.targetFormId;

        if (!eventsUrl) {
            return;
        }

        if (typeof EventSource === 'undefined') {
            console.warn('push-mfa: EventSource unsupported in this browser');
            return;
        }

        const source = new EventSource(eventsUrl);
        source.addEventListener('status', event => {
            try {
                const payload = event?.data ? JSON.parse(event.data) : {};
                if (payload.status && payload.status !== 'PENDING') {
                    source.close();
                    submitForm(formId);
                }
            } catch (err) {
                console.warn('push-mfa: unable to parse challenge SSE payload', err);
            }
        });

        source.addEventListener('error', err => {
            console.warn('push-mfa: SSE error (EventSource will retry automatically)', err);
        });
    }

    function initRegisterPage(root, config) {
        renderQrCode(config.qrContainerId, config.pushQrUri);
        if (config.eventsUrl && config.pollFormId) {
            createChallengeWatcher({
                eventsUrl: config.eventsUrl,
                targetFormId: config.pollFormId
            });
        }
    }

    function initLoginPage(root, config) {
        createChallengeWatcher({
            eventsUrl: config.eventsUrl,
            targetFormId: config.formId
        });
    }

    function autoInit() {
        const nodes = document.querySelectorAll('[data-push-mfa-page]');
        for (const node of nodes) {
            const page = node.getAttribute('data-push-mfa-page');
            const dataset = node.dataset || {};
            if (page === 'register') {
                initRegisterPage(node, {
                    eventsUrl: dataset.pushEventsUrl || '',
                    pollFormId: dataset.pushPollFormId || '',
                    qrContainerId: dataset.pushQrId || '',
                    pushQrUri: dataset.pushQrValue || ''
                });
            } else if (page === 'login-wait') {
                initLoginPage(node, {
                    eventsUrl: dataset.pushEventsUrl || '',
                    formId: dataset.pushFormId || ''
                });
            }
        }
    }

    // Register functions globally for manual use
    globalThis.KeycloakPushMfa = {
        initRegisterPage: initRegisterPage,
        initLoginPage: initLoginPage,
        autoInit: autoInit
    };

    ready(autoInit);
})();
