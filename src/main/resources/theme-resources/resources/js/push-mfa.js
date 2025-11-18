(function (window, document) {
    'use strict';

    function ready(fn) {
        if (document.readyState !== 'loading') {
            fn();
        } else {
            document.addEventListener('DOMContentLoaded', fn);
        }
    }

    function submitForm(formId) {
        if (!formId) {
            return;
        }
        var form = document.getElementById(formId);
        if (!form) {
            return;
        }
        if (typeof form.requestSubmit === 'function') {
            form.requestSubmit();
        } else {
            form.submit();
        }
    }

    function renderQrCode(containerId, payload) {
        if (!containerId || !payload) {
            return;
        }
        var container = document.getElementById(containerId);
        if (!container || typeof QRCode === 'undefined') {
            return;
        }
        container.innerHTML = '';
        new QRCode(container, {
            text: payload,
            width: 240,
            height: 240,
            correctLevel: QRCode.CorrectLevel.M
        });
    }

    function createChallengeWatcher(config) {
        var eventsUrl = config.eventsUrl || '';
        var fallbackMillis = typeof config.fallbackMillis === 'number' ? config.fallbackMillis : 0;
        var formId = config.targetFormId;
        var fallbackTimer = null;

        function scheduleFallback() {
            if (!fallbackMillis || fallbackMillis <= 0) {
                return;
            }
            if (fallbackTimer) {
                clearTimeout(fallbackTimer);
            }
            fallbackTimer = window.setTimeout(function () {
                submitForm(formId);
            }, fallbackMillis);
        }

        if (!eventsUrl) {
            scheduleFallback();
            return;
        }

        if (typeof EventSource === 'undefined') {
            console.warn('push-mfa: EventSource unsupported, falling back to timer');
            scheduleFallback();
            return;
        }

        var source = new EventSource(eventsUrl);
        source.addEventListener('status', function (event) {
            try {
                var payload = event && event.data ? JSON.parse(event.data) : {};
                if (payload.status && payload.status !== 'PENDING') {
                    if (fallbackTimer) {
                        clearTimeout(fallbackTimer);
                    }
                    source.close();
                    submitForm(formId);
                }
            } catch (err) {
                console.warn('push-mfa: unable to parse challenge SSE payload', err);
            }
        });

        source.addEventListener('error', function (err) {
            console.warn('push-mfa: SSE error, switching to fallback timer', err);
            source.close();
            scheduleFallback();
        });
    }

    function initRegisterPage(root, config) {
        renderQrCode(config.qrContainerId, config.qrPayload);
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
            targetFormId: config.formId,
            fallbackMillis: config.fallbackMillis || 0
        });
    }

    function autoInit() {
        var nodes = document.querySelectorAll('[data-push-mfa-page]');
        nodes.forEach(function (node) {
            var page = node.getAttribute('data-push-mfa-page');
            var dataset = node.dataset || {};
            if (page === 'register') {
                initRegisterPage(node, {
                    eventsUrl: dataset.pushEventsUrl || '',
                    pollFormId: dataset.pushPollFormId || '',
                    qrContainerId: dataset.pushQrId || '',
                    qrPayload: dataset.pushQrValue || ''
                });
            } else if (page === 'login-wait') {
                var fallback = parseInt(dataset.pushFallbackMs, 10);
                initLoginPage(node, {
                    eventsUrl: dataset.pushEventsUrl || '',
                    formId: dataset.pushFormId || '',
                    fallbackMillis: isNaN(fallback) ? 0 : fallback
                });
            }
        });
    }

    window.KeycloakPushMfa = {
        initRegisterPage: initRegisterPage,
        initLoginPage: initLoginPage,
        autoInit: autoInit
    };

    ready(autoInit);
})(window, document);
