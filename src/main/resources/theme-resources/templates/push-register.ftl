<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=((messagesPerField?has_content)!false) || (messageSummary??); section>
    <#if section = "header">
        ${msg("push-mfa-register-title")}
    <#elseif section = "form">
        <style>
            .kc-push-register-grid {
                display: flex;
                flex-wrap: wrap;
                gap: 1.5rem;
                align-items: flex-start;
                margin-top: 1.5rem;
            }
            .kc-push-register-card {
                flex: 1 1 280px;
                background: var(--pf-global--BackgroundColor--100, #fff);
                border: 1px solid var(--pf-global--BorderColor--100, #d2d2d2);
                border-radius: 4px;
                padding: 1.25rem;
                box-shadow: var(--pf-global--BoxShadow--md, 0 1px 2px rgba(0, 0, 0, 0.1));
            }
            .kc-push-register-token-group {
                display: flex;
                flex-direction: column;
                gap: 0.75rem;
            }
            .kc-push-register-token {
                background: var(--pf-global--BackgroundColor--200, #f5f5f5);
                border: 1px solid var(--pf-global--BorderColor--200, #c7c7c7);
                border-radius: 4px;
                padding: 1rem;
                font-family: var(--pf-global--FontFamily--monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace);
                font-size: 0.9rem;
                max-height: 240px;
                overflow-y: auto;
                white-space: pre-wrap;
                word-break: break-word;
            }
            .kc-push-register-actions {
                display: flex;
                flex-wrap: wrap;
                gap: 0.75rem;
            }
            .kc-push-register__hint {
                margin-top: 0.5rem;
                color: var(--pf-global--Color--200, #6a6e73);
                font-size: 0.9rem;
            }
            .kc-push-register-qr {
                display: flex;
                align-items: center;
                justify-content: center;
                min-height: 240px;
                padding: 0.5rem;
                background: var(--pf-global--BackgroundColor--200, #f5f5f5);
                border: 1px dashed var(--pf-global--BorderColor--200, #c7c7c7);
                border-radius: 4px;
            }
            .kc-push-register-copy.copied {
                background: var(--pf-global--BackgroundColor--success, #3e8635);
                color: #fff;
            }
            @media (max-width: 680px) {
                .kc-push-register-card {
                    flex-basis: 100%;
                }
            }
        </style>

        <div id="kc-push-register-root"
             class="${properties.kcContentWrapperClass!}"
             data-push-mfa-page="register"
             data-push-events-url="${enrollEventsUrl!""}"
             data-push-poll-form-id="kc-push-register-poll"
             data-push-qr-id="kc-push-qr"
             data-push-qr-value="${pushQrUri!""}">
            <div class="${properties.kcFormGroupClass!}">
                <p class="kc-push-register__hint">${msg("push-mfa-register-instructions", pushUsername!"")}</p>
                <p class="kc-push-register__hint">${msg("push-mfa-register-help")}</p>
            </div>

            <div class="kc-push-register-grid">
                <div class="kc-push-register-card">
                    <h3>${msg("push-mfa-register-qr-title")!"Scan to enroll"}</h3>
                    <div id="kc-push-qr" class="kc-push-register-qr" aria-live="polite"></div>
                    <p class="kc-push-register__hint">${msg("push-mfa-register-qr-hint")!"Scan with your companion app to autofill the enrollment token."}</p>
                </div>
                <div class="kc-push-register-card">
                    <h3>${msg("push-mfa-register-token-label")}</h3>
                    <div class="kc-push-register-token-group">
                        <pre id="kc-push-token" class="kc-push-register-token" tabindex="0">${enrollmentToken!''}</pre>
                        <div class="kc-push-register-actions">
                            <button id="kc-push-copy-token"
                                    type="button"
                                    class="${properties.kcButtonClass!} ${properties.kcButtonSecondaryClass!} kc-push-register-copy"
                                    data-default-label="${msg("push-mfa-register-copy-token")!"Copy token"}"
                                    data-success-label="${msg("push-mfa-register-copied")!"Copied"}">
                                ${msg("push-mfa-register-copy-token")!"Copy token"}
                            </button>
                        </div>
                        <p class="kc-push-register__hint">${msg("push-mfa-register-token-hint")}</p>
                    </div>
                </div>
            </div>

            <form id="kc-push-register-form" class="kc-push-register-actions" action="${url.loginAction}" method="post">
                <button class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!}" type="submit" name="confirm" value="true">
                    ${msg("push-mfa-register-confirm")!"I've enrolled"}
                </button>
                <button class="${properties.kcButtonClass!} ${properties.kcButtonSecondaryClass!}" type="submit" name="refresh" value="true">
                    ${msg("push-mfa-register-refresh")!"Generate new QR"}
                </button>
            </form>
            <form id="kc-push-register-poll" action="${url.loginAction}" method="post" style="display:none" aria-hidden="true">
                <input type="hidden" name="check" value="true"/>
            </form>
        </div>

        <script src="${url.resourcesPath}/js/qrcode.min.js"></script>
        <script src="${url.resourcesPath}/js/push-mfa.js"></script>
        <script>
            (function () {
                var button = document.getElementById('kc-push-copy-token');
                var tokenElement = document.getElementById('kc-push-token');
                if (!button || !tokenElement) {
                    return;
                }
                var defaultLabel = button.dataset.defaultLabel || button.textContent || '';
                var successLabel = button.dataset.successLabel || defaultLabel;
                button.addEventListener('click', function () {
                    var value = (tokenElement.textContent || '').trim();
                    if (!value) {
                        return;
                    }
                    function fallbackCopy() {
                        return new Promise(function (resolve, reject) {
                            try {
                                var textarea = document.createElement('textarea');
                                textarea.value = value;
                                textarea.style.position = 'fixed';
                                textarea.style.opacity = '0';
                                document.body.appendChild(textarea);
                                textarea.focus();
                                textarea.select();
                                var ok = document.execCommand && document.execCommand('copy');
                                document.body.removeChild(textarea);
                                if (!ok) {
                                    throw new Error('execCommand failed');
                                }
                                resolve();
                            } catch (err) {
                                reject(err);
                            }
                        });
                    }
                    var copyPromise = (navigator.clipboard && window.isSecureContext)
                        ? navigator.clipboard.writeText(value)
                        : fallbackCopy();
                    copyPromise.then(function () {
                        button.classList.add('copied');
                        button.textContent = successLabel;
                        setTimeout(function () {
                            button.classList.remove('copied');
                            button.textContent = defaultLabel;
                        }, 2000);
                    }).catch(function () {
                        button.classList.remove('copied');
                        button.textContent = defaultLabel;
                    });
                });
            })();
        </script>
    </#if>
</@layout.registrationLayout>
