<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=((messagesPerField?has_content)!false) || (messageSummary??); section>
    <#if section = "header">
        ${msg("push-mfa-title")}
    <#elseif section = "form">
        <style>
            .kc-push-card {
                background: var(--pf-global--BackgroundColor--100, #fff);
                border: 1px solid var(--pf-global--BorderColor--100, #d2d2d2);
                border-radius: 4px;
                box-shadow: var(--pf-global--BoxShadow--md, 0 1px 2px rgba(0, 0, 0, 0.1));
                padding: 1.5rem;
                margin-top: 1.5rem;
            }
            .kc-push-status {
                display: flex;
                align-items: center;
                gap: 0.75rem;
                font-weight: 600;
                color: var(--pf-global--Color--100, #151515);
            }
            .kc-push-status__dot {
                width: 0.75rem;
                height: 0.75rem;
                border-radius: 50%;
                background: var(--pf-global--active-color--100, #0066cc);
                animation: kc-push-pulse 1.2s ease-in-out infinite;
            }
            .kc-push-hint {
                margin-top: 0.75rem;
                color: var(--pf-global--Color--200, #6a6e73);
                font-size: 0.95rem;
            }
            .kc-push-actions {
                display: flex;
                gap: 0.75rem;
                flex-wrap: wrap;
                margin-top: 1.5rem;
            }
            @keyframes kc-push-pulse {
                0%, 100% { transform: scale(1); opacity: 0.4; }
                50% { transform: scale(1.4); opacity: 1; }
            }
            .kc-push-token-card {
                margin-top: 1.25rem;
                padding: 1.25rem;
                border: 1px solid var(--pf-global--BorderColor--100, #d2d2d2);
                border-radius: 4px;
                background: var(--pf-global--BackgroundColor--100, #fff);
            }
            .kc-push-token {
                background: var(--pf-global--BackgroundColor--200, #f5f5f5);
                border: 1px solid var(--pf-global--BorderColor--200, #c7c7c7);
                border-radius: 4px;
                padding: 1rem;
                font-family: var(--pf-global--FontFamily--monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace);
                font-size: 0.9rem;
                max-height: 240px;
                overflow-y: auto;
                word-break: break-all;
            }
        </style>

        <div id="kc-push-wait-root"
             class="${properties.kcContentWrapperClass!}"
             data-push-mfa-page="login-wait"
             data-push-events-url="${pushChallengeWatchUrl!""}"
             data-push-form-id="kc-push-form">
            <div class="kc-push-card">
                <p class="kc-push-hint">${msg("push-mfa-wait-details")!"Approve the notification on your device to continue."}</p>

                <#if pushConfirmToken?? && pushPseudonymousId??>
                    <div class="kc-push-token-card">
                        <h4>${msg("push-mfa-message-title")!"Simulated Firebase payload"}</h4>
                        <p class="kc-push-hint">
                            ${msg("push-mfa-message-hint")!"This token travels via Firebase. Use it with scripts/confirm-login.sh \"<token>\"."}
                            <br/>
                            ${msg("push-mfa-message-user")!"Pseudonymous user id:"} <strong>${pushPseudonymousId!""}</strong>
                        </p>
                        <pre class="kc-push-token" id="kc-push-confirm-token">${pushConfirmToken!""}</pre>
                        <div class="kc-push-actions">
                            <button id="kc-copy-confirm-token"
                                    type="button"
                                    class="${properties.kcButtonClass!} ${properties.kcButtonSecondaryClass!}"
                                    data-default-label="${msg("push-mfa-message-copy")!"Copy confirm token"}"
                                    data-success-label="${msg("push-mfa-message-copied")!"Copied!"}">
                                ${msg("push-mfa-message-copy")!"Copy confirm token"}
                            </button>
                        </div>
                    </div>
                </#if>

                <form id="kc-push-form" class="kc-push-actions" action="${url.loginAction}" method="post">
                    <input type="hidden" name="challengeId" value="${challengeId}"/>
                    <button class="${properties.kcButtonClass!} ${properties.kcButtonSecondaryClass!}" name="cancel" value="true" type="submit">
                        ${msg("push-mfa-cancel")!"Cancel push"}
                    </button>
                </form>
            </div>
        </div>

        <script src="${url.resourcesPath}/js/push-mfa.js"></script>
        <script>
            (function () {
                var button = document.getElementById('kc-copy-confirm-token');
                var tokenBlock = document.getElementById('kc-push-confirm-token');
                if (!button || !tokenBlock) {
                    return;
                }
                var defaultLabel = button.dataset.defaultLabel || button.textContent || '';
                var successLabel = button.dataset.successLabel || defaultLabel;
                button.addEventListener('click', function () {
                    var value = (tokenBlock.textContent || '').trim();
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
                        button.textContent = successLabel;
                        setTimeout(function () {
                            button.textContent = defaultLabel;
                        }, 2000);
                    }).catch(function () {
                        button.textContent = defaultLabel;
                    });
                });
            })();
        </script>
    </#if>
</@layout.registrationLayout>
