<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=((messagesPerField?has_content)!false) || (messageSummary??); section>
    <#if section = "header">
        ${msg("push-mfa-title")}
    <#elseif section = "form">
        <style>
            .kc-push-card {
                background: var(--pf-v5-global--BackgroundColor--100, #fff);
                border: 1px solid var(--pf-v5-global--BorderColor--100, #d2d2d2);
                border-radius: 4px;
                box-shadow: var(--pf-global--BoxShadow--md, 0 1px 2px rgba(0, 0, 0, 0.1));
                padding: 1.5rem;
                margin-top: 1.5rem;
            }

            .kc-push-hint {
                margin-top: 0.75rem;
                color: var(--pf-v5-global--Color--200, #6a6e73);
                font-size: 0.95rem;
            }

            .kc-push-actions {
                display: flex;
                gap: 0.75rem;
                flex-wrap: wrap;
                margin-top: 1.5rem;
            }

            @keyframes kc-push-pulse {
                0%, 100% {
                    transform: scale(1);
                    opacity: 0.4;
                }
                50% {
                    transform: scale(1.4);
                    opacity: 1;
                }
            }

            .kc-push-token-card {
                margin-top: 1.25rem;
                padding: 1.25rem;
                border: 1px solid var(--pf-v5-global--BorderColor--100, #d2d2d2);
                border-radius: 4px;
                background: var(--pf-v5-global--BackgroundColor--100, #fff);
            }

            .kc-push-token {
                background: var(--pf-v5-global--BackgroundColor--200, #f5f5f5);
                border: 1px solid var(--pf-v5-global--BorderColor--200, #c7c7c7);
                border-radius: 4px;
                padding: 1rem;
                font-family: var(--pf-v5-global--FontFamily--monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace);
                font-size: 0.9rem;
                max-height: 240px;
                overflow-y: auto;
                word-break: break-all;
            }

            .kc-push-open-app {
                margin-top: 1rem;
            }
        </style>

        <div id="kc-push-wait-root"
             class="${properties.kcContentWrapperClass!}"
             data-push-mfa-page="login-wait"
             data-push-events-url="${pushChallengeWatchUrl!""}"
             data-push-form-id="kc-push-form">
            <div class="kc-push-card">
                <p class="kc-push-hint">${msg("push-mfa-wait-details")!"Approve the notification on your device to continue."}</p>

                <#if pushConfirmToken?? && pushCredentialId??>
                    <div class="kc-push-token-card">
                        <h4>${msg("push-mfa-message-title")!"Simulated Firebase payload"}</h4>
                        <div class="kc-push-open-app">
                            <button id="kc-push-open-app"
                                    type="button"
                                    class="${properties.kcButtonClass!} ${properties.kcButtonSecondaryClass!}"
                                    onClick="openApp('${appUniversalLink!''}?token=${pushConfirmToken!''}')">
                                ${msg("push-mfa-open-app")!"Open App"}
                            </button>
                        </div>
                        <p class="kc-push-hint">
                            ${msg("push-mfa-message-hint")!"This token travels via Firebase. Use it with scripts/confirm-login.sh \"<token>\"."}
                            <br/>
                            ${msg("push-mfa-message-user")!"Credential id:"}
                            <strong>${pushCredentialId!""}</strong>
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
                    <button class="${properties.kcButtonClass!} ${properties.kcButtonSecondaryClass!}" name="cancel"
                            value="true" type="submit">
                        ${msg("push-mfa-cancel")!"Cancel push"}
                    </button>
                </form>
            </div>
        </div>

        <script src="${url.resourcesPath}/js/push-mfa.js"></script>
        <script>
            (function () {
                const button = document.getElementById('kc-copy-confirm-token');
                const tokenBlock = document.getElementById('kc-push-confirm-token');
                if (!button || !tokenBlock) {
                    return;
                }
                const defaultLabel = button.dataset.defaultLabel || button.textContent || '';
                const successLabel = button.dataset.successLabel || defaultLabel;
                button.addEventListener('click', function () {
                    const value = (tokenBlock.textContent || '').trim();
                    if (!value) {
                        return;
                    }

                    function fallbackCopy(value) {
                        return new Promise(function (resolve, reject) {

                            console.log("Using the fallback copy method. Keep it in if this is logged...")

                            const textarea = document.createElement('textarea');
                            textarea.value = value;
                            textarea.style.position = 'fixed';
                            textarea.style.opacity = '0';
                            document.body.appendChild(textarea);
                            textarea.focus();
                            textarea.select();
                            const ok = document.execCommand && document.execCommand('copy');
                            document.body.removeChild(textarea);
                            if (!ok) {
                                reject(new Error('execCommand failed'));
                            }
                            resolve();

                        });
                    }

                    const copyPromise = (navigator.clipboard && window.isSecureContext)
                        ? navigator.clipboard.writeText(value)
                        : fallbackCopy(value);
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

            function openApp(url) {
                window.open(url);
            }
        </script>
    </#if>
</@layout.registrationLayout>
