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

            .kc-push-actions {
                display: flex;
                gap: 0.75rem;
                flex-wrap: wrap;
                margin-top: 1.5rem;
            }

            .kc-push-hint {
                margin-top: 0.75rem;
                color: var(--pf-v5-global--Color--200, #6a6e73);
                font-size: 0.95rem;
            }
        </style>

        <div class="${properties.kcContentWrapperClass!}">
            <div class="kc-push-card">
                <div class="alert alert-error">
                    ${msg("push-mfa-user-locked-out-message")!"The last push approval was denied and the user indicated a possible attack."}
                </div>
                <p class="kc-push-hint">${msg("push-mfa-user-locked-out-hint")!"For your protection, your account is locked. Please contact support to regain access."}</p>
            </div>
        </div>
    </#if>
</@layout.registrationLayout>
