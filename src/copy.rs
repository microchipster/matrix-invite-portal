//! User-facing copy shared by the invite flow (`main.rs`) and the password
//! reset flow (`password_reset.rs`).
//!
//! Both flows render the same checklist and notices. Keep the wording here so a
//! single edit updates every page that shows it. Static HTML fragments are
//! constants; anything embedding user or server data is a small builder.

// The Matrix app shows the recovery key after the user signs in. The portal
// never displays it, so every mention states where and when it appears;
// otherwise users look for a key in the checklist that will never show up.
pub(crate) const RECOVERY_KEY_INTRO: &str = "🔑 After you sign in, your Matrix app shows a <strong>Recovery key</strong>. Save it then; without it, your encrypted messages may be unreadable.";
pub(crate) const RECOVERY_KEY_ITEM: &str = r#"<li class="summary-critical"><strong>Recovery key:</strong> not shown here. Your app shows it after you sign in; save it then. Without it, encrypted messages may be unreadable.</li>"#;

pub(crate) const CHECKLIST_TITLE: &str = "Your account checklist";

// "see the links below" points at onboarding_links(), rendered right after the
// checklist on both summary pages.
pub(crate) const CLIENTS_ITEM: &str = r#"<li><strong>Clients:</strong> sign in on as many apps and devices as you like. Any Matrix client works — see the links below.</li>"#;
pub(crate) const PRIVACY_ITEM: &str = r#"<li><strong>Privacy:</strong> keep your real name, email, phone number, and other personal details out of your username and profile.</li>"#;

pub(crate) const SECTION_HOMESERVER: &str = "Your homeserver";
pub(crate) const SECTION_APPS: &str = "Apps and clients";
pub(crate) const LINK_READ_INTRO_AGAIN: &str = "Read the intro again";
pub(crate) const LINK_HELP_GUIDE: &str = "❓ Help &amp; guide";
pub(crate) const LINK_WHAT_IS_MATRIX: &str = "What is Matrix?";

pub(crate) const PASSWORDS_DO_NOT_MATCH: &str = "Passwords do not match.";

pub(crate) fn read_first(target: &str) -> String {
    format!("Read these notes first, then continue to the {}.", target)
}

pub(crate) fn form_error_notice(message: &str) -> String {
    format!(
        r#"<div class="notice error form-error" role="alert">⚠️ {}</div>"#,
        crate::encode_minimal(message)
    )
}

pub(crate) fn homeserver_item(url: &str, host: &str, hint: &str) -> String {
    format!(
        r#"<li><strong>Homeserver ({}):</strong> <a href="{}" target="_blank" rel="noreferrer">{}</a></li>"#,
        crate::encode_minimal(hint),
        crate::encode_minimal(url),
        crate::encode_minimal(host)
    )
}

pub(crate) fn provider_item(display: &str, copy_value: &str) -> String {
    format!(
        r#"<li class="summary-provider"><strong>Account provider (homeserver):</strong> <span class="summary-provider-url">{}</span><button type="button" class="summary-copy-button" data-copy-text="{}">📋 Copy address</button></li>"#,
        crate::encode_minimal(display),
        crate::encode_minimal(copy_value)
    )
}

pub(crate) fn registering_notice(host: &str) -> String {
    format!(
        r#"<div class="notice info">This form creates your Matrix account on <strong>{}</strong>.</div>"#,
        crate::encode_minimal(host)
    )
}

pub(crate) fn resetting_password_notice(user_id: &str) -> String {
    format!(
        r#"<div class="notice info">You are resetting the password for <strong>{}</strong>.</div>"#,
        crate::encode_minimal(user_id)
    )
}

// Invite status shown to the person opening the link. The same wording is used
// when redemption fails mid-form, so the message never changes between pages.
pub(crate) const INVITE_PAGE_CANCELLED: &str = "Invite cancelled";
pub(crate) const INVITE_PAGE_EXPIRED: &str = "Invite expired";
pub(crate) const INVITE_PAGE_NOT_VALID: &str = "Invite not valid";
pub(crate) const NOTICE_INVITE_CANCELLED: &str =
    "This invite was cancelled by the person who created it.";
pub(crate) const NOTICE_INVITE_EXPIRED: &str =
    "This invite has expired. Ask the person who invited you for a new one.";
pub(crate) const NOTICE_INVITE_NOT_FOUND: &str = "This invite link is not valid.";
pub(crate) const NOTICE_INVITE_USED: &str = "This invite has already been used.";
pub(crate) const NOTICE_INVITE_BUSY: &str =
    "Someone is already using this invite. Wait a moment and try again.";
pub(crate) const NOTICE_INVITE_USED_SUMMARY: &str = "This invite has already been used. If your signup summary was saved in this browser, it opens automatically; otherwise, ask for a new invite.";
pub(crate) const NOTICE_LAST_ATTEMPT_FAILED: &str =
    "Your last signup attempt did not finish. Please try again.";

pub(crate) const ACCOUNT_NOT_CREATED_TITLE: &str = "Account not created";
pub(crate) const NOTICE_ACCOUNT_CREATION_TIMED_OUT: &str = "Account creation timed out.";

pub(crate) const ERROR_TITLE: &str = "Something went wrong";

// Bodies for terminal pages. Keep them free of internal error text; details
// stay in the database (record_event / mark_failure) for administrators.
pub(crate) const ERROR_CARD: &str = r#"<div class="card"><h1>Something went wrong</h1><p class="muted">Something went wrong. Please try again later.</p></div>"#;
pub(crate) const RESET_NOT_FOUND_CARD: &str = r#"<div class="card"><h1>Reset link not found</h1><p class="muted">This password reset link is not valid. It may have been removed or already used.</p></div>"#;
pub(crate) const RESET_EXPIRED_CARD: &str = r#"<div class="card"><h1>Reset link expired</h1><p class="muted">This password reset link has expired. Ask the person who sent it for a new one.</p></div>"#;
pub(crate) const RESET_BUSY_CARD: &str = r#"<div class="card"><h1>Reset link busy</h1><p class="muted">This link is being used right now. Wait a moment and try again.</p></div>"#;
pub(crate) const RESET_FAILED_CARD: &str = r#"<div class="card"><h1>Password reset failed</h1><p class="muted">We could not reset your password. Try again, or ask the person who sent you this link for help.</p></div>"#;

pub(crate) const LINK_GO_TO_START: &str = "Go to the start page";
pub(crate) const LINK_BACK_TO_FORM: &str = "Back to the form";
pub(crate) const LINK_TRY_AGAIN: &str = "Try again";
