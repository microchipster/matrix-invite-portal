use std::time::Duration;

use axum::{
    extract::{Form, Path as AxumPath, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use reqwest::Client;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use tokio::time::timeout;

use crate::{
    copy, encode_minimal, generate_token, hash_token, homeserver_url_host, html_error, json_error,
    now_ts, onboarding_links, open_connection, page, token_preview, validate_password, AppError,
    AppState, Config,
};

const RESET_SUMMARY_TTL_SECONDS: i64 = 48 * 60 * 60;

#[derive(Debug)]
struct PasswordResetRecord {
    expires_at: i64,
    user_id: String,
    redeemed_at: Option<i64>,
    logout_devices: i64,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CreatePasswordResetRequest {
    user_id: String,
    created_by: Option<String>,
    note: Option<String>,
    expires_in_hours: Option<i64>,
}

#[derive(Debug, Serialize)]
struct CreatePasswordResetResponse {
    reset_id: String,
    reset_url: String,
    token: String,
    token_preview: String,
    created_at: i64,
    expires_at: i64,
    user_id: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PasswordResetForm {
    password: String,
    confirm_password: String,
    logout_devices: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PasswordResetPageQuery {
    step: Option<String>,
}

#[derive(Debug, Serialize)]
struct SynapseResetPasswordRequest<'a> {
    new_password: &'a str,
    logout_devices: bool,
}

pub(crate) async fn create_password_reset(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(request): Json<CreatePasswordResetRequest>,
) -> Response {
    let config = &state.config;
    if !crate::is_authorized(&headers, &config.admin_token) {
        return json_error(StatusCode::UNAUTHORIZED, "unauthorized");
    }

    if config.synapse_admin_access_token.is_none() {
        return json_error(
            StatusCode::BAD_REQUEST,
            "SYNAPSE_ADMIN_ACCESS_TOKEN is required to create password reset links",
        );
    }

    let user_id = request.user_id;
    if let Err(message) = validate_user_id(&user_id) {
        return json_error(StatusCode::BAD_REQUEST, message);
    }

    let token = generate_token();
    let reset_id = generate_reset_id();
    let token_hash = hash_token(&token);
    let token_preview = token_preview(&token);
    let now = now_ts();
    let expires_in_hours = request
        .expires_in_hours
        .unwrap_or(config.default_password_reset_ttl_hours)
        .max(1);
    let expires_at = now + expires_in_hours * 60 * 60;
    let created_by = request.created_by.unwrap_or_else(|| "unknown".to_owned());

    let conn = match open_connection(&config.database_path) {
        Ok(conn) => conn,
        Err(err) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    };

    if let Err(err) = conn.execute(
        r#"
        INSERT INTO password_resets (
            reset_id,
            token_hash,
            token_preview,
            created_at,
            expires_at,
            created_by,
            note,
            user_id,
            claimed_at,
            claimed_until,
            claimed_by,
            redeemed_at,
            redeemed_by,
            logout_devices,
            last_failure_reason,
            last_failure_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL)
        "#,
        params![
            reset_id,
            token_hash,
            token_preview,
            now,
            expires_at,
            created_by,
            request.note,
            user_id,
        ],
    ) {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
    }

    Json(CreatePasswordResetResponse {
        reset_id,
        reset_url: reset_link(config, &token),
        token,
        token_preview,
        created_at: now,
        expires_at,
        user_id,
    })
    .into_response()
}

pub(crate) async fn show_password_reset(
    State(state): State<AppState>,
    AxumPath(token): AxumPath<String>,
    Query(query): Query<PasswordResetPageQuery>,
) -> Response {
    let config = &state.config;
    let conn = match open_connection(&config.database_path) {
        Ok(conn) => conn,
        Err(_) => {
            return html_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                copy::ERROR_TITLE,
                copy::ERROR_CARD,
            )
        }
    };

    let token_hash = hash_token(&token);
    let record = match load_password_reset_record(&conn, &token_hash) {
        Ok(Some(record)) => record,
        Ok(None) => {
            return html_error(
                StatusCode::NOT_FOUND,
                "Reset link not found",
                copy::RESET_NOT_FOUND_CARD,
            )
        }
        Err(_) => {
            return html_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                copy::ERROR_TITLE,
                copy::ERROR_CARD,
            )
        }
    };

    let now = now_ts();
    if record.redeemed_at.is_some() || matches!(query.step.as_deref(), Some("summary")) {
        return page(
            &config.portal_title,
            &password_reset_summary_html(
                config,
                &token,
                &record.user_id,
                None,
                None,
                record.logout_devices != 0,
            ),
        )
        .into_response();
    }

    if record.expires_at <= now {
        return html_error(
            StatusCode::GONE,
            "Reset link expired",
            copy::RESET_EXPIRED_CARD,
        );
    }

    let body = if matches!(query.step.as_deref(), Some("form")) {
        password_reset_form_html(config, &token, &record.user_id, None, false)
    } else {
        password_reset_intro_html(config, &token, &record.user_id)
    };

    page(&config.portal_title, &body).into_response()
}

pub(crate) async fn redeem_password_reset(
    State(state): State<AppState>,
    AxumPath(token): AxumPath<String>,
    Form(form): Form<PasswordResetForm>,
) -> Response {
    let config = &state.config;
    let conn = match open_connection(&config.database_path) {
        Ok(conn) => conn,
        Err(_) => {
            return html_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                copy::ERROR_TITLE,
                copy::ERROR_CARD,
            )
        }
    };

    let token_hash = hash_token(&token);
    let record = match load_password_reset_record(&conn, &token_hash) {
        Ok(Some(record)) => record,
        Ok(None) => {
            return html_error(
                StatusCode::NOT_FOUND,
                "Reset link not found",
                copy::RESET_NOT_FOUND_CARD,
            )
        }
        Err(_) => {
            return html_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                copy::ERROR_TITLE,
                copy::ERROR_CARD,
            )
        }
    };

    let now = now_ts();
    if record.expires_at <= now {
        return html_error(
            StatusCode::GONE,
            "Reset link expired",
            copy::RESET_EXPIRED_CARD,
        );
    }

    if form.password != form.confirm_password {
        let message = copy::form_error_notice(copy::PASSWORDS_DO_NOT_MATCH);
        return page(
            &config.portal_title,
            &password_reset_form_html(
                config,
                &token,
                &record.user_id,
                Some(&message),
                form.logout_devices.is_some(),
            ),
        )
        .into_response();
    }

    if let Err(message) = validate_password(&form.password) {
        let notice = copy::form_error_notice(&message);
        return page(
            &config.portal_title,
            &password_reset_form_html(
                config,
                &token,
                &record.user_id,
                Some(&notice),
                form.logout_devices.is_some(),
            ),
        )
        .into_response();
    }

    match claim_password_reset(
        &conn,
        &token_hash,
        now,
        config.provisioning_claim_timeout_seconds as i64,
        &record.user_id,
    ) {
        Ok(true) => {}
        Ok(false) => {
            return html_error(
                StatusCode::CONFLICT,
                "Reset link busy",
                copy::RESET_BUSY_CARD,
            );
        }
        Err(_) => {
            return html_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                copy::ERROR_TITLE,
                copy::ERROR_CARD,
            )
        }
    }

    let logout_devices = form.logout_devices.is_some();
    if let Err(err) =
        synapse_reset_password(config, &record.user_id, &form.password, logout_devices).await
    {
        let _ = mark_password_reset_failure(&conn, &token_hash, now, &err.to_string());
        return html_error(
            StatusCode::BAD_GATEWAY,
            "Password reset failed",
            copy::RESET_FAILED_CARD,
        );
    }

    let saved_at = now_ts();
    if let Err(err) = finalize_password_reset(
        &conn,
        &token_hash,
        saved_at,
        &record.user_id,
        logout_devices,
    ) {
        let _ = mark_password_reset_failure(&conn, &token_hash, saved_at, &err.to_string());
        return html_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            copy::ERROR_TITLE,
            copy::ERROR_CARD,
        );
    }

    page(
        &config.portal_title,
        &password_reset_summary_html(
            config,
            &token,
            &record.user_id,
            Some(&form.password),
            Some(saved_at),
            logout_devices,
        ),
    )
    .into_response()
}

pub(crate) async fn synapse_admin_health(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    let config = &state.config;
    if !crate::is_authorized(&headers, &config.admin_token) {
        return json_error(StatusCode::UNAUTHORIZED, "unauthorized");
    }

    match synapse_admin_server_version(config).await {
        Ok(()) => (StatusCode::OK, "ok").into_response(),
        Err(AppError::Config(message)) => json_error(StatusCode::SERVICE_UNAVAILABLE, message),
        Err(AppError::Timeout) => json_error(
            StatusCode::GATEWAY_TIMEOUT,
            "Synapse admin API health check timed out",
        ),
        Err(AppError::Provisioning(message)) => {
            json_error(StatusCode::SERVICE_UNAVAILABLE, message)
        }
        Err(err) => json_error(StatusCode::SERVICE_UNAVAILABLE, err.to_string()),
    }
}

fn password_reset_intro_html(_config: &Config, token: &str, user_id: &str) -> String {
    format!(
        r#"
<div class="card">
  <h1>🔐 Reset your password</h1>
  <p class="muted small">{}</p>
  {}
  <ul class="intro-list">
    <li>🔑 On the next page, choose a new password. You will type it twice to catch typos.</li>
    <li>🧹 On the next page, you can also log out your other sessions and devices.</li>
    <li>🧭 The next page has client, help, and Matrix basics links in case you need them.</li>
    <li>✅ After the reset, this page will show a checklist with your Matrix ID, new password, and useful links.</li>
  </ul>
  <div class="actions">
    <a class="primary" href="/reset/{}?step=form">Continue to password form</a>
  </div>
</div>
"#,
        copy::read_first("password form"),
        copy::resetting_password_notice(user_id),
        encode_minimal(token),
    )
}

fn password_reset_form_html(
    config: &Config,
    token: &str,
    user_id: &str,
    notice_html: Option<&str>,
    logout_devices_checked: bool,
) -> String {
    let checked = if logout_devices_checked {
        " checked"
    } else {
        ""
    };
    format!(
        r#"
<div class="card">
  <h1>Reset your password</h1>
  {}
  {}
  <form method="post" autocomplete="off">
    <label for="password">New password</label>
    <input id="password" name="password" type="password" autocomplete="off" autocapitalize="none" spellcheck="false" required>

    <label for="confirm_password">Confirm new password</label>
    <input id="confirm_password" name="confirm_password" type="password" autocomplete="off" autocapitalize="none" spellcheck="false" required>

    <div class="check-row">
      <input id="logout_devices" name="logout_devices" type="checkbox" value="1"{}>
      <label for="logout_devices">Log out all other sessions and devices after the password is changed</label>
    </div>

    <button type="submit">🔄 Save new password</button>
  </form>
  <div class="section-title">{}</div>
  <ul class="client-list">
    {}
  </ul>
  {}
  <p class="muted small"><a href="/reset/{}">{}</a></p>
</div>
"#,
        copy::resetting_password_notice(user_id),
        notice_html.unwrap_or(""),
        checked,
        copy::SECTION_HOMESERVER,
        copy::homeserver_item(
            &config.homeserver_url,
            &homeserver_url_host(&config.homeserver_url),
            "for signing in"
        ),
        onboarding_links(config),
        encode_minimal(token),
        copy::LINK_READ_INTRO_AGAIN,
    )
}

fn password_reset_summary_html(
    config: &Config,
    token: &str,
    user_id: &str,
    password: Option<&str>,
    saved_at: Option<i64>,
    logout_devices: bool,
) -> String {
    let devices_note = if logout_devices {
        "All other sessions and devices were logged out when your password changed."
    } else {
        "Your other sessions and devices are still signed in."
    };
    let password = password.unwrap_or("");
    let saved_at = saved_at.unwrap_or_default();

    format!(
        r#"
<div class="summary-block" data-summary-mode="{}" data-summary-key="{}" data-summary-token="{}" data-summary-password="{}" data-summary-saved-at="{}" data-summary-logout-devices="{}">
  <div class="section-title">{}</div>
  <ul class="summary-list">
    <li><strong>Matrix ID:</strong> <span>{}</span></li>
    <li><strong>Password:</strong> <span data-summary-field="password">{}</span></li>
    {}
    {}
    <li><strong>Sessions:</strong> {}</li>
    {}
    {}
  </ul>
  <p class="summary-note">✅ Your password has been reset.</p>
  {}
  {}
</div>
"#,
        encode_minimal(if password.is_empty() { "load" } else { "save" }),
        encode_minimal(&summary_storage_key(token)),
        encode_minimal(token),
        encode_minimal(password),
        encode_minimal(&saved_at.to_string()),
        encode_minimal(if logout_devices { "1" } else { "0" }),
        copy::CHECKLIST_TITLE,
        encode_minimal(user_id),
        encode_minimal(password),
        copy::RECOVERY_KEY_ITEM,
        copy::provider_item(
            &homeserver_url_host(&config.homeserver_url),
            &config.homeserver_url
        ),
        encode_minimal(devices_note),
        copy::CLIENTS_ITEM,
        copy::PRIVACY_ITEM,
        onboarding_links(config),
        password_reset_summary_state_script(token),
    )
}

fn password_reset_summary_state_script(token: &str) -> String {
    format!(
        r#"
<script>
  (() => {{
    const block = document.querySelector('[data-summary-key="{}"]');
    if (!block) return;

    const key = block.dataset.summaryKey;
    const token = block.dataset.summaryToken;
    const summaryUrl = '/reset/' + token + '?step=summary';
    const passwordField = block.querySelector('[data-summary-field="password"]');
    const maxAgeMs = {} * 1000;

    const parseSnapshot = (raw) => {{
      try {{
        if (!raw) return null;
        const state = typeof raw === 'string' ? JSON.parse(raw) : raw;
        if (!state || state.token !== token) return null;
        if (!state.password) return null;
        return {{
          token,
          password: state.password,
          saved_at: Number(state.saved_at) || Date.now(),
          logout_devices: Boolean(state.logout_devices),
        }};
      }} catch (_) {{
        return null;
      }}
    }};

    const readSnapshot = () => {{
      const state =
        parseSnapshot(window.localStorage.getItem(key)) ||
        parseSnapshot(window.name) ||
        parseSnapshot(window.history.state && window.history.state.matrixInvitePortalSummary);
      if (state && Date.now() - state.saved_at <= maxAgeMs) {{
        return state;
      }}
      return null;
    }};

    const writeState = (data) => {{
      if (passwordField) passwordField.textContent = data.password || '';
    }};

    const persistSnapshot = (data) => {{
      window.localStorage.setItem(key, JSON.stringify(data));
      window.name = JSON.stringify(data);
      try {{
        window.history.replaceState({{ matrixInvitePortalSummary: data }}, '', summaryUrl);
      }} catch (_) {{}}
    }};

    const restoreSummary = () => {{
      const state = readSnapshot();
      if (!state) return false;

      persistSnapshot(state);
      writeState(state);
      return true;
    }};

    try {{
      if (block.dataset.summaryMode === 'save') {{
        const payload = {{
          token,
          password: block.dataset.summaryPassword || '',
          saved_at: Number(block.dataset.summarySavedAt) || Date.now(),
          logout_devices: block.dataset.summaryLogoutDevices === '1',
        }};
        persistSnapshot(payload);
        writeState(payload);
      }} else {{
        restoreSummary();
      }}
    }} catch (_) {{
      return;
    }}

    window.addEventListener('pageshow', () => {{
      try {{
        restoreSummary();
      }} catch (_) {{}}
    }});
  }})();
</script>
"#,
        encode_minimal(token),
        RESET_SUMMARY_TTL_SECONDS,
    )
}

fn summary_storage_key(token: &str) -> String {
    format!("matrix-invite-portal.password-reset.{}", token)
}

fn reset_link(config: &Config, token: &str) -> String {
    if let Some(base_url) = &config.public_base_url {
        format!("{}/reset/{}", base_url.trim_end_matches('/'), token)
    } else {
        format!("/reset/{}", token)
    }
}

fn generate_reset_id() -> String {
    let token = generate_token();
    format!("reset_{}", token_preview(&token))
}

fn validate_user_id(user_id: &str) -> Result<(), String> {
    let trimmed = user_id.trim();
    if trimmed != user_id {
        return Err("User ID must not start or end with spaces.".into());
    }
    if !trimmed.starts_with('@') || !trimmed.contains(':') {
        return Err("User ID must look like @name:example.com".into());
    }
    if trimmed.chars().any(char::is_whitespace) {
        return Err("User ID must not contain whitespace.".into());
    }
    Ok(())
}

fn encode_path_segment(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{:02X}", byte)),
        }
    }
    out
}

fn synapse_admin_error_message(action: &str, status: reqwest::StatusCode, body: &str) -> String {
    let trimmed = body.trim();
    let message = serde_json::from_str::<serde_json::Value>(trimmed)
        .ok()
        .and_then(|value| {
            value
                .get("error")
                .and_then(|error| error.as_str())
                .map(|error| error.trim().to_owned())
        })
        .filter(|message| !message.is_empty())
        .or_else(|| (!trimmed.is_empty()).then(|| trimmed.to_owned()));

    if let Some(message) = message {
        let mut rendered = format!(
            "Synapse admin API {} failed with status {}: {}",
            action, status, message
        );

        if status == reqwest::StatusCode::UNAUTHORIZED {
            rendered.push_str(" The `SYNAPSE_ADMIN_ACCESS_TOKEN` must belong to a Synapse server-admin account. A token from `/login` only works if that account is actually an admin.");
        }

        rendered
    } else {
        let mut rendered = format!("Synapse admin API {} failed with status {}", action, status);

        if status == reqwest::StatusCode::UNAUTHORIZED {
            rendered.push_str(" The `SYNAPSE_ADMIN_ACCESS_TOKEN` must belong to a Synapse server-admin account. A token from `/login` only works if that account is actually an admin.");
        }

        rendered
    }
}

fn synapse_reset_password_url(base_url: &str, user_id: &str) -> String {
    format!(
        "{}/v1/reset_password/{}",
        base_url.trim_end_matches('/'),
        encode_path_segment(user_id)
    )
}

fn synapse_admin_server_version_url(base_url: &str) -> String {
    format!("{}/v1/server_version", base_url.trim_end_matches('/'))
}

async fn synapse_admin_server_version(config: &Config) -> Result<(), AppError> {
    let access_token = config.synapse_admin_access_token.as_ref().ok_or_else(|| {
        AppError::Config("SYNAPSE_ADMIN_ACCESS_TOKEN is required for password resets".into())
    })?;

    let client = Client::new();
    let url = synapse_admin_server_version_url(&config.synapse_admin_api_base_url);
    let response = timeout(
        Duration::from_secs(config.provisioning_timeout_seconds),
        client.get(&url).bearer_auth(access_token).send(),
    )
    .await
    .map_err(|_| AppError::Timeout)??;

    if response.status().is_success() {
        Ok(())
    } else {
        let status = response.status();
        let body = response.text().await?;
        Err(AppError::Provisioning(synapse_admin_error_message(
            "checking the Synapse admin token",
            status,
            &body,
        )))
    }
}

async fn synapse_reset_password(
    config: &Config,
    user_id: &str,
    new_password: &str,
    logout_devices: bool,
) -> Result<(), AppError> {
    let access_token = config.synapse_admin_access_token.as_ref().ok_or_else(|| {
        AppError::Config("SYNAPSE_ADMIN_ACCESS_TOKEN is required for password resets".into())
    })?;
    let client = Client::new();
    let url = synapse_reset_password_url(&config.synapse_admin_api_base_url, user_id);
    let request = client
        .post(&url)
        .bearer_auth(access_token)
        .json(&SynapseResetPasswordRequest {
            new_password,
            logout_devices,
        });

    let response = timeout(
        Duration::from_secs(config.provisioning_timeout_seconds),
        request.send(),
    )
    .await
    .map_err(|_| AppError::Timeout)??;

    if response.status().is_success() {
        return Ok(());
    }

    let status = response.status();
    let body = response.text().await?;
    Err(AppError::Provisioning(synapse_admin_error_message(
        "resetting the password",
        status,
        &body,
    )))
}

fn load_password_reset_record(
    conn: &Connection,
    token_hash: &str,
) -> Result<Option<PasswordResetRecord>, AppError> {
    conn.query_row(
        r#"
        SELECT
            expires_at,
            user_id,
            redeemed_at,
            logout_devices
        FROM password_resets
        WHERE token_hash = ?1
        "#,
        params![token_hash],
        |row| {
            Ok(PasswordResetRecord {
                expires_at: row.get(0)?,
                user_id: row.get(1)?,
                redeemed_at: row.get(2)?,
                logout_devices: row.get(3)?,
            })
        },
    )
    .optional()
    .map_err(AppError::from)
}

fn claim_password_reset(
    conn: &Connection,
    token_hash: &str,
    now: i64,
    claim_timeout_seconds: i64,
    user_id: &str,
) -> Result<bool, AppError> {
    let claimed_until = now + claim_timeout_seconds;
    let updated = conn.execute(
        r#"
        UPDATE password_resets
        SET claimed_at = ?2, claimed_until = ?3, claimed_by = ?4
        WHERE token_hash = ?1
          AND redeemed_at IS NULL
          AND expires_at > ?2
          AND (claimed_until IS NULL OR claimed_until < ?2)
        "#,
        params![token_hash, now, claimed_until, user_id],
    )?;

    Ok(updated == 1)
}

fn finalize_password_reset(
    conn: &Connection,
    token_hash: &str,
    saved_at: i64,
    user_id: &str,
    logout_devices: bool,
) -> Result<(), AppError> {
    conn.execute(
        r#"
        UPDATE password_resets
        SET claimed_at = NULL,
            claimed_until = NULL,
            claimed_by = NULL,
            redeemed_at = ?2,
            redeemed_by = ?3,
            logout_devices = ?4,
            last_failure_reason = NULL,
            last_failure_at = NULL
        WHERE token_hash = ?1
        "#,
        params![token_hash, saved_at, user_id, i64::from(logout_devices)],
    )?;

    Ok(())
}

fn mark_password_reset_failure(
    conn: &Connection,
    token_hash: &str,
    now: i64,
    reason: &str,
) -> Result<(), AppError> {
    conn.execute(
        r#"
        UPDATE password_resets
        SET claimed_at = NULL,
            claimed_until = NULL,
            claimed_by = NULL,
            last_failure_reason = ?2,
            last_failure_at = ?3
        WHERE token_hash = ?1
        "#,
        params![token_hash, reason, now],
    )?;

    Ok(())
}

pub(crate) fn migrate_password_resets_schema(_conn: &Connection) -> Result<(), AppError> {
    if column_exists(_conn, "password_resets", "summary_password")? {
        _conn.execute(
            r#"
            UPDATE password_resets
            SET summary_password = NULL,
                summary_saved_at = NULL
            "#,
            [],
        )?;
    }

    Ok(())
}

fn column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool, AppError> {
    let sql = format!("PRAGMA table_info({table})");
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for row in rows {
        if row? == column {
            return Ok(true);
        }
    }
    Ok(false)
}
