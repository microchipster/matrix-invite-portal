use std::{
    env,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    extract::{Form, Path as AxumPath, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use hmac::{Hmac, Mac};
use htmlescape::encode_minimal;
use rand::{rng, RngExt};
use reqwest::Client;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{net::TcpListener, time::timeout};

mod copy;
mod password_reset;

type HmacSha1 = Hmac<Sha1>;

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
}

const LEGACY_IOS_BADGE: &[u8] = include_bytes!("../assets/App-store-US-alt.svg");
const LEGACY_ANDROID_BADGE: &[u8] = include_bytes!("../assets/Google-Play-US.svg");
const LEGACY_FDROID_BADGE: &[u8] = include_bytes!("../assets/-Get_it_on_F-droid-_Badge.png");

#[derive(Debug, Clone)]
struct Config {
    listen_addr: SocketAddr,
    database_path: PathBuf,
    provisioning_timeout_seconds: u64,
    provisioning_claim_timeout_seconds: u64,
    default_invite_ttl_hours: i64,
    default_use_limit: i64,
    default_password_reset_ttl_hours: i64,
    admin_token: String,
    synapse_admin_api_base_url: String,
    synapse_registration_shared_secret: String,
    synapse_admin_access_token: Option<String>,
    public_base_url: Option<String>,
    portal_title: String,
    portal_success_message: String,
    portal_failure_message: String,
    portal_root_message: String,
    homeserver_url: String,
    info_website_url: String,
}

#[derive(Debug, Error)]
enum AppError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("http request error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("request timed out")]
    Timeout,
    #[error("provisioning failed: {0}")]
    Provisioning(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("configuration error: {0}")]
    Config(String),
}

#[derive(Debug, Serialize)]
struct InviteRecord {
    invite_id: String,
    token_preview: String,
    created_at: i64,
    expires_at: i64,
    created_by: String,
    use_limit: i64,
    use_count: i64,
    revoked_at: Option<i64>,
    claimed_at: Option<i64>,
    claimed_until: Option<i64>,
    claimed_by: Option<String>,
    redeemed_at: Option<i64>,
    redeemed_by: Option<String>,
    last_failure_reason: Option<String>,
    last_failure_at: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct RedeemForm {
    username: String,
    password: String,
    confirm_password: String,
}

#[derive(Debug, Deserialize)]
struct InvitePageQuery {
    step: Option<String>,
    clear: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreateInviteRequest {
    created_by: Option<String>,
    note: Option<String>,
    expires_in_hours: Option<i64>,
    use_limit: Option<i64>,
}

#[derive(Debug, Serialize)]
struct CreateInviteResponse {
    invite_id: String,
    invite_url: String,
    token: String,
    token_preview: String,
    created_at: i64,
    expires_at: i64,
    use_limit: i64,
}

#[derive(Debug, Deserialize)]
struct RevokeInviteRequest {
    reason: Option<String>,
}

#[derive(Debug, Serialize)]
struct RevokeAllInvitesResponse {
    status: String,
    revoked_count: usize,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Arc::new(Config::from_env()?);
    init_database(&config.database_path)?;
    let listen_addr = config.listen_addr;

    let app = Router::new()
        .route("/", get(root_page))
        .route("/health", get(health))
        .route("/favicon.ico", get(favicon))
        .route("/invite/{token}", get(show_invite).post(redeem_invite))
        .route(
            "/reset/{token}",
            get(password_reset::show_password_reset).post(password_reset::redeem_password_reset),
        )
        .route("/admin/invites", get(list_invites).post(create_invite))
        .route(
            "/admin/password-resets",
            post(password_reset::create_password_reset),
        )
        .route(
            "/admin/synapse-health",
            get(password_reset::synapse_admin_health),
        )
        .route("/admin/invites/revoke-all", post(revoke_all_invites))
        .route("/admin/invites/{invite_id}/revoke", post(revoke_invite))
        .route("/admin/invites/{invite_id}/rotate", post(rotate_invite))
        .with_state(AppState {
            config: config.clone(),
        });

    let listener = TcpListener::bind(listen_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

impl Config {
    fn from_env() -> Result<Self, AppError> {
        let listen_addr = env::var("PORT")
            .ok()
            .and_then(|value| value.parse().ok())
            .map(|port| SocketAddr::from(([0, 0, 0, 0], port)))
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 3000)));

        let database_path = env::var("DATABASE_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/data/invite-portal.sqlite3"));

        let provisioning_timeout_seconds = env::var("PROVISIONING_TIMEOUT_SECONDS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(60);

        let provisioning_claim_timeout_seconds = env::var("PROVISIONING_CLAIM_TIMEOUT_SECONDS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(900);

        let default_invite_ttl_hours = env::var("DEFAULT_INVITE_TTL_HOURS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(8760);

        let default_use_limit = env::var("DEFAULT_USE_LIMIT")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(1);
        let default_password_reset_ttl_hours = env::var("DEFAULT_PASSWORD_RESET_TTL_HOURS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(24);

        let admin_token = env::var("ADMIN_TOKEN")
            .map_err(|_| AppError::Config("ADMIN_TOKEN is required".into()))?;
        let synapse_admin_api_base_url = env::var("SYNAPSE_ADMIN_API_BASE_URL")
            .map_err(|_| AppError::Config("SYNAPSE_ADMIN_API_BASE_URL is required".into()))?;
        let synapse_registration_shared_secret = env::var("SYNAPSE_REGISTRATION_SHARED_SECRET")
            .map_err(|_| {
                AppError::Config("SYNAPSE_REGISTRATION_SHARED_SECRET is required".into())
            })?;
        let synapse_admin_access_token = env::var("SYNAPSE_ADMIN_ACCESS_TOKEN")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let public_base_url = env::var("PUBLIC_BASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty());

        Ok(Self {
            listen_addr,
            database_path,
            provisioning_timeout_seconds,
            provisioning_claim_timeout_seconds,
            default_invite_ttl_hours,
            default_use_limit,
            default_password_reset_ttl_hours,
            admin_token,
            synapse_admin_api_base_url,
            synapse_registration_shared_secret,
            synapse_admin_access_token,
            public_base_url,
            portal_title: env_or_default("PORTAL_TITLE", "🤝 Join our community on Matrix"),
            portal_success_message: env_or_default("PORTAL_SUCCESS_MESSAGE", "✨ Your Matrix account is ready."),
            portal_failure_message: env_or_default("PORTAL_FAILURE_MESSAGE", "We could not create your account. Please try again, or ask the person who sent you this link."),
            portal_root_message: env_or_default("PORTAL_ROOT_MESSAGE", "To create your account, open the private invite link you received."),
            homeserver_url: env::var("HOMESERVER_URL").map_err(|_| AppError::Config("HOMESERVER_URL is required".into()))?,
            info_website_url: env::var("INFO_WEBSITE_URL").map_err(|_| AppError::Config("INFO_WEBSITE_URL is required".into()))?,
        })
    }
}

fn env_or_default(name: &str, default: &str) -> String {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| default.to_owned())
}

fn init_database(path: &Path) -> Result<(), AppError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let conn = open_connection(path)?;
    conn.execute_batch(
        r#"
        PRAGMA journal_mode=WAL;
        PRAGMA foreign_keys=ON;

        CREATE TABLE IF NOT EXISTS invites (
            invite_id TEXT,
            token_hash TEXT PRIMARY KEY,
            token_preview TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            created_by TEXT NOT NULL,
            note TEXT,
            use_limit INTEGER NOT NULL,
            use_count INTEGER NOT NULL DEFAULT 0,
            revoked_at INTEGER,
            claimed_at INTEGER,
            claimed_until INTEGER,
            claimed_by TEXT,
            redeemed_at INTEGER,
            redeemed_by TEXT,
            last_failure_reason TEXT,
            last_failure_at INTEGER
        );

        CREATE TABLE IF NOT EXISTS invite_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            invite_id TEXT,
            token_hash TEXT NOT NULL,
            event_type TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            actor TEXT,
            details TEXT
        );

        CREATE TABLE IF NOT EXISTS password_resets (
            reset_id TEXT,
            token_hash TEXT PRIMARY KEY,
            token_preview TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            created_by TEXT NOT NULL,
            note TEXT,
            user_id TEXT NOT NULL,
            claimed_at INTEGER,
            claimed_until INTEGER,
            claimed_by TEXT,
            redeemed_at INTEGER,
            redeemed_by TEXT,
            logout_devices INTEGER NOT NULL DEFAULT 0,
            last_failure_reason TEXT,
            last_failure_at INTEGER
        );
        "#,
    )?;

    migrate_invites_schema(&conn)?;
    password_reset::migrate_password_resets_schema(&conn)?;

    Ok(())
}

fn migrate_invites_schema(conn: &Connection) -> Result<(), AppError> {
    if !column_exists(conn, "invites", "invite_id")? {
        conn.execute("ALTER TABLE invites ADD COLUMN invite_id TEXT", [])?;
    }

    if !column_exists(conn, "invite_events", "invite_id")? {
        conn.execute("ALTER TABLE invite_events ADD COLUMN invite_id TEXT", [])?;
    }

    if column_exists(conn, "invites", "summary_username")? {
        conn.execute(
            r#"
            UPDATE invites
            SET summary_username = NULL,
                summary_password = NULL,
                summary_saved_at = NULL
            "#,
            [],
        )?;
    }

    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_invites_invite_id ON invites(invite_id)",
        [],
    )?;

    let mut stmt =
        conn.prepare("SELECT token_hash FROM invites WHERE invite_id IS NULL OR invite_id = ''")?;
    let mut token_hashes = Vec::new();
    for row in stmt.query_map([], |row| row.get::<_, String>(0))? {
        token_hashes.push(row?);
    }
    for token_hash in token_hashes {
        let mut invite_id = generate_invite_id();
        loop {
            let updated = conn.execute(
                "UPDATE invites SET invite_id = ?2 WHERE token_hash = ?1 AND (invite_id IS NULL OR invite_id = '')",
                params![token_hash, invite_id],
            )?;
            if updated == 1 {
                break;
            }
            invite_id = generate_invite_id();
        }
    }

    let mut stmt = conn.prepare(
        r#"
        SELECT e.id, i.invite_id
        FROM invite_events e
        JOIN invites i ON i.token_hash = e.token_hash
        WHERE e.invite_id IS NULL OR e.invite_id = ''
        "#,
    )?;
    let mut event_backfills = Vec::new();
    for row in stmt.query_map([], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
    })? {
        event_backfills.push(row?);
    }
    for (id, invite_id) in event_backfills {
        conn.execute(
            "UPDATE invite_events SET invite_id = ?2 WHERE id = ?1",
            params![id, invite_id],
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

fn open_connection(path: &Path) -> Result<Connection, AppError> {
    let conn = Connection::open(path)?;
    conn.busy_timeout(Duration::from_secs(5))?;
    Ok(conn)
}

fn now_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rng().fill(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn generate_invite_id() -> String {
    let mut bytes = [0u8; 16];
    rng().fill(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    hex::encode(digest)
}

fn token_preview(token: &str) -> String {
    token.chars().take(10).collect()
}

fn validate_username(username: &str) -> Result<(), String> {
    let trimmed = username.trim();
    if trimmed != username {
        return Err("Username must not start or end with spaces.".into());
    }
    if trimmed.len() < 3 || trimmed.len() > 64 {
        return Err("Username must be between 3 and 64 characters long.".into());
    }
    if !trimmed
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '='))
    {
        return Err("Username may only contain letters, numbers, dots, underscores, hyphens, and equals signs.".into());
    }
    Ok(())
}

fn validate_password(password: &str) -> Result<(), String> {
    if password.len() < 8 {
        return Err("Password must be at least 8 characters long.".into());
    }
    Ok(())
}

fn html_document(title: &str, body: String) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title}</title>
  <style>
    :root {{ color-scheme: light dark; }}
    body {{ margin: 0; padding: 0; background: #111827; color: #f9fafb; }}
    main {{ max-width: 40rem; margin: 0 auto; padding: 2rem 1.25rem 3rem; }}
    .card {{ background: #1f2937; border: 1px solid #374151; border-radius: 1rem; padding: 1.25rem; box-shadow: 0 10px 30px rgba(0,0,0,0.2); }}
    h1 {{ margin: 0 0 0.5rem; font-size: 1.75rem; line-height: 1.2; }}
    p {{ line-height: 1.55; color: #d1d5db; }}
    label {{ display: block; margin: 1rem 0 0.35rem; font-weight: 600; }}
    input {{ width: 100%; box-sizing: border-box; border: 1px solid #4b5563; border-radius: 0.75rem; padding: 0.8rem 0.9rem; background: #111827; color: #f9fafb; }}
    button {{ margin-top: 1.1rem; border: 0; border-radius: 0.8rem; padding: 0.85rem 1.1rem; background: #4f46e5; color: white; font-weight: 700; cursor: pointer; width: 100%; }}
    .notice {{ padding: 0.9rem 1rem; border-radius: 0.75rem; margin: 1rem 0; }}
    .success {{ background: #052e16; color: #bbf7d0; border: 1px solid #166534; }}
    .error {{ background: #450a0a; color: #fecaca; border: 1px solid #991b1b; }}
    .notice.form-error {{ margin-top: 0.75rem; font-weight: 800; background: #4c0519; color: #fecaca; border: 2px solid #f87171; box-shadow: 0 0 0 1px rgba(248, 113, 113, 0.18); }}
    .muted {{ font-size: 0.95rem; color: #9ca3af; }}
    .small {{ font-size: 0.9rem; }}
    .notice.info {{ background: rgba(30, 64, 175, 0.18); color: #dbeafe; border: 1px solid rgba(59, 130, 246, 0.35); }}
    .badge-links {{ display: flex; flex-wrap: nowrap; gap: 0.65rem; margin: 1rem 0 0.35rem; align-items: stretch; }}
    .badge-links a {{ display: flex; flex: 1 1 0; min-width: 0; align-items: center; justify-content: center; border-radius: 0.75rem; overflow: hidden; }}
    .badge-links img {{ display: block; width: 100%; max-width: 100%; height: auto; max-height: 3rem; object-fit: contain; }}
    .badge-links a:hover img {{ filter: brightness(1.06); }}
    .badge-links a:focus-visible {{ outline: 2px solid #93c5fd; outline-offset: 3px; }}
    .section-title {{ margin: 0.85rem 0 0.25rem; font-size: 1.05rem; font-weight: 800; color: #f9fafb; }}
    .client-list {{ margin: 0.45rem 0 0; padding-left: 1.2rem; }}
    .client-list li + li {{ margin-top: 0.45rem; }}
    .client-link {{ display: inline-flex; align-items: center; gap: 0.45rem; padding: 0.45rem 0.65rem; border-radius: 0.75rem; background: rgba(17, 24, 39, 0.72); border: 1px solid #374151; color: #e5e7eb; text-decoration: none; font-weight: 600; font-size: 0.92rem; width: fit-content; max-width: 100%; }}
    .client-link .label {{ color: #9ca3af; font-weight: 700; }}
    .client-link .url {{ overflow-wrap: anywhere; }}
    .client-link:hover {{ border-color: #4b5563; }}
    .client-link:focus-visible {{ outline: 2px solid #93c5fd; outline-offset: 2px; }}
    .actions {{ display: flex; flex-wrap: wrap; gap: 0.75rem; margin: 0.85rem 0 0.35rem; }}
    .actions a, .actions button {{ display: inline-flex; align-items: center; justify-content: center; padding: 0.8rem 1rem; border-radius: 0.75rem; border: 1px solid #4b5563; background: #111827; color: #f9fafb; text-decoration: none; font-weight: 700; font-size: 0.95rem; }}
    .actions a.primary {{ background: #4f46e5; border-color: #4f46e5; }}
    .actions button {{ cursor: pointer; }}
    .actions a:hover {{ filter: brightness(1.08); }}
    .actions button:hover {{ filter: brightness(1.08); }}
    .actions a:focus-visible, .actions button:focus-visible {{ outline: 2px solid #93c5fd; outline-offset: 2px; }}
    .copy-status {{ min-height: 1.2rem; margin-top: 0.35rem; color: #c7d2fe; }}
    .provider-block {{ margin-top: 1rem; padding-top: 0.85rem; border-top: 1px solid #374151; }}
    .provider-header {{ display: flex; align-items: center; gap: 0.55rem; flex-wrap: wrap; }}
    .required-chip {{ display: inline-flex; align-items: center; padding: 0.2rem 0.55rem; border-radius: 999px; background: rgba(245, 158, 11, 0.16); border: 1px solid rgba(245, 158, 11, 0.35); color: #fde68a; font-size: 0.78rem; font-weight: 800; letter-spacing: 0.02em; text-transform: uppercase; }}
    .provider-block .small {{ margin-top: 0.25rem; }}
    .provider-row {{ display: flex; flex-wrap: wrap; align-items: center; gap: 0.55rem; margin-top: 0.6rem; }}
    .provider-url {{ flex: 1 1 18rem; min-width: 0; display: block; padding: 0.68rem 0.8rem; border-radius: 0.75rem; background: rgba(17, 24, 39, 0.88); border: 1px solid #4b5563; font-size: 0.92rem; line-height: 1.35; overflow-wrap: anywhere; word-break: break-word; }}
    .provider-url .scheme {{ color: #9ca3af; }}
    .provider-url .host {{ color: #f9fafb; }}
    .provider-row button {{ width: auto; margin-top: 0; padding: 0.65rem 0.85rem; font-size: 0.9rem; white-space: nowrap; }}
    .check-row {{ display: flex; align-items: flex-start; gap: 0.55rem; margin-top: 1rem; }}
    .check-row input[type="checkbox"] {{ width: auto; margin-top: 0.2rem; }}
    .check-row label {{ display: inline; margin: 0; font-weight: 600; line-height: 1.45; }}
    .summary-block {{ margin-top: 1rem; padding-top: 0.85rem; border-top: 1px solid #374151; }}
    .summary-list {{ margin: 0.45rem 0 0; padding-left: 1.2rem; }}
    .summary-list li + li {{ margin-top: 0.5rem; }}
    .summary-list strong {{ color: #f9fafb; }}
    .summary-critical strong, .summary-provider strong {{ color: #fbbf24; }}
    .summary-provider {{ display: flex; flex-wrap: wrap; align-items: center; gap: 0.45rem; }}
    .summary-provider-url {{ min-width: 0; overflow-wrap: anywhere; word-break: break-word; color: #f9fafb; padding: 0.15rem 0.45rem; border-radius: 999px; background: rgba(17, 24, 39, 0.88); border: 1px solid #4b5563; }}
    .summary-copy-button {{ width: auto; margin-top: 0; padding: 0.38rem 0.65rem; font-size: 0.82rem; white-space: nowrap; }}
    .summary-note {{ margin-top: 0.35rem; color: #9ca3af; }}
    .intro-list {{ margin: 0.65rem 0 0; padding-left: 1.2rem; }}
    .intro-list li + li {{ margin-top: 0.5rem; }}
    .footer-note {{ margin-top: 1rem; }}
    .matrix-link {{ display: inline-flex; align-items: center; padding: 0.38rem 0.7rem; border-radius: 999px; border: 1px solid #4b5563; background: rgba(17, 24, 39, 0.72); color: #dbeafe; text-decoration: none; font-weight: 700; }}
    .matrix-link:hover {{ border-color: #60a5fa; color: #eff6ff; }}
    .matrix-link:focus-visible {{ outline: 2px solid #93c5fd; outline-offset: 2px; }}
    a {{ color: #93c5fd; }}
  </style>
  <script>
    document.addEventListener("click", function (event) {{
      var node = event.target;
      var button = null;

      while (node && node !== document) {{
        if (node.matches && node.matches("[data-copy-text]")) {{
          button = node;
          break;
        }}

        node = node.parentNode;
      }}

      if (!button) return;

      var text = button.getAttribute("data-copy-text");
      if (!text) return;

      var status = null;
      var card = button;

      while (card && card !== document) {{
        if (card.classList && card.classList.contains("card")) {{
          status = card.querySelector(".copy-status");
          break;
        }}

        card = card.parentNode;
      }}

      function showCopied(originalText) {{
        button.textContent = "Copied";
        if (status) status.textContent = "Copied server address.";
        setTimeout(function () {{
          button.textContent = originalText;
          if (status) status.textContent = "";
        }}, 1200);
      }}

      var original = button.textContent || "Copy";

      if (navigator.clipboard && navigator.clipboard.writeText) {{
        navigator.clipboard.writeText(text).then(function () {{
          showCopied(original);
        }}).catch(function () {{
          if (status) status.textContent = "Could not copy automatically. Select the address and copy it manually.";
        }});
      }} else {{
        if (status) status.textContent = "Could not copy automatically. Select the address and copy it manually.";
      }}
    }});
  </script>
</head>
<body>
<main>
{body}
</main>
</body>
</html>"#,
        title = encode_minimal(title),
        body = body,
    )
}

fn page(title: &str, content: &str) -> Html<String> {
    Html(html_document(title, content.to_owned()))
}

fn invite_link(config: &Config, token: &str) -> String {
    if let Some(base_url) = &config.public_base_url {
        format!("{}/invite/{}", base_url.trim_end_matches('/'), token)
    } else {
        format!("/invite/{}", token)
    }
}

fn homeserver_url_host(homeserver_url: &str) -> String {
    let without_scheme = homeserver_url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(homeserver_url);

    let host = without_scheme
        .trim_end_matches('/')
        .split('/')
        .next()
        .unwrap_or(without_scheme);

    host.to_owned()
}

fn homeserver_host(homeserver_url: &str) -> String {
    let host = homeserver_url_host(homeserver_url);

    host.strip_prefix("matrix.")
        .unwrap_or(host.as_str())
        .to_owned()
}

fn element_client_url(homeserver_url: &str) -> String {
    format!("https://element.{}", homeserver_host(homeserver_url))
}

fn synapse_register_url(base_url: &str) -> String {
    format!("{}/v1/register", base_url.trim_end_matches('/'))
}

fn synapse_register_error_message(action: &str, status: reqwest::StatusCode, body: &str) -> String {
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
        format!(
            "Synapse admin API {} failed with status {}: {}",
            action, status, message
        )
    } else {
        format!(
            "Synapse registration API {} failed with status {}",
            action, status
        )
    }
}

fn synapse_registration_mac(
    shared_secret: &str,
    nonce: &str,
    username: &str,
    password: &str,
    admin: bool,
) -> Result<String, AppError> {
    let mut mac = HmacSha1::new_from_slice(shared_secret.as_bytes())
        .map_err(|_| AppError::Config("SYNAPSE_REGISTRATION_SHARED_SECRET is invalid".into()))?;
    mac.update(nonce.as_bytes());
    mac.update(b"\0");
    mac.update(username.as_bytes());
    mac.update(b"\0");
    mac.update(password.as_bytes());
    mac.update(b"\0");
    mac.update(if admin {
        &b"admin"[..]
    } else {
        &b"notadmin"[..]
    });

    Ok(hex::encode(mac.finalize().into_bytes()))
}

#[derive(Debug, Deserialize)]
struct SynapseRegistrationNonceResponse {
    nonce: String,
}

#[derive(Debug, Serialize)]
struct SynapseRegistrationRequest<'a> {
    nonce: &'a str,
    username: &'a str,
    password: &'a str,
    admin: bool,
    mac: String,
}

fn synapse_username_taken(status: reqwest::StatusCode, body: &str) -> bool {
    if !status.is_client_error() {
        return false;
    }

    let body = body.to_ascii_lowercase();
    body.contains("already taken")
        || body.contains("already exists")
        || body.contains("user already exists")
        || body.contains("user id already exists")
        || body.contains("duplicate")
}

async fn provision_user_via_synapse_registration_shared_secret(
    config: Arc<Config>,
    username: &str,
    password: &str,
) -> Result<(), AppError> {
    let client = Client::new();
    let register_url = synapse_register_url(&config.synapse_admin_api_base_url);

    let nonce_response = client.get(&register_url).send().await?;
    if !nonce_response.status().is_success() {
        let status = nonce_response.status();
        let body = nonce_response.text().await?;
        return Err(AppError::Provisioning(synapse_register_error_message(
            "fetching a registration nonce",
            status,
            &body,
        )));
    }

    let nonce = nonce_response
        .json::<SynapseRegistrationNonceResponse>()
        .await?
        .nonce;

    let mac = synapse_registration_mac(
        &config.synapse_registration_shared_secret,
        &nonce,
        username,
        password,
        false,
    )?;

    let response = client
        .post(&register_url)
        .json(&SynapseRegistrationRequest {
            nonce: &nonce,
            username,
            password,
            admin: false,
            mac,
        })
        .send()
        .await?;

    if response.status().is_success() {
        return Ok(());
    }

    let status = response.status();
    let body = response.text().await?;
    if synapse_username_taken(status, &body) {
        return Err(AppError::Provisioning(
            "This username is already in use. Please choose a different one.".to_string(),
        ));
    }

    Err(AppError::Provisioning(synapse_register_error_message(
        "creating the user",
        status,
        &body,
    )))
}

fn data_uri(mime_type: &str, bytes: &[u8]) -> String {
    format!("data:{};base64,{}", mime_type, STANDARD.encode(bytes))
}

fn invite_form_html(config: &Config, token: &str, notice_html: &str) -> String {
    let homeserver_display = homeserver_url_host(&config.homeserver_url);
    format!(
        r#"
<div class="card" data-invite-form-key="{}" data-invite-form-token="{}">
  <h1>{}</h1>
  {}
  {}
  <form method="post" autocomplete="off">
    <label for="username">Username</label>
    <input id="username" name="username" autocomplete="off" autocapitalize="none" spellcheck="false" required>

    <label for="password">Password</label>
    <input id="password" name="password" type="password" autocomplete="off" autocapitalize="none" spellcheck="false" required>

    <label for="confirm_password">Confirm password</label>
    <input id="confirm_password" name="confirm_password" type="password" autocomplete="off" autocapitalize="none" spellcheck="false" required>

    <button type="submit">✨ Create my account</button>
  </form>
  <div class="section-title">{}</div>
  <ul class="client-list">
    {}
  </ul>
  {}
  <p class="muted small"><a href="/invite/{}">{}</a></p>
</div>
{}"#,
        encode_minimal(token),
        encode_minimal(token),
        encode_minimal(&config.portal_title),
        copy::registering_notice(&homeserver_display),
        notice_html,
        copy::SECTION_HOMESERVER,
        copy::homeserver_item(
            &config.homeserver_url,
            &config.homeserver_url,
            "enter this in your app"
        ),
        onboarding_links(config),
        encode_minimal(token),
        copy::LINK_READ_INTRO_AGAIN,
        draft_state_script(token),
    )
}

fn onboarding_intro(token: &str, homeserver_url: &str) -> String {
    let homeserver_host = homeserver_url_host(homeserver_url);
    format!(
        r#"
<div class="card">
  <h1>👀 Before you create your account</h1>
  <p class="muted small">{}</p>
  <ul class="intro-list">
    <li>🧭 Later, when your Matrix app asks for a server, choose <strong>Custom account provider</strong> and enter <strong>{}</strong>. Do <strong>not</strong> sign up with matrix.org or any other server.</li>
    <li>{}</li>
    <li>🙅 You do not need to give your real name, email, phone number, or photo. Keep them out of your username and profile to protect your privacy.</li>
    <li>✅ After you sign up, this page will show a checklist with your username, password, homeserver, clients, and help links.</li>
  </ul>
  <div class="actions">
    <a class="primary" href="/invite/{}?step=form">Continue to sign up</a>
  </div>
</div>
<script>
  (() => {{
    const summaryKey = "{}";
    const token = "{}";
    const summaryUrl = '/invite/' + token + '?step=summary';
    const maxAgeMs = 48 * 60 * 60 * 1000;
    const parseSnapshot = (raw) => {{
      try {{
        if (!raw) return null;
        const state = typeof raw === 'string' ? JSON.parse(raw) : raw;
        if (!state || state.token !== token) return null;
        if (!state.username || !state.password) return null;
        return {{
          token,
          username: state.username,
          password: state.password,
          saved_at: Number(state.saved_at) || Date.now(),
        }};
      }} catch (_) {{
        return null;
      }}
    }};
    const readSnapshot = () => {{
      const state =
        parseSnapshot(window.localStorage.getItem(summaryKey)) ||
        parseSnapshot(window.name) ||
        parseSnapshot(window.history.state && window.history.state.matrixInvitePortalSummary);
      if (state && Date.now() - state.saved_at <= maxAgeMs) {{
        return state;
      }}
      return null;
    }};
    const restoreSummary = () => {{
      const state = readSnapshot();
      if (!state) return false;

      try {{
        window.localStorage.setItem(summaryKey, JSON.stringify(state));
        window.name = JSON.stringify(state);
        window.history.replaceState({{ matrixInvitePortalSummary: state }}, '', summaryUrl);
      }} catch (_) {{}}

      window.location.replace(summaryUrl);
      return true;
    }};
    try {{
      if (restoreSummary()) {{
        return;
      }}

      if (window.localStorage.getItem(summaryKey)) {{
        window.localStorage.removeItem(summaryKey);
      }}
    }} catch (_) {{}}

    window.addEventListener('pageshow', restoreSummary);
  }})();
</script>
"#,
        copy::read_first("signup form"),
        encode_minimal(&homeserver_host),
        copy::RECOVERY_KEY_INTRO,
        encode_minimal(token),
        encode_minimal(&summary_storage_key(token)),
        encode_minimal(token),
    )
}

fn summary_storage_key(token: &str) -> String {
    format!("matrix-invite-portal.summary.{}", token)
}

fn clear_summary_state_page(token: &str) -> String {
    format!(
        r#"
<div class="card">
  <h1>Saved signup details cleared</h1>
  <p class="muted small">Taking you back to your invite page…</p>
</div>
<script>
  (() => {{
    const token = "{}";
    const summaryKey = 'matrix-invite-portal.summary.' + token;
    const draftKey = 'matrix-invite-portal.draft.' + token;
    try {{
      window.localStorage.removeItem(summaryKey);
      window.localStorage.removeItem(draftKey);
      window.name = '';
      window.history.replaceState(null, '', '/invite/' + token);
    }} catch (_) {{}}
    window.location.replace('/invite/' + token);
  }})();
</script>
"#,
        encode_minimal(token),
    )
}

fn onboarding_summary(
    config: &Config,
    token: &str,
    username: Option<&str>,
    password: Option<&str>,
    saved_at: Option<i64>,
) -> String {
    let homeserver_display = homeserver_url_host(&config.homeserver_url);
    let storage_key = summary_storage_key(token);
    let summary_mode = if username.is_some() && password.is_some() {
        "save"
    } else {
        "load"
    };
    let username_value = username.unwrap_or("");
    let password_value = password.unwrap_or("");
    format!(
        r#"
<div class="summary-block" data-summary-mode="{}" data-summary-key="{}" data-summary-token="{}" data-summary-username="{}" data-summary-password="{}" data-summary-saved-at="{}">
  <div class="section-title">{}</div>
  <ul class="summary-list">
    <li><strong>Username:</strong> <span data-summary-field="username">{}</span></li>
    <li><strong>Password:</strong> <span data-summary-field="password">{}</span></li>
    {}
    {}
    {}
    {}
  </ul>
  <div class="actions summary-actions">
    <a href="/invite/{}?step=form&fresh=1" data-reset-invite-state>Start over</a>
    <a href="/invite/{}?clear=1" data-clear-invite-state>Clear saved details</a>
  </div>
</div>
{}"#,
        summary_mode,
        encode_minimal(&storage_key),
        encode_minimal(token),
        encode_minimal(username_value),
        encode_minimal(password_value),
        encode_minimal(&saved_at.map(|value| value.to_string()).unwrap_or_default()),
        copy::CHECKLIST_TITLE,
        encode_minimal(username_value),
        encode_minimal(password_value),
        copy::RECOVERY_KEY_ITEM,
        copy::provider_item(&homeserver_display, &config.homeserver_url),
        copy::CLIENTS_ITEM,
        copy::PRIVACY_ITEM,
        encode_minimal(token),
        encode_minimal(token),
        onboarding_links(config),
    )
}

fn draft_state_script(token: &str) -> String {
    format!(
        r#"
<script>
  (() => {{
    const block = document.querySelector('[data-invite-form-key="{}"]');
    if (!block) return;

    const fresh = new URLSearchParams(window.location.search).get('fresh') === '1';
    const summaryKey = 'matrix-invite-portal.summary.' + block.dataset.inviteFormToken;
    const draftKey = 'matrix-invite-portal.draft.' + block.dataset.inviteFormToken;
    const token = block.dataset.inviteFormToken || '';
    const summaryUrl = '/invite/' + token + '?step=summary';
    const form = block.querySelector('form');
    const usernameInput = block.querySelector('#username');
    const passwordInput = block.querySelector('#password');
    const confirmInput = block.querySelector('#confirm_password');
    const maxAgeMs = 48 * 60 * 60 * 1000;

    const parseSnapshot = (raw) => {{
      try {{
        if (!raw) return null;
        const state = typeof raw === 'string' ? JSON.parse(raw) : raw;
        if (!state || state.token !== token) return null;
        if (!state.username || !state.password) return null;
        return {{
          token,
          username: state.username,
          password: state.password,
          saved_at: Number(state.saved_at) || Date.now(),
        }};
      }} catch (_) {{
        return null;
      }}
    }};
    const readSnapshot = () => {{
      const state =
        parseSnapshot(window.localStorage.getItem(summaryKey)) ||
        parseSnapshot(window.name) ||
        parseSnapshot(window.history.state && window.history.state.matrixInvitePortalSummary);
      if (state && Date.now() - state.saved_at <= maxAgeMs) {{
        return state;
      }}
      return null;
    }};

    const clearForm = () => {{
      if (form) form.reset();
      if (usernameInput) usernameInput.value = '';
      if (passwordInput) passwordInput.value = '';
      if (confirmInput) confirmInput.value = '';
    }};

    if (fresh) {{
      try {{
        window.localStorage.removeItem(summaryKey);
        window.localStorage.removeItem(draftKey);
        window.name = '';
      }} catch (_) {{}}
    }}

    try {{
      const state = readSnapshot();
      if (state) {{
        window.localStorage.setItem(summaryKey, JSON.stringify(state));
        window.name = JSON.stringify(state);
        try {{
          window.history.replaceState({{ matrixInvitePortalSummary: state }}, '', summaryUrl);
        }} catch (_) {{}}
        window.location.replace(summaryUrl);
        return;
      }}

      if (window.localStorage.getItem(summaryKey)) {{
        window.localStorage.removeItem(summaryKey);
      }}
    }} catch (_) {{}}

    window.addEventListener('pageshow', () => {{
      try {{
        const state = readSnapshot();
        if (state) {{
          window.location.replace(summaryUrl);
        }}
      }} catch (_) {{}}
    }});

    clearForm();
    window.addEventListener('pageshow', clearForm);
  }})();
</script>
"#,
        encode_minimal(token),
    )
}

fn summary_state_script(token: &str) -> String {
    format!(
        r#"
<script>
  (() => {{
    const block = document.querySelector('[data-summary-key="{}"]');
    if (!block) return;

    const key = block.dataset.summaryKey;
    const draftKey = 'matrix-invite-portal.draft.' + block.dataset.summaryToken;
    const mode = block.dataset.summaryMode;
    const token = block.dataset.summaryToken;
    const usernameField = block.querySelector('[data-summary-field="username"]');
    const passwordField = block.querySelector('[data-summary-field="password"]');
    const resetLink = block.querySelector('[data-reset-invite-state]');
    const clearLink = block.querySelector('[data-clear-invite-state]');
    const maxAgeMs = 48 * 60 * 60 * 1000;

    const parseSnapshot = (raw) => {{
      try {{
        if (!raw) return null;
        const state = typeof raw === 'string' ? JSON.parse(raw) : raw;
        if (!state || state.token !== token) return null;
        if (!state.username || !state.password) return null;
        return {{
          token,
          username: state.username,
          password: state.password,
          saved_at: Number(state.saved_at) || Date.now(),
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
      if (usernameField) usernameField.textContent = data.username || '';
      if (passwordField) passwordField.textContent = data.password || '';
    }};

    const persistSnapshot = (data) => {{
      window.localStorage.setItem(key, JSON.stringify(data));
      window.name = JSON.stringify(data);
    }};

    const clearSnapshot = () => {{
      window.localStorage.removeItem(key);
      window.localStorage.removeItem(draftKey);
      window.name = '';
    }};

    const restoreSummary = () => {{
      const state = readSnapshot();
      if (!state) return false;

      persistSnapshot(state);
      writeState(state);
      return true;
    }};

    try {{
      if (mode === 'save') {{
        const payload = {{
          token,
          username: block.dataset.summaryUsername || '',
          password: block.dataset.summaryPassword || '',
          saved_at: Number(block.dataset.summarySavedAt) || Date.now(),
        }};
        persistSnapshot(payload);
        writeState(payload);
      }} else {{
        restoreSummary();
      }}
    }} catch (_) {{
      return;
    }}

    if (resetLink) {{
      resetLink.addEventListener('click', () => {{
        try {{
          clearSnapshot();
        }} catch (_) {{}}
      }});
    }}

    if (clearLink) {{
      clearLink.addEventListener('click', () => {{
        try {{
          clearSnapshot();
        }} catch (_) {{}}
      }});
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
    )
}

fn onboarding_links(config: &Config) -> String {
    let ios_badge = data_uri("image/svg+xml", LEGACY_IOS_BADGE);
    let android_badge = data_uri("image/svg+xml", LEGACY_ANDROID_BADGE);
    let fdroid_badge = data_uri("image/png", LEGACY_FDROID_BADGE);
    let client_url = element_client_url(&config.homeserver_url);
    let client_display = client_url.trim_start_matches("https://");

    format!(
        r#"
<div class="badge-links">
  <a href="https://apps.apple.com/us/app/element-x-secure-chat-call/id1631335820" target="_blank" rel="noreferrer">
    <img src="{}" alt="Download Element X for iOS">
  </a>
  <a href="https://play.google.com/store/apps/details?id=io.element.android.x" target="_blank" rel="noreferrer">
    <img src="{}" alt="Download Element X for Android">
  </a>
  <a href="https://f-droid.org/packages/chat.schildi.android/" target="_blank" rel="noreferrer">
    <img src="{}" alt="Get SchildiChat on F-Droid">
  </a>
</div>
<div class="section-title">{}</div>
<ul class="client-list">
  <li><a class="client-link" href="{}" target="_blank" rel="noreferrer"><span class="label">Element Web</span><span class="url">{}</span></a></li>
  <li><a class="client-link" href="https://matrix.org/ecosystem/clients/element/" target="_blank" rel="noreferrer"><span class="label">Element Desktop</span><span class="url">matrix.org/ecosystem/clients/element/</span></a></li>
  <li><a class="client-link" href="https://matrix.org/ecosystem/clients/" target="_blank" rel="noreferrer"><span class="label">More clients</span><span class="url">matrix.org/ecosystem/clients/</span></a></li>
</ul>
<div class="actions">
  <a href="{}" target="_blank" rel="noreferrer">{}</a>
</div>
<p class="muted small footer-note"><a class="matrix-link" href="https://matrix.org/" target="_blank" rel="noreferrer">{}</a></p>
"#,
        encode_minimal(&ios_badge),
        encode_minimal(&android_badge),
        encode_minimal(&fdroid_badge),
        copy::SECTION_APPS,
        encode_minimal(&client_url),
        encode_minimal(client_display),
        encode_minimal(&config.info_website_url),
        copy::LINK_HELP_GUIDE,
        copy::LINK_WHAT_IS_MATRIX,
    )
}

fn json_error(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Json(ErrorResponse {
            error: message.into(),
        }),
    )
        .into_response()
}

fn html_error(status: StatusCode, title: &str, body: &str) -> Response {
    (status, page(title, body)).into_response()
}

fn is_authorized(headers: &HeaderMap, expected_token: &str) -> bool {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(|token| token == expected_token)
        .unwrap_or(false)
}

async fn health() -> &'static str {
    "ok"
}

async fn favicon() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn root_page(State(state): State<AppState>) -> Html<String> {
    page(
        &state.config.portal_title,
        &format!(
            r#"
<div class="card">
  <h1>{}</h1>
  <p>{}</p>
  <p class="muted">{}</p>
</div>
"#,
            encode_minimal(&state.config.portal_title),
            encode_minimal(&state.config.portal_root_message),
            encode_minimal(
                "This website only creates accounts for people who were given a private invite link."
            ),
        ),
    )
}

async fn show_invite(
    State(state): State<AppState>,
    AxumPath(token): AxumPath<String>,
    Query(query): Query<InvitePageQuery>,
) -> Response {
    let status = load_invite_status(&state.config.database_path, &token);
    let show_form = query.step.as_deref() == Some("form");
    let show_summary = query.step.as_deref() == Some("summary");
    let wants_clear = query.clear.as_deref() == Some("1");
    match status {
        Ok(Some(invite)) if invite.revoked_at.is_some() => html_error(
            StatusCode::GONE,
            copy::INVITE_PAGE_CANCELLED,
            &format!(
                r#"<div class="card"><h1>{}</h1><div class="notice error">{}</div><p>{}</p></div>"#,
                copy::INVITE_PAGE_CANCELLED,
                copy::NOTICE_INVITE_CANCELLED,
                encode_minimal(&state.config.portal_failure_message),
            ),
        ),
        Ok(Some(invite)) if invite.expires_at <= now_ts() => html_error(
            StatusCode::GONE,
            copy::INVITE_PAGE_EXPIRED,
            &format!(
                r#"<div class="card"><h1>{}</h1><div class="notice error">{}</div><p>{}</p></div>"#,
                copy::INVITE_PAGE_EXPIRED,
                copy::NOTICE_INVITE_EXPIRED,
                encode_minimal(&state.config.portal_failure_message),
            ),
        ),
        Ok(Some(invite)) => {
            let invite_used = invite.use_limit > 0 && invite.use_count >= invite.use_limit;
            let message = if invite.last_failure_at.is_some() {
                format!(
                    r#"<div class="notice error">{}</div>"#,
                    copy::NOTICE_LAST_ATTEMPT_FAILED
                )
            } else {
                String::new()
            };

            if wants_clear {
                return page(
                    &state.config.portal_title,
                    &clear_summary_state_page(&token),
                )
                .into_response();
            }

            if show_summary || invite_used {
                let used_notice = if invite_used {
                    format!(
                        r#"<div class="notice info">{}</div>"#,
                        copy::NOTICE_INVITE_USED_SUMMARY
                    )
                } else {
                    String::new()
                };
                page(
                    &state.config.portal_title,
                    &format!(
                        r#"
<div class="card">
  <h1>{}</h1>
  <div class="notice success">{}</div>
  {}
  {}
</div>
{}"#,
                        encode_minimal(&state.config.portal_title),
                        encode_minimal(&state.config.portal_success_message),
                        used_notice,
                        onboarding_summary(&state.config, &token, None, None, None),
                        summary_state_script(&token),
                    ),
                )
                .into_response()
            } else if show_form && !invite_used {
                page(
                    &state.config.portal_title,
                    &invite_form_html(&state.config, &token, &message),
                )
                .into_response()
            } else {
                page(
                    &state.config.portal_title,
                    &onboarding_intro(&token, &state.config.homeserver_url),
                )
                .into_response()
            }
        }
        Ok(None) => html_error(
            StatusCode::NOT_FOUND,
            copy::INVITE_PAGE_NOT_VALID,
            &format!(
                r#"<div class="card"><h1>{}</h1><p>{}</p></div>"#,
                copy::INVITE_PAGE_NOT_VALID,
                copy::NOTICE_INVITE_NOT_FOUND,
            ),
        ),
        Err(AppError::NotFound(_)) => html_error(
            StatusCode::NOT_FOUND,
            copy::INVITE_PAGE_NOT_VALID,
            &format!(
                r#"<div class="card"><h1>{}</h1><p>{}</p></div>"#,
                copy::INVITE_PAGE_NOT_VALID,
                copy::NOTICE_INVITE_NOT_FOUND,
            ),
        ),
        Err(_) => html_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            copy::ERROR_TITLE,
            copy::ERROR_CARD,
        ),
    }
}

async fn redeem_invite(
    State(state): State<AppState>,
    AxumPath(token): AxumPath<String>,
    Form(form): Form<RedeemForm>,
) -> Response {
    if let Err(message) = validate_username(&form.username) {
        return html_error(
            StatusCode::BAD_REQUEST,
            copy::ACCOUNT_NOT_CREATED_TITLE,
            &format!(
                r#"<div class="card"><h1>{}</h1>{}<p><a href="/invite/{}?step=form">{}</a></p></div>"#,
                copy::ACCOUNT_NOT_CREATED_TITLE,
                copy::form_error_notice(&message),
                encode_minimal(&token),
                copy::LINK_BACK_TO_FORM,
            ),
        );
    }

    if let Err(message) = validate_password(&form.password) {
        return html_error(
            StatusCode::BAD_REQUEST,
            copy::ACCOUNT_NOT_CREATED_TITLE,
            &format!(
                r#"<div class="card"><h1>{}</h1>{}<p><a href="/invite/{}?step=form">{}</a></p></div>"#,
                copy::ACCOUNT_NOT_CREATED_TITLE,
                copy::form_error_notice(&message),
                encode_minimal(&token),
                copy::LINK_BACK_TO_FORM,
            ),
        );
    }

    if form.password != form.confirm_password {
        let message = copy::form_error_notice(copy::PASSWORDS_DO_NOT_MATCH);
        return html_error(
            StatusCode::BAD_REQUEST,
            &state.config.portal_title,
            &invite_form_html(&state.config, &token, &message),
        );
    }

    match redeem_token(state.config.clone(), &token, &form.username, &form.password).await {
        Ok(()) => page(
            &state.config.portal_title,
            &format!(
                r#"<div class="card"><h1>{}</h1><div class="notice success">{}</div>{}{}</div>"#,
                encode_minimal(&state.config.portal_title),
                encode_minimal(&state.config.portal_success_message),
                onboarding_summary(
                    &state.config,
                    &token,
                    Some(form.username.as_str()),
                    Some(form.password.as_str()),
                    Some(now_ts()),
                ),
                summary_state_script(&token),
            ),
        )
        .into_response(),
        Err(AppError::NotFound(_)) => html_error(
            StatusCode::NOT_FOUND,
            copy::ACCOUNT_NOT_CREATED_TITLE,
            &format!(
                r#"<div class="card"><h1>{}</h1><div class="notice error">{}</div><p>{}</p><p><a href="/">{}</a></p></div>"#,
                copy::ACCOUNT_NOT_CREATED_TITLE,
                copy::NOTICE_INVITE_NOT_FOUND,
                encode_minimal(&state.config.portal_failure_message),
                copy::LINK_GO_TO_START,
            ),
        ),
        Err(AppError::Provisioning(message)) => html_error(
            StatusCode::BAD_GATEWAY,
            copy::ACCOUNT_NOT_CREATED_TITLE,
            &format!(
                r#"<div class="card"><h1>{}</h1><div class="notice error">{}</div><p>{}</p><p><a href="/invite/{}?step=form">{}</a></p></div>"#,
                copy::ACCOUNT_NOT_CREATED_TITLE,
                encode_minimal(&message),
                encode_minimal(&state.config.portal_failure_message),
                encode_minimal(&token),
                copy::LINK_TRY_AGAIN,
            ),
        ),
        Err(AppError::Timeout) => html_error(
            StatusCode::GATEWAY_TIMEOUT,
            copy::ACCOUNT_NOT_CREATED_TITLE,
            &format!(
                r#"<div class="card"><h1>{}</h1><div class="notice error">{}</div><p>{}</p><p><a href="/invite/{}?step=form">{}</a></p></div>"#,
                copy::ACCOUNT_NOT_CREATED_TITLE,
                copy::NOTICE_ACCOUNT_CREATION_TIMED_OUT,
                encode_minimal(&state.config.portal_failure_message),
                encode_minimal(&token),
                copy::LINK_TRY_AGAIN,
            ),
        ),
        Err(_) => html_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            copy::ERROR_TITLE,
            &format!(
                r#"<div class="card"><h1>{}</h1><p>{}</p></div>"#,
                copy::ERROR_TITLE,
                encode_minimal(&state.config.portal_failure_message),
            ),
        ),
    }
}

async fn create_invite(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateInviteRequest>,
) -> Response {
    if !is_authorized(&headers, &state.config.admin_token) {
        return json_error(StatusCode::UNAUTHORIZED, "unauthorized");
    }

    match create_invite_record(state.config.clone(), request) {
        Ok(response) => (StatusCode::CREATED, Json(response)).into_response(),
        Err(AppError::NotFound(message)) => json_error(StatusCode::NOT_FOUND, message),
        Err(err) => json_error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

async fn list_invites(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !is_authorized(&headers, &state.config.admin_token) {
        return json_error(StatusCode::UNAUTHORIZED, "unauthorized");
    }

    match list_invites_records(&state.config.database_path) {
        Ok(records) => Json(records).into_response(),
        Err(AppError::NotFound(message)) => json_error(StatusCode::NOT_FOUND, message),
        Err(err) => json_error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

async fn revoke_invite(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(invite_id): AxumPath<String>,
    Json(request): Json<RevokeInviteRequest>,
) -> Response {
    if !is_authorized(&headers, &state.config.admin_token) {
        return json_error(StatusCode::UNAUTHORIZED, "unauthorized");
    }

    match revoke_invite_record(
        &state.config.database_path,
        &invite_id,
        request.reason.as_deref(),
    ) {
        Ok(()) => Json(json!({"status":"revoked"})).into_response(),
        Err(AppError::NotFound(message)) => json_error(StatusCode::NOT_FOUND, message),
        Err(err) => json_error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

async fn revoke_all_invites(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RevokeInviteRequest>,
) -> Response {
    if !is_authorized(&headers, &state.config.admin_token) {
        return json_error(StatusCode::UNAUTHORIZED, "unauthorized");
    }

    match revoke_all_invites_record(&state.config.database_path, request.reason.as_deref()) {
        Ok(revoked_count) => Json(RevokeAllInvitesResponse {
            status: "revoked".to_owned(),
            revoked_count,
        })
        .into_response(),
        Err(AppError::NotFound(message)) => json_error(StatusCode::NOT_FOUND, message),
        Err(err) => json_error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

async fn rotate_invite(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(invite_id): AxumPath<String>,
    Json(request): Json<RevokeInviteRequest>,
) -> Response {
    if !is_authorized(&headers, &state.config.admin_token) {
        return json_error(StatusCode::UNAUTHORIZED, "unauthorized");
    }

    match rotate_invite_record(state.config.clone(), &invite_id, request.reason.as_deref()) {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(AppError::NotFound(message)) => json_error(StatusCode::NOT_FOUND, message),
        Err(err) => json_error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

fn load_invite_status(database_path: &Path, token: &str) -> Result<Option<InviteRecord>, AppError> {
    let conn = open_connection(database_path)?;
    let record = conn
        .query_row(
            r#"
            SELECT invite_id, token_preview, created_at, expires_at, created_by, use_limit, use_count,
                   revoked_at, claimed_at, claimed_until, claimed_by, redeemed_at, redeemed_by,
                   last_failure_reason, last_failure_at
            FROM invites
            WHERE token_hash = ?1
            "#,
            params![hash_token(token)],
            |row| {
                Ok(InviteRecord {
                    invite_id: row.get(0)?,
                    token_preview: row.get(1)?,
                    created_at: row.get(2)?,
                    expires_at: row.get(3)?,
                    created_by: row.get(4)?,
                    use_limit: row.get(5)?,
                    use_count: row.get(6)?,
                    revoked_at: row.get(7)?,
                    claimed_at: row.get(8)?,
                    claimed_until: row.get(9)?,
                    claimed_by: row.get(10)?,
                    redeemed_at: row.get(11)?,
                    redeemed_by: row.get(12)?,
                    last_failure_reason: row.get(13)?,
                    last_failure_at: row.get(14)?,
                })
            },
        )
        .optional()?;

    Ok(record)
}

fn create_invite_record(
    config: Arc<Config>,
    request: CreateInviteRequest,
) -> Result<CreateInviteResponse, AppError> {
    let invite_id = generate_invite_id();
    let token = generate_token();
    let token_hash = hash_token(&token);
    let token_preview = token_preview(&token);
    let now = now_ts();
    let created_by = request.created_by.unwrap_or_else(|| "admin-api".to_owned());
    let expires_in_hours = request
        .expires_in_hours
        .unwrap_or(config.default_invite_ttl_hours)
        .max(1);
    let use_limit = request.use_limit.unwrap_or(config.default_use_limit).max(1);
    let expires_at = now + (expires_in_hours * 3600);
    let note = request.note;

    let conn = open_connection(&config.database_path)?;
    conn.execute(
        r#"
        INSERT INTO invites (
            invite_id, token_hash, token_preview, created_at, expires_at, created_by, note,
            use_limit, use_count, revoked_at, claimed_at, claimed_until, claimed_by,
            redeemed_at, redeemed_by, last_failure_reason, last_failure_at
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7,
            ?8, 0, NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL
        )
        "#,
        params![
            invite_id,
            token_hash,
            token_preview,
            now,
            expires_at,
            created_by,
            note,
            use_limit
        ],
    )?;

    record_event(
        &conn,
        &invite_id,
        &token_hash,
        "created",
        Some("admin-api"),
        note.as_deref(),
    )?;

    Ok(CreateInviteResponse {
        invite_id,
        invite_url: invite_link(&config, &token),
        token,
        token_preview,
        created_at: now,
        expires_at,
        use_limit,
    })
}

fn list_invites_records(database_path: &Path) -> Result<Vec<InviteRecord>, AppError> {
    let conn = open_connection(database_path)?;
    let mut stmt = conn.prepare(
        r#"
        SELECT invite_id, token_preview, created_at, expires_at, created_by, use_limit, use_count,
               revoked_at, claimed_at, claimed_until, claimed_by, redeemed_at, redeemed_by,
               last_failure_reason, last_failure_at
        FROM invites
        ORDER BY created_at DESC
        LIMIT 100
        "#,
    )?;

    let rows = stmt.query_map([], |row| {
        Ok(InviteRecord {
            invite_id: row.get(0)?,
            token_preview: row.get(1)?,
            created_at: row.get(2)?,
            expires_at: row.get(3)?,
            created_by: row.get(4)?,
            use_limit: row.get(5)?,
            use_count: row.get(6)?,
            revoked_at: row.get(7)?,
            claimed_at: row.get(8)?,
            claimed_until: row.get(9)?,
            claimed_by: row.get(10)?,
            redeemed_at: row.get(11)?,
            redeemed_by: row.get(12)?,
            last_failure_reason: row.get(13)?,
            last_failure_at: row.get(14)?,
        })
    })?;

    let mut records = Vec::new();
    for row in rows {
        records.push(row?);
    }

    Ok(records)
}

fn revoke_invite_record(
    database_path: &Path,
    invite_id: &str,
    reason: Option<&str>,
) -> Result<(), AppError> {
    let now = now_ts();
    let conn = open_connection(database_path)?;
    let mut stmt = conn.prepare("SELECT token_hash FROM invites WHERE invite_id = ?1")?;
    let token_hash = stmt
        .query_row(params![invite_id], |row| row.get::<_, String>(0))
        .optional()?
        .ok_or_else(|| AppError::NotFound("Invite not found.".into()))?;

    conn.execute(
        r#"
        UPDATE invites
        SET revoked_at = COALESCE(revoked_at, ?2),
            claimed_at = NULL,
            claimed_until = NULL,
            claimed_by = NULL,
            last_failure_reason = ?3,
            last_failure_at = ?2
        WHERE invite_id = ?1
        "#,
        params![invite_id, now, reason.unwrap_or("revoked by admin")],
    )?;
    record_event(
        &conn,
        invite_id,
        &token_hash,
        "revoked",
        Some("admin-api"),
        reason,
    )?;
    Ok(())
}

fn revoke_all_invites_record(
    database_path: &Path,
    reason: Option<&str>,
) -> Result<usize, AppError> {
    let now = now_ts();
    let mut conn = open_connection(database_path)?;
    let tx = conn.transaction()?;

    let invites = {
        let mut stmt = tx.prepare(
            r#"
            SELECT invite_id, token_hash
            FROM invites
            WHERE revoked_at IS NULL
            "#,
        )?;

        let mut rows = Vec::new();
        for row in stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })? {
            rows.push(row?);
        }
        rows
    };

    let revoked_count = invites.len();
    let reason = reason.unwrap_or("revoked by admin");

    for (invite_id, token_hash) in invites {
        tx.execute(
            r#"
            UPDATE invites
            SET revoked_at = COALESCE(revoked_at, ?2),
                claimed_at = NULL,
                claimed_until = NULL,
                claimed_by = NULL,
                last_failure_reason = ?3,
                last_failure_at = ?2
            WHERE invite_id = ?1
            "#,
            params![invite_id, now, reason],
        )?;
        record_event_tx(
            &tx,
            &invite_id,
            &token_hash,
            "revoked",
            Some("admin-api"),
            Some(json!({"reason": reason, "scope": "all"})),
        )?;
    }

    tx.commit()?;
    Ok(revoked_count)
}

fn rotate_invite_record(
    config: Arc<Config>,
    invite_id: &str,
    reason: Option<&str>,
) -> Result<CreateInviteResponse, AppError> {
    let token = generate_token();
    let token_hash = hash_token(&token);
    let token_preview = token_preview(&token);
    let now = now_ts();
    let conn = open_connection(&config.database_path)?;

    let existing = conn
        .query_row(
            r#"
            SELECT token_hash, expires_at, use_limit, use_count, revoked_at
            FROM invites
            WHERE invite_id = ?1
            "#,
            params![invite_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| AppError::NotFound("Invite not found.".into()))?;

    let (_old_token_hash, expires_at, use_limit, use_count, revoked_at) = existing;
    if revoked_at.is_some() {
        return Err(AppError::Provisioning(copy::NOTICE_INVITE_CANCELLED.into()));
    }
    if expires_at <= now {
        return Err(AppError::Provisioning(copy::NOTICE_INVITE_EXPIRED.into()));
    }
    if use_limit > 0 && use_count >= use_limit {
        return Err(AppError::Provisioning(copy::NOTICE_INVITE_USED.into()));
    }

    conn.execute(
        r#"
        UPDATE invites
        SET token_hash = ?2,
            token_preview = ?3,
            claimed_at = NULL,
            claimed_until = NULL,
            claimed_by = NULL,
            last_failure_reason = NULL,
            last_failure_at = NULL
        WHERE invite_id = ?1
        "#,
        params![invite_id, token_hash, token_preview],
    )?;

    record_event(
        &conn,
        invite_id,
        &token_hash,
        "rotated",
        Some("admin-api"),
        reason,
    )?;
    Ok(CreateInviteResponse {
        invite_id: invite_id.to_owned(),
        invite_url: invite_link(&config, &token),
        token,
        token_preview,
        created_at: now,
        expires_at,
        use_limit,
    })
}

async fn redeem_token(
    config: Arc<Config>,
    token: &str,
    username: &str,
    password: &str,
) -> Result<(), AppError> {
    let token_hash = hash_token(token);
    let now = now_ts();
    let claim_until = now + config.provisioning_claim_timeout_seconds as i64;
    let invite_id = {
        let mut conn = open_connection(&config.database_path)?;
        let tx = conn.transaction()?;

        let invite = tx
            .query_row(
                r#"
                SELECT invite_id, created_at, expires_at, use_limit, use_count, revoked_at, claimed_at, claimed_until
                FROM invites
                WHERE token_hash = ?1
                "#,
                params![token_hash],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, Option<i64>>(5)?,
                        row.get::<_, Option<i64>>(6)?,
                        row.get::<_, Option<i64>>(7)?,
                    ))
                },
            )
            .optional()?;

        let Some((
            found_invite_id,
            _created_at,
            expires_at,
            use_limit,
            use_count,
            revoked_at,
            claimed_at,
            claimed_until_existing,
        )) = invite
        else {
            return Err(AppError::NotFound(copy::NOTICE_INVITE_NOT_FOUND.into()));
        };

        if revoked_at.is_some() {
            return Err(AppError::Provisioning(copy::NOTICE_INVITE_CANCELLED.into()));
        }

        if expires_at <= now {
            return Err(AppError::Provisioning(copy::NOTICE_INVITE_EXPIRED.into()));
        }

        if use_limit > 0 && use_count >= use_limit {
            return Err(AppError::Provisioning(copy::NOTICE_INVITE_USED.into()));
        }

        if claimed_at.is_some() && claimed_until_existing.unwrap_or_default() > now {
            return Err(AppError::Provisioning(copy::NOTICE_INVITE_BUSY.into()));
        }

        tx.execute(
            r#"
            UPDATE invites
            SET claimed_at = ?2, claimed_until = ?3, claimed_by = ?4, last_failure_reason = NULL, last_failure_at = NULL
            WHERE token_hash = ?1
            "#,
            params![token_hash, now, claim_until, username],
        )?;
        record_event_tx(
            &tx,
            &found_invite_id,
            &token_hash,
            "claimed",
            Some(username),
            Some(json!({"username": username})),
        )?;
        tx.commit()?;

        found_invite_id
    };

    match timeout(
        Duration::from_secs(config.provisioning_timeout_seconds),
        provision_user_via_synapse_registration_shared_secret(config.clone(), username, password),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            let message = error.to_string();
            mark_failure(
                &config.database_path,
                &invite_id,
                &token_hash,
                username,
                &message,
            )?;
            return Err(error);
        }
        Err(_) => {
            let _ = mark_failure(
                &config.database_path,
                &invite_id,
                &token_hash,
                username,
                "Provisioning timed out",
            );
            return Err(AppError::Timeout);
        }
    }

    let mut conn = open_connection(&config.database_path)?;
    let tx = conn.transaction()?;
    tx.execute(
        r#"
        UPDATE invites
        SET use_count = use_count + 1,
            redeemed_at = ?2,
            redeemed_by = ?3,
            claimed_at = NULL,
            claimed_until = NULL,
            claimed_by = NULL,
            last_failure_reason = NULL,
            last_failure_at = NULL
        WHERE token_hash = ?1
        "#,
        params![token_hash, now, username],
    )?;
    record_event_tx(
        &tx,
        &invite_id,
        &token_hash,
        "redeemed",
        Some(username),
        Some(json!({"username": username})),
    )?;
    tx.commit()?;

    Ok(())
}

fn mark_failure(
    database_path: &Path,
    invite_id: &str,
    token_hash: &str,
    username: &str,
    reason: &str,
) -> Result<(), AppError> {
    let now = now_ts();
    let mut conn = open_connection(database_path)?;
    let tx = conn.transaction()?;
    tx.execute(
        r#"
        UPDATE invites
        SET claimed_at = NULL,
            claimed_until = NULL,
            claimed_by = NULL,
            last_failure_reason = ?2,
            last_failure_at = ?3
        WHERE token_hash = ?1
        "#,
        params![token_hash, reason, now],
    )?;
    record_event_tx(
        &tx,
        invite_id,
        token_hash,
        "failed",
        Some(username),
        Some(json!({"reason": reason})),
    )?;
    tx.commit()?;
    Ok(())
}

fn record_event(
    conn: &Connection,
    invite_id: &str,
    token_hash: &str,
    event_type: &str,
    actor: Option<&str>,
    details: Option<&str>,
) -> Result<(), AppError> {
    conn.execute(
        r#"
        INSERT INTO invite_events (invite_id, token_hash, event_type, created_at, actor, details)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        "#,
        params![invite_id, token_hash, event_type, now_ts(), actor, details],
    )?;
    Ok(())
}

fn record_event_tx(
    tx: &rusqlite::Transaction<'_>,
    invite_id: &str,
    token_hash: &str,
    event_type: &str,
    actor: Option<&str>,
    details: Option<serde_json::Value>,
) -> Result<(), AppError> {
    let details = details.map(|value| value.to_string());
    tx.execute(
        r#"
        INSERT INTO invite_events (invite_id, token_hash, event_type, created_at, actor, details)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        "#,
        params![invite_id, token_hash, event_type, now_ts(), actor, details],
    )?;
    Ok(())
}
