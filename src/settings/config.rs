use super::helpers::{get, must, parse_bool, parse_i64, parse_samesite};
use anyhow::Result;
use cookie::SameSite;
use once_cell::sync::Lazy;

#[derive(Clone, Debug)]
pub struct Settings {
    pub database_url: String,

    // JWT
    pub jwt_secret: String,
    pub jwt_issuer: String,
    pub jwt_audience: String,
    pub jwt_ttl_secs: i64,

    // COOKIES
    pub auth_cookie_name: String, // default: "_auth"
    pub auth_cookie_path: String, // default: "/"
    // pub auth_cookie_domain: Option<String>,
    pub auth_cookie_samesite: SameSite, // default: Lax
    pub auth_cookie_secure: bool,       // default: true
    pub auth_cookie_max_age_secs: i64,  // default: 604800

    // SOCIAL LOGIN
    pub google_client_id: String,
    pub google_client_secret: String,
    pub google_redirect_uri: String,
}

impl Settings {
    pub fn from_env() -> Result<Self> {
        let database_url = must("DATABASE_URL")?;

        // JWT
        let jwt_secret = must("JWT_SECRET")?;
        let jwt_issuer = get("JWT_ISSUER").unwrap_or_else(|| "actuary.aero".into());
        let jwt_audience = get("JWT_AUDIENCE").unwrap_or_else(|| "actuary.aero-api".into());
        let jwt_ttl_secs = parse_i64(&get("JWT_TTL_SECS"), 60 * 60)?;

        // COOKIES
        let auth_cookie_name = get("AUTH_COOKIE_NAME").unwrap_or_else(|| "_auth".into());
        let auth_cookie_path = get("AUTH_COOKIE_PATH").unwrap_or_else(|| "/".into());
        // let auth_cookie_domain = get("AUTH_COOKIE_DOMAIN").filter(|s| !s.is_empty());
        let auth_cookie_samesite =
            parse_samesite(&get("AUTH_COOKIE_SAMESITE").unwrap_or_else(|| "Strict".into()))?;
        let auth_cookie_secure = parse_bool(&get("AUTH_COOKIE_SECURE"), true);
        let auth_cookie_max_age_secs =
            parse_i64(&get("AUTH_COOKIE_MAX_AGE_SECS"), 60 * 60 * 24 * 7)?;

        // SOCIAL LOGIN
        let google_client_id = must("GOOGLE_CLIENT_ID")?;
        let google_client_secret = must("GOOGLE_CLIENT_SECRET")?;
        let google_redirect_uri = get("GOOGLE_REDIRECT_URI")
            .unwrap_or_else(|| "http://localhost:8080/api/auth/google/callback".into());

        Ok(Self {
            database_url,
            jwt_secret,
            jwt_issuer,
            jwt_audience,
            jwt_ttl_secs,
            auth_cookie_name,
            auth_cookie_path,
            // auth_cookie_domain,
            auth_cookie_samesite,
            auth_cookie_secure,
            auth_cookie_max_age_secs,
            google_client_id,
            google_client_secret,
            google_redirect_uri,
        })
    }
}

pub static SETTINGS: Lazy<Settings> = Lazy::new(|| {
    // panic on invalid/missing env so we fail-fast at startup
    Settings::from_env().expect("Invalid/missing environment variables for Settings")
});
