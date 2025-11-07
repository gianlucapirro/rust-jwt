use super::helpers::{get, must, parse_bool, parse_i64, parse_samesite};
use anyhow::Result;
use cookie::SameSite;
use once_cell::sync::Lazy;
use once_cell::sync::OnceCell;

static HOUR: i64 = 60 * 60;
static DAY: i64 = HOUR * 24;
static WEEK: i64 = DAY * 7;

static DID_LOAD_ENV: OnceCell<()> = OnceCell::new();

pub fn load_env() {
    DID_LOAD_ENV.get_or_init(|| {
        if let Ok(path) = std::env::var("ENV_FILE") {
            dotenvy::from_filename(&path)
                .expect("ENV_FILE was set but could not be loaded");
            return;
        } else {
            dotenvy::from_filename(".env.test")
                .expect("ENV_FILE was not set, defaulted to .env.test, but could not be loaded");
            return;
        }
    });
}

#[derive(Clone, Debug)]
pub struct Settings {
    pub database_url: String,

    // JWT
    pub jwt_access_secret: String,
    pub jwt_access_ttl_secs: i64,
    pub jwt_refresh_secret: String,
    pub jwt_refresh_ttl_secs: i64,

    pub jwt_audience: String,
    pub jwt_issuer: String,

    // COOKIES
    pub auth_cookie_name: String, // default: "_auth"
    pub auth_cookie_path: String, // default: "/"

    pub refresh_cookie_name: String,
    pub refresh_cookie_path: String,

    // pub auth_cookie_domain: Option<String>,
    pub auth_cookie_samesite: SameSite, // default: Lax
    pub auth_cookie_secure: bool,       // default: true
}

impl Settings {
    pub fn from_env() -> Result<Self> {
        let database_url = must("DATABASE_URL")?;

        // JWT
        let jwt_access_secret = must("JWT_ACCESS_SECRET")?;
        let jwt_access_ttl_secs = parse_i64(&get("JWT_ACCESS_TTL_SECS"), HOUR)?;
        
        let jwt_refresh_secret = must("JWT_REFRESH_SECRET")?;
        let jwt_refresh_ttl_secs = parse_i64(&get("JWT_REFRESH_TTL_SECS"), WEEK)?;
        
        let jwt_audience = get("JWT_AUDIENCE").unwrap();
        let jwt_issuer = get("JWT_ISSUER").unwrap();

        // COOKIES
        let auth_cookie_name = get("AUTH_COOKIE_NAME").unwrap_or_else(|| "_auth".into());
        let auth_cookie_path = get("AUTH_COOKIE_PATH").unwrap_or_else(|| "/".into());
        let refresh_cookie_name = get("REFRESH_COOKIE_NAME").unwrap_or_else(|| "_refresh".into());
        let refresh_cookie_path = get("REFRESH_COOKIE_PATH").unwrap_or_else(|| "/".into());

        let auth_cookie_samesite =
            parse_samesite(&get("AUTH_COOKIE_SAMESITE").unwrap_or_else(|| "Strict".into()))?;
        let auth_cookie_secure = parse_bool(&get("AUTH_COOKIE_SECURE"), true);

        Ok(Self {
            database_url,
            jwt_access_secret,
            jwt_refresh_secret,
            jwt_issuer,
            jwt_audience,
            jwt_access_ttl_secs,
            jwt_refresh_ttl_secs,
            auth_cookie_name,
            auth_cookie_path,
            refresh_cookie_name,
            refresh_cookie_path,
            auth_cookie_samesite,
            auth_cookie_secure,
        })
    }
}

pub static SETTINGS: Lazy<Settings> = Lazy::new(|| {
    // panic on invalid/missing env so we fail-fast at startup
    Settings::from_env().expect("Invalid/missing environment variables for Settings")
});
