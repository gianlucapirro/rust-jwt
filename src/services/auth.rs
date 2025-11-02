use argon2::password_hash::{PasswordHash, SaltString, rand_core::OsRng};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use axum::{
    extract::{FromRef, FromRequestParts, State},
    http::request::Parts,
};
use axum_extra::extract::CookieJar;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::settings::SETTINGS;
use crate::{AppState, core::errors::app::AppError};

pub struct Hasher {
    pub hash: String,
}

impl Hasher {
    /// Creates a new Hasher instance, containing the hashed password
    pub fn new(password: &str) -> Self {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        let hashed = argon2
            .hash_password(password.as_bytes(), &salt)
            .expect("hashing failed");

        Self {
            hash: hashed.to_string(),
        }
    }

    /// Verifies password against the stored hash, returning true if they match
    pub fn verify(&self, password: &str) -> bool {
        let parsed_hash = PasswordHash::new(&self.hash).expect("invalid stored hash format");

        Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok()
    }
}

#[derive(Clone)]
pub struct JwtConfig {
    issuer: String,
    audience: String,
    ttl_seconds: i64,
    enc: EncodingKey,
    dec: DecodingKey,
}

impl JwtConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let secret = SETTINGS.jwt_secret.clone();
        Ok(Self {
            issuer: SETTINGS.jwt_issuer.clone(),
            audience: SETTINGS.jwt_audience.clone(),
            ttl_seconds: SETTINGS.jwt_ttl_secs.clone(),
            enc: EncodingKey::from_secret(secret.as_bytes()),
            dec: DecodingKey::from_secret(secret.as_bytes()),
        })
    }

    pub fn validation(&self) -> Validation {
        let mut v = Validation::new(Algorithm::HS256);
        v.set_issuer(&[self.issuer.clone()]);
        v.set_audience(&[self.audience.clone()]);
        v.validate_exp = true;
        v.leeway = 5; // small clock skew
        v
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    iss: String,
    aud: String,
    pub sub: String,   // user id
    pub email: String, // email
    iat: i64,
    nbf: i64,
    exp: i64,
}

pub fn sign_jwt(user_id: i32, email: &str, cfg: &JwtConfig) -> Result<String, AppError> {
    use jsonwebtoken::encode;

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let exp = now + cfg.ttl_seconds as i64;

    let claims = Claims {
        iss: cfg.issuer.clone(),
        aud: cfg.audience.clone(),
        sub: user_id.to_string(),
        email: email.to_string(),
        iat: now,
        nbf: now - 1,
        exp,
    };

    encode(&Header::new(Algorithm::HS256), &claims, &cfg.enc).map_err(|_| AppError::Internal)
}

pub struct Auth(pub Claims);

impl<S> FromRequestParts<S> for Auth
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // 1) pull AppState from S
        let State(app): State<AppState> = State::from_request_parts(parts, state)
            .await
            .map_err(|_| AppError::Internal)?;

        // 2) read cookie
        let jar = CookieJar::from_request_parts(parts, state)
            .await
            .map_err(|_| AppError::Internal)?;
        let token = jar
            .get(SETTINGS.auth_cookie_name.as_str())
            .ok_or(AppError::Unauthorized("Missing auth cookie"))?
            .value()
            .to_owned();

        // 3) verify
        let data = jsonwebtoken::decode::<Claims>(&token, &app.jwt.dec, &app.jwt.validation())
            .map_err(|_| AppError::Unauthorized("Invalid token"))?;

        Ok(Auth(data.claims))
    }
}
