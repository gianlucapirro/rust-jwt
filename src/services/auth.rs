use cookie::time::Duration;

use argon2::password_hash::{PasswordHash, SaltString, rand_core::OsRng};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use axum::{
    extract::{FromRef, FromRequestParts, State},
    http::request::Parts,
};
use axum_extra::extract::CookieJar;
use cookie::Cookie;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;
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
    access_ttl_seconds: i64,
    refresh_ttl_seconds: i64,
    access_enc: EncodingKey,
    access_dec: DecodingKey,
    refresh_enc: EncodingKey,
    refresh_dec: DecodingKey,
}

impl JwtConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let access_secret = SETTINGS.jwt_access_secret.clone();
        let refresh_secret = SETTINGS.jwt_refresh_secret.clone();

        Ok(Self {
            issuer: SETTINGS.jwt_issuer.clone(),
            audience: SETTINGS.jwt_audience.clone(),
            access_ttl_seconds: SETTINGS.jwt_access_ttl_secs,
            refresh_ttl_seconds: SETTINGS.jwt_refresh_ttl_secs,
            access_enc: EncodingKey::from_secret(access_secret.as_bytes()),
            access_dec: DecodingKey::from_secret(access_secret.as_bytes()),
            refresh_enc: EncodingKey::from_secret(refresh_secret.as_bytes()),
            refresh_dec: DecodingKey::from_secret(refresh_secret.as_bytes()),
        })
    }

    pub fn access_validation(&self) -> Validation {
        let mut v = Validation::new(Algorithm::HS256);
        v.set_issuer(&[self.issuer.clone()]);
        v.set_audience(&[self.audience.clone()]);
        v.validate_exp = true;
        v.leeway = 5;
        v
    }

    pub fn refresh_validation(&self) -> Validation {
        let mut v = Validation::new(Algorithm::HS256);
        v.set_issuer(&[self.issuer.clone()]);
        v.set_audience(&[self.audience.clone()]);
        v.validate_exp = true;
        v.leeway = 5;
        v
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum TokenType {
    Access,
    Refresh,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JWTClaim{
    iss: String,
    aud: String,
    pub sub: String,
    iat: i64,
    nbf: i64,
    exp: i64,
    jti: String,
    token_type: TokenType
}

pub fn sign_jwt(user_id: i32, token_type: TokenType, cfg: &JwtConfig) -> Result<String, AppError> {
    /// Encodes and signs a JWT for the give user ID and token type
    use jsonwebtoken::encode;

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let (exp, enc) = match token_type {
        TokenType::Access => {
            (now + cfg.access_ttl_seconds as i64, &cfg.access_enc)
        },
        TokenType::Refresh => {
            (now + cfg.refresh_ttl_seconds as i64, &cfg.refresh_enc)
        },
    };

    let claims = JWTClaim {
        iss: cfg.issuer.clone(),
        aud: cfg.audience.clone(),
        sub: user_id.to_string(),
        iat: now,
        nbf: now - 1,
        exp,
        jti: Uuid::new_v4().to_string(),
        token_type: token_type,
    };

    encode(&Header::new(Algorithm::HS256), &claims, enc).map_err(|_| AppError::Internal)
}

pub fn issue_auth_cookies(user_id: i32, cfg: JwtConfig) -> Result<(Cookie<'static>, Cookie<'static>), AppError> {
    let token = sign_jwt(user_id, TokenType::Access, &cfg)?;
    let auth_cookie = Cookie::build((SETTINGS.auth_cookie_name.clone(), token.clone()))
        .http_only(true)
        .secure(SETTINGS.auth_cookie_secure.clone())
        .same_site(SETTINGS.auth_cookie_samesite.clone())
        .path(SETTINGS.auth_cookie_path.clone())
        .max_age(Duration::seconds(SETTINGS.jwt_access_ttl_secs.clone()))
        .build();

    let refresh_token = sign_jwt(user_id, TokenType::Refresh, &cfg)?;
    let refresh_cookie = Cookie::build((SETTINGS.refresh_cookie_name.clone(), refresh_token.clone()))
        .http_only(true)
        .secure(SETTINGS.auth_cookie_secure.clone())
        .same_site(SETTINGS.auth_cookie_samesite.clone())
        .path(SETTINGS.refresh_cookie_path.clone())
        .max_age(Duration::seconds(SETTINGS.jwt_refresh_ttl_secs.clone()))
        .build();
    Ok((auth_cookie, refresh_cookie))
}

pub struct VerifyAccessToken(pub JWTClaim);

impl<S> FromRequestParts<S> for VerifyAccessToken
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
            .ok_or(AppError::Unauthorized("Unauthorized"))?
            .value()
            .to_owned();

        // 3) verify
        let data = jsonwebtoken::decode::<JWTClaim>(&token, &app.jwt.access_dec, &app.jwt.access_validation())
            .map_err(|_| AppError::Unauthorized("Invalid token"))?;

        Ok(VerifyAccessToken(data.claims))
    }
}

pub struct VerifyRefreshToken(pub JWTClaim);

impl<S> FromRequestParts<S> for VerifyRefreshToken
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
            .get(SETTINGS.refresh_cookie_name.as_str())
            .ok_or(AppError::Unauthorized("Unauthorized"))?
            .value()
            .to_owned();

        // 3) verify
        let data = jsonwebtoken::decode::<JWTClaim>(&token, &app.jwt.refresh_dec, &app.jwt.refresh_validation())
            .map_err(|_| AppError::Unauthorized("Invalid token"))?;

        Ok(VerifyRefreshToken(data.claims))
    }
}
