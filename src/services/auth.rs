use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{SaltString, PasswordHash, rand_core::OsRng};
use axum_extra::TypedHeader;
use jsonwebtoken::{EncodingKey, DecodingKey, Algorithm, Header, Validation, decode};
use axum::{
    extract::{FromRequestParts},
    http::{request::Parts, StatusCode},
};
use headers::{Authorization, authorization::Bearer};
use time::OffsetDateTime;
use serde::{Serialize, Deserialize};

use crate::AppState;
use crate::core::errors::app::AppError;

pub struct Hasher{
    pub hash: String,
}

impl Hasher{
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
        let parsed_hash = PasswordHash::new(&self.hash)
            .expect("invalid stored hash format");

        Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok()
    }
}

#[derive(Clone)]
pub struct JwtConfig {
    issuer: String,
    audience: String,
    ttl_seconds: usize,
    enc: EncodingKey,
    dec: DecodingKey,
}

impl JwtConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let secret = std::env::var("JWT_SECRET")?;
        Ok(Self {
            issuer: std::env::var("JWT_ISSUER").unwrap_or_else(|_| "actuary.aero".into()),
            audience: std::env::var("JWT_AUDIENCE").unwrap_or_else(|_| "actuary.aero-api".into()),
            ttl_seconds: std::env::var("JWT_TTL_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(3600),
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
    pub sub: String, // user id 
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

    encode(&Header::new(Algorithm::HS256), &claims, &cfg.enc)
        .map_err(|_| AppError::Internal)
}

pub struct Auth(pub Claims);

impl FromRequestParts<AppState> for Auth {
    type Rejection = (StatusCode, axum::Json<serde_json::Value>);

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let TypedHeader(Authorization(bearer)) =
            TypedHeader::<Authorization<Bearer>>::from_request_parts(parts, state)
                .await
                .map_err(|_| (StatusCode::UNAUTHORIZED, axum::Json(serde_json::json!("Missing or invalid Authorization header"))))?;

        let token = bearer.token();
        let data = decode::<Claims>(token, &state.jwt.dec, &state.jwt.validation())
            .map_err(|e| (StatusCode::UNAUTHORIZED, axum::Json(serde_json::json!(format!("Invalid token: {}", e)))))?;

        Ok(Auth(data.claims))
    }
}