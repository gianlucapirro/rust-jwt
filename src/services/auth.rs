use rand::{Rng, distr::Alphanumeric};

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

use crate::routes::auth::UserResponse;
use crate::settings::SETTINGS;
use crate::{AppState, core::errors::app::AppError, entities::users};

use axum::response::IntoResponse;
use axum_extra::extract::cookie::Cookie;
use cookie::time::Duration;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter};

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
    pub fn new_random() -> Self {
        let random_pw: String = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        Hasher::new(&random_pw)
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

#[derive(Serialize)]
pub struct SocialLoginResult {
    pub id: i32,
    pub name: String,
    pub email: String,
}

/// Find a user by email or create a new one (social-login only).
/// Returns the DB model **and** a `UserResponse` ready for the API.
pub async fn login_or_create_social_user(
    db: &sea_orm::DatabaseConnection,
    email: &str,
    name: Option<&str>,
) -> Result<(users::Model, UserResponse), AppError> {
    let email = email.to_lowercase();

    // 1. Try to find an existing user
    let existing = users::Entity::find()
        .filter(users::Column::Email.eq(&email))
        .one(db)
        .await
        .map_err(|_| AppError::Internal)?;

    if let Some(user) = existing {
        // Existing user – just return a response
        let resp = UserResponse {
            id: user.id,
            name: user.name.clone(),
            email: user.email.clone(),
        };
        return Ok((user, resp));
    }

    // 2. No user → create one
    let name = name.unwrap_or(&email).to_string();

    let active = users::ActiveModel {
        name: Set(name.clone()),
        email: Set(email.clone()),
        // `hashed_pwd` stays NULL – social users have no password
        hashed_pwd: Set(Hasher::new_random().hash),
        ..Default::default()
    };

    let inserted = active.insert(db).await.map_err(|e| {
        if matches!(
            e.sql_err(),
            Some(sea_orm::SqlErr::UniqueConstraintViolation(_))
        ) {
            AppError::Conflict("User already exists")
        } else {
            AppError::Internal
        }
    })?;

    let resp = UserResponse {
        id: inserted.id,
        name: inserted.name.clone(),
        email: inserted.email.clone(),
    };

    Ok((inserted, resp))
}

/// Sign a JWT **and** attach the HttpOnly cookie to the response.
///
/// `response` must implement `IntoResponse` (e.g. `Redirect` or any Axum response).
pub fn set_auth_cookie<R>(
    response: &mut R,
    user: &users::Model,
    jwt_secret: &str,
) -> Result<(), AppError>
where
    R: IntoResponse,
{
    // 1. Build JWT (reuse your existing function)
    let token = sign_jwt(user.id, &user.email, jwt_secret)?;

    // 2. Build cookie – exact same settings you use in `login_user`
    let cookie = Cookie::build((SETTINGS.auth_cookie_name.clone(), token))
        .http_only(true)
        .secure(SETTINGS.auth_cookie_secure)
        .same_site(SETTINGS.auth_cookie_samesite.clone())
        .path(SETTINGS.auth_cookie_path.clone())
        .max_age(Duration::seconds(SETTINGS.auth_cookie_max_age_secs))
        .build();

    // 3. Insert the cookie into the response headers
    let mut resp = response.into_response();
    resp.headers_mut()
        .insert("Set-Cookie", cookie.to_string().parse().unwrap());

    // 4. Replace the original response with the one that now contains the cookie
    *response = resp.into_response();

    Ok(())
}
