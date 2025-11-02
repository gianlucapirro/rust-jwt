use axum::{Json, extract::State, http::StatusCode};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use cookie::time::Duration;
use sea_orm::ActiveModelTrait;
use sea_orm::ActiveValue::Set;
use sea_orm::SqlErr;
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};

use crate::AppState;
use crate::core::errors::app::AppError;
use crate::entities::extensions::models::ByColumn;
use crate::entities::users;
use crate::services::auth::{Auth, Hasher, sign_jwt};
// API DOCS

#[derive(OpenApi)]
#[openapi(
    paths(create_user, login_user, logout, verify, me),
    components(
        schemas(CreateUser, LoginUser, UserResponse),
    ),
    security(("cookieAuth" = [])),
    tags((name = "Auth", description = "User authentication"))
)]
pub struct ApiDocAuth;

//
// Router
//
pub fn router() -> axum::Router<AppState> {
    axum::Router::new()
        .route("/register", axum::routing::post(create_user))
        .route("/login", axum::routing::post(login_user))
        .route("/logout", axum::routing::post(logout))
        .route("/verify", axum::routing::get(verify))
        .route("/me", axum::routing::get(me))
}

//
// Endpoints
//
#[derive(Deserialize, ToSchema)]
pub struct CreateUser {
    pub name: String,
    pub email: String,
    pub password: String,
}

#[derive(Serialize, ToSchema)]
pub struct UserResponse {
    pub id: i32,
    pub name: String,
    pub email: String,
}

#[utoipa::path(
    post,
    tags = ["Auth"],
    path = "/api/auth/register",
    request_body = CreateUser,
    responses(
        (status = 201, description = "User created successfully", body = UserResponse),
        (status = 409, description = "Conflict"),
        (status = 422, description = "Invalid input"),
    )
)]
pub async fn create_user(
    State(state): State<AppState>,
    Json(payload): Json<CreateUser>,
) -> Result<Json<UserResponse>, AppError> {
    let email: String = payload.email.to_lowercase();
    let hashed: Hasher = Hasher::new(&payload.password);
    let active = users::ActiveModel {
        name: Set(payload.name),
        email: Set(email.clone()),
        hashed_pwd: Set(hashed.hash),
        ..Default::default()
    };
    match active.insert(&state.db).await {
        Ok(user) => {
            let body = UserResponse {
                id: user.id,
                name: user.name,
                email: email,
            };
            Ok(Json(body))
        }
        Err(e) if matches!(e.sql_err(), Some(SqlErr::UniqueConstraintViolation(_))) => {
            Err(AppError::Conflict("This user already exists"))
        }
        Err(_) => Err(AppError::Internal),
    }
}

pub const AUTH_COOKIE: &str = "_auth";
// TODO: refresh cookie endpoint
// const REFRESH_COOKIE: &str = "_refresh";

#[derive(Deserialize, ToSchema)]
pub struct LoginUser {
    pub email: String,
    pub password: String,
}

#[utoipa::path(
    post,
    tags = ["Auth"],
    path = "/api/auth/login",
    request_body = LoginUser,
    responses(
        (status = 204, description = "Login successful, cookie set"),
        (status = 401, description = "Unauthorized"),
        (status = 422, description = "Invalid input"),
    )
)]
pub async fn login_user(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::Json(payload): axum::Json<LoginUser>,
) -> Result<(CookieJar, StatusCode), AppError> {
    let user = users::Entity::by(users::Column::Email, payload.email.to_lowercase())
        .one(&state.db)
        .await
        .map_err(|_| AppError::Internal)?;

    let Some(user) = user else {
        return Err(AppError::Unauthorized("Invalid credentials"));
    };

    let hasher = Hasher {
        hash: user.hashed_pwd.clone(),
    };
    if !hasher.verify(&payload.password) {
        return Err(AppError::Unauthorized("Invalid credentials"));
    }

    let token = sign_jwt(user.id, &user.email, &state.jwt)?; // your existing signer

    // Build secure HttpOnly cookie
    let cookie = Cookie::build((AUTH_COOKIE, token))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(Duration::days(7))
        .build();

    Ok((jar.add(cookie), StatusCode::NO_CONTENT))
}

#[utoipa::path(
    post,
    tags = ["Auth"],
    path = "/api/auth/logout",
    responses((status = 204, description = "Logged out"))
)]
pub async fn logout(jar: CookieJar) -> (CookieJar, StatusCode) {
    let removal = Cookie::build(AUTH_COOKIE)
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(Duration::seconds(0)) // expire immediately
        .build();
    (jar.add(removal), StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/api/auth/verify",
    tags = ["Auth"],
    responses(
        (status = 204, description = "Session valid"),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn verify(Auth(_): Auth) -> StatusCode {
    // If the extractor succeeds, the JWT is valid → return 204 No Content
    StatusCode::NO_CONTENT
}

#[utoipa::path(
    get,
    tags = ["Auth"],
    path = "/api/auth/me",
    responses(
        (status = 200, description = "User info retrieved successfully", body = UserResponse),
        (status = 401, description = "Unauthorized"),
    ),
)]
async fn me(
    Auth(claims): Auth,
    State(state): State<AppState>,
) -> Result<axum::Json<UserResponse>, AppError> {
    let uid: i32 = claims
        .sub
        .parse()
        .map_err(|_| AppError::Unauthorized("Bad sub"))?;
    let user = users::Entity::by(users::Column::Id, uid)
        .one(&state.db)
        .await
        .map_err(|_| AppError::Internal)?;

    let Some(user) = user else {
        return Err(AppError::Unauthorized("User not found"));
    };

    Ok(axum::Json(UserResponse {
        id: user.id,
        name: user.name,
        email: user.email,
    }))
}
