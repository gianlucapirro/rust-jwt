use axum::{extract::State, Json};
use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};
use sea_orm::SqlErr;

use crate::AppState;
use crate::entities::{users};
use crate::core::errors::app::AppError;
use crate::services::auth::{Hasher, sign_jwt, Auth};
use crate::entities::extensions::models::ByColumn;

// API DOCS

#[derive(OpenApi)]
#[openapi(
    paths(
        create_user,
        login_user,
        me
    ),
    components(
        schemas(CreateUser, LoginUser),
    ),
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
        .route("/me", axum::routing::get(me))
}

// 
// Endpoints
// 
#[derive(Deserialize, ToSchema)]
pub struct CreateUser {
    pub name: String,
    pub email: String,
    pub password: String
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
    path = "/auth/register",
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
            let body = UserResponse {id: user.id, name: user.name, email: email};
            Ok(Json(body))
        }
        Err(e) if matches!(e.sql_err(), Some(SqlErr::UniqueConstraintViolation(_))) => {
            Err(AppError::Conflict("This user already exists"))
        }
        Err(_) => Err(AppError::Internal)
    }
}

#[derive(Deserialize, ToSchema)]
pub struct LoginUser {
    pub email: String,
    pub password: String
}

#[derive(Serialize, ToSchema)]
pub struct LoginResponse {
    pub token: String,
}

#[utoipa::path(
    post,
    tags = ["Auth"],
    path = "/auth/login",
    request_body = LoginUser,
    responses(
        (status = 200, description = "Login successful"),
        (status = 401, description = "Unauthorized"),
        (status = 422, description = "Invalid input"),
    )
)]
pub async fn login_user(
    State(state): State<AppState>,
    Json(payload): Json<LoginUser>,
) -> Result<Json<LoginResponse>, AppError> {
    let user = users::Entity::by(users::Column::Email, payload.email.to_lowercase())
        .one(&state.db)
        .await;
    let user = match user {
        Ok(Some(user)) => {
            let hasher = Hasher { hash: user.hashed_pwd.clone() };
            if !hasher.verify(&payload.password) {
                return Err(AppError::Unauthorized("Invalid credentials"));
            }
            user
        }
        Ok(None) => return Err(AppError::Unauthorized("Invalid credentials")),
        Err(_) => return Err(AppError::Internal),
    };
    let token = sign_jwt(user.id, &user.email, &state.jwt);
    Ok(Json(LoginResponse { token: token? }))
}

#[utoipa::path(
    get,
    tags = ["Auth"],
    path = "/auth/me",
    responses(
        (status = 200, description = "User info retrieved successfully", body = UserResponse),
        (status = 401, description = "Unauthorized"),
    ),
)]
async fn me(Auth(claims): Auth, State(state): State<AppState>) -> Result<Json<UserResponse>, AppError> {
    let user = users::Entity::by(users::Column::Id, claims.sub.parse::<i32>().unwrap())
        .one(&state.db)
        .await
        .map_err(|_| AppError::Internal)?;

    let body = match user {
        Some(user) => UserResponse {
            id: user.id,
            name: user.name,
            email: user.email,
        },
        None => return Err(AppError::Unauthorized("User not found")),
    };
    Ok(Json(body))
}
