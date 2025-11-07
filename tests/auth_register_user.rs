use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::post,
    Router,
};
use sea_orm::{DatabaseBackend, MockDatabase};
use serde_json::json;
use tower::ServiceExt; // for `.oneshot()`

use api::{
    routes::auth::{create_user, UserResponse},
    entities::users,
    services::auth::JwtConfig,
    AppState,
};

#[tokio::test]
async fn register_creates_user_and_returns_payload() {
    // 1. Arrange: set up a mocked database response.
    // SeaORM's ActiveModel::insert will call INSERT ... RETURNING * under Postgres,
    // so MockDatabase must have a query result representing that returned row.
    let mock_user = users::Model {
        id: 1,
        name: "Ada Lovelace".to_string(),
        email: "ada@example.com".to_string(),
        hashed_pwd: "hashed".to_string(),
    };

    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results(vec![vec![mock_user]])
        .into_connection();

    // 2. Prepare a JwtConfig for the AppState
    // This endpoint doesn’t use JWTs, but AppState requires it.
    // Make sure your JwtConfig::from_env() works with these defaults.
    std::env::set_var("JWT_SECRET", "test-secret");
    std::env::set_var("JWT_EXP_MINUTES", "15");
    std::env::set_var("REFRESH_EXP_DAYS", "7");
    std::env::set_var("AUTH_COOKIE_NAME", "auth");
    std::env::set_var("REFRESH_COOKIE_NAME", "refresh");
    let jwt = JwtConfig::from_env().expect("failed to create JwtConfig");

    let state = AppState { db, jwt };

    // 3. Build the app with just the register route
    let app = Router::new()
        .route("/api/auth/register", post(create_user))
        .with_state(state);

    // 4. Act: send a test HTTP request to the route
    let payload = json!({
        "name": "Ada Lovelace",
        "email": "Ada@Example.com", // will be lowercased by handler
        "password": "swordfish"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/api/auth/register")
        .header("content-type", "application/json")
        .body(Body::from(payload.to_string()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    // 5. Assert: status and returned JSON
    assert_eq!(response.status(), StatusCode::OK); // handler currently returns 200 OK

    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: UserResponse = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(body.id, 1);
    assert_eq!(body.name, "Ada Lovelace");
    assert_eq!(body.email, "ada@example.com");
}