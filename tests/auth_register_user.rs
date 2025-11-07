use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use sea_orm::{DatabaseBackend, MockDatabase};
use serde_json::json;
use tower::ServiceExt;

use api::{
    entities::users, routes::auth::UserResponse, services::auth::JwtConfig, settings::load_env, setup::build_app
};
use chrono::Utc;

#[tokio::test]
async fn register_creates_user_and_returns_payload() {
    load_env();
    let mock_user = users::Model {
        id: 1,
        name: "Ada Lovelace".to_string(),
        email: "ada@example.com".to_string(),
        hashed_pwd: "hashed".to_string(),
        created_at: Utc::now().naive_utc(),
    };

    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results(vec![vec![mock_user]])
        .into_connection();

    let jwt = JwtConfig::from_env().expect("failed to create JwtConfig");

    let app = build_app(Some(db), Some(jwt)).await.expect("failed to build app");

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