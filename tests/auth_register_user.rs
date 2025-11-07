use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use sea_orm::ActiveModelTrait;
use sea_orm::ActiveValue::Set;
use serde_json::json;
use tower::ServiceExt;
use api::{routes::auth::UserResponse};
use api::entities::users;
mod utils;

#[tokio::test]
async fn register_creates_user_and_returns_payload() {
    let test_app = utils::setup_test_app().await;
    let app = test_app.app;
    let payload = json!({
        "name": "Ada Lovelace",
        "email": "Ada@Example.com",
        "password": "swordfish"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/api/auth/register")
        .header("content-type", "application/json")
        .body(Body::from(payload.to_string()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: UserResponse = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(body.id, 1);
    assert_eq!(body.name, "Ada Lovelace");
    assert_eq!(body.email, "ada@example.com");
}


#[tokio::test]
async fn register_creates_user_already_exists() {
    let test_app = utils::setup_test_app().await;
    let app = test_app.app;

    let db = test_app.db.db;

    let existing_user = users::ActiveModel {
        id: Set(1),
        name: Set("Ada Lovelace".to_string()),
        email: Set("ada@example.com".to_string()),
        hashed_pwd: Set("hashed_pwd".to_string()),
        created_at: Set(chrono::Utc::now().naive_utc()),
        ..Default::default()
    };
    existing_user.insert(&db).await.unwrap();

    let payload = json!({
        "name": "Ada Lovelace",
        "email": "Ada@Example.com",
        "password": "swordfish"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/api/auth/register")
        .header("content-type", "application/json")
        .body(Body::from(payload.to_string()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
}
