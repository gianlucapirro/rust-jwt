use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use migration::sea_orm::Database;

use serde_json::json;
use tower::ServiceExt;

use api::{
    routes::auth::UserResponse, services::auth::JwtConfig, settings::load_env, setup::build_app
};
use testcontainers_modules::postgres::Postgres;
use testcontainers::runners::AsyncRunner;
use migration::{Migrator, MigratorTrait};

#[tokio::test]
async fn register_creates_user_and_returns_payload() {
    load_env();

    let container = Postgres::default().start().await.unwrap();
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");

    let db = Database::connect(&url).await.unwrap();
    Migrator::up(&db, None).await.unwrap();

    let jwt = JwtConfig::from_env().expect("failed to create JwtConfig");
    let app = build_app(Some(db), Some(jwt)).await.expect("failed to build app");

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
