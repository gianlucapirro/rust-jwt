mod routes;
mod entities;
mod core;
mod services;

use axum::{Router};
use dotenvy::dotenv;
use sea_orm::{Database, DatabaseConnection};
use std::env;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;
use utoipa_redoc::{Redoc, Servable};
use crate::services::auth::JwtConfig;

#[derive(Clone)]
struct AppState {
    db: DatabaseConnection,
    jwt: JwtConfig,
}

#[derive(OpenApi)]
struct ApiDoc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();

    let db_url = env::var("DATABASE_URL")?;
    let db = Database::connect(&db_url).await?;

    let jwt = JwtConfig::from_env()?;
    let state = AppState { db, jwt };

    let openapi = ApiDoc::openapi().merge_from(routes::auth::ApiDocAuth::openapi());

    let app = Router::new()
        .nest("/auth", routes::auth::router())
        .merge(SwaggerUi::new("/docs").url("/api-doc/openapi.json", openapi.clone()))
        .merge(Redoc::with_url("/redoc", openapi.clone()))
        .with_state(state);

    axum::serve(tokio::net::TcpListener::bind("127.0.0.1:3000").await?, app).await?;

    Ok(())
}