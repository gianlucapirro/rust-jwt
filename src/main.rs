mod routes;
mod entities;
mod core;
mod services;

use axum::{Router};
use dotenvy::dotenv;
use sea_orm::{Database, DatabaseConnection};
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::util::SubscriberInitExt;
use std::env;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;
use utoipa_redoc::{Redoc, Servable};
use crate::services::auth::JwtConfig;
use tracing_subscriber::{EnvFilter, fmt};
use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt;
use std::panic;
use axum::http::{Request, Response};
use tracing::{info, error, Span};
use std::time::Duration;

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

    // Add tracing and make sure to log panics
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,tower_http=info,axum::rejection=trace".into()))
        .with(fmt::layer().with_target(false))
        .try_init()?;

    // Log panics if RUST_BACKTRACE is set to 1 in env
    panic::set_hook(Box::new(|panic_info| {
        let bt = std::backtrace::Backtrace::capture();
        tracing::error!("PANIC: {panic_info}\nBacktrace:\n{bt}");
    }));

    // Init DB and AppState
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

    let app = app
        .layer(CatchPanicLayer::new())
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|req: &Request<_>| {
                    let method = req.method().clone();
                    let uri = req.uri().clone();
                    tracing::info_span!("req", %method, %uri)
                })
                .on_request(|_req: &Request<_>, _span: &Span| {
                    info!("→ request received");
                })
                .on_response(|res: &Response<_>, latency: Duration, _span: &Span| {
                    info!("← response status={} latency={:?}", res.status(), latency);
                })
                .on_failure(
                    |error: tower_http::classify::ServerErrorsFailureClass,
                    latency: Duration,
                    _span: &Span| {
                        error!("request failure: {error}; latency={latency:?}");
                    },
                ),
        );

    axum::serve(tokio::net::TcpListener::bind("127.0.0.1:3000").await?, app).await?;

    Ok(())
}