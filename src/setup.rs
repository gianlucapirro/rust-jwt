use axum::http::{Request, Response};
use sea_orm::{Database, DatabaseConnection};
use std::{panic, time::Duration};
use tower_http::{catch_panic::CatchPanicLayer, trace::TraceLayer};
use tracing::{error, info, Span};
use tracing_subscriber::{
    fmt,
    prelude::__tracing_subscriber_SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter,
};
use utoipa::OpenApi;
use utoipa_redoc::{Redoc, Servable};
use utoipa_swagger_ui::SwaggerUi;
use anyhow::Result;
use axum::Router;

use crate::{AppState, JwtConfig, routes, settings::{SETTINGS, load_env}};

#[derive(OpenApi)]
struct ApiDoc;

pub async fn build_app(
    overload_db: Option<DatabaseConnection>,
    overload_jwt: Option<JwtConfig>,
) -> Result<Router> {
    load_env();

    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,sea_orm=debug,sqlx::query=debug,tower_http=info,axum::rejection=trace".into()),
        )
        .with(fmt::layer().with_target(false))
        .try_init()
        .ok(); // avoid error if tests re-init tracing

    panic::set_hook(Box::new(|panic_info| {
        let bt = std::backtrace::Backtrace::capture();
        tracing::error!("PANIC: {panic_info}\nBacktrace:\n{bt}");
    }));

    // Overloads
    let db = match overload_db {
        Some(db) => db,
        None => Database::connect(&SETTINGS.database_url)
            .await
            .expect("Database connect failed"),
    };

    let jwt = overload_jwt.unwrap_or_else(|| JwtConfig::from_env().expect("Failed to load JWT config"));
    let state = AppState { db, jwt };

    // Router + docs
    let openapi = ApiDoc::openapi().merge_from(routes::auth::ApiDocAuth::openapi());
    let swagger = SwaggerUi::new("/api/docs").url("/api/openapi.json", openapi.clone());

    let app = Router::new()
        .nest("/api/auth", routes::auth::router())
        .with_state(state)
        .merge(swagger)
        .merge(Redoc::with_url("/redoc", openapi))
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
                .on_failure(|error: tower_http::classify::ServerErrorsFailureClass,
                             latency: Duration,
                             _span: &Span| {
                    error!("request failure: {error}; latency={latency:?}");
                }),
        );

    Ok(app)
}