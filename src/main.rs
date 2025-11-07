use api::{build_api_router, routes, settings::SETTINGS, AppState, JwtConfig};
use axum::http::{Request, Response};
use dotenvy::dotenv;
use sea_orm::Database;
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

#[derive(OpenApi)]
struct ApiDoc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();

    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tower_http=info,axum::rejection=trace".into()),
        )
        .with(fmt::layer().with_target(false))
        .try_init()?;

    panic::set_hook(Box::new(|panic_info| {
        let bt = std::backtrace::Backtrace::capture();
        tracing::error!("PANIC: {panic_info}\nBacktrace:\n{bt}");
    }));

    // State
    let db = Database::connect(&SETTINGS.database_url).await?;
    let jwt = JwtConfig::from_env()?;
    let state = AppState { db, jwt };

    // Router + docs
    let openapi = ApiDoc::openapi().merge_from(routes::auth::ApiDocAuth::openapi());
    let swagger = SwaggerUi::new("/api/docs").url("/api/openapi.json", openapi.clone());

    let app = build_api_router(state)
        .merge(swagger)
        .merge(Redoc::with_url("/redoc", openapi));

    // Layers
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

    // Serve: pass the Router directly
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}