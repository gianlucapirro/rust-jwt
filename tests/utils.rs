use migration::sea_orm::Database;
use sea_orm::DatabaseConnection;
use testcontainers::ContainerAsync;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;
use migration::{Migrator, MigratorTrait};
use api::{
    services::auth::JwtConfig, settings::load_env, setup::build_app
};

pub struct TestDb {
    pub db: DatabaseConnection,
    _container: ContainerAsync<Postgres>,
}

pub async fn setup_test_db() -> TestDb {
    let container = Postgres::default().start().await.unwrap();

    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");

    let db = Database::connect(&url).await.unwrap();
    Migrator::up(&db, None).await.unwrap();

    TestDb { db, _container: container }
}

pub struct TestApp {
    pub app: axum::Router,
    pub db: TestDb,
}

pub async fn setup_test_app() -> TestApp {
    load_env();

    let test_db = setup_test_db().await;
    let db_for_app = test_db.db.clone();

    let jwt = JwtConfig::from_env().expect("failed to create JwtConfig");
    let app = build_app(Some(db_for_app), Some(jwt))
        .await
        .expect("failed to build app");

    TestApp { app, db: test_db }
}