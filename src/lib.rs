// src/lib.rs

pub mod core;
pub mod entities;
pub mod routes;
pub mod services;
pub mod settings;
pub mod setup;

use sea_orm::DatabaseConnection;

pub use crate::services::auth::JwtConfig;

#[derive(Clone)]
pub struct AppState {
    pub db: DatabaseConnection,
    pub jwt: JwtConfig,
}