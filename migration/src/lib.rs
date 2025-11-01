pub use sea_orm_migration::prelude::*;

mod m20251028_202638_create_users;
mod m20251101_095828_add_hashed_pwd_to_user;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20251028_202638_create_users::Migration),
            Box::new(m20251101_095828_add_hashed_pwd_to_user::Migration),
        ]
    }
}
