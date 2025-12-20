pub use sea_orm_migration::prelude::*;

mod m20250124_000001_create_all_tables;
mod m20251220_000002_create_identities_table;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20250124_000001_create_all_tables::Migration),
            Box::new(m20251220_000002_create_identities_table::Migration),
        ]
    }
}
