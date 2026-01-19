use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    // User profile fields (optional / nullable)
                    .add_column(ColumnDef::new(Users::Email).string())
                    .add_column(ColumnDef::new(Users::AvatarSource).string())
                    // Cached avatar info from linked providers
                    .add_column(ColumnDef::new(Users::GithubAvatarUrl).string())
                    .add_column(ColumnDef::new(Users::GoogleAvatarUrl).string())
                    // Microsoft avatar is fetched from Graph and stored as base64 (small size).
                    .add_column(ColumnDef::new(Users::MicrosoftAvatarB64).text())
                    .add_column(ColumnDef::new(Users::MicrosoftAvatarContentType).string())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // NOTE: SQLite/libsql support DROP COLUMN on modern versions.
        // Down migrations are not typically used in production, but we keep this reasonably reversible.
        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::MicrosoftAvatarContentType)
                    .drop_column(Users::MicrosoftAvatarB64)
                    .drop_column(Users::GoogleAvatarUrl)
                    .drop_column(Users::GithubAvatarUrl)
                    .drop_column(Users::AvatarSource)
                    .drop_column(Users::Email)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Users {
    Table,
    Email,
    AvatarSource,
    GithubAvatarUrl,
    GoogleAvatarUrl,
    MicrosoftAvatarB64,
    MicrosoftAvatarContentType,
}
