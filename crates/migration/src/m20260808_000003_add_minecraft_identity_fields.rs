use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // NOTE: SQLite/libsql does not support multiple alter options in a single
        // ALTER TABLE. Keep this migration backend-agnostic (one statement per column).

        // Per-user Minecraft identity preference.
        //  - null  -> fall back to the backend-global default (MINECRAFT_IDENTITY_MODE).
        //  - "mojang"  -> use the real Mojang UUID (default).
        //  - "legacy"  -> map to the legacy offline UUID ("OfflinePlayer:<name>") so a
        //                 server migrating from offline mode keeps its world data.
        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(ColumnDef::new(Users::IdentityMode).string())
                    .to_owned(),
            )
            .await?;

        // Cached Mojang-signed `textures` profile property (value + signature) captured at
        // the last Minecraft OAuth login, so the mod can replay the real skin/cape when
        // serving a legacy offline identity.
        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(ColumnDef::new(Users::MinecraftTexturesValue).text())
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(ColumnDef::new(Users::MinecraftTexturesSignature).text())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::MinecraftTexturesSignature)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::MinecraftTexturesValue)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::IdentityMode)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum Users {
    Table,
    IdentityMode,
    MinecraftTexturesValue,
    MinecraftTexturesSignature,
}