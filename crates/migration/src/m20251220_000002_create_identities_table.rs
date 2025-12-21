use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Identities::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Identities::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Identities::UserId).integer().not_null())
                    .col(ColumnDef::new(Identities::Provider).string().not_null())
                    .col(
                        ColumnDef::new(Identities::ProviderUserId)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(Identities::PasswordHash).string())
                    .col(
                        ColumnDef::new(Identities::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Identities::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .index(
                        Index::create()
                            .name("idx_identities_user_id")
                            .table(Identities::Table)
                            .col(Identities::UserId),
                    )
                    .index(
                        Index::create()
                            .name("uidx_identities_provider_user")
                            .table(Identities::Table)
                            .col(Identities::Provider)
                            .col(Identities::ProviderUserId)
                            .unique(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_identities_user_id")
                            .from(Identities::Table, Identities::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Identities::Table).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum Identities {
    Table,
    Id,
    UserId,
    Provider,
    ProviderUserId,
    PasswordHash,
    CreatedAt,
    UpdatedAt,
}
