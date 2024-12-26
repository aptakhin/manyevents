use crate::DbPool;
use uuid::Uuid;
use std::error::Error;

pub struct ScopeRepository<'a> {
    pool: &'a DbPool,
}

impl<'a> ScopeRepository<'a> {
    pub fn new(pool: &'a DbPool) -> ScopeRepository {
        ScopeRepository { pool }
    }

    pub async fn create_scope(
        &self,
        title: String,
        slug: String,
        by_account_id: Uuid,
    ) -> Result<Uuid, ()> {
        sqlx::query_as(
            "
            INSERT INTO scope (title, slug, created_by_account_id)
                VALUES ($1, $2, $3)
                RETURNING id
            ",
        )
        .bind(title)
        .bind(slug)
        .bind(by_account_id)
        .fetch_one(self.pool)
        .await
        .and_then(|r: (Uuid,)| Ok(r.0))
        .or_else(|e| {
            println!("Database query error: {}", e);
            Err(())
        })
    }

    pub async fn create_storage_credential(
        &self,
        tenant_id: Uuid,
        type_: String,
        dsn: String,
        by_account_id: Uuid,
    ) -> Result<Uuid, ()> {
        sqlx::query_as(
            "
            INSERT INTO storage_credential (tenant_id, type, dsn, created_by_account_id)
                VALUES ($1, $2, $3, $4)
                RETURNING id
            ",
        )
        .bind(tenant_id)
        .bind(type_)
        .bind(dsn)
        .bind(by_account_id)
        .fetch_one(self.pool)
        .await
        .and_then(|r: (Uuid,)| Ok(r.0))
        .or_else(|e| {
            println!("Database query error: {}", e);
            Err(())
        })
    }

    pub async fn has_tenant_storage_credential(
        &self,
        tenant_id: Uuid,
    ) -> bool {
        sqlx::query_as(
            "
            SELECT id FROM storage_credential
            WHERE
                tenant_id = $1
            LIMIT 1
            ",
        )
        .bind(tenant_id)
        .fetch_optional(self.pool)
        .await
        .and_then(|r: Option<(Uuid,)>| Ok(r.is_some()))
        .expect("SQL error in has_tenant_storage_credential")
    }

    pub async fn create_scope_environment(
        &self,
        scope_id: Uuid,
        storage_credential_id: Uuid,
        title: String,
        slug: String,
        by_account_id: Uuid,
    ) -> Result<Uuid, ()> {
        sqlx::query_as(
            "
            INSERT INTO scope_environment (scope_id, storage_credential_id, title, slug, created_by_account_id)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING id
            ",
        )
        .bind(scope_id)
        .bind(storage_credential_id)
        .bind(title)
        .bind(slug)
        .bind(by_account_id)
        .fetch_one(self.pool)
        .await
        .and_then(|r: (Uuid,)| Ok(r.0))
        .or_else(|e| {
            println!("Database query error: {}", e);
            Err(())
        })
    }
}
