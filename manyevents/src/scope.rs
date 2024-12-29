use crate::DbPool;
use uuid::Uuid;

pub struct ScopeRepository<'a> {
    pub pool: &'a DbPool,
}

impl<'a> ScopeRepository<'a> {
    pub fn new(pool: &'a DbPool) -> ScopeRepository {
        ScopeRepository { pool }
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

    pub async fn get_tenant_storage_credential(&self, tenant_id: Uuid) -> Result<Uuid, ()> {
        let res: Result<Option<(Uuid,)>, _> = sqlx::query_as(
            "
            SELECT id FROM storage_credential
            WHERE
                tenant_id = $1
            LIMIT 1
            ",
        )
        .bind(tenant_id)
        .fetch_optional(self.pool)
        .await;
        match res {
            Ok(Some((id,))) => Ok(id),
            Ok(None) => Err(()),
            Err(e) => {
                println!("SQL error in get_tenant_storage_credential: {}", e);
                Err(())
            }
        }
    }

    pub async fn create_environment(
        &self,
        storage_credential_id: Uuid,
        title: String,
        slug: String,
        by_account_id: Uuid,
    ) -> Result<Uuid, ()> {
        sqlx::query_as(
            "
            INSERT INTO environment (storage_credential_id, title, slug, created_by_account_id)
                VALUES ($1, $2, $3, $4)
                RETURNING id
            ",
        )
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

    pub async fn get_tenant_and_storage_credential_by_environment(&self, environment_id: Uuid) -> Result<(Uuid, String), String> {
        let res: Result<Option<(Uuid, String)>, _> = sqlx::query_as(
            "
            SELECT
                sc.tenant_id as tenant_id,
                sc.dsn as dsn
            FROM environment e
            LEFT JOIN storage_credential sc ON (sc.id = e.storage_credential_id)
            WHERE
                e.id = $1
            LIMIT 1
            ",
        )
        .bind(environment_id)
        .fetch_optional(self.pool)
        .await;
        match res {
            Ok(Some((tenant_id, dsn))) => Ok((tenant_id, dsn)),
            Ok(None) => Err("No entry".to_string()),
            Err(e) => {
                Err(format!("SQL error in get_tenant_and_storage_credential_by_environment: {}", e))
            }
        }
    }
}
