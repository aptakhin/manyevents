use crate::{DbPool};
use hex::encode;
use uuid::Uuid;

pub struct TenantRepository<'a> {
    pool: &'a DbPool,
}

impl<'a> TenantRepository<'a> {
    pub async fn new(pool: &'a DbPool) -> TenantRepository {
        TenantRepository{ pool }
    }

    pub async fn create(&self, title: String, by_account_id: Uuid) -> Result<Uuid, ()> {
        sqlx::query_as(
            "
            INSERT INTO tenant (title, created_by_account_id)
                VALUES ($1, $2)
                RETURNING id
            ",
        )
        .bind(title)
        .bind(by_account_id)
        .fetch_one(self.pool)
        .await
        .and_then(|r: (Uuid,)| Ok(r.0))
        .or_else(|e| {
            println!("Database query error: {}", e);
            Err(())
        })
    }

    pub async fn link_account(&self, tenant_id: Uuid, account_id: Uuid) -> Result<Uuid, ()> {
        sqlx::query_as(
            "
            INSERT INTO tenant_and_account (tenant_id, account_id)
                VALUES ($1, $2)
                RETURNING id
            ",
        )
        .bind(tenant_id.clone())
        .bind(account_id.clone())
        .fetch_one(self.pool)
        .await
        .and_then(|r: (Uuid,)| {
            Ok(r.0)
        })
        .or_else(|e| {
            println!("Database query error: {}", e);
            Err(())
        })
    }
}

pub struct Tenant<'a> {
    repo: &'a TenantRepository<'a>,
}

impl<'a> Tenant<'a> {
    pub async fn new(repo: &'a TenantRepository<'a>) -> Tenant {
        Tenant{ repo }
    }

    pub async fn create(&self, title: String, by_account_id: Uuid) -> Result<Uuid, ()> {
        self.repo.create(title, by_account_id).await
    }

    pub async fn link_account(&self, tenant_id: Uuid, account_id: Uuid) -> Result<Uuid, ()> {
        self.repo.link_account(tenant_id, account_id).await
    }
}
