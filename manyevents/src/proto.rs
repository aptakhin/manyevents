use crate::DbPool;
use uuid::Uuid;

use crate::scope::ScopeRepository;
use crate::tenant::{Tenant, TenantRepository};

pub struct Proto {
    // repo: &'a TenantRepository<'a>,
}

impl Proto {
    pub async fn init_many_things(by_account_id: Uuid, pool: &DbPool) -> Result<(), ()> {
        let tenant_repository = TenantRepository::new(pool);
        let tenant = Tenant::new(&tenant_repository);

        let tenant_title = "my-company".to_string();

        let created_tenant_resp = tenant.create(tenant_title, by_account_id.clone()).await;
        if created_tenant_resp.is_err() {
            return Err(());
        }
        let link_resp = tenant
            .link_account(created_tenant_resp.clone().unwrap(), by_account_id.clone())
            .await;
        if link_resp.is_err() {
            return Err(());
        }

        let scope = ScopeRepository::new(pool);
        let scope_resp = scope
            .create_scope(
                "test-scope".to_string(),
                "test".to_string(),
                by_account_id.clone(),
            )
            .await;
        if scope_resp.is_err() {
            return Err(());
        }

        let storage_credential_resp = scope
            .create_storage_credential(
                created_tenant_resp.unwrap(),
                "clickhouse".to_string(),
                "clickhouse://...".to_string(),
                by_account_id.clone(),
            )
            .await;
        if storage_credential_resp.is_err() {
            return Err(());
        }
        let scope_environment_resp = scope
            .create_scope_environment(
                scope_resp.unwrap(),
                storage_credential_resp.unwrap(),
                "prod".to_string(),
                "prod".to_string(),
                by_account_id.clone(),
            )
            .await;
        if scope_environment_resp.is_err() {
            return Err(());
        }

        Ok(())
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::test::{add_random_email_account, pool};
    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
    };
    use hex::encode;
    use rstest::{fixture, rstest};

    #[rstest]
    #[tokio::test]
    async fn test_create_tenant_successful(#[future] pool: DbPool) {
        let pool = pool.await;
        let by_account_id = add_random_email_account(&pool).await;

        let init_resp = Proto::init_many_things(by_account_id, &pool).await;

        assert_eq!(init_resp.is_ok(), true);
    }
}
