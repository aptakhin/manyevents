use crate::DbPool;
use crate::Value;
use sqlx::Error;
use tracing::debug;
use uuid::Uuid;

use crate::auth::ensure_push_header;
use crate::ch::{make_migration_plan, ChColumn, ClickHouseRepository};
use crate::schema::{read_event_data, EventJsonSchema, SerializationType};

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
            debug!("Database query error: {}", e);
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
                debug!("SQL error in get_tenant_storage_credential: {}", e);
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
            debug!("Database query error: {}", e);
            Err(())
        })
    }

    pub async fn get_tenant_and_storage_credential_by_environment(
        &self,
        environment_id: Uuid,
    ) -> Result<(Uuid, String), String> {
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
            Ok(None) => Err("No tenant entry".to_string()),
            Err(e) => Err(format!(
                "SQL error in get_tenant_and_storage_credential_by_environment: {}",
                e
            )),
        }
    }

    pub async fn get_event_schema(&self, tenant_id: Uuid, name: String) -> Result<Value, String> {
        let res: Result<Option<(Value,)>, _> = sqlx::query_as(
            "
            SELECT
                description
            FROM event e
            WHERE
                tenant_id = $1 AND name = $2
            LIMIT 1
            ",
        )
        .bind(tenant_id)
        .bind(name)
        .fetch_optional(self.pool)
        .await;
        match res {
            Ok(Some((value,))) => Ok(value),
            Ok(None) => Err("No entry".to_string()),
            Err(e) => Err(format!("SQL error in get_event_schema: {}", e)),
        }
    }

    pub async fn save_event_schema(
        &self,
        tenant_id: Uuid,
        name: String,
        set: Value,
        by_account_id: Uuid,
    ) -> Result<(), String> {
        let res: Result<Option<_>, Error> = sqlx::query(
            "
            INSERT INTO event
                (tenant_id, name, description, created_by_account_id)
            VALUES
                ($1, $2, $3, $4)
            ",
        )
        .bind(tenant_id)
        .bind(name)
        .bind(set)
        .bind(by_account_id)
        .fetch_optional(self.pool)
        .await;
        match res {
            Ok(None) => Ok(()),
            Ok(Some(_)) => Ok(()),
            Err(e) => Err(format!("SQL error in get_event_schema: {}", e)),
        }
    }
}

#[derive(Debug)]
pub enum PushEventError {
    AuthError(String),
    InternalError(String),
}

pub struct Scope<'a> {
    pub pool: &'a DbPool,
}

impl<'a> Scope<'a> {
    pub async fn push_event(&self, data: Value, token: String) -> Result<(), PushEventError> {
        // auth
        let auth_response = ensure_push_header(token, &self.pool).await;
        if auth_response.is_err() {
            return Err(PushEventError::AuthError("invalid_auth".to_string()));
        }
        let auth_response = auth_response.unwrap();

        // read
        let result = read_event_data(&data);
        if result.is_err() {
            return Err(PushEventError::InternalError(
                result.unwrap_err().message_code.to_string(),
            ));
        }

        // get creds
        let scope_repository = ScopeRepository { pool: self.pool };

        let res = scope_repository
            .get_tenant_and_storage_credential_by_environment(auth_response.environment_id.clone())
            .await;

        if res.is_err() {
            return Err(PushEventError::InternalError(res.unwrap_err()));
        }

        let res = res.unwrap();
        let tenant_id = res.0;

        let unique_suffix = format!("db_{}", tenant_id.clone().as_simple());
        debug!("Use tenantdb {unique_suffix} for tenant_id={tenant_id}");
        let tenant_repo = ClickHouseRepository::choose_tenant(&unique_suffix);

        let event = result.unwrap();

        // todo check schema

        let mut columns: Vec<ChColumn> = vec![];

        let mut table_name = None;

        for unit in event.units.iter() {
            for value in unit.value.iter() {
                let column = ChColumn {
                    name: if unit.name != "" {
                        format!("{}_{}", unit.name, value.name)
                    } else {
                        value.name.clone()
                    },
                    value: value.value.clone(),
                };
                debug!("ins: {}: {:?}", column.name.clone(), value.value.clone());
                if column.name == "x-manyevents-name" {
                    if let SerializationType::Str(str) = value.value.clone() {
                        table_name = Some(str.clone());
                    }
                } else {
                    columns.push(column);
                }
            }
        }

        if table_name.is_none() {
            return Err(PushEventError::InternalError(
                "event_name_is_not_given".to_string(),
            ));
        }

        let res = tenant_repo
            .insert(table_name.unwrap().to_string(), columns)
            .await;

        if res.is_err() {
            return Err(PushEventError::InternalError(format!(
                "internal_error: {}",
                res.unwrap_err()
            )));
        }

        Ok(())
    }
}
