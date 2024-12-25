use clickhouse::sql::Identifier;
use clickhouse::Client;
use clickhouse::Row;
use serde::Deserialize;

use crate::schema::{
    JsonSchemaDiff, JsonSchemaPropertyDiff, JsonSchemaPropertyEntryDiff, JsonSchemaPropertyStatus,
    SerializationType,
};

#[derive(Row, Deserialize, Debug)]
pub struct ChColumn {
    pub name: String,
    pub value: SerializationType,
}

pub async fn insert_smth(table_name: String, rows: Vec<ChColumn>) {
    let client = Client::default()
        .with_url("http://localhost:8123")
        .with_user("username")
        .with_password("password")
        .with_database("helloworld")
        // https://clickhouse.com/docs/en/operations/settings/settings#async-insert
        .with_option("async_insert", "1")
        // https://clickhouse.com/docs/en/operations/settings/settings#wait-for-async-insert
        .with_option("wait_for_async_insert", "0");

    let x = client
        .query(
            "
            CREATE OR REPLACE TABLE ? (
                base_timestamp DateTime64(3),
                base_parent_span_id String,
                base_message String,
                span_id String,
                span_start_time DateTime64(3),
                span_end_time DateTime64(3),
            )
            ENGINE = MergeTree
            ORDER BY base_timestamp
            PARTITION BY toYYYYMMDD(base_timestamp)
            ",
        )
        .bind(Identifier(&table_name))
        .execute()
        .await;

    println!("Q: {:?}", x);

    let column_names_str = rows
        .iter()
        .map(|x| x.name.clone())
        .collect::<Vec<_>>()
        .join(", ");
    let placeholders_str = rows.iter().map(|_| "?").collect::<Vec<_>>().join(", ");

    let query = format!(
        "INSERT INTO ? ({}) VALUES ({})",
        column_names_str, placeholders_str
    );
    println!("sss: {:?}", query);
    let mut y = client.query(&query).bind(Identifier(&table_name));

    for row in rows.iter() {
        println!("pass: {}: {:?}", row.name.clone(), row.value.clone());

        match &row.value {
            SerializationType::Int(val) => y = y.bind(val),
            SerializationType::Float(val) => y = y.bind(val),
            SerializationType::Str(val) => y = y.bind(val),
        }
    }

    let yy = y.execute().await;

    println!("I: {:?}", yy);
}

pub struct ClickHouseTenantCredential {
    pub role: String,
    pub db_name: String,
    pub db_user: String,
    pub db_password: String,
}

pub struct ClickHouseRepository {
    client: Client,
}

impl ClickHouseRepository {
    pub fn new(dsn: String) -> ClickHouseRepository {
        let client = Client::default()
            .with_url("http://localhost:8123")
            .with_user("username")
            .with_password("password")
            .with_database("helloworld")
            .with_option("async_insert", "1")
            .with_option("wait_for_async_insert", "0");

        ClickHouseRepository { client }
    }

    pub async fn create_credential(
        &self,
        unique_suffix: String,
        db_password: String,
    ) -> Result<ClickHouseTenantCredential, ()> {
        let role = format!("admin_role_{}", unique_suffix);
        let db_name = format!("db_{}", unique_suffix);
        let db_user = format!("user_{}", unique_suffix);

        let res_3 = self
            .client
            .query("CREATE ROLE ?")
            .bind(Identifier(role.as_str()))
            .execute()
            .await;
        println!("CH {:?}", res_3);

        let res_2 = self
            .client
            .query("CREATE DATABASE ?")
            .bind(Identifier(db_name.as_str()))
            .execute()
            .await;
        println!("CH {:?}", res_2);

        let res_4 = self
            .client
            .query("GRANT SELECT ON ?.* TO ?;")
            .bind(Identifier(db_name.as_str()))
            .bind(Identifier(role.as_str()))
            .execute()
            .await;
        println!("CH {:?}", res_4);

        let res = self
            .client
            .query("CREATE USER ? IDENTIFIED WITH sha256_password BY ? DEFAULT DATABASE ?")
            .bind(Identifier(db_user.as_str()))
            .bind(db_password.clone())
            .bind(Identifier(db_name.as_str()))
            .execute()
            .await;
        println!("CH {:?}", res);

        Ok(ClickHouseTenantCredential {
            role,
            db_name,
            db_user,
            db_password,
        })
    }

    pub async fn execute_migration(&self, schema_diff: JsonSchemaDiff) -> Result<(), ()> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");

        let millis = since_the_epoch.as_millis();
        println!("time: {:?}", millis.to_string());

        let mut args: Vec<(String, String)> = vec![];

        for diff in schema_diff.diff {
            let name = diff.name.clone();
            let diff_ch_type: Result<String, ()> = match diff.diff[1].clone().status.clone() {
                JsonSchemaPropertyStatus::Added(new) => Ok(new),
                _ => Err(()),
            };
            args.push((name, diff_ch_type.unwrap()));
        }

        // vec![("name", "String")]
        let placeholders_str = args.iter().map(|_| "? ?").collect::<Vec<_>>().join(", ");

        let table_name = format!("table_{}", millis);

        let raw_query = format!(
            "
        CREATE TABLE ? (
            {}
        )
        ENGINE = MergeTree
        ORDER BY `name`
        PARTITION BY `name`
        ",
            placeholders_str
        );

        let mut query = self
            .client
            .query(raw_query.as_str())
            .bind(Identifier(table_name.as_str()));

        for arg in args {
            query = query
                .bind(Identifier(arg.0.as_str()))
                .bind(Identifier(arg.1.as_str()));
        }

        let exec = query.execute().await;

        if exec.is_err() {
            println!("Migration {:?}", exec);
            return Err(());
        }

        Ok(())
    }
}

pub struct ClickHouseTenantRepository {
    pub client: Client,
}

impl ClickHouseTenantRepository {
    pub fn new(tenant: ClickHouseTenantCredential) -> ClickHouseTenantRepository {
        let client = Client::default()
            .with_url("http://localhost:8123")
            .with_user(tenant.db_user)
            .with_password(tenant.db_password)
            .with_database(tenant.db_name)
            .with_option("async_insert", "1")
            .with_option("wait_for_async_insert", "0");

        ClickHouseTenantRepository { client }
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
    };
    use hex::encode;
    use rstest::{fixture, rstest};

    #[fixture]
    pub async fn repo() -> ClickHouseRepository {
        ClickHouseRepository::new("clickhouse://...".to_string())
    }

    #[rstest]
    #[tokio::test]
    async fn test_create_credential(#[future] repo: ClickHouseRepository) {
        let repo = repo.await;

        let cred = repo
            .create_credential("abc2".to_string(), "my_password".to_string())
            .await;

        assert!(cred.is_ok());
        let cred = cred.unwrap();

        let tenant_repo = ClickHouseTenantRepository::new(cred);
        let res = tenant_repo.client.query("select 'hleoo'").execute().await;
        println!("CY {:?}", res);
        assert!(res.is_ok());
    }

    #[rstest]
    #[tokio::test]
    async fn generate_migration_by_schema_change(#[future] repo: ClickHouseRepository) {
        let schema_diff = JsonSchemaDiff {
            unsupported_change: false,
            diff: vec![JsonSchemaPropertyDiff {
                name: "name".to_string(),
                status: JsonSchemaPropertyStatus::Added("".to_string()),
                diff: vec![
                    JsonSchemaPropertyEntryDiff {
                        name: "type".to_string(),
                        status: JsonSchemaPropertyStatus::Added("string".to_string()),
                    },
                    JsonSchemaPropertyEntryDiff {
                        name: "x-manyevents-ch-type".to_string(),
                        status: JsonSchemaPropertyStatus::Added("String".to_string()),
                    },
                ],
            }],
        };
        let repo = repo.await;

        let migration = repo.execute_migration(schema_diff).await;

        assert!(migration.is_ok());
    }
}
