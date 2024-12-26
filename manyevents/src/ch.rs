use clickhouse::sql::Identifier;
use clickhouse::Client;
use clickhouse::Row;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::schema::{
    JsonSchemaProperty, JsonSchemaEntity,
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
        .with_database("manyevents")
        .with_user("username")
        .with_password("password")
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
            .with_database("manyevents")
            .with_user("username")
            .with_password("password")
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

    pub async fn execute_init_migration(
        &self,
        table_name: String,
        migration_plan: ChTableMigration,
        or_replace: bool,
    ) -> Result<(), ()> {
        // order by, partition by
        let order_by: Result<String, ()> = match migration_plan.order_by {
            ChColumnMigrationStatus::Added(new) => Ok(new),
            _ => Err(()),
        };
        if order_by.is_err() {
            println!("Error order_by for query!");
            return Err(());
        }
        let order_by = order_by.unwrap();

        let partition_by: Result<String, ()> = match migration_plan.partition_by {
            ChColumnMigrationStatus::Added(new) => Ok(new),
            _ => Err(()),
        };
        if partition_by.is_err() {
            println!("Error partition_by for query!");
            return Err(());
        }
        let partition_by = partition_by.unwrap();

        let mut args: Vec<(String, String)> = vec![];

        for column in migration_plan.columns {
            let name = column.name.clone();

            let change_column_type: Result<String, ()> = match column.type_.clone() {
                ChColumnMigrationStatus::Added(new) => Ok(new),
                _ => Err(()),
            };

            if change_column_type.is_ok() {
                args.push((name, change_column_type.unwrap()));
            }
        }
        let or_replace_str = if or_replace { "OR REPLACE " } else { "" };
        let columns_str = args.iter().map(|(name, type_)| format!("{} {}", name, type_)).collect::<Vec<_>>().join(", ");
        let raw_query = format!(
        "
        CREATE {}TABLE ? (
            {}
        )
        ENGINE = MergeTree
        ORDER BY {}
        PARTITION BY {}
        ",
            or_replace_str,
            columns_str,
            order_by,
            partition_by,
        );

        let mut query = self
            .client
            .query(raw_query.as_str())
            .bind(Identifier(table_name.as_str()));

        // for arg in args {
        //     query = query
        //         .bind(Identifier(arg.0.as_str()))
        //         .bind(arg.1.as_str());
        //     println!("Binded {} {},", arg.0.as_str(), arg.1.as_str());
        // }

        // query = query
        //     .bind(Identifier(order_by.clone().unwrap().as_str()))
        //     .bind(Identifier(order_by.clone().unwrap().as_str()));

        let exec = query.execute().await;

        if exec.is_err() {
            println!("Migration {:?}/Query: {}", exec, raw_query.as_str());
            return Err(());
        }

        Ok(())
    }

    pub async fn execute_migration(
        &self,
        table_name: String,
        migration_plan: ChTableMigration,
    ) -> Result<(), String> {
        let mut args: Vec<(String, String)> = vec![];

        for column in migration_plan.columns {
            let name = column.name.clone();

            let change_column_type: Result<String, ()> = match column.type_.clone() {
                ChColumnMigrationStatus::Added(new) => Ok(new),
                _ => return Err("[Internal] Only Added supported!".to_string()),
            };

            if change_column_type.is_ok() {
                args.push((name, change_column_type.unwrap()));
            }
        }

        let order_by: Result<(), ()> = match migration_plan.order_by {
            ChColumnMigrationStatus::NoChange => Ok(()),
            _ => return Err("[Internal] Only NoChange supported for order_by!".to_string()),
        };

        for arg in args {
            let mut query = self
                .client
                .query("ALTER TABLE ? ADD COLUMN ? ?")
                .bind(Identifier(table_name.as_str()))
                .bind(Identifier(arg.0.as_str()))
                .bind(Identifier(arg.1.as_str()));

            let exec = query.execute().await;

            if exec.is_err() {
                return Err(format!("[CH] {:?}", exec));
            }
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ChColumnMigrationStatus<T> {
    NoChange,
    Added(T),
    Changed(T, T),
    Removed(T),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChColumnMigration {
    pub name: String,
    pub type_: ChColumnMigrationStatus<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChTableMigration {
    pub columns: Vec<ChColumnMigration>,
    pub order_by: ChColumnMigrationStatus<String>,
    pub partition_by: ChColumnMigrationStatus<String>,
}

pub fn make_migration_plan(from: JsonSchemaEntity, to: JsonSchemaEntity) -> ChTableMigration {
    let mut columns: Vec<ChColumnMigration> = vec![];

    for (name, to_property) in &to.properties {
        println!("{name:?} has {to_property:?}");

        if !from.properties.contains_key(name) {
            columns.push(ChColumnMigration {
                name: name.clone(),
                type_: ChColumnMigrationStatus::Added(to_property.x_manyevents_ch_type.clone()),
            })
        } else {
            let from_property = from.properties[name].clone();

            if to_property.x_manyevents_ch_type != from_property.x_manyevents_ch_type {
                columns.push(ChColumnMigration {
                    name: name.clone(),
                    type_: ChColumnMigrationStatus::Changed(from_property.x_manyevents_ch_type.clone(), to_property.x_manyevents_ch_type.clone()),
                })
            }
        }
    }

    let mut order_by = ChColumnMigrationStatus::NoChange;
    let mut partition_by = ChColumnMigrationStatus::NoChange;
    if from.properties.len() == 0 && to.properties.len() != 0 {
        order_by = ChColumnMigrationStatus::Added("timestamp".to_string());
        partition_by = ChColumnMigrationStatus::Added("timestamp".to_string());
    }

    ChTableMigration {
        columns,
        order_by,
        partition_by,
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

    #[fixture]
    pub fn unique_table_name() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        let millis = since_the_epoch.as_millis();
        let salt: [u8; 16] = rand::thread_rng().gen();
        let salt_hex = hex::encode(salt);
        format!("table_{}{}", millis, salt_hex)
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
    async fn generate_migration_by_schema_change(
        unique_table_name: String,
        #[future] repo: ClickHouseRepository,
    ) {
        let migration_plan = ChTableMigration {
            order_by: ChColumnMigrationStatus::Added("name".to_string()),
            partition_by: ChColumnMigrationStatus::Added("name".to_string()),
            columns: vec![
                ChColumnMigration {
                    name: "name".to_string(),
                    type_: ChColumnMigrationStatus::Added("String".to_string()),
                },
                ChColumnMigration {
                    name: "age".to_string(),
                    type_: ChColumnMigrationStatus::Added("Int64".to_string()),
                },
            ],
        };
        let repo = repo.await;

        let migration = repo
            .execute_init_migration(unique_table_name, migration_plan, false)
            .await;

        assert!(
            migration.is_ok(),
            "Migration failed with error: {:?}",
            migration.unwrap_err()
        );
    }

    #[rstest]
    #[tokio::test]
    async fn generate_migration_by_schema_change_2_steps(
        unique_table_name: String,
        #[future] repo: ClickHouseRepository,
    ) {
        let migration_plan = ChTableMigration {
            order_by: ChColumnMigrationStatus::Added("name".to_string()),
            partition_by: ChColumnMigrationStatus::Added("name".to_string()),
            columns: vec![ChColumnMigration {
                name: "name".to_string(),
                type_: ChColumnMigrationStatus::Added("String".to_string()),
            }],
        };
        let repo = repo.await;
        let migration = repo
            .execute_init_migration(unique_table_name.clone(), migration_plan, false)
            .await;
        assert!(
            migration.is_ok(),
            "Migration failed with error: {:?}",
            migration.unwrap_err()
        );
        let migration_plan_2 = ChTableMigration {
            order_by: ChColumnMigrationStatus::NoChange,
            partition_by: ChColumnMigrationStatus::NoChange,
            columns: vec![ChColumnMigration {
                name: "age".to_string(),
                type_: ChColumnMigrationStatus::Added("Int64".to_string()),
            }],
        };

        let migration_2 = repo
            .execute_migration(unique_table_name.clone(), migration_plan_2)
            .await;

        assert!(
            migration_2.is_ok(),
            "Migration_2 failed with error: {:?}",
            migration_2.unwrap_err()
        );
    }

    #[rstest]
    fn diff_entities_same_schema() {
        let the_same = JsonSchemaEntity {
            properties: HashMap::from([(
                "name".to_string(),
                JsonSchemaProperty {
                    type_: "string".to_string(),
                    x_manyevents_ch_type: "String".to_string(),
                },
            )]),
        };

        let migration_plan = make_migration_plan(the_same.clone(), the_same.clone());
        assert_eq!(migration_plan.columns.len(), 0);
    }

    #[rstest]
    fn diff_entities_new_field() {
        let empty = JsonSchemaEntity {
            properties: HashMap::new(),
        };
        let new = JsonSchemaEntity {
            properties: HashMap::from([(
                "name".to_string(),
                JsonSchemaProperty {
                    type_: "string".to_string(),
                    x_manyevents_ch_type: "String".to_string(),
                },
            )]),
        };

        let migration_plan = make_migration_plan(empty, new);
        assert_eq!(migration_plan.columns.len(), 1);
    }

    #[rstest]
    fn diff_entities_schema_changed_type() {
        let old = JsonSchemaEntity {
            properties: HashMap::from([(
                "name".to_string(),
                JsonSchemaProperty {
                    type_: "string".to_string(),
                    x_manyevents_ch_type: "String".to_string(),
                },
            )]),
        };
        let new = JsonSchemaEntity {
            properties: HashMap::from([(
                "name".to_string(),
                JsonSchemaProperty {
                    type_: "integer".to_string(),
                    x_manyevents_ch_type: "Int64".to_string(),
                },
            )]),
        };

        let migration_plan = make_migration_plan(old, new);

        assert_eq!(migration_plan.columns.len(), 1);
    }
}
