use clickhouse::error::Error;
use clickhouse::sql::Identifier;
use clickhouse::Client;
use clickhouse::Row;
use logos::Logos;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::schema::{EventJsonSchema, SerializationType};
use crate::settings::Settings;

#[derive(Row, Deserialize, Debug)]
pub struct ChColumn {
    pub name: String,
    pub value: SerializationType,
}

#[derive(Debug, Clone)]
pub enum MigrationError {
    QueryError(String),
    InvalidType(String, String),
}

pub struct ClickHouseTenantCredential {
    pub role: String,
    pub db_host: String,
    pub db_name: String,
    pub db_user: String,
    pub db_password: String,
}

impl ClickHouseTenantCredential {
    pub fn to_dsn(&self) -> String {
        format!(
            "clickhouse://{}:{}@{}/{}",
            self.db_user, self.db_password, self.db_host, self.db_name
        )
    }
}

pub struct ClickHouseRepository {
    client: Client,
}

impl ClickHouseRepository {
    pub fn from_settings() -> ClickHouseRepository {
        let settings = Settings::read_settings();
        let client = Client::default()
            .with_url(settings.get_local_http_clickhouse_url())
            .with_database(settings.get_clickhouse_db())
            .with_user(settings.get_clickhouse_user())
            .with_password(settings.get_clickhouse_password())
            .with_option("async_insert", "1")
            .with_option("wait_for_async_insert", "1");

        ClickHouseRepository { client }
    }

    pub fn choose_tenant(db_name: &str) -> ClickHouseRepository {
        let settings = Settings::read_settings();
        let client = Client::default()
            .with_url(settings.get_local_http_clickhouse_url())
            .with_database(db_name)
            .with_user(settings.get_clickhouse_user())
            .with_password(settings.get_clickhouse_password())
            .with_option("async_insert", "1")
            .with_option("wait_for_async_insert", "1");

        ClickHouseRepository { client }
    }

    pub fn get_client(&self) -> &Client {
        &self.client
    }

    pub async fn insert(&self, table_name: String, rows: Vec<ChColumn>) -> Result<(), Error> {
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
        debug!("sss: {}/{:?}", table_name, query);
        let mut y = self.client.query(&query).bind(Identifier(&table_name));

        for row in rows.iter() {
            debug!("pass: {}: {:?}", row.name.clone(), row.value.clone());

            match &row.value {
                SerializationType::Int(val) => y = y.bind(val),
                SerializationType::Float(val) => y = y.bind(val),
                SerializationType::Str(val) => y = y.bind(val),
            }
        }

        let yy = y.execute().await;

        debug!("I: {:?}", yy);
        yy
    }

    pub async fn create_credential(
        &self,
        db_name: String,
        db_password: String,
    ) -> Result<ClickHouseTenantCredential, ()> {
        let unique_suffix = db_name.strip_prefix("db_").unwrap_or(&db_name);

        let res_2 = self
            .client
            .query("CREATE DATABASE ?")
            .bind(Identifier(db_name.as_str()))
            .execute()
            .await;
        debug!("CREATE DATABASE {} {:?}", db_name.as_str(), res_2);

        let admin_role = format!("admin_role_{}", unique_suffix);
        let db_user = format!("user_{}", unique_suffix);

        let res_3 = self
            .client
            .query("CREATE ROLE ?")
            .bind(Identifier(admin_role.as_str()))
            .execute()
            .await;
        debug!("CREATE ROLE {} {:?}", admin_role.as_str(), res_3);

        let res_4 = self
            .client
            .query("GRANT SELECT, SHOW, dictGet ON ?.* TO ?;")
            .bind(Identifier(db_name.as_str()))
            .bind(Identifier(admin_role.as_str()))
            .execute()
            .await;
        debug!(
            "GRANT SELECT {}->{} {:?}",
            admin_role.as_str(),
            db_name.as_str(),
            res_4
        );

        let res = self
            .client
            .query("CREATE USER ? IDENTIFIED WITH sha256_password BY ? DEFAULT DATABASE ?")
            .bind(Identifier(db_user.as_str()))
            .bind(db_password.clone())
            .bind(Identifier(db_name.as_str()))
            .execute()
            .await;
        debug!("CREATE USER {} {:?}", db_user.as_str(), res);

        let res = self
            .client
            .query("GRANT ? TO ?")
            .bind(Identifier(admin_role.as_str()))
            .bind(Identifier(db_user.as_str()))
            .execute()
            .await;
        debug!(
            "GRANT ROLE {} TO {} {:?}",
            admin_role.as_str(),
            db_user.as_str(),
            res
        );

        let db_host = Settings::read_settings().clickhouse_external_host;
        Ok(ClickHouseTenantCredential {
            role: admin_role,
            db_host,
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
    ) -> Result<(), MigrationError> {
        // order by, partition by
        let order_by: Result<String, ()> = match migration_plan.order_by {
            ChColumnMigrationStatus::Added(new) => Ok(new),
            _ => Err(()),
        };
        if order_by.is_err() {
            return Err(MigrationError::QueryError(
                "Error order_by for query!".to_string(),
            ));
        }
        let order_by = order_by.unwrap();

        let partition_by: Result<String, ()> = match migration_plan.partition_by {
            ChColumnMigrationStatus::Added(new) => Ok(new),
            _ => Err(()),
        };
        if partition_by.is_err() {
            return Err(MigrationError::QueryError(
                "Error partition_by for query!".to_string(),
            ));
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
                let new_column_type = change_column_type.unwrap();
                let valid_type = validate_type(&new_column_type);
                if !valid_type {
                    return Err(MigrationError::InvalidType(
                        name.clone(),
                        new_column_type.clone(),
                    ));
                }
                args.push((name, new_column_type));
            }
        }
        let or_replace_str = if or_replace { "OR REPLACE " } else { "" };
        let columns_str = args
            .iter()
            .map(|(_, type_)| format!("? {}", type_))
            .collect::<Vec<_>>()
            .join(", ");
        let raw_query = format!(
            "
        CREATE {}TABLE ? (
            {}
        )
        ENGINE = MergeTree
        ORDER BY {}
        PARTITION BY {}
        ",
            or_replace_str, columns_str, order_by, partition_by,
        );

        let mut query = self
            .client
            .query(raw_query.as_str())
            .bind(Identifier(table_name.as_str()));

        for (name, _type_) in args {
            query = query.bind(Identifier(&name));
        }

        let exec = query.execute().await;

        if exec.is_err() {
            debug!("Migration {:?}/Query: {}", exec, raw_query.as_str());
            return Err(MigrationError::QueryError(exec.unwrap_err().to_string()));
        }

        Ok(())
    }

    pub async fn execute_migration(
        &self,
        table_name: String,
        migration_plan: ChTableMigration,
    ) -> Result<(), MigrationError> {
        let mut args: Vec<(String, String)> = vec![];

        for column in migration_plan.columns {
            let name = column.name.clone();

            let change_column_type: Result<String, ()> = match column.type_.clone() {
                ChColumnMigrationStatus::Added(new) => Ok(new),
                _ => {
                    return Err(MigrationError::QueryError(
                        "[Internal] Only Added supported!".to_string(),
                    ))
                }
            };

            if change_column_type.is_ok() {
                args.push((name, change_column_type.unwrap()));
            }
        }

        let _order_by: Result<(), ()> = match migration_plan.order_by {
            ChColumnMigrationStatus::NoChange => Ok(()),
            _ => {
                return Err(MigrationError::QueryError(
                    "[Internal] Only NoChange supported for order_by!".to_string(),
                ))
            }
        };

        for arg in &args {
            let new_column_type = &arg.1;
            if !validate_type(new_column_type) {
                return Err(MigrationError::InvalidType(arg.0.clone(), arg.1.clone()));
            }
        }

        for arg in &args {
            let raw_query = format!("ALTER TABLE ? ADD COLUMN ? {}", arg.1.as_str());
            let query = self
                .client
                .query(&raw_query)
                .bind(Identifier(table_name.as_str()))
                .bind(Identifier(arg.0.as_str()));

            let exec = query.execute().await;

            if exec.is_err() {
                return Err(MigrationError::QueryError(exec.unwrap_err().to_string()));
            }
        }

        Ok(())
    }
}

pub struct ClickHouseTenantRepository {
    client: Client,
}

impl ClickHouseTenantRepository {
    pub fn new(tenant: ClickHouseTenantCredential) -> ClickHouseTenantRepository {
        let settings = Settings::read_settings();
        let client = Client::default()
            .with_url(settings.get_local_http_clickhouse_url())
            .with_user(tenant.db_user)
            .with_password(tenant.db_password)
            .with_database(tenant.db_name)
            .with_option("async_insert", "1")
            .with_option("wait_for_async_insert", "1");

        ClickHouseTenantRepository { client }
    }

    pub fn get_client(&self) -> &Client {
        &self.client
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

pub fn make_migration_plan(from: EventJsonSchema, to: EventJsonSchema) -> ChTableMigration {
    let mut columns: Vec<ChColumnMigration> = vec![];

    for (name, to_property) in &to.properties {
        debug!("{name:?} has {to_property:?}");

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
                    type_: ChColumnMigrationStatus::Changed(
                        from_property.x_manyevents_ch_type.clone(),
                        to_property.x_manyevents_ch_type.clone(),
                    ),
                })
            }
        }
    }

    let mut order_by = ChColumnMigrationStatus::NoChange;
    let mut partition_by = ChColumnMigrationStatus::NoChange;
    if from.properties.len() == 0 && to.properties.len() != 0 {
        order_by = ChColumnMigrationStatus::Added(to.x_manyevents_ch_order_by);

        let mut partition_by_value = to.x_manyevents_ch_partition_by;
        if to.x_manyevents_ch_partition_by_func.is_some() {
            partition_by_value = format!(
                "{}({})",
                to.x_manyevents_ch_partition_by_func.unwrap(),
                partition_by_value
            );
        }
        partition_by = ChColumnMigrationStatus::Added(partition_by_value);
    }

    ChTableMigration {
        columns,
        order_by,
        partition_by,
    }
}

#[derive(Logos, Debug, PartialEq)]
#[logos(skip r"[ \t\n\f]+")]
enum Token {
    #[token("(")]
    LParen,

    #[token(")")]
    RParen,

    #[token(",")]
    Comma,

    #[regex(r"[a-zA-Z][a-zA-Z0-9_]+", |lex| lex.slice().to_string())]
    Ident(String),

    #[regex("('[a-zA-Z0-9/_]*'|\"[a-zA-Z0-9/_]*\")", |lex| lex.slice().to_string())]
    String_(String),

    #[regex(r"\d+")]
    Number,
}

#[derive(Debug, PartialEq)]
enum TypeParseState {
    WaitForIdent,
    ReadIdent,
    InsideWaitForParam,
    InsideReadParam,
    Finish,
}

pub fn validate_type(input: &str) -> bool {
    let mut lex = Token::lexer(input);
    debug!("Start parse CH type: {}", input);

    let mut state = TypeParseState::WaitForIdent;

    while let Some(token) = lex.next() {
        debug!(" state: {:?}, token: {:?}", state, token);
        if token.is_err() {
            return false;
        }
        let token = token.unwrap();
        match state {
            TypeParseState::WaitForIdent => match token {
                Token::Ident(_ident) => {
                    state = TypeParseState::ReadIdent;
                }
                _ => {
                    return false;
                }
            },
            TypeParseState::ReadIdent => match token {
                Token::LParen => {
                    state = TypeParseState::InsideWaitForParam;
                }
                _ => {
                    return false;
                }
            },
            TypeParseState::InsideWaitForParam => match token {
                Token::Ident(_ident) => {
                    state = TypeParseState::InsideReadParam;
                }
                Token::Number => {
                    state = TypeParseState::InsideReadParam;
                }
                Token::String_(_string) => {
                    state = TypeParseState::InsideReadParam;
                }
                Token::RParen => {
                    state = TypeParseState::Finish;
                }
                _ => {
                    return false;
                }
            },
            TypeParseState::InsideReadParam => match token {
                Token::Comma => {
                    state = TypeParseState::InsideWaitForParam;
                }
                Token::RParen => {
                    state = TypeParseState::Finish;
                }
                _ => {
                    return false;
                }
            },
            TypeParseState::Finish => return false,
        }
    }
    state == TypeParseState::ReadIdent || state == TypeParseState::Finish
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::schema::JsonSchemaProperty;
    use rand::Rng;
    use rstest::{fixture, rstest};
    use std::collections::HashMap;
    use tracing_test::traced_test;

    #[fixture]
    pub async fn repo() -> ClickHouseRepository {
        ClickHouseRepository::from_settings()
    }

    #[fixture]
    pub fn unique_name() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        let millis = since_the_epoch.as_millis();
        let salt: [u8; 16] = rand::thread_rng().gen();
        let salt_hex = hex::encode(salt);
        format!("{}_{}", millis, salt_hex)
    }

    #[fixture]
    pub fn unique_db_name(unique_name: String) -> String {
        format!("db_{}", unique_name)
    }

    #[fixture]
    pub fn unique_table_name(unique_name: String) -> String {
        format!("table_{}", unique_name)
    }

    #[rstest]
    #[tokio::test]
    #[traced_test]
    async fn test_create_credential(unique_db_name: String, #[future] repo: ClickHouseRepository) {
        let repo = repo.await;

        let cred = repo
            .create_credential(unique_db_name, "my_password".to_string())
            .await;

        assert!(cred.is_ok());
        let cred = cred.unwrap();
        let tenant_repo = ClickHouseTenantRepository::new(cred);
        #[derive(Row, Deserialize, Debug)]
        struct NameRow {
            name: String,
        }
        let res = tenant_repo
            .get_client()
            .query("SHOW DATABASES")
            .fetch_all::<NameRow>()
            .await;
        debug!("CY {:?}", res);
        assert!(res.is_ok());
    }

    #[rstest]
    #[tokio::test]
    #[traced_test]
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
    #[traced_test]
    async fn invalid_type_migration_error(
        unique_table_name: String,
        #[future] repo: ClickHouseRepository,
    ) {
        let migration_plan = ChTableMigration {
            order_by: ChColumnMigrationStatus::Added("name".to_string()),
            partition_by: ChColumnMigrationStatus::Added("name".to_string()),
            columns: vec![ChColumnMigration {
                name: "name".to_string(),
                type_: ChColumnMigrationStatus::Added(
                    "String) DROP TABLE Students; SELECT * FROM system.tables ".to_string(),
                ),
            }],
        };
        let repo = repo.await;

        let migration = repo
            .execute_init_migration(unique_table_name, migration_plan, false)
            .await;

        assert!(
            migration.is_err(),
            "Migration must fail: {:?}",
            migration.unwrap()
        );
        assert!(match migration.unwrap_err() {
            MigrationError::InvalidType(column, type_) => {
                assert_eq!(column, "name".to_string());
                assert!(type_.contains("DROP TABLE"), "Check: {}", type_);
                true
            }
            _ => false,
        })
    }

    #[rstest]
    #[tokio::test]
    #[traced_test]
    async fn test_access(
        unique_db_name: String,
        unique_table_name: String,
        #[future] repo: ClickHouseRepository,
    ) {
        let repo = repo.await;
        let credential = repo
            .create_credential(unique_db_name.clone(), "my_password".to_string())
            .await;
        assert!(credential.is_ok());
        let credential = credential.unwrap();
        let tenant_repo = ClickHouseRepository::choose_tenant(&credential.db_name);
        let res = tenant_repo
            .get_client()
            .query("CREATE TABLE ? (name String) ORDER BY name")
            .bind(Identifier(unique_table_name.as_str()))
            .execute()
            .await;
        debug!(
            "Created table {}/{}",
            unique_db_name.as_str(),
            unique_table_name.as_str()
        );
        assert!(res.is_ok(), "Create table error: {:?}", res);

        let tenant_repo = ClickHouseTenantRepository::new(credential);
        #[derive(Row, Deserialize, Debug)]
        struct NameRow {
            name: String,
        }
        let res = tenant_repo
            .get_client()
            .query("SHOW TABLES")
            .fetch_all::<NameRow>()
            .await;
        assert!(res.is_ok(), "Show tables error: {:?}", res);
        let res = res.unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].name, unique_table_name);
    }

    #[rstest]
    #[tokio::test]
    #[traced_test]
    async fn test_create_credential_and_migrate(
        unique_db_name: String,
        unique_table_name: String,
        #[future] repo: ClickHouseRepository,
    ) {
        let repo = repo.await;
        let credential = repo
            .create_credential(unique_db_name.clone(), "my_password".to_string())
            .await;
        assert!(credential.is_ok());
        let credential = credential.unwrap();
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
        let tenant_repo = ClickHouseRepository::choose_tenant(&unique_db_name);

        let migration = tenant_repo
            .execute_init_migration(unique_table_name.clone(), migration_plan, false)
            .await;

        assert!(
            migration.is_ok(),
            "Migration failed with error: {:?}",
            migration.unwrap_err()
        );
        let credential_tenant_repo = ClickHouseTenantRepository::new(credential);
        #[derive(Row, Deserialize, Debug)]
        struct NameRow {
            name: String,
        }
        let res = credential_tenant_repo
            .get_client()
            .query("SHOW TABLES")
            .fetch_all::<NameRow>()
            .await;
        assert!(res.is_ok(), "Show tables error: {:?}", res);
        let res = res.unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].name, unique_table_name);
    }

    #[rstest]
    #[tokio::test]
    #[traced_test]
    async fn generate_migration_by_schema_change_2_func(
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
                name: "role".to_string(),
                type_: ChColumnMigrationStatus::Added("LowCardinality(String)".to_string()),
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
    #[tokio::test]
    #[traced_test]
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
    #[tokio::test]
    #[traced_test]
    async fn generate_migration_by_schema_change_2_steps_and_type_error(
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
                type_: ChColumnMigrationStatus::Added("Int64) DROP Students".to_string()),
            }],
        };

        let migration_2 = repo
            .execute_migration(unique_table_name.clone(), migration_plan_2)
            .await;

        assert!(
            migration_2.is_err(),
            "Migration_2 must fail: {:?}",
            migration_2.unwrap()
        );
        let err = migration_2.unwrap_err();
        assert!(
            match err.clone() {
                MigrationError::InvalidType(column, type_) => {
                    assert_eq!(column, "age".to_string());
                    assert!(type_.contains("DROP Students"), "Check: {}", type_);
                    true
                }
                _ => false,
            },
            "Migration_2 error: {:?}",
            err
        );
    }

    #[rstest]
    #[traced_test]
    fn diff_entities_same_schema() {
        let mut the_same = EventJsonSchema::new();
        the_same.x_manyevents_ch_order_by = "name".to_string();
        the_same.properties = HashMap::from([(
            "name".to_string(),
            JsonSchemaProperty {
                type_: "string".to_string(),
                x_manyevents_ch_type: "String".to_string(),
            },
        )]);

        let migration_plan = make_migration_plan(the_same.clone(), the_same.clone());
        assert_eq!(migration_plan.columns.len(), 0);
    }

    #[rstest]
    #[traced_test]
    fn diff_entities_new_field() {
        let empty = EventJsonSchema::new();
        let mut new = EventJsonSchema::new();
        new.x_manyevents_ch_order_by = "name".to_string();
        new.properties = HashMap::from([(
            "name".to_string(),
            JsonSchemaProperty {
                type_: "string".to_string(),
                x_manyevents_ch_type: "String".to_string(),
            },
        )]);

        let migration_plan = make_migration_plan(empty, new);
        assert_eq!(migration_plan.columns.len(), 1);
    }

    #[rstest]
    #[traced_test]
    fn diff_entities_schema_changed_type() {
        let mut old = EventJsonSchema::new();
        old.x_manyevents_ch_order_by = "name".to_string();
        old.properties = HashMap::from([(
            "name".to_string(),
            JsonSchemaProperty {
                type_: "string".to_string(),
                x_manyevents_ch_type: "String".to_string(),
            },
        )]);
        let mut new = EventJsonSchema::new();
        new.x_manyevents_ch_order_by = "name".to_string();
        new.properties = HashMap::from([(
            "name".to_string(),
            JsonSchemaProperty {
                type_: "integer".to_string(),
                x_manyevents_ch_type: "Int64".to_string(),
            },
        )]);

        let migration_plan = make_migration_plan(old, new);

        assert_eq!(migration_plan.columns.len(), 1);
    }

    #[rstest]
    #[traced_test]
    fn test_type_lexer() {
        let mut lex = Token::lexer("String");

        assert_eq!(lex.next(), Some(Ok(Token::Ident("String".to_string()))));
        assert_eq!(lex.next(), None);
    }

    #[rstest]
    #[traced_test]
    fn test_type_lexer_compound() {
        let mut lex = Token::lexer("LowCardinality(String)");

        assert_eq!(
            lex.next(),
            Some(Ok(Token::Ident("LowCardinality".to_string())))
        );
        assert_eq!(lex.next(), Some(Ok(Token::LParen)));
        assert_eq!(lex.next(), Some(Ok(Token::Ident("String".to_string()))));
        assert_eq!(lex.next(), Some(Ok(Token::RParen)));
        assert_eq!(lex.next(), None);
    }

    #[rstest]
    #[traced_test]
    fn test_type_validation() {
        assert!(validate_type("String"));
        assert!(validate_type("LowCardinality(String)"));
        assert!(!validate_type("1"));
        assert!(!validate_type("1 + 2"));
        assert!(!validate_type("LowCardinality(String))"));
        assert!(validate_type("DateTime64(3, 'Asia/Istanbul')"));
        assert!(validate_type("DateTime64(3, \"Asia/Istanbul\")"));
        assert!(!validate_type("DateTime64(3, \"Asia/Istanbul')")); // different quotes
        assert!(validate_type("tuple(String, Int64)"));
    }
}
