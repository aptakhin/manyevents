use clickhouse::sql::Identifier;
use clickhouse::Client;
use clickhouse::Row;
use serde::Deserialize;

use crate::schema::SerializationType;

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
