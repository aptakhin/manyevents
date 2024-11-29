// use clickhouse::Client;
// use serde::Deserialize;
// use clickhouse::Row;
// use serde_derive::Deserialize;

// #[derive(Row, Deserialize, Debug)]
// struct MyRow<'a> {
//     no: u32,
//     name: &'a str,
// }



// #[tokio::main]
// async fn main() -> Result<(), Box<dyn std::error::Error>> {
//     println!("Hello, world!");

//     let client = Client::default()
//         .with_url("http://localhost:8123")
//         .with_user("username")
//         .with_password("password")
//         .with_database("helloworld");

//     let mut cursor = client
//         .query("SELECT ?fields FROM some WHERE no BETWEEN ? AND ?")
//         .bind(0)
//         .bind(504)
//         .fetch::<MyRow<'_>>()?;

//     while let Some(row) = cursor.next().await? {
//         println!("{:?}", row);
//     }
//     Ok(())
// }

// #[macro_use]
// extern crate rocket;

// use std::time::{Duration, UNIX_EPOCH};

// // use serde_derive::{Deserialize, Serialize};
// // use serde::{Deserialize, Serialize};
// use rocket::data::{Data, ToByteUnit};
// use rocket::http::{Status, Method::{Get, Post}};

// use clickhouse::sql::Identifier;
// #[tokio::main]
// async fn main() -> Result<()> {
//     let table_name = "chrs_async_insert";

//     let client = Client::default()
//         .with_url("http://localhost:8123")
//         .with_user("username")
//         .with_password("password")
//         .with_database("helloworld")
//         // https://clickhouse.com/docs/en/operations/settings/settings#async-insert
//         .with_option("async_insert", "1")
//         // https://clickhouse.com/docs/en/operations/settings/settings#wait-for-async-insert
//         .with_option("wait_for_async_insert", "0");

//     client
//         .query(
//             "
//             CREATE OR REPLACE TABLE ? (
//                 timestamp DateTime64(9),
//                 message   String
//             )
//             ENGINE = MergeTree
//             ORDER BY timestamp
//             ",
//         )
//         .bind(Identifier(table_name))
//         .execute()
//         .await?;

//     let mut insert = client.insert(table_name)?;
//     insert
//         .write(&Event {
//             timestamp: now(),
//             message: "one".into(),
//         })
//         .await?;
//     insert.end().await?;

//     loop {
//         let events = client
//             .query("SELECT ?fields FROM ?")
//             .bind(Identifier(table_name))
//             .fetch_all::<Event>()
//             .await?;
//         if !events.is_empty() {
//             println!("Async insert was flushed");
//             println!("{events:?}");
//             break;
//         }
//         // If you change the `wait_for_async_insert` setting to 1, this line will never be printed;
//         // however, without waiting, you will see it in the console output several times,
//         // as the data will remain in the server buffer for a bit before the flush happens
//         println!("Waiting for async insert flush...");
//         tokio::time::sleep(Duration::from_millis(10)).await
//     }

//     Ok(())
// }
