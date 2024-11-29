#[macro_use]
extern crate rocket;

mod schema;
mod ch;

use std::time::{Duration, UNIX_EPOCH};

use rocket::data::{Data, ToByteUnit};
use rocket::http::{
    Method::{Get, Post},
    Status,
};

use clickhouse::sql::Identifier;
use rocket::data::Capped;
use rocket::fairing::{self, AdHoc};
use rocket::response::status::Custom;
use rocket::serde::uuid::Uuid;
use rocket::{route, Build, Request, Rocket, Route};
use serde_json::Value;

use rocket::serde::json::Json;
use rocket::serde::{Deserialize, Serialize};
use rocket_db_pools::sqlx::{self, Row};
use rocket_db_pools::{Connection, Database};

use crate::schema::read_event_data;
use crate::ch::{insert_smth, ChColumn};

#[derive(Database)]
#[database("postgres")]
struct Db(sqlx::PgPool);

type Result<T, E = rocket::response::Debug<sqlx::Error>> = std::result::Result<T, E>;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
struct CreateTenantRequest {
    title: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
struct CreateTenantResponse {
    is_success: bool,
    id: Option<Uuid>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
struct PushEventResponse {
    is_success: bool,
}

#[derive(Debug, Serialize, Deserialize)]
enum SerializationType {
    Int(i64),
    Float(f64),
    Str(String),
}

#[derive(Debug, Serialize, Deserialize)]
struct Column {
    name: String,
    value: SerializationType,
}

fn push_event<'r>(req: &'r Request, data: Data<'r>) -> route::BoxFuture<'r> {
    Box::pin(async move {
        let stream = data.open(2.mebibytes());
        let f = stream.into_string().await.unwrap();

        let capped_data: Capped<String> = f.into();
        let data: Value = serde_json::from_str(&capped_data).unwrap();

        let result = read_event_data(&data);

        // match result {
        //     Ok(event) => println!("Data: {:?}", event),
        //     Err(_) => todo!(),
        // }

        let event = result.unwrap();

        // todo check schema
        // insert into clickhouse

        let mut columns: Vec<ChColumn> = vec![];

        for unit in event.units.iter() {
            for value in unit.value.iter() {
                let column = ChColumn {
                    name: format!("{}_{}", unit.name, value.name),
                    value: value.value.clone(),
                };
                println!("ins: {}: {:?}", column.name.clone(), value.value.clone());
                columns.push(column);
            }
        }

        insert_smth("chrs_async_insert".to_string(), columns).await;

        let push_event_response = PushEventResponse { is_success: true };
        let push_event_response_str = serde_json::to_string(&push_event_response).unwrap();
        return route::Outcome::from(req, push_event_response_str);
    })
}

#[post("/v1/create-tenant", data = "<tenant>")]
async fn create_tenant(
    mut db: Connection<Db>,
    tenant: Json<CreateTenantRequest>,
) -> Result<Custom<Json<CreateTenantResponse>>> {
    let results = sqlx::query(
        "
        INSERT INTO tenant (title)
            VALUES ($1)
            RETURNING id
        ",
    )
    .bind(tenant.title.clone())
    .fetch_all(&mut **db)
    .await
    .and_then(|r| {
        let processed_result: Vec<Uuid> = r
            .iter()
            .map(|row| row.get::<Uuid, _>(0))
            .collect::<Vec<Uuid>>();
        Ok(Some(processed_result))
    })
    .or_else(|e| {
        println!("Database query error: {}", e);
        Err(e)
    })?;

    let results = match results {
        Some(res) => res,
        None => return Err(rocket::response::Debug(sqlx::Error::RowNotFound)),
    };
    let result_id: Option<Uuid> = Some(results[0]);
    let response = CreateTenantResponse {
        is_success: true,
        id: result_id,
    };
    Ok(Custom(Status::Ok, Json(response)))
}

async fn run_migrations(rocket: Rocket<Build>) -> fairing::Result {
    match Db::fetch(&rocket) {
        Some(db) => match sqlx::migrate!("db/migrations").run(&**db).await {
            Ok(_) => Ok(rocket),
            Err(e) => {
                error!("Failed to initialize SQLx database: {}", e);
                Err(rocket)
            }
        },
        None => Err(rocket),
    }
}

#[launch]
fn rocket() -> _ {
    let post_push_event = Route::new(Post, "/", push_event);
    rocket::build()
        .attach(Db::init())
        // Migrations on start will work only during the early development period
        .attach(AdHoc::try_on_ignite("SQLx Migrations", run_migrations))
        .mount("/api/manage", routes![create_tenant])
        .mount("/api/push/v1/push-event", vec![post_push_event])
}

fn now() -> u64 {
    UNIX_EPOCH
        .elapsed()
        .expect("invalid system time")
        .as_nanos() as u64
}

#[cfg(test)]
mod test {
    use super::*;
    use rocket::http::Status;
    use rocket::local::blocking::Client;
    use rstest::{fixture, rstest};

    #[fixture]
    fn client() -> Client {
        Client::tracked(rocket()).unwrap()
    }

    fn create_tenant(client: Client, title: String) -> Uuid {
        let tenant_request = CreateTenantRequest { title: title };
        let tenant_request_str = serde_json::to_string(&tenant_request).unwrap();

        let response = client
            .post("/api/manage/v1/create-tenant")
            .body(tenant_request_str)
            .dispatch();

        assert_eq!(response.status(), Status::Ok);
        let response_str = response.into_string().unwrap();
        let topic_response: CreateTenantResponse = serde_json::from_str(&response_str).unwrap();
        assert_eq!(topic_response.is_success, true);
        topic_response.id.unwrap()
    }

    #[rstest]
    fn test_create_tenant(client: Client) {
        create_tenant(client, "test-tenant".to_string());
    }

    #[rstest]
    fn test_push_event(client: Client) {
        let push_request_str = r#"{
            "event": {
                "units": [
                    {
                        "type": "span",
                        "id": "xxxx",
                        "start_time": 1234567890,
                        "end_time": 1234567892
                    },
                    {
                        "type": "base",
                        "parent_span_id": "xxxx",
                        "message": "test message"
                    }
                ]
            }
        }
        "#;

        let response = client
            .post("/api/push/v1/push-event")
            .body(push_request_str)
            .dispatch();

        assert_eq!(response.status(), Status::Ok);
        let response_str = response.into_string().unwrap();
        let push_event_response: PushEventResponse = serde_json::from_str(&response_str).unwrap();
        assert_eq!(push_event_response.is_success, true);
        assert!(false);
    }
}
