#[macro_use]
extern crate rocket;

use std::time::{Duration, UNIX_EPOCH};

use rocket::data::{Data, ToByteUnit};
use rocket::http::{
    Method::{Get, Post},
    Status,
};

use clickhouse::sql::Identifier;
use serde_json::Value;
use rocket::fairing::{self, AdHoc};
use rocket::response::status::Custom;
use rocket::serde::uuid::Uuid;
use rocket::data::Capped;
use rocket::{route, Build, Request, Rocket, Route};

use rocket::serde::json::Json;
use rocket::serde::{Deserialize, Serialize};
use rocket_db_pools::sqlx::{self, Row};
use rocket_db_pools::{Connection, Database};

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

        let mut array: Vec<Column> = Vec::new();

        let event = data.get("event");
        if event.is_none() {
            return route::Outcome::error(Status::BadRequest);
        }
        if !event.unwrap().is_object() {
            return route::Outcome::error(Status::BadRequest);
        }
        let units = event.unwrap().get("units");
        if units.is_none() {
            return route::Outcome::error(Status::BadRequest);
        }
        if !units.unwrap().is_array() {
            return route::Outcome::error(Status::BadRequest);
        }
        for unit in units.unwrap().as_array().unwrap() {
            let unit_type = unit.get("type");

            if unit_type.is_none() {
                return route::Outcome::error(Status::BadRequest);
            }
            let type_str = unit_type.unwrap().as_str().unwrap();
            if !unit.is_object() {
                return route::Outcome::error(Status::BadRequest);
            }
            for val in unit.as_object().unwrap() {
                let (key, v) = val;
                println!(">>: {}", key);
                let column_name = format!("{}_{}", type_str, key.to_string());

                let mut set_value = SerializationType::Str("".to_string());
                if v.is_i64() {
                    set_value = SerializationType::Int(v.as_i64().unwrap());
                } else if v.is_f64() {
                    set_value = SerializationType::Float(v.as_f64().unwrap());
                } else if v.is_string() {
                    set_value = SerializationType::Str(v.as_str().unwrap().to_string());
                }
                array.push(Column {
                    name: column_name,
                    value: set_value,
                });
            }
        }

        println!("Data: {:?}", array);

        let push_event_response = PushEventResponse {
            is_success: true,
        };
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
        let tenant_request = CreateTenantRequest {
            title: title,
        };
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
                        "value": 1
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
