#[macro_use]
extern crate rocket;

use std::time::{Duration, UNIX_EPOCH};

use rocket::data::{Data, ToByteUnit};
use rocket::http::{
    Method::{Get, Post},
    Status,
};

use clickhouse::sql::Identifier;

use rocket::fairing::{self, AdHoc};
use rocket::response::status::Custom;
use rocket::serde::uuid::Uuid;
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
struct CreateTopicRequest {
    parent_topic_id: Option<Uuid>,
    title: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
struct CreateTopicResponse {
    is_success: bool,
    id: Option<Uuid>,
}

fn push_event<'r>(req: &'r Request, data: Data<'r>) -> route::BoxFuture<'r> {
    Box::pin(async move {
        // if !req.content_type().map_or(false, |ct| ct.is_plain()) {
        //     println!("    => Content-Type of upload must be text/plain. Ignoring.");
        //     return route::Outcome::error(Status::BadRequest);
        // }

        return route::Outcome::from(req, format!("OK: {} bytes uploaded.", 2));
    })
}

#[post("/topic/v1/create-topic", data = "<topic>")]
async fn create_topic(
    mut db: Connection<Db>,
    topic: Json<CreateTopicRequest>,
) -> Result<Custom<Json<CreateTopicResponse>>> {
    let results = sqlx::query(
        "
        INSERT INTO topic (parent_topic_id, title)
            VALUES ($1, $2)
            RETURNING id
        ",
    )
    .bind(topic.parent_topic_id)
    .bind(topic.title.clone())
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
    let response = CreateTopicResponse {
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
        .mount("/api", routes![create_topic])
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

    #[rstest]
    fn test_push_event(client: Client) {
        let push_request_str = "{}";

        let response = client
            .post("/api/push/v1/push-event")
            .body(push_request_str)
            .dispatch();

        assert_eq!(response.status(), Status::Ok);
        let response_str = response.into_string().unwrap();
        // let chat_response: CreateChatResponse = serde_json::from_str(&response_str).unwrap();
        // assert_eq!(chat_response.is_success, true);
        // assert_eq!(chat_response.id.is_some(), true);
    }
}
