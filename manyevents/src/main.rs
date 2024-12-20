#[macro_use]
extern crate rocket;

mod auth;
mod ch;
mod schema;

use rocket::data::{Data, ToByteUnit};
use rocket::http::{Method::Post, Status, ContentType};
use rocket_dyn_templates::{context, Template};

use rocket::data::Capped;
use rocket::fairing::{self, AdHoc};
use rocket::form::Form;
use rocket::response::status::Custom;
use rocket::response::Redirect;
use rocket::serde::uuid::Uuid;
use rocket::{route, Build, Request, Rocket, Route};
use serde_json::Value;

use rocket::serde::json::Json;
use rocket::serde::{Deserialize, Serialize};
use rocket_db_pools::sqlx::{self, Row};
use rocket_db_pools::{Connection, Database};

use crate::auth::{auth_signin, internal_auth_add_token, internal_auth_add_account, internal_auth_check_token, SigninRequest};
use crate::ch::{insert_smth, ChColumn};
use crate::schema::read_event_data;

#[derive(Database, Debug, Clone)]
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
    message_code: Option<String>,
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

        if result.is_err() {
            let push_event_response = PushEventResponse {
                is_success: false,
                message_code: Some(result.unwrap_err().message_code.to_string()),
            };
            let push_event_response_str = serde_json::to_string(&push_event_response).unwrap();
            return route::Outcome::from(req, push_event_response_str);
        }

        let event = result.unwrap();

        // todo check schema

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

        let push_event_response = PushEventResponse {
            is_success: true,
            message_code: None,
        };
        let push_event_response_str = serde_json::to_string(&push_event_response).unwrap();
        return route::Outcome::from(req, push_event_response_str);
    })
}

#[get("/")]
async fn get_root() -> Template {
    Template::render("index", context! { user_name: "Alex" })
}

#[get("/")]
async fn get_signin() -> Template {
    Template::render("signin", context! {})
}

#[derive(Debug, FromForm)]
pub struct Signin {
    pub email: String,
    pub password: String,
}

#[derive(Responder)]
pub enum TemplateOrRedirect {
    Template(Template),
    Redirect(Redirect),
}

#[post("/", data = "<signin_form>")]
async fn post_signin(signin_form: Form<Signin>, mut db: Connection<Db>) -> TemplateOrRedirect {
    let signin = signin_form.into_inner();

    let signin_response = auth_signin(
        SigninRequest {
            email: signin.email,
            password: signin.password,
        },
        db,
    )
    .await;

    if signin_response.is_err() {
        return TemplateOrRedirect::Template(Template::render(
            "signin",
            context! { error: signin_response.unwrap_err() },
        ));
    }

    TemplateOrRedirect::Redirect(Redirect::to("/dashboard"))
}

#[get("/")]
async fn get_docs() -> Template {
    Template::render("docs", context! {})
}

#[get("/")]
async fn get_dashboard() -> Template {
    Template::render("dashboard", context! {
        push_token_live: "me-push-live-xxxxxx22222",
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

fn rocket() -> Rocket<Build> {
    let post_push_event = Route::new(Post, "/", push_event);
    let mut build = rocket::build()
        .attach(Db::init())
        .attach(Template::fairing())
        // Migrations on start will work only during the early development period
        .attach(AdHoc::try_on_ignite("SQLx Migrations", run_migrations))
        .mount("/", routes![get_root])
        .mount("/signin", routes![get_signin, post_signin])
        .mount("/docs", routes![get_docs])
        .mount("/dashboard", routes![get_dashboard])
        .mount("/api/manage", routes![create_tenant])
        .mount("/api/push/v1/push-event", vec![post_push_event]);

    // this is internal endpoints added only because of issues to use database in tests
    // should be disabled for prod
    if cfg!(debug_assertions) {
        build = build
            .mount("/api-internal/add-account", routes![internal_auth_add_account])
            .mount("/api-internal/add-token", routes![internal_auth_add_token])
            .mount(
                "/api-internal/check-token",
                routes![internal_auth_check_token],
            );
    }
    build
}

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    let _rocket = rocket().launch().await?;
    Ok(())
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

    // #[rstest]
    // async fn test_push_event_failedxxx(client: Client) {
    //     let tenant_request = CreateTenantRequest { title: title };
    //     let tenant_request_str = serde_json::to_string(&tenant_request).unwrap();

    //     let response = client
    //         .post("/api/manage/v1/create-tenant")
    //         .body(tenant_request_str)
    //         .dispatch();
    // }

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
                        "timestamp": 1234567892,
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
    }

    #[rstest]
    fn test_push_event_failed(client: Client) {
        let push_request_str = r#"{ "event": {} }"#;

        let response = client
            .post("/api/push/v1/push-event")
            .body(push_request_str)
            .dispatch();

        assert_eq!(response.status(), Status::Ok);
        let response_str = response.into_string().unwrap();
        let push_event_response: PushEventResponse = serde_json::from_str(&response_str).unwrap();
        assert_eq!(push_event_response.is_success, false);
        assert_eq!(push_event_response.message_code.unwrap(), "invalid_units");
    }

    #[rstest]
    #[case("/")]
    #[case("/signin")]
    #[case("/docs")]
    fn test_get_not_empty_200_response(#[case] s: impl AsRef<str>, client: Client) {
        let response = client.get(s.as_ref()).dispatch();

        assert_eq!(response.status(), Status::Ok);
        let response_str = response.into_string().unwrap();
        assert!(
            !response_str.is_empty(),
            "Response string should not be empty"
        );
    }

    #[rstest]
    fn test_post_signin_successful_redirect(client: Client) {
        let push_request_str = r#"email=aaaa&password=xxx"#;

        let response = client
            .post("/signin")
            .header(ContentType::Form)
            .body(push_request_str)
            .dispatch();

        assert_eq!(response.status(), Status::SeeOther);
        let location_header = response.headers().get_one("Location");
        assert!(
            location_header.is_some(),
            "Location header should be present"
        );
        let redirect_url = location_header.unwrap();
        assert_eq!(redirect_url, "/dashboard");
    }
}
