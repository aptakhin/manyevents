use axum::{
    async_trait,
    body::Bytes,
    extract::{Form, FromRef, FromRequest, FromRequestParts, Request, State},
    http::{request::Parts, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
    routing::post,
    Json, Router,
};

use axum_extra::extract::cookie::{Cookie, CookieJar};

use http_body_util::BodyExt;
use minijinja::{context, path_loader, Environment};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;
use std::time::Duration;
use tokio::net::TcpListener;
use tower::util::ServiceExt;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use uuid::Uuid;

mod auth;
mod ch;
mod schema;

use crate::auth::{auth_signin, SigninRequest, add_auth_token, check_token_within_type};
use crate::ch::{insert_smth, ChColumn};
use crate::schema::read_event_data;

type DbPool = PgPool;

async fn make_db() -> DbPool {
    let db_connection_str = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/manyevents".to_string());

    PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(3))
        .connect(&db_connection_str)
        .await
        .expect("can't connect to database")
}

async fn using_connection_pool_extractor(
    State(pool): State<DbPool>,
) -> Result<String, (StatusCode, String)> {
    sqlx::query_scalar("select 'hello world from pg'")
        .fetch_one(&pool)
        .await
        .map_err(internal_error)
}

#[derive(Debug)]
struct DatabaseConnection(sqlx::pool::PoolConnection<sqlx::Postgres>);

#[async_trait]
impl<S> FromRequestParts<S> for DatabaseConnection
where
    DbPool: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let pool = DbPool::from_ref(state);
        let conn = pool.acquire().await.map_err(internal_error)?;
        Ok(Self(conn))
    }
}

async fn using_connection_extractor(
    DatabaseConnection(mut conn): DatabaseConnection,
) -> Result<String, (StatusCode, String)> {
    sqlx::query_scalar("select 'hello world from pg'")
        .fetch_one(&mut *conn)
        .await
        .map_err(internal_error)
}

fn internal_error<E>(err: E) -> (StatusCode, String)
where
    E: std::error::Error,
{
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct CreateTenantRequest {
    title: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct CreateTenantResponse {
    is_success: bool,
    id: Option<Uuid>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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

async fn get_root() -> Html<String> {
    let mut env = Environment::new();
    env.set_loader(path_loader("static/templates"));
    let tmpl = env.get_template("index.html.j2").unwrap();
    Html(tmpl.render(context!(name => "John")).unwrap())
}

async fn get_signin() -> Html<String> {
    let mut env = Environment::new();
    env.set_loader(path_loader("static/templates"));
    let tmpl = env.get_template("signin.html.j2").unwrap();
    Html(tmpl.render(context!(name => "John")).unwrap())
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Signin {
    pub email: String,
    pub password: String,
}

#[derive()]
pub enum HtmlOrRedirect {
    Html(Html<String>),
    Redirect(Redirect),
}

impl IntoResponse for HtmlOrRedirect {
    fn into_response(self) -> Response {
        match self {
            HtmlOrRedirect::Html(html) => html.into_response(),
            HtmlOrRedirect::Redirect(redirect) => redirect.into_response(),
        }
    }
}

async fn post_signin(
    jar: CookieJar, State(pool): State<DbPool>,
    Form(signin_form): Form<Signin>,
) -> Result<(CookieJar, Redirect), Html<String>> {
    let signin_response = auth_signin(
        SigninRequest {
            email: signin_form.email,
            password: signin_form.password,
        },
        &pool,
    )
    .await;

    if signin_response.is_err() {
        let mut env = Environment::new();
        env.set_loader(path_loader("static/templates"));
        let tmpl = env.get_template("signin.html.j2").unwrap();
        return Err(Html(tmpl.render(context!(name => "John")).unwrap()));
    }

    let auth_token = add_auth_token("auth".to_string(), signin_response.unwrap().account_id, &pool).await;
    let token = auth_token.unwrap().token;

    Ok((jar.add(Cookie::new("_s".to_string(), token)), Redirect::to("/dashboard")))
}

async fn get_docs() -> HtmlOrRedirect {
    let mut env = Environment::new();
    env.set_loader(path_loader("static/templates"));
    let tmpl = env.get_template("docs.html.j2").unwrap();
    HtmlOrRedirect::Html(Html(tmpl.render(context!(name => "John")).unwrap()))
}

#[derive(Debug)]
struct Authentificated(Uuid);

#[async_trait]
impl<S> FromRequest<S> for Authentificated
where
    DbPool: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let pool = DbPool::from_ref(state);

        let cookies = CookieJar::from_headers(req.headers());

        let token = cookies.get("_s");
        println!("Cook {:?}", token);
        if token.is_none() {
            return Err(StatusCode::UNAUTHORIZED);
        }

        let cookie_value = token.unwrap().value().to_string();
        println!("Cook2 {:?}", cookie_value.clone());

        let resp = check_token_within_type(cookie_value, "auth".to_string(), &pool).await;

        match resp {
            Ok(auth) => Ok(Authentificated(auth.id)),
            Err(_) => Err(StatusCode::UNAUTHORIZED),
        }
    }
}
async fn get_dashboard(Authentificated(auth): Authentificated) -> HtmlOrRedirect {
    let check = auth.clone();

    let mut env = Environment::new();
    env.set_loader(path_loader("static/templates"));
    let tmpl = env.get_template("dashboard.html.j2").unwrap();
    HtmlOrRedirect::Html(Html(tmpl.render(context!(push_token_live => "me-push-live-xxxxxx22222", check)).unwrap()))
}

async fn create_tenant(
    State(pool): State<DbPool>,
    Json(tenant): Json<CreateTenantRequest>,
) -> Json<CreateTenantResponse> {
    let results = sqlx::query(
        "
        INSERT INTO tenant (title)
            VALUES ($1)
            RETURNING id
        ",
    )
    .bind(tenant.title.clone())
    .fetch_all(&pool)
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
    });

    let results = match results {
        Ok(Some(res)) => res,
        Ok(None) => {
            return Json(CreateTenantResponse {
                is_success: false,
                id: None,
            })
        }
        Err(_) => {
            return Json(CreateTenantResponse {
                is_success: false,
                id: None,
            })
        }
    };
    let result_id: Option<Uuid> = Some(results[0]);
    let response = CreateTenantResponse {
        is_success: true,
        id: result_id,
    };
    Json(response)
}

async fn push_event(BufferRequestBody(body): BufferRequestBody) -> Json<PushEventResponse> {
    let body_str = std::str::from_utf8(&body).unwrap();
    let data: Value = serde_json::from_str(&body_str).unwrap();
    let result = read_event_data(&data);

    if result.is_err() {
        return Json(PushEventResponse {
            is_success: false,
            message_code: Some(result.unwrap_err().message_code.to_string()),
        });
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

    Json(PushEventResponse {
        is_success: true,
        message_code: None,
    })
}

struct BufferRequestBody(Bytes);

#[async_trait]
impl<S> FromRequest<S> for BufferRequestBody
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let body = Bytes::from_request(req, state)
            .await
            .map_err(|err| err.into_response())?;

        Ok(Self(body))
    }
}

async fn routes_app() -> Router<()> {
    let pool = make_db().await;

    let router: Router<()> = Router::new()
        .route("/", get(get_root))
        .route("/signin", get(get_signin).post(post_signin))
        .route("/docs", get(get_docs))
        .route("/dashboard", get(get_dashboard))
        .route("/api/push/v1/push-event", post(push_event))
        .route("/api/manage/v1/create-tenant", post(create_tenant))
        .route(
            "/db",
            get(using_connection_pool_extractor).post(using_connection_extractor),
        )
        .with_state(pool);

    router
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("{}=debug", env!("CARGO_CRATE_NAME")).into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let listener = TcpListener::bind("127.0.0.1:8000").await.unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());

    let app = routes_app().await;
    axum::serve(listener, app).await.unwrap();
}

#[cfg(test)]
mod test {
    use super::*;
    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
    };
    use rstest::{fixture, rstest};

    #[fixture]
    pub async fn app() -> Router<()> {
        routes_app().await
    }

    #[fixture]
    pub async fn pool() -> DbPool {
        make_db().await
    }

    async fn create_tenant(title: String, app: Router<()>) -> Uuid {
        let tenant_request = CreateTenantRequest { title: title };
        let tenant_request_str = serde_json::to_string(&tenant_request).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .header("Content-Type", "application/json")
                    .uri("/api/manage/v1/create-tenant")
                    .body(Body::from(tenant_request_str))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body_str = std::str::from_utf8(&body).unwrap();
        let tenant_response: CreateTenantResponse = serde_json::from_str(&body_str).unwrap();
        assert_eq!(tenant_response.is_success, true);
        tenant_response.id.unwrap()
    }

    #[rstest]
    #[tokio::test]
    async fn test_create_tenant(#[future] app: Router<()>) {
        let tenant_id = create_tenant("test-tenant".to_string(), app.await).await;
        assert!(tenant_id != Uuid::nil());
    }

    #[rstest]
    #[tokio::test]
    async fn test_push_event(#[future] app: Router<()>) {
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

        let response = app
            .await
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .header("Content-Type", "application/json")
                    .uri("/api/push/v1/push-event")
                    .body(Body::from(push_request_str))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let response_str = std::str::from_utf8(&body).unwrap();
        let push_event_response: PushEventResponse = serde_json::from_str(&response_str).unwrap();
        assert_eq!(push_event_response.is_success, true);
    }

    #[rstest]
    #[tokio::test]
    async fn test_push_event_failed(#[future] app: Router<()>) {
        let push_request_str = r#"{ "event": {} }"#;

        let response = app
            .await
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .header("Content-Type", "application/json")
                    .uri("/api/push/v1/push-event")
                    .body(Body::from(push_request_str))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let response_str = std::str::from_utf8(&body).unwrap();
        let push_event_response: PushEventResponse = serde_json::from_str(&response_str).unwrap();
        assert_eq!(push_event_response.is_success, false);
        assert_eq!(push_event_response.message_code.unwrap(), "invalid_units");
    }

    #[rstest]
    #[case("/")]
    #[case("/signin")]
    #[case("/docs")]
    #[tokio::test]
    async fn get_root(#[case] s: impl AsRef<str>, #[future] app: Router<()>) {
        let response = app
            .await
            .oneshot(
                Request::builder()
                    .uri(s.as_ref())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body_str = std::str::from_utf8(&body).unwrap();
        assert!(!body_str.is_empty(), "Response string should not be empty");
    }

    #[rstest]
    #[case("/dashboard")]
    #[tokio::test]
    async fn check_unauthorized(#[case] s: impl AsRef<str>, #[future] app: Router<()>) {
        let response = app
            .await
            .oneshot(
                Request::builder()
                    .uri(s.as_ref())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[rstest]
    #[tokio::test]
    async fn test_post_signin_successful_redirect(#[future] app: Router<()>) {
        let push_request_str = r#"email=aaaa&password=xxx"#;

        let response = app
            .await
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .uri("/signin")
                    .body(Body::from(push_request_str))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert!(response.headers().contains_key("Location"));
        assert_eq!(response.headers()["Location"], "/dashboard");
    }
}
