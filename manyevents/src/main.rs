use axum::{
    async_trait,
    body::Bytes,
    extract::{Form, FromRequest, Request, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
    routing::post,
    Json, Router,
};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use axum_extra::{
    headers::authorization::{Authorization, Bearer},
    TypedHeader,
};

use http_body_util::BodyExt;
use minijinja::{context, path_loader, Environment};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
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
mod scope;
mod settings;
mod tenant;

use crate::auth::{
    ensure_header_authentification, Account, AccountActionOnTenant, AccountRepository, ApiAuth,
    ApiAuthRepository, Authentificated,
};
use crate::ch::{insert_smth, make_migration_plan, ChColumn, ClickHouseRepository};
use crate::schema::{read_event_data, EventJsonSchema, JsonSchemaProperty, SerializationType};
use crate::scope::ScopeRepository;
use crate::settings::Settings;
use crate::tenant::{Tenant, TenantRepository};

type DbPool = PgPool;

async fn make_db() -> DbPool {
    let db_connection_str = Settings::read_settings().postgres_dsn;
    println!("db_connection_str ={db_connection_str}");

    PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(3))
        .connect(&db_connection_str)
        .await
        .expect("Can't connect to the database")
}

fn internal_error<E>(err: E) -> (StatusCode, String)
where
    E: std::error::Error,
{
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct CreateAccountRequest {
    email: String,
    password: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct CreateAccountResponse {
    is_success: bool,
    auth_token: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct CreateTenantRequest {
    title: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct CreateTenantResponse {
    is_success: bool,
    id: Option<Uuid>,
    clickhouse_read_dsn: String,
    clickhouse_admin_dsn: String,
    push_token: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ApplyEventSchemaRequest {
    tenant_id: Uuid,
    name: String,
    schema: Value,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct LinkTenantAccountRequest {
    tenant_id: Uuid,
    account_id: Uuid,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct LinkTenantAccountResponse {
    is_success: bool,
    message_code: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct PushEventResponse {
    is_success: bool,
    message_code: Option<String>,
}

// #[derive(Debug, Serialize, Deserialize)]
// enum SerializationType {
//     Int(i64),
//     Float(f64),
//     Str(String),
// }

// #[derive(Debug, Serialize, Deserialize)]
// struct Column {
//     name: String,
//     value: SerializationType,
// }

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
    jar: CookieJar,
    State(pool): State<DbPool>,
    Form(signin_form): Form<Signin>,
) -> Result<(CookieJar, Redirect), Html<String>> {
    let account_repository = AccountRepository { pool: &pool };
    let signin_response = Account::new(&account_repository)
        .signin(signin_form.email, signin_form.password)
        .await;

    println!("Log1 {:?}", signin_response);

    if signin_response.is_err() {
        let mut env = Environment::new();
        env.set_loader(path_loader("static/templates"));
        let tmpl = env.get_template("signin.html.j2").unwrap();
        return Err(Html(tmpl.render(context!(name => "John")).unwrap()));
    }

    let api_auth_repository = ApiAuthRepository { pool: &pool };
    let auth_token = ApiAuth::create_new(signin_response.unwrap(), &api_auth_repository).await;

    println!("Log2 {:?}", auth_token);

    if auth_token.is_err() {
        // Internal error
        let mut env = Environment::new();
        env.set_loader(path_loader("static/templates"));
        let tmpl = env.get_template("signin.html.j2").unwrap();
        return Err(Html(tmpl.render(context!(name => "John")).unwrap()));
    }

    let token = auth_token.unwrap().token;

    Ok((
        jar.add(Cookie::new("_s".to_string(), token)),
        Redirect::to("/dashboard"),
    ))
}

async fn get_docs() -> HtmlOrRedirect {
    let mut env = Environment::new();
    env.set_loader(path_loader("static/templates"));
    let tmpl = env.get_template("docs.html.j2").unwrap();
    HtmlOrRedirect::Html(Html(tmpl.render(context!(name => "John")).unwrap()))
}

async fn get_dashboard(Authentificated(auth): Authentificated) -> HtmlOrRedirect {
    let check = auth.clone();

    let mut env = Environment::new();
    env.set_loader(path_loader("static/templates"));
    let tmpl = env.get_template("dashboard.html.j2").unwrap();
    HtmlOrRedirect::Html(Html(
        tmpl.render(context!(push_token_live => "me-push-live-xxxxxx22222", check))
            .unwrap(),
    ))
}

async fn create_account(
    State(pool): State<DbPool>,
    Json(account_request): Json<CreateAccountRequest>,
) -> Result<Json<CreateAccountResponse>, StatusCode> {
    let account_repository = AccountRepository { pool: &pool  };
    let api_auth_repository = ApiAuthRepository { pool: &pool };
    let account = Account::new(&account_repository);

    let account_inserted = account
        .signin(account_request.email, account_request.password)
        .await;
    if account_inserted.is_err() {
        return Ok(Json(CreateAccountResponse {
            is_success: false,
            auth_token: None,
        }));
    }

    let account_inserted = account_inserted.unwrap();
    let auth_token = ApiAuth::create_new(account_inserted, &api_auth_repository).await;
    let bearer = auth_token.unwrap().token;

    let response = CreateAccountResponse {
        is_success: true,
        auth_token: Some(bearer),
    };
    Ok(Json(response))
}

async fn create_tenant(
    auth: TypedHeader<Authorization<Bearer>>,
    // why I can't use? Authentificated(auth2): Authentificated,
    State(pool): State<DbPool>,
    Json(tenant_request): Json<CreateTenantRequest>,
) -> Result<Json<CreateTenantResponse>, StatusCode> {
    let auth_response = ensure_header_authentification(auth, &pool).await;
    if auth_response.is_err() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let by_account_id = auth_response.clone().unwrap().0;

    // TODO: wrap TenantRepository into the transaction
    let tenant_repository = TenantRepository::new(&pool);
    let tenant = Tenant::new(&tenant_repository);
    let created_tenant_resp = tenant
        .create(tenant_request.title, by_account_id.clone())
        .await;
    if created_tenant_resp.is_err() {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    let tenant_id = created_tenant_resp.clone().unwrap();
    let link_resp = tenant
        .link_account(tenant_id.clone(), by_account_id.clone())
        .await;
    if link_resp.is_err() {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    // let action = AccountActionOnTenant::CanLinkAccount;
    // let account_repository = AccountRepository { pool: &pool };
    // let ensure_response = Account::new(&account_repository)
    //     .ensure_permissions_on_tenant(by_account_id.clone(), req.tenant_id, action)
    //     .await;
    // if ensure_response.is_err() {
    //     return Err(StatusCode::UNAUTHORIZED);
    // }

    let unique_suffix = format!("{}", tenant_id.clone().as_simple());

    let repo = ClickHouseRepository::new("clickhouse://...".to_string());

    let cred = repo
        .create_credential(unique_suffix.clone(), "my_password".to_string())
        .await;

    println!("Unique_suffix {}", unique_suffix.clone());

    assert!(cred.is_ok());
    let cred = cred.unwrap();

    let scope = ScopeRepository::new(&pool);
    if !scope.has_tenant_storage_credential(tenant_id.clone()).await {
        let storage_credential_resp = scope
            .create_storage_credential(
                tenant_id.clone(),
                "clickhouse".to_string(),
                cred.to_dsn(),
                by_account_id.clone(),
            )
            .await;
        if storage_credential_resp.is_err() {
            println!("storage_credential_resp {:?}", storage_credential_resp);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    let response = CreateTenantResponse {
        is_success: true,
        id: Some(created_tenant_resp.clone().unwrap()),
        clickhouse_read_dsn: cred.to_dsn(),
        clickhouse_admin_dsn: String::new(),
        push_token: String::new(),
    };
    Ok(Json(response))
}

async fn link_tenant_account(
    auth: TypedHeader<Authorization<Bearer>>,
    State(pool): State<DbPool>,
    Json(link_tenant): Json<LinkTenantAccountRequest>,
) -> Result<Json<LinkTenantAccountResponse>, StatusCode> {
    let auth_response = ensure_header_authentification(auth, &pool).await;
    if auth_response.is_err() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let by_account_id = auth_response.clone().unwrap().0;

    let action = AccountActionOnTenant::CanLinkAccount;
    let account_repository = AccountRepository { pool: &pool };
    let ensure_response = Account::new(&account_repository)
        .ensure_permissions_on_tenant(by_account_id.clone(), link_tenant.tenant_id, action)
        .await;
    if ensure_response.is_err() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let tenant_repository = TenantRepository::new(&pool);
    let tenant = Tenant::new(&tenant_repository);
    let link_resp = tenant
        .link_account(link_tenant.tenant_id, by_account_id.clone())
        .await;
    if link_resp.is_err() {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    let response = LinkTenantAccountResponse {
        is_success: true,
        message_code: None,
    };
    Ok(Json(response))
}

async fn apply_entity_schema_sync(
    auth: TypedHeader<Authorization<Bearer>>,
    State(pool): State<DbPool>,
    Json(req): Json<ApplyEventSchemaRequest>,
) -> Result<String, StatusCode> {
    let auth_response = ensure_header_authentification(auth, &pool).await;
    if auth_response.is_err() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let by_account_id = auth_response.clone().unwrap().0;

    let action = AccountActionOnTenant::CanLinkAccount;
    let account_repository = AccountRepository { pool: &pool };
    let ensure_response = Account::new(&account_repository)
        .ensure_permissions_on_tenant(by_account_id.clone(), req.tenant_id, action)
        .await;
    if ensure_response.is_err() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let unique_suffix = format!("{}", req.tenant_id.clone().as_simple());

    let repo = ClickHouseRepository::new("clickhouse://...".to_string());

    let tenant_repo = ClickHouseRepository::choose_tenant(unique_suffix.clone());

    let empty = EventJsonSchema::new();
    let new: Result<EventJsonSchema, _> = serde_json::from_value(req.schema);
    if new.is_err() {
        println!("EventJsonSchema parser failed {:?}", new);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    let new = new.unwrap();

    let unique_table_name = req.name;

    let migration_plan = make_migration_plan(empty, new);
    let migration = tenant_repo
        .execute_init_migration(unique_table_name.clone(), migration_plan, true)
        .await;

    if migration.is_err() {
        println!("Migration {:?}", migration);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok("OK".to_string())
}

async fn push_event(BufferRequestBody(body): BufferRequestBody) -> Json<PushEventResponse> {
    let body_str = std::str::from_utf8(&body).unwrap();
    let data: Result<Value, _> = serde_json::from_str(&body_str);
    if data.is_err() {
        return Json(PushEventResponse {
            is_success: false,
            message_code: Some(data.unwrap_err().to_string()),
        });
    }
    let data = data.unwrap();
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

    let mut table_name = None;

    for unit in event.units.iter() {
        for value in unit.value.iter() {
            let column = ChColumn {
                name: if unit.name != "" {
                    format!("{}_{}", unit.name, value.name)
                } else {
                    value.name.clone()
                },
                value: value.value.clone(),
            };
            println!("ins: {}: {:?}", column.name.clone(), value.value.clone());
            if column.name == "x-manyevents-name" {
                if let SerializationType::Str(str) = value.value.clone() {
                    table_name = Some(str.clone());
                }
            } else {
                columns.push(column);
            }
        }
    }

    if table_name.is_none() {
        return Json(PushEventResponse {
            is_success: false,
            message_code: Some("event_name_is_not_given".to_string()),
        });
    }
    let res = insert_smth(table_name.unwrap().to_string(), columns).await;

    if res.is_err() {
        return Json(PushEventResponse {
            is_success: false,
            message_code: Some(format!("internal_error: {}", res.unwrap_err())),
        });
    }

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

    let result = sqlx::migrate!("db/migrations")
        .run(&pool)
        .await
        .expect("Migrations panic!");
    println!("Migration result {:?}", result);

    let router: Router<()> = Router::new()
        .route("/", get(get_root))
        .route("/signin", get(get_signin).post(post_signin))
        .route("/docs", get(get_docs))
        .route("/dashboard", get(get_dashboard))
        .route("/push-api/v0-unstable/push-event", post(push_event))
        .route("/manage-api/v0-unstable/signin", post(create_account))
        .route("/manage-api/v0-unstable/create-tenant", post(create_tenant))
        .route(
            "/manage-api/v0-unstable/link-tenant-account",
            post(link_tenant_account),
        )
        .route(
            "/manage-api/v0-unstable/apply-entity-schema-sync",
            post(apply_entity_schema_sync),
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
pub mod test {
    use super::*;
    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
    };
    use hex::encode;
    use rstest::{fixture, rstest};

    #[fixture]
    pub async fn app() -> Router<()> {
        routes_app().await
    }

    #[fixture]
    pub async fn pool() -> DbPool {
        make_db().await
    }

    pub async fn add_random_email_account(pool: &DbPool) -> Uuid {
        let random_email = Uuid::new_v4();
        let account_repository = AccountRepository { pool };
        let account = Account::new(&account_repository);

        let account_inserted = account
            .signin(encode(random_email), "123".to_string())
            .await;

        account_inserted.expect("Should be inserted")
    }

    async fn create_tenant(
        title: String,
        bearer: String,
        app: &Router<()>,
    ) -> CreateTenantResponse {
        let tenant_request = CreateTenantRequest { title: title };
        let tenant_request_str = serde_json::to_string(&tenant_request).unwrap();

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .header("Content-Type", "application/json")
                    .header("Authorization", format!("Bearer {}", bearer))
                    .uri("/manage-api/v0-unstable/create-tenant")
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
        assert!(!tenant_response.clickhouse_read_dsn.is_empty());
        tenant_response
    }

    async fn link_tenant_account(
        tenant_id: Uuid,
        account_id: Uuid,
        bearer: String,
        app: &Router<()>,
        pool: &DbPool,
    ) -> LinkTenantAccountResponse {
        let tenant_request = LinkTenantAccountRequest {
            tenant_id,
            account_id,
        };
        let tenant_request_str = serde_json::to_string(&tenant_request).unwrap();

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .header("Content-Type", "application/json")
                    .header("Authorization", format!("Bearer {}", bearer))
                    .uri("/manage-api/v0-unstable/link-tenant-account")
                    .body(Body::from(tenant_request_str))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body_str = std::str::from_utf8(&body).unwrap();
        let tenant_response: LinkTenantAccountResponse = serde_json::from_str(&body_str).unwrap();
        assert_eq!(tenant_response.is_success, true);
        tenant_response
    }

    #[rstest]
    #[tokio::test]
    async fn test_create_tenant_successful(#[future] app: Router<()>, #[future] pool: DbPool) {
        let pool = pool.await;
        let account = add_random_email_account(&pool).await;
        let api_auth_repository = ApiAuthRepository { pool: &pool };
        let auth_token = ApiAuth::create_new(account, &api_auth_repository).await;

        let tenant_response = create_tenant(
            "test-tenant".to_string(),
            auth_token.unwrap().token,
            &app.await,
        )
        .await;

        assert_eq!(tenant_response.is_success, true);
    }

    #[rstest]
    #[tokio::test]
    async fn test_create_account(#[future] app: Router<()>, #[future] pool: DbPool) {
        let pool = pool.await;
        let random_email = Uuid::new_v4();
        let account_request = CreateAccountRequest {
            email: encode(random_email),
            password: "123".to_string(),
        };
        let account_request_str = serde_json::to_string(&account_request).unwrap();

        let response = app
            .await
            .clone()
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .header("Content-Type", "application/json")
                    .uri("/manage-api/v0-unstable/signin")
                    .body(Body::from(account_request_str))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body_str = std::str::from_utf8(&body).unwrap();
        let account_response: CreateAccountResponse = serde_json::from_str(&body_str).unwrap();
        assert!(account_response.is_success);
        assert!(account_response.auth_token.is_some());
        assert!(!account_response.auth_token.unwrap().is_empty());
    }

    #[rstest]
    #[tokio::test]
    async fn test_create_tenant_401_bad_token(#[future] app: Router<()>, #[future] pool: DbPool) {
        let pool = pool.await;

        let tenant_request = CreateTenantRequest {
            title: "test-title".to_string(),
        };
        let tenant_request_str = serde_json::to_string(&tenant_request).unwrap();

        let bearer = "invalid-token".to_string();

        let response = app
            .await
            .clone()
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .header("Content-Type", "application/json")
                    .header("Authorization", format!("Bearer {}", bearer))
                    .uri("/manage-api/v0-unstable/create-tenant")
                    .body(Body::from(tenant_request_str))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[rstest]
    #[tokio::test]
    async fn test_link_tenant_account_successful(
        #[future] app: Router<()>,
        #[future] pool: DbPool,
    ) {
        let pool = pool.await;
        let app = app.await;
        let account = add_random_email_account(&pool).await;
        let api_auth_repository = ApiAuthRepository { pool: &pool };
        let auth_token = ApiAuth::create_new(account, &api_auth_repository)
            .await
            .unwrap()
            .token;
        let tenant = create_tenant("test-tenant".to_string(), auth_token.clone(), &app).await;

        let link_response = link_tenant_account(
            tenant.id.expect("Should be a tenant!"),
            account,
            auth_token,
            &app,
            &pool,
        )
        .await;

        assert_eq!(link_response.is_success, true);
    }

    #[rstest]
    #[tokio::test]
    async fn test_link_tenant_401_bad_token(#[future] app: Router<()>, #[future] pool: DbPool) {
        let pool = pool.await;

        let bearer = "invalid-token".to_string();

        let tenant_request = LinkTenantAccountRequest {
            tenant_id: Uuid::nil(),
            account_id: Uuid::nil(),
        };
        let tenant_request_str = serde_json::to_string(&tenant_request).unwrap();

        let response = app
            .await
            .clone()
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .header("Content-Type", "application/json")
                    .header("Authorization", format!("Bearer {}", bearer))
                    .uri("/manage-api/v0-unstable/link-tenant-account")
                    .body(Body::from(tenant_request_str))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[rstest]
    #[tokio::test]
    async fn test_link_tenant_401_wrong_tenant(#[future] app: Router<()>, #[future] pool: DbPool) {
        // Create account1 and tenant1, but attempt to give access from the user unrelated to tenant
        let app = app.await;
        let pool = pool.await;
        let api_auth_repository = ApiAuthRepository { pool: &pool };
        let account_1 = add_random_email_account(&pool).await;
        let auth_token_1 = ApiAuth::create_new(account_1, &api_auth_repository).await;
        let tenant_1 =
            create_tenant("test-tenant".to_string(), auth_token_1.unwrap().token, &app).await;
        let account_2 = add_random_email_account(&pool).await;
        let auth_token_2 = ApiAuth::create_new(account_2, &api_auth_repository).await;
        let bearer_2 = auth_token_2.unwrap().token;
        let tenant_request = LinkTenantAccountRequest {
            tenant_id: tenant_1.id.expect("Should be a tenant!"),
            account_id: account_2,
        };
        let tenant_request_str = serde_json::to_string(&tenant_request).unwrap();

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .header("Content-Type", "application/json")
                    .header("Authorization", format!("Bearer {}", bearer_2))
                    .uri("/manage-api/v0-unstable/link-tenant-account")
                    .body(Body::from(tenant_request_str))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[rstest]
    #[tokio::test]
    async fn test_push_event(#[future] app: Router<()>) {
        let push_request_str = r#"{
            "x-manyevents-name": "chrs_async_insert",
            "span_id": "xxxx",
            "span_start_time": 1234567890,
            "span_end_time": 1234567892,
            "base_timestamp": 1234567892,
            "base_parent_span_id": "xxxx",
            "base_message": "test message"
        }
        "#;

        let response = app
            .await
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .header("Content-Type", "application/json")
                    .uri("/push-api/v0-unstable/push-event")
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
                    .uri("/push-api/v0-unstable/push-event")
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

    #[rstest]
    #[tokio::test]
    async fn test_make_magic(#[future] app: Router<()>, #[future] pool: DbPool) {
        let app = app.await;
        let pool = pool.await;
        let api_auth_repository = ApiAuthRepository { pool: &pool };
        let account = add_random_email_account(&pool).await;
        let auth_token = ApiAuth::create_new(account, &api_auth_repository).await;
        let bearer = auth_token.unwrap().token;
        let tenant = create_tenant("test-tenant".to_string(), bearer.clone(), &app).await;

        let req = ApplyEventSchemaRequest {
            tenant_id: tenant.id.unwrap(),
            name: "main".to_string(),
            schema: json!({
                "type": "object",
                "properties": {
                    "base_timestamp": { "type": "integer", "x-manyevents-ch-type": "DateTime64(3)" },
                    "base_name": { "type": "string", "x-manyevents-ch-type": "String" },
                    "base_age": { "type": "integer", "x-manyevents-ch-type": "Int32" },
                    "base_big_age": { "type": "integer", "x-manyevents-ch-type": "Int64" },
                },
                "x-manyevents-ch-order-by": "base_timestamp",
                "x-manyevents-ch-partition-by-func": "toYYYYMMDD",
                "x-manyevents-ch-partition-by": "base_timestamp",
            }),
        };
        let request_str = serde_json::to_string(&req).unwrap();

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .header("Content-Type", "application/json")
                    .header("Authorization", format!("Bearer {}", bearer))
                    .uri("/manage-api/v0-unstable/apply-entity-schema-sync")
                    .body(Body::from(request_str.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .header("Content-Type", "application/json")
                    .header("Authorization", format!("Bearer {}", bearer))
                    .uri("/manage-api/v0-unstable/apply-entity-schema-sync")
                    .body(Body::from(request_str.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
