use crate::DbPool;
use hex::encode;

use uuid::Uuid;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::scope::ScopeRepository;
use crate::settings::Settings;
use axum::{
    async_trait,
    extract::{FromRef, FromRequest, Request},
    http::StatusCode,
};
use axum_extra::extract::cookie::CookieJar;
use axum_extra::{
    headers::authorization::{Authorization, Bearer},
    TypedHeader,
};
use rand::Rng;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Deserialize, Debug, Clone)]
pub enum AuthError {
    InvalidToken,
}

#[derive(Debug)]
pub struct Token {
    token: String,
}

impl Token {
    pub fn new(user_id: String, _secret_key: &[u8]) -> Result<Self, String> {
        let salt: [u8; 16] = rand::thread_rng().gen();
        let salt_hex = hex::encode(salt);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("SystemTime error")
            .as_secs()
            .to_string();

        let message = format!("{}{}{}", user_id, timestamp, salt_hex);

        // Create HMAC
        // let mut mac = HmacSha256::new_from_slice(secret_key)?;
        // mac.update(message.as_bytes());

        // // Generate token
        // let result = mac.finalize();
        // let token = URL_SAFE.encode(result.into_bytes());

        Ok(Token {
            token: hash_password(message),
        })
    }
}

#[derive(Debug, Clone)]
pub struct Authentificated(pub Uuid);

#[async_trait]
impl<S> FromRequest<S> for Authentificated
where
    DbPool: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let headers = req.headers();

        let header_token = headers.get("Authorization");
        println!("header_token {:?}", header_token);

        let cookies = CookieJar::from_headers(headers);

        let cookie_token = cookies.get("_s");
        println!("Cook {:?}", cookie_token);
        if header_token.is_none() && cookie_token.is_none() {
            return Err(StatusCode::UNAUTHORIZED);
        }

        let mut check_token = String::new();
        if cookie_token.is_some() {
            check_token = cookie_token.unwrap().value().to_string();
            println!("Cook2 {:?}", check_token.clone());
        }

        if header_token.is_some() {
            check_token = header_token.unwrap().to_str().unwrap().to_string();
            println!("Cook1 {:?}", check_token.clone());
            if check_token.starts_with("Bearer ") {
                check_token = check_token.strip_prefix("Bearer ").unwrap().to_string();
            }
        }

        let pool = DbPool::from_ref(state);

        let api_auth_repository = ApiAuthRepository { pool: &pool };
        let resp = ApiAuth::from(check_token, &api_auth_repository).await;

        match resp {
            Ok(auth) => Ok(Authentificated(auth.account_id)),
            Err(_) => Err(StatusCode::UNAUTHORIZED),
        }
    }
}

pub async fn ensure_header_authentification(
    header: TypedHeader<Authorization<Bearer>>,
    pool: &DbPool,
) -> Result<Authentificated, AuthError> {
    let header_token = header.0.token().to_string();
    let api_auth_repository = ApiAuthRepository { pool: pool };
    let resp = ApiAuth::from(header_token, &api_auth_repository).await;
    match resp {
        Ok(auth) => Ok(Authentificated(auth.account_id)),
        Err(_) => Err(AuthError::InvalidToken),
    }
}

#[derive(Debug, Clone)]
pub struct PushApiInfo {
    pub environment_id: Uuid,
}

pub async fn ensure_push_header_authentification(
    header: TypedHeader<Authorization<Bearer>>,
    pool: &DbPool,
) -> Result<PushApiInfo, AuthError> {
    let header_token = header.0.token().to_string();
    let push_api_repository = PushApiAuthRepository { pool: pool };
    let resp = PushApiAuth::from(header_token, &push_api_repository).await;
    match resp {
        Ok(auth) => Ok(PushApiInfo {
            environment_id: auth.environment_id,
        }),
        Err(_) => Err(AuthError::InvalidToken),
    }
}

pub enum AccountActionOnTenant {
    CanLinkAccount,
}

fn hash_password(password: String) -> String {
    let mut hasher = Sha256::new();
    hasher.update(Settings::read_settings().get_binary_secret_key());
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    encode(result)
}

pub struct AccountRepository<'a> {
    pub pool: &'a DbPool,
}

impl<'a> AccountRepository<'a> {
    pub async fn signin(&self, email: String, hashed_password: String) -> Result<Uuid, String> {
        let result: Result<(bool, Uuid, String), String> = sqlx::query_as(
            "
            WITH ins AS (
                INSERT INTO account (email, password)
                VALUES ($1, $2)
                ON CONFLICT (email) DO NOTHING
                RETURNING id, password
            )
            SELECT true AS is_inserted, id AS account_id, password FROM ins
            UNION ALL
            SELECT false AS is_inserted, id AS account_id, password FROM account WHERE email = $1
            LIMIT 1
            ",
        )
        .bind(email.clone())
        .bind(hashed_password.clone())
        .fetch_one(self.pool)
        .await
        .and_then(|r| Ok(r))
        .or_else(|e| {
            println!("Database query error: {}", e);
            Err("nooo".to_string())
        });

        if result.is_err() {
            return Err("Internal error".to_string());
        }

        let (_is_inserted, account_id, db_hashed_password) = result.unwrap();
        if hashed_password != db_hashed_password {
            return Err("Passwords are not matching!".to_string());
        }

        Ok(account_id)
    }

    pub async fn ensure_permissions_on_tenant(
        &self,
        account_id: Uuid,
        tenant_id: Uuid,
        _action: AccountActionOnTenant,
    ) -> Result<(), ()> {
        let result: Result<(Uuid, Uuid, Uuid), String> = sqlx::query_as(
            "
            SELECT id, account_id, tenant_id FROM tenant_and_account
            WHERE
                account_id = $1 AND tenant_id = $2
            ",
        )
        .bind(account_id.clone())
        .bind(tenant_id.clone())
        .fetch_one(self.pool)
        .await
        .and_then(|r| Ok(r))
        .or_else(|e| {
            println!("Database query error: {}", e);
            Err("nooo".to_string())
        });

        if result.is_ok() {
            return Ok(());
        } else {
            return Err(());
        }
    }
}

pub struct Account<'a> {
    repo: &'a AccountRepository<'a>,
}

impl<'a> Account<'a> {
    pub fn new(repo: &'a AccountRepository<'a>) -> Account {
        Account { repo }
    }

    pub async fn signin(&self, email: String, password: String) -> Result<Uuid, String> {
        let hashed_password = hash_password(password);
        self.repo.signin(email, hashed_password).await
    }

    pub async fn ensure_permissions_on_tenant(
        &self,
        account_id: Uuid,
        tenant_id: Uuid,
        action: AccountActionOnTenant,
    ) -> Result<(), ()> {
        self.repo
            .ensure_permissions_on_tenant(account_id, tenant_id, action)
            .await
    }
}

#[derive(Debug)]
pub struct ApiAuthRepository<'a> {
    pub pool: &'a DbPool,
}

impl<'a> ApiAuthRepository<'a> {
    pub async fn add_token(&self, token: String, account_id: Uuid) -> Result<Uuid, String> {
        let device_id = "device_id".to_string();
        let result: Result<(bool, Uuid), String> = sqlx::query_as(
            "
            INSERT INTO auth_token
            (token, type, account_id, device_id)
            VALUES ($1, $2, $3, $4)
            RETURNING true, id
            ",
        )
        .bind(token.clone())
        .bind("auth")
        .bind(account_id)
        .bind(device_id.clone())
        .fetch_one(self.pool)
        .await
        .and_then(|r| Ok(r))
        .or_else(|e| {
            println!("Database query error: {}", e);
            Err("nooo".to_string())
        });

        match result {
            Ok((_, id)) => Ok(id),
            Err(_) => Err("cant_add".to_string()),
        }
    }

    pub async fn check_token(&self, token: String) -> Result<Uuid, String> {
        let result: Result<(Uuid,), String> = sqlx::query_as(
            "
            SELECT
                account_id
            FROM auth_token
            WHERE
                token = $1 AND type = $2
            LIMIT 1
            ",
        )
        .bind(token.clone())
        .bind("auth")
        .fetch_one(self.pool)
        .await
        .and_then(|r| Ok(r))
        .or_else(|e| {
            println!("Database query error: {}", e);
            Err("nooo".to_string())
        });

        match result {
            Ok((id,)) => Ok(id),
            Err(_) => Err("invalid_token".to_string()),
        }
    }
}

#[derive(Debug)]
pub struct ApiAuth<'a> {
    pub account_id: Uuid,
    pub token: String,
    auth_repo: &'a ApiAuthRepository<'a>,
}

impl<'a> ApiAuth<'a> {
    pub async fn from(
        token: String,
        auth_repo: &'a ApiAuthRepository<'a>,
    ) -> Result<ApiAuth, String> {
        let check_resp = auth_repo.check_token(token.clone()).await;
        match check_resp {
            Ok(account_id) => Ok(ApiAuth {
                account_id,
                token,
                auth_repo,
            }),
            Err(_) => Err("invalid_token".to_string()),
        }
    }

    pub async fn create_new(
        account_id: Uuid,
        auth_repo: &'a ApiAuthRepository<'a>,
    ) -> Result<ApiAuth, String> {
        let token = ApiAuth::generate_token(account_id);
        let auth_result = auth_repo.add_token(token.clone(), account_id).await;
        match auth_result {
            Ok(account_id) => Ok(ApiAuth {
                account_id,
                token,
                auth_repo,
            }),
            Err(_) => Err("invalid_token".to_string()),
        }
    }

    pub fn generate_token(account_id: Uuid) -> String {
        let secret_key = rand::thread_rng().gen::<[u8; 32]>();
        let secure_token =
            Token::new(encode(account_id).clone(), &secret_key).expect("No token error");
        secure_token.token
    }
}

#[derive(Debug)]
pub struct PushApiAuthRepository<'a> {
    pub pool: &'a DbPool,
}

impl<'a> PushApiAuthRepository<'a> {
    pub async fn add_token(
        &self,
        token: String,
        environment_id: Uuid,
        by_account_id: Uuid,
    ) -> Result<Uuid, String> {
        let result: Result<(bool, Uuid), String> = sqlx::query_as(
            "
            INSERT INTO push_token
            (token, environment_id, created_by_account_id)
            VALUES ($1, $2, $3)
            RETURNING true, id
            ",
        )
        .bind(token.clone())
        .bind(environment_id)
        .bind(by_account_id)
        .fetch_one(self.pool)
        .await
        .and_then(|r| Ok(r))
        .or_else(|e| {
            println!("Database query error: {}", e);
            Err("nooo".to_string())
        });

        match result {
            Ok((_, id)) => Ok(id),
            Err(_) => Err("cant_add".to_string()),
        }
    }

    pub async fn check_token(&self, token: String) -> Result<(Uuid,), String> {
        let result: Result<(Uuid,), String> = sqlx::query_as(
            "
            SELECT
                environment_id
            FROM push_token
            WHERE
                token = $1
            LIMIT 1
            ",
        )
        .bind(token.clone())
        .fetch_one(self.pool)
        .await
        .and_then(|r| Ok(r))
        .or_else(|e| {
            println!("Database query error: {}", e);
            Err("nooo".to_string())
        });

        match result {
            Ok(environment_id) => Ok(environment_id),
            Err(_) => Err("invalid_token".to_string()),
        }
    }

    pub fn generate_token(environment_id: Uuid) -> String {
        let secret_key = rand::thread_rng().gen::<[u8; 32]>();
        let secure_token =
            Token::new(encode(environment_id).clone(), &secret_key).expect("No token error");
        format!("pt-{}", secure_token.token)
    }
}

#[derive(Debug)]
pub struct PushApiAuth<'a> {
    pub environment_id: Uuid,
    pub token: String,
    api_auth_repo: &'a PushApiAuthRepository<'a>,
}

impl<'a> PushApiAuth<'a> {
    pub async fn from(
        token: String,
        api_auth_repo: &'a PushApiAuthRepository<'a>,
    ) -> Result<PushApiAuth, String> {
        let check_resp = api_auth_repo.check_token(token.clone()).await;
        match check_resp {
            Ok((environment_id,)) => Ok(PushApiAuth {
                environment_id,
                token,
                api_auth_repo,
            }),
            Err(_) => Err("invalid_token".to_string()),
        }
    }

    pub async fn create_new(
        environment_id: Uuid,
        api_auth_repo: &'a PushApiAuthRepository<'a>,
        by_account_id: Uuid,
    ) -> Result<PushApiAuth, String> {
        let token = PushApiAuthRepository::generate_token(environment_id);
        let auth_result = api_auth_repo
            .add_token(token.clone(), environment_id, by_account_id)
            .await;
        if auth_result.is_err() {
            return Err("invalid_token".to_string());
        }
        Ok(PushApiAuth {
            environment_id,
            token,
            api_auth_repo,
        })
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::test::{add_random_email_account, app, create_tenant, pool};
    use axum::Router;
    use rstest::rstest;

    #[rstest]
    #[tokio::test]
    async fn test_add_account(#[future] pool: DbPool) {
        let pool = pool.await;

        let account_inserted = add_random_email_account(&pool).await;

        assert!(account_inserted != Uuid::nil());
    }

    #[rstest]
    #[tokio::test]
    async fn test_auth_token_successful(#[future] pool: DbPool) {
        let pool = pool.await;
        let api_auth_repository = ApiAuthRepository { pool: &pool };
        let account = add_random_email_account(&pool).await;
        let auth = ApiAuth::create_new(account, &api_auth_repository).await;
        let token = auth.unwrap().token;
        assert!(!token.is_empty());

        let auth = ApiAuth::from(token, &api_auth_repository).await;

        assert!(auth.is_ok());
        assert_eq!(auth.unwrap().account_id, account);
    }

    #[rstest]
    #[tokio::test]
    async fn test_check_auth_token_failed_on_wrong_token(#[future] pool: DbPool) {
        let pool = pool.await;
        let api_auth_repository = ApiAuthRepository { pool: &pool };

        let check_auth = ApiAuth::from("wrong_token".to_string(), &api_auth_repository).await;

        assert_eq!(check_auth.is_err(), true);
    }

    #[rstest]
    #[tokio::test]
    async fn test_push_auth_token_successful(#[future] app: Router<()>, #[future] pool: DbPool) {
        let app = app.await;
        let pool = pool.await;
        let scope_repository = ScopeRepository { pool: &pool };
        let api_auth_repository = ApiAuthRepository { pool: &pool };
        let push_api_auth_repository = PushApiAuthRepository { pool: &pool };
        let account_id = add_random_email_account(&pool).await;
        let auth_token = ApiAuth::create_new(account_id, &api_auth_repository).await;
        let tenant_id =
            create_tenant("test-tenant".to_string(), auth_token.unwrap().token, &app).await;
        let tenant_id = tenant_id.id.unwrap();
        let storage_credential_id = scope_repository
            .create_storage_credential(
                tenant_id,
                "clickhouse".to_string(),
                "clickhouse://...".to_string(),
                account_id,
            )
            .await;
        let storage_credential_id = storage_credential_id.unwrap();
        let environment_id = scope_repository
            .create_environment(
                storage_credential_id,
                "testptile".to_string(),
                "testslug".to_string(),
                account_id,
            )
            .await;
        let environment_id = environment_id.unwrap();
        let auth =
            PushApiAuth::create_new(environment_id, &push_api_auth_repository, account_id).await;
        let token = auth.unwrap().token;
        assert!(!token.is_empty());

        let auth = PushApiAuth::from(token, &push_api_auth_repository).await;

        assert!(auth.is_ok());
        let auth_struct = auth.unwrap();
        assert_eq!(auth_struct.environment_id, environment_id);
    }
}
