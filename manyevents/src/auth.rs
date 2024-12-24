use crate::DbPool;
use hex::encode;

use uuid::Uuid;

use serde::Deserialize;
use sha2::{Digest, Sha256};

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

#[derive(Deserialize, Debug)]
pub struct SigninRequest {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize, Debug)]
pub struct SigninResponse {
    pub is_inserted: bool,
    pub account_id: Uuid,
}

#[derive(Deserialize, Debug)]
pub struct AuthEntity {
    pub id: Uuid,
    pub type_: String,
}

#[derive(Deserialize, Debug)]
pub struct AccountInserted {
    pub is_inserted: bool,
    pub account_id: Uuid,
}

#[derive(Deserialize, Debug, Clone)]
pub struct AuthTokenInserted {
    pub token_id: Uuid,
    pub token: String,
}

#[derive(Deserialize, Debug, Clone)]
pub enum AuthError {
    InvalidToken,
}

#[derive(Debug)]
pub struct Token {
    token: String,
}

impl Token {
    pub fn new(user_id: String, secret_key: &[u8]) -> Result<Self, String> {
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

        let mut check_token = "".to_string();
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
        let resp = check_token_within_type(check_token, "auth".to_string(), &pool).await;

        match resp {
            Ok(auth) => Ok(Authentificated(auth.id)),
            Err(_) => Err(StatusCode::UNAUTHORIZED),
        }
    }
}

pub async fn ensure_header_authentification(
    header: TypedHeader<Authorization<Bearer>>,
    pool: &DbPool,
) -> Result<Authentificated, AuthError> {
    let header_token = header.0.token().to_string();
    let resp = check_token_within_type(header_token, "auth".to_string(), pool).await;
    match resp {
        Ok(auth) => Ok(Authentificated(auth.id)),
        Err(_) => Err(AuthError::InvalidToken),
    }
}

pub enum AccountActionOnTenant {
    CanLinkAccount,
}

pub async fn ensure_account_permissions_on_tenant(
    account_id: Uuid,
    tenant_id: Uuid,
    action: AccountActionOnTenant,
    pool: &DbPool,
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
    .fetch_one(&*pool)
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

fn hash_password(password: String) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"unique_per_instance_hash_offset");
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    encode(result)
}

pub async fn auth_signin(
    signin_request: SigninRequest,
    pool: &DbPool,
) -> Result<SigninResponse, String> {
    let hashed_password = hash_password(signin_request.password.clone());
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
    .bind(signin_request.email.clone())
    .bind(hashed_password.clone())
    .fetch_one(&*pool)
    .await
    .and_then(|r| Ok(r))
    .or_else(|e| {
        println!("Database query error: {}", e);
        Err("nooo".to_string())
    });

    if result.is_err() {
        return Err("Internal error".to_string());
    }

    let (is_inserted, account_id, db_hashed_password) = result.unwrap();
    if hashed_password != db_hashed_password {
        return Err("Passwords are not matching!".to_string());
    }

    Ok(SigninResponse {
        is_inserted,
        account_id,
    })
}

pub async fn check_token_within_type(
    token: String,
    type_: String,
    pool: &DbPool,
) -> Result<AuthEntity, AuthError> {
    let result: Result<(Uuid, String), String> = sqlx::query_as(
        "
        SELECT
            account_id,
            type
        FROM auth_token
        WHERE
            token = $1 AND type = $2
        LIMIT 1
        ",
    )
    .bind(token.clone())
    .bind(type_)
    .fetch_one(pool)
    .await
    .and_then(|r| Ok(r))
    .or_else(|e| {
        println!("Database query error: {}", e);
        Err("nooo".to_string())
    });

    match result {
        Ok((id, type_)) => Ok(AuthEntity { id, type_ }),
        Err(_) => Err(AuthError::InvalidToken),
    }
}

pub struct AccountRepository<'a> {
    pub pool: &'a DbPool,
}

impl<'a> AccountRepository<'a> {
    pub async fn add_account(&self, email: String, hashed_password: String) -> Result<Uuid, String> {
        let result: Result<(bool, Uuid), String> = sqlx::query_as(
            "
            INSERT INTO account
            (email, password)
            VALUES ($1, $2)
            RETURNING true, id
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

        match result {
            Ok((is_inserted, account_id)) => Ok(account_id),
            Err(_) => Err("cant_add".to_string())
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

    pub async fn add_account(&self, email: String, password: String) -> Result<Uuid, String> {
        let hashed_password = hash_password(password);
        self.repo.add_account(email, hashed_password).await
    }
}


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
            Err(_) => Err("cant_add".to_string())
        }
    }

    pub async fn check_token(&self, token: String) -> Result<Uuid, String> {
        let resp = check_token_within_type(token, "auth".to_string(), self.pool).await;
        match resp {
            Ok(entity) => Ok(entity.id),
            Err(_) => Err("invalid_token".to_string())
        }
    }
}

pub struct ApiAuth<'a> {
    pub account_id: Uuid,
    pub token: String,
    auth_repo: &'a ApiAuthRepository<'a>,
}

impl<'a> ApiAuth<'a> {
    pub async fn from(token: String, auth_repo: &'a ApiAuthRepository<'a>) -> Result<ApiAuth, String> {
        let check_resp = auth_repo.check_token(token.clone()).await;
        match check_resp {
            Ok(account_id) => Ok(ApiAuth{ account_id, token, auth_repo} ),
            Err(_) => Err("invalid_token".to_string())
        }
    }

    pub async fn create_new(account_id: Uuid, auth_repo: &'a ApiAuthRepository<'a>) -> Result<ApiAuth, String> {
        let token = ApiAuth::generate_token(account_id);
        let auth_result = auth_repo.add_token(token.clone(), account_id).await;
        match auth_result {
            Ok(account_id) => Ok(ApiAuth{ account_id, token, auth_repo} ),
            Err(_) => Err("invalid_token".to_string())
        }
    }

    pub fn generate_token(account_id: Uuid) -> String {
        let secret_key = rand::thread_rng().gen::<[u8; 32]>();
        let secure_token = Token::new(encode(account_id).clone(), &secret_key).expect("No token error");
        secure_token.token
    }
}

pub struct PushAuth {
    pub tenant_id: Uuid,
    pub environment_id: Uuid,
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::test::{add_random_email_account, pool};
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
        let api_auth_repository = ApiAuthRepository{ pool: &pool };
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
        let api_auth_repository = ApiAuthRepository{ pool: &pool };
        let account = add_random_email_account(&pool).await;
        let auth = ApiAuth::create_new(account, &api_auth_repository).await;

        let check_auth = ApiAuth::from("wrong_token".to_string(), &api_auth_repository).await;

        assert_eq!(check_auth.is_err(), true);
    }
}
