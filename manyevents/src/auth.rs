use crate::DbPool;
use hex::encode;

use uuid::Uuid;

use serde::Deserialize;
use sha2::{Digest, Sha256};

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

#[derive(Deserialize, Debug)]
pub struct AuthTokenInserted {
    pub token_id: Uuid,
    pub token: String,
}

#[derive(Deserialize, Debug)]
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
        return Err("Passwords not matching!".to_string());
    }

    Ok(SigninResponse {
        is_inserted,
        account_id,
    })
}

pub async fn add_account(
    email: String,
    hashed_password: String,
    pool: &DbPool,
) -> Result<AccountInserted, AuthError> {
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
    .fetch_one(&*pool)
    .await
    .and_then(|r| Ok(r))
    .or_else(|e| {
        println!("Database query error: {}", e);
        Err("nooo".to_string())
    });

    match result {
        Ok((is_inserted, account_id)) => Ok(AccountInserted {
            is_inserted,
            account_id,
        }),
        Err(_) => Err(AuthError::InvalidToken),
    }
}

async fn repository_add_auth_token(
    token: String,
    type_: String,
    account_id: Uuid,
    pool: &DbPool,
) -> Result<AuthTokenInserted, AuthError> {
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
    .bind(type_.clone())
    .bind(account_id)
    .bind(device_id.clone())
    .fetch_one(&*pool)
    .await
    .and_then(|r| Ok(r))
    .or_else(|e| {
        println!("Database query error: {}", e);
        Err("nooo".to_string())
    });

    println!("Inserted {:?}/{}/{}", result, token.clone(), type_.clone());

    match result {
        Ok((_, id)) => Ok(AuthTokenInserted {
            token_id: id,
            token,
        }),
        Err(_) => Err(AuthError::InvalidToken),
    }
}

pub async fn add_auth_token(
    type_: String,
    account_id: Uuid,
    pool: &DbPool,
) -> Result<AuthTokenInserted, AuthError> {
    let secret_key = rand::thread_rng().gen::<[u8; 32]>();
    let secure_token = Token::new(encode(account_id).clone(), &secret_key).expect("No token error");

    repository_add_auth_token(secure_token.token.clone(), type_.clone(), account_id, pool).await
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

#[cfg(test)]
mod test {
    use super::*;

    use rstest::rstest;

    use crate::test::pool;

    async fn add_random_email_account(pool: &DbPool) -> AccountInserted {
        let random_email = Uuid::new_v4();
        let account_inserted = add_account(encode(random_email), "123".to_string(), pool).await;
        account_inserted.expect("Should be inserted")
    }

    #[rstest]
    #[tokio::test]
    async fn test_add_account(#[future] pool: DbPool) {
        let pool = pool.await;
        add_random_email_account(&pool).await;
    }

    #[rstest]
    #[tokio::test]
    async fn test_check_auth_token_successful(#[future] pool: DbPool) {
        let pool = pool.await;
        let account = add_random_email_account(&pool).await;
        let auth_token_type = "auth".to_string();
        let token_response =
            add_auth_token(auth_token_type.clone(), account.account_id, &pool).await;
        let token = token_response.unwrap().token;
        assert!(!token.is_empty());

        let check_token_response =
            check_token_within_type(token.clone(), auth_token_type.clone(), &pool).await;

        assert_eq!(check_token_response.unwrap().id, account.account_id);
    }

    #[rstest]
    #[tokio::test]
    async fn test_check_auth_token_failed_on_wrong_token(#[future] pool: DbPool) {
        let pool = pool.await;
        let account = add_random_email_account(&pool).await;
        let auth_token_type = "auth".to_string();
        let token_response =
            add_auth_token(auth_token_type.clone(), account.account_id, &pool).await;
        let token = token_response.unwrap().token;
        assert!(!token.is_empty());

        let check_token_response =
            check_token_within_type("wrong_token".to_string(), auth_token_type.clone(), &pool)
                .await;

        assert_eq!(check_token_response.is_err(), true);
    }

    #[rstest]
    #[tokio::test]
    async fn test_check_auth_token_failed_on_wrong_type(#[future] pool: DbPool) {
        let pool = pool.await;
        let account = add_random_email_account(&pool).await;
        let auth_token_type = "auth".to_string();
        let token_response =
            add_auth_token(auth_token_type.clone(), account.account_id, &pool).await;
        let token = token_response.unwrap().token;
        assert!(!token.is_empty());

        let check_token_response =
            check_token_within_type(token.clone(), "wrong_type".to_string(), &pool).await;

        assert_eq!(check_token_response.is_err(), true);
    }
}
