#[macro_use]
use crate::Db;

#[macro_use]
use crate::rocket;
use crate::Result;
use hex::encode;

use rocket::serde::uuid::Uuid;

use rocket::serde::json::Json;

use rocket::http::{Status};
use rocket::serde::{Deserialize, Serialize};
use rocket_db_pools::sqlx::{self};
use rocket_db_pools::{Connection};
use rocket_dyn_templates::{context, Template};
use sha2::{Digest, Sha256};

use rocket::response::status::Custom;
use rocket::{route, Build, Request, Rocket, Route};

use hmac::{Hmac, Mac};
use rand::Rng;
use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use std::time::{SystemTime, UNIX_EPOCH};
// use anyhow::Result;

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
pub struct AuthTokenInserted {
    pub token_id: Uuid,
    pub token: String,
}

#[derive(Deserialize, Debug)]
pub enum AuthError {
    InvalidToken,
}

// Type alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug)]
pub struct Token {
    token: String,
}

impl Token {
    pub fn new(user_id: &str, secret_key: &[u8]) -> Result<Self> {
        let salt: [u8; 16] = rand::thread_rng().gen();
        let salt_hex = hex::encode(salt);

        // Get current timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("SystemTime error")
            .as_secs()
            .to_string();


        // Combine message parts
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

pub async fn auth_signin(signin_request: SigninRequest, mut db: Connection<Db>) -> Result<SigninResponse, String> {
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
    .fetch_one(&mut **db)
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
    println!(
        "Success: {}, ID: {}, Password: {}",
        is_inserted, account_id, db_hashed_password
    );

    if hashed_password != db_hashed_password {
        return Err("Passwords not matching!".to_string());
    }

    Ok(SigninResponse {
        is_inserted: is_inserted,
        account_id: account_id,
    })
}

pub async fn add_token_with_type(
    token: String,
    type_: String,
    target_id: Uuid,
    mut db: Connection<Db>,
) -> Result<AuthTokenInserted, AuthError> {
    let device_id = "device_id".to_string();
    let result: Result<(bool, Uuid), String> = sqlx::query_as(
        "
        INSERT INTO token
        (token, type, target_id, device_id)
        VALUES ($1, $2, $3, $4)
        RETURNING true, id
        ",
    )
    .bind(token.clone())
    .bind(type_.clone())
    .bind(target_id)
    .bind(device_id.clone())
    .fetch_one(&mut **db)
    .await
    .and_then(|r| Ok(r))
    .or_else(|e| {
        println!("Database query error: {}", e);
        Err("nooo".to_string())
    });

    match result {
        Ok((bb, id)) => Ok(AuthTokenInserted { token_id: id, token: token }),
        Err(_) => Err(AuthError::InvalidToken)
    }
}

pub async fn check_token_within_type(
    token: String,
    type_: String,
    mut db: Connection<Db>,
) -> Result<AuthEntity, AuthError> {
    let result: Result<(Uuid, String), String> = sqlx::query_as(
        "
        SELECT
            target_id,
            type
        FROM token
        WHERE
            token = $1 AND type = $2
        LIMIT 1
        ",
    )
    .bind(token)
    .bind(type_)
    .fetch_one(&mut **db)
    .await
    .and_then(|r| Ok(r))
    .or_else(|e| {
        println!("Database query error: {}", e);
        Err("nooo".to_string())
    });

    match result {
        Ok((id, type_)) => Ok(AuthEntity { id: id, type_: type_ }),
        Err(_) => Err(AuthError::InvalidToken)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddTokenRequest {
    pub type_: String,
    pub target_id: Uuid,
    pub title: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddTokenResponse {
    pub is_added: bool,
    pub token: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CheckTokenRequest {
    pub type_: String,
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CheckTokenResponse {
    pub successful: bool,
    pub type_: String,
    pub target_id: Option<Uuid>,
}

#[post("/", data = "<request>")]
pub async fn internal_auth_add_token(
    request: Json<AddTokenRequest>,
    mut db: Connection<Db>,
) -> Result<Custom<Json<AddTokenResponse>>> {

    let secret_key = rand::thread_rng().gen::<[u8; 32]>();
    let user_id = "user123";
    // Generate secure token
    let secure_token = Token::new(user_id, &secret_key)?;
    println!("Secure token: {}", secure_token.token);

    let add_token = add_token_with_type(
        secure_token.token.clone(),
        request.type_.clone(),
        request.target_id,
        db,
    ).await;
    // println!("XX {:?}/{}", add_token, secure_token.token.clone());

    let response = match add_token {
        Ok(token_inserted) => AddTokenResponse {
            is_added: true,
            token: Some(token_inserted.token),
        },
        Err(_) => AddTokenResponse {
            is_added: false,
            token: None,
        },
    };

    Ok(Custom(Status::Ok, Json(response)))
}

#[post("/", data = "<request>")]
pub async fn internal_auth_check_token(
    request: Json<CheckTokenRequest>,
    mut db: Connection<Db>,
) -> Result<Custom<Json<CheckTokenResponse>>> {

    let check = check_token_within_type(
        request.token.clone(),
        request.type_.clone(),
        db,
    ).await;

    let response = match check {
        Ok(auth_entity) => CheckTokenResponse {
            successful: true,
            target_id: Some(auth_entity.id),
            type_: auth_entity.type_,
        },
        Err(_) => CheckTokenResponse {
            successful: false,
            target_id: None,
            type_: "".to_string(),
        },
    };
    Ok(Custom(Status::Ok, Json(response)))
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

    fn add_token(request: AddTokenRequest, client: &Client) -> AddTokenResponse {
        let request_str = serde_json::to_string(&request).unwrap();

        let response = client
            .post("/api-internal/add-token")
            .body(request_str)
            .dispatch();

        assert_eq!(response.status(), Status::Ok);
        let response_str = response.into_string().unwrap();
        let topic_response: AddTokenResponse = serde_json::from_str(&response_str).unwrap();
        topic_response
    }

    fn check_token(request: CheckTokenRequest, client: &Client) -> CheckTokenResponse {
        let test_token_request_str = serde_json::to_string(&request).unwrap();

        let response = client
            .post("/api-internal/check-token")
            .body(test_token_request_str)
            .dispatch();

        assert_eq!(response.status(), Status::Ok);
        let response_str = response.into_string().unwrap();
        let token_response: CheckTokenResponse = serde_json::from_str(&response_str).unwrap();
        token_response
    }

    #[rstest]
    fn test_check_token(client: Client) {
        let account_id = Uuid::new_v4();

        let add_token_request = AddTokenRequest {
            type_: "auth".to_string(),
            target_id: account_id,
            title: "hello".to_string(),
        };
        let token_response = add_token(add_token_request, &client);
        assert_eq!(token_response.is_added, true);

        let check_token_request = CheckTokenRequest {
            type_: "auth".to_string(),
            token: token_response.token.unwrap(),
        };
        let check_token_response = check_token(check_token_request, &client);

        assert_eq!(check_token_response.successful, true);
        assert_eq!(check_token_response.target_id, Some(account_id));
    }
}
