use crate::Db;
use crate::rocket;
use crate::Result;
use hex::encode;

use rocket::serde::uuid::Uuid;

use rocket::serde::json::Json;

use rocket::http::Status;
use rocket::serde::{Deserialize, Serialize};
use rocket_db_pools::sqlx::{self};
use rocket_db_pools::Connection;
use sha2::{Digest, Sha256};

use rocket::response::status::Custom;

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
    pub fn new(user_id: String, secret_key: &[u8]) -> Result<Self> {
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
    mut db: Connection<Db>,
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
    mut db: Connection<Db>,
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
    .fetch_one(&mut **db)
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

pub async fn add_auth_token(
    token: String,
    type_: String,
    account_id: Uuid,
    mut db: Connection<Db>,
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
    .fetch_one(&mut **db)
    .await
    .and_then(|r| Ok(r))
    .or_else(|e| {
        println!("Database query error: {}", e);
        Err("nooo".to_string())
    });

    match result {
        Ok((_, id)) => Ok(AuthTokenInserted {
            token_id: id,
            token,
        }),
        Err(_) => Err(AuthError::InvalidToken),
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
            account_id,
            type
        FROM auth_token
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
        Ok((id, type_)) => Ok(AuthEntity {
            id,
            type_,
        }),
        Err(_) => Err(AuthError::InvalidToken),
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AddAccountRequest {
    pub email: String,
    pub hashed_password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddAccountResponse {
    pub is_added: bool,
    pub account_id: Option<Uuid>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AddAuthTokenRequest {
    pub type_: String,
    pub account_id: Uuid,
    pub title: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddAuthTokenResponse {
    pub is_added: bool,
    pub token: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CheckAuthTokenRequest {
    pub type_: String,
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CheckAuthTokenResponse {
    pub successful: bool,
    pub type_: String,
    pub account_id: Option<Uuid>,
}

#[post("/", data = "<request>")]
pub async fn internal_auth_add_account(
    request: Json<AddAccountRequest>,
    mut db: Connection<Db>,
) -> Result<Custom<Json<AddAccountResponse>>> {
    let add_account = add_account(
        request.email.clone(),
        request.hashed_password.clone(),
        db,
    )
    .await;

    let response = match add_account {
        Ok(account_inserted) => AddAccountResponse {
            is_added: true,
            account_id: Some(account_inserted.account_id),
        },
        Err(_) => AddAccountResponse {
            is_added: false,
            account_id: None,
        },
    };

    Ok(Custom(Status::Ok, Json(response)))
}

#[post("/", data = "<request>")]
pub async fn internal_auth_add_token(
    request: Json<AddAuthTokenRequest>,
    mut db: Connection<Db>,
) -> Result<Custom<Json<AddAuthTokenResponse>>> {
    let secret_key = rand::thread_rng().gen::<[u8; 32]>();
    let account_id = encode(request.account_id);
    let secure_token = Token::new(account_id.clone(), &secret_key)?;

    let add_token = add_auth_token(
        secure_token.token.clone(),
        request.type_.clone(),
        request.account_id,
        db,
    )
    .await;

    let response = match add_token {
        Ok(token_inserted) => AddAuthTokenResponse {
            is_added: true,
            token: Some(token_inserted.token),
        },
        Err(_) => AddAuthTokenResponse {
            is_added: false,
            token: None,
        },
    };

    Ok(Custom(Status::Ok, Json(response)))
}

#[post("/", data = "<request>")]
pub async fn internal_auth_check_token(
    request: Json<CheckAuthTokenRequest>,
    mut db: Connection<Db>,
) -> Result<Custom<Json<CheckAuthTokenResponse>>> {
    let check = check_token_within_type(request.token.clone(), request.type_.clone(), db).await;

    let response = match check {
        Ok(auth_entity) => CheckAuthTokenResponse {
            successful: true,
            account_id: Some(auth_entity.id),
            type_: auth_entity.type_,
        },
        Err(_) => CheckAuthTokenResponse {
            successful: false,
            account_id: None,
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

    fn add_auth_token(request: AddAuthTokenRequest, client: &Client) -> AddAuthTokenResponse {
        let request_str = serde_json::to_string(&request).unwrap();

        let response = client
            .post("/api-internal/add-token")
            .body(request_str)
            .dispatch();

        assert_eq!(response.status(), Status::Ok);
        let response_str = response.into_string().unwrap();
        let topic_response: AddAuthTokenResponse = serde_json::from_str(&response_str).unwrap();
        topic_response
    }

    fn check_auth_token(request: CheckAuthTokenRequest, client: &Client) -> CheckAuthTokenResponse {
        let test_token_request_str = serde_json::to_string(&request).unwrap();

        let response = client
            .post("/api-internal/check-token")
            .body(test_token_request_str)
            .dispatch();

        assert_eq!(response.status(), Status::Ok);
        let response_str = response.into_string().unwrap();
        let token_response: CheckAuthTokenResponse = serde_json::from_str(&response_str).unwrap();
        token_response
    }

    fn add_account(request: AddAccountRequest, client: &Client) -> AddAccountResponse {
        let add_account_request_str = serde_json::to_string(&request).unwrap();

        let response = client
            .post("/api-internal/add-account")
            .body(add_account_request_str)
            .dispatch();

        assert_eq!(response.status(), Status::Ok);
        let response_str = response.into_string().unwrap();
        let account_response: AddAccountResponse = serde_json::from_str(&response_str).unwrap();
        assert_eq!(account_response.is_added, true);
        account_response
    }

    fn add_random_email_account(client: &Client) -> AddAccountResponse {
        let random_email = Uuid::new_v4();
        let add_account_request = AddAccountRequest {
            email: encode(random_email),
            hashed_password: "123".to_string(),
        };
        let account_response = add_account(add_account_request.clone(), &client);
        assert_eq!(account_response.is_added, true);
        account_response
    }

    #[rstest]
    fn test_add_account(client: Client) {
        add_random_email_account(&client);
    }

    #[rstest]
    fn test_check_auth_token_successful(client: Client) {
        let account = add_random_email_account(&client);
        let add_token_request = AddAuthTokenRequest {
            type_: "auth".to_string(),
            account_id: account.account_id.unwrap(),
            title: "hello".to_string(),
        };
        let token_response = add_auth_token(add_token_request.clone(), &client);
        assert_eq!(token_response.is_added, true);
        let check_token_request = CheckAuthTokenRequest {
            type_: add_token_request.type_.clone(),
            token: token_response.token.unwrap(),
        };

        let check_token_response = check_auth_token(check_token_request, &client);

        assert_eq!(check_token_response.successful, true);
        assert_eq!(check_token_response.account_id, Some(account.account_id.unwrap()));
    }

    #[rstest]
    fn test_check_auth_token_failed_on_wrong_token(client: Client) {
        let account = add_random_email_account(&client);
        let add_token_request = AddAuthTokenRequest {
            type_: "auth".to_string(),
            account_id: account.account_id.unwrap(),
            title: "hello".to_string(),
        };
        let token_response = add_auth_token(add_token_request.clone(), &client);
        assert_eq!(token_response.is_added, true);
        let check_token_request = CheckAuthTokenRequest {
            type_: add_token_request.type_.clone(),
            token: format!("{}_wrong_token", token_response.token.unwrap()),
        };

        let check_token_response = check_auth_token(check_token_request, &client);

        assert_eq!(check_token_response.successful, false);
        assert_eq!(check_token_response.account_id, None);
    }

    #[rstest]
    fn test_check_auth_token_failed_on_wrong_type(client: Client) {
        let account = add_random_email_account(&client);
        let add_token_request = AddAuthTokenRequest {
            type_: "auth".to_string(),
            account_id: account.account_id.unwrap(),
            title: "hello".to_string(),
        };
        let token_response = add_auth_token(add_token_request.clone(), &client);
        assert_eq!(token_response.is_added, true);
        let check_token_request = CheckAuthTokenRequest {
            type_: format!("{}_wrong_type", add_token_request.type_),
            token: token_response.token.unwrap(),
        };

        let check_token_response = check_auth_token(check_token_request, &client);

        assert_eq!(check_token_response.successful, false);
        assert_eq!(check_token_response.account_id, None);
    }
}
