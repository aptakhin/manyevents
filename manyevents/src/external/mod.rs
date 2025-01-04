pub mod web;

use crate::BufferRequestBody;
use axum::{http::StatusCode, Json};
use axum_extra::{
    headers::authorization::{Authorization, Bearer},
    TypedHeader,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SendEventResponse {
    ok: bool,
}

use crate::external::web::web_transform_event;

pub async fn web_send_event(
    // auth: TypedHeader<Authorization<Bearer>>,
    BufferRequestBody(body): BufferRequestBody,
) -> Result<Json<SendEventResponse>, StatusCode> {
    let body_str = std::str::from_utf8(&body).unwrap();
    let data: Value = serde_json::from_str(&body_str).unwrap();

    let result = web_transform_event(data);

    Ok(Json(SendEventResponse { ok: result.is_ok() }))
}
