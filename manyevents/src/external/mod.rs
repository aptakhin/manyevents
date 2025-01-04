pub mod web;

use crate::BufferRequestBody;
use axum::extract::Request;
use axum::{extract::ConnectInfo, http::header::HeaderMap, http::StatusCode, Json};
use axum_extra::{
    headers::authorization::{Authorization, Bearer},
    TypedHeader,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::SocketAddr;
use tracing::info;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SendEventResponse {
    ok: bool,
}

use crate::external::web::web_transform_event;

async fn web_send_event_impl(
    data: Value,
    addr: SocketAddr,
) -> Result<Json<SendEventResponse>, StatusCode> {
    info!("qww {}", addr);

    let result = web_transform_event(data, addr);
    // TODO: save

    Ok(Json(SendEventResponse { ok: true }))
}

#[axum::debug_handler]
pub async fn web_send_event(
    // auth: TypedHeader<Authorization<Bearer>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(data): Json<Value>,
) -> Result<Json<SendEventResponse>, StatusCode> {
    let res = web_send_event_impl(data.clone(), addr.clone()).await;
    res
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::Router;
    use rstest::rstest;
    use serde_json::json;
    use tower::ServiceExt;
    use tracing_test::traced_test;

    use crate::test::app;
    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
    };

    #[rstest]
    #[tokio::test]
    #[traced_test]
    async fn test_web_event_impl() {
        // TODO: Fix somehow test with `ConnectInfo(addr): ConnectInfo<SocketAddr>`
        // Because I couldn't make oneshot `into_make_service_with_connect_info`
        // https://docs.rs/axum/latest/axum/struct.Router.html#method.into_make_service_with_connect_info
        // For now we use this approach with web_send_event_impl.
        let request = json!({
            "hostname": "localhost",
            "path": "/assets/test.html",
            "hash": "#hello",
            "queryArgs": [["params", ""]],
            "browser": "Mozilla/5.0",
            "protocol": "http:",
            "origin": "http://localhost:8000",
        });

        let result = web_send_event_impl(
            request,
            "127.0.0.1:8000".parse().expect("Parse addr failed"),
        ).await;

        assert!(result.is_ok());
    }
}
