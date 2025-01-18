pub mod client;
pub mod web;

use crate::{scope::Scope, DbPool};
use axum::extract::State;
use axum::{
    extract::ConnectInfo,
    http::header::{HeaderMap, HeaderValue},
    http::StatusCode,
    Json,
};
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
    headers: &HeaderMap,
    pool: &DbPool,
) -> Result<Json<SendEventResponse>, StatusCode> {
    let result = web_transform_event(data, addr);
    if result.is_err() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut result = result.unwrap();
    let default = HeaderValue::from_str("").unwrap();
    let mut header_token = headers
        .get("Authorization")
        .unwrap_or(&default)
        .to_str()
        .unwrap()
        .to_string();

    if header_token.starts_with("Bearer ") {
        header_token = header_token.strip_prefix("Bearer ").unwrap().to_string();
    }

    info!("headerpt {}; {:?}", header_token, result);
    result["base_timestamp"] = "2019-01-01 00:00:00".into(); // TODO: make time
    result["queryArgs"] = "no-array-support".into(); // TODO: temporal obj transf
    result["x-manyevents-name"] = "main".into();

    let scope = Scope { pool: &pool };
    let push_result = scope.push_event(result, header_token).await;
    if push_result.is_err() {
        return Err(StatusCode::BAD_REQUEST);
    }

    Ok(Json(SendEventResponse { ok: true }))
}

#[axum::debug_handler]
pub async fn web_send_event(
    // auth: TypedHeader<Authorization<Bearer>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    State(pool): State<DbPool>,
    Json(data): Json<Value>,
) -> Result<Json<SendEventResponse>, StatusCode> {
    web_send_event_impl(data.clone(), addr.clone(), &headers, &pool).await
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::test::{app, pool, tenant_and_push_creds, TenantPushCreds};
    use crate::{ApplyEventSchemaRequest, Router};
    use rstest::rstest;
    use serde_json::json;
    use tower::ServiceExt;
    use tracing_test::traced_test;

    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
    };

    #[rstest]
    #[tokio::test]
    #[traced_test]
    async fn test_web_event_impl(
        #[future] app: Router,
        #[future] tenant_and_push_creds: TenantPushCreds,
        #[future] pool: DbPool,
    ) {
        // TODO: Fix somehow test with `ConnectInfo(addr): ConnectInfo<SocketAddr>`
        // Because I couldn't make oneshot `into_make_service_with_connect_info`
        // https://docs.rs/axum/latest/axum/struct.Router.html#method.into_make_service_with_connect_info
        // For now we use this approach with web_send_event_impl.
        let app = app.await;
        let tenant_and_push_creds = tenant_and_push_creds.await;
        let req = ApplyEventSchemaRequest {
            tenant_id: tenant_and_push_creds.tenant_id,
            name: "main".to_string(),
            schema: json!({
                "type": "object",
                "properties": {
                    "base_timestamp": { "type": "integer", "x-manyevents-ch-type": "DateTime64(3)" },
                    "browser": { "type": "integer", "x-manyevents-ch-type": "String" },
                    "country": { "type": "string", "x-manyevents-ch-type": "String" },
                    "hash": { "type": "string", "x-manyevents-ch-type": "String" },
                    "hostname": { "type": "string", "x-manyevents-ch-type": "String" },
                    "origin": { "type": "string", "x-manyevents-ch-type": "String" },
                    "path": { "type": "string", "x-manyevents-ch-type": "String" },
                    "protocol": { "type": "string", "x-manyevents-ch-type": "String" },
                    "queryArgs": { "type": "string", "x-manyevents-ch-type": "String" },
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
                    .header(
                        "Authorization",
                        format!("Bearer {}", tenant_and_push_creds.api_token),
                    )
                    .uri("/manage-api/v0-unstable/apply-event-schema-sync")
                    .body(Body::from(request_str.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let request = json!({
            "hostname": "localhost",
            "path": "/assets/test.html",
            "hash": "#hello",
            "queryArgs": [["params", ""]],
            "browser": "Mozilla/5.0",
            "protocol": "http:",
            "origin": "http://localhost:8000",
        });
        let mut headers = HeaderMap::new();
        let bearer = format!("Bearer {}", tenant_and_push_creds.push_token);
        headers.insert("Authorization", HeaderValue::from_str(&bearer).unwrap());

        let result = web_send_event_impl(
            request,
            "127.0.0.1:8000".parse().expect("Parse addr failed"),
            &headers,
            &pool.await,
        )
        .await;

        assert!(result.is_ok());
    }
}
