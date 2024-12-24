use crate::{DbPool};
use hex::encode;

use uuid::Uuid;


pub struct TenantRepository<'a> {
    pool: &'a DbPool,
}

impl<'a> TenantRepository<'a> {
    pub async fn new(pool: &'a DbPool) -> TenantRepository {
        TenantRepository{ pool }
    }

    pub async fn create(&self, title: String, by_account_id: Uuid) -> Result<Uuid, String> {
        // Create tenant itself
        let results: Result<(bool, Uuid), String> = sqlx::query_as(
            "
            INSERT INTO tenant (title, created_by_account_id)
                VALUES ($1, $2)
                RETURNING true, id
            ",
        )
        .bind(title)
        .bind(by_account_id)
        .fetch_one(self.pool)
        .await
        .and_then(|r| Ok(r))
        .or_else(|e| {
            println!("Database query error: {}", e);
            Err("Failed".to_string())
        });

        if results.is_err() {
            return Err("cant_add".to_string());
        }

        let result_id = results.unwrap().1;
        return Ok(result_id);

        // Create link with created account_id
        // let results_2 = sqlx::query(
        //     "
        //     INSERT INTO tenant_and_account (tenant_id, account_id)
        //         VALUES ($1, $2)
        //         RETURNING id
        //     ",
        // )
        // .bind(result_id)
        // .bind(by_account_id)
        // .fetch_all(self.pool)
        // .await
        // .and_then(|r| Ok(r))
        // .or_else(|e| {
        //     println!("Database query error: {}", e);
        //     Err(e)
        // });

        // Ok(result_id)

    }

    pub async fn link(&self, tenant_id: Uuid, account_id: Uuid) -> Result<Uuid, String> {
        // async fn link_tenant_account(
        //     auth: TypedHeader<Authorization<Bearer>>,
        //     State(pool): State<DbPool>,
        //     Json(link_tenant): Json<LinkTenantAccountRequest>,
        // ) -> Result<Json<LinkTenantAccountResponse>, StatusCode> {
        // let auth_response = ensure_header_authentification(auth, &pool).await;
        // if auth_response.is_err() {
        //     return Err(StatusCode::UNAUTHORIZED);
        // }

        // let action = AccountActionOnTenant::CanLinkAccount;
        // let account_repository = AccountRepository { pool: &pool };
        // let ensure_response = Account::new(&account_repository)
        //     .ensure_permissions_on_tenant(auth_response.unwrap().0, link_tenant.tenant_id, action)
        //     .await;

        // if ensure_response.is_err() {
        //     return Err(StatusCode::UNAUTHORIZED);
        // }

        let results: Result<Uuid, String> = sqlx::query_as(
            "
            INSERT INTO tenant_and_account (tenant_id, account_id)
                VALUES ($1, $2)
                RETURNING id
            ",
        )
        .bind(tenant_id.clone())
        .bind(account_id.clone())
        .fetch_one(self.pool)
        .await
        .and_then(|r: (Uuid,)| {
            Ok(r.0)
        })
        .or_else(|e| {
            println!("Database query error: {}", e);
            Err("no".to_string())
        });
        results



        // let results = match results {
        //     Ok(Some(res)) => res,
        //     Ok(None) => {
        //         return Ok(Json(LinkTenantAccountResponse {
        //             is_success: false,
        //             message_code: Some("nana".to_string()),
        //         }))
        //     }
        //     Err(_) => {
        //         return Ok(Json(LinkTenantAccountResponse {
        //             is_success: false,
        //             message_code: Some("nana".to_string()),
        //         }))
        //     }
        // };
        // let response = LinkTenantAccountResponse {
        //     is_success: true,
        //     message_code: None,
        // };
        // Ok(response)

    }

}

pub struct Tenant<'a> {
    repo: &'a TenantRepository<'a>,
}

impl<'a> Tenant<'a> {
    pub async fn new(repo: &'a TenantRepository<'a>) -> Tenant {
        Tenant{ repo }
    }

    pub async fn create(&self, title: String, by_account_id: Uuid) {

    }

    pub async fn link(&self, tenant_id: Uuid, account_id: Uuid) {

    }
}

// async fn create_tenant(
//     auth: TypedHeader<Authorization<Bearer>>,
//     // why I can't use? Authentificated(auth2): Authentificated,
//     State(pool): State<DbPool>,
//     Json(tenant): Json<CreateTenantRequest>,
// ) -> Result<Json<CreateTenantResponse>, StatusCode> {
//     let auth_response = ensure_header_authentification(auth, &pool).await;
//     if auth_response.is_err() {
//         return Err(StatusCode::UNAUTHORIZED);
//     }

//     // Create tenant itself
//     let results: Result<(bool, Uuid), String> = sqlx::query_as(
//         "
//         INSERT INTO tenant (title, created_by_account_id)
//             VALUES ($1, $2)
//             RETURNING true, id
//         ",
//     )
//     .bind(tenant.title.clone())
//     .bind(auth_response.clone().unwrap().0)
//     .fetch_one(&pool)
//     .await
//     .and_then(|r| Ok(r))
//     .or_else(|e| {
//         println!("Database query error: {}", e);
//         Err("Failed".to_string())
//     });

//     if results.is_err() {
//         return Ok(Json(CreateTenantResponse {
//             is_success: false,
//             id: None,
//         }));
//     }

//     let result_id = results.unwrap().1;

//     // Create link with created account_id
//     let results_2 = sqlx::query(
//         "
//         INSERT INTO tenant_and_account (tenant_id, account_id)
//             VALUES ($1, $2)
//             RETURNING id
//         ",
//     )
//     .bind(result_id)
//     .bind(auth_response.clone().unwrap().0)
//     .fetch_all(&pool)
//     .await
//     .and_then(|r| Ok(r))
//     .or_else(|e| {
//         println!("Database query error: {}", e);
//         Err(e)
//     });

//     let response = CreateTenantResponse {
//         is_success: true,
//         id: Some(result_id),
//     };
//     Ok(Json(response))
// }

// async fn link_tenant_account(
//     auth: TypedHeader<Authorization<Bearer>>,
//     State(pool): State<DbPool>,
//     Json(link_tenant): Json<LinkTenantAccountRequest>,
// ) -> Result<Json<LinkTenantAccountResponse>, StatusCode> {
//     let auth_response = ensure_header_authentification(auth, &pool).await;
//     if auth_response.is_err() {
//         return Err(StatusCode::UNAUTHORIZED);
//     }

//     let action = AccountActionOnTenant::CanLinkAccount;
//     let account_repository = AccountRepository { pool: &pool };
//     let ensure_response = Account::new(&account_repository)
//         .ensure_permissions_on_tenant(auth_response.unwrap().0, link_tenant.tenant_id, action)
//         .await;

//     if ensure_response.is_err() {
//         return Err(StatusCode::UNAUTHORIZED);
//     }

//     let results = sqlx::query(
//         "
//         INSERT INTO tenant_and_account (tenant_id, account_id)
//             VALUES ($1, $2)
//             RETURNING id
//         ",
//     )
//     .bind(link_tenant.tenant_id.clone())
//     .bind(link_tenant.account_id.clone())
//     .fetch_all(&pool)
//     .await
//     .and_then(|r| {
//         let processed_result: Vec<Uuid> = r
//             .iter()
//             .map(|row| row.get::<Uuid, _>(0))
//             .collect::<Vec<Uuid>>();
//         Ok(Some(processed_result))
//     })
//     .or_else(|e| {
//         println!("Database query error: {}", e);
//         Err(e)
//     });

//     let results = match results {
//         Ok(Some(res)) => res,
//         Ok(None) => {
//             return Ok(Json(LinkTenantAccountResponse {
//                 is_success: false,
//                 message_code: Some("nana".to_string()),
//             }))
//         }
//         Err(_) => {
//             return Ok(Json(LinkTenantAccountResponse {
//                 is_success: false,
//                 message_code: Some("nana".to_string()),
//             }))
//         }
//     };
//     let response = LinkTenantAccountResponse {
//         is_success: true,
//         message_code: None,
//     };
//     Ok(Json(response))
// }