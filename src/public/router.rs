use std::time::Duration;

use axum::routing::get;
use axum::Router;
use sqlx::PgPool;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use super::handler;

// async fn add_request_id(req: Request<Body>) -> ApiResult<Request<Body>> {
//     req.set_context(Uuid::new_v4());
//     Ok(req)
// }

// async fn logger(
//     res: Response<Body>,
//     req_info: RequestInfo,
// ) -> ApiResult<Response<Body>> {
//     let request_id = req_info
//         .context::<Uuid>()
//         .ok_or_else(|| ApiError::BadRequest("Unable to get request id".into()))?;
//     log::info!(
//         "[request-id:{}] {} {} {}",
//         request_id,
//         res.status().as_u16(),
//         req_info.method(),
//         req_info.uri().path()
//     );
//     Ok(res)
// }

// async fn set_request_id_header(
//     mut res: Response<Body>,
//     req_info: RequestInfo,
// ) -> ApiResult<Response<Body>> {
//     let request_id = req_info
//         .context::<Uuid>()
//         .ok_or_else(|| ApiError::BadRequest("Unable to get request id".into()))
//         .map(|c| c.to_string())?;
//     let value = HeaderValue::from_str(request_id.as_str()).unwrap();
//     res.headers_mut().append("x-request-id", value);
//     Ok(res)
// }

pub fn create_router(
    db: PgPool,
) -> anyhow::Result<Router> {

    let router = Router::new()
        .route("/", get(handler::index))
        .fallback(handler::not_found)
        .with_state(db)
        .layer((
          TraceLayer::new_for_http(),

          // Graceful shutdown will wait for outstanding requests to complete.
          // Added a timeout to ensure requests are not waiting indefinitely.
          TimeoutLayer::new(Duration::from_secs(10)),
        ));

    Ok(router)
}
