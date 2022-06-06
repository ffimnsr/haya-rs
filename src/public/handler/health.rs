use std::time::Instant;

/// Health Checklist:
/// o Downstream Operation Status
///   - Your API may depend on other APIs to operate. Make sure to check the
///     operational status of the downstream APIs you depend on.
/// o Database connection
///   - Your API may have an open connection to a data source. Make sure the
///     connection is available at the time of the health check.
/// o Database response time
///   - Measure the average response time to a typical DB query.
/// o Memory consumption
///   - Spike in memory usage can be because of memory leaks and can interrupt
///     the service.
/// o In-flight messages
///   - Does your API works with message queues? Too many in-flight messages
///     can be a sign of an underlying issue.
use crate::error::{ApiError, ApiResult, GenericResult};
use crate::{HeaderValues, MimeValues, DbContext};
use hyper::{Body, Request, Response, StatusCode};
use mongodb::bson::doc;
use routerify::prelude::*;
use sys_info::mem_info;

/// The readiness endpoint, returns the readiness state to accept incoming
/// requests from the gateway or the upstream proxy. Readiness signals that the
/// app is running normally but isn’t ready to receive requests just yet.
pub(crate) async fn handler_health_ready(
    req: Request<Body>,
) -> ApiResult<Response<Body>> {
    let db_elapsed = Instant::now();
    let db_status = if check_database(req).await.is_err() {
        "DOWN"
    } else {
        "UP"
    };
    let db_elapsed = db_elapsed.elapsed().as_nanos().to_string();

    let data = serde_json::json!({
        "success": true,
        "data": {
            "status": "READY",
            "checks": [
                {
                    "name": "database-ready",
                    "status": db_status,
                    "metric": {
                        "response_time_ns": db_elapsed,
                    },
                },
            ],
        },
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(HeaderValues::CACHE_CONTROL, "no-cache")
        .header(HeaderValues::CONTENT_TYPE, MimeValues::JSON_MIME_TYPE)
        .body(Body::from(data.to_string()))
        .map_err(ApiError::Http)
}

/// The liveness endpoint, returns the liveness of a microservice. If the check
/// does not return the expected response, it means that the process is
/// unhealthy or dead and should be replaced as soon as possible.
pub(crate) async fn handler_health_alive(_: Request<Body>) -> ApiResult<Response<Body>> {
    let mem = mem_info().map_err(ApiError::SysInfo)?;

    let data = serde_json::json!({
        "success": true,
        "data": {
            "status": "ALIVE",
            "checks": [
                {
                    "name": "heap-memory",
                    "data": {
                      "used": (mem.total - mem.free),
                      "max": mem.total,
                    },
                },
            ],
        },
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(HeaderValues::CACHE_CONTROL, "no-cache")
        .header(HeaderValues::CONTENT_TYPE, MimeValues::JSON_MIME_TYPE)
        .body(Body::from(data.to_string()))
        .map_err(ApiError::Http)
}

async fn check_database(req: Request<Body>) -> GenericResult<()> {
    let db = req
        .data::<DbContext>()
        .ok_or_else(ApiError::fatal("Unable to get database pool connection"))?;


    let result = db
        .run_command(doc! { "ping": 1i32 }, None)
        .await
        .map_err(|e| e.to_string())?;


    // result.get("ok");
    Ok(())
}
