use hyper::header::{self, HeaderValue};
use hyper::{body::HttpBody, Response};
use routerify::Middleware;
use std::env;
use std::error::Error;

pub fn enable_cors_all<B, E>() -> Middleware<B, E>
where
    B: HttpBody + Send + Sync + Unpin + 'static,
    E: Error + Send + Sync + Unpin + 'static,
{
    Middleware::post(enable_cors_all_middleware_handler::<B, E>)
}

async fn enable_cors_all_middleware_handler<B, E>(
    mut res: Response<B>,
) -> Result<Response<B>, E>
where
    B: HttpBody + Send + Sync + Unpin + 'static,
    E: Error + Send + Sync + Unpin + 'static,
{
    let headers = res.headers_mut();

    let origin =
        env::var("FRONTEND_URL").expect("FRONTEND_URL environment variable not set");

    // Allow only request coming from this origin.
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_str(origin.as_str())
            .expect("Header value not set for Access-Control-Allow-Origin"),
    );

    // Allow this methods to be used by client in preflight request.
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("OPTIONS, HEAD, GET, POST"),
    );

    // Allow only this requests headers to be used.
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static(
            "authorization, content-type, accept, origin, user-agent",
        ),
    );

    // Allow this headers to be accessed by client on javascript to be parsed
    // from response.
    headers.insert(
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static("content-encoding, x-session-id"),
    );

    // Set how long the results of preflight request can be cached.
    headers.insert(
        header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static("7200"),
    );

    // Used as a security measure to prevent adding wildcards and or additions
    // to the allowed origins specially if the origin contains multiple domains.
    headers.insert(header::VARY, HeaderValue::from_static("Origin"));
    headers.remove("x-powered-by");

    Ok(res)
}
