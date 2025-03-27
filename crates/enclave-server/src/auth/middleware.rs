
use http::StatusCode;
use jsonwebtoken::{decode, DecodingKey, Validation};
use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tower::Service;
use super::{AccessLevel, HttpBody, HttpRequest, HttpResponse};

#[derive(Clone)]
pub struct JwtAuthMiddleware<S> {
    pub inner: S,
    pub access_map: HashMap<String, AccessLevel>,
    pub operator_key: DecodingKey,
    pub internal_key: DecodingKey,
}

fn error_response(status_code: http::StatusCode, message: String) -> HttpResponse {
    let response = HttpResponse::builder()
        .status(status_code)
        .header("content-type", "application/json")
        .body(HttpBody::from(message))
        .unwrap();
    response
}

impl<S> Service<HttpRequest> for JwtAuthMiddleware<S>
where
    S: Service<HttpRequest, Response = HttpResponse>,
    S::Future: Send + 'static,
{
    type Response = HttpResponse;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: HttpRequest) -> Self::Future {
        let method_access = self.access_map.clone();
        let operator_key = self.operator_key.clone();
        let internal_key = self.internal_key.clone();
        let mut inner = self.inner;

        Box::pin(async move {
            // Extract JSON-RPC method name
            let (parts, _) = req.into_parts();
            let method = parts.method.to_string();
            let access = match self.access_map.get(&method) {
                Some(access) => *access,
                None => {
                    return Ok(error_response(
                        StatusCode::NOT_FOUND,
                        "JwtAuthMiddleware: method not found".to_string(),
                    ))
                }
            };

            // If public method, pass through
            if access == AccessLevel::Public {
                return inner.call(req).await;
            }

            // Check for Authorization header and extract token
            // Errors if Header/Token is malformed
            let auth_header = req
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok());
            let token = match auth_header.and_then(|s| s.strip_prefix("Bearer ")) {
                Some(t) => t,
                None => {
                    return Ok(error_response(
                        StatusCode::UNAUTHORIZED,
                        "JwtAuthMiddleware: Missing or invalid Authorization header".to_string(),
                    ))
                }
            };

            // Get the relevent jwt secret
            let key = match access {
                AccessLevel::Operator => &operator_key,
                AccessLevel::Internal => &internal_key,
                AccessLevel::Public => unreachable!(),
            };

            // Validate token
            // Errors when token is well-formed but expired or invalid
            let validation = Validation::default();
            if decode::<serde_json::Value>(token, key, &validation).is_err() {
                return Ok(error_response(
                    StatusCode::FORBIDDEN,
                    "JwtAuthMiddleware: Invalid or expired token".to_string(),
                ));
            }

            // Auth success, pass through
            inner.call(req).await
        })
    }
}