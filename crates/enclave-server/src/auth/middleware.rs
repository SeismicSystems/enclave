use super::{AccessRole, HttpBody, HttpRequest, HttpResponse};
use crate::auth::auth_future::ResponseFuture;
use http::StatusCode;
use jsonwebtoken::{decode, DecodingKey, Validation};
use std::{
    collections::HashMap,
    task::{Context, Poll},
};
use tower::Service;

/// A Tower Service for JWT Authentication
/// Performs Auth, and if it succeeds passes the request to the inner service
#[derive(Clone)]
pub struct JwtAuthMiddleware<S> {
    pub inner: S,
    pub method_roles: HashMap<String, AccessRole>,
    pub role_keys: HashMap<AccessRole, DecodingKey>,
}
impl<S> Service<HttpRequest> for JwtAuthMiddleware<S>
where
    S: Service<HttpRequest, Response = HttpResponse>,
    S::Future: Send + 'static,
{
    type Response = HttpResponse;
    type Error = S::Error;
    type Future = ResponseFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: HttpRequest) -> Self::Future {
        // Extract JSON-RPC method name and access role
        let (parts, body) = req.into_parts();
        let method = parts.method.to_string();
        let access = match self.method_roles.get(&method) {
            Some(access) => *access,
            None => {
                return ResponseFuture::invalid_auth(error_response(
                    StatusCode::NOT_FOUND,
                    "JwtAuthMiddleware: method not found".into(),
                ));
            }
        };

        // If public, pass through
        if access == AccessRole::Public {
            let req = HttpRequest::from_parts(parts, body);
            return ResponseFuture::future(self.inner.call(req));
        }

        // Check Authorization header
        // Errors if Header/Token is malformed
        let auth_header = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok());

        let token = match auth_header.and_then(|s| s.strip_prefix("Bearer ")) {
            Some(t) => t,
            None => {
                return ResponseFuture::invalid_auth(error_response(
                    StatusCode::UNAUTHORIZED,
                    "JwtAuthMiddleware: Missing or invalid Authorization header".into(),
                ));
            }
        };

        // validate the JWT token
        // Errors when token is well-formed but expired or invalid
        let key = match self.role_keys.get(&access) {
            Some(key) => key,
            None => {
                return ResponseFuture::invalid_auth(error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "JwtAuthMiddleware: failed to find key for access role".into(),
                ))
            }
        };
        let validation = Validation::default();
        if decode::<serde_json::Value>(token, key, &validation).is_err() {
            return ResponseFuture::invalid_auth(error_response(
                StatusCode::FORBIDDEN,
                "JwtAuthMiddleware: Invalid or expired token".into(),
            ));
        }

        // Auth success: reconstruct request and forward
        let req = HttpRequest::from_parts(parts, body);
        ResponseFuture::future(self.inner.call(req))
    }
}

/// A helper method to create an error response for the HttpResponse type
fn error_response(status_code: http::StatusCode, message: String) -> HttpResponse {
    let response = HttpResponse::builder()
        .status(status_code)
        .header("content-type", "application/json")
        .body(HttpBody::from(message))
        .unwrap();
    response
}
