
use http::StatusCode;
use jsonwebtoken::{decode, DecodingKey, Validation};
use std::{
    collections::HashMap,
    task::{Context, Poll},
};
use tower::Service;
use super::{AccessLevel, HttpBody, HttpRequest, HttpResponse};
use crate::auth::auth_future::ResponseFuture;

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
    type Future = ResponseFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: HttpRequest) -> Self::Future {
        // Extract JSON-RPC method name
        let (parts, body) = req.into_parts();
        let method = parts.method.to_string();
    
        let access = match self.access_map.get(&method) {
            Some(access) => *access,
            None => {
                return ResponseFuture::invalid_auth(error_response(
                    StatusCode::NOT_FOUND,
                    "JwtAuthMiddleware: method not found".into(),
                ));
            }
        };
    
        // If public, pass through
        if access == AccessLevel::Public {
            let req = HttpRequest::from_parts(parts, body);
            return ResponseFuture::future(self.inner.call(req));
        }
    
        // Check Authorization header
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
    
        let key = match access {
            AccessLevel::Operator => &self.operator_key,
            AccessLevel::Internal => &self.internal_key,
            AccessLevel::Public => unreachable!(),
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