mod middleware;
mod auth_future;

use middleware::JwtAuthMiddleware;

use std::collections::HashMap;
use jsonwebtoken::DecodingKey;
use tower::Layer;

/// Default HTTP body for the client.
pub type HttpBody = jsonrpsee_core::http_helpers::Body;
/// HTTP request with default body.
pub type HttpRequest<T = HttpBody> = jsonrpsee_core::http_helpers::Request<T>;
/// HTTP response with default body.
pub type HttpResponse<T = HttpBody> = jsonrpsee_core::http_helpers::Response<T>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessLevel {
    Public,
    Operator,
    Internal,
}

#[derive(Clone)]
pub struct JwtAuthLayer {
    access_map: HashMap<String, AccessLevel>,
    operator_key: DecodingKey,
    internal_key: DecodingKey,
}

impl JwtAuthLayer {
    pub fn new(
        access_map: HashMap<String, AccessLevel>,
        operator_key: DecodingKey,
        internal_key: DecodingKey,
    ) -> Self {
        Self {
            access_map,
            operator_key,
            internal_key,
        }
    }
}

impl<S> Layer<S> for JwtAuthLayer {
    type Service = JwtAuthMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        JwtAuthMiddleware {
            inner,
            access_map: self.access_map.clone(),
            operator_key: self.operator_key.clone(),
            internal_key: self.internal_key.clone(),
        }
    }
}