mod auth_future;
mod middleware;
// mod method_parse;
mod modify_if;

use http::method;
use middleware::JwtAuthMiddleware;

use jsonwebtoken::DecodingKey;
use std::collections::HashMap;
use tower::Layer;

/// Default HTTP body for the client.
pub type HttpBody = jsonrpsee_core::http_helpers::Body;
/// HTTP request with default body.
pub type HttpRequest<T = HttpBody> = jsonrpsee_core::http_helpers::Request<T>;
/// HTTP response with default body.
pub type HttpResponse<T = HttpBody> = jsonrpsee_core::http_helpers::Response<T>;

/// Security Roles defined for different endpoints
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccessRole {
    Public,
    Operator,
    Internal,
}

/// A Tower Layer for JWT Authentication
#[derive(Clone)]
pub struct JwtAuthLayer {
    method_roles: HashMap<String, AccessRole>,
    role_keys: HashMap<AccessRole, DecodingKey>,
}
impl JwtAuthLayer {
    pub fn new(
        method_roles: HashMap<String, AccessRole>,
        role_keys: HashMap<AccessRole, DecodingKey>,
    ) -> Self {
        // TODO: consider validating that the maps are complete
        Self {
            method_roles,
            role_keys,
        }
    }

    // pub fn default() -> Self {
    //     let method_roles = HashMap::from([
    //         (method::GET, AccessRole::Public),
    //         (method::POST, AccessRole::Operator),
    //         (method::PUT, AccessRole::Operator),
    //         (method::DELETE, AccessRole::Operator),
    //     ]);
        
    //     Self::new(HashMap::new(), HashMap::new())
    // }
}
impl<S> Layer<S> for JwtAuthLayer {
    type Service = JwtAuthMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        JwtAuthMiddleware {
            inner,
            method_roles: self.method_roles.clone(),
            role_keys: self.role_keys.clone(),
        }
    }
}
