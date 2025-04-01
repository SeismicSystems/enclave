use http::HeaderMap;
use jsonrpsee_http_client::HttpResponse;

mod auth_client_layer;
mod auth_layer;
mod jwt_validator;
mod jwt;

pub use auth_client_layer::{secret_to_bearer_header, AuthClientLayer, AuthClientService};
pub use auth_layer::AuthLayer;
pub use jwt_validator::JwtAuthValidator;
pub use jwt::{Claims, JwtError, JwtSecret};

/// General purpose trait to validate Http Authorization headers. It's supposed to be integrated as
/// a validator trait into an [`AuthLayer`].
pub trait AuthValidator {
    /// This function is invoked by the [`AuthLayer`] to perform validation on Http headers.
    /// The result conveys validation errors in the form of an Http response.
    fn validate(&self, headers: &HeaderMap) -> Result<(), HttpResponse>;
}
