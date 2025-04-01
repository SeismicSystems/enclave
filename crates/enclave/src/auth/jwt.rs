//! JWT (JSON Web Token) utilities for the Engine API.

// use alloc::string::String;
// use alloy_primitives::hex;
use core::{str::FromStr, time::Duration};
use jsonwebtoken::get_current_timestamp;
use rand::Rng;
use std::fmt;

use jsonwebtoken::{errors::ErrorKind, Algorithm, DecodingKey, Validation};

/// Errors returned by the [`JwtSecret`]
#[derive(Debug)]
pub enum JwtError {
    /// An error encountered while decoding the hexadecimal string for the JWT secret.
    JwtSecretHexDecodeError(hex::FromHexError),

    /// The JWT key length provided is invalid, expecting a specific length.
    InvalidLength(usize, usize),

    /// The signature algorithm used in the JWT is not supported. Only HS256 is supported.
    UnsupportedSignatureAlgorithm,

    /// The provided signature in the JWT is invalid.
    InvalidSignature,

    /// The "iat" (issued-at) claim in the JWT is not within the allowed ±60 seconds from the
    /// current time.
    InvalidIssuanceTimestamp,

    /// The Authorization header is missing or invalid in the context of JWT validation.
    MissingOrInvalidAuthorizationHeader,

    /// An error occurred during JWT decoding.
    JwtDecodingError(String),
}

impl fmt::Display for JwtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JwtError::JwtSecretHexDecodeError(e) => write!(f, "{}", e),
            JwtError::InvalidLength(expected, actual) => {
                write!(
                    f,
                    "JWT key is expected to have a length of {} digits. {} digits key provided",
                    expected, actual
                )
            }
            JwtError::UnsupportedSignatureAlgorithm => {
                write!(
                    f,
                    "unsupported signature algorithm. Only HS256 is supported"
                )
            }
            JwtError::InvalidSignature => write!(f, "provided signature is invalid"),
            JwtError::InvalidIssuanceTimestamp => {
                write!(
                    f,
                    "IAT (issued-at) claim is not within ±60 seconds from the current time"
                )
            }
            JwtError::MissingOrInvalidAuthorizationHeader => {
                write!(f, "Authorization header is missing or invalid")
            }
            JwtError::JwtDecodingError(err) => write!(f, "JWT decoding error: {}", err),
        }
    }
}

impl std::error::Error for JwtError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            JwtError::JwtSecretHexDecodeError(e) => Some(e),
            _ => None,
        }
    }
}

/// Length of the hex-encoded 256 bit secret key.
/// A 256-bit encoded string in Rust has a length of 64 digits because each digit represents 4 bits
/// of data. In hexadecimal representation, each digit can have 16 possible values (0-9 and A-F), so
/// 4 bits can be represented using a single hex digit. Therefore, to represent a 256-bit string,
/// we need 64 hexadecimal digits (256 bits ÷ 4 bits per digit = 64 digits).
const JWT_SECRET_LEN: usize = 64;

/// The JWT `iat` (issued-at) claim cannot exceed +-60 seconds from the current time.
const JWT_MAX_IAT_DIFF: Duration = Duration::from_secs(60);

/// The execution layer client MUST support at least the following alg HMAC + SHA256 (HS256)
const JWT_SIGNATURE_ALGO: Algorithm = Algorithm::HS256;

/// Claims in JWT are used to represent a set of information about an entity.
///
/// Claims are essentially key-value pairs that are encoded as JSON objects and included in the
/// payload of a JWT. They are used to transmit information such as the identity of the entity, the
/// time the JWT was issued, and the expiration time of the JWT, among others.
///
/// The Engine API spec requires that just the `iat` (issued-at) claim is provided.
/// It ignores claims that are optional or additional for this specification.
#[derive(Copy, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Claims {
    /// The "iat" value MUST be a number containing a NumericDate value.
    /// According to the RFC A NumericDate represents the number of seconds since
    /// the UNIX_EPOCH.
    /// - [`RFC-7519 - Spec`](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.6)
    /// - [`RFC-7519 - Notations`](https://www.rfc-editor.org/rfc/rfc7519#section-2)
    pub iat: u64,
    /// The "exp" (expiration time) claim identifies the expiration time on or after which the JWT
    /// MUST NOT be accepted for processing.
    pub exp: Option<u64>,
}

impl Claims {
    /// Creates a new instance of [`Claims`] with the current timestamp as the `iat` claim.
    pub fn with_current_timestamp() -> Self {
        Self {
            iat: get_current_timestamp(),
            exp: None,
        }
    }

    /// Checks if the `iat` claim is within the allowed range from the current time.
    pub fn is_within_time_window(&self) -> bool {
        let now_secs = get_current_timestamp();
        now_secs.abs_diff(self.iat) <= JWT_MAX_IAT_DIFF.as_secs()
    }
}

impl Default for Claims {
    /// By default, the `iat` claim is set to the current timestamp.
    fn default() -> Self {
        Self::with_current_timestamp()
    }
}

/// Value-object holding a reference to a hex-encoded 256-bit secret key.
///
/// A JWT secret key is used to secure JWT-based authentication. The secret key is
/// a shared secret between the server and the client and is used to calculate a digital signature
/// for the JWT, which is included in the JWT along with its payload.
///
/// See also: [Secret key - Engine API specs](https://github.com/ethereum/execution-apis/blob/main/src/engine/authentication.md#key-distribution)
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct JwtSecret([u8; 32]);

impl JwtSecret {
    /// Creates an instance of [`JwtSecret`].
    ///
    /// Returns an error if one of the following applies:
    /// - `hex` is not a valid hexadecimal string
    /// - `hex` argument length is less than `JWT_SECRET_LEN`
    ///
    /// This strips the leading `0x`, if any.
    pub fn from_hex<S: AsRef<str>>(hex: S) -> Result<Self, JwtError> {
        let hex = hex.as_ref().trim().trim_start_matches("0x");
        if hex.len() == JWT_SECRET_LEN {
            let hex_bytes = hex::decode(hex).map_err(JwtError::JwtSecretHexDecodeError)?;
            // is 32bytes, see length check
            let bytes = hex_bytes.try_into().expect("is expected len");
            Ok(Self(bytes))
        } else {
            Err(JwtError::InvalidLength(JWT_SECRET_LEN, hex.len()))
        }
    }

    /// Validates a JWT token along the following rules:
    /// - The JWT signature is valid.
    /// - The JWT is signed with the `HMAC + SHA256 (HS256)` algorithm.
    /// - The JWT `iat` (issued-at) claim is a timestamp within +-60 seconds from the current time.
    /// - The JWT `exp` (expiration time) claim is validated by default if defined.
    ///
    /// See also: [JWT Claims - Engine API specs](https://github.com/ethereum/execution-apis/blob/main/src/engine/authentication.md#jwt-claims)
    pub fn validate(&self, jwt: &str) -> Result<(), JwtError> {
        // Create a new validation object with the required signature algorithm
        // and ensure that the `iat` claim is present. The `exp` claim is validated if defined.
        let mut validation = Validation::new(JWT_SIGNATURE_ALGO);
        validation.set_required_spec_claims(&["iat"]);
        let bytes = &self.0;

        match jsonwebtoken::decode::<Claims>(jwt, &DecodingKey::from_secret(bytes), &validation) {
            Ok(token) => {
                if !token.claims.is_within_time_window() {
                    Err(JwtError::InvalidIssuanceTimestamp)?
                }
            }
            Err(err) => match *err.kind() {
                ErrorKind::InvalidSignature => Err(JwtError::InvalidSignature)?,
                ErrorKind::InvalidAlgorithm => Err(JwtError::UnsupportedSignatureAlgorithm)?,
                _ => {
                    let detail = format!("{err}");
                    Err(JwtError::JwtDecodingError(detail))?
                }
            },
        };

        Ok(())
    }

    /// Generates a random [`JwtSecret`] containing a hex-encoded 256 bit secret key.
    pub fn random() -> Self {
        let random_bytes: [u8; 32] = rand::rng().random();
        let secret = hex::encode(random_bytes);
        Self::from_hex(secret).unwrap()
    }

    pub fn encode(&self, claims: &Claims) -> Result<String, jsonwebtoken::errors::Error> {
        let bytes = &self.0;
        let key = jsonwebtoken::EncodingKey::from_secret(bytes);
        let algo = jsonwebtoken::Header::new(Algorithm::HS256);
        jsonwebtoken::encode(&algo, claims, &key)
    }

    /// Returns the secret key as a byte slice.
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub const fn mock_default() -> Self {
        Self([0u8; 32])
    }
}

impl core::fmt::Debug for JwtSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("JwtSecretHash").field(&"{{}}").finish()
    }
}

impl FromStr for JwtSecret {
    type Err = JwtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_hex() {
        let key = "f79ae8046bc11c9927afe911db7143c51a806c4a537cc08e0d37140b0192f430";
        let secret: Result<JwtSecret, _> = JwtSecret::from_hex(key);
        assert!(secret.is_ok());

        let secret: Result<JwtSecret, _> = JwtSecret::from_hex(key);
        assert!(secret.is_ok());
    }

    #[test]
    fn original_key_integrity_across_transformations() {
        let original = "f79ae8046bc11c9927afe911db7143c51a806c4a537cc08e0d37140b0192f430";
        let secret = JwtSecret::from_hex(original).unwrap();
        let bytes = &secret.0;
        let computed = hex::encode(bytes);
        assert_eq!(original, computed);
    }

    #[test]
    fn secret_has_64_hex_digits() {
        let expected_len = 64;
        let secret = JwtSecret::random();
        let hex = hex::encode(secret.0);
        assert_eq!(hex.len(), expected_len);
    }

    #[test]
    fn creation_ok_hex_string_with_0x() {
        let hex: String =
            "0x7365637265747365637265747365637265747365637265747365637265747365".into();
        let result = JwtSecret::from_hex(hex);
        assert!(result.is_ok());
    }

    #[test]
    fn creation_error_wrong_len() {
        let hex = "f79ae8046";
        let result = JwtSecret::from_hex(hex);
        assert!(matches!(result, Err(JwtError::InvalidLength(_, _))));
    }

    #[test]
    fn creation_error_wrong_hex_string() {
        let hex: String = "This__________Is__________Not_______An____Hex_____________String".into();
        let result = JwtSecret::from_hex(hex);
        assert!(matches!(result, Err(JwtError::JwtSecretHexDecodeError(_))));
    }
}
