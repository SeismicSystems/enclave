use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HealthCheckResponse {
    pub status_ok: bool,
    pub boot_complete: bool,
}