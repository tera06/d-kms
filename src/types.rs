use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct SignRequest {
    pub request_id: String,
    pub timestamp: u64,
    pub message: String,
}

#[derive(Serialize, Deserialize)]
pub struct SignResponse {
    pub request_id: String,
    pub timestamp: u64,
    pub index: Option<usize>,
    pub sig_share: Option<String>,
    pub error: Option<String>,
}
