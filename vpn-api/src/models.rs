use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    pub id: String,
    pub username: String,
    pub subscription_active: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VpnNode {
    pub id: String,
    pub location: String,
    pub ip_address: String,
    pub public_key: String,
    pub load_percent: u8,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthRequest {
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    pub success: bool,
    pub user: Option<User>,
    pub error_message: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NodeListResponse {
    pub nodes: Vec<VpnNode>,
}
