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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_request_serialization() {
        let req = AuthRequest { token: "secret_123".into() };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(json, r#"{"token":"secret_123"}"#);
        
        let deserialized: AuthRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.token, req.token);
    }
}
