use std::sync::Arc;
use crate::models::{User, VpnNode};
use tokio::sync::RwLock;
use std::collections::HashMap;

pub struct AppState {
    pub users: RwLock<HashMap<String, User>>,
    pub nodes: RwLock<Vec<VpnNode>>,
}

impl AppState {
    pub fn new_mock() -> Arc<Self> {
        let mut users = HashMap::new();
        users.insert("mock-token-123".into(), User {
            id: "u_1".into(),
            username: "test_user".into(),
            subscription_active: true,
        });

        let nodes = vec![
            VpnNode {
                id: "n_1".into(),
                location: "Frankfurt, DE".into(),
                ip_address: "198.51.100.1".into(),
                public_key: "abc123mockkey=".into(),
                load_percent: 45,
            },
            VpnNode {
                id: "n_2".into(),
                location: "New York, US".into(),
                ip_address: "203.0.113.5".into(),
                public_key: "xyz789mockkey=".into(),
                load_percent: 82,
            },
        ];

        Arc::new(Self {
            users: RwLock::new(users),
            nodes: RwLock::new(nodes),
        })
    }
}
