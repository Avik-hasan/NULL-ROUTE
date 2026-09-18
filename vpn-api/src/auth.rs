use crate::models::{User, AuthResponse};
use std::collections::HashMap;

pub fn process_auth(users: &HashMap<String, User>, token: &str) -> AuthResponse {
    if let Some(user) = users.get(token) {
        if user.subscription_active {
            AuthResponse {
                success: true,
                user: Some(user.clone()),
                error_message: None,
            }
        } else {
            AuthResponse {
                success: false,
                user: Some(user.clone()),
                error_message: Some("Subscription expired".into()),
            }
        }
    } else {
        AuthResponse {
            success: false,
            user: None,
            error_message: Some("Invalid token".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_token_active_sub() {
        let mut users = HashMap::new();
        users.insert("t1".into(), User {
            id: "u1".into(),
            username: "test".into(),
            subscription_active: true,
        });

        let resp = process_auth(&users, "t1");
        assert!(resp.success);
        assert!(resp.user.is_some());
    }

    #[test]
    fn test_invalid_token() {
        let users = HashMap::new();
        let resp = process_auth(&users, "t1");
        assert!(!resp.success);
        assert_eq!(resp.error_message.unwrap(), "Invalid token");
    }
}
