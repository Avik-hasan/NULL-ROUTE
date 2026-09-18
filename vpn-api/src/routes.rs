use axum::{
    extract::State,
    Json,
};
use std::sync::Arc;
use crate::models::{AuthRequest, AuthResponse, NodeListResponse};
use crate::state::AppState;

pub async fn authenticate(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AuthRequest>,
) -> Json<AuthResponse> {
    let users = state.users.read().await;
    
    if let Some(user) = users.get(&payload.token) {
        if user.subscription_active {
            Json(AuthResponse {
                success: true,
                user: Some(user.clone()),
                error_message: None,
            })
        } else {
            Json(AuthResponse {
                success: false,
                user: Some(user.clone()),
                error_message: Some("Subscription expired".into()),
            })
        }
    } else {
        Json(AuthResponse {
            success: false,
            user: None,
            error_message: Some("Invalid token".into()),
        })
    }
}

pub async fn get_nodes(
    State(state): State<Arc<AppState>>,
) -> Json<NodeListResponse> {
    let nodes = state.nodes.read().await;
    Json(NodeListResponse {
        nodes: nodes.clone(),
    })
}
