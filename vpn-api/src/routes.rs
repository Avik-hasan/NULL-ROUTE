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
    
    let response = crate::auth::process_auth(&users, &payload.token);
    Json(response)
}

pub async fn get_nodes(
    State(state): State<Arc<AppState>>,
) -> Json<NodeListResponse> {
    let nodes = state.nodes.read().await;
    Json(NodeListResponse {
        nodes: nodes.clone(),
    })
}
