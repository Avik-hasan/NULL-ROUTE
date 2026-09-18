mod models;
mod routes;
mod state;
mod auth;

use axum::{
    routing::{get, post},
    Router,
};
use state::AppState;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    info!("Starting NULL-ROUTE Mock API Server...");

    let state = AppState::new_mock();

    let app = Router::new()
        .route("/api/v1/auth", post(routes::authenticate))
        .route("/api/v1/nodes", get(routes::get_nodes))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
    info!("Listening on {}", listener.local_addr()?);
    
    axum::serve(listener, app).await?;

    Ok(())
}
