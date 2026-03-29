//src/routes/health.rs

use axum::response::IntoResponse;

pub async fn health() -> impl IntoResponse {
    "OK"
}
