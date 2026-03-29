// src/routes/mod.rs

use axum::{
    routing::{get, post},
    Router,
};

use crate::identity_web::AuthState;

pub mod download;
pub mod health;
pub mod inbox;
pub mod share;
pub mod upload;
