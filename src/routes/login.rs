use std::fmt::Debug;

use actix_web::{HttpResponse, ResponseError, http::StatusCode, web};
use sqlx::PgPool;

use crate::{
    domain::{AuthError, Credentials, UserName, UserPassword, validate_credentials},
    routes::{FormData, error_chain_fmt},
    session_state::TypedSession,
    startup::ApplicationBaseUrl,
};

#[derive(thiserror::Error)]
pub enum LoginError {
    #[error("{0}")]
    ValidationError(String),
    #[error("Authentication failed")]
    AuthError(#[source] anyhow::Error),
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

impl Debug for LoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        error_chain_fmt(self, f)
    }
}

impl ResponseError for LoginError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        match self {
            LoginError::UnexpectedError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            LoginError::AuthError(_) => StatusCode::UNAUTHORIZED,
            LoginError::ValidationError(_) => StatusCode::BAD_REQUEST,
            LoginError::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
        }
    }

    fn error_response(&self) -> HttpResponse<actix_web::body::BoxBody> {
        let (error_type, message) = match self {
            LoginError::UnexpectedError(_) => {
                ("Internal server error", "Something went wrong on our end.")
            }
            LoginError::AuthError(_) => (
                "Wrong credentials.",
                "You are not allowed to login with that information provided.",
            ),
            LoginError::ValidationError(_) => {
                ("Validation failed.", "You entered invalid credentials.")
            }
            LoginError::TooManyRequests => ("Too Many Requests", "Please try again later"),
        };

        HttpResponse::build(self.status_code()).json(serde_json::json!({
            "error": error_type,
            "message": message
        }))
    }
}
