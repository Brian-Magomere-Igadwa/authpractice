use std::fmt::Debug;

use actix_web::{HttpResponse, ResponseError, http::StatusCode, web};

use crate::routes::{FormData, error_chain_fmt};

#[derive(thiserror::Error)]
pub enum LoginError {
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
        }
    }
    fn error_response(&self) -> HttpResponse<actix_web::body::BoxBody> {
        match self {
            LoginError::UnexpectedError(_) => {
                HttpResponse::build(self.status_code()).json(serde_json::json!({
                    "error": "Internal server error",
                    "message": "Something went wrong on our end."
                }))
            }
        }
    }
}

pub async fn login(form: web::Json<FormData>) -> Result<HttpResponse, LoginError> {
    Ok(HttpResponse::Ok().finish())
}
