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
            LoginError::AuthError(_) => {
                HttpResponse::build(self.status_code()).json(serde_json::json!({
                    "error": "Wrong credentials.",
                    "message": "You are not allowed to login with that information provided."
                }))
            }
            LoginError::ValidationError(_) => {
                HttpResponse::build(self.status_code()).json(serde_json::json!({
                    "error": "Validation failed.",
                    "message": "You entered invalid credentials."
                }))
            }
        }
    }
}

pub async fn login(
    form: web::Json<FormData>,
    pool: web::Data<PgPool>,
    session: TypedSession,
    hibp_url: web::Data<ApplicationBaseUrl>,
) -> Result<HttpResponse, LoginError> {
    //fetch the user from db
    // hash the passed password from form.password
    // compare the results
    // if they match then we create a session for them else invalid creds

    let credentials = Credentials {
        username: UserName::parse(form.0.name).map_err(|e| LoginError::ValidationError(e))?,
        password: UserPassword::parse(form.0.password, &hibp_url.0)
            .await
            .map_err(|e| LoginError::ValidationError(e))?,
    };

    tracing::Span::current().record(
        "username",
        tracing::field::display(&credentials.username.as_ref()),
    );
    match validate_credentials(credentials, &pool).await {
        Ok(user_id) => {
            tracing::Span::current().record("user_id", tracing::field::display(&user_id));
            session.renew();
            session
                .insert_user_id(user_id)
                .map_err(|e| LoginError::UnexpectedError(e.into()))?;
            Ok(HttpResponse::Ok().finish())
        }
        Err(e) => {
            let e = match e {
                AuthError::InvalidCredentials(_) => LoginError::AuthError(e.into()),
                AuthError::UnexpectedError(_) => LoginError::UnexpectedError(e.into()),
            };
            Err(e)
        }
    }
}
