use std::fmt::Debug;

use actix_web::http::StatusCode;
use actix_web::{HttpResponse, ResponseError, web};

use anyhow::Context;
use sqlx::PgPool;
use uuid::Uuid;

use crate::domain::{User, UserName, UserPassword, create_credential};
use crate::startup::ApplicationBaseUrl;

#[derive(serde::Deserialize)]
pub struct FormData {
    pub name: String,
    pub password: String,
}

const POSTGRES_UNIQUE_VIOLATION: &str = "23505";

impl User {
    /// Custom async constructor to bypass TryFrom's synchronous limitation
    pub async fn try_from_form(value: FormData, hibp_base_url: &str) -> Result<Self, String> {
        let name = UserName::parse(value.name)?;
        let password = UserPassword::parse(value.password, hibp_base_url).await?;

        Ok(Self { name, password })
    }
}

#[derive(thiserror::Error)]
pub enum SignUpError {
    #[error("{0}")]
    ValidationError(String),
    #[error("Username is already taken.")]
    DuplicateUsername,
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

impl Debug for SignUpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        error_chain_fmt(self, f)
    }
}

impl ResponseError for SignUpError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        match self {
            SignUpError::ValidationError(_) => StatusCode::BAD_REQUEST,
            SignUpError::DuplicateUsername => StatusCode::BAD_REQUEST,
            SignUpError::UnexpectedError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        match self {
            SignUpError::UnexpectedError(_) => {
                HttpResponse::build(self.status_code()).json(serde_json::json!({
                    "error": "Internal server error",
                    "message": "Something went wrong on our end."
                }))
            }
            other => HttpResponse::build(other.status_code()).json(serde_json::json!({
                "error": "Registration failed",
                "message": other.to_string()
            })),
        }
    }
}

impl SignUpError {
    /// Helper to convert a generic database error into a semantic SignUpError
    pub fn from_database_error(e: anyhow::Error) -> Self {
        if let Some(sqlx::Error::Database(db_err)) =
            e.source().and_then(|s| s.downcast_ref::<sqlx::Error>())
            && db_err.code().as_deref() == Some(POSTGRES_UNIQUE_VIOLATION)
        {
            return SignUpError::DuplicateUsername;
        }

        SignUpError::UnexpectedError(e)
    }
}

pub fn error_chain_fmt(
    e: &impl std::error::Error,
    f: &mut std::fmt::Formatter<'_>,
) -> std::fmt::Result {
    writeln!(f, "{}\n", e)?;
    let mut current = e.source();
    while let Some(cause) = current {
        writeln!(f, "Caused by:\n\t{}", cause)?;
        current = cause.source();
    }
    Ok(())
}

#[tracing::instrument(
    name = "Adding a new user",
    skip(form, pool,hibp_url),
    fields(
        user_name = %form.name,
    )
)]
pub async fn create_user_account(
    form: web::Json<FormData>,
    pool: web::Data<PgPool>,
    hibp_url: web::Data<ApplicationBaseUrl>,
) -> Result<HttpResponse, SignUpError> {
    // increment active gauge on request entry
    metrics::gauge!("auth_signup_active_requests").increment(1.0);
    let start_time = std::time::Instant::now();

    let form_data = form.into_inner();

    // Call the associated async function on User and explicitly .await it
    let new_user = User::try_from_form(form_data, &hibp_url.0)
        .await
        .map_err(|e| {
            // Record failure counter on validation break
            metrics::counter!("auth_signup_total", "status" => "validation_error").increment(1);
            SignUpError::ValidationError(e)
        })?;

    // Insert the newly verified domain model into your DB
    let result = match insert_user(&pool, new_user).await {
        Ok(_) => {
            metrics::counter!("auth_signup_total", "status" => "success").increment(1);
            Ok(HttpResponse::Created().finish())
        }
        Err(e) => {
            // Check if the underlying cause chain contains a Postgres Unique Constraint violation
            let signup_err = SignUpError::from_database_error(e);

            // Record dynamic metric names based on what the helper categorized it as
            let metric_status = match &signup_err {
                SignUpError::DuplicateUsername => "duplicate_username",
                _ => "db_error",
            };
            metrics::counter!("auth_signup_total", "status" => metric_status).increment(1);

            Err(signup_err)
        }
    };

    //  Performance Tracking - calculate exact elapsed duration before return
    let duration = start_time.elapsed();
    metrics::histogram!("auth_signup_duration_seconds").record(duration.as_secs_f64());

    // Decrement the active gauge since this task thread loop is finished
    metrics::gauge!("auth_signup_active_requests").decrement(1.0);

    result
}

// Assuming user already created an account
// We will be getting a user profile by username (unique per schema)
// #[tracing::instrument(name = "Get user by username", skip(pool))]
// pub async fn get_user_by_username(pool: &PgPool, user_name: &str) -> Result<User, sqlx::Error> {
//     let user_found = sqlx::query_as!(
//         User,
//         r#"SELECT user_id, user_name FROM users WHERE user_name = $1"#,
//         user_name
//     )
//     .fetch_one(pool)
//     .await
//     .inspect_err(|e| tracing::error!("Failed to execute query: {:?}", e));

//     Ok(user_found.unwrap().into())
// }

#[tracing::instrument(name = "Saving new user details in the database", skip(new_user, pool))]
pub async fn insert_user(pool: &PgPool, new_user: User) -> Result<(), anyhow::Error> {
    create_credential(
        Uuid::new_v4(),
        new_user.name,
        new_user.password.into(),
        pool,
    )
    .await
    .context("Failed to insert user into the database.")
}
