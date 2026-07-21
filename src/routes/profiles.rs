use std::fmt::Debug;

use actix_web::http::StatusCode;
use actix_web::{HttpResponse, ResponseError, web};
use anyhow::Context;
use redis::AsyncCommands;
use secrecy::ExposeSecret;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::configuration::Settings;
use crate::domain::{UserId, UserName, UserPassword, compute_password_hash};
use crate::routes::{error_chain_fmt, login};
use crate::startup::ApplicationBaseUrl;

use crate::telemetry::spawn_blocking_with_tracing;

#[derive(serde::Deserialize)]
pub struct UpdateProfileData {
    pub name: Option<String>,
    pub password: Option<String>,
}

#[derive(thiserror::Error)]
pub enum UpdateProfileError {
    #[error("{0}")]
    ValidationError(String),
    #[error("User not found or unauthenticated.")]
    NotFound,
    #[error("Username is already taken.")]
    DuplicateUsername,
    #[error("Too many requests. Please try again later.")]
    TooManyRequests,
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

impl Debug for UpdateProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        error_chain_fmt(self, f)
    }
}

impl ResponseError for UpdateProfileError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        match self {
            UpdateProfileError::ValidationError(_) => StatusCode::BAD_REQUEST,
            UpdateProfileError::DuplicateUsername => StatusCode::CONFLICT,
            UpdateProfileError::NotFound => StatusCode::UNAUTHORIZED,
            UpdateProfileError::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
            UpdateProfileError::UnexpectedError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        match self {
            UpdateProfileError::UnexpectedError(_) => {
                HttpResponse::build(self.status_code()).json(serde_json::json!({
                    "error": "Internal server error",
                    "message": "Something went wrong while updating profile."
                }))
            }
            other => HttpResponse::build(other.status_code()).json(serde_json::json!({
                "error": "Update failed",
                "message": other.to_string()
            })),
        }
    }
}

const POSTGRES_UNIQUE_VIOLATION: &str = "23505";

impl UpdateProfileError {
    pub fn from_database_error(e: anyhow::Error) -> Self {
        if let Some(sqlx::Error::Database(db_err)) =
            e.source().and_then(|s| s.downcast_ref::<sqlx::Error>())
            && db_err.code().as_deref() == Some(POSTGRES_UNIQUE_VIOLATION)
        {
            return UpdateProfileError::DuplicateUsername;
        }

        UpdateProfileError::UnexpectedError(e)
    }
}

#[tracing::instrument(
    name = "Update user profile",
    skip(user_id, form, pool, settings, redis, hibp_url),
    fields(user_id = tracing::field::Empty) // 1. Pre-declare an empty field on the span
)]
pub async fn update_user_profile(
    user_id: web::ReqData<UserId>, // Extracted from auth middleware
    form: web::Json<UpdateProfileData>,
    pool: web::Data<PgPool>,
    settings: web::Data<Settings>,
    redis: web::Data<redis::Client>, // Standard multiplexed client
    hibp_url: web::Data<ApplicationBaseUrl>,
) -> Result<HttpResponse, UpdateProfileError> {
    metrics::gauge!("auth_profile_update_active_requests").increment(1.0);
    let start_time = std::time::Instant::now();

    let user_id = *user_id.into_inner(); // Extracts inner Uuid
    let payload = form.into_inner();

    // 0. QUARANTINE GUARD: Resolve username and check LoginTracker state in Redis
    let current_username =
        sqlx::query_scalar!(r#"SELECT user_name FROM users WHERE user_id = $1"#, user_id)
            .fetch_one(pool.get_ref())
            .await
            .context("Failed to fetch username for quarantine check")
            .map_err(UpdateProfileError::UnexpectedError)?;

    let mut con = redis
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| UpdateProfileError::UnexpectedError(e.into()))?;

    let namespace = &settings.application.redis_namespace;

    // Reuse LoginTracker from your login module
    let mut tracker = login::LoginTracker::fetch(&mut con, namespace, &current_username)
        .await
        .map_err(|e| UpdateProfileError::UnexpectedError(e.into()))?;

    if tracker.check_quarantine().is_err() {
        metrics::counter!("auth_profile_update_total", "status" => "quarantined_blocked")
            .increment(1);
        metrics::gauge!("auth_profile_update_active_requests").decrement(1.0);
        return Err(UpdateProfileError::TooManyRequests);
    }

    // 1. Validate inputs before starting database transactions
    let parsed_username = match payload.name {
        Some(u) => Some(UserName::parse(&u).map_err(UpdateProfileError::ValidationError)?),
        None => None,
    };

    let parsed_password = match payload.password {
        Some(p) => Some(
            UserPassword::parse(p, &hibp_url.0)
                .await
                .map_err(UpdateProfileError::ValidationError)?,
        ),
        None => None,
    };

    if parsed_username.is_none() && parsed_password.is_none() {
        metrics::counter!("auth_profile_update_total", "status" => "empty_payload").increment(1);
        metrics::gauge!("auth_profile_update_active_requests").decrement(1.0);
        return Err(UpdateProfileError::ValidationError(
            "At least one field (username or password) must be provided.".to_string(),
        ));
    }

    // 2. LAYER 2 (DB Level Safety): Begin Postgres Transaction with Row-Level Lock (FOR UPDATE)
    let mut transaction = pool
        .begin()
        .await
        .context("Failed to begin database transaction")
        .map_err(UpdateProfileError::UnexpectedError)?;

    let is_password_updated = parsed_password.is_some();

    execute_profile_update(&mut transaction, user_id, parsed_username, parsed_password)
        .await
        .map_err(UpdateProfileError::from_database_error)?;

    transaction
        .commit()
        .await
        .context("Failed to commit profile update transaction")
        .map_err(UpdateProfileError::UnexpectedError)?;

    // 3. LAYER 1 (Redis Cache Level Safety): Invalidate Active Sessions
    if is_password_updated
        && let Err(e) =
            revoke_user_sessions_in_redis(&redis, &settings.application.redis_namespace, user_id)
                .await
    {
        tracing::warn!(
            error.cause_chain = ?e,
            "Failed to revoke Redis session tokens for user {}. DB row was locked during update.",
            user_id
        );
    }

    metrics::counter!("auth_profile_update_total", "status" => "success").increment(1);
    metrics::histogram!("auth_profile_update_duration_seconds")
        .record(start_time.elapsed().as_secs_f64());
    metrics::gauge!("auth_profile_update_active_requests").decrement(1.0);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Profile updated successfully"
    })))
}

/// Executes row lock and conditional update inside a transaction.
#[tracing::instrument(name = "Lock user row and apply profile update", skip(transaction))]
async fn execute_profile_update(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    new_username: Option<UserName>,
    new_password: Option<UserPassword>,
) -> Result<(), anyhow::Error> {
    let row = sqlx::query!(
        r#"
        SELECT user_id FROM users
        WHERE user_id = $1
        FOR UPDATE
        "#,
        user_id
    )
    .fetch_optional(&mut **transaction)
    .await
    .context("Failed to lock user record for update")?;

    if row.is_none() {
        return Err(anyhow::anyhow!("User record not found"));
    }

    if let Some(username) = new_username {
        sqlx::query!(
            r#"
            UPDATE users
            SET user_name = $1
            WHERE user_id = $2
            "#,
            username.as_ref(),
            user_id
        )
        .execute(&mut **transaction)
        .await
        .context("Failed to update username in database")?;
    }

    if let Some(password) = new_password {
        // let password_hash: String = password;
        let password_hash =
            spawn_blocking_with_tracing(move || compute_password_hash(password.into()))
                .await?
                .context("Failed to hash password")?;
        sqlx::query!(
            r#"
            UPDATE users
            SET password_hash = $1
            WHERE user_id = $2
            "#,
            password_hash.expose_secret(),
            user_id
        )
        .execute(&mut **transaction)
        .await
        .context("Failed to update password hash in database")?;
    }

    Ok(())
}

/// Revokes all active session keys for this `user_id` from Redis using multiplexed redis client.
#[tracing::instrument(name = "Revoking user Redis sessions", skip(redis_client))]
pub async fn revoke_user_sessions_in_redis(
    redis_client: &redis::Client,
    namespace: &str,
    user_id: Uuid,
) -> Result<(), anyhow::Error> {
    let mut con = redis_client
        .get_multiplexed_async_connection()
        .await
        .context("Failed to get multiplexed Redis connection")?;

    let user_sessions_key = if namespace.is_empty() {
        format!("user_sessions:{}", user_id)
    } else {
        format!("{}:user_sessions:{}", namespace, user_id)
    };

    // 1. Fetch all tracked session IDs for this user
    let session_ids: Vec<String> = con.smembers(&user_sessions_key).await.unwrap_or_default();

    // 2. Delete each actix-session key
    for session_id in session_ids {
        let session_key = if namespace.is_empty() {
            format!("session:{}", session_id)
        } else {
            format!("{}:session:{}", namespace, session_id)
        };
        let _: () = con.del(session_key).await.unwrap_or(());
    }

    // 3. Delete the tracking set key itself
    let _: () = con.del(user_sessions_key).await.unwrap_or(());

    Ok(())
}
