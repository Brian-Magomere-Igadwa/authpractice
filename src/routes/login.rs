use std::fmt::Debug;

use actix_web::{HttpResponse, ResponseError, http::StatusCode, web};
use chrono::{DateTime, Duration, Utc};
use redis::{AsyncCommands, aio::MultiplexedConnection};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::{
    configuration::Settings,
    domain::{AuthError, Credentials, UserName, UserPassword, validate_credentials},
    routes::{FormData, error_chain_fmt},
    session_state::TypedSession,
    startup::ApplicationBaseUrl,
};

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct LoginTracker {
    pub failures: i32,
    pub is_quarantined: bool,
    pub quarantined_until: Option<DateTime<Utc>>,
}

impl LoginTracker {
    /// Helper to generate a namespaced key
    fn make_key(namespace: &str, username: &str) -> String {
        if namespace.is_empty() {
            format!("login_attempts:{}", username)
        } else {
            format!("{}:login_attempts:{}", namespace, username)
        }
    }

    /// Fetches the tracker state for a given username from Redis.
    pub async fn fetch(
        con: &mut MultiplexedConnection,
        namespace: &str,
        username: &str,
    ) -> Result<Self, LoginError> {
        let tracker_key = Self::make_key(namespace, username);
        let tracker_json: Option<String> = con
            .get(&tracker_key)
            .await
            .map_err(|e| LoginError::UnexpectedError(e.into()))?;

        match tracker_json {
            Some(json) => Ok(serde_json::from_str(&json).unwrap_or_default()),
            None => Ok(Self::default()),
        }
    }

    /// Checks if the user is currently quarantined. Resets the tracker if the quarantine expired.
    pub fn check_quarantine(&mut self) -> Result<(), LoginError> {
        if self.is_quarantined
            && let Some(until) = self.quarantined_until
        {
            if Utc::now() < until {
                return Err(LoginError::TooManyRequests);
            } else {
                // Quarantine expired, reset tracking
                *self = Self::default();
            }
        }
        Ok(())
    }

    /// Increments failures, applies quarantine if limit exceeded, and saves state to Redis.
    async fn register_failure(
        &mut self,
        con: &mut MultiplexedConnection,
        namespace: &str,
        username: &str,
        quarantine_seconds: i64,
    ) -> Result<(), LoginError> {
        self.failures += 1;
        if self.failures >= 3 {
            self.is_quarantined = true;
            self.quarantined_until = Some(Utc::now() + Duration::seconds(quarantine_seconds));
        }

        let tracker_key = Self::make_key(namespace, username);
        let serialized =
            serde_json::to_string(&self).map_err(|e| LoginError::UnexpectedError(e.into()))?;

        // Expire tracker entry after 1 day (86400 seconds)
        let _: () = con
            .set_ex(&tracker_key, serialized, 86400)
            .await
            .map_err(|e| LoginError::UnexpectedError(e.into()))?;

        Ok(())
    }

    /// Clears any tracking data from Redis upon successful authentication.
    async fn clear(
        con: &mut MultiplexedConnection,
        namespace: &str,
        username: &str,
    ) -> Result<(), LoginError> {
        let tracker_key = Self::make_key(namespace, username);
        let _: () = con
            .del(&tracker_key)
            .await
            .map_err(|e| LoginError::UnexpectedError(e.into()))?;
        Ok(())
    }
}
// --- Handler ---

pub async fn login(
    form: web::Json<FormData>,
    pool: web::Data<PgPool>,
    session: TypedSession,
    hibp_url: web::Data<ApplicationBaseUrl>,
    settings: web::Data<Settings>,
    redis_client: web::Data<redis::Client>,
) -> Result<HttpResponse, LoginError> {
    let username_str = &form.0.name;
    let password = UserPassword::parse(form.0.password, &hibp_url.0)
        .await
        .map_err(LoginError::ValidationError)?;
    let username = UserName::parse(username_str).map_err(LoginError::ValidationError)?;

    tracing::Span::current().record("username", tracing::field::display(username_str));

    let mut con = redis_client
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| LoginError::UnexpectedError(e.into()))?;

    // Extract namespace from settings configuration context
    let namespace = &settings.application.redis_namespace;

    // 1. Rate limiting checks
    let mut tracker = LoginTracker::fetch(&mut con, namespace, username_str).await?;
    tracker.check_quarantine()?;

    // 2. Authenticate
    match validate_credentials(Credentials { username, password }, &pool).await {
        Ok(user_id) => {
            tracing::Span::current().record("user_id", tracing::field::display(&user_id));

            LoginTracker::clear(&mut con, namespace, username_str).await?;

            session.renew();
            session
                .insert_user_id(user_id)
                .map_err(|e| LoginError::UnexpectedError(e.into()))?;

            // Generate a fresh unique session ID for Redis tracking
            let new_session_id = uuid::Uuid::new_v4().to_string();
            session
                .insert_session_id(new_session_id)
                .map_err(|e| LoginError::UnexpectedError(e.into()))?;

            // Strategy A Guard: Track active session token under user's Redis tracking set
            if let Ok(Some(session_id)) = session.get_session_id() {
                let user_session_key = if namespace.is_empty() {
                    format!("user_sessions:{}", user_id)
                } else {
                    format!("{}:user_sessions:{}", namespace, user_id)
                };

                let session_ttl = settings.application.session_ttl_seconds;

                let _: () = con
                    .sadd(&user_session_key, &session_id)
                    .await
                    .map_err(|e| LoginError::UnexpectedError(e.into()))?;

                let _: () = con
                    .expire(&user_session_key, session_ttl)
                    .await
                    .map_err(|e| LoginError::UnexpectedError(e.into()))?;
            }

            Ok(HttpResponse::Ok().finish())
        }
        Err(auth_err) => {
            if let AuthError::InvalidCredentials(_) = auth_err {
                tracker
                    .register_failure(
                        &mut con,
                        namespace,
                        username_str,
                        settings.application.quarantine_duration_seconds,
                    )
                    .await?;

                if tracker.is_quarantined {
                    return Err(LoginError::TooManyRequests);
                }
            }

            let e = match auth_err {
                AuthError::InvalidCredentials(_) => LoginError::AuthError(auth_err.into()),
                AuthError::UnexpectedError(_) => LoginError::UnexpectedError(auth_err.into()),
            };
            Err(e)
        }
    }
}

// --- Errors ---

#[derive(thiserror::Error)]
pub enum LoginError {
    #[error("{0}")]
    ValidationError(String),
    #[error("Authentication failed")]
    AuthError(#[source] anyhow::Error),
    #[error("Too many requests. Please try again later.")]
    TooManyRequests,
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
