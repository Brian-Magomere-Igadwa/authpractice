use std::fmt::Debug;

use actix_web::http::StatusCode;
use actix_web::{HttpResponse, ResponseError, web};

use sqlx::PgPool;

// use validator::validate_email;
use crate::domain::{User, UserName, UserPassword};

#[derive(serde::Deserialize)]
pub struct FormData {
    name: String,
    password: String,
}

impl User {
    /// Custom async constructor to bypass TryFrom's synchronous limitation
    pub async fn try_from_form(value: FormData) -> Result<Self, String> {
        let name = UserName::parse(value.name)?;

        // Now you can cleanly .await your async password parser!
        let password = UserPassword::parse(value.password).await?;

        Ok(Self { name, password })
    }
}

#[derive(thiserror::Error)]
pub enum SignUpError {
    #[error("{0}")]
    ValidationError(String),
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
            SignUpError::UnexpectedError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
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
    skip(form, pool),
    fields(
        user_name = %form.name,
    )
)]
pub async fn create_user_account(
    form: web::Json<FormData>,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, SignUpError> {
    let form_data = form.into_inner();

    // 2. Call the associated async function on User and explicitly .await it
    let new_user = User::try_from_form(form_data)
        .await
        .map_err(SignUpError::ValidationError)?;

    // 3. Insert the newly verified domain model into your DB
    match insert_user(&pool, &new_user).await {
        Ok(_) => Ok(HttpResponse::Created().finish()),
        Err(e) => Err(SignUpError::UnexpectedError(e.into())),
    }
}

// Assuming user already created an account
// We will be getting a user profile by email (unique per schema)
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
pub async fn insert_user(pool: &PgPool, new_user: &User) -> Result<(), sqlx::Error> {
    //     let _outcome = sqlx::query!(
    //         r#"
    // INSERT INTO users (id, email, name, signedup_at)
    // VALUES ($1, $2, $3, $4)
    // "#,
    //         Uuid::new_v4(),
    //         new_user.email.as_ref(),
    //         new_user.name.as_ref(),
    //         Utc::now()
    //     )
    //     .execute(pool)
    //     .await
    //     .map_err(|e| {
    //         tracing::error!("Failed to execute query: {:?}", e);
    //     });
    Ok(())
}
