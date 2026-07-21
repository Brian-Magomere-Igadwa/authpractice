use actix_session::SessionExt;
use actix_web::{
    HttpMessage, HttpResponse,
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
    error::InternalError,
    middleware::Next,
};
use std::ops::Deref;
use uuid::Uuid;

// 1. Newtype wrapper to inject into request extensions
#[derive(Copy, Clone, Debug)]
pub struct UserId(pub Uuid);

impl std::fmt::Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl Deref for UserId {
    type Target = Uuid;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// 2. Auth Middleware
pub async fn reject_anonymous_users(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<impl MessageBody>, actix_web::Error> {
    let session = req.get_session();

    // Look for the user_id stored in the session during login
    let user_id: Option<Uuid> = session
        .get("user_id")
        .map_err(actix_web::error::ErrorInternalServerError)?;

    match user_id {
        Some(user_id) => {
            // Attach the extracted UserId to request extension state
            req.extensions_mut().insert(UserId(user_id));
            next.call(req).await
        }
        None => {
            // For JSON/API setups: Return 401 Unauthorized
            let response = HttpResponse::Unauthorized().finish();
            let e = anyhow::anyhow!("The user is not authenticated");
            Err(InternalError::from_response(e, response).into())
        }
    }
}
