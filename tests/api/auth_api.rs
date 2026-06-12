use std::collections::HashMap;

use actix_web::http::StatusCode;
use fake::{Fake, Faker};

use crate::helpers::spawn_app;

#[tokio::test]
async fn mis_shaped_auth_requests_are_rejected() {
    // Arrange
    let app = spawn_app().await;
    let nonsensical_mis_shaped_payload: HashMap<String, String> = Faker.fake();

    //Act
    let response = reqwest::Client::new()
        .post(&format!("{}/auth", &app.address))
        .json(&serde_json::json!(nonsensical_mis_shaped_payload))
        .send()
        .await
        .expect("Failed to execute request.");

    // Assert
    assert_eq!(StatusCode::BAD_REQUEST, response.status().as_u16());
}
//signup

//signin
//delete
//patch
