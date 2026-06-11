use crate::helpers::spawn_app;

#[tokio::test]
async fn requests_missing_authorization_are_rejected() {
    // Arrange
    let app = spawn_app().await;

    //Act
    let response = reqwest::Client::new()
        .post(&format!("{}/auth", &app.address))
        .json(&serde_json::json!({
        "title": "Test title",
        "content": {
            "text": "Test body as plain text",
        "html": "<p>Test body as HTML</p>",
        }
        }))
        .send()
        .await
        .expect("Failed to execute request.");

    // Assert
    assert_eq!(401, response.status().as_u16());
    assert_eq!(
        r#"Basic realm="publish""#,
        response.headers()["WWW-Authenticate"]
    );
}

//signup

//signin
//delete
//patch
