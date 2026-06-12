use std::collections::HashMap;

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
    assert_eq!(reqwest::StatusCode::BAD_REQUEST, response.status().as_u16());
}
//signup
//make sure the payload you are passing will be rejected if our parser doesnt give it a clean bill of health
#[tokio::test]
async fn cant_signup_with_invalid_user_name() {
    //Arrange
    let app = spawn_app().await;
    let more_than_256_characters = "a".repeat(257);
    let name_with_only_white_spaces = " ".to_string();
    let empty_name = "".to_string();
    let forward_slash = "/".to_string();
    let left_parenthesis = "(".to_string();
    let right_parenthesis = ")".to_string();
    let double_quote = "\"".to_string();
    let left_angle_bracket = "<".to_string();
    let right_angle_bracket = ">".to_string();
    let backslash = "\\".to_string();
    let left_curly_brace = "{".to_string();
    let right_curly_brace = "}".to_string();
    let valid_pass = "test1234";
    let test_cases = vec![
        (more_than_256_characters, "More than 256 characters."),
        (name_with_only_white_spaces, "No whitespaces allowed."),
        (empty_name, "No empty names allowed."),
        (forward_slash, "No forward slash allowed."),
        (left_parenthesis, "No left parenthesis allowed."),
        (right_parenthesis, "No right parenthesis allowed."),
        (double_quote, "No double quote names allowed."),
        (left_angle_bracket, "No left angle bracket allowed."),
        (right_angle_bracket, "No right angle bracket allowed."),
        (backslash, "No backslash allowed."),
        (left_curly_brace, "No left curly allowed."),
        (right_curly_brace, "No right curly allowed."),
    ];

    for (invalid_name, error_message) in test_cases {
        //Act
        let response = reqwest::Client::new()
            .post(format!("{}/auth", &app.address))
            .json(&serde_json::json!(
                {
                    "name":&invalid_name,
                    "password":valid_pass
                }
            ))
            .send()
            .await
            .expect("Failed to execute request.");

        //Assert
        assert_eq!(
            reqwest::StatusCode::BAD_REQUEST,
            response.status().as_u16(),
            "{}",
            error_message
        )
    }
}
//signin
//delete
//patch
