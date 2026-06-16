use std::collections::HashMap;

use authpractice::end_points::AUTH;
use fake::{Fake, Faker};
use sha1::digest::array::AsArrayMut;

use crate::helpers::spawn_app;

#[tokio::test]
async fn mis_shaped_auth_requests_are_rejected() {
    // Arrange
    let app = spawn_app().await;
    let nonsensical_mis_shaped_payload: HashMap<String, String> = Faker.fake();
    let signup_body = serde_json::json!(nonsensical_mis_shaped_payload);

    //Act
    let response = app.post_signup(&signup_body).await;

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
        let signup_body = serde_json::json!(
            {
                "name":&invalid_name,
                "password":valid_pass
            }
        );
        //Act
        let response = app.post_signup(&signup_body).await;

        //Assert
        assert_eq!(
            reqwest::StatusCode::BAD_REQUEST,
            response.status().as_u16(),
            "{}",
            error_message
        )
    }
}

#[tokio::test]
async fn cant_signup_with_invalid_password_one_that_cant_be_parsed() {
    //Arrange
    let app = spawn_app().await;
    let below_agreed_characters = "";
    let more_than_agreed_characters = &"a".repeat(65);
    let password_that_exists_in_block_list = "password123";
    let valid_user_name = "johndoe";

    let test_cases = vec![
        (
            below_agreed_characters,
            "No password with less than 8(from NIST) characters allowed.",
        ),
        (
            more_than_agreed_characters,
            "No password with more than 64(from NIST) characters allowed.",
        ),
        (
            password_that_exists_in_block_list,
            "No password that exists in block list is allowed.",
        ),
    ];

    for (invalid_pass, error_message) in test_cases {
        let signup_body = serde_json::json!(
            {
                "name":&valid_user_name,
                "password":&invalid_pass,
            }
        );
        //Act
        let response = app.post_signup(&signup_body).await;
        //Assert
        assert_eq!(
            reqwest::StatusCode::BAD_REQUEST,
            response.status().as_u16(),
            "{}",
            error_message
        )
    }
}

//confirm that you can sign up with valid data
// confirm that the side effects of signing up actually work as expected, that is the user exists in the db post the handler invocation
#[tokio::test]
async fn sign_up_returns_201() {
    let name = "random-tom-username";
    let pass = "()^%$£**£>?-random-password";
    // Arrange
    let app = spawn_app().await;
    let signup_body = serde_json::json!({
        "name": name,
        "password": pass
    });

    // Act
    let response = app.post_signup(&signup_body).await;

    // Assert
    assert_eq!(
        response.status().as_u16(),
        201,
        "The API failed to accept the signup request. Response body: {:?}",
        response.text().await // Prints the server's error message if it fails
    );
}
//confirm that you can sign up with valid data
// confirm that the side effects of signing up actually work as expected, that is the user exists in the db post the handler invocation
#[tokio::test]
async fn create_user_account_persists_the_new_user() {
    let name = "random-tom-username";
    let pass = "()^%$£**£>?-random-password";
    // Arrange
    let app = spawn_app().await;
    let signup_body = serde_json::json!({
        "name": name,
        "password": pass
    });

    // Act
     app.post_signup(&signup_body).await;

    // Assert
    let saved = sqlx::query!("SELECT user_name FROM users",)
        .fetch_one(&app.db_pool)
        .await
        .expect("Failed to fetch saved user");

    assert_eq!(saved.user_name, name);
}

// confirm fails if there are db errors
//signin
//delete
//patch
