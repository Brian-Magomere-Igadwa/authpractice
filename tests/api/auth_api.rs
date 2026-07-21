use std::{collections::HashMap, time::Duration};

use authpractice::domain::{Credentials, UserName, UserPassword, validate_credentials};
use fake::{Fake, Faker};

use wiremock::{
    Mock, ResponseTemplate,
    matchers::{method, path_regex},
};

use crate::helpers::{HibpTarget, get_docker_accessible_url, spawn_app};

use crate::authentication::validate_credentials;
use crate::domain::{Credentials, UserName, UserPassword};

#[tokio::test]
async fn mis_shaped_auth_requests_are_rejected() {
    // Arrange
    let app = spawn_app(HibpTarget::LiveProduction).await;
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
    let app = spawn_app(HibpTarget::LiveProduction).await;
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
async fn hibp_and_argon2_workload_dont_regress_availability_under_load_with_k6() {
    // House keeping
    // Skip performance testing under coverage tracking due to instrumentation overhead
    if std::env::var("TARPAULIN").is_ok() || std::env::var("CARGO_LLVM_COV").is_ok() {
        return;
    }

    // Skip entirely if running inside GitHub Actions
    if std::env::var("CI").is_ok() {
        return;
    }
    // Arrange
    // Going with the mock option to avoid assaulting the real HIBP website
    // While testing
    let app = spawn_app(HibpTarget::Mock).await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/range/[0-9A-FA-f]{5}$"))
        .respond_with(
            ResponseTemplate::new(200)
                // Default to safe password response strings because we just care about
                // confirming availability and breach of service level objective here
                .set_body_string("0018A45135D29:0")
                .set_delay(Duration::from_millis(250)), // Your 250ms load-testing bottleneck simulator
        )
        .mount(&app.hibp_server)
        .await;

    // Compile your TypeScript files locally first so Docker can read the plain JS bundle
    let pnpm_bundle = tokio::process::Command::new("pnpm")
        .current_dir("./load_tests")
        .args(["run", "bundle"])
        .output()
        .await
        .map_err(|err| format!("Failed to execute Docker k6 container: {err}"))
        .unwrap();

    assert!(
        pnpm_bundle.status.success(),
        "TypeScript compilation failed!\n\nSTDOUT:\n{}\n\nSTDERR:\n{}",
        String::from_utf8_lossy(&pnpm_bundle.stdout),
        String::from_utf8_lossy(&pnpm_bundle.stderr)
    );

    // Map 'localhost' to the special Docker host routing address
    // If app.address is "http://127.0.0.1:4321", we swap it for Docker's host bridge
    // let docker_target_address = app.address.replace("127.0.0.1", "host.docker.internal");
    // let docker_target_address = app
    //     .address
    //     .replace("127.0.0.1", "host.docker.internal")
    //     .replace("0.0.0.0", "host.docker.internal");
    let docker_target_address = get_docker_accessible_url(app.current_port);

    let project_root =
        std::env::current_dir().expect("Failed to determine current workspace directory");
    let dist_volume_mount = format!("{}/load_tests/dist:/apps/dist", project_root.display());
    // Create the host-to-container path mapping string
    let summary_volume_mount = format!(
        "{}/load_tests/benchmarks:/apps/benchmarks",
        project_root.display()
    );

    // Act: Trigger the official k6 Docker container instead of a local binary
    // to avoid environment disparities
    //Resolve an absolute path to avoid any working-directory drift inside the test runner
    let k6_run = tokio::process::Command::new("docker")
        .args([
            "run",
            "--rm",
            // Crucial for macOS network bridging out to the host loopback interface
            "--add-host",
            "host.docker.internal:host-gateway",
            // Absolute path volume mounting maps reliably inside the cargo runner
            "-v",
            &dist_volume_mount,
            // ACTUALLY MOUNT IT HERE so the container can write to your local disk
            "-v",
            &summary_volume_mount,
            // Match the working manual CLI variable mapping
            "-e",
            &format!("K6_ENV_BASE_URL={}", docker_target_address),
            "grafana/k6:latest",
            "run",
            //  Directs k6 to dump raw stat metrics to JSON before ending execution
            // keeping this off because ofcourse this is only meant to store when testing k6 on dev machine
            // "--summary-export=/apps/benchmarks/signup_scenario_tests_summary.json",
            "/apps/dist/signup_stress.js",
        ])
        .output()
        .await
        .map_err(|err| format!("Failed to execute Docker k6 container: {err}"))
        .unwrap();

    let stdout = String::from_utf8_lossy(&k6_run.stdout);
    let stderr = String::from_utf8_lossy(&k6_run.stderr);

    // 4. Assert: Still traps thresholds perfectly!
    assert!(
        k6_run.status.success(),
        "PERFORMANCE REGRESSION TRAPPED BY DOCKER K6 CONTAINER!\n\nSTDOUT:\n{}\nSTDERR:\n{}",
        stdout,
        stderr
    );
}

#[tokio::test]
async fn cant_signup_with_invalid_password_one_that_cant_be_parsed() {
    //Arrange
    let app = spawn_app(HibpTarget::LiveProduction).await;
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

#[tokio::test]
async fn sign_up_returns_201() {
    let name = "random-tom-username";
    let pass = "()^%$£**£>?-random-password";
    // Arrange
    let app = spawn_app(HibpTarget::LiveProduction).await;
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
        response.text().await
    );
}
//confirm that you can sign up with valid data
// confirm that the side effects of signing up actually work as expected, that is the user exists in the db post the handler invocation
#[tokio::test]
async fn create_user_account_persists_the_new_user() {
    let name = "random-tom-username";
    let pass = "()^%$£**£>?-random-password";
    // Arrange
    let app = spawn_app(HibpTarget::LiveProduction).await;
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
        "Something failed when signing up the user. Details : {:?}",
        response.text().await
    );

    let saved = sqlx::query!(
        r#"
        SELECT user_name FROM users WHERE user_name = $1
        "#,
        name
    )
    .fetch_one(&app.db_pool)
    .await
    .expect("User not found in postgress.");

    assert_eq!(saved.user_name, name);
}

// confirm fails if there are db errors
/// signin
#[tokio::test]
async fn login_returns_200() {
    // Arrange
    let app = spawn_app(HibpTarget::LiveProduction).await;

    // Act
    let response = app.test_user.login(&app).await;

    // Assert
    assert_eq!(
        response.status().as_u16(),
        200,
        "The API failed to accept the login request. Response body: {:?}",
        response.text().await
    );
}

#[tokio::test]
async fn invalid_login_returns_401() {
    // Arrange
    let app = spawn_app(HibpTarget::LiveProduction).await;

    // Act
    let bad_user = app.test_user.clone_with_bad_password();
    let response = bad_user.login(&app).await;

    // Assert
    assert_eq!(
        response.status().as_u16(),
        401,
        "The API failed to throw 401 for invalid credentials. Response body: {:?}",
        response.text().await
    );
}

#[tokio::test]
async fn session_persisted_on_login() {
    // Arrange
    let app = spawn_app(HibpTarget::LiveProduction).await;

    // Connect directly to Redis
    let redis_client = redis::Client::open(app.redis_uri.as_str()).unwrap();
    let mut con = redis_client
        .get_multiplexed_async_connection()
        .await
        .unwrap();

    // Act
    let response = app.test_user.login(&app).await;

    assert_eq!(
        response.status().as_u16(),
        200,
        "The API failed to accept the login request. Response body: {:?}",
        response.text().await
    );

    // 2. Query Redis for the newly created key inside our unique namespace
    let pattern = format!("{}:*", app.redis_namespace);
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg(&pattern)
        .query_async(&mut con)
        .await
        .expect("Failed to execute KEYS command in Redis");

    // Filter down specifically to the actix-session key within this namespace
    let session_key = keys
        .iter()
        .find(|key| key.contains(":session:"))
        .expect("No session keys found in Redis. The session was not persisted.");

    // Fetch the JSON string
    let redis_data: String = redis::cmd("GET")
        .arg(session_key)
        .query_async(&mut con)
        .await
        .expect("Failed to fetch session key from Redis.");

    // 3. Deserialize using serde_json::Value instead of String to handle inner JSON serialization properly
    let session_state: HashMap<String, serde_json::Value> =
        serde_json::from_str(&redis_data).expect("Failed to deserialize Redis session JSON");

    // Grab the user_id and extract it as a clean str (removing the escaped quotes)
    let session_user_id_val = session_state
        .get("user_id")
        .expect("user_id not found in session state");

    let session_user_id_str = session_user_id_val
        .as_str()
        .expect("user_id in session was not a string value");

    // Grab the user id from Postgres for the username used to log in
    let db_user = sqlx::query!(
        r#"
        SELECT user_id FROM users WHERE user_name = $1
        "#,
        app.test_user.username
    )
    .fetch_one(&app.db_pool)
    .await
    .expect("Failed to fetch user from Postgres");

    let parsed_redis_user_id: String = serde_json::from_str(session_user_id_str).unwrap();

    // Assert that the two clean UUID strings match
    assert_eq!(
        parsed_redis_user_id,
        db_user.user_id.to_string(),
        "The user_id stored in Redis session does not match the Postgres user ID!"
    );
}

#[tokio::test]
async fn login_attempts_exceeding_threshold_returns_429() {
    let app = spawn_app(HibpTarget::LiveProduction).await;

    let redis_client = redis::Client::open(app.redis_uri.as_str()).unwrap();
    let mut con = redis_client
        .get_multiplexed_async_connection()
        .await
        .unwrap();

    let bad_user = app.test_user.clone_with_bad_password();

    // Act & Assert: Track failures up to 3 attempts
    for attempt in 1..=2 {
        let response = bad_user.login(&app).await;
        assert_ne!(response.status().as_u16(), 429);

        // Fetch your custom brute-force tracking key inside your namespace prefix
        let rate_limit_key = format!(
            "{}:login_attempts:{}",
            app.redis_namespace, app.test_user.username
        );
        let state_json: String = redis::cmd("GET")
            .arg(&rate_limit_key)
            .query_async(&mut con)
            .await
            .expect("Failed to fetch login failure state");

        // Validate structure matches the serialized `LoginTracker`
        let state: serde_json::Value = serde_json::from_str(&state_json).unwrap();

        assert_eq!(state["failures"].as_i64().unwrap(), attempt as i64);
        assert_eq!(state["is_quarantined"].as_bool().unwrap(), false);
    }

    // 3rd attempt exceeds threshold
    let response = bad_user.login(&app).await;
    let status = response.status().as_u16();
    // 1. Parse the JSON body immediately (this consumes the response stream)
    let body_json: serde_json::Value = response
        .json()
        .await
        .expect("Failed to parse 429 response body as JSON");

    // 2. Assert status code (include the structured JSON in the failure message if it drops)
    assert_eq!(
        status, 429,
        "Exceeding 3 failed attempts did not return 429. Payload: {:?}",
        body_json
    );

    // 3. Assert on the structured machine-readable error classification field
    assert_eq!(
        body_json["error"], "Too Many Requests",
        "Unexpected error payload type classification. Found payload: {:?}",
        body_json
    );
}

#[tokio::test]
async fn user_in_quarantine_continually_gets_429() {
    // Arrange
    let app = spawn_app(HibpTarget::LiveProduction).await;

    let bad_user = app.test_user.clone_with_bad_password();

    // Act: Exceed 3 failed attempts to trigger quarantine
    for _ in 0..4 {
        let _ = bad_user.login(&app).await;
    }

    // Assert: Attempt to login again immediately while under quarantine
    let subsequent_response = bad_user.login(&app).await;

    assert_eq!(
        subsequent_response.status().as_u16(),
        429,
        "The user was allowed to attempt login again during their quarantine window."
    );
}

#[tokio::test]
async fn user_can_login_successfully_after_quarantine_expires() {
    // Arrange
    let app = spawn_app(HibpTarget::LiveProduction).await;

    let bad_user = app.test_user.clone_with_bad_password();

    // Act: Put the user into quarantine by exceeding 3 failures
    for _ in 0..4 {
        let _ = bad_user.login(&app).await;
    }
    //assert that the user is getting 429 at this point
    let last_status_code = bad_user.login(&app).await.status().as_u16();
    assert_eq!(
        last_status_code, 429,
        "Expected the status code to be 429 got otherwise."
    );

    // Wait out the quarantine period (configured to a short 2s window via configuration setup in spawn_app)
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Act: Attempt to login using correct credentials after quarantine expires
    let recovery_response = app.test_user.login(&app).await;

    // Assert: User is allowed back in
    assert_eq!(
        recovery_response.status().as_u16(),
        200,
        "User failed to log in with 200 OK after the quarantine window expired."
    );
}

#[tokio::test]
async fn login_creates_exactly_one_session_and_no_duplicates() {
    let app = spawn_app(HibpTarget::LiveProduction).await;

    let redis_client = redis::Client::open(app.redis_uri.as_str()).unwrap();
    let mut con = redis_client
        .get_multiplexed_async_connection()
        .await
        .unwrap();

    // Log in successfully
    let response = app.test_user.login(&app).await;
    assert_eq!(response.status().as_u16(), 200);

    // Query keys scoped to this namespace instance context
    let pattern = format!("{}:*", app.redis_namespace);
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg(&pattern)
        .query_async(&mut con)
        .await
        .unwrap();

    // Filter to isolate ONLY your namespaced actix-session keys
    let tracker_prefix = format!("{}:login_attempts:", app.redis_namespace);
    let session_keys: Vec<&String> = keys
        .iter()
        .filter(|key| !key.starts_with(&tracker_prefix))
        .collect();

    assert_eq!(
        session_keys.len(),
        1,
        "Expected exactly 1 session key to exist in Redis, but found: {:?}",
        session_keys
    );
}

// Write a test for load testing login ep Needs updating to match spec
#[tokio::test]
async fn login_latency_doesnt_drop_past_threshold_and_targets_under_load_with_k6() {
    // House keeping
    // Skip performance testing under coverage tracking due to instrumentation overhead
    if std::env::var("TARPAULIN").is_ok() || std::env::var("CARGO_LLVM_COV").is_ok() {
        return;
    }
    // Skip entirely if running inside GitHub Actions
    if std::env::var("CI").is_ok() {
        return;
    }

    // Arrange
    // Going with the mock option to avoid assaulting the real HIBP website while testing
    let app = spawn_app(HibpTarget::Mock).await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/range/[0-9A-FA-f]{5}$"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("0018A45135D29:0")
                .set_delay(Duration::from_millis(250)),
        )
        .mount(&app.hibp_server)
        .await;

    // Compile your TypeScript files locally first so Docker can read the plain JS bundle
    let pnpm_bundle = tokio::process::Command::new("pnpm")
        .current_dir("./load_tests")
        .args(["run", "bundle"])
        .output()
        .await
        .map_err(|err| format!("Failed to execute TypeScript compiler bundle sequence: {err}"))
        .unwrap();

    assert!(
        pnpm_bundle.status.success(),
        "TypeScript compilation failed!\n\nSTDOUT:\n{}\n\nSTDERR:\n{}",
        String::from_utf8_lossy(&pnpm_bundle.stdout),
        String::from_utf8_lossy(&pnpm_bundle.stderr)
    );

    // Map 'localhost' to the special Docker host routing address
    let docker_target_address = get_docker_accessible_url(app.current_port);

    let project_root =
        std::env::current_dir().expect("Failed to determine current workspace directory");
    let dist_volume_mount = format!("{}/load_tests/dist:/apps/dist", project_root.display());
    let summary_volume_mount = format!(
        "{}/load_tests/benchmarks:/apps/benchmarks",
        project_root.display()
    );

    // Act: Trigger the official k6 Docker container
    let k6_run = tokio::process::Command::new("docker")
        .args([
            "run",
            "--rm",
            // Crucial for network bridging out to the host loopback interface
            "--add-host",
            "host.docker.internal:host-gateway",
            // Absolute path volume mounting maps reliably inside the cargo runner
            "-v",
            &dist_volume_mount,
            "-v",
            &summary_volume_mount,
            // Match the working manual CLI variable mapping
            "-e",
            &format!("K6_ENV_BASE_URL={}", docker_target_address),
            // Inject the runtime test credentials to force k6 down the heavy Argon2 path
            "-e",
            &format!("TARGET_USER_NAME={}", app.test_user.username),
            "-e",
            &format!("TARGET_USER_PASSWORD={}", app.test_user.password),
            "grafana/k6:latest",
            "run",
            "/apps/dist/login_stress.js",
        ])
        .output()
        .await
        .map_err(|err| format!("Failed to execute Docker k6 container: {err}"))
        .unwrap();

    let stdout = String::from_utf8_lossy(&k6_run.stdout);
    let stderr = String::from_utf8_lossy(&k6_run.stderr);

    // Assert: Traps performance regressions or structural threshold failures perfectly!
    assert!(
        k6_run.status.success(),
        "LOGIN PERFORMANCE REGRESSION TRAPPED BY DOCKER K6 CONTAINER!\n\nSTDOUT:\n{}\nSTDERR:\n{}",
        stdout,
        stderr
    );
}

///patch
#[tokio::test]
async fn updating_profile_with_session_does_indeed_update_the_user_in_db() {
    // Arrange
    let app = spawn_app(HibpTarget::LiveProduction).await;

    // 1. Log in existing user
    let login_res = app.test_user.login(&app).await;
    assert_eq!(
        login_res.status().as_u16(),
        200,
        "Setup failed: Could not log in test user before attempting profile update."
    );

    let new_username_str = "brand-new-updated-username";
    let new_password_str = "Updated-Secure-Pass-123!#";

    let update_payload = serde_json::json!({
        "username": new_username_str,
        "password": new_password_str
    });

    // Act
    // 2. Call PUT /user with active session
    let update_response = app.put_user_profile(&update_payload).await;

    assert_eq!(
        update_response.status().as_u16(),
        200,
        "The API failed to update the user profile. Response body: {:?}",
        update_response.text().await
    );

    // Assert
    // 3. Re-parse domain types for the new credentials
    let new_username = UserName::parse(new_username_str)
        .expect("Failed to parse test username into UserName domain type");

    let new_password = UserPassword::parse(new_password_str.to_string(), &app.hibp_url)
        .await
        .expect("Failed to parse test password into UserPassword domain type");

    let credentials = Credentials {
        username: new_username,
        password: new_password,
    };

    // 4. Reuse validate_credentials directly against the DB pool!
    let validated_user_id = validate_credentials(credentials, &app.db_pool)
        .await
        .expect("Failed to validate updated credentials against Postgres!");

    // 5. Confirm the returned user_id matches our original user
    assert_eq!(
        validated_user_id, app.test_user.user_id,
        "The validated user ID does not match the updated user!"
    );
}

#[tokio::test]
async fn updating_profile_without_session_yield_rejection() {
    // Arrange
    let app = spawn_app(HibpTarget::LiveProduction).await;
    let new_user_profile_body = serde_json::json!({
        "name": name,
        "password": pass
    });

    // Act
    //deliberately missing login step guaranteeing no session
    let response = app.put_user(&new_user_profile_body).await;
    let status_code = response.status().as_u16();

    // Assert
    assert_eq!(
        status_code,
        403,
        "Expected 403 for attempts to update profile without an existing session but got a different status code. Response body: {:?}",
        response.text().await
    );
}

/// Scenario C: Fake / Spoofed Session Token leads to rejection and quarantine
#[tokio::test]
async fn updating_profile_with_invalid_or_fake_token_returns_rejection() {
    // Arrange
    let app = spawn_app(HibpTarget::LiveProduction).await;

    let update_payload = serde_json::json!({
        "username": "spoofed-user-attempt",
        "password": "Some-New-Password-123!"
    });

    // Act - Send request with a completely fabricated session cookie
    let response = app
        .put_user_profile_with_raw_cookie(&update_payload, "actix-session=fake_invalid_token_12345")
        .await;

    // Assert - Should return 401/403
    assert_eq!(
        response.status().as_u16(),
        401, // or 403 depending on your middleware setup
        "Expected 401/403 for forged session token, but got a different status. Response body: {:?}",
        response.text().await
    );
}

/// Partial Update: Updating ONLY the username preserves the existing password
#[tokio::test]
async fn partial_update_username_only_preserves_existing_password() {
    // Arrange
    let app = spawn_app(HibpTarget::LiveProduction).await;

    // Log in
    let login_res = app.test_user.login(&app).await;
    assert_eq!(
        login_res.status().as_u16(),
        200,
        "Setup failed: login failed."
    );

    let new_username_str = "new-only-username-change";
    let update_payload = serde_json::json!({
        "username": new_username_str
        // Password deliberately omitted
    });

    // Act
    let update_response = app.put_user_profile(&update_payload).await;
    assert_eq!(
        update_response.status().as_u16(),
        200,
        "Partial profile update failed. Details: {:?}",
        update_response.text().await
    );

    // Assert - Validate that original password STILL works with the NEW username
    let new_username = UserName::parse(new_username_str).unwrap();
    let original_password = UserPassword::parse(app.test_user.password.clone(), &app.hibp_url)
        .await
        .unwrap();

    let credentials = Credentials {
        username: new_username,
        password: original_password,
    };

    let validated_id = validate_credentials(credentials, &app.db_pool)
        .await
        .expect("Failed to validate user credentials with new username and original password!");

    assert_eq!(validated_id, app.test_user.user_id);
}

/// Partial Update: Updating ONLY the password preserves the existing username
#[tokio::test]
async fn partial_update_password_only_preserves_existing_username() {
    // Arrange
    let app = spawn_app(HibpTarget::LiveProduction).await;

    let login_res = app.test_user.login(&app).await;
    assert_eq!(
        login_res.status().as_u16(),
        200,
        "Setup failed: login failed."
    );

    let new_password_str = "Brand-New-Password-Only-456!";
    let update_payload = serde_json::json!({
        "password": new_password_str
        // Username deliberately omitted
    });

    // Act
    let update_response = app.put_user_profile(&update_payload).await;
    assert_eq!(
        update_response.status().as_u16(),
        200,
        "Partial profile update (password only) failed. Details: {:?}",
        update_response.text().await
    );

    // Assert - Validate original username works with NEW password
    let original_username = UserName::parse(&app.test_user.username).unwrap();
    let new_password = UserPassword::parse(new_password_str.to_string(), &app.hibp_url)
        .await
        .unwrap();

    let credentials = Credentials {
        username: original_username,
        password: new_password,
    };

    let validated_id = validate_credentials(credentials, &app.db_pool)
        .await
        .expect("Failed to validate user credentials with original username and new password!");

    assert_eq!(validated_id, app.test_user.user_id);
}

/// Scenario B/C Boundary: Quarantined user hitting update endpoint gets 429
#[tokio::test]
async fn quarantined_client_is_blocked_from_profile_update() {
    // Arrange
    let app = spawn_app(HibpTarget::LiveProduction).await;

    // 1. Force client into quarantine by repeatedly hitting /auth with bad passwords
    let bad_user = app.test_user.clone_with_bad_password();
    for _ in 0..4 {
        let _ = bad_user.login(&app).await;
    }

    let update_payload = serde_json::json!({
        "username": "quarantined-attempt"
    });

    // Act
    let response = app.put_user_profile(&update_payload).await;

    // Assert
    assert_eq!(
        response.status().as_u16(),
        429,
        "Expected 429 Too Many Requests for quarantined user attempting update, got different code. Response: {:?}",
        response.text().await
    );
}

//delete
