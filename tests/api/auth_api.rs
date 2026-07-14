use std::{collections::HashMap, time::Duration};

use fake::{Fake, Faker};

use wiremock::{
    Mock, ResponseTemplate,
    matchers::{method, path_regex},
};

use crate::helpers::{HibpTarget, get_docker_accessible_url, spawn_app};

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
async fn session_persisted_on_login() {
    // Arrange
    let app = spawn_app(HibpTarget::LiveProduction).await;

    // Connect directly to Redis
    let redis_client = redis::Client::open(app.redis_uri.as_str()).unwrap();
    let mut con = redis_client
        .get_multiplexed_async_connection()
        .await
        .unwrap();

    // 1. FLUSH REDIS to clear out stale sessions from previous test runs
    let _: () = redis::cmd("FLUSHDB")
        .query_async(&mut con)
        .await
        .expect("Failed to flush test Redis database");

    // Act
    let response = app.test_user.login(&app).await;

    assert_eq!(
        response.status().as_u16(),
        200,
        "The API failed to accept the login request. Response body: {:?}",
        response.text().await
    );

    // 2. Query Redis for the newly created key (it will be the only one now)
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg("*")
        .query_async(&mut con)
        .await
        .expect("Failed to execute KEYS command in Redis");

    let redis_key = keys
        .first()
        .expect("No session keys found in Redis. The session was not persisted.");

    // Fetch the JSON string
    let redis_data: String = redis::cmd("GET")
        .arg(redis_key)
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

// Write a red test that confirms that indeed multiple login attempts of the same user that exceed our threshold lead to 429 with error try again later from a subsequent login attempt atop the threshold.
#[tokio::test]
async fn login_attempts_exceeding_threshold_returns_429() {
    // Arrange
    let app = spawn_app(HibpTarget::LiveProduction).await;

    // Connect to Redis and flush it to ensure rate-limiting state is clean
    let redis_client = redis::Client::open(app.redis_uri.as_str()).unwrap();
    let mut con = redis_client
        .get_multiplexed_async_connection()
        .await
        .unwrap();

    let _: () = redis::cmd("FLUSHDB")
        .query_async(&mut con)
        .await
        .expect("Failed to flush test Redis database");

    // Act & Assert
    // Simulate multiple login attempts to exceed your application's threshold.
    // Replace 10 with a number slightly higher than your planned rate-limit threshold.
    let mut last_status = 200;
    for _ in 0..10 {
        let response = app.test_user.login(&app).await;
        last_status = response.status().as_u16();

        if last_status == 429 {
            break;
        }
    }

    // This should fail (turn red) if your app does not yet support rate limiting,
    // as all attempts would return 200.
    assert_eq!(
        last_status, 429,
        "The application did not return a 429 status code after multiple login attempts."
    );
}

// Write a red test to confirm that indeed if a user is put under quarantine for multiple login attempts that they will keep getting 429.
#[tokio::test]
async fn user_in_quarantine_continually_gets_429() {
    // Arrange
    let app = spawn_app(HibpTarget::LiveProduction).await;

    // Clean slate
    let redis_client = redis::Client::open(app.redis_uri.as_str()).unwrap();
    let mut con = redis_client
        .get_multiplexed_async_connection()
        .await
        .unwrap();

    let _: () = redis::cmd("FLUSHDB")
        .query_async(&mut con)
        .await
        .expect("Failed to flush test Redis database");

    // Act: Fire off enough requests to trigger quarantine (429)
    let mut triggered_429 = false;
    for _ in 0..10 {
        let response = app.test_user.login(&app).await;
        if response.status().as_u16() == 429 {
            triggered_429 = true;
            break;
        }
    }

    assert!(
        triggered_429,
        "Failed to initiate rate-limiting state for the test."
    );

    // Act & Assert: Attempt to login *again* immediately while under quarantine
    let subsequent_response = app.test_user.login(&app).await;

    // This will turn red if your rate limiter does not enforce a quarantine/block window
    assert_eq!(
        subsequent_response.status().as_u16(),
        429,
        "The user was allowed to attempt login again during their quarantine window."
    );
}

