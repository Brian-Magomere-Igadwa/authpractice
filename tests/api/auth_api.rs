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
    if std::env::var("TARPAULIN").is_ok() {
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
