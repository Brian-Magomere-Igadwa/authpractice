use authpractice::configuration::{DatabaseSettings, get_configuration};
use authpractice::end_points::{AUTH, HEALTH_CHECK, USERS};
use authpractice::startup::run;
use authpractice::telemetry::{get_subscriber, init_subscriber};
use once_cell::sync::Lazy;
use secrecy::ExposeSecret;
use sqlx::{Connection, Executor, PgConnection, PgPool};
use std::env;
use std::net::TcpListener;
use uuid::Uuid;
use wiremock::MockServer;

// Ensure that the `tracing` stack is only initialised once using `once_cell`
static TRACING: Lazy<()> = Lazy::new(|| {
    let default_filter_level = "info".to_string();
    let subscriber_name = "test".to_string();
    if std::env::var("TEST_LOG").is_ok() {
        let subscriber = get_subscriber(subscriber_name, default_filter_level, std::io::stdout);
        init_subscriber(subscriber);
    } else {
        let subscriber = get_subscriber(subscriber_name, default_filter_level, std::io::sink);
        init_subscriber(subscriber);
    };

    // Safely initialize the metrics global state once for the test sweeps
    authpractice::startup::init_metrics_recorder();
});

pub struct TestApp {
    pub address: String,
    pub current_port: u16,
    pub db_pool: PgPool,
    pub api_client: reqwest::Client,
    pub hibp_server: MockServer,
}

/// Determines the network routing target for the Have I Been Pwned (HIBP) API.
pub enum HibpTarget {
    /// Routes requests to an isolated local `wiremock` server.
    /// Use this for load/stress testing to simulate network latency without
    /// assaulting the production HIBP API.
    Mock,

    /// Routes requests directly to the live production `https://api.pwnedpasswords.com`.
    /// Use this for end-to-end integration tests validating real-world password constraints.
    LiveProduction,
}

impl TestApp {
    pub async fn post_signup<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.api_client
            .post(&format!("{}{}", &self.address, USERS))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn login<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.api_client
            .post(&format!("{}{}", &self.address, AUTH))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn health_check(&self) -> reqwest::Response {
        self.api_client
            .get(&format!("{}{}", &self.address, HEALTH_CHECK))
            .send()
            .await
            .expect("Failed to execute request.")
    }
}

pub fn get_docker_accessible_url(local_port: u16) -> String {
    // If running in CI (GitHub Actions sets CI=true automatically),
    // route to the standard Linux Docker bridge gateway IP.
    let standard_linux_docker_bridge_gateway_ip = "172.17.0.1";
    let host_ip = if env::var("CI").is_ok() {
        standard_linux_docker_bridge_gateway_ip
    } else {
        // Local machines (Mac/Windows) handle this natively
        "host.docker.internal"
    };

    format!("http://{}:{}", host_ip, local_port)
}

/// Boots up a completely isolated, temporary instance of the application runtime.
///
/// This helper initializes a fresh database context, spins up the Actix Web server on a
/// random local port, and configures the HIBP integration according to the selected `hibp_target`.
///
/// # Arguments
/// * `hibp_target` - Choose `HibpTarget::Mock` to inject an artificial network latency pipeline (useful for load testing),
///   or `HibpTarget::LiveProduction` to hit the real hibp api.
/// Mostly we just use the production option when doing tests that
/// dont hit the hibp api more than once per test and the mock is preffered otherwise
/// to avoid assualting the real hibp api when performing our load tests with k6.
///
/// # Examples
/// ```rust
/// // Testing real-world validation
/// let app = spawn_app(HibpTarget::LiveProduction).await;
/// ```
pub async fn spawn_app(hibp_target: HibpTarget) -> TestApp {
    Lazy::force(&TRACING);

    // Launch the mock HIBP server first on a random local port
    let mock_hibp_server = MockServer::start().await;

    // We are simulating this because we'd need a permission to attack (PTA) to just load test
    // our own sign up, so this is a much less stressful way that avoids all that.
    // Instruct the Mock to mimic HIBP's range API and hold connections for 250ms
    // Changed "127.0.0.1:0" to "0.0.0.0:0" to allow the ephemeral k6 container to fbe able to call the api in ci.
    let listener = TcpListener::bind("0.0.0.0:0").expect("Failed to bind random port");
    // We retrieve the port assigned to us by the OS
    let port = listener.local_addr().unwrap().port();

    let mut configuration = get_configuration().expect("Failed to read configuration.");
    configuration.database.database_name = Uuid::new_v4().to_string();
    // This is entirely isolated to this test thread execution context.
    // Read the enum target to decide where to route the application configuration!
    match hibp_target {
        HibpTarget::Mock => {
            configuration.application.hibp_api_url = mock_hibp_server.uri();
        }
        HibpTarget::LiveProduction => {
            configuration.application.hibp_api_url = "https://api.pwnedpasswords.com".to_string();
        }
    }

    let connection_pool = configure_database(&configuration.database).await;
    let server = run(
        listener,
        connection_pool.clone(),
        configuration.application.hibp_api_url.clone(),
    )
    .expect("Failed to bind address");
    let _ = tokio::spawn(server);

    // We return the application address to the caller!
    let address = format!("http://127.0.0.1:{}", port);

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap();

    TestApp {
        address,
        db_pool: connection_pool,
        api_client: client,
        hibp_server: mock_hibp_server,
        current_port: port,
    }
}

async fn configure_database(config: &DatabaseSettings) -> PgPool {
    // Create database
    let mut connection = PgConnection::connect_with(&config.without_db())
        .await
        .expect("Failed to connect to Postgres");

    connection
        .execute(format!(r#"CREATE DATABASE "{}";"#, config.database_name).as_str())
        .await
        .expect("Failed to create database.");

    // Migrate database
    let connection_pool = PgPool::connect(&config.connection_string().expose_secret())
        .await
        .expect("Failed to connect to Postgres.");
    sqlx::migrate!("./migrations")
        .run(&connection_pool)
        .await
        .expect("Failed to migrate the database");
    connection_pool
}
