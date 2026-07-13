use std::net::TcpListener;

use authpractice::{
    configuration::get_configuration,
    startup::{init_metrics_recorder, run},
    telemetry::{get_subscriber, init_subscriber},
};
use sqlx::postgres::PgPoolOptions;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    //telemetry setup
    let subscriber = get_subscriber("authpractice".into(), "info".into(), std::io::stdout);
    init_subscriber(subscriber);

    // Initialize Prometheus global recorder ONCE
    init_metrics_recorder();

    // Bubble up the io::Error if we failed to bind the address
    let configuration = get_configuration().expect("Failed to read configuration.");
    let connection_pool = PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_secs(2))
        .connect_lazy_with(configuration.database.connect_options());

    let address = format!(
        "{}:{}",
        configuration.application.host, configuration.application.port
    );
    let listener = TcpListener::bind(address)?;

    run(
        listener,
        connection_pool,
        configuration.application.hibp_api_url,
    )?
    .await?;
    Ok(())
}
