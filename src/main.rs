use authpractice::{
    configuration::get_configuration,
    startup::{Application, init_metrics_recorder},
    telemetry::{get_subscriber, init_subscriber},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    //telemetry setup
    let subscriber = get_subscriber("authpractice".into(), "info".into(), std::io::stdout);
    init_subscriber(subscriber);
    // Initialize Prometheus global recorder ONCE
    init_metrics_recorder();

    // Bubble up the io::Error if we failed to bind the address
    let configuration = get_configuration().expect("Failed to read configuration.");

    Application::build(configuration.clone()).await?;

    Ok(())
}
