use std::fmt::{Debug, Display};

use authpractice::{
    configuration::get_configuration,
    startup::{Application, init_metrics_recorder},
    telemetry::{get_subscriber, init_subscriber},
};
use tokio::task::JoinError;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    //telemetry setup
    let subscriber = get_subscriber("authpractice".into(), "info".into(), std::io::stdout);
    init_subscriber(subscriber);
    // Initialize Prometheus global recorder ONCE
    init_metrics_recorder();

    // Bubble up the io::Error if we failed to bind the address
    let configuration = get_configuration().expect("Failed to read configuration.");

    let application = Application::build(configuration.clone()).await?;
    let application_task = tokio::spawn(application.run_until_stopped());
    let outcome = application_task.await;
    report_exit("API", outcome);

    Ok(())
}

fn report_exit(task_name: &str, outcome: Result<Result<(), impl Debug + Display>, JoinError>) {
    match outcome {
        Ok(Ok(())) => {
            tracing::info!("{} has exited", task_name)
        }
        Ok(Err(e)) => {
            tracing::error!(
                error.cause_chain = ?e,
                error.message = %e,
                "{} failed",
                task_name
            )
        }
        Err(e) => {
            tracing::error!(
                error.cause_chain = ?e,
                error.message = %e,
                "{}' task failed to complete",
                task_name
            )
        }
    }
}
