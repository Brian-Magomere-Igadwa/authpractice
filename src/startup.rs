use std::net::TcpListener;

use actix_web::{App, HttpResponse, HttpServer, Responder, dev::Server, web};

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use sqlx::PgPool;
use tracing_actix_web::TracingLogger;

use crate::{
    end_points::{HEALTH_CHECK, USERS},
    routes::{create_user_account, health_check},
};

pub struct ApplicationBaseUrl(pub String);

use std::sync::OnceLock;

static METRICS_HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

pub fn init_metrics_recorder() {
    // Ensure initialization only runs ONCE across the entire lifecycle
    METRICS_HANDLE.get_or_init(|| {
        PrometheusBuilder::new()
            .install_recorder()
            .expect("Failed to install Prometheus recorder")
    });
}

async fn metrics_endpoint(db_pool: web::Data<PgPool>) -> impl Responder {
    // Safely read from the cell and sample pool state
    if let Some(handle) = METRICS_HANDLE.get() {
        let total_connections = db_pool.size();
        let idle_connections = db_pool.num_idle();

        // Active connections are total open connections minus the idle ones
        let active_connections = total_connections.saturating_sub(idle_connections as u32);

        // 2. Report the values cleanly to your Prometheus gauges
        metrics::gauge!("db_pool_connections_active").set(active_connections as f64);
        metrics::gauge!("db_pool_connections_idle").set(idle_connections as f64);

        HttpResponse::Ok()
            .content_type("text/plain; version=0.0.4; charset=utf-8")
            .body(handle.render())
    } else {
        HttpResponse::InternalServerError().body("Metrics recorder not initialized")
    }
}

pub fn run(
    listener: TcpListener,
    db_pool: PgPool,
    hibp_api_url: String,
) -> Result<Server, std::io::Error> {
    // Wrap the pool using web::Data, which boils down to an Arc smart pointer
    let connection = web::Data::new(db_pool);
    let base_url = web::Data::new(ApplicationBaseUrl(hibp_api_url));
    let server = HttpServer::new(move || {
        App::new()
            .wrap(TracingLogger::default())
            .route(HEALTH_CHECK, web::get().to(health_check))
            .route(USERS, web::post().to(create_user_account))
            .route("/metrics", web::get().to(metrics_endpoint))
            // Register the connection as part of the application state
            // Get a pointer copy and attach it to the application state
            .app_data(connection.clone())
            .app_data(base_url.clone())
    })
    .listen(listener)?
    .run();

    Ok(server)
}
