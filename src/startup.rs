use std::net::TcpListener;

use actix_web::{App, HttpServer, dev::Server, web};

use sqlx::PgPool;
use tracing_actix_web::TracingLogger;

use crate::routes::health_check;

pub fn run(listener: TcpListener, db_pool: PgPool) -> Result<Server, std::io::Error> {
    // Wrap the pool using web::Data, which boils down to an Arc smart pointer
    let connection = web::Data::new(db_pool);
    let server = HttpServer::new(move || {
        App::new()
            .wrap(TracingLogger::default())
            .route("/health_check", web::get().to(health_check))
            // Register the connection as part of the application state
            // Get a pointer copy and attach it to the application state
            .app_data(connection.clone())
    })
    .listen(listener)?
    .run();

    Ok(server)
}
