use secrecy::{ExposeSecret, Secret};
use serde_aux::field_attributes::deserialize_number_from_string;
use sqlx::postgres::{PgConnectOptions, PgSslMode};

#[derive(serde::Deserialize, Clone)]
pub struct Settings {
    // since we are using the type DbSettings, it's a good idea to impl Deserialize as we have on Settings with the macro
    pub database: DatabaseSettings,
    pub application: ApplicationSettings,
    pub redis_uri: Secret<String>,
}

#[derive(serde::Deserialize, Clone)]
pub struct DatabaseSettings {
    pub username: String,
    pub password: Secret<String>,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub port: u16,
    pub host: String,
    pub database_name: String,
    // Determine if we demand the connection to be encrypted or not
    pub require_ssl: bool,
}

#[derive(serde::Deserialize, Clone)]
pub struct ApplicationSettings {
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub port: u16,
    pub host: String,
    pub hibp_api_url: String,
    pub hmac_secret: Secret<String>,
    // The duration (in seconds) a user remains quarantined after too many failed attempts
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub quarantine_duration_seconds: i64,
}

impl DatabaseSettings {
    pub fn connect_options(&self) -> PgConnectOptions {
        let ssl_mode = if self.require_ssl {
            PgSslMode::Require
        } else {
            PgSslMode::Prefer
        };
        PgConnectOptions::new()
            .host(&self.host)
            .username(&self.username)
            .password(self.password.expose_secret())
            .port(self.port)
            .ssl_mode(ssl_mode)
            .database(&self.database_name)
    }

    pub fn connection_string(&self) -> Secret<String> {
        Secret::new(format!(
            "postgres://{}:{}@{}:{}/{}",
            self.username,
            self.password.expose_secret(),
            self.host,
            self.port,
            self.database_name
        ))
    }
}

pub fn get_configuration() -> Result<Settings, config::ConfigError> {
    // Initialise our configuration reader
    let settings = config::Config::builder();
    let base_path = std::env::current_dir().expect("Failed to determine the current directory");
    let configuration_directory = base_path.join("configuration");
    // Read the "default" configuration file
    let settings = settings
        .add_source(config::File::from(configuration_directory.join("base")).required(true));

    // Detect the running environment.
    // Default to `local` if unspecified.
    let environment: Environment = std::env::var("APP_ENVIRONMENT")
        .unwrap_or_else(|_| "local".into())
        .try_into()
        .expect("Failed to parse APP_ENVIRONMENT.");

    // Initialise our configuration reader
    let settings = settings
        // Add configuration values from a file named `configuration`.
        // It will look for any top-level file with an extension
        // that `config` knows how to parse: yaml, json, etc.
        .add_source(
            config::File::from(configuration_directory.join(environment.as_str())).required(true),
        );

    // Add in settings from environment variables (with a prefix of APP and '__' as separator)
    // E.g. `APP_APPLICATION__PORT=5001 would set `Settings.application.port`
    // let settings = settings.add_source(config::Environment::with_prefix("app").separator("__"));
    let settings = settings.add_source(
        config::Environment::with_prefix("APP")
            .prefix_separator("_")
            .separator("__"),
    );

    // Try to convert the configuration values it read into
    // our Settings type
    settings.build()?.try_deserialize()
}

/// The possible runtime environment for our application.
pub enum Environment {
    Local,
    Production,
}
impl Environment {
    pub fn as_str(&self) -> &'static str {
        match self {
            Environment::Local => "local",
            Environment::Production => "production",
        }
    }
}
impl TryFrom<String> for Environment {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.to_lowercase().as_str() {
            "local" => Ok(Self::Local),
            "production" => Ok(Self::Production),
            other => Err(format!(
                "{} is not a supported environment. Use either `local` or `production`.",
                other
            )),
        }
    }
}
