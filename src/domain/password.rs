use argon2::{
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
    password_hash::SaltString,
};
use chrono::Utc;

use secrecy::{ExposeSecret, Secret};
use sha1::{Digest, Sha1};

use crate::{domain::UserName, telemetry::spawn_blocking_with_tracing};
use anyhow::Context;

use sqlx::PgPool;

#[derive(Debug)]
pub struct UserPassword(Secret<String>);

pub struct Credentials {
    pub username: UserName,
    pub password: UserPassword,
}

#[tracing::instrument(name = "Get stored credentials", skip(username, pool))]
async fn get_stored_credentials(
    username: &str,
    pool: &PgPool,
) -> Result<Option<(uuid::Uuid, Secret<String>)>, anyhow::Error> {
    let row = sqlx::query!(
        r#"
        SELECT user_id, password_hash
        FROM users
        WHERE user_name = $1
        "#,
        username,
    )
    .fetch_optional(pool)
    .await
    .context("Failed to performed a query to retrieve stored credentials.")?
    .map(|row| (row.user_id, Secret::new(row.password_hash)));
    Ok(row)
}

#[derive(thiserror::Error, Debug)]
pub enum AuthError {
    #[error("Invalid credentials.")]
    InvalidCredentials(#[source] anyhow::Error),
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

impl From<UserPassword> for Secret<String> {
    fn from(value: UserPassword) -> Self {
        value.0
    }
}

impl UserPassword {
    /// Parse and validate a password following NIST SP 800-63B guidelines.
    pub async fn parse(s: String, hibp_base_url: &str) -> Result<UserPassword, String> {
        // 1. Minimum length: 8 characters, Maximum length: 64 characters (per your spec)
        if s.len() < 8 {
            return Err("Password must be at least 8 characters long.".to_string());
        }
        // Note: NIST actually recommends supporting up to 64+ characters to allow passphrases. We
        // are deliberately choosing 64 for now as a cap.
        if s.len() > 64 {
            return Err("Password must be 64 characters or fewer.".to_string());
        }

        // 2. Blocklist verification via K-Anonymity HIBP API
        if Self::is_in_blocklist(&s, hibp_base_url).await? {
            return Err(
                "Password is insecure: it has been found in global data breaches, please change it.".to_string(),
            );
        }

        Ok(UserPassword(Secret::new(s)))
    }

    /// Internal helper to execute the K-Anonymity check against HIBP
    /// There's a cost of network latency, a cost am willing to pay to make
    /// sure the users are safe particularly during sign up.
    async fn is_in_blocklist(password: &str, base_url: &str) -> Result<bool, String> {
        // Hash the candidate password using SHA-1
        let mut hasher = Sha1::new();
        hasher.update(password.as_bytes());
        let hash_result = hasher.finalize();
        //Map over the byte slice, formatting each byte to a 2-character wide upper hex string
        // Convert hash bytes to an uppercase hex string (40 characters)
        let hash_hex: String = hash_result.iter().map(|b| format!("{:02X}", b)).collect();

        // Split the hash into a 5-character prefix and 35-character suffix
        let prefix = &hash_hex[0..5];
        let suffix = &hash_hex[5..];

        // Send ONLY the 5-character prefix to the API
        // Dynamically target our configuration path
        let url = format!("{}/range/{}", base_url, prefix);

        // let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);

        let response = reqwest::get(&url)
            .await
            .map_err(|e| format!("Failed to reach blocklist API: {}", e))?;

        if !response.status().is_success() {
            return Err("Blocklist provider returned an error code.".to_string());
        }

        let body = response
            .text()
            .await
            .map_err(|e| format!("Failed to read blocklist response: {}", e))?;

        // Parse the body line-by-line to find our suffix
        // The API returns lines formatted as: SUFFIX:COUNT (e.g., "0018A45C3511E589421A2EC645D003474F2:3")
        if let Some(value) = find_suffix(suffix, body) {
            return value;
        }

        Ok(false)
    }
}

fn find_suffix(suffix: &str, body: String) -> Option<Result<bool, String>> {
    for line in body.lines() {
        if let Some((returned_suffix, _count)) = line.split_once(':')
            && returned_suffix == suffix
        {
            return Some(Ok(true));
        }
    }
    None
}

#[tracing::instrument(name = "Create user account", skip(password, pool))]
pub async fn create_credential(
    user_id: uuid::Uuid,
    user_name: UserName,
    password: Secret<String>,
    pool: &PgPool,
) -> Result<(), anyhow::Error> {
    let password_hash = spawn_blocking_with_tracing(move || compute_password_hash(password))
        .await?
        .context("Failed to hash password")?;
    sqlx::query!(
        r#"
        INSERT INTO users( user_id, user_name, password_hash, signed_up_at)
        VALUES ($1, $2, $3, $4)
        "#,
        user_id,
        user_name.as_ref(),
        password_hash.expose_secret(),
        Utc::now()
    )
    .execute(pool)
    .await?;

    Ok(())
}

#[tracing::instrument(name = "Validate credentials", skip(credentials, pool))]
pub async fn validate_credentials(
    credentials: Credentials,
    pool: &PgPool,
) -> Result<uuid::Uuid, AuthError> {
    let mut user_id = None;
    let mut expected_password_hash = Secret::new(
        "$argon2id$v=19$m=15000,t=2,p=1$\
        gZiV/M1gPc22ElAH/Jh1Hw$\
        CWOrkoo7oJBQ/iyh7uJ0LO2aLEfrHwTWllSAxT0zRno"
            .to_string(),
    );

    if let Some((stored_user_id, stored_password_hash)) =
        get_stored_credentials(&credentials.username.as_ref(), pool).await?
    {
        user_id = Some(stored_user_id);
        expected_password_hash = stored_password_hash;
    }

    spawn_blocking_with_tracing(move || {
        verify_password_hash(expected_password_hash, credentials.password.into())
    })
    .await
    .context("Failed to spawn blocking task.")??;

    user_id
        .ok_or_else(|| anyhow::anyhow!("Unknown username."))
        .map_err(AuthError::InvalidCredentials)
}

#[tracing::instrument(
    name = "Validate credentials",
    skip(expected_password_hash, password_candidate)
)]
fn verify_password_hash(
    expected_password_hash: Secret<String>,
    password_candidate: Secret<String>,
) -> Result<(), AuthError> {
    let expected_password_hash = PasswordHash::new(expected_password_hash.expose_secret())
        .context("Failed to parse hash in PHC string format.")?;

    Argon2::default()
        .verify_password(
            password_candidate.expose_secret().as_bytes(),
            &expected_password_hash,
        )
        .context("Invalid password.")
        .map_err(AuthError::InvalidCredentials)
}

fn compute_password_hash(password: Secret<String>) -> Result<Secret<String>, anyhow::Error> {
    let salt = SaltString::generate(&mut rand::thread_rng());
    let password_hash = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(15000, 2, 1, None).unwrap(),
    )
    .hash_password(password.expose_secret().as_bytes(), &salt)?
    .to_string();
    Ok(Secret::new(password_hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::PasswordHash;
    // Make sure we pull UserPassword into scope from above
    use argon2::PasswordVerifier;

    const LIVE_HIBP_URL: &str = "https://api.pwnedpasswords.com";

    // Invalids
    #[tokio::test]
    async fn pass_less_than_set_minimum_is_rejected() {
        // [Arrange]
        let pass = "short12".to_string();

        // [Act] Resolve the future first
        let result = UserPassword::parse(pass, LIVE_HIBP_URL).await;

        // [Assert] Check the final Result cleanly
        assert!(
            result.is_err(),
            "Expected Err, but execution successfully returned Ok"
        );
    }

    #[tokio::test]
    async fn pass_is_not_more_than_set_maximum_is_rejected() {
        // [Arrange]
        let pass = "a".repeat(65);

        // [Act]
        let result = UserPassword::parse(pass, LIVE_HIBP_URL).await;

        // [Assert]
        assert!(
            result.is_err(),
            "Expected Err, but execution successfully returned Ok"
        );
    }

    #[tokio::test]
    async fn pass_found_in_blocklist_is_rejected() {
        // [Arrange]
        let pass = "password123".to_string();

        // [Act]
        let result = UserPassword::parse(pass, LIVE_HIBP_URL).await;

        // [Assert]
        assert!(
            result.is_err(),
            "Expected Err, but execution successfully returned Ok"
        );
    }

    // Valids
    #[tokio::test]
    async fn pass_within_set_minimum_and_maximum_bounds_is_accepted() {
        // [Arrange]
        let pass = "Xy7!pQ9@mZ2$".to_string();

        // [Act]
        let result = UserPassword::parse(pass, LIVE_HIBP_URL).await;

        // [Assert]
        assert!(result.is_ok(), "Expected Ok, got Err: {:?}", result.err());
    }

    #[tokio::test]
    async fn pass_that_isnt_found_in_blocklist_is_accepted() {
        // [Arrange]
        let pass = "Correct-Horse-Battery-Staple-2026!".to_string();

        // [Act]
        let result = UserPassword::parse(pass, LIVE_HIBP_URL).await;

        // [Assert]
        assert!(result.is_ok(), "Expected Ok, got Err: {:?}", result.err());
    }

    //Test that find_suffix indeed works to prevent future regression after any updates later
    #[test]
    fn find_suffix_does_return_accurate_values() {
        // Positive case: Suffix exists on the first line
        let body_1 = String::from("expected_suffix:12\n");
        assert_eq!(find_suffix("expected_suffix", body_1), Some(Ok(true)));

        // Positive case: Suffix exists on a later line
        let body_2 = String::from("wrong_suffix\nwrong_suffix3target_suffix:2");
        assert_eq!(
            find_suffix("wrong_suffix3target_suffix", body_2),
            Some(Ok(true))
        );
    }

    #[test]
    fn find_suffix_returns_none_when_absent() {
        // Negative case: Suffix is nowhere in the body
        let body_missing = String::from("alpha:1\nbeta:2\ngamma:3");
        assert_eq!(find_suffix("omega", body_missing), None);

        // Negative case: Body is completely empty
        let body_empty = String::from("");
        assert_eq!(find_suffix("any_suffix", body_empty), None);
    }

    #[test]
    fn find_suffix_handles_edge_cases() {
        // Edge case: Suffix matches but line has no colon split
        let body_no_colon = String::from("target_suffix");
        assert_eq!(find_suffix("target_suffix", body_no_colon), None);

        // Edge case: Suffix is part of the value side, not the key side
        let body_value_match = String::from("some_key:target_suffix");
        assert_eq!(find_suffix("target_suffix", body_value_match), None);
    }

    #[test]
    fn test_compute_password_hash_success() {
        // Arrange
        let password_plaintext = "my_super_duper_secure_password".to_string();
        let secret_password = Secret::new(password_plaintext.clone());

        // Act
        let result = compute_password_hash(secret_password);

        // Assert
        // 1. Claim ensures the result is an Ok variant and unwraps it
        let Ok(hashed_secret) = result else {
            panic!("Expected Ok, got Err: {:?}", result.err());
        };

        // Expose the secret inside the test boundary to verify it
        let hash_string = hashed_secret.expose_secret();

        // 2. Verify it's not empty and actually did something
        assert!(!hash_string.is_empty(), "Hash string should not be empty");
        assert_ne!(
            hash_string, &password_plaintext,
            "Hash should not match plaintext"
        );

        // 3. Black-box verification: Can Argon2 decode and validate this string?
        let parsed_hash = PasswordHash::new(hash_string)
            .expect("Failed to parse the generated output into a valid Argon2 PasswordHash");

        let argon2 = Argon2::default();
        let verification_result =
            argon2.verify_password(password_plaintext.as_bytes(), &parsed_hash);

        assert!(
            verification_result.is_ok(),
            "Password verification failed: {:?}",
            verification_result.err()
        );
    }

    #[test]
    fn test_different_salts_for_same_password() {
        // Arrange
        let password = Secret::new("same_password".to_string());

        // Act
        let result_one = compute_password_hash(password.clone());
        let result_two = compute_password_hash(password);

        // Assert
        let Ok(hash_one) = result_one else {
            panic!("Expected Ok for hash_one, got Err: {:?}", result_one.err());
        };
        let Ok(hash_two) = result_two else {
            panic!("Expected Ok for hash_two, got Err: {:?}", result_two.err());
        };
        // Because of rand::thread_rng(), two back-to-back hashes must never be identical
        assert_ne!(
            hash_one.expose_secret(),
            hash_two.expose_secret(),
            "Random salting failed; hashes are identical."
        );
    }
}
