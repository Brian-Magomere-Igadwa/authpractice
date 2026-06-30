use argon2::{Algorithm, Argon2, Params, PasswordHasher, Version, password_hash::SaltString};
use chrono::Utc;

use secrecy::{ExposeSecret, Secret};
use sha1::{Digest, Sha1};

use crate::{domain::UserName, telemetry::spawn_blocking_with_tracing};
use anyhow::Context;

use sqlx::PgPool;

#[derive(Debug)]
pub struct UserPassword(Secret<String>);

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
        for line in body.lines() {
            if let Some((returned_suffix, _count)) = line.split_once(':')
                && returned_suffix == suffix
            {
                return Ok(true);
            }
        }

        Ok(false)
    }
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
    .await
    .context("Failed to create new credential in the database.")?;
    Ok(())
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
    use claim::{assert_err, assert_ok};

    const LIVE_HIBP_URL: &str = "https://api.pwnedpasswords.com";

    // Invalids
    #[tokio::test]
    async fn pass_less_than_set_minimum_is_rejected() {
        // [Arrange]
        let pass = "short12".to_string();

        // [Act] Resolve the future first
        let result = UserPassword::parse(pass, LIVE_HIBP_URL).await;

        // [Assert] Check the final Result cleanly
        assert_err!(result);
    }

    #[tokio::test]
    async fn pass_is_not_more_than_set_maximum_is_rejected() {
        // [Arrange]
        let pass = "a".repeat(65);

        // [Act]
        let result = UserPassword::parse(pass, LIVE_HIBP_URL).await;

        // [Assert]
        assert_err!(result);
    }

    #[tokio::test]
    async fn pass_found_in_blocklist_is_rejected() {
        // [Arrange]
        let pass = "password123".to_string();

        // [Act]
        let result = UserPassword::parse(pass, LIVE_HIBP_URL).await;

        // [Assert]
        assert_err!(result);
    }

    // Valids
    #[tokio::test]
    async fn pass_within_set_minimum_and_maximum_bounds_is_accepted() {
        // [Arrange]
        let pass = "Xy7!pQ9@mZ2$".to_string();

        // [Act]
        let result = UserPassword::parse(pass, LIVE_HIBP_URL).await;

        // [Assert]
        assert_ok!(result);
    }

    #[tokio::test]
    async fn pass_that_isnt_found_in_blocklist_is_accepted() {
        // [Arrange]
        let pass = "Correct-Horse-Battery-Staple-2026!".to_string();

        // [Act]
        let result = UserPassword::parse(pass, LIVE_HIBP_URL).await;

        // [Assert]
        assert_ok!(result);
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
        let hashed_secret = assert_ok!(result);

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

        assert_ok!(verification_result);
    }

    #[test]
    fn test_different_salts_for_same_password() {
        // Arrange
        let password = Secret::new("same_password".to_string());

        // Act
        let hash_one = assert_ok!(compute_password_hash(password.clone()));
        let hash_two = assert_ok!(compute_password_hash(password));

        // Assert
        // Because of rand::thread_rng(), two back-to-back hashes must never be identical
        assert_ne!(
            hash_one.expose_secret(),
            hash_two.expose_secret(),
            "Random salting failed; hashes are identical."
        );
    }
}
