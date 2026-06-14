use sha1::{Digest, Sha1};

#[derive(Debug)]
pub struct UserPassword(String);

impl UserPassword {
    /// Parse and validate a password following NIST SP 800-63B guidelines.
    pub async fn parse(s: String) -> Result<UserPassword, String> {
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
        if Self::is_in_blocklist(&s).await? {
            return Err(
                "Password is insecure: it has been found in global data breaches, please change it.".to_string(),
            );
        }

        Ok(UserPassword(s))
    }

    /// Internal helper to execute the K-Anonymity check against HIBP
    /// There's a cost of network latency, a cost am willing to pay to make
    /// sure the users are safe particularly during sign up.
    async fn is_in_blocklist(password: &str) -> Result<bool, String> {
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
        let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);

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
            if let Some((returned_suffix, _count)) = line.split_once(':') {
                if returned_suffix == suffix {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*; // Make sure we pull UserPassword into scope from above
    use claim::{assert_err, assert_ok};

    // Invalids
    #[tokio::test]
    async fn pass_less_than_set_minimum_is_rejected() {
        // [Arrange]
        let pass = "short12".to_string();

        // [Act] Resolve the future first
        let result = UserPassword::parse(pass).await;

        // [Assert] Check the final Result cleanly
        assert_err!(result);
    }

    #[tokio::test]
    async fn pass_is_not_more_than_set_maximum_is_rejected() {
        // [Arrange]
        let pass = "a".repeat(65);

        // [Act]
        let result = UserPassword::parse(pass).await;

        // [Assert]
        assert_err!(result);
    }

    #[tokio::test]
    async fn pass_found_in_blocklist_is_rejected() {
        // [Arrange]
        let pass = "password123".to_string();

        // [Act]
        let result = UserPassword::parse(pass).await;

        // [Assert]
        assert_err!(result);
    }

    // Valids
    #[tokio::test]
    async fn pass_within_set_minimum_and_maximum_bounds_is_accepted() {
        // [Arrange]
        let pass = "Xy7!pQ9@mZ2$".to_string();

        // [Act]
        let result = UserPassword::parse(pass).await;

        // [Assert]
        assert_ok!(result);
    }

    #[tokio::test]
    async fn pass_that_isnt_found_in_blocklist_is_accepted() {
        // [Arrange]
        let pass = "Correct-Horse-Battery-Staple-2026!".to_string();

        // [Act]
        let result = UserPassword::parse(pass).await;

        // [Assert]
        assert_ok!(result);
    }
}
