use unicode_segmentation::UnicodeSegmentation;

#[derive(Debug)]
pub struct UserName(String);

impl UserName {
    pub fn parse(s: &str) -> Result<UserName, String> {
        let is_empty_or_whitespace = s.trim().is_empty();
        let is_too_long = s.graphemes(true).count() > 256;
        let is_too_short = s.graphemes(true).count() < 8;
        let forbidden_characters = ['/', '(', ')', '"', '<', '>', '\\', '{', '}'];
        let contains_forbidden_characters = s.chars().any(|g| forbidden_characters.contains(&g));
        if is_empty_or_whitespace || is_too_long || is_too_short || contains_forbidden_characters {
            Err(format!("'{}' is not a valid user name.", s))
        } else {
            Ok(Self(s.to_string()))
        }
    }
}

impl AsRef<str> for UserName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use crate::domain::UserName;

    #[test]
    fn a_256_grapheme_long_name_is_valid() {
        let name = "a".repeat(256);
        assert!(UserName::parse(&name).is_ok());
    }
    #[test]
    fn a_name_longer_than_256_graphemes_is_rejected() {
        let name = "a".repeat(257);
        assert!(UserName::parse(&name).is_err());
    }

    #[test]
    fn a_name_shorter_than_256_graphemes_is_rejected() {
        let name = "a".repeat(7);
        assert!(UserName::parse(&name).is_err());
    }

    #[test]
    fn whitespace_only_names_are_rejected() {
        let name = " ".to_string();
        assert!(UserName::parse(&name).is_err());
    }
    #[test]
    fn empty_string_is_rejected() {
        let name = "".to_string();
        assert!(UserName::parse(&name).is_err());
    }
    #[test]
    fn names_containing_an_invalid_character_are_rejected() {
        for name in &['/', '(', ')', '"', '<', '>', '\\', '{', '}'] {
            let name = name.to_string();
            assert!(UserName::parse(&name).is_err());
        }
    }

    #[test]
    fn a_valid_name_is_parsed_successfully() {
        let name = "John De Reffic".to_string();
        assert!(UserName::parse(&name).is_ok());
    }
}
