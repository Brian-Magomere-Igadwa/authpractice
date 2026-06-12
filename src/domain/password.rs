pub struct UserPassword(String);

impl UserPassword {
    //Following Nist password requirements
    pub fn parse(s: String) -> Result<UserPassword, String> {
        //Minimum length: 8 characters max 64 characters
        //Blocklist verification: checked against lists of commonly used passwords

        todo!()
    }
}
