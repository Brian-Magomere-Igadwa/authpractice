use crate::domain::{UserPassword, user_name::UserName};
pub struct User {
    pub name: UserName,
    pub password: UserPassword,
}
