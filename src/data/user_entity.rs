use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::domain;

pub struct UserEntity {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    pub signedup_at: DateTime<Utc>,
}

impl From<UserEntity> for crate::domain::User {
    fn from(entity: UserEntity) -> Self {
        Self {
            email: domain::UserEmail::parse(entity.email).expect("DB Corruption"),
            name: domain::UserName::parse(entity.name).expect("DB Corruption"),
        }
    }
}
