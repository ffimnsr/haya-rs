use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use uuid::Uuid;

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct Client {
    pub client_id: Uuid,
    pub client_secret: String,
    pub owner: String,
    pub audience: String,
    pub grants: Vec<String>,
    pub response_types: Vec<String>,
    pub scopes: Vec<String>,
    pub redirect_uris: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Client {
    pub async fn get_client(pool: Pool, client_id: Uuid) -> Self {
        let db = pool.get().await.unwrap();

        let query = format!("SELECT * FROM view_client_unite WHERE client_id = $1");
        let client_result = db.query_opt(&query, &[&client_id]).await.unwrap().unwrap();

        let client = Self {
            client_id: client_result.get("client_id"),
            client_secret: client_result.get("client_secret"),
            owner: client_result.get("owner"),
            audience: client_result.get("audience"),
            grants: client_result
                .get::<&str, String>("grants")
                .split(",")
                .map(String::from)
                .collect::<Vec<String>>(),
            response_types: client_result
                .get::<&str, String>("response_types")
                .split(",")
                .map(String::from)
                .collect::<Vec<String>>(),
            scopes: client_result
                .get::<&str, String>("scopes")
                .split(",")
                .map(String::from)
                .collect::<Vec<String>>(),
            redirect_uris: client_result
                .get::<&str, String>("redirect_uris")
                .split(",")
                .map(String::from)
                .collect::<Vec<String>>(),
            created_at: client_result.get("created_at"),
            updated_at: client_result.get("updated_at"),
        };

        client
    }
}
