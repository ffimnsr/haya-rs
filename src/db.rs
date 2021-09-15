use deadpool_postgres::{Manager, ManagerConfig, RecyclingMethod};
use std::env;
use std::str::FromStr;
use tokio_postgres::{Config, NoTls};

use crate::errors::{ServiceError, ServiceResult};
pub(crate) use deadpool_postgres::Pool;

pub(crate) fn get_db_pool() -> ServiceResult<Pool> {
    let db_url = env::var("DSN").map_err(|e| ServiceError::Env(e.to_string()))?;

    let pg_config = Config::from_str(db_url.as_str())
        .map_err(|e| ServiceError::Database(e.to_string()))?;

    let manager = Manager::from_config(
        pg_config,
        NoTls,
        ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        },
    );

    Ok(Pool::new(manager, 16))
}
