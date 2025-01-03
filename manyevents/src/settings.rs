use std::env;

pub struct Settings {
    pub local_run: bool,
    pub secret_key: String,
    pub postgres_dsn: String,
    pub clickhouse_dsn: String,
    pub clickhouse_external_host: String,
}

impl Settings {
    pub fn read_settings() -> Settings {
        let local_run: bool = env::var("MANYEVENTS_LOCAL_RUN")
            .unwrap_or_default()
            .parse()
            .unwrap_or(false);
        let secret_key = env::var("MANYEVENTS_SECRET_KEY").unwrap();
        let postgres_dsn = Self::build_postgres_dsn();
        let clickhouse_dsn = Self::build_clickhouse_dsn();
        let clickhouse_external_host = env::var("MANYEVENTS_CH_EXTERNAL_HOST").unwrap();
        Settings {
            local_run,
            secret_key,
            postgres_dsn,
            clickhouse_dsn,
            clickhouse_external_host,
        }
    }

    pub fn get_binary_secret_key(&self) -> &[u8] {
        self.secret_key.as_bytes()
    }

    pub fn get_local_http_clickhouse_url(&self) -> String {
        format!(
            "http://{}:{}",
            env::var("CLICKHOUSE_HOST").unwrap(),
            env::var("CLICKHOUSE_PORT").unwrap(),
        )
    }

    pub fn get_clickhouse_db(&self) -> String {
        env::var("CLICKHOUSE_DB").unwrap()
    }

    pub fn get_clickhouse_user(&self) -> String {
        env::var("CLICKHOUSE_USER").unwrap()
    }

    pub fn get_clickhouse_password(&self) -> String {
        env::var("CLICKHOUSE_PASSWORD").unwrap()
    }

    fn build_postgres_dsn() -> String {
        format!(
            "postgres://{}:{}@{}:{}/{}",
            env::var("POSTGRES_USER").unwrap(),
            env::var("POSTGRES_PASSWORD").unwrap(),
            env::var("POSTGRES_HOST").unwrap(),
            env::var("POSTGRES_PORT").unwrap(),
            env::var("POSTGRES_DB").unwrap()
        )
    }

    fn build_clickhouse_dsn() -> String {
        format!(
            "clickhouse://{}:{}@{}:{}/{}",
            env::var("CLICKHOUSE_USER").unwrap(),
            env::var("CLICKHOUSE_PASSWORD").unwrap(),
            env::var("CLICKHOUSE_HOST").unwrap(),
            env::var("CLICKHOUSE_PORT").unwrap(),
            env::var("CLICKHOUSE_DB").unwrap()
        )
    }
}
