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
        let secret_key = env::var("MANYEVENTS_SECRET_KEY")
            .expect("MANYEVENTS_SECRET_KEY is expected for the run");
        let postgres_dsn = Self::build_postgres_dsn();
        let clickhouse_dsn = Self::build_clickhouse_dsn();
        let clickhouse_external_host = env::var("MANYEVENTS_CH_EXTERNAL_HOST")
            .expect("MANYEVENTS_CH_EXTERNAL_HOST is expected for the run");
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
            env::var("CLICKHOUSE_HOST").expect("CLICKHOUSE_HOST is expected for the run"),
            env::var("CLICKHOUSE_PORT").expect("CLICKHOUSE_PORT is expected for the run"),
        )
    }

    pub fn get_clickhouse_db(&self) -> String {
        env::var("CLICKHOUSE_DB").expect("CLICKHOUSE_DB is expected for the run")
    }

    pub fn get_clickhouse_user(&self) -> String {
        env::var("CLICKHOUSE_USER").expect("CLICKHOUSE_USER is expected for the run")
    }

    pub fn get_clickhouse_password(&self) -> String {
        env::var("CLICKHOUSE_PASSWORD").expect("CLICKHOUSE_PASSWORD is expected for the run")
    }

    fn build_postgres_dsn() -> String {
        format!(
            "postgres://{}:{}@{}:{}/{}",
            env::var("POSTGRES_USER").expect("POSTGRES_USER is expected for the run"),
            env::var("POSTGRES_PASSWORD").expect("POSTGRES_PASSWORD is expected for the run"),
            env::var("POSTGRES_HOST").expect("POSTGRES_HOST is expected for the run"),
            env::var("POSTGRES_PORT").expect("POSTGRES_PORT is expected for the run"),
            env::var("POSTGRES_DB").expect("POSTGRES_DB is expected for the run")
        )
    }

    fn build_clickhouse_dsn() -> String {
        format!(
            "clickhouse://{}:{}@{}:{}/{}",
            env::var("CLICKHOUSE_USER").expect("CLICKHOUSE_USER is expected for the run"),
            env::var("CLICKHOUSE_PASSWORD").expect("CLICKHOUSE_PASSWORD is expected for the run"),
            env::var("CLICKHOUSE_HOST").expect("CLICKHOUSE_HOST is expected for the run"),
            env::var("CLICKHOUSE_PORT").expect("CLICKHOUSE_PORT is expected for the run"),
            env::var("CLICKHOUSE_DB").expect("CLICKHOUSE_DB is expected for the run")
        )
    }
}
