## Run for the development

```bash
cp .env.example .env
# edit secrets
```

Export all variables from `.env` to global environment. We could use `dotenv`, but we have errors variables weren't passing to children threads.

```bash
set -a; source .env; set +a
```

Setup infra:

```bash
docker compose up -d --build
```

Then:

```bash
make run
# run tests once
make test
# run tests permanently watching for the source changes
make testw
```

## Install tools

```bash
$ cargo install cargo-watch --locked
$ cargo install sqlx-cli
```


```bash
$ sqlx migrate add --source manyevents/db/migrations create_tables
```