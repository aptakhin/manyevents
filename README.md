## Run for the development

Setup infra:

```bash
docker compose up -d --build
```

Then:

```bash
make run
make test
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