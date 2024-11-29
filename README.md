

```bash
$ cargo install cargo-watch --locked
$ cargo install sqlx-cli
```


```bash
$ sqlx migrate add --source manyevents/db/migrations create_tables
```

Setup infra:

```bash
docker compose up -d --build
```

```bash
make run
make test
make testw
```