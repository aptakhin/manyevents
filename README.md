Business and tech observability in the one product. Because this separation hurts us.

# The shortest guide to run queries

```bash
# https://manyevents.cloud
curl "http://localhost:8000/manage-api/v0-unstable/signin" -d '{"email": "your_email@.com", "password": "<your_password>"}' -H "Content-Type: application/json"
```

Got response:

```json
{
  "is_success": true,
  "auth_token": "ce7834cf6ba2a19ce6c5a9a0be8276fc61e1b3669a8cc8e9a9c8ff4a0fc5d110"
}
```

Use `auth_token` in `Authorization: Bearer <<TOKEN>>` within all next queries. Let's create own company-tenant.

```bash
curl "http://localhost:8000/manage-api/v0-unstable/create-tenant" -d '{"title": "my-company"}' -H "Content-Type: application/json" -H "Authorization: Bearer 36d07c9580c0f2ef69a7d7262ad13a22d5cfeaeccc3c22951e29bcea57207c4b" | jq
```

Got response:

```json
{
  "is_success": true,
  "id": "8e28355d-3744-466f-8fb1-262015af284d",
  "clickhouse_read_dsn": "clickhouse://user_8e28355d3744466f8fb1262015af284d:my_password@localhost/db_8e28355d3744466f8fb1262015af284d",
  "clickhouse_admin_dsn": "",
  "push_token": ""
}
```

`id` - Created tenant id. We will use it in the following query.
`clickhouse_read_dsn` - could be used to access database with read-only user.

Let's declare a schema for wide-event named `main`.

```bash
curl "http://localhost:8000/manage-api/v0-unstable/apply-entity-schema-sync" -d '{"tenant_id": "8e28355d-3744-466f-8fb1-262015af284d", "name": "main", "schema": {"type": "object",
    "properties": {
        "base_timestamp": { "type": "integer", "x-manyevents-ch-type": "DateTime64(3)" },
        "base_name": { "type": "string", "x-manyevents-ch-type": "String" },
        "base_age": { "type": "integer", "x-manyevents-ch-type": "Int32" },
        "base_big_age": { "type": "integer", "x-manyevents-ch-type": "Int64" }
    },
    "x-manyevents-ch-order-by": "base_timestamp",
    "x-manyevents-ch-partition-by-func": "toYYYYMMDD",
    "x-manyevents-ch-partition-by": "base_timestamp"} }' \
    -H "Content-Type: application/json" -H "Authorization: Bearer 36d07c9580c0f2ef69a7d7262ad13a22d5cfeaeccc3c22951e29bcea57207c4b"
```

Got response:

```json
OK
```

We will use `push_token` to send new data.

```bash
curl "http://localhost:8000/push-api/v0-unstable/push-event" -d '{"x-manyevents-name": "main",
    "span_id": "xxxx",
    "span_start_time": 1234567890,
    "span_end_time": 1234567892,
    "base_timestamp": 1234567892,
    "base_parent_span_id": "xxxx",
    "base_message": "test message"}' \
    -H "Content-Type: application/json" -H "Authorization: Bearer me-pt-36d07c9580c0f2ef69a7d7262ad13a22d5cfeaeccc3c22951e29bcea57207c4b"
```

The data is in Clickhouse now.

# Run for the development

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