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
  "auth_token": "c5e323de6fa621aa1dcba6befcd7555ebcf37bf91ab8295caf464267baa604e1"
}
```

Use `auth_token` in `Authorization: Bearer <<TOKEN>>` within all next queries. Let's create own company-tenant.

```bash
curl "http://localhost:8000/manage-api/v0-unstable/create-tenant" -d '{"title": "my-company"}' -H "Content-Type: application/json" -H "Authorization: Bearer c5e323de6fa621aa1dcba6befcd7555ebcf37bf91ab8295caf464267baa604e1" | jq
```

Got response:

```json
{
  "is_success": true,
  "id": "2b0d6db7-ff34-4f65-9385-3d2d463d3013",
  "clickhouse_read_dsn": "clickhouse://user_2b0d6db7ff344f6593853d2d463d3013:my_password@localhost/db_2b0d6db7ff344f6593853d2d463d3013",
  "clickhouse_admin_dsn": "",
  "push_token": "c1f7c0f9e7ca95daf5979576a5dc3b757428a3395548bcd39f0148593907dadd"
}
```

`id` - Created tenant id. We will use it in the following query.
`clickhouse_read_dsn` - could be used to access database with read-only user.

Let's declare a schema for wide-event named `main`.

```bash
curl "http://localhost:8000/manage-api/v0-unstable/apply-entity-schema-sync" -d '{"tenant_id": "2b0d6db7-ff34-4f65-9385-3d2d463d3013", "name": "main", "schema": {"type": "object",
    "properties": {
        "base_timestamp": { "type": "integer", "x-manyevents-ch-type": "DateTime64(3)" },
        "base_parent_span_id": { "type": "string", "x-manyevents-ch-type": "String" },
        "base_message": { "type": "string", "x-manyevents-ch-type": "String" },
        "span_start_time": { "type": "integer", "x-manyevents-ch-type": "DateTime64(3)" },
        "span_end_time": { "type": "integer", "x-manyevents-ch-type": "DateTime64(3)" },
        "span_id": { "type": "string", "x-manyevents-ch-type": "String" }
    },
    "x-manyevents-ch-order-by": "base_timestamp",
    "x-manyevents-ch-partition-by-func": "toYYYYMMDD",
    "x-manyevents-ch-partition-by": "base_timestamp"} }' \
    -H "Content-Type: application/json" -H "Authorization: Bearer c5e323de6fa621aa1dcba6befcd7555ebcf37bf91ab8295caf464267baa604e1"
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
    -H "Content-Type: application/json" -H "Authorization: Bearer c1f7c0f9e7ca95daf5979576a5dc3b757428a3395548bcd39f0148593907dadd"
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