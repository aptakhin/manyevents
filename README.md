Business and tech observability in the one product. Because this separation hurts us.

[![Build and test](https://github.com/aptakhin/manyevents/actions/workflows/build-and-test.yml/badge.svg?branch=main)](https://github.com/aptakhin/manyevents/actions/workflows/build-and-test.yml)

# The shortest guide to run queries

`jq` command in the end is optional, it's for more readable output.

```bash
# https://manyevents.cloud
curl "https://manyevents.cloud/manage-api/v0-unstable/signin" -d '{"email": "your_email@.com", "password": "<your_password>"}' -H "Content-Type: application/json" | jq
```

Got response:

```json
{
  "is_success": true,
  "auth_token": "9160b32b7df1e9e6fef247d39ca8fb7f5861805a4327806f5df791d9a070d59a"
}
```

Use `auth_token` in `Authorization: Bearer <<TOKEN>>` within all next queries. Let's create own company-tenant.

```bash
curl "https://manyevents.cloud/manage-api/v0-unstable/create-tenant" -d '{"title": "my-company"}' -H "Content-Type: application/json" -H "Authorization: Bearer 9160b32b7df1e9e6fef247d39ca8fb7f5861805a4327806f5df791d9a070d59a" | jq
```

Got response:

```json
{
  "is_success": true,
  "id": "6d0edd61-9a68-48b4-9b18-c3ffbd793e4b",
  "clickhouse_read_dsn": "clickhouse://user_6d0edd619a6848b49b18c3ffbd793e4b:my_password@localhost/db_6d0edd619a6848b49b18c3ffbd793e4b",
  "clickhouse_admin_dsn": "",
  "push_token": "2c2f5367b19b6624500e6f22a123c06a14037d00014850a1e1cb2dc9fca2f913"
}
```

`id` - Created tenant id. We will use it in the following query.
`clickhouse_read_dsn` - could be used to access database with read-only user.

Let's declare a schema for wide-event named `main`. In manage api we still use our first bearer token.

```bash
curl "https://manyevents.cloud/manage-api/v0-unstable/apply-event-schema-sync" \
-d '{"tenant_id": "2b0d6db7-ff34-4f65-9385-3d2d463d3013", "name": "main", "schema": {"type": "object",
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
    -H "Content-Type: application/json" -H "Authorization: Bearer 9160b32b7df1e9e6fef247d39ca8fb7f5861805a4327806f5df791d9a070d59a"
```

Got response:

```json
OK
```

We will use `push_token` to send new data.

```bash
curl "https://manyevents.cloud/push-api/v0-unstable/push-event" -d '{"x-manyevents-name": "main",
    "span_id": "xxxx",
    "span_start_time": 1234567890,
    "span_end_time": 1234567892,
    "base_timestamp": 1234567892,
    "base_parent_span_id": "xxxx",
    "base_message": "test message"}' \
    -H "Content-Type: application/json" -H "Authorization: Bearer 2c2f5367b19b6624500e6f22a123c06a14037d00014850a1e1cb2dc9fca2f913"
```

Response:

```json
{"is_success":true,"message_code":null}
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

Then run data migrations in PostgreSQL:

```bash
make migrate
```

Then:

```bash
# Just run it
make run

# Run tests once
make test

# Run tests permanently watching for the source changes
make testw

# Run building binary rerunning on code changes
make runw
```

I use [Miro board](https://miro.com/app/board/uXjVL9mlc6Y=/?share_link_id=101307934260) for brainstorming. There various things could be found for the product development.

## Install tools

```bash
$ cargo install cargo-watch --locked
$ cargo install sqlx-cli
```

```bash
$ sqlx migrate add --source manyevents/db/migrations create_tables
```
