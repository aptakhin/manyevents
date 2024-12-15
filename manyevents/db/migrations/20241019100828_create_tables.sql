CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE account (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    email varchar,
    password varchar,
    UNIQUE(email)
);

-- insert dummy one
INSERT INTO account (id) VALUES ('00000000-0000-0000-0000-000000000000');

CREATE TABLE account_token (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    account_id UUID REFERENCES account (id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expiring_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    token varchar NOT NULL,
    device_id varchar NOT NULL
);

CREATE TABLE tenant (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_by_account_id UUID REFERENCES account (id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    title varchar NOT NULL
);

CREATE TABLE scope (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES tenant (id),
    created_by_account_id UUID REFERENCES account (id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    slug varchar NOT NULL,
    title varchar NOT NULL
);

CREATE TABLE storage_credential (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_by_account_id UUID REFERENCES account (id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    type varchar NOT NULL,
    dsn varchar NOT NULL
);

CREATE TABLE scope_environment (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scope_id UUID REFERENCES tenant (id),
    storage_credential_id UUID REFERENCES storage_credential (id),
    created_by_account_id UUID REFERENCES account (id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    slug varchar NOT NULL,
    title varchar NOT NULL
);

CREATE TABLE push_token (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scope_environment_id UUID REFERENCES scope_environment (id),
    created_by_account_id UUID REFERENCES account (id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    token varchar NOT NULL
);

CREATE TABLE market_component (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_by_account_id UUID REFERENCES account (id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    suggested_name varchar NOT NULL,
    source varchar NOT NULL,
    description JSONB NOT NULL
);

CREATE TABLE scope_component (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scope_id UUID REFERENCES scope (id),
    created_by_account_id UUID REFERENCES account (id),
    original_market_component_ud UUID REFERENCES market_component (id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    description JSONB NOT NULL,
    version INT NOT NULL
);
