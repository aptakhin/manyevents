CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE account (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    email VARCHAR,
    password VARCHAR,
    UNIQUE(email)
);

CREATE TABLE auth_token (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    account_id UUID REFERENCES account (id),
    created_by_account_id UUID REFERENCES account (id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    expiring_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    type VARCHAR NOT NULL,
    token VARCHAR NOT NULL,
    device_id VARCHAR NOT NULL,
    UNIQUE(token)
);

CREATE TABLE tenant (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_by_account_id UUID REFERENCES account (id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    title VARCHAR NOT NULL
);

-- Many to many tenant and account
CREATE TABLE tenant_and_account (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_by_account_id UUID REFERENCES account (id),
    tenant_id UUID REFERENCES tenant (id),
    account_id UUID REFERENCES account (id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE DEFAULT NULL
);

CREATE TABLE scope (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES tenant (id),
    created_by_account_id UUID REFERENCES account (id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,

    slug VARCHAR NOT NULL,
    title VARCHAR NOT NULL
);

CREATE TABLE storage_credential (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES tenant (id),
    created_by_account_id UUID REFERENCES account (id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    type VARCHAR NOT NULL,
    dsn VARCHAR NOT NULL
);

CREATE TABLE scope_environment (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scope_id UUID REFERENCES tenant (id),
    storage_credential_id UUID REFERENCES storage_credential (id),
    created_by_account_id UUID REFERENCES account (id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    slug VARCHAR NOT NULL,
    title VARCHAR NOT NULL
);

CREATE TABLE push_token (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scope_environment_id UUID REFERENCES scope_environment (id),
    created_by_account_id UUID REFERENCES account (id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    expiring_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    token VARCHAR NOT NULL,
    UNIQUE(token)
);

CREATE TABLE component_version (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_by_account_id UUID REFERENCES account (id),
    based_on_id UUID REFERENCES component_version (id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    suggested_name VARCHAR NOT NULL,
    source VARCHAR NOT NULL,
    description JSONB NOT NULL,
    version INT NOT NULL
);

-- Many to many scope_environment and component
CREATE TABLE scope_environment_and_component (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_by_account_id UUID REFERENCES account (id),
    scope_environment_id UUID REFERENCES scope_environment (id),
    component_version_id UUID REFERENCES component_version (id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE DEFAULT NULL
);
