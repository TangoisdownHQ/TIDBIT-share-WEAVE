alter table if exists documents
    add column if not exists encryption_mode text not null default 'plaintext_server_managed',
    add column if not exists ciphertext_hash_hex text,
    add column if not exists evidence_bundle_arweave_tx text;

create table if not exists agent_identities (
    id uuid primary key default gen_random_uuid(),
    owner_wallet text not null,
    label text not null,
    provider text,
    model text,
    capabilities_json jsonb not null default '[]'::jsonb,
    api_token_hash text not null unique,
    is_active boolean not null default true,
    created_at timestamptz not null default now()
);

create index if not exists idx_agent_identities_owner_created
    on agent_identities (owner_wallet, created_at desc);

create table if not exists document_policies (
    doc_id uuid primary key references documents(id) on delete cascade,
    owner_wallet text not null,
    policy_json jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create index if not exists idx_document_policies_owner_updated
    on document_policies (owner_wallet, updated_at desc);
