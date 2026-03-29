create extension if not exists pgcrypto;

create table if not exists documents (
    id uuid primary key default gen_random_uuid(),
    owner_wallet text not null,
    hash_hex text not null,
    label text,
    file_size bigint not null,
    mime_type text not null,
    storage_path text not null,
    version integer not null default 1,
    parent_id uuid references documents(id) on delete set null,
    arweave_tx text,
    is_deleted boolean not null default false,
    created_at timestamptz not null default now()
);

create table if not exists document_events (
    id uuid primary key default gen_random_uuid(),
    doc_id uuid not null references documents(id) on delete cascade,
    actor_wallet text not null,
    event_type text not null,
    payload jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now()
);

create table if not exists document_shares (
    id uuid primary key default gen_random_uuid(),
    doc_id uuid not null references documents(id) on delete cascade,
    sender_wallet text not null,
    recipient_wallet text not null,
    envelope_id uuid not null,
    note text,
    created_at timestamptz not null default now()
);

create table if not exists c2c_events (
    id text primary key,
    owner_wallet text not null,
    document_id uuid not null references documents(id) on delete cascade,
    version_id uuid,
    action text not null,
    hash_hex text,
    signature text,
    ip_address text,
    created_at timestamptz not null default now()
);

create index if not exists idx_documents_owner_created
    on documents (owner_wallet, created_at desc)
    where is_deleted = false;

create unique index if not exists idx_documents_owner_hash_active
    on documents (owner_wallet, hash_hex)
    where is_deleted = false;

create index if not exists idx_document_events_doc_created
    on document_events (doc_id, created_at desc);

create index if not exists idx_document_shares_recipient_doc
    on document_shares (recipient_wallet, doc_id);

create index if not exists idx_c2c_events_owner_document_created
    on c2c_events (owner_wallet, document_id, created_at desc);
