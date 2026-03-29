alter table if exists document_shares
    alter column recipient_wallet drop not null;

alter table if exists document_shares
    add column if not exists recipient_email text,
    add column if not exists recipient_phone text,
    add column if not exists access_token text,
    add column if not exists status text not null default 'sent',
    add column if not exists viewed_at timestamptz,
    add column if not exists signed_at timestamptz,
    add column if not exists completed_at timestamptz,
    add column if not exists signer_name text,
    add column if not exists signer_title text,
    add column if not exists signer_org text,
    add column if not exists sign_reason text,
    add column if not exists annotation_json jsonb not null default '{}'::jsonb;

create unique index if not exists idx_document_shares_access_token
    on document_shares (access_token)
    where access_token is not null;

create index if not exists idx_document_shares_status_created
    on document_shares (status, created_at desc);
