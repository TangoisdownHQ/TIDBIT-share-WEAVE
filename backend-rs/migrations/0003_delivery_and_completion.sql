alter table if exists document_shares
    add column if not exists recipient_name text,
    add column if not exists delivery_json jsonb not null default '[]'::jsonb,
    add column if not exists signer_email text,
    add column if not exists signer_wallet text,
    add column if not exists completion_signature_type text;
