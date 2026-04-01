create table if not exists wallet_mlkem_keys (
    wallet text primary key,
    kem text not null default 'mlkem768',
    pk_b64 text not null,
    sk_b64 text not null,
    source text not null default 'generated',
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);
