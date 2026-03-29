alter table document_shares
    add column if not exists recipient_chain text;

create index if not exists idx_document_shares_recipient_chain_wallet_doc
    on document_shares (recipient_chain, recipient_wallet, doc_id);
