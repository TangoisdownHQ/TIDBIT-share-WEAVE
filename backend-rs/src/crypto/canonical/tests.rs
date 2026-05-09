//src/crypto/canonical/tests.rs

use crate::crypto::canonical::{CanonicalDocumentV1, DocumentEnvelopeV1};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use fips203::ml_kem_768;
use fips203::traits::{Encaps, SerDes as MlKemSerDes};
use crate::crypto::canonical::kem::{
    mlkem_decapsulate_b64, mlkem_encapsulate_b64, mlkem_generate_keypair_b64,
};

#[test]
fn mlkem_roundtrip_b64() {
    let kp = mlkem_generate_keypair_b64();

    let (ct_b64, ss1) = mlkem_encapsulate_b64(&kp.pk_b64).expect("encapsulate");

    let ss2 = mlkem_decapsulate_b64(&kp.sk_b64, &ct_b64).expect("decapsulate");

    assert_eq!(ss1, ss2);
}

#[test]
fn fips203_browser_encapsulation_decapsulates_on_server_path() {
    let kp = mlkem_generate_keypair_b64();
    let pk_bytes = URL_SAFE_NO_PAD.decode(&kp.pk_b64).expect("decode pk");
    let pk = ml_kem_768::EncapsKey::try_from_bytes(
        pk_bytes
            .try_into()
            .expect("browser/public key bytes must match ML-KEM-768 length"),
    )
    .expect("deserialize browser/public key");

    let (shared_secret, ciphertext) = pk.encaps_from_seed(&[7u8; 32]);
    let ct_b64 = URL_SAFE_NO_PAD.encode(ciphertext.into_bytes());
    let decapsulated = mlkem_decapsulate_b64(&kp.sk_b64, &ct_b64).expect("server decapsulation");

    assert_eq!(shared_secret.into_bytes().to_vec(), decapsulated);
}

#[test]
fn mixed_case_solana_owner_envelopes_decrypt_on_server_path() {
    let kp = mlkem_generate_keypair_b64();
    let wallet = "SoLAbCdEfGh123456789ExampleWallet";
    let plaintext = b"hello from solana";
    let doc = CanonicalDocumentV1::from_plaintext(
        "logical-1".to_string(),
        plaintext,
        Some("note.txt".to_string()),
        Some("text/plain".to_string()),
    );

    let (envelope, _) = DocumentEnvelopeV1::create_mlkem_owner(
        wallet.to_string(),
        &kp.pk_b64,
        1_715_218_400,
        doc,
        plaintext,
    )
    .expect("create envelope");

    assert_eq!(envelope.owner, wallet);
    assert_eq!(envelope.encryption.wrapped_keys[0].recipient, wallet);

    let decrypted = envelope
        .decrypt_for_owner_mlkem(&kp.sk_b64)
        .expect("decrypt owner envelope");

    assert_eq!(decrypted, plaintext);
}

#[test]
fn legacy_lowercased_solana_wrapped_keys_still_decrypt() {
    let kp = mlkem_generate_keypair_b64();
    let wallet = "SoLAbCdEfGh123456789ExampleWallet";
    let plaintext = b"legacy solana path";
    let doc = CanonicalDocumentV1::from_plaintext(
        "logical-2".to_string(),
        plaintext,
        Some("legacy.txt".to_string()),
        Some("text/plain".to_string()),
    );

    let (mut envelope, _) = DocumentEnvelopeV1::create_mlkem_owner(
        wallet.to_string(),
        &kp.pk_b64,
        1_715_218_401,
        doc,
        plaintext,
    )
    .expect("create envelope");

    envelope.encryption.wrapped_keys[0].recipient = wallet.to_ascii_lowercase();

    let decrypted = envelope
        .decrypt_for_wallet_mlkem(wallet, &kp.sk_b64)
        .expect("decrypt legacy lowercase recipient");

    assert_eq!(decrypted, plaintext);
}
