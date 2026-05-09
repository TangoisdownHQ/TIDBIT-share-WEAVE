//src/crypto/canonical/tests.rs

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
