//src/crypto/canonical/tests.rs

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
