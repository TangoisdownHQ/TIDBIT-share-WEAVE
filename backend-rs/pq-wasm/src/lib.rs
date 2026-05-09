use core::slice;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use fips203::ml_kem_768;
use fips203::traits::{Encaps, SerDes as MlKemSerDes};
use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};

const MLDSA65_SEED_LEN: usize = 32;
const MLDSA65_SIGNING_SEED_LEN: usize = 32;
const MLKEM768_SEED_LEN: usize = 32;
const MLKEM768_SHARED_SECRET_LEN: usize = 32;
const XCHACHA20POLY1305_KEY_LEN: usize = 32;
const XCHACHA20POLY1305_NONCE_LEN: usize = 24;

fn read_input<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], i32> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(-1);
    }
    Ok(unsafe { slice::from_raw_parts(ptr, len) })
}

fn write_output(ptr: *mut u8, len: usize, bytes: &[u8]) -> Result<(), i32> {
    if len != bytes.len() {
        return Err(-2);
    }
    if len == 0 {
        return Ok(());
    }
    if ptr.is_null() {
        return Err(-1);
    }
    unsafe {
        slice::from_raw_parts_mut(ptr, len).copy_from_slice(bytes);
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn mldsa65_public_key_len() -> usize {
    ml_dsa_65::PK_LEN
}

#[no_mangle]
pub extern "C" fn mldsa65_secret_key_len() -> usize {
    ml_dsa_65::SK_LEN
}

#[no_mangle]
pub extern "C" fn mldsa65_signature_len() -> usize {
    ml_dsa_65::SIG_LEN
}

#[no_mangle]
pub extern "C" fn mlkem768_public_key_len() -> usize {
    ml_kem_768::EK_LEN
}

#[no_mangle]
pub extern "C" fn mlkem768_ciphertext_len() -> usize {
    ml_kem_768::CT_LEN
}

#[no_mangle]
pub extern "C" fn mlkem768_shared_secret_len() -> usize {
    MLKEM768_SHARED_SECRET_LEN
}

#[no_mangle]
pub extern "C" fn xchacha20poly1305_ciphertext_len(plaintext_len: usize) -> usize {
    plaintext_len + 16
}

#[no_mangle]
pub extern "C" fn wasm_alloc(len: usize) -> *mut u8 {
    let mut buffer = Vec::<u8>::with_capacity(len);
    let ptr = buffer.as_mut_ptr();
    core::mem::forget(buffer);
    ptr
}

#[no_mangle]
pub extern "C" fn wasm_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    unsafe {
        drop(Vec::from_raw_parts(ptr, len, len));
    }
}

#[no_mangle]
pub extern "C" fn mldsa65_keygen_from_seed(
    seed_ptr: *const u8,
    seed_len: usize,
    public_key_ptr: *mut u8,
    public_key_len: usize,
    secret_key_ptr: *mut u8,
    secret_key_len: usize,
) -> i32 {
    if seed_len != MLDSA65_SEED_LEN
        || public_key_len != ml_dsa_65::PK_LEN
        || secret_key_len != ml_dsa_65::SK_LEN
    {
        return -2;
    }

    let seed = match read_input(seed_ptr, seed_len) {
        Ok(value) => value,
        Err(code) => return code,
    };
    let seed: [u8; MLDSA65_SEED_LEN] = match seed.try_into() {
        Ok(value) => value,
        Err(_) => return -3,
    };
    let (public_key, secret_key) = ml_dsa_65::KG::keygen_from_seed(&seed);
    let public_key_bytes = public_key.into_bytes();
    let secret_key_bytes = secret_key.into_bytes();

    if let Err(code) = write_output(public_key_ptr, public_key_len, &public_key_bytes) {
        return code;
    }
    if let Err(code) = write_output(secret_key_ptr, secret_key_len, &secret_key_bytes) {
        return code;
    }

    0
}

#[no_mangle]
pub extern "C" fn mldsa65_sign_with_seed(
    secret_key_ptr: *const u8,
    secret_key_len: usize,
    message_ptr: *const u8,
    message_len: usize,
    signing_seed_ptr: *const u8,
    signing_seed_len: usize,
    signature_ptr: *mut u8,
    signature_len: usize,
) -> i32 {
    if secret_key_len != ml_dsa_65::SK_LEN
        || signing_seed_len != MLDSA65_SIGNING_SEED_LEN
        || signature_len != ml_dsa_65::SIG_LEN
    {
        return -2;
    }

    let secret_key_bytes = match read_input(secret_key_ptr, secret_key_len) {
        Ok(value) => value,
        Err(code) => return code,
    };
    let message_bytes = match read_input(message_ptr, message_len) {
        Ok(value) => value,
        Err(code) => return code,
    };
    let signing_seed_bytes = match read_input(signing_seed_ptr, signing_seed_len) {
        Ok(value) => value,
        Err(code) => return code,
    };
    let signing_seed: [u8; MLDSA65_SIGNING_SEED_LEN] = match signing_seed_bytes.try_into() {
        Ok(value) => value,
        Err(_) => return -3,
    };
    let secret_key = match ml_dsa_65::PrivateKey::try_from_bytes(
        match secret_key_bytes.try_into() {
            Ok(value) => value,
            Err(_) => return -4,
        },
    ) {
        Ok(value) => value,
        Err(_) => return -5,
    };
    let signature = match secret_key.try_sign_with_seed(&signing_seed, message_bytes, &[]) {
        Ok(value) => value,
        Err(_) => return -6,
    };

    if let Err(code) = write_output(signature_ptr, signature_len, &signature) {
        return code;
    }

    0
}

#[no_mangle]
pub extern "C" fn mldsa65_verify(
    public_key_ptr: *const u8,
    public_key_len: usize,
    message_ptr: *const u8,
    message_len: usize,
    signature_ptr: *const u8,
    signature_len: usize,
) -> i32 {
    if public_key_len != ml_dsa_65::PK_LEN || signature_len != ml_dsa_65::SIG_LEN {
        return -2;
    }

    let public_key_bytes = match read_input(public_key_ptr, public_key_len) {
        Ok(value) => value,
        Err(code) => return code,
    };
    let message_bytes = match read_input(message_ptr, message_len) {
        Ok(value) => value,
        Err(code) => return code,
    };
    let signature_bytes = match read_input(signature_ptr, signature_len) {
        Ok(value) => value,
        Err(code) => return code,
    };

    let public_key = match ml_dsa_65::PublicKey::try_from_bytes(
        match public_key_bytes.try_into() {
            Ok(value) => value,
            Err(_) => return -3,
        },
    ) {
        Ok(value) => value,
        Err(_) => return -4,
    };
    let signature: [u8; ml_dsa_65::SIG_LEN] = match signature_bytes.try_into() {
        Ok(value) => value,
        Err(_) => return -5,
    };

    if public_key.verify(message_bytes, &signature, &[]) {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn mlkem768_encaps_from_seed(
    public_key_ptr: *const u8,
    public_key_len: usize,
    seed_ptr: *const u8,
    seed_len: usize,
    ciphertext_ptr: *mut u8,
    ciphertext_len: usize,
    shared_secret_ptr: *mut u8,
    shared_secret_len: usize,
) -> i32 {
    if public_key_len != ml_kem_768::EK_LEN
        || seed_len != MLKEM768_SEED_LEN
        || ciphertext_len != ml_kem_768::CT_LEN
        || shared_secret_len != MLKEM768_SHARED_SECRET_LEN
    {
        return -2;
    }

    let public_key_bytes = match read_input(public_key_ptr, public_key_len) {
        Ok(value) => value,
        Err(code) => return code,
    };
    let seed_bytes = match read_input(seed_ptr, seed_len) {
        Ok(value) => value,
        Err(code) => return code,
    };

    let public_key = match ml_kem_768::EncapsKey::try_from_bytes(
        match public_key_bytes.try_into() {
            Ok(value) => value,
            Err(_) => return -3,
        },
    ) {
        Ok(value) => value,
        Err(_) => return -4,
    };
    let seed: [u8; MLKEM768_SEED_LEN] = match seed_bytes.try_into() {
        Ok(value) => value,
        Err(_) => return -5,
    };

    let (shared_secret, ciphertext) = public_key.encaps_from_seed(&seed);
    let ciphertext_bytes = ciphertext.into_bytes();
    let shared_secret_bytes = shared_secret.into_bytes();

    if let Err(code) = write_output(ciphertext_ptr, ciphertext_len, &ciphertext_bytes) {
        return code;
    }
    if let Err(code) = write_output(shared_secret_ptr, shared_secret_len, &shared_secret_bytes) {
        return code;
    }

    0
}

#[no_mangle]
pub extern "C" fn xchacha20poly1305_encrypt(
    key_ptr: *const u8,
    key_len: usize,
    nonce_ptr: *const u8,
    nonce_len: usize,
    plaintext_ptr: *const u8,
    plaintext_len: usize,
    ciphertext_ptr: *mut u8,
    ciphertext_len: usize,
) -> i32 {
    if key_len != XCHACHA20POLY1305_KEY_LEN || nonce_len != XCHACHA20POLY1305_NONCE_LEN {
        return -2;
    }
    if ciphertext_len != xchacha20poly1305_ciphertext_len(plaintext_len) {
        return -3;
    }

    let key_bytes = match read_input(key_ptr, key_len) {
        Ok(value) => value,
        Err(code) => return code,
    };
    let nonce_bytes = match read_input(nonce_ptr, nonce_len) {
        Ok(value) => value,
        Err(code) => return code,
    };
    let plaintext_bytes = match read_input(plaintext_ptr, plaintext_len) {
        Ok(value) => value,
        Err(code) => return code,
    };

    let key_arr: [u8; XCHACHA20POLY1305_KEY_LEN] = match key_bytes.try_into() {
        Ok(value) => value,
        Err(_) => return -4,
    };
    let nonce_arr: [u8; XCHACHA20POLY1305_NONCE_LEN] = match nonce_bytes.try_into() {
        Ok(value) => value,
        Err(_) => return -5,
    };

    let cipher = XChaCha20Poly1305::new((&key_arr).into());
    let ciphertext = match cipher.encrypt(XNonce::from_slice(&nonce_arr), plaintext_bytes) {
        Ok(value) => value,
        Err(_) => return -6,
    };

    match write_output(ciphertext_ptr, ciphertext_len, &ciphertext) {
        Ok(()) => 0,
        Err(code) => code,
    }
}
