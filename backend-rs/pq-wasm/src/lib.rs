use core::slice;
use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};

const MLDSA65_SEED_LEN: usize = 32;
const MLDSA65_SIGNING_SEED_LEN: usize = 32;

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
    if seed_ptr.is_null() || public_key_ptr.is_null() || secret_key_ptr.is_null() {
        return -1;
    }
    if seed_len != MLDSA65_SEED_LEN
        || public_key_len != ml_dsa_65::PK_LEN
        || secret_key_len != ml_dsa_65::SK_LEN
    {
        return -2;
    }

    let seed = unsafe { slice::from_raw_parts(seed_ptr, seed_len) };
    let seed: [u8; MLDSA65_SEED_LEN] = match seed.try_into() {
        Ok(value) => value,
        Err(_) => return -3,
    };
    let (public_key, secret_key) = ml_dsa_65::KG::keygen_from_seed(&seed);
    let public_key_bytes = public_key.into_bytes();
    let secret_key_bytes = secret_key.into_bytes();

    unsafe {
        slice::from_raw_parts_mut(public_key_ptr, public_key_len).copy_from_slice(&public_key_bytes);
        slice::from_raw_parts_mut(secret_key_ptr, secret_key_len).copy_from_slice(&secret_key_bytes);
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
    if secret_key_ptr.is_null()
        || message_ptr.is_null()
        || signing_seed_ptr.is_null()
        || signature_ptr.is_null()
    {
        return -1;
    }
    if secret_key_len != ml_dsa_65::SK_LEN
        || signing_seed_len != MLDSA65_SIGNING_SEED_LEN
        || signature_len != ml_dsa_65::SIG_LEN
    {
        return -2;
    }

    let secret_key_bytes = unsafe { slice::from_raw_parts(secret_key_ptr, secret_key_len) };
    let message_bytes = unsafe { slice::from_raw_parts(message_ptr, message_len) };
    let signing_seed_bytes = unsafe { slice::from_raw_parts(signing_seed_ptr, signing_seed_len) };
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

    unsafe {
        slice::from_raw_parts_mut(signature_ptr, signature_len).copy_from_slice(&signature);
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
    if public_key_ptr.is_null() || message_ptr.is_null() || signature_ptr.is_null() {
        return -1;
    }
    if public_key_len != ml_dsa_65::PK_LEN || signature_len != ml_dsa_65::SIG_LEN {
        return -2;
    }

    let public_key_bytes = unsafe { slice::from_raw_parts(public_key_ptr, public_key_len) };
    let message_bytes = unsafe { slice::from_raw_parts(message_ptr, message_len) };
    let signature_bytes = unsafe { slice::from_raw_parts(signature_ptr, signature_len) };

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
