use crate::err::*;
use crate::utils::*;

use pgp::Message;

use libc::c_char;
use libc::size_t;
use pgp;

use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;

use pgp::ser::Serialize;
use pgp::types::CompressionAlgorithm;

use pgp::types::PublicKeyTrait;

use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use std::ptr;
use std::slice;

#[no_mangle]
pub extern "C" fn public_key_verify(
    public_key: *mut pgp::PublicKey,
    data: *mut u8,
    data_len: size_t,
    signature: *mut pgp::Signature,
) -> c_char {
    if public_key.is_null() {
        update_last_error(Box::new("public key can't be null".into()));
        return -1;
    }
    if signature.is_null() {
        update_last_error(Box::new("signature can't be null".into()));
        return -1;
    }

    let signature = unsafe { &*signature };
    let public_key = unsafe { &*public_key };
    let data = unsafe { slice::from_raw_parts(data, data_len) };
    let digest = {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize()
    };
    let digest = digest.as_slice();

    let raw_signature = signature.signature.clone();
    match public_key.verify_signature(HashAlgorithm::SHA2_256, digest, &raw_signature) {
        Ok(_) => 0,
        Err(e) => {
            update_last_error(e.to_string());
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn public_key_encrypt(
    public_key: *mut pgp::PublicKey,
    data: *mut u8,
    len: *mut size_t,
) -> *mut u8 {
    if public_key.is_null() {
        update_last_error(Box::new("public key can't be null".into()));
        return ptr::null_mut();
    }
    if data.is_null() {
        update_last_error(Box::new("data can't be null".into()));
        return ptr::null_mut();
    }
    let public_key = unsafe { &*public_key };

    let data = ptr_to_vec(data, unsafe { *len });
    let msg = Message::new_literal_bytes("", data.as_slice());
    let compressed = msg.compress(CompressionAlgorithm::ZLIB);
    if let Err(e) = compressed {
        update_last_error(e.to_string());
        return ptr::null_mut();
    }
    let compressed = compressed.unwrap(); // safe unwrap
    let encrypted = compressed.encrypt_to_keys(
        &mut OsRng,
        SymmetricKeyAlgorithm::AES128,
        &[&public_key][..],
    );
    if let Err(e) = encrypted {
        update_last_error(e.to_string());
        return ptr::null_mut();
    }
    let encrypted = encrypted.unwrap(); // safe unwrap
    let bytes_vec = encrypted.to_bytes();
    if let Err(e) = bytes_vec {
        update_last_error(e.to_string());
        return ptr::null_mut();
    }
    let mut bytes_vec = bytes_vec.unwrap();
    let bytes_ptr = bytes_vec.as_mut_ptr(); // safe unwrap
    unsafe {
        *len = bytes_vec.len();
    }
    std::mem::forget(bytes_vec);
    return bytes_ptr;
}

#[no_mangle]
pub extern "C" fn public_key_sign_and_free(
    public_key: Box<pgp::PublicKey>,
    secret_key: *mut pgp::SignedSecretKey,
) -> *mut pgp::SignedPublicKey {
    let public_key = *public_key;

    let secret_key = unsafe { &*secret_key };

    Box::into_raw(Box::new(public_key.sign(secret_key, || "".into()).unwrap()))
}

#[no_mangle]
pub extern "C" fn public_key_free(public_key: *mut pgp::PublicKey) -> c_char {
    if public_key.is_null() {
        update_last_error(Box::new("public key can't be null".into()));
        return -1;
    }

    unsafe {
        Box::from_raw(public_key);
    }
    0
}
