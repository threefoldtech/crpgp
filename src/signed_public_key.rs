use std::ffi::CString;
use std::ffi::CStr;
use crate::encrypt::encrypt;
use crate::err::*;
use crate::utils::*;
use pgp::ser::Serialize;
use pgp::Deserializable;
use libc::c_char;
use libc::size_t;
use pgp;

use pgp::crypto::hash::HashAlgorithm;


use pgp::types::PublicKeyTrait;
use pgp::types::KeyTrait;
use sha2::{Digest, Sha256};

use std::ptr;
use std::slice;

#[no_mangle]
pub extern "C" fn signed_public_key_verify(
    signed_public_key: *mut pgp::SignedPublicKey,
    data: *mut u8,
    data_len: size_t,
    signature: *mut pgp::Signature,
) -> c_char {
    if signed_public_key.is_null() {
        update_last_error(Box::new("signed public key can't be null".into()));
        return -1;
    }
    if signature.is_null() {
        update_last_error(Box::new("signature can't be null".into()));
        return -1;
    }

    let signature = unsafe { &*signature };
    let public_key = unsafe { &*signed_public_key };
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
pub extern "C" fn signed_public_key_encrypt(
    signed_public_key: *mut pgp::SignedPublicKey,
    data: *mut u8,
    len: *mut size_t,
) -> *mut u8 {
    if signed_public_key.is_null() {
        update_last_error(Box::new("signed public key can't be null".into()));
        return ptr::null_mut();
    }
    let public_key = unsafe { &*signed_public_key };
    return encrypt(public_key, data, len)
}

#[no_mangle]
pub extern "C" fn signed_public_key_encrypt_with_any(
    signed_public_key: *mut pgp::SignedPublicKey,
    data: *mut u8,
    len: *mut size_t,
) -> *mut u8 {
    if signed_public_key.is_null() {
        update_last_error(Box::new("signed public key can't be null".into()));
        return ptr::null_mut();
    }
    let public_key = unsafe { &*signed_public_key };
    if public_key.is_encryption_key() {
        return encrypt(public_key, data, len)
    } else {
        for k in public_key.public_subkeys.iter() {
            if k.is_encryption_key() {
                return encrypt(k, data, len)
            }
        }
    }
    update_last_error(Box::new("key and all of its subkeys is of type that can't encrypt data".into()));
    return ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn signed_public_key_to_bytes(signed_public_key: *mut pgp::SignedPublicKey, len: *mut size_t) -> *mut u8 {
    if signed_public_key.is_null() {
        update_last_error(Box::new("signed public key can't be null".into()));
        return ptr::null_mut();
    }
    if len.is_null() {
        update_last_error(Box::new("len can't be null".into()));
        return ptr::null_mut();
    }

    let signed_public_key = unsafe {
        &*signed_public_key
    };
    let vec = signed_public_key.to_bytes();
    if let Err(e) = vec {
        update_last_error(Box::new(e.to_string()));
        return ptr::null_mut()
    }
    let mut vec = vec.unwrap(); // safe unwrap
    vec.shrink_to_fit();
    let res = vec.as_mut_ptr();
    unsafe {
        *len = vec.len()
    }
    std::mem::forget(vec);
    res
}

#[no_mangle]
pub extern "C" fn signed_public_key_from_bytes(bytes: *mut u8, len: size_t) -> *mut pgp::SignedPublicKey {
    if bytes.is_null() {
        update_last_error(Box::new("bytes can't be null".into()));
        return ptr::null_mut();
    }
    let vec = ptr_to_vec(bytes, len);
    let sk = pgp::SignedPublicKey::from_bytes(vec.as_slice());
    if let Err(e) = sk {
        update_last_error(Box::new(e.to_string()));
        return ptr::null_mut()
    }
    let sk = sk.unwrap(); // safe unwrap 
    Box::into_raw(Box::new(sk))
}


#[no_mangle]
pub extern "C" fn signed_public_key_to_armored(signed_public_key: *mut pgp::SignedPublicKey) -> *mut c_char {
    if signed_public_key.is_null() {
        update_last_error(Box::new("signed public key can't be null".into()));
        return ptr::null_mut();
    }

    let signed_public_key = unsafe {
        &*signed_public_key
    };
    let s = signed_public_key.to_armored_string(None);
    if let Err(e) = s {
        update_last_error(Box::new(e.to_string()));
        return ptr::null_mut()
    }
    let s = s.unwrap(); // safe unwrap
    let s = CString::new(s);
    if let Err(e) = s {
        update_last_error(Box::new(e.to_string()));
        return ptr::null_mut()
    }
    let s = s.unwrap(); // safe unwrap
    return s.into_raw()
}

#[no_mangle]
pub extern "C" fn signed_public_key_from_armored(s: *mut c_char) -> *mut pgp::SignedPublicKey {
    if s.is_null() {
        update_last_error(Box::new("armored string can't be null".into()));
        return ptr::null_mut();
    }
    let s = unsafe { CStr::from_ptr(s) }.to_str();
    if let Err(e) = s {
        update_last_error(Box::new(e.to_string()));
        return ptr::null_mut()
    }
    let s = s.unwrap(); // safe unwrap
    let sk = pgp::SignedPublicKey::from_string(s);
    if let Err(e) = sk {
        update_last_error(Box::new(e.to_string()));
        return ptr::null_mut()
    }
    let sk = sk.unwrap().0; // safe unwrap 
    Box::into_raw(Box::new(sk))
}

#[no_mangle]
pub extern "C" fn signed_public_key_free(public_key: *mut pgp::SignedPublicKey) -> c_char {
    if public_key.is_null() {
        update_last_error(Box::new("signed public key can't be null".into()));
        return -1;
    }

    unsafe {
        Box::from_raw(public_key);
    }
    0
}
