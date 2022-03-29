use std::ffi::CString;
use std::ffi::CStr;
use crate::err::*;
use crate::utils::*;

use pgp::Deserializable;
use pgp::Message;

use libc::c_char;
use libc::size_t;
use pgp;
use pgp::crypto::hash::HashAlgorithm;
use pgp::types::KeyTrait;
use pgp::types::SecretKeyTrait;
use sha2::{Digest, Sha256};
use std::ptr;
use std::slice;
use pgp::ser::Serialize;

#[no_mangle]
pub extern "C" fn signed_secret_key_public_key(
    signed_secret_key: *mut pgp::SignedSecretKey,
) -> *mut pgp::PublicKey {
    if signed_secret_key.is_null() {
        update_last_error(Box::new("signed secret key can't be null".into()));
        return ptr::null_mut();
    }
    let signed_secret_key = unsafe { &*signed_secret_key };
    let public_key = signed_secret_key.public_key();
    Box::into_raw(Box::new(public_key))
}

#[no_mangle]
pub extern "C" fn signed_secret_key_create_signature(
    signed_secret_key: *mut pgp::SignedSecretKey,
    data: *mut u8,
    len: size_t,
) -> *mut pgp::Signature {
    if signed_secret_key.is_null() {
        update_last_error(Box::new("signed secret key can't be null".into()));
        return ptr::null_mut();
    }
    if data.is_null() {
        update_last_error(Box::new("data can't be null".into()));
        return ptr::null_mut();
    }
    let signed_secret_key = unsafe { &*signed_secret_key };
    let data = unsafe { slice::from_raw_parts(data, len) };
    let digest = {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize()
    };
    let digest = digest.as_slice();
    let passwd_fn = || String::new();
    let signature = signed_secret_key.create_signature(passwd_fn, HashAlgorithm::SHA2_256, digest);
    if let Err(e) = signature {
        update_last_error(e.to_string());
        return ptr::null_mut();
    }
    let now = chrono::Utc::now();
    let signature = pgp::Signature::new(
        pgp::types::Version::Old,
        pgp::packet::SignatureVersion::V4,
        pgp::packet::SignatureType::Binary,
        signed_secret_key.algorithm(),
        HashAlgorithm::SHA2_256,
        [digest[0], digest[1]],
        signature.unwrap(), // safe unwrap
        vec![
            pgp::packet::Subpacket::SignatureCreationTime(now),
            pgp::packet::Subpacket::Issuer(signed_secret_key.key_id()),
        ],
        vec![],
    );
    Box::into_raw(Box::new(signature))
}

#[no_mangle]
pub extern "C" fn signed_secret_key_decrypt(
    secret_key: *mut pgp::SignedSecretKey,
    encrypted: *mut u8,
    len: *mut size_t,
) -> *mut u8 {
    if secret_key.is_null() {
        update_last_error(Box::new("secret key can't be null".into()));
        return ptr::null_mut();
    }
    if encrypted.is_null() {
        update_last_error(Box::new("encrypted data can't be null".into()));
        return ptr::null_mut();
    }
    if len.is_null() {
        update_last_error(Box::new("length data can't be null".into()));
        return ptr::null_mut();
    }
    let secret_key = unsafe { &*secret_key };

    let data = ptr_to_vec(encrypted, unsafe { *len });
    let msg = Message::from_bytes(data.as_slice());
    if let Err(e) = msg {
        update_last_error(e.to_string());
        return ptr::null_mut();
    }
    let msg = msg.unwrap(); // safe unwrap
    let msg = msg.decrypt(|| "".into(), || "".into(), &[secret_key][..]);
    if let Err(e) = msg {
        update_last_error(e.to_string());
        return ptr::null_mut();
    }
    let mut msg = msg.unwrap(); // safe unwrap
    let decrypted = msg.0.next();
    if let None = decrypted {
        update_last_error(Box::new("message doesn't contain content".into()));
        return ptr::null_mut();
    }
    let decrypted = decrypted.unwrap(); // safe unwrap
    if let Err(e) = decrypted {
        update_last_error(e.to_string());
        return ptr::null_mut();
    }
    let decrypted = decrypted.unwrap(); // safe unwrap
    let decompressed = decrypted.decompress();
    if let Err(e) = decompressed {
        update_last_error(e.to_string());
        return ptr::null_mut();
    }
    let decompressed = decompressed.unwrap(); // safe unwrap
    let content = decompressed.get_content();
    if let Err(e) = content {
        update_last_error(e.to_string());
        return ptr::null_mut();
    }
    if let Ok(None) = content {
        update_last_error(Box::new("Message content is None(?!)".into()));
        return ptr::null_mut();
    }
    let content = content.unwrap(); // safe unwrap
    let mut content = content.unwrap(); // safe unwrap
    content.shrink_to_fit();
    let res = content.as_mut_ptr();
    unsafe {
        *len = content.len();
    }
    std::mem::forget(content);
    res
}

#[no_mangle]
pub extern "C" fn signed_secret_key_free(signed_secret_key: *mut pgp::SignedSecretKey) -> c_char {
    if signed_secret_key.is_null() {
        update_last_error(Box::new("signed secret key can't be null".into()));
        return -1;
    }

    unsafe {
        Box::from_raw(signed_secret_key);
    }
    0
}

#[no_mangle]
pub extern "C" fn signed_secret_key_to_bytes(signed_secret_key: *mut pgp::SignedSecretKey, len: *mut size_t) -> *mut u8 {
    if signed_secret_key.is_null() {
        update_last_error(Box::new("signed secret key can't be null".into()));
        return ptr::null_mut();
    }
    if len.is_null() {
        update_last_error(Box::new("len can't be null".into()));
        return ptr::null_mut();
    }

    let signed_secret_key = unsafe {
        &*signed_secret_key
    };
    let vec = signed_secret_key.to_bytes();
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
pub extern "C" fn signed_secret_key_from_bytes(bytes: *mut u8, len: size_t) -> *mut pgp::SignedSecretKey {
    if bytes.is_null() {
        update_last_error(Box::new("bytes can't be null".into()));
        return ptr::null_mut();
    }
    let vec = ptr_to_vec(bytes, len);
    let sk = pgp::SignedSecretKey::from_bytes(vec.as_slice());
    if let Err(e) = sk {
        update_last_error(Box::new(e.to_string()));
        return ptr::null_mut()
    }
    let sk = sk.unwrap(); // safe unwrap 
    Box::into_raw(Box::new(sk))
}


#[no_mangle]
pub extern "C" fn signed_secret_key_to_armored(signed_secret_key: *mut pgp::SignedSecretKey) -> *mut c_char {
    if signed_secret_key.is_null() {
        update_last_error(Box::new("signed secret key can't be null".into()));
        return ptr::null_mut();
    }

    let signed_secret_key = unsafe {
        &*signed_secret_key
    };
    let s = signed_secret_key.to_armored_string(None);
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
pub extern "C" fn signed_secret_key_from_armored(s: *mut c_char) -> *mut pgp::SignedSecretKey {
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
    let sk = pgp::SignedSecretKey::from_string(s);
    if let Err(e) = sk {
        update_last_error(Box::new(e.to_string()));
        return ptr::null_mut()
    }
    let sk = sk.unwrap().0; // safe unwrap 
    Box::into_raw(Box::new(sk))
}
