use crate::err::*;
use crate::utils::*;

use libc::c_char;
use libc::size_t;
use pgp;

use pgp::de::Deserialize;
use pgp::ser::Serialize;
use pgp::Deserializable;

use std::ptr;

#[no_mangle]
pub extern "C" fn signature_serialize(
    signature: *mut pgp::Signature,
    output_len: *mut size_t,
) -> *mut u8 {
    if signature.is_null() {
        update_last_error(Box::new("signature can't be null".into()));
        return ptr::null_mut();
    }
    let signature = unsafe { &*signature };
    let bytes = signature.to_bytes();
    if let Err(e) = bytes {
        update_last_error(e.to_string());
        return ptr::null_mut();
    }
    let mut bytes = bytes.unwrap(); // safe unwrap
    bytes.shrink_to_fit();
    unsafe { *output_len = bytes.len() }
    let ptr = bytes.as_mut_ptr();
    std::mem::forget(bytes);
    ptr
}

#[no_mangle]
pub extern "C" fn signature_deserialize(
    signature_bytes: *mut u8,
    len: size_t,
) -> *mut pgp::Signature {
    if signature_bytes.is_null() {
        update_last_error(Box::new("signature bytes can't be null".into()));
        return ptr::null_mut();
    }
    let signature_vec = ptr_to_vec(signature_bytes, len);
    let signature = pgp::Signature::from_slice(pgp::types::Version::Old, signature_vec.as_slice());
    match signature {
        Ok(v) => Box::into_raw(Box::new(v)),
        Err(e) => {
            update_last_error(e.to_string());
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn signature_to_armored(
    signature: *mut pgp::Signature,
    output_len: *mut size_t,
) -> *mut c_char {
    if signature.is_null() {
        update_last_error(Box::new("signature can't be null".into()));
        return ptr::null_mut();
    }
    let signature = unsafe { &*signature };
    let s = pgp::StandaloneSignature::new(signature.clone()).to_armored_string(None);
    match s {
        Ok(v) => {
            let p = string_to_bytes(&v, output_len);
            if let Err(e) = p {
                update_last_error(Box::new(e.into()));
                return ptr::null_mut();

            }
            p.unwrap() // safe unwrap

        }
        Err(e) => {
            update_last_error(e.to_string());
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn signature_from_armored(
    signature_bytes: *mut c_char,
) -> *mut pgp::Signature {
    if signature_bytes.is_null() {
        update_last_error(Box::new("signature bytes can't be null".into()));
        return ptr::null_mut();
    }
    let signature = bytes_to_string(signature_bytes);
    if let Err(e) = signature {
        update_last_error(e);
        return ptr::null_mut();
    }
    let signature = signature.unwrap(); // safe unwrap
    let signature = pgp::StandaloneSignature::from_string(&signature);
    match signature {
        Ok(v) => Box::into_raw(Box::new(v.0.signature)),
        Err(e) => {
            update_last_error(e.to_string());
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn signature_free(signature: *mut pgp::Signature) -> c_char {
    if signature.is_null() {
        update_last_error(Box::new("signature can't be null".into()));
        return -1;
    }
    unsafe {
        Box::from_raw(signature);
    }
    0
}
