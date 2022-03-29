use crate::err::*;
use crate::utils::*;

use pgp::Message;

use libc::size_t;
use pgp;

use pgp::crypto::sym::SymmetricKeyAlgorithm;

use pgp::ser::Serialize;
use pgp::types::CompressionAlgorithm;

use pgp::types::PublicKeyTrait;

use rand::rngs::OsRng;

use std::ptr;

pub fn encrypt(
    public_key: &impl PublicKeyTrait,
    data: *mut u8,
    len: *mut size_t,
) -> *mut u8 {
    if data.is_null() {
        update_last_error(Box::new("data can't be null".into()));
        return ptr::null_mut();
    }

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
    bytes_vec.shrink_to_fit();
    let bytes_ptr = bytes_vec.as_mut_ptr(); // safe unwrap
    unsafe {
        *len = bytes_vec.len();
    }
    std::mem::forget(bytes_vec);
    return bytes_ptr;
}
