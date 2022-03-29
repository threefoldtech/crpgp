use std::ffi::CStr;
use std::ffi::CString;
use crate::err::*;
use libc::{c_char, size_t};

pub fn ptr_to_vec<T: Clone>(bytes: *mut T, len: size_t) -> Vec<T> {
    let v = unsafe { Vec::from_raw_parts(bytes, len, len) };
    let res = v.clone();
    std::mem::forget(v);
    res
}

pub fn string_to_bytes(s: &str, output_len: *mut size_t) -> Result<*mut c_char, String> {
    unsafe { *output_len = s.len() + 1 };
    let s = CString::new(s);
    if let Err(e) = s {
        return Err(e.to_string())
    }
    Ok(s.unwrap().into_raw())
}

pub fn bytes_to_string(s: *mut c_char) -> Result<String, String> {
    let s = unsafe { CStr::from_ptr(s) }.to_str();
    if let Err(e) = s {
        return Err(e.to_string())
    }
    Ok(s.unwrap().into()) // safe unwrap
}

#[no_mangle]
pub extern "C" fn ptr_free(ptr: *mut u8) -> c_char {
    if ptr.is_null() {
        update_last_error(Box::new("pointer can't be null".into()));
        return -1;
    }
    unsafe {
        Box::from_raw(ptr);
    }
    0
}
