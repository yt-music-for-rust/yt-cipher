use std::{
    ffi::{CStr, CString},
    os::raw::c_char,
};

use crate::sig::{extract_decipher_func, extract_n_transform_func, extract_tce_func};

mod sig;

#[unsafe(no_mangle)]
pub extern "C" fn extract_decode_script(input: *const c_char, output: *mut *mut c_char) -> bool {
    macro_rules! return_error {
        ($msg: expr) => {{
            let err = CString::new($msg).unwrap();
            unsafe {
                *output = err.into_raw();
            }
            return false;
        }};
    }

    if input.is_null() {
        return_error!("Input string is null");
    }

    if output.is_null() {
        return_error!("Output string is null");
    }

    let c_str = unsafe { CStr::from_ptr(input) };

    let body = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return_error!("Invalid Input string"),
    };

    let (name, code) = match extract_tce_func(body) {
        Ok(etf) => (etf.name, etf.code),
        Err(e) => return_error!(e),
    };

    let decipher_script = match extract_decipher_func(body, &code) {
        Ok(ds) => ds,
        Err(e) => return_error!(e),
    };

    let n_transform_script = match extract_n_transform_func(body, &name, &code) {
        Ok(nts) => nts,
        Err(e) => return_error!(e),
    };

    let result = CString::new(decipher_script + &n_transform_script)
        .unwrap()
        .into_raw();

    unsafe {
        *output = result;
    }

    true
}
