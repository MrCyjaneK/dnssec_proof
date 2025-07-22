pub use dnssec_prover::query::ProofBuildingError;
use dnssec_prover::query::{build_txt_proof, build_a_proof, build_aaaa_proof};
use std::ffi::{c_char, c_int, c_uchar, CStr, CString};
use std::net::{ToSocketAddrs};
use std::ptr;

fn create_error_string(error: &str) -> *const c_char {
    match CString::new(error) {
        Ok(c_string) => {
            eprintln!("Error: {}", error);
            let ptr = c_string.as_ptr();
            std::mem::forget(c_string);
            ptr
        }
        Err(_) => {
            eprintln!("Error: Failed to create error string");
            ptr::null()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn get_txt_proof(
    sockaddr: *const c_char,
    query_name: *const c_char,
    result_len: *mut c_int,
    error_msg: *mut *const c_char,
) -> *const c_uchar {
    if !error_msg.is_null() {
        *error_msg = ptr::null();
    }

    let sockaddr_str = match CStr::from_ptr(sockaddr).to_str() {
        Ok(s) => s.to_string(),
        Err(e) => {
            if !error_msg.is_null() {
                *error_msg = create_error_string(&format!("Invalid sockaddr UTF-8: {}", e));
            }
            return ptr::null();
        }
    };

    let query_name_str = match CStr::from_ptr(query_name).to_str() {
        Ok(s) => s.to_string(),
        Err(e) => {
            if !error_msg.is_null() {
                *error_msg = create_error_string(&format!("Invalid query_name UTF-8: {}", e));
            }
            return ptr::null();
        }
    };

    let sockaddr = match sockaddr_str.to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => addr,
            None => {
                if !error_msg.is_null() {
                    *error_msg = create_error_string("No socket address found");
                }
                return ptr::null();
            }
        },
        Err(e) => {
            if !error_msg.is_null() {
                *error_msg = create_error_string(&format!("Failed to resolve socket address: {}", e));
            }
            return ptr::null();
        }
    };

    let query_name = match query_name_str.try_into() {
        Ok(name) => name,
        Err(_) => {
            if !error_msg.is_null() {
                *error_msg = create_error_string("Invalid domain name format");
            }
            return ptr::null();
        }
    };

    let (proof, _) = match build_txt_proof(sockaddr, &query_name) {
        Ok(result) => result,
        Err(e) => {
            if !error_msg.is_null() {
                *error_msg = create_error_string(&format!("Failed to build TXT proof: {}", e));
            }
            return ptr::null();
        }
    };

    *result_len = proof.len() as c_int;
    proof.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn get_a_proof(
    sockaddr: *const c_char,
    query_name: *const c_char,
    result_len: *mut c_int,
    error_msg: *mut *const c_char,
) -> *const c_uchar {
    if !error_msg.is_null() {
        *error_msg = ptr::null();
    }

    let sockaddr_str = match CStr::from_ptr(sockaddr).to_str() {
        Ok(s) => s.to_string(),
        Err(e) => {
            if !error_msg.is_null() {
                *error_msg = create_error_string(&format!("Invalid sockaddr UTF-8: {}", e));
            }
            return ptr::null();
        }
    };

    let query_name_str = match CStr::from_ptr(query_name).to_str() {
        Ok(s) => s.to_string(),
        Err(e) => {
            if !error_msg.is_null() {
                *error_msg = create_error_string(&format!("Invalid query_name UTF-8: {}", e));
            }
            return ptr::null();
        }
    };

    let sockaddr = match sockaddr_str.to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => addr,
            None => {
                if !error_msg.is_null() {
                    *error_msg = create_error_string("No socket address found");
                }
                return ptr::null();
            }
        },
        Err(e) => {
            if !error_msg.is_null() {
                *error_msg = create_error_string(&format!("Failed to resolve socket address: {}", e));
            }
            return ptr::null();
        }
    };

    let query_name = match query_name_str.try_into() {
        Ok(name) => name,
        Err(_) => {
            if !error_msg.is_null() {
                *error_msg = create_error_string("Invalid domain name format");
            }
            return ptr::null();
        }
    };

    let (proof, _) = match build_a_proof(sockaddr, &query_name) {
        Ok(result) => result,
        Err(e) => {
            if !error_msg.is_null() {
                *error_msg = create_error_string(&format!("Failed to build A proof: {}", e));
            }
            return ptr::null();
        }
    };

    *result_len = proof.len() as c_int;
    proof.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn get_aaaa_proof(
    sockaddr: *const c_char,
    query_name: *const c_char,
    result_len: *mut c_int,
    error_msg: *mut *const c_char,
) -> *const c_uchar {
    if !error_msg.is_null() {
        *error_msg = ptr::null();
    }

    let sockaddr_str = match CStr::from_ptr(sockaddr).to_str() {
        Ok(s) => s.to_string(),
        Err(e) => {
            if !error_msg.is_null() {
                *error_msg = create_error_string(&format!("Invalid sockaddr UTF-8: {}", e));
            }
            return ptr::null();
        }
    };

    let query_name_str = match CStr::from_ptr(query_name).to_str() {
        Ok(s) => s.to_string(),
        Err(e) => {
            if !error_msg.is_null() {
                *error_msg = create_error_string(&format!("Invalid query_name UTF-8: {}", e));
            }
            return ptr::null();
        }
    };

    let sockaddr = match sockaddr_str.to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => addr,
            None => {
                if !error_msg.is_null() {
                    *error_msg = create_error_string("No socket address found");
                }
                return ptr::null();
            }
        },
        Err(e) => {
            if !error_msg.is_null() {
                *error_msg = create_error_string(&format!("Failed to resolve socket address: {}", e));
            }
            return ptr::null();
        }
    };

    let query_name = match query_name_str.try_into() {
        Ok(name) => name,
        Err(_) => {
            if !error_msg.is_null() {
                *error_msg = create_error_string("Invalid domain name format");
            }
            return ptr::null();
        }
    };

    let (proof, _) = match build_aaaa_proof(sockaddr, &query_name) {
        Ok(result) => result,
        Err(e) => {
            if !error_msg.is_null() {
                *error_msg = create_error_string(&format!("Failed to build AAAA proof: {}", e));
            }
            return ptr::null();
        }
    };

    *result_len = proof.len() as c_int;
    proof.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn free_error_string(error_msg: *const c_char) {
    if !error_msg.is_null() {
        let _ = CString::from_raw(error_msg as *mut c_char);
    }
}
