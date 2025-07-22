pub use dnssec_prover::query::ProofBuildingError;
use dnssec_prover::query::{build_txt_proof, build_a_proof, build_aaaa_proof};
extern crate dnssec_prover;
use dnssec_prover::ser::parse_rr_stream;
use dnssec_prover::validation::verify_rr_stream;
use std::ffi::{c_char, c_int, c_uchar, CStr, CString};
use std::net::{ToSocketAddrs};
use std::ptr;
use std::time::{SystemTime, UNIX_EPOCH};

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

    let rrs = match parse_rr_stream(&proof) {
        Ok(rrs) => rrs,
        Err(e) => {
            if !error_msg.is_null() {
                *error_msg = create_error_string(&format!("Failed to parse RR stream: {:?}", e));
            }
            return ptr::null();
        }
    };

    let verified_rrs = match verify_rr_stream(&rrs) {
        Ok(verified) => verified,
        Err(e) => {
            if !error_msg.is_null() {
                *error_msg = create_error_string(&format!("Failed to verify RR stream: {:?}", e));
            }
            return ptr::null();
        }
    };

    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(e) => {
            if !error_msg.is_null() {
                *error_msg = create_error_string(&format!("Failed to get current time: {}", e));
            }
            return ptr::null();
        }
    };

    if now < verified_rrs.valid_from {
        if !error_msg.is_null() {
            *error_msg = create_error_string("Verification failed: current time is before valid_from");
        }
        return ptr::null();
    }

    if now > verified_rrs.expires {
        if !error_msg.is_null() {
            *error_msg = create_error_string("Verification failed: current time is after expires");
        }
        return ptr::null();
    }

    *result_len = proof.len() as c_int;
    proof.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn free_error_string(error_msg: *const c_char) {
    if !error_msg.is_null() {
        let _ = CString::from_raw(error_msg as *mut c_char);
    }
}