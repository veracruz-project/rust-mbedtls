/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

// needed to have common code for `mod support` in unit and integrations tests
extern crate mbedtls;

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use mbedtls::pk::Pk;
use mbedtls::rng::CtrDrbg;
use mbedtls::ssl::config::{AuthMode, Endpoint, Preset, Transport};
use mbedtls::ssl::{Config, Context, Version};
use mbedtls::x509::Certificate;
use mbedtls::Result as TlsResult;

#[path = "../tests/support/mod.rs"]
mod support;
use support::entropy::entropy_new;
use support::keys;
use support::rand::test_rng;

#[cfg(feature = "debug")]
use std::borrow::Cow;

use ear::{Ear, TrustTier};
use jsonwebtoken as jwt;
use lazy_static::lazy_static;
use mbedtls_sys::*;
use mbedtls_sys::types::raw_types::{c_int, c_void};
use std::sync::Mutex;
use veraison_apiclient::{ChallengeResponseBuilder, ChallengeResponse, ChallengeResponseSession, Discovery, Nonce};

// Static variables
lazy_static! {
    // Veraison challenge/response session, used to get a nonce from Veraison, then to request Veraison to verify the attester's evidence.
    static ref VERAISON_CHALLENGE_RESPONSE_SESSION: Mutex<Option<ChallengeResponseSession>> = Mutex::new(None);
    static ref VERAISON_CHALLENGE_RESPONSE: Mutex<Option<ChallengeResponse>> = Mutex::new(None);

    static ref VERAISON_ENDPOINT: Mutex<String> = Mutex::new(String::new());
    static ref API_ENDPOINT: Mutex<String> = Mutex::new(String::new());
    static ref NONCE_SIZE: Mutex<usize> = Mutex::new(0);
}

fn listen<E, F: FnMut(TcpStream) -> Result<(), E>>(mut handle_client: F) -> Result<(), E> {
    let sock = TcpListener::bind("0.0.0.0:4435").unwrap();
    for conn in sock.incoming().map(Result::unwrap) {
        println!("Connection from {}", conn.peer_addr().unwrap());
        handle_client(conn)?;
    }

    Ok(())
}

// Destroy Veraison session
fn destroy_veraison_session() -> () {
    *VERAISON_CHALLENGE_RESPONSE_SESSION.lock().unwrap() = None;
    *VERAISON_CHALLENGE_RESPONSE.lock().unwrap() = None;
    *API_ENDPOINT.lock().unwrap() = String::new();
}

unsafe extern "C" fn my_verify(
    _data: *mut c_void,
    kat_bundle: *mut u8,
    kat_bundle_len: usize,
    _nonce: *mut u8,
    _nonce_len: usize,
    ik_pub: *mut u8,
    ik_pub_len: *mut usize,
) -> c_int {
    println!("Verification of KAT-Bundle requested");

    // Get Veraison challenge/response session
    let veraison_challenge_response_lock = VERAISON_CHALLENGE_RESPONSE
        .lock()
        .unwrap();
    let veraison_challenge_response = match &*veraison_challenge_response_lock {
        None => {
            println!("ERROR: Need to call Veraison service, but no session has been set up.");
            return -1
        },
        Some(r) => r,
    };

    let discovery = Discovery::from_base_url(
        VERAISON_ENDPOINT
        .lock()
        .unwrap()
        .to_string()
    ).expect("Failed to start API discovery with the service.");

    // Get the characteristics of the Veraison verification service. This
    // includes the public key against which we need to verify the EAR.
    let verification_api = discovery
        .get_verification_api()
        .expect("Failed to discover the verification endpoint details.");

    // Call the Veraison challenge response session with the given evidence.
    let vresult = veraison_challenge_response
        .challenge_response(
            std::slice::from_raw_parts(kat_bundle, kat_bundle_len),
            "application/cmw",
            &*API_ENDPOINT.lock().unwrap());
    drop(veraison_challenge_response_lock);
    match vresult {
        Ok(_) => {},
        Err(ref e) => {
            println!("Veraison verification attempt failed ({})", e);
            destroy_veraison_session();
            return -1
        },
    }
    let attestation_result = vresult.unwrap();
    println!("Veraison attestation result: {}", attestation_result);

    println!("Public key dump for verification:\n{:?}", verification_api.ear_verification_key_as_pem());

    println!("Public key algorithm: {:?}", verification_api.ear_verification_algorithm());

    // XXX: There is only one algorithm implemented by both rust-ear (https://github.com/veraison/rust-ear/blob/main/src/algorithm.rs) and jsonwebkey (https://github.com/veraison/rust-apiclient/blob/e34784dbf2188d6bcc1a01fe70e225d5464844f3/rust-client/src/lib.rs#L349)
    if verification_api.ear_verification_algorithm() != "ES256" {
        println!("EAR is using an unsupported signature algorithm");
        return -1;
    }
    let ear = Ear::from_jwt(
        &attestation_result,
        jwt::Algorithm::ES256,
        &jwt::DecodingKey::from_ec_pem(
            verification_api
                .ear_verification_key_as_pem()
                .unwrap()
                .as_bytes()
        ).unwrap()
    );
    let ear = match ear {
        Err(e) => {
            println!("Unable to process attestation result ({})", e);
            destroy_veraison_session();
            return -1
        },
        Ok(r) => r,
    };

    // Get the list of appraisal records - we expect only a single entry.
    let (submodule, appraisal) = if ear.submods.len() > 1 {
        println!("Unexpected number of appraisal records. Expected 1, obtained {}", ear.submods.len());
        destroy_veraison_session();
        return -1;
    } else {
        ear.submods.first_key_value().unwrap()
    };

    println!("{} Status tier: {:?}", submodule, appraisal.status);

    // Fail if we don't have affirming status.
    if appraisal.status != TrustTier::Affirming {
        println!("ATTESTATION VERIFICATION FAILED: Non-affirming tier status.");
        destroy_veraison_session();
        return -1;
    }

    // Get the AK pub from the parsed claims.
    let key = match &appraisal.key_attestation {
        None => {
            println!("Appraisal for {} contains no public key", submodule);
            destroy_veraison_session();
            return -1;
        },
        Some(r) => r.pub_key.as_slice(),
    };

    // Copy the public key back for the caller if their buffer is allocated and big enough.
    if ik_pub != std::ptr::null_mut() && *ik_pub_len >= key.len() {
        ik_pub.copy_from(key.as_ptr(), key.len());
        *ik_pub_len = key.len();
    } else {
        // Tell the caller how much memory is needed.
        *ik_pub_len = key.len();
        destroy_veraison_session();
        return -1;
    }

    destroy_veraison_session();

    0
}

unsafe extern "C" fn my_nonce(
    _data: *mut c_void,
    _context: *mut ssl_context,
    nonce: *mut u8,
    nonce_size: *mut usize,
) -> c_int {
    println!("Attestation nonce requested");
    let veraison_endpoint = &*VERAISON_ENDPOINT
        .lock()
        .unwrap();

    let discovery = Discovery::from_base_url(veraison_endpoint.to_string())
        .expect("Failed to start API discovery with the service.");

    // Get the verification API details from the configured Veraison endpoint.
    let verification_api = discovery
        .get_verification_api()
        .expect("Failed to discover the verification endpoint details.");

    // Search the individual API endpoints, and capture the "newChallengeResponseSession"
    // endpoint, which will be used in the next step.
    let relative_endpoint = verification_api
        .get_api_endpoint("newChallengeResponseSession")
        .expect("Could not locate a newChallengeResponseSession endpoint.");

    let api_endpoint = format!("{}{}", veraison_endpoint, relative_endpoint);

    // Create a ChallengeResponse object
    let challenge_response = ChallengeResponseBuilder::new()
        .with_new_session_url(api_endpoint.clone())
        .build();
    match challenge_response {
        Ok(_) => {},
        Err(ref e) => {
            println!("Error creating a ChallengeResponse object: {}", e);
            return -1
        }
    }
    let challenge_response = challenge_response.unwrap();

    // Create new challenge/response session. Let Veraison decide the nonce
    let new_session = challenge_response.new_session(&Nonce::Size(*NONCE_SIZE
        .lock()
        .unwrap()));
    match new_session {
        Ok(_) => {},
        Err(ref e) => {
            println!("Failed to establish session with Veraison service at {} ({})", veraison_endpoint, e);
            return -1
        }
    }
    let (new_api_endpoint, session) = new_session.unwrap();

    // Copy nonce and nonce size
    let session_nonce = session.nonce();
    nonce.copy_from(
        session_nonce.as_ptr(),
        session_nonce.len(),
    );
    *nonce_size = session_nonce.len();

    // Save session to static variable
    *VERAISON_CHALLENGE_RESPONSE_SESSION.lock().unwrap() = Some(session);
    *VERAISON_CHALLENGE_RESPONSE.lock().unwrap() = Some(challenge_response);
    *API_ENDPOINT.lock().unwrap() = new_api_endpoint;

    0
}

fn result_main() -> TlsResult<()> {
    let veraison_endpoint = "http://vfe:8080";
    *VERAISON_ENDPOINT.lock().unwrap() = veraison_endpoint.to_string();
    let nonce_size: usize = 8;
    *NONCE_SIZE.lock().unwrap() = nonce_size;

    let entropy = entropy_new();
    let rng = Arc::new(CtrDrbg::new(Arc::new(entropy), None)?);
    let cert = Arc::new(Certificate::from_pem_multiple(keys::PEM_CERT.as_bytes())?);
    let key = Arc::new(Pk::from_private_key(&mut test_rng(),keys::PEM_KEY.as_bytes(), None)?);
    let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);

    // Configure debugging
    #[cfg(feature = "debug")]
    {
        let dbg_callback =
            |level: i32, file: Cow<'_, str>, line: i32, message: Cow<'_, str>| {
                print!("{} {}:{} {}", level, file, line, message);
            };
        config.set_dbg_callback(dbg_callback);
        unsafe { mbedtls::set_global_debug_threshold(4); }
    }

    config.set_rng(rng);
    config.push_cert(cert, key)?;
    config.set_min_version(Version::Tls13)?;
    config.set_max_version(Version::Tls13)?;
    config.set_authmode(AuthMode::Required);
    unsafe {
        ssl_conf_attestation_verify(config.get_mut_inner(), Some(my_verify), std::ptr::null_mut() as *mut c_void);
        ssl_conf_attestation_nonce(config.get_mut_inner(), Some(my_nonce));
    }

    let rc_config = Arc::new(config);

    listen(move |conn| {
        let mut ctx = Context::new(rc_config.clone());
        ctx.establish(conn, None)?;
        let mut session = BufReader::new(ctx);
        let mut line = Vec::new();
        session.read_until(b'\n', &mut line).unwrap();
        session.get_mut().write_all(&line).unwrap();
        Ok(())
    })
}

fn main() {
    result_main().unwrap();
}
