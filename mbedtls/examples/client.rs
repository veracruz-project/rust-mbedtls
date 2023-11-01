/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

// needed to have common code for `mod support` in unit and integrations tests
extern crate mbedtls;

use std::io::{self, stdin, stdout, Write};
use std::net::TcpStream;
use std::sync::Arc;

use mbedtls::rng::CtrDrbg;
use mbedtls::ssl::config::{Endpoint, Preset, Transport};
use mbedtls::ssl::{Config, Context};
use mbedtls::x509::Certificate;
use mbedtls::Result as TlsResult;

#[path = "../tests/support/mod.rs"]
mod support;
use support::entropy::entropy_new;
use support::keys;

use mbedtls_sys::*;
use mbedtls_sys::psa::*;
use parsec_se_driver::PARSEC_SE_DRIVER;

#[cfg(feature = "debug")]
use std::borrow::Cow;

fn result_main(addr: &str) -> TlsResult<()> {
    // Register Parsec SE driver
    let location: key_location_t = 0x000001;
    let parsec_se_driver = unsafe { &PARSEC_SE_DRIVER as *const _ as *const drv_se_t };
    let ret;
    unsafe {
        ret = register_se_driver(location, parsec_se_driver);
    }
    if ret != 0 { } // TODO: handle error
    let mut key_handle: key_handle_t = 0;

    let entropy = Arc::new(entropy_new());
    let rng = Arc::new(CtrDrbg::new(entropy, None)?);
    let cert = Arc::new(Certificate::from_pem_multiple(keys::ROOT_CA_CERT.as_bytes())?);
    let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);

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
    config.set_ca_list(cert, None);


    // Generate PSA key
    let client_attestation_type_list: [u16; 1] = [TLS_ATTESTATION_TYPE_EAT as u16];
    let key_pair_id: key_id_t = 0xBEEF;
    unsafe {
        ssl_conf_client_attestation_type(config.get_mut_inner(),client_attestation_type_list.as_ptr());
        let mut key_pair_attributes = key_attributes_init();
        set_key_id(&mut key_pair_attributes, key_pair_id);
        let lifetime = 0x000001 << 8 | 0x000001;
        set_key_lifetime(&mut key_pair_attributes, lifetime);
        set_key_usage_flags(&mut key_pair_attributes, KEY_USAGE_SIGN_HASH as u32 | KEY_USAGE_VERIFY_HASH as u32);
        set_key_algorithm(&mut key_pair_attributes, ALG_ECDSA_BASE as u32 | (ALG_SHA_256 as u32 & ALG_HASH_MASK as u32));
        set_key_type(&mut key_pair_attributes, KEY_TYPE_ECC_KEY_PAIR_BASE as u16 | ECC_FAMILY_SECP_R1 as u16);
        set_key_bits(&mut key_pair_attributes, 256);

        let ret = generate_key(&key_pair_attributes, &mut key_handle);
        if ret != 0 { } // TODO: handle error
        ssl_conf_client_rpk(config.get_mut_inner(), &mut key_handle);
    }

    let mut ctx = Context::new(Arc::new(config));
    let conn = TcpStream::connect(addr).unwrap();
    ctx.establish(conn, None)?;

    let mut line = String::new();
    stdin().read_line(&mut line).unwrap();
    ctx.write_all(line.as_bytes()).unwrap();
    io::copy(&mut ctx, &mut stdout()).unwrap();
    Ok(())
}

fn main() {
    let mut args = std::env::args();
    args.next();
    result_main(
        &args
            .next()
            .expect("supply destination in command-line argument"),
    )
    .unwrap();
}
