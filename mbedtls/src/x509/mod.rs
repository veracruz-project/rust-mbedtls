/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;

pub mod certificate;
mod crl;
pub mod csr;
pub mod profile;
// TODO
// write_crt
// write_csr

use crate::error::Error;
use crate::private::UnsafeFrom;
#[doc(inline)]
pub use self::certificate::Certificate;
pub use self::crl::Crl;
#[doc(inline)]
pub use self::csr::Csr;
#[doc(inline)]
pub use self::profile::Profile;

use mbedtls_sys::*;
use mbedtls_sys::types::raw_types::{c_int, c_uint, c_void};
bitflags! {
    pub struct KeyUsage: c_uint {
        const DIGITAL_SIGNATURE  = MBEDTLS_X509_KU_DIGITAL_SIGNATURE as c_uint;
        const NON_REPUDIATION    = MBEDTLS_X509_KU_NON_REPUDIATION as c_uint;
        const KEY_ENCIPHERMENT   = MBEDTLS_X509_KU_KEY_ENCIPHERMENT as c_uint;
        const DATA_ENCIPHERMENT  = MBEDTLS_X509_KU_DATA_ENCIPHERMENT as c_uint;
        const KEY_AGREEMENT      = MBEDTLS_X509_KU_KEY_AGREEMENT as c_uint;
        const KEY_CERT_SIGN      = MBEDTLS_X509_KU_KEY_CERT_SIGN as c_uint;
        const CRL_SIGN           = MBEDTLS_X509_KU_CRL_SIGN as c_uint;
        const ENCIPHER_ONLY      = MBEDTLS_X509_KU_ENCIPHER_ONLY as c_uint;
        const DECIPHER_ONLY      = MBEDTLS_X509_KU_DECIPHER_ONLY as c_uint;
    }
}

bitflags! {
    pub struct VerifyError: u32 {
        const CERT_BAD_KEY       = MBEDTLS_X509_BADCERT_BAD_KEY as u32;
        const CERT_BAD_MD        = MBEDTLS_X509_BADCERT_BAD_MD as u32;
        const CERT_BAD_PK        = MBEDTLS_X509_BADCERT_BAD_PK as u32;
        const CERT_CN_MISMATCH   = MBEDTLS_X509_BADCERT_CN_MISMATCH as u32;
        const CERT_EXPIRED       = MBEDTLS_X509_BADCERT_EXPIRED as u32;
        const CERT_EXT_KEY_USAGE = MBEDTLS_X509_BADCERT_EXT_KEY_USAGE as u32;
        const CERT_FUTURE        = MBEDTLS_X509_BADCERT_FUTURE as u32;
        const CERT_KEY_USAGE     = MBEDTLS_X509_BADCERT_KEY_USAGE as u32;
        const CERT_MISSING       = MBEDTLS_X509_BADCERT_MISSING as u32;
        const CERT_NOT_TRUSTED   = MBEDTLS_X509_BADCERT_NOT_TRUSTED as u32;
        const CERT_NS_CERT_TYPE  = MBEDTLS_X509_BADCERT_NS_CERT_TYPE as u32;
        const CERT_OTHER         = MBEDTLS_X509_BADCERT_OTHER as u32;
        const CERT_REVOKED       = MBEDTLS_X509_BADCERT_REVOKED as u32;
        const CERT_SKIP_VERIFY   = MBEDTLS_X509_BADCERT_SKIP_VERIFY as u32;
        const CRL_BAD_KEY        = MBEDTLS_X509_BADCRL_BAD_KEY as u32;
        const CRL_BAD_MD         = MBEDTLS_X509_BADCRL_BAD_MD as u32;
        const CRL_BAD_PK         = MBEDTLS_X509_BADCRL_BAD_PK as u32;
        const CRL_EXPIRED        = MBEDTLS_X509_BADCRL_EXPIRED as u32;
        const CRL_FUTURE         = MBEDTLS_X509_BADCRL_FUTURE as u32;
        const CRL_NOT_TRUSTED    = MBEDTLS_X509_BADCRL_NOT_TRUSTED as u32;
        const CUSTOM_BIT_20      = 0x10_0000;
        const CUSTOM_BIT_21      = 0x20_0000;
        const CUSTOM_BIT_22      = 0x40_0000;
        const CUSTOM_BIT_23      = 0x80_0000;
        const CUSTOM_BIT_24      = 0x100_0000;
        const CUSTOM_BIT_25      = 0x200_0000;
        const CUSTOM_BIT_26      = 0x400_0000;
        const CUSTOM_BIT_27      = 0x800_0000;
        const CUSTOM_BIT_28      = 0x1000_0000;
        const CUSTOM_BIT_29      = 0x2000_0000;
        const CUSTOM_BIT_30      = 0x4000_0000;
        const CUSTOM_BIT_31      = 0x8000_0000;
    }
}

impl VerifyError {
    pub fn error_info(&self) -> Vec<&'static str> {
        macro_rules! map {
            ( $e:expr, $v:expr, $( $variant:ident -> $msg:expr , )* ) => {{
                $(
                    if $e.contains(VerifyError::$variant) {
                        $v.push($msg);
                    }
                )*
            }}
        }
        let mut v = Vec::new();
        map!{
            self, v,
            CERT_BAD_KEY       -> "The certificate is signed with an unacceptable key (eg bad curve, RSA too short).",
            CERT_BAD_MD        -> "The certificate is signed with an unacceptable hash.",
            CERT_BAD_PK        -> "The certificate is signed with an unacceptable PK alg (eg RSA vs ECDSA).",
            CERT_CN_MISMATCH   -> "The certificate Common Name (CN) does not match with the expected CN.",
            CERT_EXPIRED       -> "The certificate validity has expired.",
            CERT_EXT_KEY_USAGE -> "Usage does not match the extendedKeyUsage extension.",
            CERT_FUTURE        -> "The certificate validity starts in the future.",
            CERT_KEY_USAGE     -> "Usage does not match the keyUsage extension.",
            CERT_MISSING       -> "Certificate was missing.",
            CERT_NOT_TRUSTED   -> "The certificate is not correctly signed by the trusted CA.",
            CERT_NS_CERT_TYPE  -> "Usage does not match the nsCertType extension.",
            CERT_OTHER         -> "Other reason (can be used by verify callback).",
            CERT_REVOKED       -> "The certificate has been revoked (is on a CRL).",
            CERT_SKIP_VERIFY   -> "Certificate verification was skipped.",
            CRL_BAD_KEY        -> "The CRL is signed with an unacceptable key (eg bad curve, RSA too short).",
            CRL_BAD_MD         -> "The CRL is signed with an unacceptable hash.",
            CRL_BAD_PK         -> "The CRL is signed with an unacceptable PK alg (eg RSA vs ECDSA).",
            CRL_EXPIRED        -> "The CRL is expired.",
            CRL_FUTURE         -> "The CRL is from the future.",
            CRL_NOT_TRUSTED    -> "The CRL is not correctly signed by the trusted CA.",
        }
        v
    }
}

callback!(VerifyCallback: Fn(&Certificate, i32, &mut VerifyError) -> Result<(), Error>);

pub(crate) unsafe extern "C" fn verify_callback<F>(
    closure: *mut c_void,
    crt: *mut mbedtls_x509_crt,
    depth: c_int,
    flags: *mut u32,
) -> c_int
where
    F: VerifyCallback + 'static,
{
    if crt.is_null() || closure.is_null() || flags.is_null() {
        return ::mbedtls_sys::MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }

    let cb = &*(closure as *const F);
    let crt: &mut Certificate = UnsafeFrom::from(crt).expect("valid certificate");

    let mut verify_error = match VerifyError::from_bits(*flags) {
        Some(ve) => ve,
        // This can only happen if mbedtls is setting flags in VerifyError that are
        // missing from our definition.
        None => return ::mbedtls_sys::MBEDTLS_ERR_X509_BAD_INPUT_DATA,
    };

    let res = cb(crt, depth, &mut verify_error);
    *flags = verify_error.bits();
    match res {
        Ok(()) => 0,
        Err(e) => e.to_int(),
    }
}

/// A specific moment in time in UTC
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Time {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
}

use core::fmt::{self, Write as FmtWrite};

struct TimeWriter {
    buf: [u8; 15],
    idx: usize,
}

impl fmt::Write for TimeWriter {
    fn write_str(&mut self, s: &str) -> Result<(), fmt::Error> {
        for (dst, src) in self.buf.iter_mut().skip(self.idx).zip(s.as_bytes().iter()) {
            *dst = *src
        }
        self.idx += s.len();
        Ok(())
    }

    fn write_char(&mut self, c: char) -> Result<(), fmt::Error> {
        if c >= '0' || c <= '9' {
            if let Some(dst) = self.buf.get_mut(self.idx) {
                *dst = c as u8;
                self.idx += 1;
                return Ok(());
            }
        }
        Err(fmt::Error)
    }
}

impl Time {
    pub fn new(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> Option<Time> {
        if year < 10000
            && month >= 1
            && month <= 12
            && day >= 1
            && day <= 31
            && hour < 24
            && minute < 60
            && second < 60
        {
            Some(Time {
                year: year,
                month: month,
                day: day,
                hour: hour,
                minute: minute,
                second: second,
            })
        } else {
            None
        }
    }

    pub fn to_x509_time(&self) -> [u8; 15] {
        let mut writer = TimeWriter {
            buf: [0; 15],
            idx: 0,
        };
        write!(
            writer,
            "{:04}{:02}{:02}{:02}{:02}{:02}",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
        .expect("error formatting time");
        assert!(writer.idx == 14);
        writer.buf
    }
}
