/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use mbedtls_sys::types::raw_types::{c_char, c_int};
use mbedtls_sys::*;

/// Always use into() to convert to i32, do not use 'as i32'. (until issue is fixed: https://github.com/fortanix/rust-mbedtls/issues/129)
define!(
    #[non_exhaustive]
    #[c_ty(c_int)]
    enum Tls12CipherSuite {
        RsaWithNullMd5 = TLS_RSA_WITH_NULL_MD5,
        RsaWithNullSha = TLS_RSA_WITH_NULL_SHA,
        PskWithNullSha = TLS_PSK_WITH_NULL_SHA,
        DhePskWithNullSha = TLS_DHE_PSK_WITH_NULL_SHA,
        RsaPskWithNullSha = TLS_RSA_PSK_WITH_NULL_SHA,
        RsaWithAes128CbcSha = TLS_RSA_WITH_AES_128_CBC_SHA,
        DheRsaWithAes128CbcSha = TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
        RsaWithAes256CbcSha = TLS_RSA_WITH_AES_256_CBC_SHA,
        DheRsaWithAes256CbcSha = TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
        RsaWithNullSha256 = TLS_RSA_WITH_NULL_SHA256,
        RsaWithAes128CbcSha256 = TLS_RSA_WITH_AES_128_CBC_SHA256,
        RsaWithAes256CbcSha256 = TLS_RSA_WITH_AES_256_CBC_SHA256,
        RsaWithCamellia128CbcSha = TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,
        DheRsaWithCamellia128CbcSha = TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
        DheRsaWithAes128CbcSha256 = TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
        DheRsaWithAes256CbcSha256 = TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
        RsaWithCamellia256CbcSha = TLS_RSA_WITH_CAMELLIA_256_CBC_SHA,
        DheRsaWithCamellia256CbcSha = TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
        PskWithAes128CbcSha = TLS_PSK_WITH_AES_128_CBC_SHA,
        PskWithAes256CbcSha = TLS_PSK_WITH_AES_256_CBC_SHA,
        DhePskWithAes128CbcSha = TLS_DHE_PSK_WITH_AES_128_CBC_SHA,
        DhePskWithAes256CbcSha = TLS_DHE_PSK_WITH_AES_256_CBC_SHA,
        RsaPskWithAes128CbcSha = TLS_RSA_PSK_WITH_AES_128_CBC_SHA,
        RsaPskWithAes256CbcSha = TLS_RSA_PSK_WITH_AES_256_CBC_SHA,
        RsaWithAes128GcmSha256 = TLS_RSA_WITH_AES_128_GCM_SHA256,
        RsaWithAes256GcmSha384 = TLS_RSA_WITH_AES_256_GCM_SHA384,
        DheRsaWithAes128GcmSha256 = TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
        DheRsaWithAes256GcmSha384 = TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
        PskWithAes128GcmSha256 = TLS_PSK_WITH_AES_128_GCM_SHA256,
        PskWithAes256GcmSha384 = TLS_PSK_WITH_AES_256_GCM_SHA384,
        DhePskWithAes128GcmSha256 = TLS_DHE_PSK_WITH_AES_128_GCM_SHA256,
        DhePskWithAes256GcmSha384 = TLS_DHE_PSK_WITH_AES_256_GCM_SHA384,
        RsaPskWithAes128GcmSha256 = TLS_RSA_PSK_WITH_AES_128_GCM_SHA256,
        RsaPskWithAes256GcmSha384 = TLS_RSA_PSK_WITH_AES_256_GCM_SHA384,
        PskWithAes128CbcSha256 = TLS_PSK_WITH_AES_128_CBC_SHA256,
        PskWithAes256CbcSha384 = TLS_PSK_WITH_AES_256_CBC_SHA384,
        PskWithNullSha256 = TLS_PSK_WITH_NULL_SHA256,
        PskWithNullSha384 = TLS_PSK_WITH_NULL_SHA384,
        DhePskWithAes128CbcSha256 = TLS_DHE_PSK_WITH_AES_128_CBC_SHA256,
        DhePskWithAes256CbcSha384 = TLS_DHE_PSK_WITH_AES_256_CBC_SHA384,
        DhePskWithNullSha256 = TLS_DHE_PSK_WITH_NULL_SHA256,
        DhePskWithNullSha384 = TLS_DHE_PSK_WITH_NULL_SHA384,
        RsaPskWithAes128CbcSha256 = TLS_RSA_PSK_WITH_AES_128_CBC_SHA256,
        RsaPskWithAes256CbcSha384 = TLS_RSA_PSK_WITH_AES_256_CBC_SHA384,
        RsaPskWithNullSha256 = TLS_RSA_PSK_WITH_NULL_SHA256,
        RsaPskWithNullSha384 = TLS_RSA_PSK_WITH_NULL_SHA384,
        RsaWithCamellia128CbcSha256 = TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256,
        DheRsaWithCamellia128CbcSha256 = TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
        RsaWithCamellia256CbcSha256 = TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256,
        DheRsaWithCamellia256CbcSha256 = TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
        EcdhEcdsaWithNullSha = TLS_ECDH_ECDSA_WITH_NULL_SHA,
        EcdhEcdsaWithAes128CbcSha = TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
        EcdhEcdsaWithAes256CbcSha = TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
        EcdheEcdsaWithNullSha = TLS_ECDHE_ECDSA_WITH_NULL_SHA,
        EcdheEcdsaWithAes128CbcSha = TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        EcdheEcdsaWithAes256CbcSha = TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
        EcdhRsaWithNullSha = TLS_ECDH_RSA_WITH_NULL_SHA,
        EcdhRsaWithAes128CbcSha = TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
        EcdhRsaWithAes256CbcSha = TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
        EcdheRsaWithNullSha = TLS_ECDHE_RSA_WITH_NULL_SHA,
        EcdheRsaWithAes128CbcSha = TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        EcdheRsaWithAes256CbcSha = TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        EcdheEcdsaWithAes128CbcSha256 = TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        EcdheEcdsaWithAes256CbcSha384 = TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
        EcdhEcdsaWithAes128CbcSha256 = TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
        EcdhEcdsaWithAes256CbcSha384 = TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
        EcdheRsaWithAes128CbcSha256 = TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        EcdheRsaWithAes256CbcSha384 = TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
        EcdhRsaWithAes128CbcSha256 = TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
        EcdhRsaWithAes256CbcSha384 = TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
        EcdheEcdsaWithAes128GcmSha256 = TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        EcdheEcdsaWithAes256GcmSha384 = TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        EcdhEcdsaWithAes128GcmSha256 = TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
        EcdhEcdsaWithAes256GcmSha384 = TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
        EcdheRsaWithAes128GcmSha256 = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        EcdheRsaWithAes256GcmSha384 = TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        EcdhRsaWithAes128GcmSha256 = TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
        EcdhRsaWithAes256GcmSha384 = TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
        EcdhePskWithAes128CbcSha = TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA,
        EcdhePskWithAes256CbcSha = TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA,
        EcdhePskWithAes128CbcSha256 = TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
        EcdhePskWithAes256CbcSha384 = TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
        EcdhePskWithNullSha = TLS_ECDHE_PSK_WITH_NULL_SHA,
        EcdhePskWithNullSha256 = TLS_ECDHE_PSK_WITH_NULL_SHA256,
        EcdhePskWithNullSha384 = TLS_ECDHE_PSK_WITH_NULL_SHA384,
        RsaWithAria128CbcSha256 = TLS_RSA_WITH_ARIA_128_CBC_SHA256,
        RsaWithAria256CbcSha384 = TLS_RSA_WITH_ARIA_256_CBC_SHA384,
        DheRsaWithAria128CbcSha256 = TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256,
        DheRsaWithAria256CbcSha384 = TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384,
        EcdheEcdsaWithAria128CbcSha256 = TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256,
        EcdheEcdsaWithAria256CbcSha384 = TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384,
        EcdhEcdsaWithAria128CbcSha256 = TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256,
        EcdhEcdsaWithAria256CbcSha384 = TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384,
        EcdheRsaWithAria128CbcSha256 = TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256,
        EcdheRsaWithAria256CbcSha384 = TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384,
        EcdhRsaWithAria128CbcSha256 = TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256,
        EcdhRsaWithAria256CbcSha384 = TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384,
        RsaWithAria128GcmSha256 = TLS_RSA_WITH_ARIA_128_GCM_SHA256,
        RsaWithAria256GcmSha384 = TLS_RSA_WITH_ARIA_256_GCM_SHA384,
        DheRsaWithAria128GcmSha256 = TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256,
        DheRsaWithAria256GcmSha384 = TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384,
        EcdheEcdsaWithAria128GcmSha256 = TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256,
        EcdheEcdsaWithAria256GcmSha384 = TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384,
        EcdhEcdsaWithAria128GcmSha256 = TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256,
        EcdhEcdsaWithAria256GcmSha384 = TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384,
        EcdheRsaWithAria128GcmSha256 = TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256,
        EcdheRsaWithAria256GcmSha384 = TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384,
        EcdhRsaWithAria128GcmSha256 = TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256,
        EcdhRsaWithAria256GcmSha384 = TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384,
        PskWithAria128CbcSha256 = TLS_PSK_WITH_ARIA_128_CBC_SHA256,
        PskWithAria256CbcSha384 = TLS_PSK_WITH_ARIA_256_CBC_SHA384,
        DhePskWithAria128CbcSha256 = TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256,
        DhePskWithAria256CbcSha384 = TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384,
        RsaPskWithAria128CbcSha256 = TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256,
        RsaPskWithAria256CbcSha384 = TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384,
        PskWithAria128GcmSha256 = TLS_PSK_WITH_ARIA_128_GCM_SHA256,
        PskWithAria256GcmSha384 = TLS_PSK_WITH_ARIA_256_GCM_SHA384,
        DhePskWithAria128GcmSha256 = TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256,
        DhePskWithAria256GcmSha384 = TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384,
        RsaPskWithAria128GcmSha256 = TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256,
        RsaPskWithAria256GcmSha384 = TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384,
        EcdhePskWithAria128CbcSha256 = TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256,
        EcdhePskWithAria256CbcSha384 = TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384,
        EcdheEcdsaWithCamellia128CbcSha256 = TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
        EcdheEcdsaWithCamellia256CbcSha384 = TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
        EcdhEcdsaWithCamellia128CbcSha256 = TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
        EcdhEcdsaWithCamellia256CbcSha384 = TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
        EcdheRsaWithCamellia128CbcSha256 = TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
        EcdheRsaWithCamellia256CbcSha384 = TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384,
        EcdhRsaWithCamellia128CbcSha256 = TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256,
        EcdhRsaWithCamellia256CbcSha384 = TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384,
        RsaWithCamellia128GcmSha256 = TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256,
        RsaWithCamellia256GcmSha384 = TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384,
        DheRsaWithCamellia128GcmSha256 = TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,
        DheRsaWithCamellia256GcmSha384 = TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384,
        EcdheEcdsaWithCamellia128GcmSha256 = TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256,
        EcdheEcdsaWithCamellia256GcmSha384 = TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384,
        EcdhEcdsaWithCamellia128GcmSha256 = TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256,
        EcdhEcdsaWithCamellia256GcmSha384 = TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384,
        EcdheRsaWithCamellia128GcmSha256 = TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,
        EcdheRsaWithCamellia256GcmSha384 = TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384,
        EcdhRsaWithCamellia128GcmSha256 = TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256,
        EcdhRsaWithCamellia256GcmSha384 = TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384,
        PskWithCamellia128GcmSha256 = TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256,
        PskWithCamellia256GcmSha384 = TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384,
        DhePskWithCamellia128GcmSha256 = TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256,
        DhePskWithCamellia256GcmSha384 = TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384,
        RsaPskWithCamellia128GcmSha256 = TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256,
        RsaPskWithCamellia256GcmSha384 = TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384,
        PskWithCamellia128CbcSha256 = TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256,
        PskWithCamellia256CbcSha384 = TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384,
        DhePskWithCamellia128CbcSha256 = TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
        DhePskWithCamellia256CbcSha384 = TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
        RsaPskWithCamellia128CbcSha256 = TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256,
        RsaPskWithCamellia256CbcSha384 = TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384,
        EcdhePskWithCamellia128CbcSha256 = TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
        EcdhePskWithCamellia256CbcSha384 = TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
        RsaWithAes128Ccm = TLS_RSA_WITH_AES_128_CCM,
        RsaWithAes256Ccm = TLS_RSA_WITH_AES_256_CCM,
        DheRsaWithAes128Ccm = TLS_DHE_RSA_WITH_AES_128_CCM,
        DheRsaWithAes256Ccm = TLS_DHE_RSA_WITH_AES_256_CCM,
        RsaWithAes128Ccm8 = TLS_RSA_WITH_AES_128_CCM_8,
        RsaWithAes256Ccm8 = TLS_RSA_WITH_AES_256_CCM_8,
        DheRsaWithAes128Ccm8 = TLS_DHE_RSA_WITH_AES_128_CCM_8,
        DheRsaWithAes256Ccm8 = TLS_DHE_RSA_WITH_AES_256_CCM_8,
        PskWithAes128Ccm = TLS_PSK_WITH_AES_128_CCM,
        PskWithAes256Ccm = TLS_PSK_WITH_AES_256_CCM,
        DhePskWithAes128Ccm = TLS_DHE_PSK_WITH_AES_128_CCM,
        DhePskWithAes256Ccm = TLS_DHE_PSK_WITH_AES_256_CCM,
        PskWithAes128Ccm8 = TLS_PSK_WITH_AES_128_CCM_8,
        PskWithAes256Ccm8 = TLS_PSK_WITH_AES_256_CCM_8,
        DhePskWithAes128Ccm8 = TLS_DHE_PSK_WITH_AES_128_CCM_8,
        DhePskWithAes256Ccm8 = TLS_DHE_PSK_WITH_AES_256_CCM_8,
        EcdheEcdsaWithAes128Ccm = TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
        EcdheEcdsaWithAes256Ccm = TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
        EcdheEcdsaWithAes128Ccm8 = TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
        EcdheEcdsaWithAes256Ccm8 = TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
        EcjpakeWithAes128Ccm8 = TLS_ECJPAKE_WITH_AES_128_CCM_8,
        EcdheRsaWithChacha20Poly1305Sha256 = TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        EcdheEcdsaWithChacha20Poly1305Sha256 = TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        DheRsaWithChacha20Poly1305Sha256 = TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        PskWithChacha20Poly1305Sha256 = TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
        EcdhePskWithChacha20Poly1305Sha256 = TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
        DhePskWithChacha20Poly1305Sha256 = TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
        RsaPskWithChacha20Poly1305Sha256 = TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256,
    }
);

/// Always use into() to convert to i32, do not use 'as i32'. (until issue is fixed: https://github.com/fortanix/rust-mbedtls/issues/129)
#[cfg(feature = "tls13")]
define!(
    #[non_exhaustive]
    #[c_ty(c_int)]
    enum Tls13CipherSuite {
        Tls13Aes128GcmSha256 = TLS1_3_AES_128_GCM_SHA256,
        Tls13Aes256GcmSha384 = TLS1_3_AES_256_GCM_SHA384,
        Tls13Chacha20Poly1305Sha256 = TLS1_3_CHACHA20_POLY1305_SHA256,
        Tls13Aes128CcmSha256 = TLS1_3_AES_128_CCM_SHA256,
        Tls13Aes128Ccm8Sha256 = TLS1_3_AES_128_CCM_8_SHA256,
    }
);

/// Always use into() to convert to i32, do not use 'as i32'. (until issue is fixed: https://github.com/fortanix/rust-mbedtls/issues/129)
#[cfg(feature = "tls13")]
define!(
    #[non_exhaustive]
    #[c_ty(c_int)]
    enum IanaTlsNamedGroup {
        None = SSL_IANA_TLS_GROUP_NONE,
        Secp192k1 = SSL_IANA_TLS_GROUP_SECP192K1,
        Secp192r1 = SSL_IANA_TLS_GROUP_SECP192R1,
        Secp224k1 = SSL_IANA_TLS_GROUP_SECP224K1,
        Secp224r1 = SSL_IANA_TLS_GROUP_SECP224R1,
        Secp256k1 = SSL_IANA_TLS_GROUP_SECP256K1,
        Secp256r1 = SSL_IANA_TLS_GROUP_SECP256R1,
        Secp384r1 = SSL_IANA_TLS_GROUP_SECP384R1,
        Secp521r1 = SSL_IANA_TLS_GROUP_SECP521R1,
        Bp256r1 = SSL_IANA_TLS_GROUP_BP256R1,
        Bp384r1 = SSL_IANA_TLS_GROUP_BP384R1,
        Bp512r1 = SSL_IANA_TLS_GROUP_BP512R1,
        X25519 = SSL_IANA_TLS_GROUP_X25519,
        X448 = SSL_IANA_TLS_GROUP_X448,
        Ffdhe2048 = SSL_IANA_TLS_GROUP_FFDHE2048,
        Ffdhe3072 = SSL_IANA_TLS_GROUP_FFDHE3072,
        Ffdhe4096 = SSL_IANA_TLS_GROUP_FFDHE4096,
        Ffdhe6144 = SSL_IANA_TLS_GROUP_FFDHE6144,
        Ffdhe8192 = SSL_IANA_TLS_GROUP_FFDHE8192,
    }
);

/// Always use into() to convert to i32, do not use 'as i32'. (until issue is fixed: https://github.com/fortanix/rust-mbedtls/issues/129)
#[cfg(feature = "tls13")]
define!(
    #[non_exhaustive]
    #[c_ty(c_int)]
    enum Tls13SignatureAlgorithms {
        RsaPkcs1Sha256 = TLS1_3_SIG_RSA_PKCS1_SHA256,
        RsaPkcs1Sha384 = TLS1_3_SIG_RSA_PKCS1_SHA384,
        RsaPkcs1Sha512 = TLS1_3_SIG_RSA_PKCS1_SHA512,
        EcdsaSecp256R1Sha256 = TLS1_3_SIG_ECDSA_SECP256R1_SHA256,
        EcdsaSecp384R1Sha384 = TLS1_3_SIG_ECDSA_SECP384R1_SHA384,
        EcdsaSecp521R1Sha512 = TLS1_3_SIG_ECDSA_SECP521R1_SHA512,
        RsaPssRsaeSha256 = TLS1_3_SIG_RSA_PSS_RSAE_SHA256,
        RsaPssRsaeSha384 = TLS1_3_SIG_RSA_PSS_RSAE_SHA384,
        RsaPssRsaeSha512 = TLS1_3_SIG_RSA_PSS_RSAE_SHA512,
        Ed25519 = TLS1_3_SIG_ED25519,
        Ed448 = TLS1_3_SIG_ED448,
        RsaPssPssSha256 = TLS1_3_SIG_RSA_PSS_PSS_SHA256,
        RsaPssPssSha384 = TLS1_3_SIG_RSA_PSS_PSS_SHA384,
        RsaPssPssSha512 = TLS1_3_SIG_RSA_PSS_PSS_SHA512,
        RsaPkcs1Sha1 = TLS1_3_SIG_RSA_PKCS1_SHA1,
        EcdsaSha1 = TLS1_3_SIG_ECDSA_SHA1,
        None = TLS1_3_SIG_NONE,
    }
);

#[cfg(all(not(feature = "std"), feature = "tls13"))]
use crate::alloc_prelude::*;

#[cfg(feature = "tls13")]
pub fn tls13_preset_default_sig_algs() -> Vec<u16> {
    use Tls13SignatureAlgorithms::*;
    vec![
        Into::<c_int>::into(EcdsaSecp256R1Sha256) as u16,
        Into::<c_int>::into(EcdsaSecp384R1Sha384) as u16,
        Into::<c_int>::into(EcdsaSecp521R1Sha512) as u16,
        Into::<c_int>::into(RsaPkcs1Sha256) as u16,
        Into::<c_int>::into(RsaPkcs1Sha384) as u16,
        Into::<c_int>::into(RsaPkcs1Sha512) as u16,
        Into::<c_int>::into(RsaPssRsaeSha256) as u16,
        Into::<c_int>::into(RsaPssRsaeSha384) as u16,
        Into::<c_int>::into(RsaPssRsaeSha512) as u16,
        Into::<c_int>::into(None) as u16,
    ]
}

pub fn lookup_ciphersuite(name: &str) -> Option<c_int> {
    let c_str = match std::ffi::CString::new(name) {
        Ok(x) => x.into_bytes(),
        Err(_) => return None,
    };
    unsafe {
        let p = mbedtls_sys::ssl_ciphersuite_from_string(c_str.as_ptr() as *const c_char);
        if p.is_null() {
            None
        } else {
            Some((*p).private_id)
        }
    }
}
