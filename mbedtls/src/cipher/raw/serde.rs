/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;
use crate::cipher::*;
use core::convert::TryInto;
use core::fmt;
use core::marker::PhantomData;
use core::mem::size_of;
use core::ptr;
use core::slice::from_raw_parts;
use core::str;
use core::result::Result;
use mbedtls_sys::*;
use serde;
use serde::de::Unexpected;
use serde::ser::SerializeSeq;
use serde::{de, ser};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

struct Bytes<T: BytesSerde>(T);

#[derive(Serialize, Deserialize)]
enum SavedCipher {
    Encryption(SavedRawCipher, raw::CipherPadding),
    Decryption(SavedRawCipher, raw::CipherPadding),
}

// Custom serialization in serde.rs to force encoding as sequence.
#[derive(Deserialize)]
pub struct SavedRawCipher {
    cipher_id: cipher_id_t,
    cipher_mode: cipher_mode_t,
    key_bit_len: u32,
    context: Bytes<cipher_context_t>,
    algorithm_ctx: AlgorithmContext,
}

#[derive(Serialize, Deserialize)]
enum AlgorithmContext {
    Aes(Bytes<aes_context>),
    Aria(Bytes<aria_context>),
    Des(Bytes<des_context>),
    Des3(Bytes<des3_context>),
    Gcm {
        context: Bytes<gcm_context>,
        inner_cipher_ctx: Box<SavedRawCipher>
    }
}

// Serialization support for cipher structs. We only support serialization in the "data" state.

impl<Op: Operation, T: Type> Serialize for Cipher<Op, T, CipherData> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let saved_raw_cipher = unsafe {
            let cipher_context = self.raw_cipher.inner;
            serialize_raw_cipher(cipher_context)
                .map_err(ser::Error::custom)?
        };

        match Op::is_encrypt() {
            true => SavedCipher::Encryption(saved_raw_cipher, self.padding).serialize(s),
            false => SavedCipher::Decryption(saved_raw_cipher, self.padding).serialize(s),
        }
    }
}

fn cipher_type_to_id(cipher_type : cipher_type_t) -> Result<cipher_id_t, &'static str>  {
    match cipher_type {
        CIPHER_NONE => Ok(CIPHER_ID_NONE),
        CIPHER_NULL => Ok(CIPHER_ID_NULL),
        CIPHER_AES_128_ECB..=CIPHER_AES_256_GCM |
        CIPHER_AES_128_CCM..=CIPHER_AES_256_CCM_STAR_NO_TAG |
        CIPHER_AES_128_OFB..=CIPHER_AES_256_XTS |
        CIPHER_AES_128_KW..=CIPHER_AES_256_KWP => Ok(CIPHER_ID_AES),
        CIPHER_DES_ECB..=CIPHER_DES_EDE_CBC => Ok(CIPHER_ID_DES),
        CIPHER_DES_EDE3_ECB..=CIPHER_DES_EDE3_CBC=> Ok(CIPHER_ID_3DES),
        CIPHER_CAMELLIA_128_ECB..=CIPHER_CAMELLIA_256_GCM |
        CIPHER_CAMELLIA_128_CCM..=CIPHER_CAMELLIA_256_CCM_STAR_NO_TAG => Ok(CIPHER_ID_CAMELLIA),
        CIPHER_ARIA_128_ECB..=CIPHER_ARIA_256_CCM_STAR_NO_TAG => Ok(CIPHER_ID_ARIA),
        CIPHER_CHACHA20..=CIPHER_CHACHA20_POLY1305 => Ok(CIPHER_ID_CHACHA20),
        _ => Err("invalid cipher type when converting cipher_type to cipher_id")
    }
}

unsafe fn serialize_raw_cipher(mut cipher_context: cipher_context_t)
    -> Result<SavedRawCipher, &'static str> {
    let cipher_type = (*cipher_context.private_cipher_info).private_type;
    let cipher_id = cipher_type_to_id(cipher_type)?;
    let cipher_mode = (*cipher_context.private_cipher_info).private_mode;
    let key_bit_len = (*cipher_context.private_cipher_info).private_key_bitlen;

    // Null the cipher info now that we've extracted the important bits.
    cipher_context.private_cipher_info = ::core::ptr::null();

    // We only allow certain modes that we know have serialization-safe context
    // structures. If adding GCM/CCM support, be aware that they don't use the same
    // context types as the conventional modes.
    let algorithm_ctx = match (cipher_id, cipher_mode) {
        (CIPHER_ID_AES, MODE_CBC)
        | (CIPHER_ID_AES, MODE_CTR)
        | (CIPHER_ID_AES, MODE_OFB)
        | (CIPHER_ID_AES, MODE_CFB)
        | (CIPHER_ID_AES, MODE_ECB) => {
            let aes_context = *(cipher_context.private_cipher_ctx as *const aes_context);
            AlgorithmContext::Aes(Bytes(aes_context))
        }
        (CIPHER_ID_ARIA, MODE_CBC)
        | (CIPHER_ID_ARIA, MODE_CTR)
        | (CIPHER_ID_ARIA, MODE_CFB)
        | (CIPHER_ID_ARIA, MODE_ECB) => {
            AlgorithmContext::Aria(Bytes(*(cipher_context.private_cipher_ctx as *const aria_context)))
        }
        (CIPHER_ID_DES, MODE_CBC)
        | (CIPHER_ID_DES, MODE_CTR)
        | (CIPHER_ID_DES, MODE_OFB)
        | (CIPHER_ID_DES, MODE_CFB) => {
            AlgorithmContext::Des(Bytes(*(cipher_context.private_cipher_ctx as *const des_context)))
        }
        (CIPHER_ID_3DES, MODE_CBC)
        | (CIPHER_ID_3DES, MODE_CTR)
        | (CIPHER_ID_3DES, MODE_OFB)
        | (CIPHER_ID_3DES, MODE_CFB) => AlgorithmContext::Des3(Bytes(
            *(cipher_context.private_cipher_ctx as *const des3_context),
        )),
        (CIPHER_ID_AES, MODE_GCM) => {
            let gcm_context = *(cipher_context.private_cipher_ctx as *const gcm_context);

            let inner_ctx = gcm_context.private_cipher_ctx;

            let inner_saved_cipher = serialize_raw_cipher(inner_ctx)?;

            AlgorithmContext::Gcm {
                context: Bytes(gcm_context),
                inner_cipher_ctx: Box::new(inner_saved_cipher)
            }
        },
        _ => {
            return Err("unsupported algorithm for serialization");
        }
    };

    // Null the algorithm context
    cipher_context.private_cipher_ctx = ::core::ptr::null_mut();

    // Null function pointers
    cipher_context.private_add_padding = None;
    cipher_context.private_get_padding = None;

    Ok(SavedRawCipher {
        cipher_id: cipher_id,
        cipher_mode: cipher_mode,
        key_bit_len: key_bit_len,
        context: Bytes(cipher_context),
        algorithm_ctx: algorithm_ctx,
    })
}

impl<'de, Op: Operation, T: Type> Deserialize<'de> for Cipher<Op, T, CipherData> {
    fn deserialize<D>(d: D) -> Result<Cipher<Op, T, CipherData>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let saved_cipher: SavedCipher = SavedCipher::deserialize(d)?;

        let (raw, padding) = match saved_cipher {
            SavedCipher::Encryption(..) if !Op::is_encrypt() => {
                return Err(de::Error::invalid_value(
                    Unexpected::Other("incorrect cipher operation"),
                    &"encryption",
                ));
            }
            SavedCipher::Decryption(..) if Op::is_encrypt() => {
                return Err(de::Error::invalid_value(
                    Unexpected::Other("incorrect cipher operation"),
                    &"decryption",
                ));
            }
            SavedCipher::Encryption(raw, padding) | SavedCipher::Decryption(raw, padding)
            => {
                (raw, padding)
            }
        };

        unsafe {
            let raw_cipher = deserialize_raw_cipher(raw, padding)
                .map_err(|(e1, e2)| de::Error::invalid_value(Unexpected::Other(e1), &e2))?;
            Ok(Cipher {
                raw_cipher: raw_cipher,
                padding: padding,
                _op: PhantomData,
                _type: PhantomData,
                _state: PhantomData,
            })
        }
    }
}

unsafe fn deserialize_raw_cipher(raw: SavedRawCipher, padding: raw::CipherPadding)
    -> Result<raw::Cipher, (&'static str, &'static str)> {

    let mut raw_cipher = match raw::Cipher::setup(
        raw.cipher_id.try_into().map_err(|_| ("bad cipher_id", "valid parameters"))?,
        raw.cipher_mode.into(),
        raw.key_bit_len,
    ) {
        Ok(raw) => raw,
        Err(_) => {
            return Err(("bad cipher parameters", "valid parameters"));
        }
    };

    if raw.cipher_mode == MODE_CBC {
        raw_cipher
            .set_padding(padding)
            .map_err(|_| ("bad padding mode", "valid mode"))?;
    }

    let cipher_context = &mut raw_cipher.inner;

    match (raw.cipher_id, raw.algorithm_ctx) {
        (CIPHER_ID_AES, AlgorithmContext::Aes(Bytes(aes_ctx))) => {
            let ret_aes_ctx = cipher_context.private_cipher_ctx as *mut aes_context;
            *ret_aes_ctx = aes_ctx;
            // aes_ctx.rk needs to be a pointer to aes_ctx.buf, which holds the round keys.
            // We don't adjust for the padding needed on VIA Padlock (see definition of
            // mbedtls_aes_context in the mbedTLS source).
            (*ret_aes_ctx).private_rk_offset = 0;
        }
        (CIPHER_ID_ARIA, AlgorithmContext::Aria(Bytes(aria_ctx))) => {
            *(cipher_context.private_cipher_ctx as *mut aria_context) = aria_ctx
        }
        (CIPHER_ID_DES, AlgorithmContext::Des(Bytes(des_ctx))) => {
            *(cipher_context.private_cipher_ctx as *mut des_context) = des_ctx
        }
        (CIPHER_ID_3DES, AlgorithmContext::Des3(Bytes(des3_ctx))) => {
            *(cipher_context.private_cipher_ctx as *mut des3_context) = des3_ctx
        }
        (CIPHER_ID_AES, AlgorithmContext::Gcm {
            context: Bytes(mut gcm_ctx),
            inner_cipher_ctx
        }) => {
            let inner_raw_cipher = deserialize_raw_cipher(*inner_cipher_ctx, raw::CipherPadding::None)?;
            gcm_ctx.private_cipher_ctx = inner_raw_cipher.into_inner();

            *(cipher_context.private_cipher_ctx as *mut gcm_context) = gcm_ctx;
        }
        _ => {
            return Err(("bad algorithm", "valid algorithm"));
        }
    };

    cipher_context.private_key_bitlen = raw.context.0.private_key_bitlen;
    cipher_context.private_operation = raw.context.0.private_operation;
    cipher_context.private_unprocessed_data = raw.context.0.private_unprocessed_data;
    cipher_context.private_unprocessed_len = raw.context.0.private_unprocessed_len;
    cipher_context.private_iv = raw.context.0.private_iv;
    cipher_context.private_iv_size = raw.context.0.private_iv_size;

    Ok(raw_cipher)
}

// Serialization support for raw cipher structs. Custom serialization as a sequence to save the
// space of encoding all the member names.

impl Serialize for SavedRawCipher {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = s.serialize_seq(Some(5))?;
        seq.serialize_element(&self.cipher_id)?;
        seq.serialize_element(&self.cipher_mode)?;
        seq.serialize_element(&self.key_bit_len)?;
        seq.serialize_element(&self.context)?;
        seq.serialize_element(&self.algorithm_ctx)?;
        seq.end()
    }
}

// Byte block serialization support
// (Note: serde_cbor represents each element in a u8 Vec or slice as an
// integer, which uses two bytes except for most values.)

unsafe trait BytesSerde: Sized {
    fn read_slice(s: &[u8]) -> Option<Self> {
        unsafe {
            if s.len() == size_of::<Self>() {
                Some(ptr::read(s.as_ptr() as *const Self))
            } else {
                None
            }
        }
    }

    fn as_slice(&self) -> &[u8] {
        unsafe { from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }
}

impl<T: BytesSerde> Serialize for Bytes<T> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_bytes(self.0.as_slice())
    }
}

impl<'de, T: BytesSerde> Deserialize<'de> for Bytes<T> {
    fn deserialize<D>(d: D) -> Result<Bytes<T>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BytesVisitor<T: BytesSerde>(PhantomData<T>);
        impl<'de, T: BytesSerde> de::Visitor<'de> for BytesVisitor<T> {
            type Value = Bytes<T>;

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                T::read_slice(v)
                    .map(Bytes)
                    .ok_or_else(|| E::invalid_length(v.len(), &self))
            }

            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_bytes(&v)
            }

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "{}", size_of::<T>())
            }
        }

        d.deserialize_bytes(BytesVisitor(PhantomData))
    }
}

unsafe impl BytesSerde for cipher_context_t {}
unsafe impl BytesSerde for aes_context {}
unsafe impl BytesSerde for aria_context {}
unsafe impl BytesSerde for des_context {}
unsafe impl BytesSerde for des3_context {}
unsafe impl BytesSerde for gcm_context {}

// If the C API changes, the serde implementation needs to be reviewed for correctness. The
// following (unused) functions will most probably fail to compile when this happens so a
// compilation failure here reminds us of reviewing the serde impl.

// The sizes of usize and isize as well as all pointer types will be dependent on the architecture
// we are building for. So to be platform independent, the expected sizes are calculated from the
// fixed-sized fields, the number and size of pointer-sized fields and some alignment bytes.

const _SIZE_OF_CIPHER_CONTEXT: usize = size_of::<usize>() + 2 * 4 + 2 * size_of::<usize>() + 16 + size_of::<usize>() + 16 + 3 * size_of::<usize>();
const _SIZE_OF_AES_CONTEXT: usize = 2 * size_of::<usize>() + 4 * 68;
const _SIZE_OF_DES_CONTEXT: usize = 4 * 32;
const _SIZE_OF_DES3_CONTEXT: usize = 4 * 96;
const _SIZE_OF_GCM_CONTEXT: usize = (_SIZE_OF_CIPHER_CONTEXT+7)/8*8 + 8 * 16 + 8 * 16 + 8 + 8 + 16 + 16 + 16 + 8; // first summand: cipher_context 8-byte aligned

unsafe fn _check_cipher_context_t_size(ctx: cipher_context_t) -> [u8; _SIZE_OF_CIPHER_CONTEXT] {
    ::core::mem::transmute(ctx)
}

unsafe fn _check_aes_context_size(ctx: aes_context) -> [u8; _SIZE_OF_AES_CONTEXT] {
    ::core::mem::transmute(ctx)
}

unsafe fn _check_des_context_size(ctx: des_context) -> [u8; _SIZE_OF_DES_CONTEXT] {
    ::core::mem::transmute(ctx)
}

unsafe fn _check_des3_context_size(ctx: des3_context) -> [u8; _SIZE_OF_DES3_CONTEXT] {
    ::core::mem::transmute(ctx)
}

unsafe fn _check_gcm_context_size(ctx: gcm_context) -> [u8; _SIZE_OF_GCM_CONTEXT] { ::core::mem::transmute(ctx) }
