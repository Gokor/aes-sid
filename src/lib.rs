//! Authenticated encryption for the 64-bit integer range using techniques from
//! the AES-SIV (i.e. AES-CTR + AES-CMAC) construction, with 128-bit ciphertexts.
//! Useful for encrypting database primary keys or other 64-bit identifiers with
//! tamper-detecting ciphertexts small enough to fit in a UUID.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(html_root_url = "https://docs.rs/aes-sid/0.0.0")]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, intra_doc_link_resolution_failure)]

use block_cipher_trait::generic_array::{typenum::U16, ArrayLength, GenericArray};
use block_cipher_trait::BlockCipher;
use cmac::Cmac;
use core::convert::TryInto;
use crypto_mac::Mac;
use zeroize::Zeroize;

#[cfg(feature = "aes")]
use aes::{Aes128, Aes256};

#[cfg(feature = "uuid")]
use uuid::Uuid;

/// Length of the resulting ciphertext in bytes
pub const CIPHERTEXT_SIZE: usize = 16;

/// Size of the SIV tag in bytes
pub const IV_SIZE: usize = 8;

/// AES-SID with a 128-bit AES key (AES-128-CMAC-SID)
#[cfg(feature = "aes")]
pub type Aes128Sid = AesSid<Aes128>;

/// AES-SID with a 256-bit AES key (AES-256-CMAC-SID)
#[cfg(feature = "aes")]
pub type Aes256Sid = AesSid<Aes256>;

/// AES-SID: AES-based Synthetic IDs
pub struct AesSid<C>
where
    C: BlockCipher<BlockSize = U16> + Clone,
    C::ParBlocks: ArrayLength<GenericArray<u8, U16>>,
{
    cipher: C,
    mac: Cmac<C>,
}

impl<C> AesSid<C>
where
    C: BlockCipher<BlockSize = U16> + Clone,
    C::ParBlocks: ArrayLength<GenericArray<u8, U16>>,
{
    /// Initialize AES-SID from the given key.
    pub fn new(key: &GenericArray<u8, C::KeySize>) -> Self {
        let keygen_cipher = C::new(key);

        let mut mac_key = GenericArray::default();
        let mut enc_key = GenericArray::default();
        let mut counter = 0u32;

        // Derive subkeys from the master key-generating-key in counter mode
        // following the same method as RFC 8452 Section 4
        // (using a nonce of all zeroes):
        //
        // <https://tools.ietf.org/html/rfc8452#section-4>
        for derived_key in &mut [mac_key.as_mut(), enc_key.as_mut()] {
            for chunk in derived_key.chunks_mut(8) {
                let mut block = GenericArray::default();
                block[..4].copy_from_slice(&counter.to_le_bytes());
                keygen_cipher.encrypt_block(&mut block);
                chunk.copy_from_slice(&block.as_slice()[..8]);
                block.as_mut_slice().zeroize();
                counter += 1;
            }
        }

        let result = Self {
            cipher: C::new(&enc_key),
            mac: Cmac::new(&mac_key),
        };

        mac_key.as_mut_slice().zeroize();
        enc_key.as_mut_slice().zeroize();

        result
    }

    /// Encrypt the given 64-bit integer, returning its ciphertext.
    pub fn encrypt(&self, value: u64) -> [u8; CIPHERTEXT_SIZE] {
        let mut buffer = [0u8; CIPHERTEXT_SIZE];
        buffer[IV_SIZE..].copy_from_slice(&value.to_le_bytes());

        let mut mac = self.mac.clone();
        mac.input(&buffer[IV_SIZE..]);
        buffer[..IV_SIZE].copy_from_slice(&mac.result().code()[..IV_SIZE]);

        self.apply_keystream(&mut buffer);
        buffer
    }

    /// Decrypt the given ciphertext, returning the original value if authentic
    /// or an error if the ciphertext is inauthentic.
    pub fn decrypt(&self, ciphertext: impl TryInto<[u8; CIPHERTEXT_SIZE]>) -> Result<u64, ()> {
        let mut buffer = ciphertext.try_into().map_err(|_| ())?;
        self.apply_keystream(&mut buffer);

        let mut mac = self.mac.clone();
        mac.input(&buffer[IV_SIZE..]);
        let expected_tag = mac.result().code();

        use subtle::ConstantTimeEq;

        let result = if expected_tag[..IV_SIZE]
            .ct_eq(&buffer[..IV_SIZE])
            .unwrap_u8()
            == 1
        {
            Ok(u64::from_le_bytes(buffer[IV_SIZE..].try_into().unwrap()))
        } else {
            Err(())
        };

        buffer.zeroize();
        result
    }

    /// Encrypt the given 64-bit integer as a [`Uuid`].
    #[cfg(feature = "uuid")]
    #[cfg_attr(docsrs, doc(cfg(feature = "uuid")))]
    pub fn encrypt_to_uuid(&self, value: u64) -> Uuid {
        Uuid::from_bytes(self.encrypt(value))
    }

    /// Decrypt the given [`Uuid`] to a `u64` if it is authentic,
    /// or an error if the [`Uuid`] is inauthentic.
    #[cfg(feature = "uuid")]
    #[cfg_attr(docsrs, doc(cfg(feature = "uuid")))]
    pub fn decrypt_from_uuid(&self, uuid: impl Into<Uuid>) -> Result<u64, ()> {
        self.decrypt(*uuid.into().as_bytes())
    }

    /// Apply the keystream to the given message buffer
    fn apply_keystream(&self, buffer: &mut [u8; CIPHERTEXT_SIZE]) {
        let (iv, msg) = buffer.split_at_mut(IV_SIZE);

        let mut keystream = GenericArray::default();
        keystream[..IV_SIZE].copy_from_slice(&iv);
        self.cipher.encrypt_block(&mut keystream);

        for (a, b) in msg.iter_mut().zip(&keystream[..IV_SIZE]) {
            *a ^= *b;
        }

        keystream.as_mut_slice().zeroize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test vectors
    struct TestVector<K> {
        key: K,
        plaintext: u64,
        ciphertext: [u8; CIPHERTEXT_SIZE],
    }

    /// AES-128-SID keys used in test vectors
    const AES_128_SID_KEY_0: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    /// Test vectors for AES-128-SID.
    ///
    /// Note: based ons Wilson's primeth recurrence.
    const AES_128_SID_TEST_VECTORS: &[TestVector<[u8; 16]>] = &[
        TestVector {
            key: AES_128_SID_KEY_0,
            plaintext: 1,
            ciphertext: [
                140, 42, 48, 66, 67, 243, 81, 226, 93, 25, 26, 208, 175, 16, 139, 15,
            ],
        },
        TestVector {
            key: AES_128_SID_KEY_0,
            plaintext: 2,
            ciphertext: [
                233, 12, 40, 66, 197, 87, 142, 191, 253, 205, 61, 147, 135, 73, 229, 66,
            ],
        },
        TestVector {
            key: AES_128_SID_KEY_0,
            plaintext: 3,
            ciphertext: [
                10, 162, 36, 217, 6, 225, 99, 133, 93, 120, 244, 134, 126, 115, 238, 221,
            ],
        },
        TestVector {
            key: AES_128_SID_KEY_0,
            plaintext: 5,
            ciphertext: [
                105, 157, 216, 92, 197, 196, 115, 217, 132, 5, 151, 124, 142, 199, 79, 137,
            ],
        },
        TestVector {
            key: AES_128_SID_KEY_0,
            plaintext: 11,
            ciphertext: [
                198, 249, 45, 61, 89, 78, 215, 243, 36, 8, 142, 250, 127, 207, 181, 68,
            ],
        },
        TestVector {
            key: AES_128_SID_KEY_0,
            plaintext: 31,
            ciphertext: [
                131, 196, 102, 33, 37, 130, 138, 53, 50, 30, 11, 209, 102, 120, 81, 130,
            ],
        },
        TestVector {
            key: AES_128_SID_KEY_0,
            plaintext: 127,
            ciphertext: [
                12, 124, 121, 52, 255, 127, 28, 41, 134, 92, 242, 150, 81, 182, 5, 155,
            ],
        },
        TestVector {
            key: AES_128_SID_KEY_0,
            plaintext: 709,
            ciphertext: [
                167, 248, 223, 134, 49, 168, 76, 182, 201, 55, 219, 160, 156, 166, 172, 74,
            ],
        },
        TestVector {
            key: AES_128_SID_KEY_0,
            plaintext: 5381,
            ciphertext: [
                37, 18, 141, 12, 186, 98, 227, 145, 91, 1, 241, 245, 204, 9, 213, 247,
            ],
        },
        TestVector {
            key: AES_128_SID_KEY_0,
            plaintext: 52711,
            ciphertext: [
                225, 229, 73, 149, 210, 45, 5, 154, 127, 52, 78, 26, 131, 168, 231, 181,
            ],
        },
        TestVector {
            key: AES_128_SID_KEY_0,
            plaintext: 648391,
            ciphertext: [
                247, 43, 229, 75, 118, 50, 127, 96, 235, 125, 61, 194, 22, 211, 49, 145,
            ],
        },
        TestVector {
            key: AES_128_SID_KEY_0,
            plaintext: 9737333,
            ciphertext: [
                67, 26, 179, 41, 204, 35, 135, 117, 245, 23, 38, 225, 46, 221, 58, 247,
            ],
        },
        TestVector {
            key: AES_128_SID_KEY_0,
            plaintext: 174440041,
            ciphertext: [
                213, 54, 77, 123, 155, 177, 89, 15, 200, 88, 106, 68, 139, 193, 50, 39,
            ],
        },
        TestVector {
            key: AES_128_SID_KEY_0,
            plaintext: 3657500101,
            ciphertext: [
                26, 244, 18, 165, 253, 240, 6, 221, 38, 51, 233, 115, 122, 249, 125, 100,
            ],
        },
        TestVector {
            key: AES_128_SID_KEY_0,
            plaintext: 88362852307,
            ciphertext: [
                215, 0, 219, 138, 116, 87, 241, 119, 207, 58, 29, 167, 207, 232, 46, 165,
            ],
        },
        TestVector {
            key: AES_128_SID_KEY_0,
            plaintext: 2428095424619,
            ciphertext: [
                166, 227, 37, 248, 142, 80, 169, 158, 68, 216, 56, 248, 237, 253, 200, 31,
            ],
        },
    ];

    #[test]
    fn encrypt() {
        for vector in AES_128_SID_TEST_VECTORS {
            let cipher = Aes128Sid::new(&vector.key.into());
            let ciphertext = cipher.encrypt(vector.plaintext);
            assert_eq!(vector.ciphertext, ciphertext);
        }
    }

    #[test]
    fn decrypt() {
        for vector in AES_128_SID_TEST_VECTORS {
            let cipher = Aes128Sid::new(&vector.key.into());
            let plaintext = cipher.decrypt(vector.ciphertext).unwrap();
            assert_eq!(vector.plaintext, plaintext);
        }
    }

    #[test]
    fn decrypt_failure() {
        for vector in AES_128_SID_TEST_VECTORS {
            let cipher = Aes128Sid::new(&vector.key.into());

            for bit in 0..128 {
                let byte = bit / 8;
                let byte_bit = bit % 8;

                let mut ciphertext = vector.ciphertext;
                ciphertext[byte] ^= 1 << byte_bit as u8;

                assert!(cipher.decrypt(ciphertext).is_err());
            }
        }
    }

    #[cfg(feature = "uuid")]
    #[test]
    fn encrypt_uuid() {
        let cipher = Aes128Sid::new(&AES_128_SID_KEY_0.into());
        let uuid = cipher.encrypt_to_uuid(2428095424619);
        let expected = Uuid::parse_str("a6e325f8-8e50-a99e-44d8-38f8edfdc81f").unwrap();
        assert_eq!(expected, uuid);
    }

    #[cfg(feature = "uuid")]
    #[test]
    fn decrypt_uuid() {
        let cipher = Aes128Sid::new(&AES_128_SID_KEY_0.into());
        let uuid = Uuid::parse_str("a6e325f8-8e50-a99e-44d8-38f8edfdc81f").unwrap();
        assert_eq!(2428095424619, cipher.decrypt_from_uuid(uuid).unwrap());
    }
}
