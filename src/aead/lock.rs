//! Authenticated encryption w/o additional data

use ffi;
use std::mem;

/// Encrypt and authenticate plaintext data.
///
/// # Example
///
/// ```
/// use monocypher::aead::lock::easy;
///
/// let plaintext = "plaintext";
/// let key = [137u8; 32];
/// let nonce = [120u8; 24];
///
/// let cymac = easy(plaintext.as_bytes(), key, nonce);
/// ```
pub fn easy(plain_text: &[u8], key: [u8; 32], nonce: [u8; 24]) -> (Vec<u8>, [u8; 16]) {
    unsafe {
        let mut cipher_text: Vec<u8> = vec![0u8; plain_text.len()];
        let mut mac = mem::MaybeUninit::<[u8; 16]>::uninit();
        ffi::crypto_lock(
            mac.as_mut_ptr() as *mut u8,
            cipher_text.as_mut_ptr(),
            key.as_ptr(),
            nonce.as_ptr(),
            plain_text.as_ptr(),
            plain_text.len(),
        );

        (cipher_text, mac.assume_init())
    }
}

/// Encrypt and authenticate plaintext with additional data.
///
/// # Example
///
/// ```
/// use monocypher::aead::lock::aead;
///
/// let plaintext = "plaintext";
/// let key = [137u8; 32];
/// let nonce = [120u8; 24];
/// let ad = "data";
///
/// let cymac = aead(plaintext.as_bytes(), key, nonce, ad.as_bytes());
/// ```
pub fn aead(plain_text: &[u8], key: [u8; 32], nonce: [u8; 24], ad: &[u8]) -> (Vec<u8>, [u8; 16]) {
    unsafe {
        let mut cipher_text: Vec<u8> = vec![0u8; plain_text.len()];
        let mut mac = mem::MaybeUninit::<[u8; 16]>::uninit();
        ffi::crypto_lock_aead(
            mac.as_mut_ptr() as *mut u8,
            cipher_text.as_mut_ptr(),
            key.as_ptr(),
            nonce.as_ptr(),
            ad.as_ptr(),
            ad.len(),
            plain_text.as_ptr(),
            plain_text.len(),
        );
        (cipher_text, mac.assume_init())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn easy_aead() {
        let plaintext = "secret";

        let key: [u8; 32] = [1; 32];
        let nonce: [u8; 24] = [2; 24];
        let (a, b) = easy(plaintext.as_bytes(), key, nonce);

        assert_eq!(a, vec![191, 3, 85, 157, 207, 3]);
        assert_eq!(
            b,
            [106, 87, 195, 174, 146, 191, 227, 61, 151, 170, 230, 242, 47, 45, 28, 236]
        );
    }
}
