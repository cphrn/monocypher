//! Authenticated decryption w/o additional data

use ffi;

/// Decrypt encrypted data.
///
/// # Example
///
/// ```
/// use monocypher::aead::{lock, unlock};
///
/// let plaintext = "plaintext";
/// let key = [137u8; 32];
/// let nonce = [120u8; 24];
///
/// let cymac = lock::easy(plaintext.as_bytes(), key, nonce);
/// unlock::easy(&cymac.0, key, nonce, cymac.1).unwrap();
/// ```
pub fn easy(
    cipher_text: &[u8],
    key: [u8; 32],
    nonce: [u8; 24],
    mac: [u8; 16],
) -> Result<Vec<u8>, String> {
    unsafe {
        let mut plain_text: Vec<u8> = vec![0u8; cipher_text.len()];
        if ffi::crypto_unlock(
            plain_text.as_mut_ptr(),
            key.as_ptr(),
            nonce.as_ptr(),
            mac.as_ptr(),
            cipher_text.as_ptr(),
            cipher_text.len(),
        ) == 0
        {
            return Ok(plain_text);
        }
        Err("Message is corrupt.".to_owned())
    }
}

/// Decrypt ciphertext with additional data.
///
/// # Example
///
/// ```
/// use monocypher::aead::{lock, unlock};
///
/// let plaintext = "plaintext";
/// let key = [137u8; 32];
/// let nonce = [120u8; 24];
/// let ad = "data";
///
/// let cymac = lock::aead(plaintext.as_bytes(), key, nonce, ad.as_bytes());
/// unlock::aead(&cymac.0, key, nonce, cymac.1, ad.as_bytes()).unwrap();
/// ```
pub fn aead(
    cipher_text: &[u8],
    key: [u8; 32],
    nonce: [u8; 24],
    mac: [u8; 16],
    ad: &[u8],
) -> Result<Vec<u8>, String> {
    unsafe {
        let mut plain_text: Vec<u8> = vec![0u8; cipher_text.len()];
        if ffi::crypto_unlock_aead(
            plain_text.as_mut_ptr(),
            key.as_ptr(),
            nonce.as_ptr(),
            mac.as_ptr(),
            ad.as_ptr(),
            ad.len(),
            cipher_text.as_ptr(),
            cipher_text.len(),
        ) == 0
        {
            return Ok(plain_text);
        }
        Err("Message is corrupt.".to_owned())
    }
}
