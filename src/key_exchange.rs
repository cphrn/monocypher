//! Elliptic Curve Diffie-Hellman key exchange
//!
//! //! [Official documentation](https://monocypher.org/manual/key_exchange)

use ffi;
use std::mem;

/// Computes a shared key with your secret key and their public key.
///
/// # Example
///
/// ```
/// use monocypher::key_exchange::shared;
///
/// let pubkey = [1u8; 32];
/// shared([31u8; 32], pubkey);
/// ```
pub fn shared(secret_key: [u8; 32], their_public_key: [u8; 32]) -> [u8; 32] {
    unsafe {
        let mut shared_key = mem::MaybeUninit::<[u8; 32]>::uninit();
        ffi::crypto_key_exchange(
            shared_key.as_mut_ptr() as *mut _,
            secret_key.as_ptr(),
            their_public_key.as_ptr(),
        );

        shared_key.assume_init()
    }
}

/// Deterministically computes the public key from a random secret key.
///
/// # Example
/// ```
/// use monocypher::key_exchange::public;
///
/// let secret_key = [2u8; 32];
/// public(secret_key);
/// ```
pub fn public(secret_key: [u8; 32]) -> [u8; 32] {
    unsafe {
        let mut public_key= mem::MaybeUninit::<[u8; 32]>::uninit();
        ffi::crypto_x25519_public_key(public_key.as_mut_ptr() as *mut u8, secret_key.as_ptr());
        public_key.assume_init()
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn shared() {
        let pubkey = [1u8; 32];
        let shared_key = ::key_exchange::shared([31u8; 32], pubkey);

        assert_eq!(shared_key,
                   [221, 154, 19, 66, 124, 44, 238, 44, 9, 242, 98, 231, 40,23, 150, 119, 121, 116,
                       47, 199, 173, 61, 70, 53, 155, 235, 80, 11, 107, 75, 87, 110])
    }

    #[test]
    fn public() {
        let secret_key = [2u8; 32];
        let public_key = ::key_exchange::public(secret_key);

        assert_eq!(public_key,
                   [206, 141, 58, 209, 204, 182, 51, 236, 123, 112, 193, 120, 20, 165, 199, 110,
                       205, 2, 150, 133, 5, 13, 52, 71, 69, 186, 5, 135, 14, 88, 125, 89])

    }
}
