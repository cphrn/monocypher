//! Public key signature functions
//!
//! [Official documentation](https://monocypher.org/manual/sign)

use ffi;
use std::mem;

pub fn check(signature: [u8; 64], public_key: [u8; 32], message: &[u8]) -> Result<(), String> {
    unsafe {
        if ffi::crypto_check(
            signature.as_ptr(),
            public_key.as_ptr(),
            message.as_ptr(),
            message.len(),
        ) == 0
            {
                return Ok(());
            }
        Err("Forged message detected.".to_owned())
    }
}

pub struct Context(ffi::crypto_check_ctx);

impl Context {
    #[inline]
    pub fn new(signature: [u8; 64], public_key: [u8; 32]) -> Context {
        unsafe {
            let mut ctx = mem::MaybeUninit::<ffi::crypto_check_ctx>::uninit();
            ffi::crypto_check_init(ctx.as_mut_ptr() as *mut _ as *mut _, signature.as_ptr(), public_key.as_ptr());
            Context(ctx.assume_init())
        }
    }

    #[inline]
    pub fn update(&mut self, message: &[u8]) {
        unsafe {
            ffi::crypto_check_update(&mut self.0 as *mut _ as *mut _, message.as_ptr(), message.len());
        }
    }

    #[inline]
    pub fn finalize(&mut self) -> Result<(), String> {
        unsafe {
            if ffi::crypto_check_final(&mut self.0 as *mut _ as *mut _) == 0 {
                return Ok(());
            }
            Err("Message corrupted, aborting.".to_owned())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ::pubkey::sign;

    #[test]
    fn check() {
        let secret_key = [2u8; 32];
        let public_key = ::pubkey::sign::public_key(secret_key);

        let sig = sign::sign(secret_key, public_key, "test".as_bytes());

        let ret = ::pubkey::check::check(sig, public_key, "test".as_bytes());

        assert_eq!(ret.is_ok(), true)
    }

    #[test]
    fn check_forged() {
        let secret_key = [2u8; 32];
        let public_key = sign::public_key(secret_key);

        let sig = sign::sign(secret_key, public_key, "test".as_bytes());

        let ret = ::pubkey::check::check(sig, public_key, "not_test".as_bytes());

        assert_eq!(ret.is_err(), true)
    }

    #[test]
    fn ctx() {
        let secret_key = [2u8; 32];
        let public_key = ::pubkey::sign::public_key(secret_key);

        let sig = sign::sign(secret_key, public_key, "test".as_bytes());

        let mut ctx = Context::new(sig, public_key);
        ctx.update("test".as_bytes());
        let ret = ctx.finalize();

        assert_eq!(ret.is_ok(), true)
    }

    #[test]
    fn ctx_fail() {
        let secret_key = [2u8; 32];
        let public_key = ::pubkey::sign::public_key(secret_key);

        let sig = sign::sign(secret_key, public_key, "test".as_bytes());

        let mut ctx = Context::new(sig, public_key);
        ctx.update("not_test".as_bytes());
        let ret = ctx.finalize();

        assert_eq!(ret.is_err(), true);
        assert_eq!(ret.err().unwrap(), "Message corrupted, aborting.".to_owned());
    }
}
