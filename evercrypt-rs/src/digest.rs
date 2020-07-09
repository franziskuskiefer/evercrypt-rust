use evercrypt_sys::evercrypt_bindings::*;

#[derive(Debug)]
pub enum Error {
    InvalidStateFinished,
}

#[derive(Copy, Clone, Debug)]
pub enum Mode {
    Sha1 = Spec_Hash_Definitions_SHA1 as isize,
    Sha224 = Spec_Hash_Definitions_SHA2_224 as isize,
    Sha256 = Spec_Hash_Definitions_SHA2_256 as isize,
    Sha384 = Spec_Hash_Definitions_SHA2_384 as isize,
    Sha512 = Spec_Hash_Definitions_SHA2_512 as isize,
}

pub(crate) fn get_digest_size(mode: Mode) -> usize {
    match mode {
        Mode::Sha1 => 20,
        Mode::Sha224 => 28,
        Mode::Sha256 => 32,
        Mode::Sha384 => 48,
        Mode::Sha512 => 64,
    }
}

pub struct Digest {
    mode: Mode,
    finished: bool,
    c_state: *mut Hacl_Streaming_Functor_state_s___EverCrypt_Hash_state_s____,
}

impl Digest {
    pub fn new(alg: Mode) -> Self {
        let c_state: *mut Hacl_Streaming_Functor_state_s___EverCrypt_Hash_state_s____ =
            unsafe { EverCrypt_Hash_Incremental_create_in(alg as Spec_Hash_Definitions_hash_alg) };
        Self {
            mode: alg,
            finished: false,
            c_state: c_state,
        }
    }

    pub fn hash(mode: Mode, data: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; get_digest_size(mode)];
        unsafe {
            EverCrypt_Hash_hash(
                mode as Spec_Hash_Definitions_hash_alg,
                out.as_mut_ptr(),
                data.as_ptr() as _,
                data.len() as u32,
            );
        }
        out
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.finished {
            return Err(Error::InvalidStateFinished);
        }
        unsafe {
            EverCrypt_Hash_Incremental_update(self.c_state, data.as_ptr() as _, data.len() as u32);
        }
        Ok(())
    }

    pub fn finish(&mut self) -> Result<Vec<u8>, Error> {
        if self.finished {
            return Err(Error::InvalidStateFinished);
        }
        let mut out = vec![0u8; get_digest_size(self.mode)];
        unsafe {
            EverCrypt_Hash_Incremental_finish(self.c_state, out.as_mut_ptr());
            EverCrypt_Hash_Incremental_free(self.c_state);
        }
        self.finished = true;
        Ok(out)
    }
}
