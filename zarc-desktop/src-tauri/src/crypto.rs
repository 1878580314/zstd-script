use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;
use std::cmp::min;
use std::io::{self, ErrorKind, Read, Write};

pub const MAGIC_HEADER: &[u8; 6] = b"ZARCv2";
pub const SALT_SIZE: usize = 16;
pub const NONCE_SIZE: usize = 12;
pub const CHUNK_SIZE: usize = 64 * 1024;
const KEY_SIZE: usize = 32;
const PBKDF2_ITERATIONS: u32 = 600_000;

fn derive_key(password: &str, salt: &[u8; SALT_SIZE]) -> [u8; KEY_SIZE] {
    let mut key = [0_u8; KEY_SIZE];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    key
}

pub struct EncryptedWriter<W: Write> {
    inner: W,
    cipher: Aes256Gcm,
    buffer: Vec<u8>,
    finished: bool,
}

impl<W: Write> EncryptedWriter<W> {
    pub fn new(mut inner: W, password: &str) -> io::Result<Self> {
        let mut salt = [0_u8; SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut salt);

        let key = derive_key(password, &salt);
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| {
            io::Error::new(
                ErrorKind::InvalidInput,
                "failed to initialize AES-256-GCM cipher",
            )
        })?;

        inner.write_all(MAGIC_HEADER)?;
        inner.write_all(&salt)?;

        Ok(Self {
            inner,
            cipher,
            buffer: Vec::with_capacity(CHUNK_SIZE),
            finished: false,
        })
    }

    fn write_chunk(&mut self, chunk: &[u8]) -> io::Result<()> {
        if chunk.is_empty() {
            return Ok(());
        }

        let mut nonce_bytes = [0_u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self.cipher.encrypt(nonce, chunk).map_err(|_| {
            io::Error::new(
                ErrorKind::InvalidData,
                "encryption failed while processing archive chunk",
            )
        })?;

        let total_len = NONCE_SIZE
            .checked_add(ciphertext.len())
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "encrypted chunk overflow"))?;

        if total_len > u32::MAX as usize {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "encrypted chunk too large",
            ));
        }

        self.inner.write_all(&(total_len as u32).to_be_bytes())?;
        self.inner.write_all(&nonce_bytes)?;
        self.inner.write_all(&ciphertext)?;
        Ok(())
    }

    fn flush_full_chunks(&mut self) -> io::Result<()> {
        while self.buffer.len() >= CHUNK_SIZE {
            let chunk: Vec<u8> = self.buffer.drain(..CHUNK_SIZE).collect();
            self.write_chunk(&chunk)?;
        }
        Ok(())
    }

    pub fn finish(mut self) -> io::Result<W> {
        if self.finished {
            return Ok(self.inner);
        }

        if !self.buffer.is_empty() {
            let final_chunk = std::mem::take(&mut self.buffer);
            self.write_chunk(&final_chunk)?;
        }

        self.inner.write_all(&0_u32.to_be_bytes())?;
        self.inner.flush()?;
        self.finished = true;
        Ok(self.inner)
    }
}

impl<W: Write> Write for EncryptedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.finished {
            return Err(io::Error::new(
                ErrorKind::BrokenPipe,
                "cannot write to a finished encrypted stream",
            ));
        }

        if buf.is_empty() {
            return Ok(0);
        }

        self.buffer.extend_from_slice(buf);
        self.flush_full_chunks()?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub struct DecryptedReader<R: Read> {
    inner: R,
    cipher: Aes256Gcm,
    plain_buf: Vec<u8>,
    plain_offset: usize,
    eof: bool,
}

impl<R: Read> DecryptedReader<R> {
    pub fn new(mut inner: R, password: &str) -> io::Result<Self> {
        let mut magic = [0_u8; MAGIC_HEADER.len()];
        inner.read_exact(&mut magic)?;
        if &magic != MAGIC_HEADER {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "invalid encrypted archive header",
            ));
        }

        let mut salt = [0_u8; SALT_SIZE];
        inner.read_exact(&mut salt)?;

        let key = derive_key(password, &salt);
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| {
            io::Error::new(
                ErrorKind::InvalidInput,
                "failed to initialize AES-256-GCM cipher",
            )
        })?;

        Ok(Self {
            inner,
            cipher,
            plain_buf: Vec::with_capacity(CHUNK_SIZE),
            plain_offset: 0,
            eof: false,
        })
    }

    fn read_next_chunk(&mut self) -> io::Result<bool> {
        if self.eof {
            return Ok(false);
        }

        let mut len_buf = [0_u8; 4];
        self.inner.read_exact(&mut len_buf)?;
        let block_len = u32::from_be_bytes(len_buf) as usize;

        if block_len == 0 {
            self.eof = true;
            return Ok(false);
        }

        if block_len < NONCE_SIZE {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "invalid encrypted block length",
            ));
        }

        let mut block = vec![0_u8; block_len];
        self.inner.read_exact(&mut block)?;

        let (nonce_bytes, ciphertext) = block.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = self.cipher.decrypt(nonce, ciphertext).map_err(|_| {
            io::Error::new(
                ErrorKind::InvalidData,
                "authentication failed: wrong password or corrupted archive",
            )
        })?;

        self.plain_buf = plaintext;
        self.plain_offset = 0;
        Ok(true)
    }
}

impl<R: Read> Read for DecryptedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let mut written = 0_usize;

        while written < buf.len() {
            if self.plain_offset >= self.plain_buf.len() {
                self.plain_buf.clear();
                self.plain_offset = 0;

                match self.read_next_chunk() {
                    Ok(true) => {}
                    Ok(false) => break,
                    Err(err) if err.kind() == ErrorKind::UnexpectedEof => {
                        return Err(io::Error::new(
                            ErrorKind::UnexpectedEof,
                            "encrypted stream ended unexpectedly",
                        ))
                    }
                    Err(err) => return Err(err),
                }
            }

            let available = &self.plain_buf[self.plain_offset..];
            let to_copy = min(buf.len() - written, available.len());
            buf[written..written + to_copy].copy_from_slice(&available[..to_copy]);
            self.plain_offset += to_copy;
            written += to_copy;
        }

        Ok(written)
    }
}
