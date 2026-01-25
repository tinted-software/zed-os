use std::io::{Read, Seek, SeekFrom, Write};
use std::mem;
use std::slice;
use thiserror::Error;

use aes::Aes128;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use des::TdesEde3;
use des::cipher::block_padding;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;

#[derive(Error, Debug)]
pub enum VfDecryptError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Cipher error: {0}")]
    Cipher(String),
    #[error("Decryption error: {0}")]
    Decryption(String),
    #[error("Password is required")]
    PasswordRequired,
    #[error("Unsupported format")]
    UnsupportedFormat,
    #[error("Unsupported blob encryption key bits: {0}")]
    UnsupportedKeyBits(u32),
    #[error("Unsupported KDF algorithm: {0}")]
    UnsupportedKdfAlgorithm(u32),
    #[error("Unsupported KDF PRNG algorithm: {0}")]
    UnsupportedKdfPrng(u32),
    #[error("KDF salt length {0} exceeds buffer size")]
    SaltTooLong(usize),
    #[error("Header specifies IV size {0} which exceeds buffer size")]
    IvTooLong(usize),
    #[error("Unsupported blob IV size: {0}. Expected 8 for TDES.")]
    UnsupportedIvSize(usize),
    #[error("Keyblob size {0} exceeds buffer")]
    KeyblobTooLong(usize),
    #[error("Decrypted key material too short")]
    KeyMaterialTooShort,
    #[error("Decrypted keyblob too short: {0} bytes, expected at least 32")]
    KeyblobTooShort(usize),
    #[error("Hex decode error: {0}")]
    HexDecode(String),
    #[error("Unknown error: {0}")]
    Unknown(String),
}

type Result<T> = core::result::Result<T, VfDecryptError>;

const PBKDF2_ITERATION_COUNT: u32 = 1000;

type Aes128CbcDec = cbc::Decryptor<Aes128>;
type TdesEde3CbcDec = cbc::Decryptor<TdesEde3>;

#[repr(C, packed)]
struct CEncryptedV1Header {
    filler1: [u8; 48],
    kdf_iteration_count: u32,
    kdf_salt_len: u32,
    kdf_salt: [u8; 48],
    unwrap_iv: [u8; 32],
    len_wrapped_aes_key: u32,
    wrapped_aes_key: [u8; 296],
    len_hmac_sha1_key: u32,
    wrapped_hmac_sha1_key: [u8; 300],
    len_integrity_key: u32,
    wrapped_integrity_key: [u8; 48],
    filler6: [u8; 484],
}

impl CEncryptedV1Header {
    fn adjust_byteorder(&mut self) {
        self.kdf_iteration_count = u32::from_be(self.kdf_iteration_count);
        self.kdf_salt_len = u32::from_be(self.kdf_salt_len);
        self.len_wrapped_aes_key = u32::from_be(self.len_wrapped_aes_key);
        self.len_hmac_sha1_key = u32::from_be(self.len_hmac_sha1_key);
        self.len_integrity_key = u32::from_be(self.len_integrity_key);
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct CEncryptedV2PwHeader {
    sig: [u8; 8],
    version: u32,
    enc_iv_size: u32,
    unk1: u32,
    unk2: u32,
    unk3: u32,
    unk4: u32,
    unk5: u32,
    uuid: [u8; 16],
    blocksize: u32,
    datasize: u64,
    dataoffset: u64,
    filler1: [u8; 0x260],
    kdf_algorithm: u32,
    kdf_prng_algorithm: u32,
    kdf_iteration_count: u32,
    kdf_salt_len: u32,
    kdf_salt: [u8; 32],
    blob_enc_iv_size: u32,
    blob_enc_iv: [u8; 32],
    blob_enc_key_bits: u32,
    blob_enc_algorithm: u32,
    blob_enc_padding: u32,
    blob_enc_mode: u32,
    encrypted_keyblob_size: u32,
    encrypted_keyblob: [u8; 0x30],
}

impl CEncryptedV2PwHeader {
    fn adjust_byteorder(&mut self) {
        self.blocksize = u32::from_be(self.blocksize);
        self.datasize = u64::from_be(self.datasize);
        self.dataoffset = u64::from_be(self.dataoffset);
        self.kdf_algorithm = u32::from_be(self.kdf_algorithm);
        self.kdf_prng_algorithm = u32::from_be(self.kdf_prng_algorithm);
        self.kdf_iteration_count = u32::from_be(self.kdf_iteration_count);
        self.kdf_salt_len = u32::from_be(self.kdf_salt_len);
        self.blob_enc_iv_size = u32::from_be(self.blob_enc_iv_size);
        self.blob_enc_key_bits = u32::from_be(self.blob_enc_key_bits);
        self.blob_enc_algorithm = u32::from_be(self.blob_enc_algorithm);
        self.blob_enc_padding = u32::from_be(self.blob_enc_padding);
        self.blob_enc_mode = u32::from_be(self.blob_enc_mode);
        self.encrypted_keyblob_size = u32::from_be(self.encrypted_keyblob_size);
    }
}

fn determine_header_version<Input: Read + Seek>(dmg: &mut Input) -> Result<i32> {
    let mut buf = [0u8; 8];

    let _ = dmg.seek(SeekFrom::Start(0))?;
    if dmg.read_exact(&mut buf).is_ok() && &buf == b"encrcdsa" {
        return Ok(2);
    }

    let _ = dmg.seek(SeekFrom::End(-8))?;
    if dmg.read_exact(&mut buf).is_ok() && &buf == b"cdsaencr" {
        return Ok(1);
    }

    Err(VfDecryptError::UnsupportedFormat)
}

fn apple_des3_ede_unwrap_key(
    wrapped_key: &[u8],
    wrapped_key_len: usize,
    decrypt_key: &[u8],
    unwrapped_key_len: usize,
) -> Result<Vec<u8>> {
    let iv: [u8; 8] = [0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05];
    let cipher = TdesEde3CbcDec::new_from_slices(decrypt_key, &iv).map_err(|e| {
        VfDecryptError::Cipher(format!("Failed to initialize TDES cipher (1): {}", e))
    })?;
    let mut temp1 = wrapped_key[..wrapped_key_len].to_vec();
    let pt1 = cipher
        .decrypt_padded_mut::<block_padding::Pkcs7>(&mut temp1)
        .map_err(|e| VfDecryptError::Decryption(format!("decrypt error 1: {}", e)))?;

    let mut temp2 = pt1.to_vec();
    temp2.reverse();

    let (iv2, ciphertext2) = temp2.split_at(8);

    let cipher2 = TdesEde3CbcDec::new_from_slices(decrypt_key, iv2).map_err(|e| {
        VfDecryptError::Cipher(format!("Failed to initialize TDES cipher (2): {}", e))
    })?;
    let mut cekicv = ciphertext2.to_vec();
    let decrypted = cipher2
        .decrypt_padded_mut::<block_padding::Pkcs7>(&mut cekicv)
        .map_err(|e| VfDecryptError::Decryption(format!("decrypt error 2: {}", e)))?;

    if decrypted.len() < 4 + unwrapped_key_len {
        return Err(VfDecryptError::KeyMaterialTooShort);
    }
    Ok(decrypted[4..4 + unwrapped_key_len].to_vec())
}

fn unwrap_v1_header(passphrase: &str, header: &CEncryptedV1Header) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut derived_key = vec![0u8; 24];
    pbkdf2_hmac::<Sha1>(
        passphrase.as_bytes(),
        &header.kdf_salt[..20],
        PBKDF2_ITERATION_COUNT,
        &mut derived_key,
    );

    let aes_key = apple_des3_ede_unwrap_key(&header.wrapped_aes_key, 40, &derived_key, 16)?;
    let hmacsha1_key =
        apple_des3_ede_unwrap_key(&header.wrapped_hmac_sha1_key, 48, &derived_key, 20)?;

    Ok((aes_key, hmacsha1_key))
}

fn unwrap_v2_header(passphrase: &str, header: &CEncryptedV2PwHeader) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut derived_key = vec![0u8; 24];
    pbkdf2_hmac::<Sha1>(
        passphrase.as_bytes(),
        &header.kdf_salt[..20],
        PBKDF2_ITERATION_COUNT,
        &mut derived_key,
    );

    let iv_size = header.blob_enc_iv_size as usize;
    let cipher =
        TdesEde3CbcDec::new_from_slices(derived_key.as_slice(), &header.blob_enc_iv[..iv_size])
            .map_err(|e| {
                VfDecryptError::Cipher(format!("Failed to initialize blob cipher: {}", e))
            })?;

    let mut keyblob = header.encrypted_keyblob[..header.encrypted_keyblob_size as usize].to_vec();

    let decrypted = cipher
        .decrypt_padded_mut::<block_padding::Pkcs7>(&mut keyblob)
        .map_err(|e| VfDecryptError::Decryption(format!("v2 decrypt: {}", e)))?;

    if decrypted.len() < 20 {
        return Err(VfDecryptError::KeyblobTooShort(decrypted.len()));
    }

    let aes_key = decrypted[0..16].to_vec();
    let hmacsha1_key = decrypted[0..20].to_vec();
    Ok((aes_key, hmacsha1_key))
}

pub struct VfDecryptor<R> {
    input: R,
    aes_key: [u8; 16],
    hmac_key: [u8; 20],
    block_size: usize,
    data_size: u64,
    total_out: u64,
    hdr_version: i32,
    chunk_no: u32,
    buffer: Vec<u8>,
    buffer_pos: usize,
    buffer_len: usize,
}

impl<R: Read + Seek> VfDecryptor<R> {
    pub fn new(mut input: R, key_or_passphrase: &str) -> Result<Self> {
        let hdr_version = determine_header_version(&mut input)?;

        let mut aes_key_vec = vec![0u8; 16];
        let mut hmac_key_vec = vec![0u8; 20];

        let mut block_size = 4096;
        let mut data_size = 0u64;
        let mut data_offset = 0u64;

        if key_or_passphrase.len() >= 32 {
            for i in 0..16 {
                aes_key_vec[i] = u8::from_str_radix(&key_or_passphrase[i * 2..i * 2 + 2], 16)
                    .map_err(|e| VfDecryptError::HexDecode(e.to_string()))?;
            }
            if key_or_passphrase.len() >= 72 {
                for i in 0..20 {
                    let start = 32 + i * 2;
                    hmac_key_vec[i] = u8::from_str_radix(&key_or_passphrase[start..start + 2], 16)
                        .map_err(|e| VfDecryptError::HexDecode(e.to_string()))?;
                }
            }
        } else if hdr_version == 1 {
            input.seek(SeekFrom::End(
                -(mem::size_of::<CEncryptedV1Header>() as i64 + 8),
            ))?;
            let mut v1header: CEncryptedV1Header = unsafe { mem::zeroed() };
            let header_slice = unsafe {
                slice::from_raw_parts_mut(
                    &mut v1header as *mut _ as *mut u8,
                    mem::size_of::<CEncryptedV1Header>(),
                )
            };
            input.read_exact(header_slice)?;
            v1header.adjust_byteorder();
            let (a, h) = unwrap_v1_header(key_or_passphrase, &v1header)?;
            aes_key_vec = a;
            hmac_key_vec = h;
        } else if hdr_version == 2 {
            input.seek(SeekFrom::Start(0))?;
            let mut v2header: CEncryptedV2PwHeader = unsafe { mem::zeroed() };
            let header_slice = unsafe {
                slice::from_raw_parts_mut(
                    &mut v2header as *mut _ as *mut u8,
                    mem::size_of::<CEncryptedV2PwHeader>(),
                )
            };
            input.read_exact(header_slice)?;
            v2header.adjust_byteorder();
            let (a, h) = unwrap_v2_header(key_or_passphrase, &v2header)?;
            aes_key_vec = a;
            hmac_key_vec = h;
        }

        let mut aes_key = [0u8; 16];
        aes_key.copy_from_slice(&aes_key_vec[..16]);
        let mut hmac_key = [0u8; 20];
        hmac_key.copy_from_slice(&hmac_key_vec[..20]);

        if hdr_version == 1 {
            let file_size = input.seek(SeekFrom::End(0))?;
            data_size = file_size - (mem::size_of::<CEncryptedV1Header>() as u64 + 8);
            data_offset = 0;
            block_size = 4096;
        } else if hdr_version == 2 {
            input.seek(SeekFrom::Start(0))?;
            let mut v2header: CEncryptedV2PwHeader = unsafe { mem::zeroed() };
            let header_slice = unsafe {
                slice::from_raw_parts_mut(
                    &mut v2header as *mut _ as *mut u8,
                    mem::size_of::<CEncryptedV2PwHeader>(),
                )
            };
            input.read_exact(header_slice)?;
            v2header.adjust_byteorder();
            block_size = v2header.blocksize as usize;
            data_size = v2header.datasize;
            data_offset = v2header.dataoffset;
        }

        input.seek(SeekFrom::Start(data_offset))?;

        Ok(Self {
            input,
            aes_key,
            hmac_key,
            block_size,
            data_size,
            total_out: 0,
            hdr_version,
            chunk_no: 0,
            buffer: vec![0u8; block_size],
            buffer_pos: 0,
            buffer_len: 0,
        })
    }

    pub fn data_size(&self) -> u64 {
        self.data_size
    }
}

impl<R: Read + Seek> Read for VfDecryptor<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.hdr_version == 2 && self.total_out >= self.data_size {
            return Ok(0);
        }

        if self.buffer_pos >= self.buffer_len {
            let n = self.input.read(&mut self.buffer)?;
            if n == 0 {
                return Ok(0);
            }

            let mut hmac = <Hmac<Sha1> as Mac>::new_from_slice(&self.hmac_key).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::Other, format!("HMAC init error: {}", e))
            })?;
            hmac.update(&self.chunk_no.to_be_bytes());
            let result = hmac.finalize();
            let digest = result.into_bytes();
            let iv = &digest[..16];

            let cipher = Aes128CbcDec::new_from_slices(&self.aes_key, iv).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::Other, format!("AES init error: {}", e))
            })?;

            cipher
                .decrypt_padded_mut::<block_padding::NoPadding>(&mut self.buffer[..n])
                .map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Decryption error: {}", e),
                    )
                })?;

            self.buffer_len =
                if self.hdr_version == 2 && (self.data_size - self.total_out) < n as u64 {
                    (self.data_size - self.total_out) as usize
                } else {
                    n
                };
            self.buffer_pos = 0;
            self.chunk_no += 1;
        }

        let remaining = self.buffer_len - self.buffer_pos;
        let to_copy = std::cmp::min(buf.len(), remaining);
        buf[..to_copy].copy_from_slice(&self.buffer[self.buffer_pos..self.buffer_pos + to_copy]);
        self.buffer_pos += to_copy;
        self.total_out += to_copy as u64;

        Ok(to_copy)
    }
}

pub fn decrypt<Input: Read + Seek, Output: Write>(
    input: &mut Input,
    output: &mut Output,
    key: &str,
) -> Result<()> {
    let mut decryptor = VfDecryptor::new(input, key)?;
    std::io::copy(&mut decryptor, output)?;
    Ok(())
}
