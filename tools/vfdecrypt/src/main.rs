use anyhow::{anyhow, Result};
use clap::Parser;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem;
use std::path::PathBuf;
use std::slice;

use aes::Aes128;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use des::cipher::block_padding;
use des::TdesEde3;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;

// Constants
const PBKDF2_ITERATION_COUNT: u32 = 1000;

type Aes128CbcDec = cbc::Decryptor<Aes128>;
type TdesEde3CbcDec = cbc::Decryptor<TdesEde3>;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    input: PathBuf,

    #[arg(short, long)]
    output: PathBuf,

    #[arg(short, long)]
    password: Option<String>,

    #[arg(short, long)]
    key: Option<String>,
}

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

fn determine_header_version(dmg: &mut File) -> Result<i32> {
    let mut buf = [0u8; 8];

    dmg.seek(SeekFrom::Start(0))?;
    dmg.read_exact(&mut buf)?;
    if &buf == b"encrcdsa" {
        return Ok(2);
    }

    dmg.seek(SeekFrom::End(-8))?;
    dmg.read_exact(&mut buf)?;
    if &buf == b"cdsaencr" {
        return Ok(1);
    }

    Ok(-1)
}

fn apple_des3_ede_unwrap_key(
    wrapped_key: &[u8],
    decrypt_key: &[u8],
    unwrapped_key: &mut [u8],
) -> Result<()> {
    let iv: [u8; 8] = [0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05];
    let cipher = TdesEde3CbcDec::new_from_slices(decrypt_key, &iv).unwrap();
    let mut temp1 = wrapped_key.to_vec();
    let pt1 = cipher
        .decrypt_padded_mut::<block_padding::Pkcs7>(&mut temp1)
        .map_err(|e| anyhow!("decrypt error 1: {}", e))?;

    let mut temp2 = pt1.to_vec();
    temp2.reverse();

    let (iv2, ciphertext2) = temp2.split_at(8);

    let cipher2 = TdesEde3CbcDec::new_from_slices(decrypt_key, iv2).unwrap();
    let mut cekicv = ciphertext2.to_vec();
    let decrypted = cipher2
        .decrypt_padded_mut::<block_padding::Pkcs7>(&mut cekicv)
        .map_err(|e| anyhow!("decrypt error 2: {}", e))?;

    unwrapped_key.copy_from_slice(&decrypted[4..]);

    Ok(())
}

fn unwrap_v1_header(passphrase: &str, header: &CEncryptedV1Header) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut derived_key = vec![0u8; 24]; // 192/8
    pbkdf2_hmac::<Sha1>(
        passphrase.as_bytes(),
        &header.kdf_salt[..20],
        PBKDF2_ITERATION_COUNT,
        &mut derived_key,
    );

    let mut aes_key = vec![0u8; 32];
    apple_des3_ede_unwrap_key(&header.wrapped_aes_key[..40], &derived_key, &mut aes_key)?;

    let mut hmacsha1_key = vec![0u8; 40];
    apple_des3_ede_unwrap_key(
        &header.wrapped_hmac_sha1_key[..48],
        &derived_key,
        &mut hmacsha1_key,
    )?;

    Ok((aes_key[..16].to_vec(), hmacsha1_key[..20].to_vec()))
}

fn unwrap_v2_header(passphrase: &str, header: &CEncryptedV2PwHeader) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut derived_key = vec![0u8; 24]; // 192/8
    let salt = &header.kdf_salt[..header.kdf_salt_len as usize];
    pbkdf2_hmac::<Sha1>(
        passphrase.as_bytes(),
        salt,
        header.kdf_iteration_count,
        &mut derived_key,
    );

    let cipher =
        TdesEde3CbcDec::new_from_slices(derived_key.as_slice(), &header.blob_enc_iv).unwrap();
    let mut keyblob = header.encrypted_keyblob.to_vec();
    let decrypted = cipher
        .decrypt_padded_mut::<block_padding::Pkcs7>(&mut keyblob)
        .map_err(|e| anyhow!("v2 decrypt: {}", e))?;

    let aes_key = decrypted[..16].to_vec();
    let hmac_key = decrypted[..20].to_vec();
    Ok((aes_key, hmac_key))
}

fn main() -> Result<()> {
    let args = Args::parse();

    let password = args
        .password
        .ok_or_else(|| anyhow!("Password is required"))?;

    let mut in_file = File::open(&args.input)?;
    let mut out_file = File::create(&args.output)?;

    let hdr_version = determine_header_version(&mut in_file)?;
    println!("v{} header detected.", hdr_version);

    let mut chunk_size = 4096;

    let (aes_key, hmac_key) = if hdr_version == 1 {
        in_file.seek(SeekFrom::End(
            -(mem::size_of::<CEncryptedV1Header>() as i64),
        ))?;
        let mut v1header: CEncryptedV1Header = unsafe { mem::zeroed() };
        let header_slice = unsafe {
            slice::from_raw_parts_mut(
                &mut v1header as *mut _ as *mut u8,
                mem::size_of::<CEncryptedV1Header>(),
            )
        };
        in_file.read_exact(header_slice)?;
        v1header.adjust_byteorder();
        unwrap_v1_header(&password, &v1header)?
    } else if hdr_version == 2 {
        in_file.seek(SeekFrom::Start(0))?;
        let mut v2header: CEncryptedV2PwHeader = unsafe { mem::zeroed() };
        let header_slice = unsafe {
            slice::from_raw_parts_mut(
                &mut v2header as *mut _ as *mut u8,
                mem::size_of::<CEncryptedV2PwHeader>(),
            )
        };
        in_file.read_exact(header_slice)?;
        v2header.adjust_byteorder();
        chunk_size = v2header.blocksize as usize;
        let (aes_key, hmac_key) = unwrap_v2_header(&password, &v2header)?;
        in_file.seek(SeekFrom::Start(v2header.dataoffset as u64))?;
        (aes_key, hmac_key)
    } else {
        return Err(anyhow!("Unknown format."));
    };

    println!("Keys unwrapped successfully.");

    let mut chunk_no: u32 = 0;
    let mut in_buf = vec![0u8; chunk_size];

    loop {
        let bytes_read = in_file.read(&mut in_buf)?;
        if bytes_read == 0 {
            break;
        }

        let mut hmac = <Hmac<Sha1> as Mac>::new_from_slice(&hmac_key).unwrap();
        hmac.update(&chunk_no.to_be_bytes());
        let result = hmac.finalize();
        let iv = &result.into_bytes()[..16];

        let mut out_buf = in_buf[..bytes_read].to_vec();
        let cipher = Aes128CbcDec::new_from_slices(&aes_key, iv).unwrap();
        let pt = cipher
            .decrypt_padded_mut::<block_padding::NoPadding>(&mut out_buf)
            .unwrap();

        out_file.write_all(pt)?;

        chunk_no += 1;
    }

    println!("Decryption finished. {} chunks written.", chunk_no);

    Ok(())
}
