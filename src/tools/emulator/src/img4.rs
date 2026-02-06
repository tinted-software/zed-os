use derive_more::derive::Display;
use rasn::types::{OctetString, Utf8String};
use rasn::{AsnType, Decode, Decoder, Encode};

#[derive(Debug, Display)]
pub enum Img4Error {
    #[display("ASN.1 parsing error: {_0}")]
    Asn1(String),
    #[display("Invalid IMG4 format: {_0}")]
    Format(String),
    #[display("Missing component: {_0}")]
    Missing(String),
}

impl std::error::Error for Img4Error {}

pub type Img4Result<T> = std::result::Result<T, Img4Error>;

#[derive(Decode, Encode, Debug, AsnType)]
pub struct Im4p {
    pub magic: Utf8String,
    pub im_type: Utf8String,
    pub description: Utf8String,
    pub data: OctetString,
}

#[derive(Decode, Encode, Debug, AsnType)]
pub struct Im4m {
    pub magic: Utf8String,
    pub version: u32,
    pub manifest: OctetString,
}

#[derive(Decode, Encode, Debug, AsnType)]
pub struct Img4 {
    pub magic: Utf8String,
    pub payload: Im4p,
    pub manifest: Option<Im4m>,
}

#[repr(C, packed)]
pub struct DfuHeader {
    pub magic: [u8; 5],
    pub version: u8,
    pub size: u32,
    pub crc: u32,
}

pub fn parse_dfu(data: &[u8]) -> Img4Result<&[u8]> {
    let header_size = std::mem::size_of::<DfuHeader>();
    if data.len() < header_size {
        return Err(Img4Error::Format("DFU file too small".to_string()));
    }

    let header: DfuHeader = unsafe { std::ptr::read(data.as_ptr() as *const _) };
    if &header.magic != b"DfuSe" {
        return Err(Img4Error::Format("Invalid DFU magic".to_string()));
    }

    Ok(&data[header_size..])
}

pub fn parse_img4(data: &[u8]) -> Img4Result<Img4> {
    let img4: Img4 = rasn::ber::decode(data).map_err(|e| Img4Error::Asn1(e.to_string()))?;

    if img4.magic.as_str() != "IMG4" {
        return Err(Img4Error::Format("Invalid IMG4 magic".to_string()));
    }

    Ok(img4)
}
