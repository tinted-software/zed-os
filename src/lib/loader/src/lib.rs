#![no_std]
extern crate alloc;

pub mod elf;
pub mod macho;

use alloc::string::String;
use derive_more::derive::Display;

#[derive(Debug, Display)]
pub enum LoaderError {
    #[display("Parse error: {_0}")]
    ParseError(goblin::error::Error),
    #[display("Invalid magic: {_0:#x}")]
    InvalidMagic(u32),
    #[display("Relocation error: {_0}")]
    RelocationError(&'static str),
    #[display("Missing symbol: {_0}")]
    MissingSymbol(String),
}

impl core::error::Error for LoaderError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            LoaderError::ParseError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<goblin::error::Error> for LoaderError {
    fn from(err: goblin::error::Error) -> Self {
        LoaderError::ParseError(err)
    }
}

#[derive(Debug)]
pub enum BinaryFormat {
    Elf,
    MachO,
}

pub struct LoadedBinary {
    pub entry: u64,
    pub image_base: u64,
    pub image_size: u64,
    pub is_64bit: bool,
    pub dylinker: Option<String>,
}
