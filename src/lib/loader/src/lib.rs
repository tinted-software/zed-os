#![no_std]
extern crate alloc;

pub mod elf;
pub mod macho;

use alloc::string::String;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LoaderError {
    #[error("Parse error: {0}")]
    ParseError(#[from] goblin::error::Error),
    #[error("Invalid magic: {0:#x}")]
    InvalidMagic(u32),
    #[error("Relocation error: {0}")]
    RelocationError(&'static str),
    #[error("Missing symbol: {0}")]
    MissingSymbol(String),
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
