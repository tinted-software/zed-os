// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
extern crate alloc;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use {
    crate::blkx::BlkxTable,
    serde::{Deserialize, Serialize},
};

use crate::Result;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Plist {
    #[serde(rename = "resource-fork")]
    pub resource_fork: ResourceFork,
}

impl Plist {
    pub fn partitions(&self) -> &[Partition] {
        &self.resource_fork.blkx
    }

    pub fn add_partition(&mut self, partition: Partition) {
        self.resource_fork.blkx.push(partition);
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ResourceFork {
    pub blkx: Vec<Partition>,
    #[serde(default)]
    pub plst: Vec<Partition>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Partition {
    #[serde(rename = "Attributes")]
    pub attributes: String,
    #[serde(rename = "CFName")]
    #[serde(default)]
    pub cfname: String,
    #[serde(rename = "Data")]
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "Name")]
    pub name: String,
}

impl Partition {
    pub fn new(id: i32, name: String, table: BlkxTable) -> Self {
        let mut data = vec![];
        let mut cursor = binrw::io::Cursor::new(&mut data);
        table.write_to(&mut cursor).unwrap();
        Self {
            attributes: "0x0050".to_string(),
            cfname: name.clone(),
            data,
            id: id.to_string(),
            name,
        }
    }

    pub fn table(&self) -> Result<BlkxTable> {
        let mut cursor = binrw::io::Cursor::new(&self.data[..]);
        BlkxTable::read_from(&mut cursor)
    }
}
