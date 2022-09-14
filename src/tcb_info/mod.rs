use chrono::{
  DateTime, FixedOffset
};

pub const FMSPC_SIZE: usize = 6;
pub const PCE_ID_SIZE: usize = 2;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TCBInfoVersion {
    V2,
    V3,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TCBInfoID {
    TDX,
    SGX,
}

#[derive(Clone, PartialEq, Eq)]
pub struct TCBLevel {

}

#[derive(Clone, PartialEq, Eq)]
pub struct TCBInfo<'a> {
    pub signature: &'a str,
    pub version: TCBInfoVersion,
    pub id: TCBInfoID,
    pub issue_date: DateTime<FixedOffset>,
    pub next_update: DateTime<FixedOffset>,
    pub fmspc: &'a [u8; FMSPC_SIZE],
    pub pce_id: &'a [u8; PCE_ID_SIZE],
}
