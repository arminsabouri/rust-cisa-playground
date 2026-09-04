// BIP 460 Pass 3 verifies a full-aggregation group with Verify as defined in
// BIP 459, over the group's ordered public key and message lists.
pub use bip459::{Message, PublicKey, verify as verify_full_agg};

// Marker bytes and sighash epoch defined by BIP 460. The marker is the last
// byte of the witness element of the final input of an aggregation group.
pub const HALF_AGG_MARKER: u8 = 0xbc;
pub const FULL_AGG_MARKER: u8 = 0xbd;
pub const SIGHASH_EPOCH_AGGREGATED: u8 = 0x01;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AggMode {
    Half,
    Full,
}

impl AggMode {
    pub const fn as_byte(self) -> u8 {
        match self {
            AggMode::Half => HALF_AGG_MARKER,
            AggMode::Full => FULL_AGG_MARKER,
        }
    }

    pub const fn from_byte(byte: u8) -> Option<AggMode> {
        match byte {
            HALF_AGG_MARKER => Some(AggMode::Half),
            FULL_AGG_MARKER => Some(AggMode::Full),
            _ => None,
        }
    }
}
