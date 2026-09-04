use std::borrow::Borrow;

use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::sighash::{
    Annex, Prevouts, SigningDataError, SighashCache, TapSighash, TapSighashType, TaprootError,
};
use bitcoin::{Transaction, TxOut};

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

// The signature message of an aggregated input commits to its aggregation mode:
//     m = hash_TapSighash(0x01 || agg_mode || SigMsg(hash_type, 0))
// SigMsg is unchanged from BIP 341, so this reuses rust-bitcoin's encoder and
// only replaces the leading sighash epoch byte, which it writes as 0x00.
pub fn aggregated_sighash<Tx: Borrow<Transaction>, T: Borrow<TxOut>>(
    cache: &mut SighashCache<Tx>,
    input_index: usize,
    prevouts: &Prevouts<T>,
    annex: Option<Annex>,
    hash_type: TapSighashType,
    agg_mode: AggMode,
) -> Result<TapSighash, SigningDataError<TaprootError>> {
    let mut sig_msg = Vec::new();
    cache.taproot_encode_signing_data_to(
        &mut sig_msg,
        input_index,
        prevouts,
        annex,
        None,
        hash_type,
    )?;

    let mut engine = TapSighash::engine();
    engine.input(&[SIGHASH_EPOCH_AGGREGATED, agg_mode.as_byte()]);
    engine.input(&sig_msg[1..]);
    Ok(TapSighash::from_engine(engine))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::deserialize;
    use bitcoin::{Amount, ScriptBuf};

    // keyPathSpending from bip-0460/wallet-test-vectors.json in
    // https://github.com/bitcoin/bips/pull/2212
    const OPTED_OUT_TX: &str = "0200000003375412079d92555f10368dc54e08189023c8a6bfe0318933dda280bb8c96e76a0000000000ffffffff2dea8db84ee1bcea688026b1bda8fea0667b8f3b24d914e2afe0f5dffae5086d0000000000ffffffff8e89080fe122cee9ffa6c0b2128cc14be4ca148c2629d0040f6037cfd0f816190000000000ffffffff01c060d211000000002252204049ce224d4b6407e9c7864e88d8020996beb04663cd1596bf4ff8ab335bc57b00000000";
    const FULL_AGG_TX: &str = "020000000254d36a0897340110cc34b526d73b206175ae4f5db4d25fe7bdeef3a8a5e89afd0100000000ffffffff835a02826d69e61b563ec713020bd2b7c3bc3848223cda2b3c52bbdcd3e6267a0100000000ffffffff01c0cb1707000000002252208640c68f13b51a1e63dfc5cc41202cca21c18f1f9d7037c2cbec3f03f63e52e400000000";

    fn hex(value: &str) -> Vec<u8> {
        (0..value.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
            .collect()
    }

    fn spent_outputs(utxos: &[(&str, u64)]) -> Vec<TxOut> {
        utxos
            .iter()
            .map(|(script_pubkey, sats)| TxOut {
                value: Amount::from_sat(*sats),
                script_pubkey: ScriptBuf::from_hex(script_pubkey).unwrap(),
            })
            .collect()
    }

    #[test]
    fn opted_out_input_keeps_the_bip341_message() {
        let transaction: Transaction = deserialize(&hex(OPTED_OUT_TX)).unwrap();
        let spent = spent_outputs(&[
            ("52204049ce224d4b6407e9c7864e88d8020996beb04663cd1596bf4ff8ab335bc57b", 100000000),
            ("5220cc93415eadd2ed34dc668b345ef49dd492eaaf5c0562482d393917966a6dbfd5", 101000000),
            ("52208877c408836c8fac26214cd6ce52200ef5c44f8466b08d889cc671b7fa7dbcbd", 102000000),
        ]);
        let prevouts = Prevouts::All(&spent);
        let mut cache = SighashCache::new(&transaction);

        let opted_out = cache
            .taproot_key_spend_signature_hash(0, &prevouts, TapSighashType::All)
            .unwrap();
        assert_eq!(
            opted_out.to_byte_array()[..],
            hex("d69ac779928b23970adb2b5db967f32353d9f8025b721b146f063a65015e0809")[..]
        );

        for (index, expected) in [
            (1, "b4790a58d8405ea70b8758143fd245301d725b23af4a60a2d2393686b79122af"),
            (2, "d8562e8cf18da05da50f2bc3f00fc8b93585bcc3c07e398b85a68b068c15247c"),
        ] {
            let sighash = aggregated_sighash(
                &mut cache,
                index,
                &prevouts,
                None,
                TapSighashType::Default,
                AggMode::Half,
            )
            .unwrap();
            assert_eq!(sighash.to_byte_array()[..], hex(expected)[..]);
        }
    }

    #[test]
    fn full_aggregation_sighashes() {
        let transaction: Transaction = deserialize(&hex(FULL_AGG_TX)).unwrap();
        let spent = spent_outputs(&[
            ("52208640c68f13b51a1e63dfc5cc41202cca21c18f1f9d7037c2cbec3f03f63e52e4", 50000000),
            ("522018b6491469cc78b764b01669b0a5a4e892f57e8c1b20b89bc1ca6dce3e881b51", 70000000),
        ]);
        let prevouts = Prevouts::All(&spent);
        let mut cache = SighashCache::new(&transaction);

        for (index, expected) in [
            (0, "9339267f5f6715d1b7e1b26bd69e13689b3872be5fa0c50a9d90daf9f2ae46cc"),
            (1, "d2982e6665e1e964ecefa2a747b19f17ad46d6765e284d639c293647c9349857"),
        ] {
            let sighash = aggregated_sighash(
                &mut cache,
                index,
                &prevouts,
                None,
                TapSighashType::All,
                AggMode::Full,
            )
            .unwrap();
            assert_eq!(sighash.to_byte_array()[..], hex(expected)[..]);
        }
    }
}
