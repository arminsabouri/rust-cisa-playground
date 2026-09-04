use std::borrow::Borrow;

use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::sighash::{
    Annex, Prevouts, SigningDataError, SighashCache, TapSighash, TapSighashType, TaprootError,
};
use bitcoin::{Transaction, TxOut, Witness};

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

pub const ANNEX_PREFIX: u8 = 0x50;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    EmptyWitness,
    NotKeyPath,
    UndefinedStructure(usize),
    ExplicitSighashDefault,
    UndefinedSighashType(u8),
}

// The valid witness element forms of BIP 460. A half-aggregation final carries
// its nonce share followed by the group's s value, a full-aggregation final
// carries the 64 byte aggregate signature, so both are 64 bytes of signature
// data and Pass 3 splits them according to the mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WitnessElement<'a> {
    OptedOut {
        signature: &'a [u8; 64],
        hash_type: TapSighashType,
    },
    HalfAggMember {
        nonce_share: &'a [u8; 32],
        hash_type: TapSighashType,
    },
    FullAggMember {
        hash_type: TapSighashType,
    },
    Final {
        mode: AggMode,
        data: &'a [u8; 64],
        hash_type: TapSighashType,
    },
}

impl WitnessElement<'_> {
    pub fn hash_type(&self) -> TapSighashType {
        match self {
            WitnessElement::OptedOut { hash_type, .. }
            | WitnessElement::HalfAggMember { hash_type, .. }
            | WitnessElement::FullAggMember { hash_type }
            | WitnessElement::Final { hash_type, .. } => *hash_type,
        }
    }

    pub fn mode(&self) -> Option<AggMode> {
        match self {
            WitnessElement::OptedOut { .. } => None,
            WitnessElement::HalfAggMember { .. } => Some(AggMode::Half),
            WitnessElement::FullAggMember { .. } => Some(AggMode::Full),
            WitnessElement::Final { mode, .. } => Some(*mode),
        }
    }
}

// SIGHASH_DEFAULT is only expressible by omitting the sighash byte, so that
// every signature message has exactly one witness encoding.
fn parse_hash_type(byte: Option<u8>) -> Result<TapSighashType, ParseError> {
    match byte {
        None => Ok(TapSighashType::Default),
        Some(0x00) => Err(ParseError::ExplicitSighashDefault),
        Some(byte) => match byte {
            0x01..=0x03 | 0x81..=0x83 => Ok(TapSighashType::from_consensus_u8(byte)
                .expect("checked against the valid sighash types")),
            _ => Err(ParseError::UndefinedSighashType(byte)),
        },
    }
}

fn array<const N: usize>(bytes: &[u8]) -> &[u8; N] {
    bytes.try_into().expect("length checked by the caller")
}

pub fn parse_witness_element(element: &[u8]) -> Result<WitnessElement<'_>, ParseError> {
    match element.len() {
        // A 64 byte element is always opted out, even when its last byte
        // happens to equal a marker value.
        64 => Ok(WitnessElement::OptedOut {
            signature: array(element),
            hash_type: TapSighashType::Default,
        }),
        // Only 65 and 66 byte elements are interpreted against the marker.
        65 => match AggMode::from_byte(element[64]) {
            None => Ok(WitnessElement::OptedOut {
                signature: array(&element[..64]),
                hash_type: parse_hash_type(Some(element[64]))?,
            }),
            Some(mode) => Ok(WitnessElement::Final {
                mode,
                data: array(&element[..64]),
                hash_type: TapSighashType::Default,
            }),
        },
        66 => {
            let mode = AggMode::from_byte(element[65]).ok_or(ParseError::UndefinedStructure(66))?;
            Ok(WitnessElement::Final {
                mode,
                data: array(&element[..64]),
                hash_type: parse_hash_type(Some(element[64]))?,
            })
        }
        0 => Ok(WitnessElement::FullAggMember {
            hash_type: TapSighashType::Default,
        }),
        // In the 1 and 33 byte forms the last byte is a sighash byte, so an
        // element of those lengths ending in a marker value is a member with an
        // invalid sighash type.
        1 => Ok(WitnessElement::FullAggMember {
            hash_type: parse_hash_type(Some(element[0]))?,
        }),
        32 => Ok(WitnessElement::HalfAggMember {
            nonce_share: array(element),
            hash_type: TapSighashType::Default,
        }),
        33 => Ok(WitnessElement::HalfAggMember {
            nonce_share: array(&element[..32]),
            hash_type: parse_hash_type(Some(element[32]))?,
        }),
        length => Err(ParseError::UndefinedStructure(length)),
    }
}

pub fn split_annex(witness: &Witness) -> Result<(&[u8], Option<&[u8]>), ParseError> {
    let length = witness.len();
    if length == 0 {
        return Err(ParseError::EmptyWitness);
    }
    let last = witness.last().expect("witness is not empty");
    // A single element is never an annex.
    let (spend_length, annex) = if length >= 2 && last.first() == Some(&ANNEX_PREFIX) {
        (length - 1, Some(last))
    } else {
        (length, None)
    };
    if spend_length != 1 {
        return Err(ParseError::NotKeyPath);
    }
    Ok((witness.nth(0).expect("witness is not empty"), annex))
}

pub fn parse_key_path_witness(
    witness: &Witness,
) -> Result<(WitnessElement<'_>, Option<&[u8]>), ParseError> {
    let (element, annex) = split_annex(witness)?;
    Ok((parse_witness_element(element)?, annex))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupError {
    MembersWithoutFinal(AggMode),
    MultipleFinals(AggMode),
    MemberAfterFinal(AggMode),
}

// The inputs of one aggregation group in input order, with the input carrying
// the group's marker last. A group may consist of its final input alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregationGroup {
    pub mode: AggMode,
    pub inputs: Vec<usize>,
}

// Takes the parsed witness v2 key path spends of a transaction, indexed by
// input index, with None for inputs validated under their own rules. A
// transaction carries at most one group per mode, so opted-out inputs, script
// path spends and other output types can be mixed in freely.
pub fn aggregation_groups(
    inputs: &[Option<WitnessElement<'_>>],
) -> Result<Vec<AggregationGroup>, GroupError> {
    let mut groups = Vec::new();
    for mode in [AggMode::Half, AggMode::Full] {
        let mut members = Vec::new();
        let mut final_input = None;

        for (index, element) in inputs.iter().enumerate() {
            let Some(element) = element else { continue };
            if element.mode() != Some(mode) {
                continue;
            }
            match element {
                WitnessElement::Final { .. } => {
                    if final_input.is_some() {
                        return Err(GroupError::MultipleFinals(mode));
                    }
                    final_input = Some(index);
                }
                _ => {
                    if final_input.is_some() {
                        return Err(GroupError::MemberAfterFinal(mode));
                    }
                    members.push(index);
                }
            }
        }

        match final_input {
            Some(index) => {
                members.push(index);
                groups.push(AggregationGroup {
                    mode,
                    inputs: members,
                });
            }
            None if !members.is_empty() => return Err(GroupError::MembersWithoutFinal(mode)),
            None => {}
        }
    }
    Ok(groups)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::deserialize;
    use bitcoin::{Amount, ScriptBuf};
    use bitcoin::Witness;

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

    fn bytes(length: usize, last: Option<u8>) -> Vec<u8> {
        let mut out = vec![0x11u8; length];
        if let Some(byte) = last {
            *out.last_mut().expect("non-empty") = byte;
        }
        out
    }

    #[test]
    fn opted_out_forms() {
        let sig = bytes(64, None);
        assert_eq!(
            parse_witness_element(&sig).unwrap(),
            WitnessElement::OptedOut {
                signature: array(&sig),
                hash_type: TapSighashType::Default
            }
        );

        let explicit = bytes(65, Some(0x83));
        assert_eq!(
            parse_witness_element(&explicit).unwrap(),
            WitnessElement::OptedOut {
                signature: array(&explicit[..64]),
                hash_type: TapSighashType::SinglePlusAnyoneCanPay
            }
        );

        // A 64 byte element is opted out even when its last byte is a marker.
        let lookalike = bytes(64, Some(HALF_AGG_MARKER));
        assert_eq!(
            parse_witness_element(&lookalike).unwrap().mode(),
            None
        );
    }

    #[test]
    fn member_forms() {
        assert_eq!(
            parse_witness_element(&bytes(0, None)).unwrap(),
            WitnessElement::FullAggMember {
                hash_type: TapSighashType::Default
            }
        );
        assert_eq!(
            parse_witness_element(&bytes(1, Some(0x01))).unwrap(),
            WitnessElement::FullAggMember {
                hash_type: TapSighashType::All
            }
        );

        let share = bytes(32, None);
        assert_eq!(
            parse_witness_element(&share).unwrap(),
            WitnessElement::HalfAggMember {
                nonce_share: array(&share),
                hash_type: TapSighashType::Default
            }
        );

        let with_sighash = bytes(33, Some(0x03));
        assert_eq!(
            parse_witness_element(&with_sighash).unwrap(),
            WitnessElement::HalfAggMember {
                nonce_share: array(&with_sighash[..32]),
                hash_type: TapSighashType::Single
            }
        );
    }

    #[test]
    fn final_forms() {
        for (marker, mode) in [(HALF_AGG_MARKER, AggMode::Half), (FULL_AGG_MARKER, AggMode::Full)] {
            let default = bytes(65, Some(marker));
            assert_eq!(
                parse_witness_element(&default).unwrap(),
                WitnessElement::Final {
                    mode,
                    data: array(&default[..64]),
                    hash_type: TapSighashType::Default
                }
            );

            let mut explicit = bytes(66, Some(marker));
            explicit[64] = 0x02;
            assert_eq!(
                parse_witness_element(&explicit).unwrap(),
                WitnessElement::Final {
                    mode,
                    data: array(&explicit[..64]),
                    hash_type: TapSighashType::None
                }
            );
        }
    }

    #[test]
    fn rejected_forms() {
        let mut explicit_default_final = bytes(66, Some(HALF_AGG_MARKER));
        explicit_default_final[64] = 0x00;

        for (element, expected) in [
            // 65 bytes not ending in a marker is an opted-out signature, so an
            // undefined marker value is read as an undefined sighash byte.
            (bytes(65, Some(0xbb)), ParseError::UndefinedSighashType(0xbb)),
            (bytes(65, Some(0x04)), ParseError::UndefinedSighashType(0x04)),
            // The last byte of the 1 and 33 byte forms is a sighash byte.
            (bytes(1, Some(HALF_AGG_MARKER)), ParseError::UndefinedSighashType(HALF_AGG_MARKER)),
            (bytes(33, Some(HALF_AGG_MARKER)), ParseError::UndefinedSighashType(HALF_AGG_MARKER)),
            // SIGHASH_DEFAULT is only expressible by omitting the byte.
            (bytes(65, Some(0x00)), ParseError::ExplicitSighashDefault),
            (bytes(1, Some(0x00)), ParseError::ExplicitSighashDefault),
            (bytes(33, Some(0x00)), ParseError::ExplicitSighashDefault),
            (explicit_default_final, ParseError::ExplicitSighashDefault),
            // Lengths and marker combinations that match no row of the table.
            (bytes(2, Some(HALF_AGG_MARKER)), ParseError::UndefinedStructure(2)),
            (bytes(66, Some(0x01)), ParseError::UndefinedStructure(66)),
            (bytes(97, Some(HALF_AGG_MARKER)), ParseError::UndefinedStructure(97)),
            (bytes(67, Some(FULL_AGG_MARKER)), ParseError::UndefinedStructure(67)),
        ] {
            let length = element.len();
            assert_eq!(
                parse_witness_element(&element).unwrap_err(),
                expected,
                "element of length {}",
                length
            );
        }
    }

    #[test]
    fn annex_handling() {
        let annex = vec![ANNEX_PREFIX, 0x01, 0x02];

        let with_annex = Witness::from_slice(&[bytes(64, None), annex.clone()]);
        let (element, found) = parse_key_path_witness(&with_annex).unwrap();
        assert_eq!(element.mode(), None);
        assert_eq!(found, Some(&annex[..]));

        let without_annex = Witness::from_slice(&[bytes(32, None)]);
        let (element, found) = parse_key_path_witness(&without_annex).unwrap();
        assert_eq!(element.mode(), Some(AggMode::Half));
        assert_eq!(found, None);

        assert_eq!(
            parse_key_path_witness(&Witness::default()).unwrap_err(),
            ParseError::EmptyWitness
        );

        // A single element is never an annex, so this is parsed as a spend.
        let lone_annex = Witness::from_slice(&[annex.clone()]);
        assert_eq!(
            parse_key_path_witness(&lone_annex).unwrap_err(),
            ParseError::UndefinedStructure(3)
        );

        // Two non-annex elements make this a script path spend.
        let script_path = Witness::from_slice(&[bytes(64, None), bytes(34, None)]);
        assert_eq!(
            parse_key_path_witness(&script_path).unwrap_err(),
            ParseError::NotKeyPath
        );
    }

    fn opted_out() -> WitnessElement<'static> {
        WitnessElement::OptedOut {
            signature: &[0; 64],
            hash_type: TapSighashType::Default,
        }
    }

    fn member(mode: AggMode) -> WitnessElement<'static> {
        match mode {
            AggMode::Half => WitnessElement::HalfAggMember {
                nonce_share: &[0; 32],
                hash_type: TapSighashType::Default,
            },
            AggMode::Full => WitnessElement::FullAggMember {
                hash_type: TapSighashType::Default,
            },
        }
    }

    fn group_final(mode: AggMode) -> WitnessElement<'static> {
        WitnessElement::Final {
            mode,
            data: &[0; 64],
            hash_type: TapSighashType::Default,
        }
    }

    #[test]
    fn mixed_transaction_groups() {
        // Example 4 of the BIP: two opted-out inputs, a half-aggregation group
        // and a full-aggregation group, with a non witness v2 input mixed in.
        let inputs = [
            Some(opted_out()),
            Some(member(AggMode::Half)),
            Some(member(AggMode::Full)),
            None,
            Some(member(AggMode::Full)),
            Some(group_final(AggMode::Half)),
            Some(opted_out()),
            Some(group_final(AggMode::Full)),
        ];
        assert_eq!(
            aggregation_groups(&inputs).unwrap(),
            vec![
                AggregationGroup {
                    mode: AggMode::Half,
                    inputs: vec![1, 5]
                },
                AggregationGroup {
                    mode: AggMode::Full,
                    inputs: vec![2, 4, 7]
                },
            ]
        );
    }

    #[test]
    fn a_group_may_be_its_final_input_alone() {
        for mode in [AggMode::Half, AggMode::Full] {
            let inputs = [Some(opted_out()), Some(group_final(mode))];
            assert_eq!(
                aggregation_groups(&inputs).unwrap(),
                vec![AggregationGroup {
                    mode,
                    inputs: vec![1]
                }]
            );
        }
    }

    #[test]
    fn opted_out_inputs_do_not_form_groups() {
        let inputs = [Some(opted_out()), None, Some(opted_out())];
        assert!(aggregation_groups(&inputs).unwrap().is_empty());
    }

    #[test]
    fn rejected_group_structures() {
        for mode in [AggMode::Half, AggMode::Full] {
            assert_eq!(
                aggregation_groups(&[Some(member(mode)), Some(member(mode))]).unwrap_err(),
                GroupError::MembersWithoutFinal(mode)
            );
            assert_eq!(
                aggregation_groups(&[Some(group_final(mode)), Some(member(mode))]).unwrap_err(),
                GroupError::MemberAfterFinal(mode)
            );
            assert_eq!(
                aggregation_groups(&[Some(group_final(mode)), Some(group_final(mode))]).unwrap_err(),
                GroupError::MultipleFinals(mode)
            );
        }
    }

    #[test]
    fn the_two_groups_are_independent() {
        // A complete half-aggregation group does not rescue full-aggregation
        // members that have no final input of their own.
        let inputs = [
            Some(member(AggMode::Half)),
            Some(group_final(AggMode::Half)),
            Some(member(AggMode::Full)),
        ];
        assert_eq!(
            aggregation_groups(&inputs).unwrap_err(),
            GroupError::MembersWithoutFinal(AggMode::Full)
        );
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
