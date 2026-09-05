mod signer;
pub use signer::*;

use std::borrow::Borrow;

use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::sighash::{
    Annex, Prevouts, SigningDataError, SighashCache, TapSighash, TapSighashType, TaprootError,
};
use bitcoin::{Script, Transaction, TxOut};

pub use bip459::Message;

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

// The sighash of an aggregated input commits to its aggregation mode:
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

// The witness element forms of BIP 460. A half-aggregation final carries its
// nonce share followed by the group's s value, a full-aggregation final carries
// the 64 byte aggregate signature, so both are 64 bytes of signature data.
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

// SIGHASH_DEFAULT is only expressible by omitting the byte, so every signature
// message has exactly one witness encoding.
fn push_hash_type(out: &mut Vec<u8>, hash_type: TapSighashType) {
    if hash_type != TapSighashType::Default {
        out.push(hash_type as u8);
    }
}

impl WitnessElement<'_> {
    // The single witness stack element this spend contributes, without the annex.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            WitnessElement::OptedOut {
                signature,
                hash_type,
            } => {
                out.extend_from_slice(*signature);
                push_hash_type(&mut out, *hash_type);
            }
            WitnessElement::HalfAggMember {
                nonce_share,
                hash_type,
            } => {
                out.extend_from_slice(*nonce_share);
                push_hash_type(&mut out, *hash_type);
            }
            WitnessElement::FullAggMember { hash_type } => {
                push_hash_type(&mut out, *hash_type);
            }
            WitnessElement::Final {
                mode,
                data,
                hash_type,
            } => {
                out.extend_from_slice(*data);
                push_hash_type(&mut out, *hash_type);
                out.push(mode.as_byte());
            }
        }
        out
    }
}

// Witness version 2 outputs have a scriptPubKey of OP_2 <32-byte program>.
pub const WITNESS_V2_PREFIX: [u8; 2] = [0x52, 0x20];

pub fn witness_v2_program(script_pubkey: &Script) -> Option<[u8; 32]> {
    let bytes = script_pubkey.as_bytes();
    if bytes.len() != 34 || bytes[..2] != WITNESS_V2_PREFIX {
        return None;
    }
    Some(bytes[2..].try_into().expect("length checked above"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip459::{Coordinator as AggCoordinator, Signer, Tweak, serialize_signature};
    use bitcoin::consensus::{deserialize, serialize};
    use k256::Scalar;
    use k256::elliptic_curve::PrimeField;
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

    const FULL_AGG_SIGNED_TX: &str = "0200000000010254d36a0897340110cc34b526d73b206175ae4f5db4d25fe7bdeef3a8a5e89afd0100000000ffffffff835a02826d69e61b563ec713020bd2b7c3bc3848223cda2b3c52bbdcd3e6267a0100000000ffffffff01c0cb1707000000002252208640c68f13b51a1e63dfc5cc41202cca21c18f1f9d7037c2cbec3f03f63e52e40101010142f00c224cc4e1bb038b1f35d71c28608510236327924d350d75520eb6295eb1908a38b68c0a7b484bc4ac7330ae2f5e909bf25b53fa60131f7d6799d5017311d801bd00000000";

    fn full_agg_spent_outputs() -> Vec<TxOut> {
        spent_outputs(&[
            ("52208640c68f13b51a1e63dfc5cc41202cca21c18f1f9d7037c2cbec3f03f63e52e4", 50000000),
            ("522018b6491469cc78b764b01669b0a5a4e892f57e8c1b20b89bc1ca6dce3e881b51", 70000000),
        ])
    }

    const VECTOR_FULL_AGG_MEMBER: &str = "01";
    const VECTOR_FULL_AGG_FINAL: &str = "f00c224cc4e1bb038b1f35d71c28608510236327924d350d75520eb6295eb1908a38b68c0a7b484bc4ac7330ae2f5e909bf25b53fa60131f7d6799d5017311d801bd";
    const VECTOR_OPTED_OUT: &str = "86a207d61052859ed25d045739ff69f6c94e246c7e95c0bd2dbf951cb75f0ee55e890397180835f8d5aeb8eabef4c9e234b13aa87fe38c96f25001f3b1a0631d01";

    #[test]
    fn encoding_has_the_fixed_lengths_of_the_table() {
        let signature = [7u8; 64];
        let share = [9u8; 32];
        let elements = [
            WitnessElement::OptedOut { signature: &signature, hash_type: TapSighashType::Default },
            WitnessElement::OptedOut { signature: &signature, hash_type: TapSighashType::All },
            WitnessElement::FullAggMember { hash_type: TapSighashType::Default },
            WitnessElement::FullAggMember { hash_type: TapSighashType::All },
            WitnessElement::HalfAggMember { nonce_share: &share, hash_type: TapSighashType::Default },
            WitnessElement::HalfAggMember { nonce_share: &share, hash_type: TapSighashType::Single },
            WitnessElement::Final { mode: AggMode::Half, data: &signature, hash_type: TapSighashType::Default },
            WitnessElement::Final { mode: AggMode::Half, data: &signature, hash_type: TapSighashType::All },
            WitnessElement::Final { mode: AggMode::Full, data: &signature, hash_type: TapSighashType::Default },
            WitnessElement::Final { mode: AggMode::Full, data: &signature, hash_type: TapSighashType::AllPlusAnyoneCanPay },
        ];
        // The fixed lengths of the ten rows of the BIP's structure table.
        let lengths = [64, 65, 0, 1, 32, 33, 65, 66, 65, 66];

        for (element, length) in elements.iter().zip(lengths) {
            let encoded = element.encode();
            assert_eq!(encoded.len(), length, "{:?}", element);
            if let WitnessElement::Final { mode, .. } = element {
                assert_eq!(*encoded.last().unwrap(), mode.as_byte());
            }
        }
    }

    #[test]
    fn encoding_matches_the_vector_witnesses() {
        assert_eq!(
            WitnessElement::FullAggMember {
                hash_type: TapSighashType::All
            }
            .encode(),
            hex(VECTOR_FULL_AGG_MEMBER)
        );

        let expected = hex(VECTOR_FULL_AGG_FINAL);
        let signature: [u8; 64] = expected[..64].try_into().unwrap();
        assert_eq!(
            WitnessElement::Final {
                mode: AggMode::Full,
                data: &signature,
                hash_type: TapSighashType::All
            }
            .encode(),
            expected
        );

        let expected = hex(VECTOR_OPTED_OUT);
        let signature: [u8; 64] = expected[..64].try_into().unwrap();
        assert_eq!(
            WitnessElement::OptedOut {
                signature: &signature,
                hash_type: TapSighashType::All
            }
            .encode(),
            expected
        );
    }

    const FULL_AGG_UNSIGNED_TX: &str = "020000000254d36a0897340110cc34b526d73b206175ae4f5db4d25fe7bdeef3a8a5e89afd0100000000ffffffff835a02826d69e61b563ec713020bd2b7c3bc3848223cda2b3c52bbdcd3e6267a0100000000ffffffff01c0cb1707000000002252208640c68f13b51a1e63dfc5cc41202cca21c18f1f9d7037c2cbec3f03f63e52e400000000";
    const INTERNAL_PRIVKEYS: [&str; 2] = [
        "edc07892ebcc0812db6aea0fbc967eed825fedecf70db83d4c69fbe574b97361",
        "80f4d8f499868a546ca66497352d4df0aa1c7e99cd83faeba3eeb11ecafec708",
    ];
    const TAP_TWEAKS: [&str; 2] = [
        "22b1442d7532c6cdbe4d9854a90b8f7a5820c559af2ca6f7d375e6fc3bfd8a09",
        "85fb96a1a8a6c3a93ebfaf308aecc9837eceb6cfda6eb735cf8586e989a87563",
    ];
    const TWEAKED_PRIVKEYS: [&str; 2] = [
        "1071bcc060fecee099b8826465a20e691fd1d65ff6f1bef9600d8454e080bc29",
        "0506bdad0f203954d2194a9955bf7b92d4b238360ceabc4a2b96d5cabea9ae5b",
    ];
    const SECNONCES: [&str; 2] = [
        "87c33dcedc7db5994d68278a81a4693ee961d08ef7e3fdeab611ab8061e92dd4517ac39af981926ed1124224dfe721c6dc0769a8ea24d2e2fc2636c3b1e9ca15",
        "3c4b7832dd37bbdb955ebf900769d133d55161e5c6ad9e09c2efa4ace1ba2e153d007745e9f74e6b8a47651a672111b07589261401674263a40e286340bcefea",
    ];

    fn scalar(value: &str) -> Scalar {
        let bytes: [u8; 32] = hex(value).try_into().unwrap();
        Scalar::from_repr(bytes.into()).unwrap()
    }

    fn secnonce(value: &str) -> (Scalar, Scalar) {
        (scalar(&value[..64]), scalar(&value[64..]))
    }

    // Drives a BIP 459 signing session to the serialized 64 byte aggregate.
    fn sign_full_agg(
        keys: &[(Scalar, Option<Tweak>)],
        nonces: &[(Scalar, Scalar)],
        messages: &[Message],
    ) -> [u8; 64] {
        let signers: Vec<_> = keys
            .iter()
            .zip(nonces)
            .map(|((private_key, tweak), (r1, r2))| {
                Signer::from_private_key(*private_key, *tweak).with_nonces(*r1, *r2)
            })
            .collect();

        let mut coordinator = AggCoordinator::new();
        for (index, signer) in signers.iter().enumerate() {
            coordinator.add_context_item(signer.context_item(messages[index]));
        }
        let mut coordinator = coordinator.collect_nonces();
        for (index, signer) in signers.into_iter().enumerate() {
            let partial = signer.with_context(coordinator.context()).sign(&messages[index]);
            coordinator.add_signature(partial);
        }
        let (s, group_nonce) = coordinator.collect_signatures();
        serialize_signature(&group_nonce, &s)
    }

    fn full_agg_messages(transaction: &Transaction, spent: &[TxOut]) -> Vec<Message> {
        let prevouts = Prevouts::All(spent);
        let mut cache = SighashCache::new(transaction);
        (0..2)
            .map(|index| {
                aggregated_sighash(
                    &mut cache,
                    index,
                    &prevouts,
                    None,
                    TapSighashType::All,
                    AggMode::Full,
                )
                .unwrap()
                .to_byte_array()
            })
            .collect()
    }

    #[test]
    fn signing_reproduces_the_vector_transaction() {
        let unsigned: Transaction = deserialize(&hex(FULL_AGG_UNSIGNED_TX)).unwrap();
        let spent = full_agg_spent_outputs();
        let messages = full_agg_messages(&unsigned, &spent);
        let nonces: Vec<(Scalar, Scalar)> = SECNONCES.iter().map(|n| secnonce(n)).collect();

        let tweaked: Vec<(Scalar, Option<Tweak>)> = TWEAKED_PRIVKEYS
            .iter()
            .map(|key| (scalar(key), None))
            .collect();
        let signature = sign_full_agg(&tweaked, &nonces, &messages);

        // The same signature must come out of the untweaked keys carrying their
        // taproot tweaks, which is what BIP 459 key tweaking is for.
        let internal: Vec<(Scalar, Option<Tweak>)> = INTERNAL_PRIVKEYS
            .iter()
            .zip(TAP_TWEAKS)
            .map(|(key, tweak)| {
                (
                    scalar(key),
                    Some(Tweak {
                        value: scalar(tweak),
                        is_xonly: true,
                    }),
                )
            })
            .collect();
        assert_eq!(sign_full_agg(&internal, &nonces, &messages), signature);

        let mut signed = unsigned.clone();
        signed.input[0].witness = Witness::from_slice(&[WitnessElement::FullAggMember {
            hash_type: TapSighashType::All,
        }
        .encode()]);
        signed.input[1].witness = Witness::from_slice(&[WitnessElement::Final {
            mode: AggMode::Full,
            data: &signature,
            hash_type: TapSighashType::All,
        }
        .encode()]);

        assert_eq!(serialize(&signed), hex(FULL_AGG_SIGNED_TX));
    }

    fn vector_session() -> (Transaction, Vec<TxOut>, Vec<SessionInput<'static>>) {
        let unsigned: Transaction = deserialize(&hex(FULL_AGG_UNSIGNED_TX)).unwrap();
        let inputs = (0..2)
            .map(|index| SessionInput {
                index,
                hash_type: TapSighashType::All,
                annex: None,
            })
            .collect();
        (unsigned, full_agg_spent_outputs(), inputs)
    }

    fn key(value: &str) -> [u8; 32] {
        hex(value).try_into().unwrap()
    }

    #[test]
    fn multi_party_session_produces_the_vector_transaction() {
        let (unsigned, spent, inputs) = vector_session();
        let mut coordinator = Coordinator::new(&unsigned, &spent);
        let mut participants = Vec::new();

        // Round 1: every participant publishes its public nonce.
        for (position, input) in inputs.iter().enumerate() {
            let (participant, pubnonce) = Participant::new(
                &key(INTERNAL_PRIVKEYS[position]),
                Some(&key(TAP_TWEAKS[position])),
                *input,
                &unsigned,
                &spent,
            )
            .unwrap();
            coordinator.add_nonce(*input, pubnonce).unwrap();
            participants.push(participant);
        }

        // Round 2: the coordinator publishes the session, each participant signs.
        let session = coordinator.session().unwrap();
        assert_eq!(session.indices(), [0, 1]);
        for participant in participants {
            let index = participant.index();
            let partial = participant.sign(&session).unwrap();
            coordinator.add_partial(index, partial).unwrap();
        }

        let signed = coordinator.finalize().unwrap();

        // The aggregate we produced verifies against the group's keys and messages.
        let element = signed.input[1].witness.nth(0).unwrap();
        let aggregate: [u8; 64] = element[..64].try_into().unwrap();
        let pubkeys: Vec<[u8; 32]> = spent
            .iter()
            .map(|output| witness_v2_program(&output.script_pubkey).unwrap())
            .collect();
        assert!(bip459::verify_serialized(
            &pubkeys,
            &full_agg_messages(&unsigned, &spent),
            &aggregate
        ));

        // Nonces are fresh, so the aggregate differs from the vector's. Swapping
        // the vector's signature back in must reproduce its transaction exactly.
        let signature: [u8; 64] = hex(VECTOR_FULL_AGG_FINAL)[..64].try_into().unwrap();
        let mut rebuilt = signed.clone();
        rebuilt.input[1].witness = Witness::from_slice(&[WitnessElement::Final {
            mode: AggMode::Full,
            data: &signature,
            hash_type: TapSighashType::All,
        }
        .encode()]);
        assert_eq!(serialize(&rebuilt), hex(FULL_AGG_SIGNED_TX));
    }

    #[test]
    fn a_key_that_does_not_match_the_output_is_refused() {
        let (unsigned, spent, inputs) = vector_session();
        // The right key for the wrong input.
        let error = Participant::new(
            &key(INTERNAL_PRIVKEYS[0]),
            Some(&key(TAP_TWEAKS[0])),
            inputs[1],
            &unsigned,
            &spent,
        )
        .map(|_| ())
        .unwrap_err();
        assert_eq!(error, SignerError::KeyMismatch(1));
    }

    #[test]
    fn a_bad_partial_signature_is_attributed_to_its_signer() {
        let (unsigned, spent, inputs) = vector_session();
        let mut coordinator = Coordinator::new(&unsigned, &spent);
        let mut participants = Vec::new();
        for (position, input) in inputs.iter().enumerate() {
            let (participant, pubnonce) = Participant::new(
                &key(TWEAKED_PRIVKEYS[position]),
                None,
                *input,
                &unsigned,
                &spent,
            )
            .unwrap();
            coordinator.add_nonce(*input, pubnonce).unwrap();
            participants.push(participant);
        }
        let session = coordinator.session().unwrap();

        let mut partials: Vec<_> = participants
            .into_iter()
            .map(|participant| (participant.index(), participant.sign(&session).unwrap()))
            .collect();
        let mut tampered = partials[1].1.to_bytes();
        tampered[31] ^= 1;
        partials[1].1 = PartialSignature::from_bytes(tampered);

        assert_eq!(
            coordinator.add_partial(partials[0].0, partials[0].1),
            Ok(())
        );
        assert_eq!(
            coordinator.add_partial(partials[1].0, partials[1].1),
            Err(SignerError::InvalidPartialSignature(1))
        );
        assert_eq!(
            coordinator.finalize().unwrap_err(),
            SignerError::MissingPartialSignature(1)
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
