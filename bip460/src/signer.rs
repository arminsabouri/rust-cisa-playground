use bip459::{
    CollectingSignatures, Context, Coordinator as AggCoordinator, Message, Signer as AggSigner,
    Tweak, WithNonces, lift_x_bytes, parse_point, partial_sig_verify, serialize_point,
    serialize_signature, serialize_xonly,
};
use bitcoin::hashes::Hash;
use bitcoin::key::{TapTweak, UntweakedPublicKey};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::sighash::{Annex, Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{TapNodeHash, TapTweakHash};
use bitcoin::{Transaction, TxOut, Witness};
use k256::Scalar;
use k256::elliptic_curve::PrimeField;

use crate::{AggMode, WitnessElement, aggregated_sighash, witness_v2_program};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerError {
    InvalidSecretKey,
    InvalidInternalKey,
    InvalidTweak,
    InvalidPubNonce(usize),
    InvalidPartialSignature(usize),
    NotWitnessV2(usize),
    KeyMismatch(usize),
    Sighash(usize),
    DuplicateInput(usize),
    UnknownInput(usize),
    MissingPartialSignature(usize),
    EmptyGroup,
}

// The two public nonce points a signer publishes in the first round, SEC1
// compressed, as R1 || R2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PubNonce([u8; 66]);

impl PubNonce {
    pub fn from_bytes(bytes: [u8; 66]) -> Self {
        Self(bytes)
    }

    pub fn to_bytes(&self) -> [u8; 66] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartialSignature([u8; 32]);

impl PartialSignature {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

/// The taproot tweak and output key of a witness v2 output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaprootKey {
    pub tweak: [u8; 32],
    pub output_key: [u8; 32],
}

/// Derives the BIP 341 tweak and output key for an internal key, which is what
/// a witness v2 output commits to and what the signer must sign under.
pub fn taproot_key(
    internal_key: &[u8; 32],
    merkle_root: Option<TapNodeHash>,
) -> Result<TaprootKey, SignerError> {
    let internal =
        UntweakedPublicKey::from_slice(internal_key).map_err(|_| SignerError::InvalidInternalKey)?;
    let tweak = TapTweakHash::from_key_and_tweak(internal, merkle_root)
        .to_scalar()
        .to_be_bytes();
    let (output_key, _parity) = internal.tap_tweak(&Secp256k1::verification_only(), merkle_root);
    Ok(TaprootKey {
        tweak,
        output_key: output_key.serialize(),
    })
}

// One input's place in the signing session.
#[derive(Clone, Copy, Debug)]
pub struct SessionInput<'a> {
    pub index: usize,
    pub hash_type: TapSighashType,
    pub annex: Option<&'a [u8]>,
}

fn scalar(bytes: &[u8; 32]) -> Option<Scalar> {
    Option::from(Scalar::from_repr((*bytes).into()))
}

fn scalar_bytes(value: &Scalar) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&value.to_bytes());
    out
}

fn output_key(spent_outputs: &[TxOut], index: usize) -> Result<[u8; 32], SignerError> {
    let output = spent_outputs
        .get(index)
        .ok_or(SignerError::UnknownInput(index))?;
    witness_v2_program(&output.script_pubkey).ok_or(SignerError::NotWitnessV2(index))
}

fn message_for(
    transaction: &Transaction,
    spent_outputs: &[TxOut],
    input: SessionInput<'_>,
) -> Result<Message, SignerError> {
    let prevouts = Prevouts::All(spent_outputs);
    let mut cache = SighashCache::new(transaction);
    let annex = match input.annex {
        Some(bytes) => Some(Annex::new(bytes).map_err(|_| SignerError::Sighash(input.index))?),
        None => None,
    };
    Ok(aggregated_sighash(
        &mut cache,
        input.index,
        &prevouts,
        annex,
        input.hash_type,
        AggMode::Full,
    )
    .map_err(|_| SignerError::Sighash(input.index))?
    .to_byte_array())
}

// The session context the coordinator distributes after collecting every
// nonce. BIP 459 binds the signature to this whole list, so any change to the
// transaction or the membership invalidates it and needs fresh nonces.
#[derive(Clone, Debug)]
pub struct Session {
    indices: Vec<usize>,
    pubkeys: Vec<[u8; 32]>,
    messages: Vec<Message>,
    context: Context,
}

impl Session {
    pub fn indices(&self) -> &[usize] {
        &self.indices
    }
}

pub struct Participant {
    index: usize,
    pubkey: [u8; 32],
    message: Message,
    signer: AggSigner<WithNonces>,
}

impl Participant {
    // Generates this input's nonces and returns the public half to send to the
    // coordinator. The secret nonces live in the returned Participant and are
    // consumed by sign, so they cannot be reused.
    pub fn new(
        secret_key: &[u8; 32],
        tap_tweak: Option<&[u8; 32]>,
        input: SessionInput<'_>,
        transaction: &Transaction,
        spent_outputs: &[TxOut],
    ) -> Result<(Self, PubNonce), SignerError> {
        let private_key = scalar(secret_key).ok_or(SignerError::InvalidSecretKey)?;
        let tweak = match tap_tweak {
            Some(value) => Some(Tweak {
                value: scalar(value).ok_or(SignerError::InvalidTweak)?,
                is_xonly: true,
            }),
            None => None,
        };
        let signer = AggSigner::from_private_key(private_key, tweak).generate_nonces();

        let pubkey = output_key(spent_outputs, input.index)?;
        if serialize_xonly(&signer.public_key()) != pubkey {
            return Err(SignerError::KeyMismatch(input.index));
        }

        let message = message_for(transaction, spent_outputs, input)?;
        let (r1, r2) = signer.public_nonces();
        let mut pubnonce = [0u8; 66];
        pubnonce[..33].copy_from_slice(&serialize_point(&r1));
        pubnonce[33..].copy_from_slice(&serialize_point(&r2));

        Ok((
            Participant {
                index: input.index,
                pubkey,
                message,
                signer,
            },
            PubNonce(pubnonce),
        ))
    }

    pub fn index(&self) -> usize {
        self.index
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.pubkey
    }

    pub fn message(&self) -> Message {
        self.message
    }

    // Consumes the participant, so one nonce pair can only ever sign once.
    pub fn sign(self, session: &Session) -> Result<PartialSignature, SignerError> {
        let position = session
            .indices
            .iter()
            .position(|index| *index == self.index)
            .ok_or(SignerError::UnknownInput(self.index))?;
        if session.pubkeys[position] != self.pubkey || session.messages[position] != self.message {
            return Err(SignerError::KeyMismatch(self.index));
        }
        let partial = self
            .signer
            .with_context(session.context.clone())
            .sign(&self.message);
        Ok(PartialSignature(scalar_bytes(&partial)))
    }
}

struct Entry {
    index: usize,
    hash_type: TapSighashType,
    annex: Option<Vec<u8>>,
    pubkey: [u8; 32],
    message: Message,
    pubnonce: PubNonce,
    partial: Option<PartialSignature>,
}

// Collects the group's nonces, hands out the session, collects the partial
// signatures and assembles the signed transaction.
pub struct Coordinator<'a> {
    transaction: &'a Transaction,
    spent_outputs: &'a [TxOut],
    entries: Vec<Entry>,
}

fn nonce_points(
    pubnonce: &PubNonce,
    index: usize,
) -> Result<(k256::ProjectivePoint, k256::ProjectivePoint), SignerError> {
    let first: &[u8; 33] = pubnonce.0[..33].try_into().expect("fixed width");
    let second: &[u8; 33] = pubnonce.0[33..].try_into().expect("fixed width");
    let r1 = parse_point(first).ok_or(SignerError::InvalidPubNonce(index))?;
    let r2 = parse_point(second).ok_or(SignerError::InvalidPubNonce(index))?;
    Ok((r1, r2))
}

impl<'a> Coordinator<'a> {
    pub fn new(transaction: &'a Transaction, spent_outputs: &'a [TxOut]) -> Self {
        Coordinator {
            transaction,
            spent_outputs,
            entries: Vec::new(),
        }
    }

    // Entries are kept in input order, which is the order BIP 460 requires for
    // the group's public key and message lists.
    pub fn add_nonce(
        &mut self,
        input: SessionInput<'_>,
        pubnonce: PubNonce,
    ) -> Result<(), SignerError> {
        if self.entries.iter().any(|entry| entry.index == input.index) {
            return Err(SignerError::DuplicateInput(input.index));
        }
        nonce_points(&pubnonce, input.index)?;
        let pubkey = output_key(self.spent_outputs, input.index)?;
        let message = message_for(self.transaction, self.spent_outputs, input)?;

        self.entries.push(Entry {
            index: input.index,
            hash_type: input.hash_type,
            annex: input.annex.map(|bytes| bytes.to_vec()),
            pubkey,
            message,
            pubnonce,
            partial: None,
        });
        self.entries.sort_by_key(|entry| entry.index);
        Ok(())
    }

    fn aggregate(&self) -> Result<AggCoordinator<CollectingSignatures>, SignerError> {
        if self.entries.is_empty() {
            return Err(SignerError::EmptyGroup);
        }
        let mut coordinator = AggCoordinator::new();
        for entry in &self.entries {
            let pubkey =
                lift_x_bytes(&entry.pubkey).ok_or(SignerError::KeyMismatch(entry.index))?;
            let (r1, r2) = nonce_points(&entry.pubnonce, entry.index)?;
            coordinator.add_context_item((pubkey, entry.message, r1, r2));
        }
        Ok(coordinator.collect_nonces())
    }

    pub fn session(&self) -> Result<Session, SignerError> {
        let coordinator = self.aggregate()?;
        Ok(Session {
            indices: self.entries.iter().map(|entry| entry.index).collect(),
            pubkeys: self.entries.iter().map(|entry| entry.pubkey).collect(),
            messages: self.entries.iter().map(|entry| entry.message).collect(),
            context: coordinator.context(),
        })
    }

    // Rejects a share that does not verify, which identifies the disruptive
    // signer instead of leaving a failing aggregate.
    pub fn add_partial(
        &mut self,
        index: usize,
        partial: PartialSignature,
    ) -> Result<(), SignerError> {
        let session = self.session()?;
        let position = session
            .indices
            .iter()
            .position(|entry| *entry == index)
            .ok_or(SignerError::UnknownInput(index))?;
        let value =
            scalar(&partial.0).ok_or(SignerError::InvalidPartialSignature(index))?;
        if !partial_sig_verify(&session.context, value, position) {
            return Err(SignerError::InvalidPartialSignature(index));
        }
        self.entries[position].partial = Some(partial);
        Ok(())
    }

    pub fn finalize(&self) -> Result<Transaction, SignerError> {
        let mut coordinator = self.aggregate()?;
        for entry in &self.entries {
            let partial = entry
                .partial
                .ok_or(SignerError::MissingPartialSignature(entry.index))?;
            let value = scalar(&partial.0)
                .ok_or(SignerError::InvalidPartialSignature(entry.index))?;
            coordinator.add_signature(value);
        }
        let (s, group_nonce) = coordinator.collect_signatures();
        let signature = serialize_signature(&group_nonce, &s);

        let mut signed = self.transaction.clone();
        let last = self.entries.len() - 1;
        for (position, entry) in self.entries.iter().enumerate() {
            let element = if position == last {
                WitnessElement::Final {
                    mode: AggMode::Full,
                    data: &signature,
                    hash_type: entry.hash_type,
                }
            } else {
                WitnessElement::FullAggMember {
                    hash_type: entry.hash_type,
                }
            };
            let mut witness = Witness::new();
            witness.push(element.encode());
            if let Some(annex) = &entry.annex {
                witness.push(annex);
            }
            signed.input[entry.index].witness = witness;
        }
        Ok(signed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn};
    use k256::ProjectivePoint;

    fn output_for(secret: &[u8; 32]) -> TxOut {
        let key = serialize_xonly(&(ProjectivePoint::GENERATOR * scalar(secret).unwrap()));
        let mut script = vec![0x52, 0x20];
        script.extend_from_slice(&key);
        TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::from_bytes(script),
        }
    }

    #[test]
    fn two_signers_produce_a_verifiable_aggregate() {
        let keys = [[1u8; 32], [2u8; 32]];
        let spent: Vec<TxOut> = keys.iter().map(output_for).collect();
        let unsigned = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: (0..2)
                .map(|_| TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: vec![TxOut {
                value: Amount::from_sat(150_000),
                script_pubkey: spent[0].script_pubkey.clone(),
            }],
        };
        let inputs: Vec<SessionInput> = (0..2)
            .map(|index| SessionInput {
                index,
                hash_type: TapSighashType::Default,
                annex: None,
            })
            .collect();

        let mut coordinator = Coordinator::new(&unsigned, &spent);
        let mut participants = Vec::new();
        for (position, input) in inputs.iter().enumerate() {
            let (participant, pubnonce) =
                Participant::new(&keys[position], None, *input, &unsigned, &spent).unwrap();
            coordinator.add_nonce(*input, pubnonce).unwrap();
            participants.push(participant);
        }

        let session = coordinator.session().unwrap();
        for participant in participants {
            let index = participant.index();
            let partial = participant.sign(&session).unwrap();
            coordinator.add_partial(index, partial).unwrap();
        }
        let signed = coordinator.finalize().unwrap();

        let aggregate: [u8; 64] = signed.input[1].witness.nth(0).unwrap()[..64]
            .try_into()
            .unwrap();
        let pubkeys: Vec<[u8; 32]> = spent
            .iter()
            .map(|output| witness_v2_program(&output.script_pubkey).unwrap())
            .collect();
        let messages: Vec<Message> = inputs
            .iter()
            .map(|input| message_for(&unsigned, &spent, *input).unwrap())
            .collect();
        assert!(bip459::verify_serialized(&pubkeys, &messages, &aggregate));
    }
}
