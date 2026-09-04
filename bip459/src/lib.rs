use std::ops::Deref;

use k256::{
    ProjectivePoint, Scalar, U256,
    elliptic_curve::{Field, ops::Reduce, rand_core::{OsRng, RngCore}},
    sha2::Digest,
};

use k256::EncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::sha2::Sha256;

const TAG_AUX: &[u8] = b"FullAgg/aux";
const TAG_NONCE: &[u8] = b"FullAgg/nonce";
const TAG_NONCECOEF: &[u8] = b"FullAgg/noncecoef";
const TAG_SIG: &[u8] = b"FullAgg/sig";

fn has_even_y(point: &ProjectivePoint) -> bool {
    !bool::from(point.to_affine().y_is_odd())
}

fn lift_x(point: &ProjectivePoint) -> ProjectivePoint {
    if has_even_y(point) { *point } else { -*point }
}

fn cbytes(point: &ProjectivePoint) -> [u8; 33] {
    let mut out = [0u8; 33];
    out[0] = if has_even_y(point) { 0x02 } else { 0x03 };
    out[1..].copy_from_slice(&point.to_affine().x());
    out
}

fn tagged_hasher(tag: &[u8]) -> Sha256 {
    let tag_hash = Sha256::digest(tag);
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher
}

/// Private and public nonces for a signer
pub type NoncePair = (Scalar, ProjectivePoint);
pub type Message = [u8; 32];
/// Individual signer's public key, message, and individual R1, R2
pub type ContextItem = (PublicKey, Message, ProjectivePoint, ProjectivePoint);
/// Signer list is a list of public keys and messages
pub type SignerList = Vec<(PublicKey, Message)>;
/// Public key is a group element
pub type PublicKey = ProjectivePoint;

#[derive(Clone, Copy)]
pub struct Tweak {
    pub value: Scalar,
    pub is_xonly: bool,
}

#[derive(Clone)]
pub struct SignerKey {
    private_key: Scalar,
    tweak: Option<Tweak>,
}

impl SignerKey {
    pub fn new_random(tweak: Option<Tweak>) -> SignerKey {
        let private_key = Scalar::random(&mut OsRng);
        SignerKey { private_key, tweak }
    }

    pub fn public_key(&self) -> ProjectivePoint {
        ProjectivePoint::GENERATOR * self.private_key()
    }

    pub fn private_key(&self) -> Scalar {
        if let Some(tweak) = self.tweak {
            let untweaked = ProjectivePoint::GENERATOR * self.private_key;
            let d = if !tweak.is_xonly || has_even_y(&untweaked) {
                self.private_key
            } else {
                -self.private_key
            };
            d + tweak.value
        } else {
            self.private_key
        }
    }
}

pub struct Signer<SignerState> {
    state: SignerState,
}

impl<SignerState> Deref for Signer<SignerState> {
    type Target = SignerState;
    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

pub struct Coordinator<CoordinatorState> {
    state: CoordinatorState,
}

impl<CoordinatorState> Deref for Coordinator<CoordinatorState> {
    type Target = CoordinatorState;
    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

pub struct CollectingNonces {
    context: Vec<ContextItem>,
}

impl Coordinator<CollectingNonces> {
    pub fn new() -> Coordinator<CollectingNonces> {
        Coordinator {
            state: CollectingNonces {
                context: Vec::new(),
            },
        }
    }

    pub fn add_context_item(&mut self, context_item: ContextItem) {
        self.state.context.push(context_item);
    }

    /// Returns the context and the group nonce
    pub fn collect_nonces(&self) -> Coordinator<CollectingSignatures> {
        let group_nonce_r1 = self
            .context
            .iter()
            .map(|item| item.2)
            .sum::<ProjectivePoint>();
        let group_nonce_r2 = self
            .context
            .iter()
            .map(|item| item.3)
            .sum::<ProjectivePoint>();
        assert!(group_nonce_r1 != ProjectivePoint::IDENTITY);
        assert!(group_nonce_r2 != ProjectivePoint::IDENTITY);
        let context = Context {
            context: self.context.clone(),
            group_nonce_r1,
            group_nonce_r2,
        };
        Coordinator {
            state: CollectingSignatures {
                context,
                signatures: Vec::new(),
            },
        }
    }
}

pub struct CollectingSignatures {
    context: Context,
    signatures: Vec<Scalar>,
}

impl Coordinator<CollectingSignatures> {
    pub fn context(&self) -> Context {
        self.state.context.clone()
    }

    pub fn add_signature(&mut self, signature: Scalar) {
        let index = self.state.signatures.len();
        assert!(partial_sig_verify(&self.state.context, signature, index));
        self.state.signatures.push(signature);
    }

    /// Coordinator collects the signatures and computes the group signature and group nonce
    pub fn collect_signatures(&self) -> (Scalar, ProjectivePoint) {
        let signature = self.state.signatures.iter().sum::<Scalar>();
        let group_nonce = self.state.context.group_nonce();
        (signature, group_nonce)
    }
}

pub struct Init;
impl Signer<Init> {
    /// Signer generates their private and public key
    pub fn new_keypair(tweak: Option<Tweak>) -> Signer<WithKeypair> {
        let signer_key = SignerKey::new_random(tweak);
        Signer {
            state: WithKeypair { signer_key },
        }
    }

        pub fn from_private_key(private_key: Scalar, tweak: Option<Tweak>) -> Signer<WithKeypair> {
        Signer {
            state: WithKeypair {
                signer_key: SignerKey { private_key, tweak },
            },
        }
    }
}

pub struct WithKeypair {
    signer_key: SignerKey,
}

fn nonce_gen(sk: Scalar) -> (Scalar, Scalar) {
    let mut rand_prime = [0u8; 32];
    OsRng.fill_bytes(&mut rand_prime);
    let mut hasher = tagged_hasher(TAG_AUX);
    hasher.update(rand_prime);
    let aux = hasher.finalize();
    let sk_bytes = sk.to_bytes();
    let mut rand = [0u8; 32];
    for i in 0..32 {
        rand[i] = sk_bytes[i] ^ aux[i];
    }
    let nonce = |counter: u8| {
        let mut hasher = tagged_hasher(TAG_NONCE);
        hasher.update(rand);
        hasher.update([counter]);
        hasher_to_scalar(hasher)
    };
    let r1 = nonce(0);
    let r2 = nonce(1);
    assert!(r1 != Scalar::ZERO && r2 != Scalar::ZERO);
    (r1, r2)
}

impl Signer<WithKeypair> {
    /// Signer generates their secret nonces r1 and r2 and computes the public nonces R1 and R2 from them.
    pub fn generate_nonces(&self) -> Signer<WithNonces> {
        let (r1, r2) = nonce_gen(self.signer_key.private_key());
        self.with_nonces(r1, r2)
    }

    pub fn with_nonces(&self, r1: Scalar, r2: Scalar) -> Signer<WithNonces> {
        let r1_point = ProjectivePoint::GENERATOR * r1;
        let r2_point = ProjectivePoint::GENERATOR * r2;
        Signer {
            state: WithNonces {
                r1: (r1, r1_point),
                r2: (r2, r2_point),
                signer_key: self.signer_key.clone(),
            },
        }
    }
}

pub struct WithNonces {
    r1: NoncePair,
    r2: NoncePair,
    signer_key: SignerKey,
}

impl Signer<WithNonces> {
    /// The public nonces this signer must publish before the context is built.
    pub fn public_nonces(&self) -> (ProjectivePoint, ProjectivePoint) {
        (self.r1.1, self.r2.1)
    }

    pub fn context_item(&self, message: Message) -> ContextItem {
        (self.signer_key.public_key(), message, self.r1.1, self.r2.1)
    }

    /// Signer adds the context to their state and can now sign
    pub fn with_context(self, context: Context) -> Signer<WithContext> {
        Signer {
            state: WithContext {
                r1: self.state.r1,
                r2: self.state.r2,
                signer_key: self.state.signer_key,
                context,
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct Context {
    group_nonce_r1: ProjectivePoint,
    group_nonce_r2: ProjectivePoint,
    context: Vec<ContextItem>,
}

/// Digest the hasher to a Scalar
fn hasher_to_scalar(hasher: Sha256) -> Scalar {
    // This is acceptable because secp256k1 curve order is close to 2^256,
    // and the input is uniformly random since it is a hash output, therefore
    // the bias is negligibly small.
    Scalar::reduce(U256::from_be_slice(&hasher.finalize()))
}

impl Context {
    fn tagged_hash(&self) -> Sha256 {
        let mut hasher = tagged_hasher(TAG_NONCECOEF);
        hasher.update(cbytes(&self.group_nonce_r1));
        hasher.update(cbytes(&self.group_nonce_r2));
        for (pk, message, _, r2) in self.context.iter() {
            hasher.update(pk.to_affine().x());
            hasher.update(&message);
            hasher.update(cbytes(r2));
        }
        hasher
    }

    pub(crate) fn beta(&self) -> Scalar {
        hasher_to_scalar(self.tagged_hash())
    }

    pub(crate) fn group_nonce(&self) -> ProjectivePoint {
        let beta = self.beta();
        let group_nonce = self.group_nonce_r1 + (self.group_nonce_r2 * beta);
        assert!(group_nonce != ProjectivePoint::IDENTITY);
        group_nonce
    }

    /// Returns the signer list which consists of a tuple of public keys and messages
    pub(crate) fn signer_list(&self) -> SignerList {
        self.context
            .iter()
            .map(|item| (item.0.clone(), item.1.clone()))
            .collect()
    }
}

pub struct WithContext {
    r1: NoncePair,
    r2: NoncePair,
    context: Context,
    signer_key: SignerKey,
}

fn challenge(
    signer_list: &SignerList,
    group_nonce: &ProjectivePoint,
    pk: &PublicKey,
    message: &Message,
) -> Scalar {
    let mut hasher = tagged_hasher(TAG_SIG);
    for (signer_pk, signer_message) in signer_list.iter() {
        hasher.update(signer_pk.to_affine().x());
        hasher.update(signer_message);
    }
    hasher.update(group_nonce.to_affine().x());
    hasher.update(pk.to_affine().x());
    hasher.update(message);
    hasher_to_scalar(hasher)
}

fn partial_sig_verify(context: &Context, psig: Scalar, index: usize) -> bool {
    let (pk, message, r1, r2) = &context.context[index];
    let group_nonce = context.group_nonce();
    let e = if has_even_y(&group_nonce) {
        Scalar::ONE
    } else {
        -Scalar::ONE
    };
    let c = challenge(&context.signer_list(), &group_nonce, pk, message);
    let r_eff = *r1 + (*r2 * context.beta());
    ProjectivePoint::GENERATOR * psig == (r_eff * e) + (lift_x(pk) * c)
}

impl Signer<WithContext> {
    /// Signer signs the message and returns their partial signature
    pub fn sign(self, message: &Message) -> Scalar {
        let mut counter = 0;
        let mut index = None;
        for (i, (_, _, _, r2)) in self.context.context.iter().enumerate() {
            if *r2 == self.r2.1 {
                counter += 1;
                index = Some(i);
            }
        }
        // Ensure that our R2 is on the list only once
        assert!(counter == 1);
        // Ensure the coordinator paired our nonce with our own key and message
        let (context_pk, context_message, _, _) = &self.context.context[index.unwrap()];
        assert!(context_pk.to_affine().x() == self.signer_key.public_key().to_affine().x());
        assert!(context_message == message);
        let beta = self.context.beta();
        let group_nonce = self.context.group_nonce();
        let public_key = self.signer_key.public_key();
        let challenge = challenge(
            &self.context.signer_list(),
            &group_nonce,
            &public_key,
            message,
        );
        // Negate so that the aggregate verifies against the x-only group nonce
        // and the x-only public keys.
        let e = if has_even_y(&group_nonce) {
            Scalar::ONE
        } else {
            -Scalar::ONE
        };
        let sk = self.signer_key.private_key();
        let d = if has_even_y(&public_key) { sk } else { -sk };
        let s = e * (self.r1.0 + (self.r2.0 * beta)) + (challenge * d);
        s
    }
}

pub fn serialize_signature(group_nonce: &ProjectivePoint, s: &Scalar) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&group_nonce.to_affine().x());
    out[32..].copy_from_slice(&s.to_bytes());
    out
}

/// Lifts an x-only encoding to the point with even Y, as lift_x is defined in
/// BIP 340. Returns None if no curve point has this x coordinate.
pub fn lift_x_bytes(x: &[u8; 32]) -> Option<PublicKey> {
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(x);
    parse_point(&compressed)
}

/// Parses a SEC1 compressed point, as used for public nonces.
pub fn parse_point(bytes: &[u8; 33]) -> Option<ProjectivePoint> {
    let encoded = EncodedPoint::from_bytes(bytes).ok()?;
    Option::from(ProjectivePoint::from_encoded_point(&encoded))
}

/// Serializes a point SEC1 compressed.
pub fn serialize_point(point: &ProjectivePoint) -> [u8; 33] {
    cbytes(point)
}

fn scalar_from_bytes(bytes: &[u8]) -> Option<Scalar> {
    let bytes: [u8; 32] = bytes.try_into().ok()?;
    Option::from(Scalar::from_repr(bytes.into()))
}

/// Verifies a serialized aggregate signature against x-only public keys, as
/// Verify is defined in BIP 459. Fails if a public key or the nonce is not on
/// the curve, if s is not a valid scalar, or if the lists do not line up.
pub fn verify_serialized(
    pubkeys: &[[u8; 32]],
    messages: &[Message],
    signature: &[u8; 64],
) -> bool {
    if pubkeys.is_empty() || pubkeys.len() != messages.len() {
        return false;
    }
    let Some(group_nonce) = signature[..32]
        .try_into()
        .ok()
        .and_then(|x: &[u8; 32]| lift_x_bytes(x))
    else {
        return false;
    };
    let Some(s) = scalar_from_bytes(&signature[32..]) else {
        return false;
    };
    let mut signer_list = SignerList::with_capacity(pubkeys.len());
    for (pubkey, message) in pubkeys.iter().zip(messages) {
        let Some(point) = lift_x_bytes(pubkey) else {
            return false;
        };
        signer_list.push((point, *message));
    }
    verify(s, group_nonce, &signer_list)
}

/// Verifies the group signature and group nonce
pub fn verify(s: Scalar, group_nonce: ProjectivePoint, signer_list: &SignerList) -> bool {
    let gs = ProjectivePoint::GENERATOR * s;
    let rhs = lift_x(&group_nonce)
        + signer_list
            .iter()
            .map(|(pk, message)| {
                let c = challenge(signer_list, &group_nonce, pk, message);
                let x = lift_x(pk) * c;
                x
            })
            .sum::<ProjectivePoint>();
    gs == rhs
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::FieldBytes;
    use k256::elliptic_curve::PrimeField;

    // "Two-member full-aggregation group with SIGHASH_ALL (using deterministic
    // nonces)" from bip-0460/wallet-test-vectors.json in
    // https://github.com/bitcoin/bips/pull/2212. The signature messages are the
    // BIP 460 sighashes and the keys are the taproot tweaked keys, both of which
    // that BIP derives from the transaction before handing them to BIP 459.
    const TWEAKED_PRIVKEYS: [&str; 2] = [
        "1071bcc060fecee099b8826465a20e691fd1d65ff6f1bef9600d8454e080bc29",
        "0506bdad0f203954d2194a9955bf7b92d4b238360ceabc4a2b96d5cabea9ae5b",
    ];
    const WITNESS_PROGRAMS: [&str; 2] = [
        "8640c68f13b51a1e63dfc5cc41202cca21c18f1f9d7037c2cbec3f03f63e52e4",
        "18b6491469cc78b764b01669b0a5a4e892f57e8c1b20b89bc1ca6dce3e881b51",
    ];
    const SIG_HASHES: [&str; 2] = [
        "9339267f5f6715d1b7e1b26bd69e13689b3872be5fa0c50a9d90daf9f2ae46cc",
        "d2982e6665e1e964ecefa2a747b19f17ad46d6765e284d639c293647c9349857",
    ];
    const SECNONCES: [&str; 2] = [
        "87c33dcedc7db5994d68278a81a4693ee961d08ef7e3fdeab611ab8061e92dd4\
         517ac39af981926ed1124224dfe721c6dc0769a8ea24d2e2fc2636c3b1e9ca15",
        "3c4b7832dd37bbdb955ebf900769d133d55161e5c6ad9e09c2efa4ace1ba2e15\
         3d007745e9f74e6b8a47651a672111b07589261401674263a40e286340bcefea",
    ];
    const PUBNONCES: [&str; 2] = [
        "021be5111aa027a4b7368d88cb0f5419f7b530e17e41af6fe7a611a03abc9bab63\
         020e72955a3c53f163a1373ac5233ad30ff8bb4ef69dad424d91529c0ef6329ac6",
        "0367b7d091e6b58f7e94e9228393bc6b777e9fbe0186e9fce56248c9177c96f65e\
         03592137dea3431dbb0fbe1287c35f8e44a30d68e62486969d21e90d2b4c68f05e",
    ];
    const AGGREGATE_SIGNATURE: &str =
        "f00c224cc4e1bb038b1f35d71c28608510236327924d350d75520eb6295eb190\
         8a38b68c0a7b484bc4ac7330ae2f5e909bf25b53fa60131f7d6799d5017311d8";

    fn demo_messages() -> Vec<Message> {
        (0..3)
            .map(|i| {
                let digest = Sha256::digest(format!("cisa is cool {}", i));
                let mut message = [0u8; 32];
                message.copy_from_slice(&digest);
                message
            })
            .collect()
    }

    #[test]
    fn full_aggregation_round_trip() {

        let mut coordinator = Coordinator::new();
        let signers = vec![
            Signer::new_keypair(None).generate_nonces(),
            Signer::new_keypair(None).generate_nonces(),
            Signer::new_keypair(None).generate_nonces(),
        ];
        let messages = demo_messages();
        for (i, singer) in signers.iter().enumerate() {
            coordinator.add_context_item(singer.context_item(messages[i].clone()));
        }

        let mut coordinator = coordinator.collect_nonces();

        for (i, singer) in signers.into_iter().enumerate() {
            let signature = singer
                .with_context(coordinator.context())
                .sign(&messages[i]);
            coordinator.add_signature(signature);
        }

        let (signature, group_nonce) = coordinator.collect_signatures();
        let res = verify(signature, group_nonce, &coordinator.context().signer_list());
        assert!(res);
    }

    #[test]
    fn full_aggregation_round_trip_with_tweaks() {
        let messages = demo_messages();
        let mut coordinator = Coordinator::new();
        let signers = vec![
            Signer::new_keypair(Some(Tweak {
                value: Scalar::random(&mut OsRng),
                is_xonly: true,
            }))
            .generate_nonces(),
            Signer::new_keypair(Some(Tweak {
                value: Scalar::random(&mut OsRng),
                is_xonly: true,
            }))
            .generate_nonces(),
            Signer::new_keypair(Some(Tweak {
                value: Scalar::random(&mut OsRng),
                is_xonly: true,
            }))
            .generate_nonces(),
        ];
        for (i, singer) in signers.iter().enumerate() {
            coordinator.add_context_item(singer.context_item(messages[i].clone()));
        }
        let mut coordinator = coordinator.collect_nonces();
        for (i, singer) in signers.into_iter().enumerate() {
            let signature = singer
                .with_context(coordinator.context())
                .sign(&messages[i]);
            coordinator.add_signature(signature);
        }
        let (signature, group_nonce) = coordinator.collect_signatures();
        let res = verify(signature, group_nonce, &coordinator.context().signer_list());
        assert!(res);
    }

    fn hex(value: &str) -> Vec<u8> {
        let value: String = value.chars().filter(|c| !c.is_whitespace()).collect();
        (0..value.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
            .collect()
    }

    fn scalar(bytes: &[u8]) -> Scalar {
        Scalar::from_repr(FieldBytes::from(<[u8; 32]>::try_from(bytes).unwrap())).unwrap()
    }

    fn message(value: &str) -> Message {
        let mut out = [0u8; 32];
        out.copy_from_slice(&hex(value));
        out
    }

    fn program(value: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&hex(value));
        out
    }

    #[test]
    fn verify_serialized_accepts_the_vector() {
        let pubkeys: Vec<[u8; 32]> = WITNESS_PROGRAMS.iter().map(|p| program(p)).collect();
        let messages: Vec<Message> = SIG_HASHES.iter().map(|m| message(m)).collect();
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&hex(AGGREGATE_SIGNATURE));

        assert!(verify_serialized(&pubkeys, &messages, &signature));

        // A flipped bit in s, a swapped signer order, and a truncated list are
        // all rejected rather than panicking.
        let mut tampered = signature;
        tampered[63] ^= 1;
        assert!(!verify_serialized(&pubkeys, &messages, &tampered));

        let swapped = vec![pubkeys[1], pubkeys[0]];
        assert!(!verify_serialized(&swapped, &messages, &signature));

        assert!(!verify_serialized(&pubkeys[..1], &messages, &signature));
        assert!(!verify_serialized(&[], &[], &signature));

        // An x coordinate with no curve point is a verification failure.
        assert!(!verify_serialized(&[[0xff; 32]], &messages[..1], &signature));
    }

    #[test]
    fn bip460_full_aggregation_vector() {
        let messages: Vec<Message> = SIG_HASHES.iter().map(|m| message(m)).collect();
        let signers: Vec<Signer<WithNonces>> = (0..2)
            .map(|i| {
                let secnonce = hex(SECNONCES[i]);
                Signer::from_private_key(scalar(&hex(TWEAKED_PRIVKEYS[i])), None)
                    .with_nonces(scalar(&secnonce[..32]), scalar(&secnonce[32..]))
            })
            .collect();

        for (i, signer) in signers.iter().enumerate() {
            assert_eq!(
                &signer.signer_key.public_key().to_affine().x()[..],
                &hex(WITNESS_PROGRAMS[i])[..]
            );
            let mut pubnonce = cbytes(&signer.r1.1).to_vec();
            pubnonce.extend_from_slice(&cbytes(&signer.r2.1));
            assert_eq!(pubnonce, hex(PUBNONCES[i]));
        }

        let mut coordinator = Coordinator::new();
        for (i, signer) in signers.iter().enumerate() {
            coordinator.add_context_item(signer.context_item(messages[i]));
        }
        let mut coordinator = coordinator.collect_nonces();
        for (i, signer) in signers.into_iter().enumerate() {
            let signature = signer.with_context(coordinator.context()).sign(&messages[i]);
            coordinator.add_signature(signature);
        }

        let (signature, group_nonce) = coordinator.collect_signatures();
        assert_eq!(
            serialize_signature(&group_nonce, &signature).as_slice(),
            hex(AGGREGATE_SIGNATURE).as_slice()
        );
        assert!(verify(signature, group_nonce, &coordinator.context().signer_list()));
    }
}
