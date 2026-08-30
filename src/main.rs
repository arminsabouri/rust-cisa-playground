use std::ops::Deref;

use k256::{
    ProjectivePoint, Scalar, U256,
    elliptic_curve::{Field, ops::Reduce, rand_core::OsRng},
    sha2::Digest,
};

use k256::elliptic_curve::point::AffineCoordinates;
use k256::sha2::Sha256;

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
type NoncePair = (Scalar, ProjectivePoint);
type Message = [u8; 32];
/// Individual signer's public key, message, and individual R1, R2
type ContextItem = (PublicKey, Message, ProjectivePoint, ProjectivePoint);
/// Signer list is a list of public keys and messages
type SignerList = Vec<(PublicKey, Message)>;
/// Public key is a group element
type PublicKey = ProjectivePoint;

#[derive(Clone, Copy)]
struct Tweak {
    value: Scalar,
    is_xonly: bool,
}

#[derive(Clone)]
struct SignerKey {
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

struct Signer<SignerState> {
    state: SignerState,
}

impl<SignerState> Deref for Signer<SignerState> {
    type Target = SignerState;
    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

struct Coordinator<CoordinatorState> {
    state: CoordinatorState,
}

impl<CoordinatorState> Deref for Coordinator<CoordinatorState> {
    type Target = CoordinatorState;
    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

struct CollectingNonces {
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

struct CollectingSignatures {
    context: Context,
    signatures: Vec<Scalar>,
}

impl Coordinator<CollectingSignatures> {
    pub fn context(&self) -> Context {
        self.state.context.clone()
    }

    pub fn add_signature(&mut self, signature: Scalar) {
        self.state.signatures.push(signature);
    }

    /// Coordinator collects the signatures and computes the group signature and group nonce
    pub fn collect_signatures(&self) -> (Scalar, ProjectivePoint) {
        let signature = self.state.signatures.iter().sum::<Scalar>();
        let group_nonce = self.state.context.group_nonce();
        (signature, group_nonce)
    }
}

#[allow(dead_code)]
struct Init;
impl Signer<Init> {
    /// Signer generates their private and public key
    pub fn new_keypair(tweak: Option<Tweak>) -> Signer<WithKeypair> {
        let signer_key = SignerKey::new_random(tweak);
        Signer {
            state: WithKeypair { signer_key },
        }
    }
}

struct WithKeypair {
    signer_key: SignerKey,
}

impl Signer<WithKeypair> {
    /// Signer generates their secret nonces r1 and r2 and computes the public nonces R1 and R2 from them.
    pub fn generate_nonces(&self) -> Signer<WithNonces> {
        let r1 = Scalar::random(&mut OsRng);
        let r2 = Scalar::random(&mut OsRng);
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

struct WithNonces {
    r1: NoncePair,
    r2: NoncePair,
    signer_key: SignerKey,
}

impl Signer<WithNonces> {
    // TODO: message should be part of the WithNonces state, NOT a parameter. that can lead to nonce reuse for different messages
    pub fn context_item(&self, message: Message) -> ContextItem {
        (self.signer_key.public_key(), message, self.r1.1, self.r2.1)
    }

    /// Signer adds the context to their state and can now sign
    pub fn with_context(&self, context: Context) -> Signer<WithContext> {
        Signer {
            state: WithContext {
                r1: self.r1,
                r2: self.r2,
                signer_key: self.signer_key.clone(),
                context,
            },
        }
    }
}

#[derive(Debug, Clone)]
struct Context {
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

struct WithContext {
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

impl Signer<WithContext> {
    /// Signer signs the message and returns their partial signature
    pub fn sign(&self, message: &Message) -> Scalar {
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

fn main() {
    // TODO: this should be converted to a library and main should be a test
    let mut coordinator = Coordinator::new();
    let signers = vec![
        Signer::new_keypair(None).generate_nonces(),
        Signer::new_keypair(None).generate_nonces(),
        Signer::new_keypair(None).generate_nonces(),
    ];
    let mut messages: Vec<Message> = Vec::new();
    for i in 0..3 {
        let digest = Sha256::digest(format!("cisa is cool {}", i));
        let mut message = [0u8; 32];
        message.copy_from_slice(&digest);
        messages.push(message);
    }
    for (i, singer) in signers.iter().enumerate() {
        coordinator.add_context_item(singer.context_item(messages[i].clone()));
    }

    let mut coordinator = coordinator.collect_nonces();

    for (i, singer) in signers.iter().enumerate() {
        let signature = singer
            .with_context(coordinator.context())
            .sign(&messages[i]);
        coordinator.add_signature(signature);
    }

    let (signature, group_nonce) = coordinator.collect_signatures();
    let res = verify(signature, group_nonce, &coordinator.context().signer_list());
    assert!(res);

    // Test with tweaks
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
    for (i, singer) in signers.iter().enumerate() {
        let signature = singer
            .with_context(coordinator.context())
            .sign(&messages[i]);
        coordinator.add_signature(signature);
    }
    let (signature, group_nonce) = coordinator.collect_signatures();
    let res = verify(signature, group_nonce, &coordinator.context().signer_list());
    assert!(res);
}
