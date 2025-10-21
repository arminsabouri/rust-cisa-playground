use std::ops::Deref;

use k256::{
    ProjectivePoint, PublicKey, Scalar, SecretKey, U256,
    elliptic_curve::{Field, ops::Reduce, rand_core::OsRng},
    sha2::Digest,
};

use k256::elliptic_curve::point::AffineCoordinates;
use k256::sha2::Sha256;

const TAGGED_HASH_CONTEXT_NONCE: &[u8] = b"fullagg-nonce-secp256k1-Sha256-v0";
const TAGGED_HASH_CONTEXT_SIGNATURE: &[u8] = b"fullagg-signature-secp256k1-Sha256-v0";

/// Private and public key for a signer
type Keypair = (SecretKey, PublicKey);
/// Private and public nonces for a signer
type NoncePair = (Scalar, ProjectivePoint);
type Message = Vec<u8>;
/// Individual signer's public key, message, and individual R1, R2
type ContextItem = (PublicKey, Message, ProjectivePoint, ProjectivePoint);
/// Signer list is a list of public keys and messages
type SignerList = Vec<(PublicKey, Message)>;

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
    pub fn new_keypair() -> Signer<WithKeypair> {
        let sk = SecretKey::random(&mut OsRng);
        let pk = sk.public_key();
        Signer {
            state: WithKeypair { keypair: (sk, pk) },
        }
    }
}

struct WithKeypair {
    keypair: Keypair,
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
                keypair: self.keypair.clone(),
            },
        }
    }
}

struct WithNonces {
    r1: NoncePair,
    r2: NoncePair,
    keypair: Keypair,
}

impl Signer<WithNonces> {
    // TODO: message should be part of the WithNonces state, NOT a parameter. that can lead to nonce reuse for different messages
    pub fn context_item(&self, message: Message) -> ContextItem {
        (self.keypair.1, message, self.r1.1, self.r2.1)
    }

    /// Signer adds the context to their state and can now sign
    pub fn with_context(&self, context: Context) -> Signer<WithContext> {
        Signer {
            state: WithContext {
                r1: self.r1,
                r2: self.r2,
                keypair: self.keypair.clone(),
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
        let mut hasher = Sha256::new();
        hasher.update(TAGGED_HASH_CONTEXT_NONCE);
        hasher.update(self.group_nonce_r1.to_affine().x());
        hasher.update(self.group_nonce_r2.to_affine().x());
        for (pk, message, _, r2) in self.context.iter() {
            hasher.update(pk.to_projective().to_affine().x());
            hasher.update(&message);
            hasher.update(r2.to_affine().x());
        }
        hasher
    }

    pub(crate) fn beta(&self) -> Scalar {
        hasher_to_scalar(self.tagged_hash())
    }

    pub(crate) fn group_nonce(&self) -> ProjectivePoint {
        let beta = self.beta();
        self.group_nonce_r1 + (self.group_nonce_r2 * beta)
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
    keypair: Keypair,
    context: Context,
}

fn challenge(
    signer_list: &SignerList,
    group_nonce: &ProjectivePoint,
    pk: &PublicKey,
    message: &Message,
) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(TAGGED_HASH_CONTEXT_SIGNATURE);
    hasher.update(group_nonce.to_affine().x());
    hasher.update(pk.to_projective().to_affine().x());
    hasher.update(message);
    for (signer_pk, signer_message) in signer_list.iter() {
        hasher.update(signer_pk.to_projective().to_affine().x());
        hasher.update(signer_message);
    }
    hasher_to_scalar(hasher)
}

impl Signer<WithContext> {
    /// Signer signs the message and returns their partial signature
    pub fn sign(&self, message: &Message) -> Scalar {
        let mut counter = 0;
        for (_, _, _, r2) in self.context.context.iter() {
            if *r2 == self.r2.1 {
                counter += 1;
            }
        }
        // Ensure that our R2 is on the list only once
        assert!(counter == 1);
        // TODO ensure our public key message is correct from the context at an earlier stage
        let beta = self.context.beta();
        let challenge = challenge(
            &self.context.signer_list(),
            &self.context.group_nonce(),
            &self.keypair.1,
            message,
        );
        let br2 = self.r2.0 * beta;
        let csk = self.keypair.0.to_nonzero_scalar().mul(&challenge);
        let s = self.r1.0 + br2 + csk;
        s
    }
}

/// Verifies the group signature and group nonce
pub fn verify(s: Scalar, group_nonce: ProjectivePoint, signer_list: &SignerList) -> bool {
    let gs = ProjectivePoint::GENERATOR * s;
    let rhs = group_nonce
        + signer_list
            .iter()
            .map(|(pk, message)| {
                let c = challenge(signer_list, &group_nonce, pk, message);
                let x = pk.to_projective() * c;
                x
            })
            .sum::<ProjectivePoint>();
    gs == rhs
}

fn main() {
    let mut coordinator = Coordinator::new();
    let signer_1 = Signer::new_keypair().generate_nonces();
    let signer_2 = Signer::new_keypair().generate_nonces();
    let signer_3 = Signer::new_keypair().generate_nonces();

    let mut messages = Vec::new();
    for i in 0..3 {
        messages.push(format!("cisa is cool {}", i).as_bytes().to_vec());
    }

    coordinator.add_context_item(signer_1.context_item(messages[0].clone()));
    coordinator.add_context_item(signer_2.context_item(messages[1].clone()));
    coordinator.add_context_item(signer_3.context_item(messages[2].clone()));

    let mut coordinator = coordinator.collect_nonces();

    let singature_1 = signer_1
        .with_context(coordinator.context())
        .sign(&messages[0]);
    let singature_2 = signer_2
        .with_context(coordinator.context())
        .sign(&messages[1]);
    let singature_3 = signer_3
        .with_context(coordinator.context())
        .sign(&messages[2]);

    coordinator.add_signature(singature_1);
    coordinator.add_signature(singature_2);
    coordinator.add_signature(singature_3);

    let (signature, group_nonce) = coordinator.collect_signatures();
    println!("signature: {:?}", signature);
    println!("group_nonce: {:?}", group_nonce);

    let verify = verify(signature, group_nonce, &coordinator.context().signer_list());
    assert!(verify);
    println!("verify: {:?}", verify);
}
