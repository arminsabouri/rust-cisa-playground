use std::ops::Deref;

use k256::{
    ProjectivePoint, PublicKey, Scalar, SecretKey, U256,
    elliptic_curve::{Field, ops::Reduce, rand_core::OsRng},
    schnorr::Signature,
    sha2::Digest,
};

use k256::elliptic_curve::point::AffineCoordinates;
use k256::sha2::Sha256;

const TAGGED_HASH_CONTEXT_NONCE: &[u8] = b"fullagg-nonce-secp256k1-Sha256-v0";
const TAGGED_HASH_CONTEXT_SIGNATURE: &[u8] = b"fullagg-signature-secp256k1-Sha256-v0";

type Keypair = (SecretKey, PublicKey);
type NoncePair = (Scalar, ProjectivePoint);
type Message = Vec<u8>;
/// Individual signer's public key, message, and individual R2
type ContextItem = (PublicKey, Message, ProjectivePoint);

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

    pub fn add_nonce(&mut self, nonce: ContextItem) {
        self.state.context.push(nonce);
    }

    /// Returns the context and the group nonce
    pub fn collect_nonces(&self) -> (Context, Coordinator<CollectingSignatures>) {
        let group_nonce_R1 = self
            .context
            .iter()
            .map(|item| item.2)
            .sum::<ProjectivePoint>();
        let group_nonce_R2 = self
            .context
            .iter()
            .map(|item| item.2)
            .sum::<ProjectivePoint>();
        let context = Context {
            context: self.context.clone(),
            group_nonce_R1,
            group_nonce_R2,
        };
        (
            context.clone(),
            Coordinator {
                state: CollectingSignatures {
                    context,
                    signatures: Vec::new(),
                },
            },
        )
    }
}

struct CollectingSignatures {
    context: Context,
    signatures: Vec<Scalar>,
}

impl Coordinator<CollectingSignatures> {
    pub fn add_signature(&mut self, signature: Scalar) {
        self.state.signatures.push(signature);
    }

    pub fn collect_signatures(&self) -> (Scalar, ProjectivePoint) {
        let signature = self.state.signatures.iter().sum::<Scalar>();
        let group_nonce = self.state.context.group_nonce();
        (signature, group_nonce)
    }
}

struct Init;
impl Signer<Init> {
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
    /// Signer generates their secret nonces r1_i and r2_i and computes the
    /// public nonces R1_i and R2_i from them.
    /// Then they store state st_i and send out_i to the coordinator.
    pub fn generate_nonces(&self) -> Signer<WithNonces> {
        let r1 = Scalar::random(&mut OsRng);
        let r2 = Scalar::random(&mut OsRng);
        let R1 = ProjectivePoint::GENERATOR * r1;
        let R2 = ProjectivePoint::GENERATOR * r2;
        Signer {
            state: WithNonces {
                r1: (r1, R1),
                r2: (r2, R2),
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
    pub fn context_item(&self, message: Message) -> ContextItem {
        (self.keypair.1, message, self.r2.1)
    }

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
    group_nonce_R1: ProjectivePoint,
    group_nonce_R2: ProjectivePoint,
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
        hasher.update(self.group_nonce_R1.to_affine().x());
        hasher.update(self.group_nonce_R2.to_affine().x());
        for item in self.context.iter() {
            hasher.update(item.0.to_projective().to_affine().x());
            hasher.update(&item.1);
            hasher.update(item.2.to_affine().x());
        }
        hasher
    }

    pub(crate) fn beta(&self) -> Scalar {
        hasher_to_scalar(self.tagged_hash())
    }

    pub(crate) fn group_nonce(&self) -> ProjectivePoint {
        let beta = self.beta();
        self.group_nonce_R1 + self.group_nonce_R2 * beta
    }

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

impl Signer<WithContext> {
    fn challenge(&self, singer_list: SignerList) -> Scalar {
        let mut hasher = Sha256::new();
        hasher.update(TAGGED_HASH_CONTEXT_SIGNATURE);
        hasher.update(self.context.group_nonce().to_affine().x());
        // Hash my pk one extra time ?
        hasher.update(self.keypair.1.to_projective().to_affine().x());
        for (pk, message) in singer_list.iter() {
            hasher.update(pk.to_projective().to_affine().x());
            hasher.update(&message);
        }
        hasher_to_scalar(hasher)
    }

    pub fn sign(&self, message: Message) -> Scalar {
        let mut counter = 0;
        for (_, _, r2) in self.context.context.iter() {
            if *r2 == self.r2.1 {
                counter += 1;
            }
        }
        // Ensure that our R2 is on the list only once
        assert!(counter == 1);
        // TODO ensure our public key message is correct from the context at an earlier stage
        let beta = self.context.beta();
        let challenge = self.challenge(self.context.signer_list());
        let br2 = self.r2.0 * beta;
        let csk = self.keypair.0.to_nonzero_scalar().mul(&challenge);
        let s = self.r1.0 + br2 + csk;
        s
    }
}

fn main() {
    let mut coordinator = Coordinator::new();
    let signer_1 = Signer::new_keypair().generate_nonces();
    let signer_2 = Signer::new_keypair().generate_nonces();
    let signer_3 = Signer::new_keypair().generate_nonces();

    let message = b"cisa is cool".to_vec();

    coordinator.add_nonce(signer_1.context_item(message.clone()));
    coordinator.add_nonce(signer_2.context_item(message.clone()));
    coordinator.add_nonce(signer_3.context_item(message.clone()));

    let context = coordinator.collect_nonces();
}
