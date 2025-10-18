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
/// Individual signer's public key, R1, R2, and message
type ContextItem = (PublicKey, ProjectivePoint, ProjectivePoint, Message);

struct Signer<SignerState> {
    state: SignerState,
}

impl<SignerState> Deref for Signer<SignerState> {
    type Target = SignerState;
    fn deref(&self) -> &Self::Target {
        &self.state
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

struct Context {
    context: Vec<ContextItem>,
}

impl Context {
    fn tagged_hash(&self) -> Sha256 {
        let mut hasher = Sha256::new();
        hasher.update(TAGGED_HASH_CONTEXT_NONCE);
        for item in self.context.iter() {
            hasher.update(item.0.to_projective().to_affine().x());
            hasher.update(item.1.to_affine().x());
            hasher.update(item.2.to_affine().x());
            hasher.update(&item.3);
        }
        hasher
    }

    /// Digest the hasher to a Scalar
    fn hasher_to_scalar(hasher: Sha256) -> Scalar {
        // This is acceptable because secp256k1 curve order is close to 2^256,
        // and the input is uniformly random since it is a hash output, therefore
        // the bias is negligibly small.
        Scalar::reduce(U256::from_be_slice(&hasher.finalize()))
    }

    pub(crate) fn beta(&self) -> Scalar {
        Self::hasher_to_scalar(self.tagged_hash())
    }
}

struct WithContext {
    r1: NoncePair,
    r2: NoncePair,
    keypair: Keypair,
    context: Context,
}

impl Signer<WithContext> {
    fn effective_nonce(&self) -> Scalar {
        let beta = self.context.beta();
        let effective_nonce = self.r1.0 + beta * self.r2.0;
        effective_nonce
    }
    pub fn sign(&self, message: Message) -> Signature {
        todo!()
    }
}

fn main() {
}
